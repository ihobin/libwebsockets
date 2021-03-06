/*
 * libwebsockets-test-server - libwebsockets test implementation
 *
 * Copyright (C) 2010-2017 Andy Green <andy@warmcat.com>
 *
 * This file is made available under the Creative Commons CC0 1.0
 * Universal Public Domain Dedication.
 *
 * The person who associated a work with this deed has dedicated
 * the work to the public domain by waiving all of his or her rights
 * to the work worldwide under copyright law, including all related
 * and neighboring rights, to the extent allowed by law. You can copy,
 * modify, distribute and perform the work, even for commercial purposes,
 * all without asking permission.
 *
 * The test apps are intended to be adapted for use in your code, which
 * may be proprietary.  So unlike the library itself, they are licensed
 * Public Domain.
 */

#if !defined (LWS_PLUGIN_STATIC)
#define LWS_DLL
#define LWS_INTERNAL
#include "../lib/libwebsockets.h"
#endif

#include <string.h>
#include <stdlib.h>

#define QUEUELEN 64
/* queue free space below this, rx flow is disabled */
#define RXFLOW_MIN (4)
/* queue free space above this, rx flow is enabled */
#define RXFLOW_MAX (QUEUELEN / 3)

#define MAX_MIRROR_INSTANCES 10

struct mirror_instance;

struct per_session_data__lws_mirror {
	struct lws *wsi;
	struct mirror_instance *mi;
	struct per_session_data__lws_mirror *same_mi_pss_list;
	uint32_t tail;
};

struct a_message {
	void *payload;
	size_t len;
};

struct mirror_instance {
	struct mirror_instance *next;
	struct per_session_data__lws_mirror *same_mi_pss_list;
	struct lws_ring *ring;
	char name[30];
	char rx_enabled;
};

struct per_vhost_data__lws_mirror {
	struct mirror_instance *mi_list;
};


/* enable or disable rx from all connections to this mirror instance */
static void
mirror_rxflow_instance(struct mirror_instance *mi, int enable)
{
	lws_start_foreach_ll(struct per_session_data__lws_mirror *,
			     pss, mi->same_mi_pss_list) {
		lws_rx_flow_control(pss->wsi, enable);
	} lws_end_foreach_ll(pss, same_mi_pss_list);

	mi->rx_enabled = enable;
}

/*
 * Find out which connection to this mirror instance has the longest number
 * of still unread elements in the ringbuffer and update the lws_ring "oldest
 * tail" with it.  Elements behind the "oldest tail" are freed and recycled for
 * new head content.  Elements after the "oldest tail" are still waiting to be
 * read by somebody.
 *
 * If the oldest tail moved on from before, check if it created enough space
 * in the queue to re-enable RX flow control for the mirror instance.
 *
 * Mark connections that are at the oldest tail as being on a 3s timeout to
 * transmit something, otherwise the connection will be closed.  Without this,
 * a choked or nonresponsive connection can block the FIFO from freeing up any
 * new space for new data.
 *
 * You can skip calling this if on your connection, before processing, the tail
 * was not equal to the current worst, ie,  if the tail you will work on is !=
 * lws_ring_get_oldest_tail(ring) then no need to call this when the tail
 * has changed; it wasn't the oldest so it won't change the oldest.
 *
 * Returns 0 if oldest unchanged or 1 if oldest changed from this call.
 */
static int
mirror_update_worst_tail(struct mirror_instance *mi)
{
	uint32_t wai, worst = 0, worst_tail, oldest;
	struct per_session_data__lws_mirror *worst_pss = NULL;

	oldest = lws_ring_get_oldest_tail(mi->ring);

	lws_start_foreach_ll(struct per_session_data__lws_mirror *,
			     pss, mi->same_mi_pss_list) {
		wai = lws_ring_get_count_waiting_elements(mi->ring, &pss->tail);
		if (wai >= worst) {
			worst = wai;
			worst_tail = pss->tail;
			worst_pss = pss;
		}
	} lws_end_foreach_ll(pss, same_mi_pss_list);

	if (!worst_pss)
		return 0;

	lws_ring_update_oldest_tail(mi->ring, worst_tail);
	if (oldest == lws_ring_get_oldest_tail(mi->ring))
		return 0;

	/*
	 * The oldest tail did move on.  Check if we should re-enable rx flow
	 * for the mirror instance since we made some space now.
	 */
	if (!mi->rx_enabled && /* rx is disabled */
	    lws_ring_get_count_free_elements(mi->ring) > RXFLOW_MAX)
		/* there is enough space, let's re-enable rx for our instance */
		mirror_rxflow_instance(mi, 1);

	/* if nothing in queue, no timeout needed */
	if (!worst)
		return 1;

	/*
	 * The guy(s) with the oldest tail block the ringbuffer from recycling
	 * the FIFO entries he has not read yet.  Don't allow those guys to
	 * block the FIFO operation for very long.
	 */
	lws_start_foreach_ll(struct per_session_data__lws_mirror *,
			     pss, mi->same_mi_pss_list) {
		if (pss->tail == worst_tail)
			/*
			 * Our policy is if you are the slowest connection,
			 * you had better transmit something to help with that
			 * within 3s, or we will hang up on you to stop you
			 * blocking the FIFO for everyone else.
			 */
			lws_set_timeout(pss->wsi,
					PENDING_TIMEOUT_USER_REASON_BASE, 3);
	} lws_end_foreach_ll(pss, same_mi_pss_list);

	return 1;
}

static void
mirror_callback_all_in_mi_on_writable(struct mirror_instance *mi)
{
	/* ask for WRITABLE callback for every wsi on this mi */
	lws_start_foreach_ll(struct per_session_data__lws_mirror *,
			     pss, mi->same_mi_pss_list) {
		lws_callback_on_writable(pss->wsi);
	} lws_end_foreach_ll(pss, same_mi_pss_list);
}

static void
mirror_destroy_message(void *_msg)
{
	struct a_message *msg = _msg;

	free(msg->payload);
	msg->payload = NULL;
	msg->len = 0;
}

static int
callback_lws_mirror(struct lws *wsi, enum lws_callback_reasons reason,
		    void *user, void *in, size_t len)
{
	struct per_session_data__lws_mirror *pss =
			(struct per_session_data__lws_mirror *)user;
	struct per_vhost_data__lws_mirror *v =
			(struct per_vhost_data__lws_mirror *)
			lws_protocol_vh_priv_get(lws_get_vhost(wsi),
						 lws_get_protocol(wsi));
	struct mirror_instance *mi = NULL;
	const struct a_message *msg;
	struct a_message amsg;
	char name[300], update_worst, sent_something;
	uint32_t oldest_tail;
	int n, count_mi = 0;

	switch (reason) {
	case LWS_CALLBACK_ESTABLISHED:
		lwsl_info("%s: LWS_CALLBACK_ESTABLISHED\n", __func__);

		/*
		 * mirror instance name... defaults to "", but if URL includes
		 * "?mirror=xxx", will be "xxx"
		 */
		name[0] = '\0';
		if (lws_get_urlarg_by_name(wsi, "mirror", name,
					   sizeof(name) - 1))
			lwsl_debug("get urlarg failed\n");
		lwsl_info("%s: mirror name '%s'\n", __func__, name);

		/* is there already a mirror instance of this name? */

		lws_start_foreach_ll(struct mirror_instance *, mi1,
				     v->mi_list) {
			count_mi++;
			if (strcmp(name, mi1->name))
				continue;
			/* yes... we will join it */
			lwsl_info("Joining existing mi %p '%s'\n", mi1, name);
			mi = mi1;
			break;
		} lws_end_foreach_ll(mi1, next);

		if (!mi) {

			/* no existing mirror instance for name */
			if (count_mi == MAX_MIRROR_INSTANCES)
				return -1;

			/* create one with this name, and join it */
			mi = malloc(sizeof(*mi));
			if (!mi)
				return 1;
			memset(mi, 0, sizeof(*mi));
			mi->ring = lws_ring_create(sizeof(struct a_message),
						   QUEUELEN,
						   mirror_destroy_message);
			if (!mi->ring) {
				free(mi);
				return 1;
			}

			mi->next = v->mi_list;
			v->mi_list = mi;
			strcpy(mi->name, name);
			mi->rx_enabled = 1;

			lwsl_info("Created new mi %p '%s'\n", mi, name);
		}

		/* add our pss to list of guys bound to this mi */

		pss->same_mi_pss_list = mi->same_mi_pss_list;
		mi->same_mi_pss_list = pss;

		/* init the pss */

		pss->mi = mi;
		pss->tail = lws_ring_get_oldest_tail(mi->ring);
		pss->wsi = wsi;
		break;

	case LWS_CALLBACK_CLOSED:
		/* detach our pss from the mirror instance */
		mi = pss->mi;
		if (!mi)
			break;

		/* remove our closing pss from its mirror instance list */
		lws_start_foreach_llp(struct per_session_data__lws_mirror **,
			ppss, mi->same_mi_pss_list) {
			if (*ppss == pss) {
				*ppss = pss->same_mi_pss_list;
				break;
			}
		} lws_end_foreach_llp(ppss, same_mi_pss_list);

		pss->mi = NULL;

		if (mi->same_mi_pss_list) {
			/*
			 * Still other pss using the mirror instance.  The pss
			 * going away may have had the oldest tail, reconfirm
			 * using the remaining pss what is the current oldest
			 * tail.  If the oldest tail moves on, this call also
			 * will re-enable rx flow control when appropriate.
			 */
			mirror_update_worst_tail(mi);
			break;
		}

		/* No more pss using the mirror instance... delete mi */

		lws_start_foreach_llp(struct mirror_instance **,
				pmi, v->mi_list) {
			if (*pmi != mi)
				continue;

			*pmi = (*pmi)->next;

			lws_ring_destroy(mi->ring);
			free(mi);
			break;
		} lws_end_foreach_llp(pmi, next);

		break;

	case LWS_CALLBACK_CONFIRM_EXTENSION_OKAY:
		return 1; /* disallow compression */

	case LWS_CALLBACK_PROTOCOL_INIT: /* per vhost */
		lws_protocol_vh_priv_zalloc(lws_get_vhost(wsi),
				lws_get_protocol(wsi),
				sizeof(struct per_vhost_data__lws_mirror));
		break;

	case LWS_CALLBACK_SERVER_WRITEABLE:
		oldest_tail = lws_ring_get_oldest_tail(pss->mi->ring);
		update_worst = oldest_tail == pss->tail;
		sent_something = 0;

		lwsl_debug(" original oldest %d, free elements %ld\n",
			   oldest_tail,
			   lws_ring_get_count_free_elements(pss->mi->ring));

		do {
			msg = lws_ring_get_element(pss->mi->ring, &pss->tail);
			if (!msg)
				break;

			if (!msg->payload) {
				lwsl_err("%s: NULL payload: worst = %d,"
					 " pss->tail = %d\n", __func__,
					 oldest_tail, pss->tail);
				if (lws_ring_consume(pss->mi->ring, &pss->tail,
						     NULL, 1))
					continue;
				break;
			}

			n = lws_write(wsi, (unsigned char *)msg->payload +
				      LWS_PRE, msg->len, LWS_WRITE_TEXT);
			if (n < 0) {
				lwsl_info("%s: WRITEABLE: %d\n", __func__, n);

				return -1;
			}
			sent_something = 1;
			lws_ring_consume(pss->mi->ring, &pss->tail, NULL, 1);

		} while (!lws_send_pipe_choked(wsi));

		/* if any left for us to send, ask for writeable again */
		if (lws_ring_get_count_waiting_elements(pss->mi->ring,
							&pss->tail))
			lws_callback_on_writable(wsi);

		if (!sent_something || !update_worst)
			break;

		/*
		 * We are no longer holding the oldest tail (since we sent
		 * something.  So free us of the timeout related to hogging the
		 * oldest tail.
		 */
		lws_set_timeout(pss->wsi, NO_PENDING_TIMEOUT, 0);
		/*
		 * If we were originally at the oldest fifo position of
		 * all the tails, now we used some up we may have
		 * changed the oldest fifo position and made some space.
		 */
		mirror_update_worst_tail(pss->mi);
		break;

	case LWS_CALLBACK_RECEIVE:
		n = lws_ring_get_count_free_elements(pss->mi->ring);
		if (!n) {
			lwsl_notice("dropping!\n");
			if (pss->mi->rx_enabled)
				mirror_rxflow_instance(pss->mi, 0);
			goto req_writable;
		}

		amsg.payload = malloc(LWS_PRE + len);
		amsg.len = len;
		if (!amsg.payload) {
			lwsl_notice("OOM: dropping\n");
			break;
		}
		memcpy((char *)amsg.payload + LWS_PRE, in, len);
		if (!lws_ring_insert(pss->mi->ring, &amsg, 1)) {
			mirror_destroy_message(&amsg);
			lwsl_notice("dropping!\n");
			if (pss->mi->rx_enabled)
				mirror_rxflow_instance(pss->mi, 0);
			goto req_writable;
		}

		if (pss->mi->rx_enabled &&
		    lws_ring_get_count_free_elements(pss->mi->ring) < RXFLOW_MIN)
			mirror_rxflow_instance(pss->mi, 0);

req_writable:
		mirror_callback_all_in_mi_on_writable(pss->mi);
		break;

	default:
		break;
	}

	return 0;
}

#define LWS_PLUGIN_PROTOCOL_MIRROR { \
		"lws-mirror-protocol", \
		callback_lws_mirror, \
		sizeof(struct per_session_data__lws_mirror), \
		128, /* rx buf size must be >= permessage-deflate rx size */ \
	}

#if !defined (LWS_PLUGIN_STATIC)

static const struct lws_protocols protocols[] = {
	LWS_PLUGIN_PROTOCOL_MIRROR
};

LWS_EXTERN LWS_VISIBLE int
init_protocol_lws_mirror(struct lws_context *context,
			     struct lws_plugin_capability *c)
{
	if (c->api_magic != LWS_PLUGIN_API_MAGIC) {
		lwsl_err("Plugin API %d, library API %d", LWS_PLUGIN_API_MAGIC,
			 c->api_magic);
		return 1;
	}

	c->protocols = protocols;
	c->count_protocols = ARRAY_SIZE(protocols);
	c->extensions = NULL;
	c->count_extensions = 0;

	return 0;
}

LWS_EXTERN LWS_VISIBLE int
destroy_protocol_lws_mirror(struct lws_context *context)
{
	return 0;
}
#endif
