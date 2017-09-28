/*
 * lib/hpack.c
 *
 * Copyright (C) 2014-2017 Andy Green <andy@warmcat.com>
 *
 *  This library is free software; you can redistribute it and/or
 *  modify it under the terms of the GNU Lesser General Public
 *  License as published by the Free Software Foundation:
 *  version 2.1 of the License.
 *
 *  This library is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 *  Lesser General Public License for more details.
 *
 *  You should have received a copy of the GNU Lesser General Public
 *  License along with this library; if not, write to the Free Software
 *  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston,
 *  MA  02110-1301  USA
 */

#include "private-libwebsockets.h"

/*
 * Official static header table for HPACK
 *        +-------+-----------------------------+---------------+
          | 1     | :authority                  |               |
          | 2     | :method                     | GET           |
          | 3     | :method                     | POST          |
          | 4     | :path                       | /             |
          | 5     | :path                       | /index.html   |
          | 6     | :scheme                     | http          |
          | 7     | :scheme                     | https         |
          | 8     | :status                     | 200           |
          | 9     | :status                     | 204           |
          | 10    | :status                     | 206           |
          | 11    | :status                     | 304           |
          | 12    | :status                     | 400           |
          | 13    | :status                     | 404           |
          | 14    | :status                     | 500           |
          | 15    | accept-charset              |               |
          | 16    | accept-encoding             | gzip, deflate |
          | 17    | accept-language             |               |
          | 18    | accept-ranges               |               |
          | 19    | accept                      |               |
          | 20    | access-control-allow-origin |               |
          | 21    | age                         |               |
          | 22    | allow                       |               |
          | 23    | authorization               |               |
          | 24    | cache-control               |               |
          | 25    | content-disposition         |               |
          | 26    | content-encoding            |               |
          | 27    | content-language            |               |
          | 28    | content-length              |               |
          | 29    | content-location            |               |
          | 30    | content-range               |               |
          | 31    | content-type                |               |
          | 32    | cookie                      |               |
          | 33    | date                        |               |
          | 34    | etag                        |               |
          | 35    | expect                      |               |
          | 36    | expires                     |               |
          | 37    | from                        |               |
          | 38    | host                        |               |
          | 39    | if-match                    |               |
          | 40    | if-modified-since           |               |
          | 41    | if-none-match               |               |
          | 42    | if-range                    |               |
          | 43    | if-unmodified-since         |               |
          | 44    | last-modified               |               |
          | 45    | link                        |               |
          | 46    | location                    |               |
          | 47    | max-forwards                |               |
          | 48    | proxy-authenticate          |               |
          | 49    | proxy-authorization         |               |
          | 50    | range                       |               |
          | 51    | referer                     |               |
          | 52    | refresh                     |               |
          | 53    | retry-after                 |               |
          | 54    | server                      |               |
          | 55    | set-cookie                  |               |
          | 56    | strict-transport-security   |               |
          | 57    | transfer-encoding           |               |
          | 58    | user-agent                  |               |
          | 59    | vary                        |               |
          | 60    | via                         |               |
          | 61    | www-authenticate            |               |
          +-------+-----------------------------+---------------+
*/

static const unsigned char static_token[] = {
	0,
	WSI_TOKEN_HTTP_COLON_AUTHORITY,
	WSI_TOKEN_HTTP_COLON_METHOD,
	WSI_TOKEN_HTTP_COLON_METHOD,
	WSI_TOKEN_HTTP_COLON_PATH,
	WSI_TOKEN_HTTP_COLON_PATH,
	WSI_TOKEN_HTTP_COLON_SCHEME,
	WSI_TOKEN_HTTP_COLON_SCHEME,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_COLON_STATUS,
	WSI_TOKEN_HTTP_ACCEPT_CHARSET,
	WSI_TOKEN_HTTP_ACCEPT_ENCODING,
	WSI_TOKEN_HTTP_ACCEPT_LANGUAGE,
	WSI_TOKEN_HTTP_ACCEPT_RANGES,
	WSI_TOKEN_HTTP_ACCEPT,
	WSI_TOKEN_HTTP_ACCESS_CONTROL_ALLOW_ORIGIN,
	WSI_TOKEN_HTTP_AGE,
	WSI_TOKEN_HTTP_ALLOW,
	WSI_TOKEN_HTTP_AUTHORIZATION,
	WSI_TOKEN_HTTP_CACHE_CONTROL,
	WSI_TOKEN_HTTP_CONTENT_DISPOSITION,
	WSI_TOKEN_HTTP_CONTENT_ENCODING,
	WSI_TOKEN_HTTP_CONTENT_LANGUAGE,
	WSI_TOKEN_HTTP_CONTENT_LENGTH,
	WSI_TOKEN_HTTP_CONTENT_LOCATION,
	WSI_TOKEN_HTTP_CONTENT_RANGE,
	WSI_TOKEN_HTTP_CONTENT_TYPE,
	WSI_TOKEN_HTTP_COOKIE,
	WSI_TOKEN_HTTP_DATE,
	WSI_TOKEN_HTTP_ETAG,
	WSI_TOKEN_HTTP_EXPECT,
	WSI_TOKEN_HTTP_EXPIRES,
	WSI_TOKEN_HTTP_FROM,
	WSI_TOKEN_HOST,
	WSI_TOKEN_HTTP_IF_MATCH,
	WSI_TOKEN_HTTP_IF_MODIFIED_SINCE,
	WSI_TOKEN_HTTP_IF_NONE_MATCH,
	WSI_TOKEN_HTTP_IF_RANGE,
	WSI_TOKEN_HTTP_IF_UNMODIFIED_SINCE,
	WSI_TOKEN_HTTP_LAST_MODIFIED,
	WSI_TOKEN_HTTP_LINK,
	WSI_TOKEN_HTTP_LOCATION,
	WSI_TOKEN_HTTP_MAX_FORWARDS,
	WSI_TOKEN_HTTP_PROXY_AUTHENTICATE,
	WSI_TOKEN_HTTP_PROXY_AUTHORIZATION,
	WSI_TOKEN_HTTP_RANGE,
	WSI_TOKEN_HTTP_REFERER,
	WSI_TOKEN_HTTP_REFRESH,
	WSI_TOKEN_HTTP_RETRY_AFTER,
	WSI_TOKEN_HTTP_SERVER,
	WSI_TOKEN_HTTP_SET_COOKIE,
	WSI_TOKEN_HTTP_STRICT_TRANSPORT_SECURITY,
	WSI_TOKEN_HTTP_TRANSFER_ENCODING,
	WSI_TOKEN_HTTP_USER_AGENT,
	WSI_TOKEN_HTTP_VARY,
	WSI_TOKEN_HTTP_VIA,
	WSI_TOKEN_HTTP_WWW_AUTHENTICATE,
};

/* some of the entries imply values as well as header names */

static const char * const http2_canned[] = {
	"",
	"",
	"GET",
	"POST",
	"/",
	"/index.html",
	"http",
	"https",
	"200",
	"204",
	"206",
	"304",
	"400",
	"404",
	"500",
	"",
	"gzip, deflate"
};

/* see minihuf.c */

#include "huftable.h"

static int huftable_decode(int pos, char c)
{
	int q = pos + !!c;

	if (lextable_terms[q >> 3] & (1 << (q & 7))) /* terminal */
		return lextable[q] | 0x8000;

	return pos + (lextable[q] << 1);
}

static int lws_hpack_update_table_size(struct lws *wsi, int idx)
{
	lwsl_info("hpack set table size %d\n", idx);
	return 0;
}

static int lws_frag_start(struct lws *wsi, int hdr_token_idx)
{
	struct allocated_headers *ah = wsi->u.http2.http.ah;

	lwsl_debug("%s: token %d ah->pos = %d, ah->nfrag = %d\n", __func__, hdr_token_idx, ah->pos, ah->nfrag);

	if (!hdr_token_idx) {
		lwsl_err("%s: zero hdr_token_idx\n", __func__);
		return 1;
	}

	if (ah->nfrag >= ARRAY_SIZE(ah->frag_index)) {
		lwsl_err("%s: frag index %d too big\n", __func__, ah->nfrag);
		return 1;
	}

	if (ah->nfrag == 0)
		ah->nfrag = 1;

	ah->frags[ah->nfrag].offset = ah->pos;
	ah->frags[ah->nfrag].len = 0;
	ah->frags[ah->nfrag].nfrag = 0;

	ah->frag_index[hdr_token_idx] = ah->nfrag;

	return 0;
}

static int lws_frag_append(struct lws *wsi, unsigned char c)
{
	struct allocated_headers * ah = wsi->u.http2.http.ah;

	ah->data[ah->pos++] = c;
	ah->frags[ah->nfrag].len++;

	return ah->pos >= wsi->context->max_http_header_data;
}

static int lws_frag_end(struct lws *wsi)
{
	lwsl_debug("%s\n", __func__);
	if (lws_frag_append(wsi, 0))
		return 1;

	wsi->u.http2.http.ah->nfrag++;
	return 0;
}

static void lws_dump_header(struct lws *wsi, int hdr)
{
	char s[200];
	int len;

	if (hdr == LWS_HPACK_IGNORE_ENTRY) {
		lwsl_notice("hdr tok ignored\n");
		return;
	}

	len = lws_hdr_copy(wsi, s, sizeof(s) - 1, hdr);
	s[len] = '\0';
	lwsl_debug("  hdr tok %d (%s) = '%s' (len %d)\n", hdr, lws_token_to_string(hdr), s, len);
}

/*
 * returns 0 if dynamic entry (arg and len are filled)
 * returns -1 if failure
 * returns nonzero token index if actually static token
 */
static int
lws_token_from_index(struct lws *wsi, int index, char **arg, int *len)
{
	struct hpack_dynamic_table *dyn;

	if (index == LWS_HPACK_IGNORE_ENTRY)
		return LWS_HPACK_IGNORE_ENTRY;

	/* dynamic table only belongs to network wsi */
	wsi = lws_http2_get_network_wsi(wsi);
	if (!wsi->u.http2.h2n)
		return -1;
	dyn = &wsi->u.http2.h2n->hpack_dyn_table;

	if (index < ARRAY_SIZE(static_token))
		return static_token[index];

	if (!dyn) {
		lwsl_notice("no dynamic table\n");
		return -1;
	}

	index -= ARRAY_SIZE(static_token);
	if (index >= dyn->used_entries) {
		lwsl_debug("  %s: adjusted index %d >= %d", __func__, index,
			    dyn->num_entries);
		return -1;
	}

	index = (index + dyn->pos) % dyn->num_entries;

	if (arg && len) {
		*arg = dyn->entries[index].value;
		*len = dyn->entries[index].value_len;
	}

	return dyn->entries[index].lws_hdr_idx;
}

static int
lws_dynamic_token_insert(struct lws *wsi, int lws_hdr_index, char *arg, int len)
{
	struct hpack_dynamic_table *dyn;
	int new_index;

	/* dynamic table only belongs to network wsi */
	wsi = lws_http2_get_network_wsi(wsi);
	if (!wsi->u.http2.h2n)
		return 1;
	dyn = &wsi->u.http2.h2n->hpack_dyn_table;

	if (!dyn->entries) {
		lwsl_err("%s: unsized dyn table\n", __func__);

		return 1;
	}

	new_index = dyn->used_entries;
	if (dyn->num_entries && dyn->used_entries == dyn->num_entries) {
		/* we have to drop the oldest to make space */

		new_index = (dyn->pos + dyn->num_entries - 1) % dyn->num_entries;

		lws_free_set_NULL(dyn->entries[new_index].value);
		dyn->entries[new_index].value_len = 0;
		dyn->pos = (dyn->pos + 1) % dyn->num_entries;
	}

	if (dyn->used_entries < dyn->num_entries)
		dyn->used_entries++;

	dyn->entries[new_index].value_len = 0;

	if (lws_hdr_index != LWS_HPACK_IGNORE_ENTRY) {
		dyn->entries[new_index].value = lws_malloc(len + 1);
		if (!dyn->entries[new_index].value)
			return 1;

		memcpy(dyn->entries[new_index].value, arg, len);
		dyn->entries[new_index].value[len] = '\0';
		dyn->entries[new_index].value_len = len;
	} else
		dyn->entries[new_index].value = NULL;

	dyn->entries[new_index].lws_hdr_idx = lws_hdr_index;

	lwsl_debug("%s: index %ld: lws_hdr_index 0x%x, '%s' len %d\n", __func__,
			(long)new_index + ARRAY_SIZE(static_token), lws_hdr_index,
			dyn->entries[new_index].value, len);

	return 0;
}

int
lws_hpack_dynamic_size(struct lws *wsi, int size)
{
	struct hpack_dynamic_table *dyn;
	struct hpack_dt_entry *dte;
	int min = size, n = 0;

	wsi = lws_http2_get_network_wsi(wsi);
	if (!wsi->u.http2.h2n)
		return 1;

	dyn = &wsi->u.http2.h2n->hpack_dyn_table;

	if (dyn->num_entries < min)
		min = dyn->num_entries;

	dte = lws_zalloc(sizeof(*dte) * size);
	if (!dte)
		return 1;

	if (dyn->entries) {
		for (n = 0; n < min; n++)
			dte[n] = dyn->entries[(dyn->pos + n) % dyn->num_entries];

		lws_free(dyn->entries);
	}
	dyn->entries = dte;
	dyn->num_entries = size;
	dyn->pos = 0;

	return 0;
}

void
lws_hpack_destroy_dynamic_header(struct lws *wsi)
{
	struct hpack_dynamic_table *dyn;
	int n;

	if (!wsi->u.http2.h2n)
		return;

	dyn = &wsi->u.http2.h2n->hpack_dyn_table;

	if (!dyn->entries)
		return;

	for (n = 0; n < dyn->num_entries; n++)
		if (dyn->entries[n].value)
			lws_free_set_NULL(dyn->entries[n].value);

	lws_free_set_NULL(dyn->entries);
}

static int
lws_hpack_use_indexed_hdr(struct lws *wsi, int idx, int known_token)
{
	char *arg = NULL;
	int len;
	const char *p = NULL;
	int tok = lws_token_from_index(wsi, idx, &arg, &len);

	if (arg) {
		/* dynamic result */
		lwsl_debug("%s: got dyn result idx %d '%s'\n", __func__, idx, arg);
		tok = known_token;
	} else
		lwsl_debug("writing indexed hdr %d (tok %d '%s')\n", idx, tok,
				lws_token_to_string(tok));

	if (!tok)
		return 0;

	if (arg)
		p = arg;

	if (idx < ARRAY_SIZE(http2_canned))
		p = http2_canned[idx];


	if (lws_frag_start(wsi, tok))
		return 1;

	if (p)
		while (*p)
			if (lws_frag_append(wsi, *p++))
				return 1;

	if (lws_frag_end(wsi))
		return 1;

	lws_dump_header(wsi, tok);

	return 0;
}

int lws_hpack_interpret(struct lws *wsi, unsigned char c)
{
	struct lws *nwsi = lws_http2_get_network_wsi(wsi);
	struct lws_http2_netconn *h2n;
	struct allocated_headers *ah = wsi->u.http2.http.ah;
	unsigned int prev;
	unsigned char c1;
	int n, m;

	h2n = nwsi->u.http2.h2n;
	if (!h2n)
		return -1;

	//lwsl_debug("   state %d\n", wsi->u.http2.hpack);

	switch (h2n->hpack) {

	case HPKS_OPT_PADDING:
		h2n->padding = c;
		lwsl_info("padding %d\n", c);
		if (h2n->flags & LWS_HTTP2_FLAG_PRIORITY) {
			h2n->hpack = HKPS_OPT_E_DEPENDENCY;
			h2n->hpack_m = 4;
		} else
			h2n->hpack = HPKS_TYPE;
		break;

	case HKPS_OPT_E_DEPENDENCY:
		h2n->hpack_e_dep <<= 8;
		h2n->hpack_e_dep |= c;
		if (! --h2n->hpack_m) {
			lwsl_info("hpack_e_dep = 0x%x\n", h2n->hpack_e_dep);
			h2n->hpack = HKPS_OPT_WEIGHT;
		}
		break;

	case HKPS_OPT_WEIGHT:
		/* weight */
		h2n->hpack = HPKS_TYPE;
		break;

	case HPKS_TYPE:
		if (h2n->count > (h2n->length - h2n->padding)) {
			lwsl_info("padding eat\n");
			break;
		}
		/*
		 * 	HPKT_INDEXED_HDR_7		1xxxxxxx: just "header field"
		 * 	HPKT_INDEXED_HDR_6_VALUE_INCR   01xxxxxx: NEW indexed hdr with value
		 * 	HPKT_LITERAL_HDR_VALUE_INCR	01000000: NEW literal hdr with value
		 * 	HPKT_INDEXED_HDR_4_VALUE	0000xxxx: indexed hdr with value
		 * 	HPKT_INDEXED_HDR_4_VALUE_NEVER 	0001xxxx: NEVER NEW indexed hdr with value
		 * 	HPKT_LITERAL_HDR_VALUE		00000000: literal hdr with value
		 * 	HPKT_LITERAL_HDR_VALUE_NEVER	00010000: NEVER NEW literal hdr with value
		 */

		if (c & 0x80) { /* indexed header field only */
			/* just a possibly-extended integer */
			h2n->hpack_type = HPKT_INDEXED_HDR_7;
			lwsl_debug("HPKT_INDEXED_HDR_7 setting header_index %d\n", c & 0x7f);
			h2n->header_index = c & 0x7f;
			if ((c & 0x7f) == 0x7f) {
				h2n->hpack_len = c & 0x7f;
				h2n->hpack_m = 0;
				h2n->hpack = HPKS_IDX_EXT;
				break;
			}
			lwsl_debug("HPKT_INDEXED_HDR_7: writing indexed hdr %d\n", c & 0x7f);
			if (lws_hpack_use_indexed_hdr(wsi, c & 0x7f, h2n->header_index))
				return 1;
			/* stay at same state */
			break;
		}
		if (c & 0x40) { /* literal header incr idx */
			/*
			 * [possibly-extended hdr idx (6) | new literal hdr name]
			 * H + possibly-extended value length
			 * literal value
			 */
			lwsl_debug("HKPS_TYPE 2 setting INCR IDX header_index %d\n", 0);
			h2n->header_index = 0;
			if (c == 0x40) { /* literal name */
				lwsl_debug("   HPKT_LITERAL_HDR_VALUE_INCR\n");
				h2n->hpack_type = HPKT_LITERAL_HDR_VALUE_INCR;
				h2n->value = 0;
				h2n->hpack = HPKS_HLEN;
				break;
			}
			/* indexed name */
			h2n->hpack_type = HPKT_INDEXED_HDR_6_VALUE_INCR;
			lwsl_debug("   HPKT_INDEXED_HDR_6_VALUE_INCR\n");
			if ((c & 0x3f) == 0x3f) {
				h2n->hpack_len = c & 0x3f;
				h2n->hpack_m = 0;
				h2n->hpack = HPKS_IDX_EXT;
				break;
			}

			lwsl_debug("HKPS_TYPE 3 setting header_index %d\n", c & 0x3f);
			h2n->header_index = c & 0x3f;
			h2n->value = 1;
			h2n->hpack = HPKS_HLEN;
			break;
		}
		switch(c & 0xf0) {
		case 0x10: /* literal header never index */
		case 0: /* literal header without indexing */
			/*
			 * follows 0x40 except 4-bit hdr idx
			 * and don't add to index
			 */
			if (c == 0) { /* literal name */
				h2n->hpack_type = HPKT_LITERAL_HDR_VALUE;
				lwsl_debug("   HPKT_LITERAL_HDR_VALUE\n");
				h2n->hpack = HPKS_HLEN;
				h2n->value = 0;
				break;
			}
			if (c == 0x10) { /* literal name NEVER */
				h2n->hpack_type = HPKT_LITERAL_HDR_VALUE_NEVER;
				lwsl_debug("   HPKT_LITERAL_HDR_VALUE_NEVER\n");
				h2n->hpack = HPKS_HLEN;
				h2n->value = 0;
				break;
			}
			lwsl_debug("indexed\n");
			/* indexed name */
			if (c & 0x10) {
				h2n->hpack_type = HPKT_INDEXED_HDR_4_VALUE_NEVER;
				lwsl_debug("   HPKT_LITERAL_HDR_4_VALUE_NEVER\n");
			} else {
				h2n->hpack_type = HPKT_INDEXED_HDR_4_VALUE;
				lwsl_debug("   HPKT_INDEXED_HDR_4_VALUE\n");
			}
			h2n->header_index = 0;
			if ((c & 0xf) == 0xf) {
				h2n->hpack_len = c & 0xf;
				h2n->hpack_m = 0;
				h2n->hpack = HPKS_IDX_EXT;
				break;
			}
			h2n->header_index = c & 0xf;
			h2n->value = 1;
			h2n->hpack = HPKS_HLEN;
			break;

		case 0x20:
		case 0x30: /* header table size update */
			/* possibly-extended size value (5) */
			lwsl_debug("HPKT_SIZE_5\n");
			h2n->hpack_type = HPKT_SIZE_5;
			if ((c & 0x1f) == 0x1f) {
				h2n->hpack_len = c & 0x1f;
				h2n->hpack_m = 0;
				h2n->hpack = HPKS_IDX_EXT;
				break;
			}
			lws_hpack_update_table_size(wsi, c & 0x1f);
			/* stay at HPKS_TYPE state */
			break;
		}
		break;

	case HPKS_IDX_EXT:
		h2n->hpack_len += (c & 0x7f) << h2n->hpack_m;
		h2n->hpack_m += 7;
		if (!(c & 0x80)) {
			switch (h2n->hpack_type) {
			case HPKT_INDEXED_HDR_7:
				//lwsl_err("HKPS_IDX_EXT hdr idx %d\n", wsi->u.http2.hpack_len);
				if (lws_hpack_use_indexed_hdr(wsi, h2n->hpack_len, h2n->header_index))
					return 1;
				h2n->hpack = HPKS_TYPE;
				break;
			default:
				// lwsl_err("HKPS_IDX_EXT setting header_index %d\n",
				//		wsi->u.http2.hpack_len);
				h2n->header_index = h2n->hpack_len;
				h2n->value = 1;
				h2n->hpack = HPKS_HLEN;
				break;
			}
		}
		break;

	case HPKS_HLEN: /* [ H | 7+ ] */
		h2n->huff = !!(c & 0x80);
		h2n->hpack_pos = 0;
		h2n->hpack_len = c & 0x7f;
		if (h2n->hpack_len < 0x7f) {

pre_data:
			if (h2n->value && h2n->header_index) {
				if (h2n->hpack_type == HPKT_LITERAL_HDR_VALUE)
					n = h2n->header_index;
				else
					n = lws_token_from_index(wsi, h2n->header_index,
							 NULL, NULL);

				if (n == LWS_HPACK_IGNORE_ENTRY)
					h2n->header_index = LWS_HPACK_IGNORE_ENTRY;
				lwsl_debug("  lws_token_from_index for %d says %d\n", h2n->header_index, n);
				if (n != LWS_HPACK_IGNORE_ENTRY && lws_frag_start(wsi, n))
					return 1;
			} else {
				wsi->u.hdr.parser_state = WSI_TOKEN_NAME_PART;
				wsi->u.hdr.lextable_pos = 0;
				h2n->unknown_header = 0;
			}

			h2n->hpack = HPKS_DATA;
			break;
		}
		h2n->hpack_m = 0;
		h2n->hpack = HPKS_HLEN_EXT;
		break;

	case HPKS_HLEN_EXT:
		h2n->hpack_len += (c & 0x7f) << h2n->hpack_m;
		h2n->hpack_m += 7;
		if (!(c & 0x80))
			goto pre_data;

		break;

	case HPKS_DATA:
		for (n = 0; n < 8; n++) {
			c1 = c;
			if (h2n->huff) {
				prev = h2n->hpack_pos;
				h2n->hpack_pos = huftable_decode(
						h2n->hpack_pos, (c >> 7) & 1);
				c <<= 1;
				if (h2n->hpack_pos == 0xffff)
					return 1;
				if (!(h2n->hpack_pos & 0x8000))
					continue;
				c1 = h2n->hpack_pos & 0x7fff;
				h2n->hpack_pos = 0;

				if (!c1 && prev == HUFTABLE_0x100_PREV) {
					; /* EOT */
				}
			} else
				n = 8;

			if (h2n->value) { /* value */
				if (h2n->header_index && h2n->header_index != LWS_HPACK_IGNORE_ENTRY)
					if (lws_frag_append(wsi, c1))
						return 1;
			} else {
				/*
				 * Convert name using existing parser,
			 	 * If h2n->unknown_header == 0, result is
			 	 * in wsi->u.hdr.parser_state
			 	 * using WSI_TOKEN_GET_URI + ordinals.
			 	 *
			 	 * If unknown header h2n->unknown_header
			 	 * will be set.
			 	 */
				lwsl_debug("parser: %c\n", c1);
				if (!h2n->unknown_header && lws_parse(wsi, c1))
					h2n->unknown_header = 1;
			}
		}

		if (--h2n->hpack_len == 0) {

			if (!h2n->value && h2n->hpack_type == HPKT_LITERAL_HDR_VALUE) {
				h2n->header_index = LWS_HPACK_IGNORE_ENTRY;
				if (wsi->u.hdr.parser_state == WSI_TOKEN_NAME_PART ||
				    wsi->u.hdr.parser_state == WSI_TOKEN_SKIPPING)
					h2n->unknown_header = 1;
				if (!h2n->unknown_header)
					h2n->header_index = wsi->u.hdr.parser_state;

				lwsl_debug("header index 0x%x\n", h2n->header_index);
			}

			/* we have the payload */
			if (h2n->value) {
				switch (h2n->hpack_type) {
				/*
				 * These are the only two that insert to the dyntable
				 */
				case HPKT_INDEXED_HDR_6_VALUE_INCR: /* NEW indexed hdr with value */
					m = lws_token_from_index(wsi, h2n->header_index, NULL, NULL);
					goto add_it;
				case HPKT_LITERAL_HDR_VALUE_INCR:   /* NEW literal hdr with value */
					if (h2n->unknown_header)
						m = LWS_HPACK_IGNORE_ENTRY;
					else
						m = wsi->u.hdr.parser_state;
	add_it:
					if (lws_dynamic_token_insert(wsi, m,
							&ah->data[ah->frags[ah->nfrag].offset],
							ah->frags[ah->nfrag].len))
						return 1;
					break;
				default:
					break;
				}
			}

			n = 8;
			if (h2n->value) {
				if (h2n->header_index != LWS_HPACK_IGNORE_ENTRY && lws_frag_end(wsi))
					return 1;

				lws_dump_header(wsi, lws_token_from_index(
						wsi, h2n->header_index,
						NULL, NULL));
				if (h2n->count + h2n->padding == h2n->length)
					h2n->hpack = HKPS_OPT_DISCARD_PADDING;
				else
					h2n->hpack = HPKS_TYPE;
			} else { /* name */
				//if (wsi->u.hdr.parser_state < WSI_TOKEN_COUNT)

				h2n->value = 1;
				h2n->hpack = HPKS_HLEN;
			}
		}
		break;
	case HKPS_OPT_DISCARD_PADDING:
		lwsl_info("eating padding %x\n", c);
		if (! --h2n->padding)
			h2n->hpack = HPKS_TYPE;
		break;
	}

	return 0;
}

static int lws_http2_num(int starting_bits, unsigned long num,
			 unsigned char **p, unsigned char *end)
{
	int mask = (1 << starting_bits) - 1;

	if (num < mask) {
		*((*p)++) |= num;
		return *p >= end;
	}

	*((*p)++) |= mask;
	if (*p >= end)
		return 1;

	num -= mask;
	while (num >= 128) {
		*((*p)++) = 0x80 | (num & 0x7f);
		if (*p >= end)
			return 1;
		num >>= 7;
	}

	return 0;
}

int lws_add_http2_header_by_name(struct lws *wsi, const unsigned char *name,
				 const unsigned char *value, int length,
				 unsigned char **p, unsigned char *end)
{
	int len;

	lwsl_debug("%s: %p  %s:%s\n", __func__, *p, name, value);

	len = strlen((char *)name);
	if (len)
		if (name[len - 1] == ':')
			len--;

	if (end - *p < len + length + 8)
		return 1;

	*((*p)++) = 0; /* not indexed, literal name */

	**p = 0; /* non-HUF */
	if (lws_http2_num(7, len, p, end))
		return 1;
	memcpy(*p, name, len);
	*p += len;

	*(*p) = 0; /* non-HUF */
	if (lws_http2_num(7, length, p, end))
		return 1;

	memcpy(*p, value, length);
	*p += length;

	return 0;
}

int lws_add_http2_header_by_token(struct lws *wsi, enum lws_token_indexes token,
				  const unsigned char *value, int length,
				  unsigned char **p, unsigned char *end)
{
	const unsigned char *name;

	name = lws_token_to_string(token);
	if (!name)
		return 1;

	return lws_add_http2_header_by_name(wsi, name, value, length, p, end);
}

int lws_add_http2_header_status(struct lws *wsi, unsigned int code,
				unsigned char **p, unsigned char *end)
{
	unsigned char status[10];
	int n;

	wsi->u.http2.send_END_STREAM = 0; // !!(code >= 400);

	n = sprintf((char *)status, "%u", code);
	if (lws_add_http2_header_by_token(wsi, WSI_TOKEN_HTTP_COLON_STATUS,
					  status, n, p, end))

		return 1;

	return 0;
}
