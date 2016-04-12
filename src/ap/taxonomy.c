/*
 * hostapd / Client taxonomy
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

/*
 * Parse a series of IEs, as in Probe or Association packets,
 * and render them to a descriptive string. The tag number of
 * standard options is written to the string, while the vendor
 * ID and subtag are written for vendor options.
 *
 * Example strings:
 * 0,1,50,45,221(00904c,51)
 * 0,1,33,36,48,45,221(00904c,51),221(0050f2,2)
 */

#include "includes.h"

#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include "common/wpa_ctrl.h"
#include "utils/includes.h"
#include "utils/common.h"
#include "hostapd.h"
#include "sta_info.h"

/* Copy a string with no funny schtuff allowed; only alphanumerics. */
static void no_mischief_strncpy(char *dst, const char *src, size_t n)
{
	size_t i;
	for (i = 0; i < n; i++) {
		unsigned char s = src[i];
		int is_lower = (s >= 'a' && s <= 'z');
		int is_upper = (s >= 'A' && s <= 'Z');
		int is_digit = (s >= '0' && s <= '9');
		if (is_lower || is_upper || is_digit) {
			/* TODO: if any manufacturer uses Unicode within the
			 * WPS header, it will get mangled here. */
			dst[i] = s;
		} else {
			/* note that even spaces will be transformed to underscores,
			 * so 'Nexus 7' will turn into 'Nexus_7'. This is deliberate,
			 * to make the string easier to parse. */
			dst[i] = '_';
		}
	}
}

static int get_wps_name(char *name, size_t name_len,
		const u8 *data, size_t data_len)
{
	/* Inside the WPS IE are a series of sub-IEs, using two byte IDs
	 * and two byte lengths. We're looking for the model name, if
	 * present. */
	while (data_len >= 4) {
		u16 id, elen;
		id = (data[0] << 8) | data[1];
		elen = (data[2] << 8) | data[3];
		data += 4;
		data_len -= 4;

		if (elen > data_len) {
			return 0;
		}

		if (id == 0x1023) {
			/* Model name, like 'Nexus 7' */
			size_t n = (elen < name_len) ? elen : name_len;
			no_mischief_strncpy(name, (const char *)data, n);
			return n;
		}

		data += elen;
		data_len -= elen;
	}

	return 0;
}

static void ie_to_string(char *fstr, size_t fstr_len,
                         const u8 *ie, size_t ie_len)
{
	size_t flen = fstr_len - 1;
	char htcap[7 + 4 + 1];  // ",htcap:" + %04hx + trailing NUL
	char htagg[7 + 2 + 1];  // ",htagg:" + %02hx + trailing NUL
	char htmcs[7 + 8 + 1];  // ",htmcs:" + %08x + trailing NUL
	char vhtcap[8 + 8 + 1];  // ",vhtcap:" + %08x + trailing NUL
	char vhtrxmcs[10 + 8 + 1];  // ",vhtrxmcs:" + %08x + trailing NUL
	char vhttxmcs[10 + 8 + 1];  // ",vhttxmcs:" + %08x + trailing NUL
	#define MAX_EXTCAP	254
	char extcap[8 + (2 * MAX_EXTCAP) + 1];  // ",extcap:" + hex + trailing NUL
	char txpow[7 + 4 + 1];  // ",txpow:" + %04hx + trailing NUL
	#define WPS_NAME_LEN		32
	char wps[WPS_NAME_LEN + 5 + 1];  // room to prepend ",wps:" + trailing NUL
	int num = 0;

	memset(htcap, 0, sizeof(htcap));
	memset(htagg, 0, sizeof(htagg));
	memset(htmcs, 0, sizeof(htmcs));
	memset(vhtcap, 0, sizeof(vhtcap));
	memset(vhtrxmcs, 0, sizeof(vhtrxmcs));
	memset(vhttxmcs, 0, sizeof(vhttxmcs));
	memset(extcap, 0, sizeof(extcap));
	memset(txpow, 0, sizeof(txpow));
	memset(wps, 0, sizeof(wps));
	fstr[0] = '\0';

	while (ie_len >= 2) {
		u8 id, elen;
		char tagbuf[32];
		char *sep = (num++ == 0) ? "" : ",";

		id = *ie++;
		elen = *ie++;
		ie_len -= 2;

		if (elen > ie_len) {
			break;
		}

		if ((id == 221) && (elen >= 4)) {
			/* Vendor specific */
			int is_MSFT = (ie[0] == 0x00 && ie[1] == 0x50 && ie[2] == 0xf2);
			if (is_MSFT && ie[3] == 0x04) {
				/* WPS */
				char model_name[WPS_NAME_LEN + 1];
				const u8 *data = &ie[4];
				size_t data_len = elen - 4;
				memset(model_name, 0, sizeof(model_name));
				if (get_wps_name(model_name, WPS_NAME_LEN, data, data_len)) {
					snprintf(wps, sizeof(wps), ",wps:%s", model_name);
				}
			}

			snprintf(tagbuf, sizeof(tagbuf), "%s%d(%02x%02x%02x,%d)",
			         sep, id, ie[0], ie[1], ie[2], ie[3]);
		} else {
			if ((id == 45) && (elen >= 2)) {
				/* HT Capabilities (802.11n) */
				u16 cap;
				memcpy(&cap, ie, sizeof(cap));
				snprintf(htcap, sizeof(htcap), ",htcap:%04hx",
				         le_to_host16(cap));
			}
			if ((id == 45) && (elen >= 3)) {
				/* HT Capabilities (802.11n), A-MPDU information */
				u8 agg;
				memcpy(&agg, ie + 2, sizeof(agg));
				snprintf(htagg, sizeof(htagg), ",htagg:%02hx", (u16)agg);
			}
			if ((id == 45) && (elen >= 7)) {
				/* HT Capabilities (802.11n), MCS information */
				u32 mcs;
				memcpy(&mcs, ie + 3, sizeof(mcs));
				snprintf(htmcs, sizeof(htmcs), ",htmcs:%08hx",
						(u16)le_to_host32(mcs));
			}
			if ((id == 191) && (elen >= 4)) {
				/* VHT Capabilities (802.11ac) */
				u32 cap;
				memcpy(&cap, ie, sizeof(cap));
				snprintf(vhtcap, sizeof(vhtcap), ",vhtcap:%08x",
				         le_to_host32(cap));
			}
			if ((id == 191) && (elen >= 8)) {
				/* VHT Capabilities (802.11ac), RX MCS information */
				u32 mcs;
				memcpy(&mcs, ie + 4, sizeof(mcs));
				snprintf(vhtrxmcs, sizeof(vhtrxmcs), ",vhtrxmcs:%08x",
				         le_to_host32(mcs));
			}
			if ((id == 191) && (elen >= 12)) {
				/* VHT Capabilities (802.11ac), TX MCS information */
				u32 mcs;
				memcpy(&mcs, ie + 8, sizeof(mcs));
				snprintf(vhttxmcs, sizeof(vhttxmcs), ",vhttxmcs:%08x",
				         le_to_host32(mcs));
			}
			if (id == 127) {
				/* Extended Capabilities */
				int i;
				int len = (elen < MAX_EXTCAP) ? elen : MAX_EXTCAP;
				char *p = extcap;

				p += snprintf(extcap, sizeof(extcap), ",extcap:");
				for (i = 0; i < len; ++i) {
					int lim = sizeof(extcap) - strlen(extcap);
					p += snprintf(p, lim, "%02x", *(ie + i));
				}
			}
			if ((id == 33) && (elen == 2)) {
				/* TX Power */
				u16 p;
				memcpy(&p, ie, sizeof(p));
				snprintf(txpow, sizeof(txpow), ",txpow:%04hx",
				         le_to_host16(p));
			}

			snprintf(tagbuf, sizeof(tagbuf), "%s%d", sep, id);
		}

		strncat(fstr, tagbuf, flen);
		flen = fstr_len - strlen(fstr) - 1;

		ie += elen;
		ie_len -= elen;
	}

	if (strlen(htcap)) {
		strncat(fstr, htcap, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(htagg)) {
		strncat(fstr, htagg, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(htmcs)) {
		strncat(fstr, htmcs, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(vhtcap)) {
		strncat(fstr, vhtcap, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(vhtrxmcs)) {
		strncat(fstr, vhtrxmcs, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(vhttxmcs)) {
		strncat(fstr, vhttxmcs, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(txpow)) {
		strncat(fstr, txpow, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(extcap)) {
		strncat(fstr, extcap, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}
	if (strlen(wps)) {
		strncat(fstr, wps, flen);
		flen = fstr_len - strlen(fstr) - 1;
	}

	fstr[fstr_len - 1] = '\0';
}

static void write_sta_taxonomy(const struct hostapd_data *hapd,
	struct sta_info *sta)
{
	if ((os_strlen(sta->probe_ie_taxonomy) == 0) ||
	    (os_strlen(sta->assoc_ie_taxonomy) == 0)) {
		return;
	}

	wpa_msg(hapd->msg_ctx, MSG_INFO,
			AP_STA_TAXONOMY MACSTR " wifi4|probe:%s|assoc:%s",
			MAC2STR(sta->addr), sta->probe_ie_taxonomy,
			sta->assoc_ie_taxonomy);
}

void hostapd_taxonomy_probe_req(const struct hostapd_data *hapd,
	struct sta_info *sta, const u8 *ie, size_t ie_len)
{
	char taxonomy[TAXONOMY_STRING_LEN];
	ie_to_string(taxonomy, sizeof(taxonomy), ie, ie_len);
	if (os_strcmp(taxonomy, sta->probe_ie_taxonomy) != 0) {
		os_memcpy(sta->probe_ie_taxonomy, taxonomy, os_strlen(taxonomy) + 1);
		write_sta_taxonomy(hapd, sta);
	}
}

void hostapd_taxonomy_assoc_req(const struct hostapd_data *hapd,
	struct sta_info *sta, const u8 *ie, size_t ie_len)
{
	char taxonomy[TAXONOMY_STRING_LEN];
	ie_to_string(taxonomy, sizeof(taxonomy), ie, ie_len);
	if (os_strcmp(taxonomy, sta->assoc_ie_taxonomy) != 0) {
		os_memcpy(sta->assoc_ie_taxonomy, taxonomy, os_strlen(taxonomy) + 1);
		write_sta_taxonomy(hapd, sta);
	}
}

/* vim: set tabstop=4 softtabstop=4 shiftwidth=4 noexpandtab : */
