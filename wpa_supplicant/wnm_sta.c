/*
 * wpa_supplicant - WNM
 * Copyright (c) 2011-2013, Qualcomm Atheros, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "common/ieee802_11_common.h"
#include "common/wpa_ctrl.h"
#include "rsn_supp/wpa.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "scan.h"
#include "bgscan.h"
#include "ctrl_iface.h"
#include "bss.h"
#include "hs20_supplicant.h"
#include "probe.h"
#include "wnm_sta.h"

#define MAX_TFS_IE_LEN  1024
#define WNM_PROBE_RESPONSE_TIMEOUT_SEC 0
#define WNM_PROBE_RESPONSE_TIMEOUT_U_SEC 100000
#define WNM_MAX_PROBE_REQS 3


/* get the TFS IE from driver */
static int ieee80211_11_get_tfs_ie(struct wpa_supplicant *wpa_s, u8 *buf,
				   u16 *buf_len, enum wnm_oper oper)
{
	wpa_printf(MSG_DEBUG, "%s: TFS get operation %d", __func__, oper);

	return wpa_drv_wnm_oper(wpa_s, oper, wpa_s->bssid, buf, buf_len);
}


/* set the TFS IE to driver */
static int ieee80211_11_set_tfs_ie(struct wpa_supplicant *wpa_s,
				   const u8 *addr, u8 *buf, u16 *buf_len,
				   enum wnm_oper oper)
{
	wpa_printf(MSG_DEBUG, "%s: TFS set operation %d", __func__, oper);

	return wpa_drv_wnm_oper(wpa_s, oper, addr, buf, buf_len);
}


/* MLME-SLEEPMODE.request */
int ieee802_11_send_wnmsleep_req(struct wpa_supplicant *wpa_s,
				 u8 action, u16 intval, struct wpabuf *tfs_req)
{
	struct ieee80211_mgmt *mgmt;
	int res;
	size_t len;
	struct wnm_sleep_element *wnmsleep_ie;
	u8 *wnmtfs_ie;
	u8 wnmsleep_ie_len;
	u16 wnmtfs_ie_len;  /* possibly multiple IE(s) */
	enum wnm_oper tfs_oper = action == 0 ? WNM_SLEEP_TFS_REQ_IE_ADD :
		WNM_SLEEP_TFS_REQ_IE_NONE;

	wpa_printf(MSG_DEBUG, "WNM: Request to send WNM-Sleep Mode Request "
		   "action=%s to " MACSTR,
		   action == 0 ? "enter" : "exit",
		   MAC2STR(wpa_s->bssid));

	/* WNM-Sleep Mode IE */
	wnmsleep_ie_len = sizeof(struct wnm_sleep_element);
	wnmsleep_ie = os_zalloc(sizeof(struct wnm_sleep_element));
	if (wnmsleep_ie == NULL)
		return -1;
	wnmsleep_ie->eid = WLAN_EID_WNMSLEEP;
	wnmsleep_ie->len = wnmsleep_ie_len - 2;
	wnmsleep_ie->action_type = action;
	wnmsleep_ie->status = WNM_STATUS_SLEEP_ACCEPT;
	wnmsleep_ie->intval = host_to_le16(intval);
	wpa_hexdump(MSG_DEBUG, "WNM: WNM-Sleep Mode element",
		    (u8 *) wnmsleep_ie, wnmsleep_ie_len);

	/* TFS IE(s) */
	if (tfs_req) {
		wnmtfs_ie_len = wpabuf_len(tfs_req);
		wnmtfs_ie = os_malloc(wnmtfs_ie_len);
		if (wnmtfs_ie == NULL) {
			os_free(wnmsleep_ie);
			return -1;
		}
		os_memcpy(wnmtfs_ie, wpabuf_head(tfs_req), wnmtfs_ie_len);
	} else {
		wnmtfs_ie = os_zalloc(MAX_TFS_IE_LEN);
		if (wnmtfs_ie == NULL) {
			os_free(wnmsleep_ie);
			return -1;
		}
		if (ieee80211_11_get_tfs_ie(wpa_s, wnmtfs_ie, &wnmtfs_ie_len,
					    tfs_oper)) {
			wnmtfs_ie_len = 0;
			os_free(wnmtfs_ie);
			wnmtfs_ie = NULL;
		}
	}
	wpa_hexdump(MSG_DEBUG, "WNM: TFS Request element",
		    (u8 *) wnmtfs_ie, wnmtfs_ie_len);

	mgmt = os_zalloc(sizeof(*mgmt) + wnmsleep_ie_len + wnmtfs_ie_len);
	if (mgmt == NULL) {
		wpa_printf(MSG_DEBUG, "MLME: Failed to allocate buffer for "
			   "WNM-Sleep Request action frame");
		os_free(wnmsleep_ie);
		os_free(wnmtfs_ie);
		return -1;
	}

	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.wnm_sleep_req.action = WNM_SLEEP_MODE_REQ;
	mgmt->u.action.u.wnm_sleep_req.dialogtoken = 1;
	os_memcpy(mgmt->u.action.u.wnm_sleep_req.variable, wnmsleep_ie,
		  wnmsleep_ie_len);
	/* copy TFS IE here */
	if (wnmtfs_ie_len > 0) {
		os_memcpy(mgmt->u.action.u.wnm_sleep_req.variable +
			  wnmsleep_ie_len, wnmtfs_ie, wnmtfs_ie_len);
	}

	len = 1 + sizeof(mgmt->u.action.u.wnm_sleep_req) + wnmsleep_ie_len +
		wnmtfs_ie_len;

	res = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  &mgmt->u.action.category, len, 0);
	if (res < 0)
		wpa_printf(MSG_DEBUG, "Failed to send WNM-Sleep Request "
			   "(action=%d, intval=%d)", action, intval);

	os_free(wnmsleep_ie);
	os_free(wnmtfs_ie);
	os_free(mgmt);

	return res;
}


static void wnm_sleep_mode_enter_success(struct wpa_supplicant *wpa_s,
					 u8 *tfsresp_ie_start,
					 u8 *tfsresp_ie_end)
{
	wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_CONFIRM,
			 wpa_s->bssid, NULL, NULL);
	/* remove GTK/IGTK ?? */

	/* set the TFS Resp IE(s) */
	if (tfsresp_ie_start && tfsresp_ie_end &&
	    tfsresp_ie_end - tfsresp_ie_start >= 0) {
		u16 tfsresp_ie_len;
		tfsresp_ie_len = (tfsresp_ie_end + tfsresp_ie_end[1] + 2) -
			tfsresp_ie_start;
		wpa_printf(MSG_DEBUG, "TFS Resp IE(s) found");
		/* pass the TFS Resp IE(s) to driver for processing */
		if (ieee80211_11_set_tfs_ie(wpa_s, wpa_s->bssid,
					    tfsresp_ie_start,
					    &tfsresp_ie_len,
					    WNM_SLEEP_TFS_RESP_IE_SET))
			wpa_printf(MSG_DEBUG, "WNM: Fail to set TFS Resp IE");
	}
}


static void wnm_sleep_mode_exit_success(struct wpa_supplicant *wpa_s,
					const u8 *frm, u16 key_len_total)
{
	u8 *ptr, *end;
	u8 gtk_len;

	wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_CONFIRM,  wpa_s->bssid,
			 NULL, NULL);

	/* Install GTK/IGTK */

	/* point to key data field */
	ptr = (u8 *) frm + 1 + 2;
	end = ptr + key_len_total;
	wpa_hexdump_key(MSG_DEBUG, "WNM: Key Data", ptr, key_len_total);

	while (ptr + 1 < end) {
		if (ptr + 2 + ptr[1] > end) {
			wpa_printf(MSG_DEBUG, "WNM: Invalid Key Data element "
				   "length");
			if (end > ptr) {
				wpa_hexdump(MSG_DEBUG, "WNM: Remaining data",
					    ptr, end - ptr);
			}
			break;
		}
		if (*ptr == WNM_SLEEP_SUBELEM_GTK) {
			if (ptr[1] < 11 + 5) {
				wpa_printf(MSG_DEBUG, "WNM: Too short GTK "
					   "subelem");
				break;
			}
			gtk_len = *(ptr + 4);
			if (ptr[1] < 11 + gtk_len ||
			    gtk_len < 5 || gtk_len > 32) {
				wpa_printf(MSG_DEBUG, "WNM: Invalid GTK "
					   "subelem");
				break;
			}
			wpa_wnmsleep_install_key(
				wpa_s->wpa,
				WNM_SLEEP_SUBELEM_GTK,
				ptr);
			ptr += 13 + gtk_len;
#ifdef CONFIG_IEEE80211W
		} else if (*ptr == WNM_SLEEP_SUBELEM_IGTK) {
			if (ptr[1] < 2 + 6 + WPA_IGTK_LEN) {
				wpa_printf(MSG_DEBUG, "WNM: Too short IGTK "
					   "subelem");
				break;
			}
			wpa_wnmsleep_install_key(wpa_s->wpa,
						 WNM_SLEEP_SUBELEM_IGTK, ptr);
			ptr += 10 + WPA_IGTK_LEN;
#endif /* CONFIG_IEEE80211W */
		} else
			break; /* skip the loop */
	}
}


static void ieee802_11_rx_wnmsleep_resp(struct wpa_supplicant *wpa_s,
					const u8 *frm, int len)
{
	/*
	 * Action [1] | Dialog Token [1] | Key Data Len [2] | Key Data |
	 * WNM-Sleep Mode IE | TFS Response IE
	 */
	u8 *pos = (u8 *) frm; /* point to payload after the action field */
	u16 key_len_total;
	struct wnm_sleep_element *wnmsleep_ie = NULL;
	/* multiple TFS Resp IE (assuming consecutive) */
	u8 *tfsresp_ie_start = NULL;
	u8 *tfsresp_ie_end = NULL;
	size_t left;

	if (len < 3)
		return;
	key_len_total = WPA_GET_LE16(frm + 1);

	wpa_printf(MSG_DEBUG, "WNM-Sleep Mode Response token=%u key_len_total=%d",
		   frm[0], key_len_total);
	left = len - 3;
	if (key_len_total > left) {
		wpa_printf(MSG_INFO, "WNM: Too short frame for Key Data field");
		return;
	}
	pos += 3 + key_len_total;
	while (pos - frm < len) {
		u8 ie_len = *(pos + 1);
		if (pos + 2 + ie_len > frm + len) {
			wpa_printf(MSG_INFO, "WNM: Invalid IE len %u", ie_len);
			break;
		}
		wpa_hexdump(MSG_DEBUG, "WNM: Element", pos, 2 + ie_len);
		if (*pos == WLAN_EID_WNMSLEEP)
			wnmsleep_ie = (struct wnm_sleep_element *) pos;
		else if (*pos == WLAN_EID_TFS_RESP) {
			if (!tfsresp_ie_start)
				tfsresp_ie_start = pos;
			tfsresp_ie_end = pos;
		} else
			wpa_printf(MSG_DEBUG, "EID %d not recognized", *pos);
		pos += ie_len + 2;
	}

	if (!wnmsleep_ie) {
		wpa_printf(MSG_DEBUG, "No WNM-Sleep IE found");
		return;
	}

	if (wnmsleep_ie->status == WNM_STATUS_SLEEP_ACCEPT ||
	    wnmsleep_ie->status == WNM_STATUS_SLEEP_EXIT_ACCEPT_GTK_UPDATE) {
		wpa_printf(MSG_DEBUG, "Successfully recv WNM-Sleep Response "
			   "frame (action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_ENTER) {
			wnm_sleep_mode_enter_success(wpa_s, tfsresp_ie_start,
						     tfsresp_ie_end);
		} else if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_EXIT) {
			wnm_sleep_mode_exit_success(wpa_s, frm, key_len_total);
		}
	} else {
		wpa_printf(MSG_DEBUG, "Reject recv WNM-Sleep Response frame "
			   "(action=%d, intval=%d)",
			   wnmsleep_ie->action_type, wnmsleep_ie->intval);
		if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_ENTER)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_ENTER_FAIL,
					 wpa_s->bssid, NULL, NULL);
		else if (wnmsleep_ie->action_type == WNM_SLEEP_MODE_EXIT)
			wpa_drv_wnm_oper(wpa_s, WNM_SLEEP_EXIT_FAIL,
					 wpa_s->bssid, NULL, NULL);
	}
}


void wnm_deallocate_memory(struct wpa_supplicant *wpa_s)
{
	int i;

	for (i = 0; i < wpa_s->wnm_num_neighbor_report; i++) {
		os_free(wpa_s->wnm_neighbor_report_elements[i].meas_pilot);
		os_free(wpa_s->wnm_neighbor_report_elements[i].mul_bssid);
	}

	wpa_s->wnm_num_neighbor_report = 0;
	os_free(wpa_s->wnm_neighbor_report_elements);
	wpa_s->wnm_neighbor_report_elements = NULL;
	// wnm_best_neighbor should always point to a neighbor in wnm_neighbor_report_elements
	// and therefore it shouldn't ever need to be freed
	wpa_s->wnm_best_neighbor = NULL;
	wpa_s->wnm_num_exp_probe_resp = 0;


}


static void wnm_parse_neighbor_report_elem(struct neighbor_report *rep,
					   u8 id, u8 elen, const u8 *pos)
{
	switch (id) {
	case WNM_NEIGHBOR_TSF:
		if (elen < 2 + 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short TSF");
			break;
		}
		rep->tsf_offset = WPA_GET_LE16(pos);
		rep->beacon_int = WPA_GET_LE16(pos + 2);
		rep->tsf_present = 1;
		break;
	case WNM_NEIGHBOR_CONDENSED_COUNTRY_STRING:
		if (elen < 2) {
			wpa_printf(MSG_DEBUG, "WNM: Too short condensed "
				   "country string");
			break;
		}
		os_memcpy(rep->country, pos, 2);
		rep->country_present = 1;
		break;
	case WNM_NEIGHBOR_BSS_TRANSITION_CANDIDATE:
		if (elen < 1) {
			wpa_printf(MSG_DEBUG, "WNM: Too short BSS transition "
				   "candidate");
			break;
		}
		rep->preference = pos[0];
		rep->preference_present = 1;
		break;
	case WNM_NEIGHBOR_BSS_TERMINATION_DURATION:
		rep->bss_term_tsf = WPA_GET_LE64(pos);
		rep->bss_term_dur = WPA_GET_LE16(pos + 8);
		rep->bss_term_present = 1;
		break;
	case WNM_NEIGHBOR_BEARING:
		if (elen < 8) {
			wpa_printf(MSG_DEBUG, "WNM: Too short neighbor "
				   "bearing");
			break;
		}
		rep->bearing = WPA_GET_LE16(pos);
		rep->distance = WPA_GET_LE32(pos + 2);
		rep->rel_height = WPA_GET_LE16(pos + 2 + 4);
		rep->bearing_present = 1;
		break;
	case WNM_NEIGHBOR_MEASUREMENT_PILOT:
		if (elen < 1) {
			wpa_printf(MSG_DEBUG, "WNM: Too short measurement "
				   "pilot");
			break;
		}
		os_free(rep->meas_pilot);
		rep->meas_pilot = os_zalloc(sizeof(struct measurement_pilot));
		if (rep->meas_pilot == NULL)
			break;
		rep->meas_pilot->measurement_pilot = pos[0];
		rep->meas_pilot->subelem_len = elen - 1;
		os_memcpy(rep->meas_pilot->subelems, pos + 1, elen - 1);
		break;
	case WNM_NEIGHBOR_RRM_ENABLED_CAPABILITIES:
		if (elen < 5) {
			wpa_printf(MSG_DEBUG, "WNM: Too short RRM enabled "
				   "capabilities");
			break;
		}
		os_memcpy(rep->rm_capab, pos, 5);
		rep->rm_capab_present = 1;
		break;
	case WNM_NEIGHBOR_MULTIPLE_BSSID:
		if (elen < 1) {
			wpa_printf(MSG_DEBUG, "WNM: Too short multiple BSSID");
			break;
		}
		os_free(rep->mul_bssid);
		rep->mul_bssid = os_zalloc(sizeof(struct multiple_bssid));
		if (rep->mul_bssid == NULL)
			break;
		rep->mul_bssid->max_bssid_indicator = pos[0];
		rep->mul_bssid->subelem_len = elen - 1;
		os_memcpy(rep->mul_bssid->subelems, pos + 1, elen - 1);
		break;
	}
}


static int wnm_nei_get_chan(struct wpa_supplicant *wpa_s, u8 op_class, u8 chan)
{
	struct wpa_bss *bss = wpa_s->current_bss;
	const char *country = NULL;

	if (bss) {
		const u8 *elem = wpa_bss_get_ie(bss, WLAN_EID_COUNTRY);

		if (elem && elem[1] >= 2)
			country = (const char *) (elem + 2);
	}

	return ieee80211_chan_to_freq(country, op_class, chan);
}


static void wnm_parse_neighbor_report(struct wpa_supplicant *wpa_s,
				      const u8 *pos, u8 len,
				      struct neighbor_report *rep)
{
	u8 left = len;

	if (left < 13) {
		wpa_printf(MSG_DEBUG, "WNM: Too short neighbor report");
		return;
	}

	os_memcpy(rep->bssid, pos, ETH_ALEN);
	rep->bssid_info = WPA_GET_LE32(pos + ETH_ALEN);
	rep->regulatory_class = *(pos + 10);
	rep->channel_number = *(pos + 11);
	rep->phy_type = *(pos + 12);

	pos += 13;
	left -= 13;

	while (left >= 2) {
		u8 id, elen;

		id = *pos++;
		elen = *pos++;
		wpa_printf(MSG_DEBUG, "WNM: Subelement id=%u len=%u", id, elen);
		left -= 2;
		if (elen > left) {
			wpa_printf(MSG_DEBUG,
				   "WNM: Truncated neighbor report subelement");
			break;
		}
		wnm_parse_neighbor_report_elem(rep, id, elen, pos);
		left -= elen;
		pos += elen;
	}

	rep->freq = wnm_nei_get_chan(wpa_s, rep->regulatory_class,
				     rep->channel_number);
}


static struct wpa_bss *
compare_scan_neighbor_results(struct wpa_supplicant *wpa_s)
{

	u8 i;
	struct wpa_bss *current_bss = wpa_s->current_bss;
	struct wpa_bss *target;

	if (!current_bss)
		return 0;

	wpa_printf(MSG_DEBUG, "WNM: Current BSS " MACSTR " RSSI %d",
		   MAC2STR(wpa_s->bssid), current_bss->level);

	for (i = 0; i < wpa_s->wnm_num_neighbor_report; i++) {
		struct neighbor_report *nei;

		nei = &wpa_s->wnm_neighbor_report_elements[i];
		if (nei->preference_present && nei->preference == 0) {
			wpa_printf(MSG_DEBUG, "Skip excluded BSS " MACSTR,
				   MAC2STR(nei->bssid));
			continue;
		}

		target = wpa_bss_get(wpa_s, nei->bssid, current_bss->ssid, current_bss->ssid_len);
		if (!target) {
			wpa_printf(MSG_DEBUG, "Candidate BSS " MACSTR
				   " (pref %d) not found in scan results",
				   MAC2STR(nei->bssid),
				   nei->preference_present ? nei->preference :
				   -1);
			continue;
		}

		if (current_bss->ssid_len != target->ssid_len ||
		    os_memcmp(current_bss->ssid, target->ssid, current_bss->ssid_len) != 0) {
			/*
			 * TODO: Could consider allowing transition to another
			 * ESS if PMF was enabled for the association.
			 */
			wpa_printf(MSG_DEBUG, "Candidate BSS " MACSTR
				   " (pref %d) in different ESS",
				   MAC2STR(nei->bssid),
				   nei->preference_present ? nei->preference :
				   -1);
			continue;
		}

		wpa_printf(MSG_DEBUG,
			   "WNM: Found an acceptable preferred transition candidate BSS "
			   MACSTR " (RSSI %d)",
			   MAC2STR(nei->bssid), target->level);
		return target;
	}

	return NULL;
}

static void wnm_send_bss_transition_mgmt_resp(
	struct wpa_supplicant *wpa_s, u8 dialog_token,
	enum bss_trans_mgmt_status_code status, u8 delay,
	const u8 *target_bssid)
{
	u8 buf[1000], *pos;
	struct ieee80211_mgmt *mgmt;
	size_t len;
	int res;

	wpa_printf(MSG_DEBUG, "WNM: Send BSS Transition Management Response "
		   "to " MACSTR " dialog_token=%u status=%u delay=%d",
		   MAC2STR(wpa_s->bssid), dialog_token, status, delay);
	if (!wpa_s->current_bss) {
		wpa_printf(MSG_DEBUG,
			   "WNM: Current BSS not known - drop response");
		return;
	}

	mgmt = (struct ieee80211_mgmt *) buf;
	os_memset(&buf, 0, sizeof(buf));
	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.bss_tm_resp.action = WNM_BSS_TRANS_MGMT_RESP;
	mgmt->u.action.u.bss_tm_resp.dialog_token = dialog_token;
	mgmt->u.action.u.bss_tm_resp.status_code = status;
	mgmt->u.action.u.bss_tm_resp.bss_termination_delay = delay;
	pos = mgmt->u.action.u.bss_tm_resp.variable;
	if (target_bssid) {
		os_memcpy(pos, target_bssid, ETH_ALEN);
		pos += ETH_ALEN;
	} else if (status == WNM_BSS_TM_ACCEPT) {
		/*
		 * P802.11-REVmc clarifies that the Target BSSID field is always
		 * present when status code is zero, so use a fake value here if
		 * no BSSID is yet known.
		 */
		os_memset(pos, 0, ETH_ALEN);
		pos += ETH_ALEN;
	}

	len = pos - (u8 *) &mgmt->u.action.category;

	res = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  &mgmt->u.action.category, len, 0);
	if (res < 0) {
		wpa_printf(MSG_DEBUG,
			   "WNM: Failed to send BSS Transition Management Response");
	}
}

static int cand_pref_compar(const void *a, const void *b)
{
	const struct neighbor_report *aa = a;
	const struct neighbor_report *bb = b;

	if (!aa->preference_present && !bb->preference_present)
		return 0;
	if (!aa->preference_present)
		return 1;
	if (!bb->preference_present)
		return -1;
	if (bb->preference > aa->preference)
		return 1;
	if (bb->preference < aa->preference)
		return -1;
	return 0;
}


static void wnm_sort_cand_list(struct wpa_supplicant *wpa_s)
{
	if (!wpa_s->wnm_neighbor_report_elements)
		return;
	qsort(wpa_s->wnm_neighbor_report_elements,
	      wpa_s->wnm_num_neighbor_report, sizeof(struct neighbor_report),
	      cand_pref_compar);
}

static void wnm_dump_cand_list(struct wpa_supplicant *wpa_s)
{
	unsigned int i;

	if (!wpa_s->wnm_neighbor_report_elements)
		return;

	wpa_printf(MSG_DEBUG, "WNM: BSS Transition Candidate List (len=%d):", wpa_s->wnm_num_neighbor_report);
	for (i = 0; i < wpa_s->wnm_num_neighbor_report; i++) {
		struct neighbor_report *nei;

		nei = &wpa_s->wnm_neighbor_report_elements[i];
		wpa_printf(MSG_DEBUG, "WNM:    %u: " MACSTR
			   " info=0x%x op_class=%u chan=%u phy=%u pref=%d freq=%d",
			   i, MAC2STR(nei->bssid), nei->bssid_info,
			   nei->regulatory_class,
			   nei->channel_number, nei->phy_type,
			   nei->preference_present ? nei->preference : -1,
			   nei->freq);
	}
}

// Attempts to connect to wnm_best_neighbor
int wnm_connect_to_best_neighbor(struct wpa_supplicant* wpa_s)
{
	struct wpa_bss* candidate;
	struct wpa_bss* current_bss = wpa_s->current_bss;
	int ret = 0;

	if(wpa_s->wnm_best_neighbor == NULL){
		ret = -1;
		goto abort_connection_attempt;
	}


	if(current_bss == NULL){
		ret = -1;
		goto abort_connection_attempt;
	}

	wpa_printf(MSG_DEBUG, "WNM: Attempting to transition to BSSID "MACSTR,
				MAC2STR(wpa_s->wnm_best_neighbor->bssid));

	const u8* rsn_ie = wpa_bss_get_ie(current_bss, WLAN_EID_RSN);
	if(rsn_ie == NULL){
		ret = -1;
		goto abort_connection_attempt;
	}

	u8 ie_len = rsn_ie[1];
	candidate = os_zalloc(sizeof(struct wpa_bss) + 2 + ie_len);
	if (candidate == NULL){
		ret = -1;
		goto abort_connection_attempt;
	}

	memcpy(candidate + 1, rsn_ie, 2 + ie_len);
	candidate->ie_len = ie_len;

	memcpy(candidate->bssid, wpa_s->wnm_best_neighbor->bssid, ETH_ALEN);
	candidate->freq = wpa_s->wnm_best_neighbor->freq;
	os_get_reltime(&candidate->last_update);
	candidate->id = wpa_s->bss_next_id++;
	wpa_s->bss_update_idx++;
	candidate->last_update_idx = wpa_s->bss_update_idx;
	memcpy(candidate->ssid, current_bss->ssid, current_bss->ssid_len);
	candidate->ssid_len = current_bss->ssid_len;

	dl_list_add_tail(&wpa_s->bss, &candidate->list);
	dl_list_add_tail(&wpa_s->bss_id, &candidate->list_id);
	wpa_s->num_bss++;
	wpa_printf(MSG_DEBUG, "WNM: Add new wpa_bss with minimal "
			"information for association: id %u BSSID "MACSTR" SSID '%s'",
			candidate->id, MAC2STR(candidate->bssid), wpa_ssid_txt(candidate->ssid, candidate->ssid_len));
	wpas_notify_bss_added(wpa_s, candidate->bssid, candidate->id);

	/* Associate to the network */
	/* Send the BSS Management Response - Accept */
	if (wpa_s->wnm_reply) {
		wpa_s->wnm_reply = 0;
		wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  WNM_BSS_TM_ACCEPT,
						  0, candidate->bssid);
	}

	if (memcmp(candidate->bssid, current_bss->bssid, ETH_ALEN) == 0) {
		wpa_printf(MSG_DEBUG, "WNM: Already associated with the preferred candidate");
		ret = 0;
		goto abort_connection_attempt;
	}

	wpa_s->reassociate = 1;
	wpa_supplicant_connect(wpa_s, candidate, wpa_s->current_ssid);
	wnm_deallocate_memory(wpa_s);

	return 0;

abort_connection_attempt:
	if (ret < 0 && wpa_s->wnm_reply) {
		wpa_s->wnm_reply = 0;
		wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  WNM_BSS_TM_REJECT_NO_SUITABLE_CANDIDATES,
						  0, NULL);
	}

#ifdef CONFIG_BGSCAN
	wpa_supplicant_start_bgscan(wpa_s);
#endif /* CONFIG_BGSCAN */

	wnm_deallocate_memory(wpa_s);
	return ret;

}

/**
 * wnm_handle_direct_probe_timeout - Timer for direct probe responses
 * @eloop_ctx: struct wpa_supplicant *
 * @timeout_ctx: NULL
 *
 * This function is called if we haven't received the expected number
 * of probe responses within WNM_PROBE_RESPONSE_TIMEOUT
 */
void wnm_handle_direct_probe_timeout(void *eloop_ctx, void *timeout_ctx)
{
	struct wpa_supplicant* wpa_s = eloop_ctx;
	wpa_printf(MSG_INFO, "WNM: Direct probe response timeout");
	wpa_s->wnm_num_exp_probe_resp = 0;
	wnm_connect_to_best_neighbor(wpa_s);
}

int wnm_rx_directed_probe_response(struct wpa_supplicant* wpa_s,
		const struct ieee80211_mgmt* mgmt, int freq, int rssi)
{
	int i;

	if(wpa_s->wnm_num_exp_probe_resp == 0)
		return 0;

	for(i = 0; wpa_s->wnm_neighbor_report_elements && i < wpa_s->wnm_num_neighbor_report; i++)	{
		struct neighbor_report* rep = &wpa_s->wnm_neighbor_report_elements[i];
		if(memcmp(mgmt->bssid, rep->bssid, ETH_ALEN) == 0) {
			wpa_printf(MSG_DEBUG, "WNM: Probe response from "MACSTR" with BSSID "MACSTR,
								MAC2STR(mgmt->sa),MAC2STR(mgmt->bssid));

			if(wpa_s->wnm_rx_probe_resp_counts[i] == 0)
				wpa_s->wnm_num_exp_probe_resp--;

			wpa_s->wnm_rx_probe_resp_counts[i]++;

			if((wpa_s->wnm_best_neighbor == NULL) ||
			   (rep->preference > wpa_s->wnm_best_neighbor->preference) ||
			   ((rep->preference == wpa_s->wnm_best_neighbor->preference && rssi > wpa_s->wnm_best_neighbor_rssi)))
			{
				wpa_s->wnm_best_neighbor = rep;
				wpa_s->wnm_best_neighbor_rssi = rssi;
			}

			break;
		}
	}

	if(wpa_s->wnm_num_exp_probe_resp == 0) {
		eloop_cancel_timeout(wnm_handle_direct_probe_timeout, wpa_s, NULL);
		wnm_connect_to_best_neighbor(wpa_s);
	}

	return 0;
}

static void wnm_probe_neighbors(struct wpa_supplicant *wpa_s)
{
	int i;
	int j;

	wpa_s->wnm_num_exp_probe_resp = wpa_s->wnm_num_neighbor_report;
	os_memset(wpa_s->wnm_rx_probe_resp_counts, 0, WNM_MAX_NEIGHBOR_REPORT);

	for(i = 0; wpa_s->wnm_neighbor_report_elements && i < wpa_s->wnm_num_neighbor_report; i++) {
		struct neighbor_report* rep = &wpa_s->wnm_neighbor_report_elements[i];
		for(j = 0; j < WNM_MAX_PROBE_REQS; j++) {
			wpa_send_directed_probe_request(wpa_s, rep->bssid, rep->freq);
		}
	}

	eloop_cancel_timeout(wnm_handle_direct_probe_timeout, wpa_s, NULL); //Clear any old timers
	eloop_register_timeout(WNM_PROBE_RESPONSE_TIMEOUT_SEC,
			WNM_PROBE_RESPONSE_TIMEOUT_U_SEC,
			wnm_handle_direct_probe_timeout, wpa_s, NULL);

}

static void ieee802_11_rx_bss_trans_mgmt_req(struct wpa_supplicant *wpa_s,
					     const u8 *pos, const u8 *end,
					     int reply)
{
	unsigned int beacon_int;
	u8 valid_int;

	wnm_deallocate_memory(wpa_s);

#ifdef CONFIG_BGSCAN
	wpa_supplicant_stop_bgscan(wpa_s);
#endif /* CONFIG_BGSCAN */

	if (pos + 5 > end)
		return;

	if (wpa_s->current_bss)
		beacon_int = wpa_s->current_bss->beacon_int;
	else
		beacon_int = 100; /* best guess */

	wpa_s->wnm_dialog_token = pos[0];
	wpa_s->wnm_mode = pos[1];
	wpa_s->wnm_dissoc_timer = WPA_GET_LE16(pos + 2);
	valid_int = pos[4];
	wpa_s->wnm_reply = reply;

	wpa_printf(MSG_DEBUG, "WNM: BSS Transition Management Request: "
		   "dialog_token=%u request_mode=0x%x "
		   "disassoc_timer=%u validity_interval=%u",
		   wpa_s->wnm_dialog_token, wpa_s->wnm_mode,
		   wpa_s->wnm_dissoc_timer, valid_int);

	pos += 5;

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_BSS_TERMINATION_INCLUDED) {
		if (pos + 12 > end) {
			wpa_printf(MSG_DEBUG, "WNM: Too short BSS TM Request");
			return;
		}
		os_memcpy(wpa_s->wnm_bss_termination_duration, pos, 12);
		pos += 12; /* BSS Termination Duration */
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT) {
		char url[256];

		if (pos + 1 > end || pos + 1 + pos[0] > end) {
			wpa_printf(MSG_DEBUG, "WNM: Invalid BSS Transition "
				   "Management Request (URL)");
			return;
		}
		os_memcpy(url, pos + 1, pos[0]);
		url[pos[0]] = '\0';
		pos += 1 + pos[0];

		wpa_msg(wpa_s, MSG_INFO, ESS_DISASSOC_IMMINENT "%d %u %s",
			wpa_sm_pmf_enabled(wpa_s->wpa),
			wpa_s->wnm_dissoc_timer * beacon_int * 128 / 125, url);
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_DISASSOC_IMMINENT) {
		wpa_msg(wpa_s, MSG_INFO, "WNM: Disassociation Imminent - "
			"Disassociation Timer %u", wpa_s->wnm_dissoc_timer);
	}

	if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_PREF_CAND_LIST_INCLUDED) {
		unsigned int valid_ms;

		wpa_msg(wpa_s, MSG_INFO, "WNM: Preferred List Available");
		wnm_deallocate_memory(wpa_s);
		wpa_s->wnm_neighbor_report_elements = os_calloc(
			WNM_MAX_NEIGHBOR_REPORT,
			sizeof(struct neighbor_report));
		if (wpa_s->wnm_neighbor_report_elements == NULL)
			return;

		while (pos + 2 <= end &&
		       wpa_s->wnm_num_neighbor_report < WNM_MAX_NEIGHBOR_REPORT)
		{
			u8 tag = *pos++;
			u8 len = *pos++;

			wpa_printf(MSG_DEBUG, "WNM: Neighbor report tag %u",
				   tag);
			if (pos + len > end) {
				wpa_printf(MSG_DEBUG, "WNM: Truncated request");
				return;
			}
			if (tag == WLAN_EID_NEIGHBOR_REPORT) {
				struct neighbor_report *rep;
				rep = &wpa_s->wnm_neighbor_report_elements[
					wpa_s->wnm_num_neighbor_report];
				wnm_parse_neighbor_report(wpa_s, pos, len, rep);
			}

			pos += len;
			wpa_s->wnm_num_neighbor_report++;
		}
		wnm_sort_cand_list(wpa_s);
		wnm_dump_cand_list(wpa_s);
		valid_ms = valid_int * beacon_int * 128 / 125;
		wpa_printf(MSG_MSGDUMP, "WNM: Candidate list valid for %u ms",
			   valid_ms);
		os_get_reltime(&wpa_s->wnm_cand_valid_until);
		wpa_s->wnm_cand_valid_until.sec += valid_ms / 1000;
		wpa_s->wnm_cand_valid_until.usec += (valid_ms % 1000) * 1000;
		wpa_s->wnm_cand_valid_until.sec +=
			wpa_s->wnm_cand_valid_until.usec / 1000000;
		wpa_s->wnm_cand_valid_until.usec %= 1000000;

		wnm_probe_neighbors(wpa_s);

	} else if (reply) {
		enum bss_trans_mgmt_status_code status;
		if (wpa_s->wnm_mode & WNM_BSS_TM_REQ_ESS_DISASSOC_IMMINENT)
			status = WNM_BSS_TM_ACCEPT;
		else {
			wpa_msg(wpa_s, MSG_INFO, "WNM: BSS Transition Management Request did not include candidates");
			status = WNM_BSS_TM_REJECT_UNSPECIFIED;
		}
		wnm_send_bss_transition_mgmt_resp(wpa_s,
						  wpa_s->wnm_dialog_token,
						  status, 0, NULL);
		wnm_deallocate_memory(wpa_s);
	}
}


int wnm_send_bss_transition_mgmt_query(struct wpa_supplicant *wpa_s,
				       u8 query_reason)
{
	u8 buf[1000], *pos;
	struct ieee80211_mgmt *mgmt;
	size_t len;
	int ret;

	wpa_printf(MSG_DEBUG, "WNM: Send BSS Transition Management Query to "
		   MACSTR " query_reason=%u",
		   MAC2STR(wpa_s->bssid), query_reason);

	mgmt = (struct ieee80211_mgmt *) buf;
	os_memset(&buf, 0, sizeof(buf));
	os_memcpy(mgmt->da, wpa_s->bssid, ETH_ALEN);
	os_memcpy(mgmt->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(mgmt->bssid, wpa_s->bssid, ETH_ALEN);
	mgmt->frame_control = IEEE80211_FC(WLAN_FC_TYPE_MGMT,
					   WLAN_FC_STYPE_ACTION);
	mgmt->u.action.category = WLAN_ACTION_WNM;
	mgmt->u.action.u.bss_tm_query.action = WNM_BSS_TRANS_MGMT_QUERY;
	mgmt->u.action.u.bss_tm_query.dialog_token = 1;
	mgmt->u.action.u.bss_tm_query.query_reason = query_reason;
	pos = mgmt->u.action.u.bss_tm_query.variable;

	len = pos - (u8 *) &mgmt->u.action.category;

	ret = wpa_drv_send_action(wpa_s, wpa_s->assoc_freq, 0, wpa_s->bssid,
				  wpa_s->own_addr, wpa_s->bssid,
				  &mgmt->u.action.category, len, 0);

	return ret;
}


static void ieee802_11_rx_wnm_notif_req_wfa(struct wpa_supplicant *wpa_s,
					    const u8 *sa, const u8 *data,
					    int len)
{
	const u8 *pos, *end, *next;
	u8 ie, ie_len;

	pos = data;
	end = data + len;

	while (pos + 1 < end) {
		ie = *pos++;
		ie_len = *pos++;
		wpa_printf(MSG_DEBUG, "WNM: WFA subelement %u len %u",
			   ie, ie_len);
		if (ie_len > end - pos) {
			wpa_printf(MSG_DEBUG, "WNM: Not enough room for "
				   "subelement");
			break;
		}
		next = pos + ie_len;
		if (ie_len < 4) {
			pos = next;
			continue;
		}
		wpa_printf(MSG_DEBUG, "WNM: Subelement OUI %06x type %u",
			   WPA_GET_BE24(pos), pos[3]);

#ifdef CONFIG_HS20
		if (ie == WLAN_EID_VENDOR_SPECIFIC && ie_len >= 5 &&
		    WPA_GET_BE24(pos) == OUI_WFA &&
		    pos[3] == HS20_WNM_SUB_REM_NEEDED) {
			/* Subscription Remediation subelement */
			const u8 *ie_end;
			u8 url_len;
			char *url;
			u8 osu_method;

			wpa_printf(MSG_DEBUG, "WNM: Subscription Remediation "
				   "subelement");
			ie_end = pos + ie_len;
			pos += 4;
			url_len = *pos++;
			if (url_len == 0) {
				wpa_printf(MSG_DEBUG, "WNM: No Server URL included");
				url = NULL;
				osu_method = 1;
			} else {
				if (pos + url_len + 1 > ie_end) {
					wpa_printf(MSG_DEBUG, "WNM: Not enough room for Server URL (len=%u) and Server Method (left %d)",
						   url_len,
						   (int) (ie_end - pos));
					break;
				}
				url = os_malloc(url_len + 1);
				if (url == NULL)
					break;
				os_memcpy(url, pos, url_len);
				url[url_len] = '\0';
				osu_method = pos[url_len];
			}
			hs20_rx_subscription_remediation(wpa_s, url,
							 osu_method);
			os_free(url);
			pos = next;
			continue;
		}

		if (ie == WLAN_EID_VENDOR_SPECIFIC && ie_len >= 8 &&
		    WPA_GET_BE24(pos) == OUI_WFA &&
		    pos[3] == HS20_WNM_DEAUTH_IMMINENT_NOTICE) {
			const u8 *ie_end;
			u8 url_len;
			char *url;
			u8 code;
			u16 reauth_delay;

			ie_end = pos + ie_len;
			pos += 4;
			code = *pos++;
			reauth_delay = WPA_GET_LE16(pos);
			pos += 2;
			url_len = *pos++;
			wpa_printf(MSG_DEBUG, "WNM: HS 2.0 Deauthentication "
				   "Imminent - Reason Code %u   "
				   "Re-Auth Delay %u  URL Length %u",
				   code, reauth_delay, url_len);
			if (pos + url_len > ie_end)
				break;
			url = os_malloc(url_len + 1);
			if (url == NULL)
				break;
			os_memcpy(url, pos, url_len);
			url[url_len] = '\0';
			hs20_rx_deauth_imminent_notice(wpa_s, code,
						       reauth_delay, url);
			os_free(url);
			pos = next;
			continue;
		}
#endif /* CONFIG_HS20 */

		pos = next;
	}
}


static void ieee802_11_rx_wnm_notif_req(struct wpa_supplicant *wpa_s,
					const u8 *sa, const u8 *frm, int len)
{
	const u8 *pos, *end;
	u8 dialog_token, type;

	/* Dialog Token [1] | Type [1] | Subelements */

	if (len < 2 || sa == NULL)
		return;
	end = frm + len;
	pos = frm;
	dialog_token = *pos++;
	type = *pos++;

	wpa_dbg(wpa_s, MSG_DEBUG, "WNM: Received WNM-Notification Request "
		"(dialog_token %u type %u sa " MACSTR ")",
		dialog_token, type, MAC2STR(sa));
	wpa_hexdump(MSG_DEBUG, "WNM-Notification Request subelements",
		    pos, end - pos);

	if (wpa_s->wpa_state != WPA_COMPLETED ||
	    os_memcmp(sa, wpa_s->bssid, ETH_ALEN) != 0) {
		wpa_dbg(wpa_s, MSG_DEBUG, "WNM: WNM-Notification frame not "
			"from our AP - ignore it");
		return;
	}

	switch (type) {
	case 1:
		ieee802_11_rx_wnm_notif_req_wfa(wpa_s, sa, pos, end - pos);
		break;
	default:
		wpa_dbg(wpa_s, MSG_DEBUG, "WNM: Ignore unknown "
			"WNM-Notification type %u", type);
		break;
	}
}


void ieee802_11_rx_wnm_action(struct wpa_supplicant *wpa_s,
			      const struct ieee80211_mgmt *mgmt, size_t len)
{
	const u8 *pos, *end;
	u8 act;

	if (len < IEEE80211_HDRLEN + 2)
		return;

	pos = ((const u8 *) mgmt) + IEEE80211_HDRLEN + 1;
	act = *pos++;
	end = ((const u8 *) mgmt) + len;

	wpa_printf(MSG_DEBUG, "WNM: RX action %u from " MACSTR,
		   act, MAC2STR(mgmt->sa));
	if (wpa_s->wpa_state < WPA_ASSOCIATED ||
	    os_memcmp(mgmt->sa, wpa_s->bssid, ETH_ALEN) != 0) {
		wpa_printf(MSG_DEBUG, "WNM: Ignore unexpected WNM Action "
			   "frame");
		return;
	}

	switch (act) {
	case WNM_BSS_TRANS_MGMT_REQ:
		ieee802_11_rx_bss_trans_mgmt_req(wpa_s, pos, end,
						 !(mgmt->da[0] & 0x01));
		break;
	case WNM_SLEEP_MODE_RESP:
		ieee802_11_rx_wnmsleep_resp(wpa_s, pos, end - pos);
		break;
	case WNM_NOTIFICATION_REQ:
		ieee802_11_rx_wnm_notif_req(wpa_s, mgmt->sa, pos, end - pos);
		break;
	default:
		wpa_printf(MSG_ERROR, "WNM: Unknown request");
		break;
	}
}
