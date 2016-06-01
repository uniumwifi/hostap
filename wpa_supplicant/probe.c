/*
 * WPA Supplicant - Handle Probe Request/Response
 * Author: Benjamin Morgan <bmorgan@cococorp.com>
 * Copyright (c) 2016, CoCo Communications Corp.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "wpa_supplicant_i.h"
#include "driver_i.h"
#include "utils/list.h"
#include "probe.h"

int wpa_send_directed_probe_request(struct wpa_supplicant* wpa_s, const u8* target_bssid,
				unsigned int freq)
{
	int ret = 0;
	struct wpabuf* frame_buf;
	struct ieee80211_mgmt* req;

	if(wpa_s->current_ssid->ssid_len > SSID_MAX_LEN)
		return -1;

	frame_buf = wpabuf_alloc(200);
	if(frame_buf == NULL)
		return -1;

	req = wpabuf_put(frame_buf, offsetof(struct ieee80211_mgmt, u.probe_req.variable));

	req->frame_control = host_to_le16((WLAN_FC_TYPE_MGMT << 2) |
			(WLAN_FC_STYPE_PROBE_REQ << 4));

	os_memcpy(req->sa, wpa_s->own_addr, ETH_ALEN);
	os_memcpy(req->da, target_bssid, ETH_ALEN);
	os_memcpy(req->bssid, target_bssid, ETH_ALEN);

	wpabuf_put_u8(frame_buf, WLAN_EID_SSID);
	wpabuf_put_u8(frame_buf, wpa_s->current_ssid->ssid_len);
	wpabuf_put_data(frame_buf, wpa_s->current_ssid->ssid, wpa_s->current_ssid->ssid_len);

	wpabuf_put_u8(frame_buf, WLAN_EID_SUPP_RATES);
	wpabuf_put_u8(frame_buf, 8);
	wpabuf_put_u8(frame_buf, (60 / 5) | 0x80);	// 6  Mb/s (BSSBasicRateSet)
	wpabuf_put_u8(frame_buf, 90 / 5);			// 9  Mb/s
	wpabuf_put_u8(frame_buf, (120 / 5) | 0x80);	// 12 Mb/s (BSSBasicRateSet)
	wpabuf_put_u8(frame_buf, 180 / 5);			// 18 Mb/s
	wpabuf_put_u8(frame_buf, (240 / 5) | 0x80); // 24 Mb/s (BSSBasicRateSet)
	wpabuf_put_u8(frame_buf, 360 / 5);			// 36 Mb/s
	wpabuf_put_u8(frame_buf, 480 / 5);			// 48 Mb/s
	wpabuf_put_u8(frame_buf, 540 / 5);			// 54 Mb/s

	wpa_printf(MSG_MSGDUMP, "Probe: Sending directed probe request DA="MACSTR
			" with BSSID="MACSTR, MAC2STR(req->da), MAC2STR(req->bssid));

	ret = wpa_drv_send_mlme(wpa_s, wpabuf_head(frame_buf), wpabuf_len(frame_buf), 0, freq);

	wpabuf_free(frame_buf);

	return ret;
}


int wpa_handle_probe_resp (struct wpa_supplicant *wpa_s,
				const u8 *frame, size_t len, int freq, int rssi)
{
	const struct ieee80211_mgmt *mgmt;
	const u8 *payload;
	size_t plen;
	u8 category;
	int ret = 0;

	if (len < IEEE80211_HDRLEN + 2)
		return -1;

	mgmt = (const struct ieee80211_mgmt *) frame;
	payload = frame + IEEE80211_HDRLEN;
	plen = len - IEEE80211_HDRLEN - 1;

	wpa_printf(MSG_MSGDUMP, "Probe: Received Probe Response frame: SA=" MACSTR
		" freq=%d MHz", MAC2STR(mgmt->sa), freq);

#ifdef CONFIG_WNM
	ret = wnm_rx_directed_probe_response(wpa_s, mgmt, freq, rssi);
#endif /* CONFIG_WNM */

	return ret;
}
