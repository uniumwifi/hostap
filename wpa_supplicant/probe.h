/*
 * WPA Supplicant - Handle Probe Request/Response
 * Author: Benjamin Morgan <bmorgan@cococorp.com>
 * Copyright (c) 2016, CoCo Communications Corp.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef PROBE_H
#define PROBE_H

int wpa_send_directed_probe_request(struct wpa_supplicant* wpa_s, const u8* target_bssid,
				unsigned int freq);

int wpa_handle_probe_resp (struct wpa_supplicant *wpa_s,
				const u8 *frame, size_t len, int freq, int rssi);

#endif /* PROBE_H */
