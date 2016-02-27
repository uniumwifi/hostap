/*
 * hostapd / Station client taxonomy
 * Copyright (c) 2015 Google, Inc.
 *
 * This software may be distributed under the terms of the BSD license.
 * See README for more details.
 */

#ifndef TAXONOMY_H
#define TAXONOMY_H

void hostapd_taxonomy_probe_req(const struct hostapd_data *hapd,
	struct sta_info *sta, const u8 *ie, size_t ie_len);
void hostapd_taxonomy_assoc_req(const struct hostapd_data *hapd,
	struct sta_info *sta, const u8 *ie, size_t ie_len);

#endif /* TAXONOMY_H */
