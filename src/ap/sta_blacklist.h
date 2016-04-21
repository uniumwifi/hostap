#ifndef STA_BLACKLIST_H
#define STA_BLACKLIST_H

struct sta_blacklist {
	struct sta_blacklist *next;
	u8 sta[ETH_ALEN];
};

struct sta_blacklist * sta_blacklist_get(struct hostapd_data *hapd, const u8 *sta);
int sta_blacklist_present(struct hostapd_data *hapd, const u8 *sta);
int sta_blacklist_add(struct hostapd_data *hapd, const u8 *sta);
int sta_blacklist_rm(struct hostapd_data *hapd, const u8 *sta);
int sta_blacklist_clear(struct hostapd_data *hapd);
#endif /* STA_BLACKLIST_H */
