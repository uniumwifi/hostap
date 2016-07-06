#include "utils/includes.h"

#include "utils/common.h"
#include "common/ieee802_11_defs.h"
#include "eapol_auth/eapol_auth_sm.h"
#include "hostapd.h"
#include "ieee802_1x.h"
#include "wpa_auth.h"
#include "ieee802_11.h"
#include "sta_info.h"
#include "sta_blacklist.h"

/**
 * sta_blacklist_get - Get the blacklist entry for a BSSID
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID
 * Returns: Matching blacklist entry for the BSSID or %NULL if not found
 */
struct sta_blacklist * sta_blacklist_get(struct hostapd_data *hapd, const u8 *sta) {
	struct sta_blacklist *e;

	if (hapd == NULL || sta == NULL)
		return NULL;

	e = hapd->blacklist;
	while (e) {
		if (os_memcmp(e->sta, sta, ETH_ALEN) == 0)
			return e;
		e = e->next;
	}

	return NULL;
}

int sta_blacklist_present(struct hostapd_data *hapd, const u8 *sta)
{
	if(sta_blacklist_get(hapd, sta) != NULL)
		return 1;

	return 0;
}



/**
 * wpa_blacklist_add - Add an BSSID to the blacklist
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID to be added to the blacklist
 * Returns: Current blacklist count on success, -1 on failure
 *
 * This function adds the specified BSSID to the blacklist or increases the
 * blacklist count if the BSSID was already listed. It should be called when
 * an association attempt fails either due to the selected BSS rejecting
 * association or due to timeout.
 *
 * This blacklist is used to force %wpa_supplicant to go through all available
 * BSSes before retrying to associate with an BSS that rejected or timed out
 * association. It does not prevent the listed BSS from being used; it only
 * changes the order in which they are tried.
 */
int sta_blacklist_add(struct hostapd_data *hapd, const u8 *sta) {
	struct sta_blacklist *e;

	if (hapd == NULL || sta == NULL)
		return -1;

	e = sta_blacklist_get(hapd, sta);
	if (e) {
		return 0;
	}

	e = os_zalloc(sizeof(*e));
	if (e == NULL)
		return -1;
	os_memcpy(e->sta, sta, ETH_ALEN);


	e->next = hapd->blacklist;
	hapd->blacklist = e;

	hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
		       HOSTAPD_LEVEL_INFO, "Added BSSID " MACSTR " into blacklist", MAC2STR(sta));

	return 0;
}

/**
 * wpa_blacklist_del - Remove an BSSID from the blacklist
 * @wpa_s: Pointer to wpa_supplicant data
 * @bssid: BSSID to be removed from the blacklist
 * Returns: 0 on success, -1 on failure
 */
int sta_blacklist_rm(struct hostapd_data *hapd, const u8 *sta) {
	struct sta_blacklist *e, *prev = NULL;

	if (hapd == NULL || sta == NULL)
		return -1;

	e = hapd->blacklist;
	while (e) {
		if (os_memcmp(e->sta, sta, ETH_ALEN) == 0) {
			if (prev == NULL) {
				hapd->blacklist = e->next;
			} else {
				prev->next = e->next;
			}

			hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
				       HOSTAPD_LEVEL_INFO, "Removed BSSID " MACSTR " from blacklist", MAC2STR(sta));

			os_free(e);

			return 0;
		}
		prev = e;
		e = e->next;
	}
	return -1;
}

/**
 * wpa_blacklist_clear - Clear the blacklist of all entries
 * @wpa_s: Pointer to wpa_supplicant data
 */
int sta_blacklist_clear(struct hostapd_data *hapd) {
	struct sta_blacklist *e, *prev;

	e = hapd->blacklist;
	hapd->blacklist = NULL;
	while (e) {
		prev = e;
		e = e->next;
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_IEEE80211,
			       HOSTAPD_LEVEL_INFO, "Removed BSSID " MACSTR " from blacklist", MAC2STR(prev->sta));
		//wpa_printf(MSG_ERROR, "Removed BSSID " MACSTR " from blacklist (clear)", MAC2STR(prev->sta));
		os_free(prev);
	}

	return 0;
}
