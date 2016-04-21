#include "net_steering.h"
#include "utils/includes.h"
#include "utils/state_machine.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"
#include "utils/wpabuf.h"
#include "utils/list.h"
#include "common/defs.h"
#include "sta_info.h"
#include "l2_packet/l2_packet.h"
#include "hostapd.h"
#include "ap_config.h"

#include <sys/ioctl.h>

// #include <net/if.h>
// #include <netinet/ether.h>
// #include <linux/if_packet.h>

#define MAX_FRAME_SIZE 1024

static const u16 proto = 0x8267; // chosen at random from unassigned
static const u8 tlv_magic = 48;
static const u8 tlv_version = 1;

#define TLV_SCORE 0
#define TLV_CLOSE_CLIENT = 1;
#define TLV_CLOSED_CLIENT = 2;
#define TLV_MAP = 4;
#define TLV_CLIENT_FLAGS = 5;

// One context per bss
// TODO: need to track list of peers
struct net_steering_context {
	struct dl_list list;
	struct hostapd_data *hapd;
	u16 frame_sn;
	struct l2_packet_data *control; // the steering control channel
};

static struct dl_list nsc_list = DL_LIST_HEAD_INIT(nsc_list);

static u8 one[ETH_ALEN] = { 0xe8, 0xde, 0x27, 0x6d, 0xcc, 0x5c };
static u8 two[ETH_ALEN] = { 0xe8, 0xde, 0x27, 0x65, 0xe5, 0x1c };

static void put_header(struct wpabuf* buf, u16 sn)
{
	u16 len = 0;
	wpabuf_put_u8(buf, tlv_magic);
	wpabuf_put_u8(buf, tlv_version);
	wpabuf_put_data(buf, &len, sizeof(len));
	sn = htons(sn);
	wpabuf_put_data(buf, &sn, sizeof(sn));
}

// write the total length into the header
static void finalize_header(struct wpabuf* buf)
{
	u16* p = (u16*)(wpabuf_mhead_u8(buf) + (sizeof(tlv_magic) + sizeof(tlv_version)));
	*p = htons(wpabuf_len(buf));
}

static size_t parse_header(const u8* buf, size_t len, u8* magic, u8* version, u16* packet_len, u16* sn)
{
	static u16 header_len = sizeof(*magic) + sizeof(*version) + sizeof(*sn) + sizeof(*packet_len);

	if (len < header_len) return 0;

	const u8* tmp = buf;
	os_memcpy(magic, tmp, sizeof(*magic));
	tmp += sizeof(*magic);

	os_memcpy(version, tmp, sizeof(*version));
	tmp += sizeof(*version);

	os_memcpy(packet_len, tmp, sizeof(*packet_len));
	*packet_len = ntohs(*packet_len);
	tmp += sizeof(*packet_len);

	os_memcpy(sn, tmp, sizeof(*sn));
	*sn = ntohs(*sn);
	tmp += sizeof(*sn);

	return tmp - buf;
}

static void put_tlv_header(struct wpabuf* buf, u8 tlv_type, u8 tlv_len)
{
	wpabuf_put_u8(buf, tlv_type);
	wpabuf_put_u8(buf, tlv_len);
}

static size_t parse_tlv_header(const u8* buf, size_t len, u8* tlv_type, u8* tlv_len)
{
	static const header_len = sizeof(*tlv_type) + sizeof(*tlv_len);
	const u8* tmp = buf;
	if (len < header_len) return 0;

	os_memcpy(tlv_type, tmp, sizeof(*tlv_type));
	tmp += sizeof(*tlv_type);

	os_memcpy(tlv_len, tmp, sizeof(*tlv_len));
	tmp += sizeof(*tlv_len);

	return tmp - buf;
}

static void put_score(struct wpabuf* buf, u8* sta, u8* bssid, u16 score)
{
	static u8 score_len = ETH_ALEN + ETH_ALEN + sizeof(score);

	put_tlv_header(buf, TLV_SCORE, score_len);
	wpabuf_put_data(buf, sta, ETH_ALEN);
	wpabuf_put_data(buf, bssid, ETH_ALEN);
	score = htons(score);
	wpabuf_put_data(buf, &score, sizeof(score));
}

static size_t parse_score(const u8* buf, size_t len, u8* sta, u8* bssid, u16* score)
{
	static u8 score_len = ETH_ALEN + ETH_ALEN + sizeof(*score);

	if (len < score_len) return 0;

	const u8* tmp = buf;
	os_memcpy(sta, tmp, ETH_ALEN);
	tmp += ETH_ALEN;
	os_memcpy(bssid, tmp, ETH_ALEN);
	tmp += ETH_ALEN;
	os_memcpy(score, tmp, sizeof(*score));
	*score = ntohs(*score);
	tmp += sizeof(*score);
	return tmp - buf;
}

struct net_steering_sm {

	enum {
		STEERING_IDLE,        // AP will allow the client to associate with it.
		STEERING_CONFIRMING,  // AP has told another AP to blacklist the client and is waiting for it to tell us that it has blacklisted the client.
		STEERING_ASSOCIATING, // A remote AP has confirmed that it has blacklisted the client; AP is now waiting on an associate.
		STEERING_ASSOCIATED,  // The client is using this AP to communicate with other devices.
		STEERING_REJECTING,   // The AP has blacklisted the client is waiting on a disassociate and will then send out a closed packet to remotes.
		STEERING_REJECTED,    // The client is blacklisted and disassociated.
	} STEERING_state;

	unsigned int changed;
	u8 addr[ETH_ALEN];
};

#define STATE_MACHINE_DATA struct net_steering_sm
#define STATE_MACHINE_DEBUG_PREFIX "STEERING"
#define STATE_MACHINE_ADDR sm->addr

SM_STATE(STEERING, IDLE) {
	SM_ENTRY(STEERING, IDLE);
}

SM_STATE(STEERING, CONFIRMING) {
	SM_ENTRY(STEERING, CONFIRMING);
}

SM_STATE(STEERING, ASSOCIATING) {
	SM_ENTRY(STEERING, ASSOCIATING);
}

SM_STATE(STEERING, ASSOCIATED) {
	SM_ENTRY(STEERING, ASSOCIATED);
}

SM_STATE(STEERING, REJECTING) {
	SM_ENTRY(STEERING, REJECTING);
}

SM_STATE(STEERING, REJECTED) {
	SM_ENTRY(STEERING, REJECTED);
}

static void nsc_receive(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct net_steering_context* nsc = ctx;
	u16 sn = 0;
	u8 magic, version, type_tlv, tlv_len = 0;
	u16 packet_len = 0;
	u16 score = 0;
	u8 sta[ETH_ALEN];
	u8 bssid[ETH_ALEN];
	size_t num_read = 0;

	const u8* buf_pos = buf;

	num_read = parse_header(buf_pos, len, &magic, &version, &packet_len, &sn);
	if (!num_read) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": %d bytes\n",
				MAC2STR(src_addr), len);
		return;
	}

	if (len < packet_len) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": recv %d bytes, expected %d\n",
				MAC2STR(src_addr), len, packet_len);
		return;
	}

	if (tlv_version != version || tlv_magic != magic) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping invalid message from "MACSTR": magic %d version %d\n",
				MAC2STR(src_addr), magic, version);
		return;
	}
	buf_pos += num_read;

	while (buf_pos < buf + packet_len) {
		num_read = parse_tlv_header(buf_pos, packet_len-(buf_pos-buf), &type_tlv, &tlv_len);
		if (!num_read) {
			hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
					HOSTAPD_LEVEL_DEBUG, "Could not parse tlv header from "MACSTR"\n",
					len, MAC2STR(src_addr));
			return;
		}
		buf_pos += num_read;

		switch (type_tlv)
		{
		case TLV_SCORE:
			num_read = parse_score(buf_pos, tlv_len, sta, bssid, &score);
			if (!num_read) {
				hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
						HOSTAPD_LEVEL_DEBUG, "Could not parse score from "MACSTR"\n",
						len, MAC2STR(src_addr));
				return;
			}
			buf_pos += num_read;

			break;
		default:
			// skip unknown tlvs
			buf_pos += tlv_len;

			// TODO WARNING
			break;
		}
	}

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "Received %d bytes from "MACSTR" : %d\n",
			len, MAC2STR(src_addr), ntohs(sn));
}

void net_steering_association(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct wpabuf *buf;
	int ret = 0;
	u8 *dst = NULL;
	struct net_steering_context* nsc = NULL;
	u8 own[ETH_ALEN];
	u16 score = 0;

	dl_list_for_each(nsc, &nsc_list, struct net_steering_context, list) {
		if (nsc->hapd == hapd) break;
	}

	if (!nsc) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_WARNING, "Association to unknown bss "MACSTR"\n",
			MAC2STR(hapd->conf->bssid));
		return;
	}

	// TODO compute score!
	// TODO track the client, or is it already tracked in hapd somewhere?

	buf = wpabuf_alloc(MAX_FRAME_SIZE);
	put_header(buf, nsc->frame_sn++);
	put_score(buf, sta->addr, nsc->hapd->conf->bssid, score);
	// TODO remove this extra score put here as test
	score = 10;
	put_score(buf, sta->addr, nsc->hapd->conf->bssid, score);
	finalize_header(buf);

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_association - "MACSTR" associated to "MACSTR"\n",
				MAC2STR(sta->addr), MAC2STR(nsc->hapd->conf->bssid));

	// TODO need to manage configuration of peer list
	l2_packet_get_own_addr(nsc->control, own);
	dst = (os_memcmp(own, one, ETH_ALEN) == 0) ? two : one;

	ret = l2_packet_send(nsc->control, dst, proto, wpabuf_head(buf), wpabuf_len(buf));
	if (ret < 0) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "Failed l2 send to "MACSTR" : error %d\n",
				MAC2STR(dst), ret);
	}

	wpabuf_free(buf);
}

void net_steering_deinit(struct hostapd_data *hapd)
{
	struct net_steering_context* nsc;
	struct net_steering_context* tmp;

	dl_list_for_each_safe(nsc, tmp, &nsc_list, struct net_steering_context, list) {
		if (nsc->hapd == hapd) {
			if (nsc->control != NULL) {
				l2_packet_deinit(nsc->control);
				wpa_printf(MSG_DEBUG, "net_steering_deinit - l2_packet_deinit");
			}
			os_memset(nsc, 0, sizeof(*nsc));
			os_free(nsc);
			break;
		}
	}
}

int net_steering_init(struct hostapd_data *hapd)
{
	struct net_steering_context* nsc = (struct net_steering_context*) os_zalloc(sizeof(*nsc));

	if (!nsc) return -1;

	nsc->hapd = hapd;

	// TODO: what if there is no bridge in use? use iface?
	nsc->control = l2_packet_init(hapd->conf->bridge, NULL, proto, nsc_receive, nsc, 0);
	if (nsc->control == NULL) {

		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_init - l2_packet_init failed for %s with bssid "MACSTR"\n",
				hapd->conf->bridge, MAC2STR(nsc->hapd->conf->bssid));

		os_memset(nsc, 0, sizeof(*nsc));
		os_free(nsc);
		return -1;
	}

	// add the context to the end of the list
	dl_list_add(&nsc_list, &nsc->list);

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "net_steering_init - ready on %s with bssid "MACSTR"\n",
			hapd->conf->bridge, MAC2STR(nsc->hapd->conf->bssid));

	return 0;
}

