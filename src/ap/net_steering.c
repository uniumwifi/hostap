#include "net_steering.h"
#include "utils/includes.h"
#include "utils/state_machine.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"
#include "utils/wpabuf.h"
#include "utils/list.h"
#include "utils/eloop.h"
#include "hostapd.h"
#include "ap_config.h"
#include "sta_blacklist.h"
#include "sta_info.h"
#include "wpa_auth.h"
#include "common/defs.h"
#include "l2_packet/l2_packet.h"

#include <sys/ioctl.h>

// #include <net/if.h>
// #include <netinet/ether.h>
// #include <linux/if_packet.h>

#define MAX_FRAME_SIZE 1024

static const u16 proto = 0x8267; // chosen at random from unassigned
static const u8 tlv_magic = 48;
static const u8 tlv_version = 1;

#define TLV_SCORE 0
#define TLV_CLOSE_CLIENT 1
#define TLV_CLOSED_CLIENT 2
#define TLV_MAP 4
#define TLV_CLIENT_FLAGS 5

#define FLOOD_TIMEOUT 1

struct net_steering_client;
struct net_steering_bss;

struct net_steering_sm {

	enum {
		STEERING_IDLE,        // AP will allow the client to associate with it.
		STEERING_CONFIRMING,  // AP has told another AP to blacklist the client and is waiting for it to tell us that it has blacklisted the client.
		STEERING_ASSOCIATING, // A remote AP has confirmed that it has blacklisted the client; AP is now waiting on an associate.
		STEERING_ASSOCIATED,  // The client is using this AP to communicate with other devices.
		STEERING_REJECTING,   // The AP has blacklisted the client is waiting on a disassociate and will then send out a closed packet to remotes.
		STEERING_REJECTED,    // The client is blacklisted and disassociated.
	} STEERING_state;

	enum {
		STEERING_E_ASSOCIATED,
		STEERING_E_DISASSOCIATED,
		STEERING_E_PEER_IS_WORSE,
		STEERING_E_PEER_NOT_WORSE,
		STEERING_E_PEER_LOST_CLIENT,
		STEERING_E_CLOSE_CLIENT,
		STEERING_E_CLOSED_CLIENT,
		STEERING_E_TIMEOUT,
	} STEERING_event;

	unsigned int changed;
	u8 addr[ETH_ALEN];
	struct net_steering_client* client;
};


// Use this so we can track additional data for stas and avoid adding more members to sta_info
// It does mean that we need to be concerned about the lifetime of sta_info objects tracked
// by hapd
struct net_steering_client
{
	struct dl_list list;
	struct net_steering_sm sm;
	struct sta_info* sta;           // This will point to a sta in the hapd list pointed to by the nsb.
	struct net_steering_bss* nsb;
	int rssi;
};

// One context per bss
struct net_steering_bss {
	struct dl_list list;        // supports a dl_list of net_steering_bss
	struct dl_list clients;     // contains the list of associated clients
	struct hostapd_data *hapd;
	u16 frame_sn;
	struct l2_packet_data *control; // the steering control channel
};

static struct dl_list nsb_list = DL_LIST_HEAD_INIT(nsb_list);

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

int probe_req_cb(void *ctx, const u8 *sa, const u8 *da, const u8 *bssid,
		   const u8 *ie, size_t ie_len, int ssi_signal)
{
	struct net_steering_bss* nsb = ctx;
	struct hostapd_data *hapd = nsb->hapd;
	struct net_steering_client *client = NULL;

	dl_list_for_each(client, &nsb->clients, struct net_steering_client, list) {
		if (client->sta && os_memcmp(sa, client->sta->addr, ETH_ALEN) == 0) {
			hostapd_logger(hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "probe request from "MACSTR" signal %d\n",
				MAC2STR(sa), ssi_signal);
			client->rssi = ssi_signal;
			break;
		}
	}

	return 0;
}

static void flood_score(void *eloop_data, void *user_ctx);

static void start_flood_timer(struct net_steering_client *client)
{
	if (eloop_register_timeout(FLOOD_TIMEOUT, 0, flood_score, client, NULL)) {
		hostapd_logger(client->nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "client "MACSTR" failed to schedule flood\n",
				MAC2STR(client->sta->addr));
	}
}

static void flood_score(void *eloop_data, void *user_ctx)
{
	struct net_steering_client* client = (struct net_steering_client*) eloop_data;
	struct net_steering_bss* nsb = client->nsb;
	struct wpabuf* buf;
	struct ft_remote_r0kh *r0kh = nsb->hapd->conf->r0kh_list;
	int ret;

	// TODO pick a better encoding?
	u16 score = abs(client->rssi);

	buf = wpabuf_alloc(MAX_FRAME_SIZE);
	put_header(buf, nsb->frame_sn++);
	put_score(buf, client->sta->addr, nsb->hapd->conf->bssid, score);
	finalize_header(buf);

	while (r0kh) {
		u8* dst = r0kh->addr;

		// don't send to ourself
		if (os_memcmp(dst, nsb->hapd->own_addr, ETH_ALEN) != 0) {

			hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "Flooding from "MACSTR" to "MACSTR"\n",
			MAC2STR(nsb->hapd->own_addr), MAC2STR(dst));

			ret = l2_packet_send(nsb->control, dst, proto, wpabuf_head(buf), wpabuf_len(buf));
			if (ret < 0) {
				hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "Failed flood to "MACSTR" : error %d\n",
				MAC2STR(dst), ret);
			}
		}
		r0kh = r0kh->next;
	}

	wpabuf_free(buf);
	start_flood_timer(client);
}

static void client_timeout(void *eloop_data, void *user_ctx)
{
	struct net_steering_client* client = (struct net_steering_client*) eloop_data;
	struct net_steering_bss* nsb = client->nsb;


}


static void start_timeout_timer(struct net_steering_client *client)
{
	if (eloop_register_timeout(FLOOD_TIMEOUT, 0, client_timeout, client, NULL)) {
		hostapd_logger(client->nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "client "MACSTR" failed to schedule timeout\n",
				MAC2STR(client->sta->addr));
	}
}

#define STATE_MACHINE_DATA struct net_steering_sm
#define STATE_MACHINE_DEBUG_PREFIX "STEERING"
#define STATE_MACHINE_ADDR sm->addr

#define SM_EVENT(machine, fromstate, e_event, tostate) \
static void sm_ ## machine ## _ ## fromstate ## _on_ ## e_event ## _ ## tostate(STATE_MACHINE_DATA *sm, \
			int global)

#define SM_TRANSITION(machine, fromstate, e_event, tostate) \
	if (sm->machine ## _state == machine ## _ ## fromstate && event == machine ## _ ## e_event) { \
		sm_ ## machine ## _ ## fromstate ## _on ## _ ## e_event ## _ ## tostate(sm, 0); \
		SM_ENTER(STEERING, tostate); \
		return; \
	}

#define SM_TRANS_NOOP(machine, fromstate, e_event, tostate) \
	if (sm->machine ## _state == machine ## _ ## fromstate && event == machine ## _ ## e_event) { \
		SM_ENTER(STEERING, tostate); \
		return; \
	}

#define SM_STEP_EVENT(machine) \
static void sm_ ## machine ## _do_Event(STATE_MACHINE_DATA *sm, int event)


#define SM_STEP_EVENT_RUN(machine, event, sm) \
	sm_ ## machine ## _do_Event(sm, machine ## _ ## event);


SM_STATE(STEERING, IDLE) { SM_ENTRY(STEERING, IDLE); }
SM_STATE(STEERING, CONFIRMING) { SM_ENTRY(STEERING, CONFIRMING); }
SM_STATE(STEERING, ASSOCIATING) { SM_ENTRY(STEERING, ASSOCIATING); }
SM_STATE(STEERING, ASSOCIATED) { SM_ENTRY(STEERING, ASSOCIATED); }
SM_STATE(STEERING, REJECTING) { SM_ENTRY(STEERING, REJECTING); }
SM_STATE(STEERING, REJECTED) { SM_ENTRY(STEERING, REJECTED); }

SM_EVENT(STEERING, IDLE, E_ASSOCIATED, ASSOCIATED)
{
	// flood score
	start_flood_timer(sm->client);
}

SM_EVENT(STEERING, IDLE, E_PEER_IS_WORSE, CONFIRMING)
{
	// send close client
}

SM_EVENT(STEERING, IDLE, E_PEER_NOT_WORSE, REJECTED)
{
	// blacklist
}

SM_EVENT(STEERING, IDLE, E_CLOSE_CLIENT, REJECTED)
{
	// close client
	// blacklist
}

SM_EVENT(STEERING, CONFIRMING, E_PEER_IS_WORSE, CONFIRMING)
{
	// close client
}

SM_EVENT(STEERING, CONFIRMING, E_PEER_NOT_WORSE, REJECTED)
{
	// blacklist
}


SM_EVENT(STEERING, ASSOCIATING, E_PEER_IS_WORSE, ASSOCIATING)
{
	// close client
}

SM_EVENT(STEERING, ASSOCIATING, E_CLOSE_CLIENT, REJECTED)
{
	// closed client
	// blacklist
}


SM_EVENT(STEERING, ASSOCIATED, E_CLOSE_CLIENT, REJECTING)
{
	// flood score
	// blacklist
	// disassociate
	// clear remotes
}

SM_EVENT(STEERING, ASSOCIATED, E_DISASSOCIATED, IDLE)
{
	// flood score
	// flood peer lost client
}

SM_EVENT(STEERING, ASSOCIATED, E_PEER_IS_WORSE, ASSOCIATED)
{
	// flood peer lost client
	// close client
}

SM_EVENT(STEERING, REJECTING, E_DISASSOCIATED, REJECTED)
{
	// closed client
}

SM_EVENT(STEERING, REJECTING, E_PEER_IS_WORSE, CONFIRMING)
{
	// close client
	// unblacklist
}

SM_EVENT(STEERING, REJECTING, E_PEER_LOST_CLIENT, CONFIRMING)
{
	// unblacklist
}

SM_EVENT(STEERING, REJECTING, E_TIMEOUT, ASSOCIATING)
{
	// unblacklist
}

SM_EVENT(STEERING, REJECTED, E_PEER_IS_WORSE, CONFIRMING)
{
	// close client
}

SM_EVENT(STEERING, REJECTED, E_PEER_LOST_CLIENT, CONFIRMING)
{
	// close client
	// unblacklist
}

SM_EVENT(STEERING, REJECTED, E_CLOSE_CLIENT, REJECTED)
{
	// close client
}

SM_EVENT(STEERING, REJECTED, E_TIMEOUT, ASSOCIATING)
{
	// unblacklist
}

SM_STEP_EVENT(STEERING)
{
	// Not sure if this is needed other than the macros in state_machine.h need it.
	int global = 0;

	SM_TRANSITION(STEERING, IDLE, E_ASSOCIATED, ASSOCIATED);
	SM_TRANSITION(STEERING, IDLE, E_PEER_IS_WORSE, CONFIRMING);
	SM_TRANSITION(STEERING, IDLE, E_PEER_NOT_WORSE, REJECTED);
	SM_TRANS_NOOP(STEERING, IDLE, E_PEER_LOST_CLIENT, ASSOCIATING);
	SM_TRANSITION(STEERING, IDLE, E_CLOSE_CLIENT, REJECTED);

	SM_TRANS_NOOP(STEERING, CONFIRMING, E_CLOSED_CLIENT, ASSOCIATING);
	SM_TRANS_NOOP(STEERING, CONFIRMING, E_ASSOCIATED, ASSOCIATED);
	SM_TRANS_NOOP(STEERING, CONFIRMING, E_TIMEOUT, IDLE);
	SM_TRANSITION(STEERING, CONFIRMING, E_PEER_IS_WORSE, CONFIRMING);
	SM_TRANSITION(STEERING, CONFIRMING, E_PEER_NOT_WORSE, REJECTED);

	SM_TRANS_NOOP(STEERING, ASSOCIATING, E_ASSOCIATED, ASSOCIATED);
	SM_TRANS_NOOP(STEERING, ASSOCIATING, E_DISASSOCIATED, IDLE);
	SM_TRANSITION(STEERING, ASSOCIATING, E_PEER_IS_WORSE, ASSOCIATING);
	SM_TRANSITION(STEERING, ASSOCIATING, E_CLOSE_CLIENT, REJECTED);

	SM_TRANSITION(STEERING, ASSOCIATED, E_CLOSE_CLIENT, REJECTING);
	SM_TRANSITION(STEERING, ASSOCIATED, E_DISASSOCIATED, IDLE);
	SM_TRANSITION(STEERING, ASSOCIATED, E_PEER_IS_WORSE, ASSOCIATED);

	SM_TRANS_NOOP(STEERING, REJECTING, E_CLOSE_CLIENT, REJECTING);
	SM_TRANSITION(STEERING, REJECTING, E_DISASSOCIATED, REJECTED);
	SM_TRANSITION(STEERING, REJECTING, E_PEER_IS_WORSE, CONFIRMING);
	SM_TRANSITION(STEERING, REJECTING, E_PEER_LOST_CLIENT, CONFIRMING);
	SM_TRANSITION(STEERING, REJECTING, E_TIMEOUT, ASSOCIATING);

	SM_TRANSITION(STEERING, REJECTED, E_PEER_IS_WORSE, CONFIRMING);
	SM_TRANSITION(STEERING, REJECTED, E_PEER_LOST_CLIENT, CONFIRMING);
	SM_TRANSITION(STEERING, REJECTED, E_CLOSE_CLIENT, REJECTED);
	SM_TRANSITION(STEERING, REJECTED, E_TIMEOUT, ASSOCIATING);
}

static void nsc_receive(void *ctx, const u8 *src_addr, const u8 *buf, size_t len)
{
	struct net_steering_bss* nsb = ctx;
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
		hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": %d bytes\n",
				MAC2STR(src_addr), len);
		return;
	}

	if (len < packet_len) {
		hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": recv %d bytes, expected %d\n",
				MAC2STR(src_addr), len, packet_len);
		return;
	}

	if (tlv_version != version || tlv_magic != magic) {
		hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping invalid message from "MACSTR": magic %d version %d\n",
				MAC2STR(src_addr), magic, version);
		return;
	}
	buf_pos += num_read;

	while (buf_pos < buf + packet_len) {
		num_read = parse_tlv_header(buf_pos, packet_len-(buf_pos-buf), &type_tlv, &tlv_len);
		if (!num_read) {
			hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
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
				hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
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

	hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "Received %d bytes from "MACSTR" : %d\n",
			len, MAC2STR(src_addr), ntohs(sn));
}

static void net_steering_del_client(struct net_steering_client* client)
{
	eloop_cancel_timeout(flood_score, client, NULL);
	eloop_cancel_timeout(client_timeout, client, NULL);

	dl_list_del(&client->list);
	os_memset(client, 0, sizeof(*client));
	os_free(client);
}

void net_steering_disassociation(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct net_steering_bss* nsb = NULL;
	struct net_steering_client *client, *ctmp;

	// find the context
	dl_list_for_each(nsb, &nsb_list, struct net_steering_bss, list) {
		if (nsb->hapd == hapd) break;
	}

	if (!nsb) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_WARNING, "Association to unknown bss "MACSTR"\n",
			MAC2STR(hapd->conf->bssid));
		return;
	}

	// find the client and clean it up
	dl_list_for_each_safe(client, ctmp, &nsb->clients, struct net_steering_client, list) {
		if (client->sta == sta) {
			// TODO Log this event
			SM_STEP_EVENT_RUN(STEERING, E_DISASSOCIATED, &(client->sm));
			net_steering_del_client(client);
			break;
		}
	}
}

void net_steering_association(struct hostapd_data *hapd, struct sta_info *sta)
{
	struct net_steering_bss* nsb = NULL;
	struct net_steering_client* client = NULL;

	dl_list_for_each(nsb, &nsb_list, struct net_steering_bss, list) {
		if (nsb->hapd == hapd) break;
	}

	if (!nsb) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_WARNING, "Association to unknown bss "MACSTR"\n",
			MAC2STR(hapd->conf->bssid));
		return;
	}

	hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_association - "MACSTR" associated to "MACSTR"\n",
				MAC2STR(sta->addr), MAC2STR(nsb->hapd->conf->bssid));

	// TODO Scan the list of existing clients

	client = (struct net_steering_client*) os_zalloc(sizeof(*client));
	if (!client)
	{
		// LOG and return
		return;
	}

	// TODO Verify lifetime of the sta pointer.
	client->sta = sta;
	client->nsb = nsb;
	client->rssi = -1;
	client->sm.STEERING_state = STEERING_IDLE;
	client->sm.client = client;

	dl_list_add(&nsb->clients, &client->list);

	SM_STEP_EVENT_RUN(STEERING, E_ASSOCIATED, &(client->sm));
}

void net_steering_deinit(struct hostapd_data *hapd)
{
	struct net_steering_bss *nsb, *tmp;

	dl_list_for_each_safe(nsb, tmp, &nsb_list, struct net_steering_bss, list) {
		if (nsb->hapd == hapd) {
			struct net_steering_client *client, *ctmp;
			if (nsb->control != NULL) {
				l2_packet_deinit(nsb->control);
				wpa_printf(MSG_DEBUG, "net_steering_deinit - l2_packet_deinit");
			}

			// free all clients
			dl_list_for_each_safe(client, ctmp, &nsb->clients, struct net_steering_client, list) {
				net_steering_del_client(client);
			}
			os_memset(nsb, 0, sizeof(*nsb));
			os_free(nsb);
			break;
		}
	}
}

int net_steering_init(struct hostapd_data *hapd)
{
	struct net_steering_bss* nsb = (struct net_steering_bss*) os_zalloc(sizeof(*nsb));

	if (!nsb) return -1;

	// TODO: what if there is no bridge in use? use iface?
	nsb->control = l2_packet_init(hapd->conf->bridge, NULL, proto, nsc_receive, nsb, 0);
	if (nsb->control == NULL) {
		hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_init - l2_packet_init failed for %s with bssid "MACSTR"\n",
				hapd->conf->bridge, MAC2STR(nsb->hapd->conf->bssid));

		os_memset(nsb, 0, sizeof(*nsb));
		os_free(nsb);
		return -1;
	}

	nsb->hapd = hapd;
	dl_list_init(&nsb->clients);

	// add the context to the end of the list
	dl_list_add(&nsb_list, &nsb->list);
	hostapd_register_probereq_cb(hapd, probe_req_cb, nsb);

	hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "net_steering_init - ready on %s with bssid "MACSTR" own addr "MACSTR"\n",
			hapd->conf->bridge, MAC2STR(nsb->hapd->conf->bssid), MAC2STR(nsb->hapd->own_addr));

	// We piggy-back on R configuration, and use that config to identify our peer APs
	if (!nsb->hapd->conf->r0kh_list) {
		hostapd_logger(nsb->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "net_steering_init - no FT peers configured on bssid "MACSTR"\n",
				MAC2STR(nsb->hapd->conf->bssid));
	}
	return 0;
}

