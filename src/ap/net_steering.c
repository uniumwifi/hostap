#include "net_steering.h"
#include "utils/includes.h"
#include "utils/state_machine.h"
#include "utils/common.h"
#include "utils/wpa_debug.h"
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
#define TLV_MAGIC 32
#define TLV_VERSION 1
#define PROTO 0x8267

struct net_steering_header {
	u8 magic;
	u8 version;
	u16 counter;
	u16 len;
}__attribute__ ((packed));

// One context per bss
// TODO: need to track list of peers
struct net_steering_context {
	struct net_steering_context* next;
	struct hostapd_data *hapd;
	u16 frame_counter;              // count our frames TODO Maybe we don't need this
	struct l2_packet_data *control; // the steering control channel
};

// crude linked-list to track contexts
static struct net_steering_context *nsc_head;

static u8 one[ETH_ALEN] = { 0xe8, 0xde, 0x27, 0x6d, 0xcc, 0x5c };
static u8 two[ETH_ALEN] = { 0xe8, 0xde, 0x27, 0x65, 0xe5, 0x1c };

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

static void nsc_receive(void *ctx, const u8 *src_addr, const u8 *buf, size_t len) {
	struct net_steering_header* hdr;
	struct net_steering_context* nsc = ctx;

	if (len < sizeof(*hdr)) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": %d bytes\n",
				MAC2STR(src_addr), len);
		return;
	}

	hdr = (struct net_steering_header*) buf;
	if (len < (sizeof(*hdr) + ntohs(hdr->len))) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping short message from "MACSTR": %d bytes\n",
				MAC2STR(src_addr), len);
		return;
	}

	if (TLV_VERSION != hdr->version || TLV_MAGIC != hdr->magic) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG,
				"Dropping invalid message from "MACSTR": magic %d version %d\n",
				MAC2STR(src_addr), hdr->magic, hdr->version);
		return;
	}

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "Received %d bytes from "MACSTR" : %d\n",
			len, MAC2STR(src_addr), ntohs(hdr->counter));

}

static struct net_steering_context* find_nsc_by_hapd(struct hostapd_data *hapd)
{
	struct net_steering_context* tmp = nsc_head;
	while (tmp && tmp->hapd != hapd) tmp = tmp->next;
	return tmp;
}

void net_steering_association(struct hostapd_data *hapd, struct sta_info *sta)
{
	u8 buf[MAX_FRAME_SIZE];
	int ret = 0;
	u8 *dst = NULL;
	struct net_steering_context* nsc = NULL;
	struct net_steering_header* hdr = (struct net_steering_header*) buf;
	u16 proto = PROTO;
	u8 own[ETH_ALEN];

	nsc = find_nsc_by_hapd(hapd);
	if (!nsc) {
		hostapd_logger(hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_WARNING, "Association to unknown bss "MACSTR"\n",
				MAC2STR(hapd->conf->bssid));
		return;
	}

	hdr->magic = TLV_MAGIC;
	hdr->version = TLV_VERSION;
	hdr->counter = htons(nsc->frame_counter++);
	hdr->len = 0; // TODO fix this when there is more than just header

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_association - "MACSTR" associated to "MACSTR"\n",
				MAC2STR(sta->addr), MAC2STR(nsc->hapd->conf->bssid));

	// TODO need to manage configuration of peer list
	l2_packet_get_own_addr(nsc->control, own);
	dst = (os_memcmp(own, one, ETH_ALEN) == 0) ? two : one;
	ret = l2_packet_send(nsc->control, dst, proto, buf, sizeof(*hdr) + hdr->len);
	if (ret < 0) {
		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "Failed l2 send to "MACSTR" : error %d\n",
				MAC2STR(dst), ret);
	}
}

static void free_context(struct net_steering_context *nsc)
{
	struct net_steering_context* tmp = nsc_head;

	while (tmp && tmp->next != nsc) tmp = tmp->next;
	if (tmp) tmp->next = nsc->next;
	else wpa_printf(MSG_DEBUG, "net_steering free_context - unknown context for %s", nsc->hapd->conf->iface);
	os_memset(nsc, 0, sizeof(*nsc));
	os_free(nsc);
}

void net_steering_deinit(struct net_steering_context *nsc)
{

	if (nsc->control != NULL) {
		l2_packet_deinit(nsc->control);
		wpa_printf(MSG_DEBUG, "net_steering_deinit - l2_packet_deinit");
	}
	free_context(nsc);
}

int net_steering_init(struct hostapd_data *hapd)
{
	struct net_steering_context* tmp = NULL;
	struct net_steering_context* nsc = NULL;

	u16 proto = PROTO;

	nsc = (struct net_steering_context*) os_zalloc(sizeof(*nsc));
	nsc->hapd = hapd;
	nsc->control = NULL;

	// TODO: what if there is no bridge in use?
	nsc->control = l2_packet_init(hapd->conf->bridge, NULL, proto, nsc_receive, nsc, 0);
	if (nsc->control == NULL) {

		hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
				HOSTAPD_LEVEL_DEBUG, "net_steering_init - l2_packet_init failed for %s with bssid "MACSTR"\n",
				hapd->conf->bridge, MAC2STR(nsc->hapd->conf->bssid));

		net_steering_deinit(nsc);
		return -1;
	}

	hostapd_logger(nsc->hapd, NULL, HOSTAPD_MODULE_NET_STEERING,
			HOSTAPD_LEVEL_DEBUG, "net_steering_init - ready on %s with bssid "MACSTR"\n",
			hapd->conf->bridge, MAC2STR(nsc->hapd->conf->bssid));

	if (!nsc_head) {
		nsc_head = nsc;
	}
	else {
		tmp = nsc_head;
		while (tmp->next) tmp = tmp->next;
		tmp->next = nsc;
	}

	return 0;
}

