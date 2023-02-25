/*
 * cntlr.h - MAP controller header file
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef CNTLR_H
#define CNTLR_H

#define cntlr_dbg(...)     dbg(green "CNTLR: " nocl __VA_ARGS__)
#define cntlr_warn(...)    warn(red "CNTLR: " __VA_ARGS__)
#define cntlr_info(...)    info(blue "CNTLR: " nocl __VA_ARGS__)

#include <timer_impl.h>
#include <cmdu_ackq.h>
#include <map_module.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include "wifi_dataelements.h"
#include "config.h"
#include "steer.h"
#include "allmac.h"

#ifndef EASYMESH_VENDOR_EXT_OUI
#define EASYMESH_VENDOR_EXT_OUI         (uint8_t *)"\x00\x11\x22"
#endif

extern const char *ubus_socket;

typedef uint32_t object_t;
#define OBJECT_INVALID	((uint32_t)-1)

enum device_type {
	NON_IEEE1905,
	IEEE1905
};

struct cac_data {
	uint8_t radio[6];
	uint8_t opclass;
	uint8_t channel;
	uint8_t cac_method;
	uint8_t cac_action;
};

#define SCAN_REQ_MAX_NUM_RADIO 4
#define SCAN_REQ_MAX_NUM_OPCLASS 8
#define SCAN_REQ_MAX_NUM_CHAN 16
struct scan_req_data {
	bool is_fresh_scan;
	uint8_t num_radio;
	struct scan_req_radio {
		uint8_t radio_mac[6];
		uint8_t num_opclass;
		struct scan_req_opclass {
			uint8_t classid;
			uint8_t num_channel;
			uint8_t channels[SCAN_REQ_MAX_NUM_CHAN];
		} opclasses[SCAN_REQ_MAX_NUM_OPCLASS];
	} radios[SCAN_REQ_MAX_NUM_RADIO];
};

struct proxied_encap_dpp_data {
	/* TODO: implement & use as param
	 * to cntlr_gen_proxied_encap_dpp
	 */
};

struct direct_encap_dpp_data {
	/* TODO: implement & use as param
	 * to cntlr_gen_direct_encap_dpp
	 */
};

struct bcn_meas_element {
	uint8_t tag_number;
	uint8_t tag_length;
	uint8_t meas_token;
	uint8_t meas_report_mode;
	uint8_t meas_report_type;
	uint8_t op_class;
	uint8_t channel;
	uint8_t start_time[8]; /* measuring STA's TSF timer */
	uint8_t duration[2];
	uint8_t frame_info;
	uint8_t rcpi;
	uint8_t rsni;
	uint8_t bssid[6];
	uint8_t antena_id;
	uint8_t tsf[4];
	uint8_t frame[];
};

struct bcnreq {
	uint8_t sta_mac[6];
	uint8_t agent_mac[6];
	struct timespec tsp;
	int request_num;

	struct list_head list;
};

struct una_sta_metrics {
	/* node the measurement has been done on */
	struct node *agent;
	uint8_t channel;
	uint32_t time_delta;
	uint8_t ul_rcpi;

	struct list_head list;
};

struct sta {
	uint8_t bssid[6];

	uint32_t time_delta;

	/* TODO: change name to match the data (e.g. umetriclist) */
	struct list_head unassoclist;

	struct wifi_sta_element *de_sta;

	struct netif_iface *fh; /* the AP interface the sta is connected at */

	enum device_type type;
	struct node *agent; /* the agent representing an IEEE1905 device, only applicable for backhaul stations */
	atimer_t bcn_metrics_timer;
	struct timespec last_bcn_metrics_query;
	int latest_assoc_cntrl_mid;

#define BTM_RESP_EXP_TIMEOUT 5
	atimer_t btm_req_timer;

	struct list_head list;
};

enum media_type {
	ETH,
	WIFI
};

/* This struct maps to fronthaul AP-BSS interface
 * of neighboring nodes.
 */
struct netif_iface {
	char ifname[16];

	enum wifi_band band;
	enum media_type med_type;	/* TODO unused */
	uint32_t bssid_info;		/* TODO unused */
	uint8_t reg;				/* TODO unused */
	uint8_t phy;				/* TODO unused */
	int channel;				/* TODO unused */
	int capacity;				/* TODO unused */

	struct node *agent;
	uint8_t upstream_bssid[6]; /* in the case of the interface is a bsta interface */

	struct wifi_bss_element *bss;

	struct list_head list;
};

/** Latest combined infra metrics data **/
struct link_metrics {
	// unsigned char downstream[6];
	// unsigned char upstream[6];
#define NETIF_LINK_ETH	1
#define NETIF_LINK_WIFI	2
	uint16_t type;	/** Media Type*/
	/* tx link metrics */
	bool bridge;
	uint32_t packet_tx_error;
	uint32_t packet_trans;
	uint16_t thp;	/** MAC Throughput Capacity in Mbps */
	uint16_t link_av;	/** Link Availability */
	uint16_t phy_rate;	/* in Mpbs */
	/* rx link metrics */
	uint32_t packet_rx_error;
	uint32_t packet_rec;
	int8_t rssi;	/** in dBm */
	struct netif_link *l;
	struct list_head list;
};

/* cut-down version of what agents have */
/* TODO - refine this struct */
struct netif_link {
//	char name[16];
	struct netif_iface *downstream;
	struct netif_iface *upstream;
	int channel;
#define NETIF_LINK_ETH	1
#define NETIF_LINK_WIFI	2
	/* int type; */
	/* bool active; */
	int capacity;
	struct link_metrics *metrics;	/** 1905 Link Metric TLV data **/
	struct list_head list;
};

#define MAX_NUM_RADIO 8
/* TODO - fill this structure */
struct netif_radio {
	char name[16];

	struct node *agent;
	struct list_head iflist; /** list of netif_iface */

	struct wifi_radio_element *radio_el;

	struct list_head list;
};

enum nodetype {
	NODE_WIFI_EXTENDER,
	NODE_WIFI_REPEATER,
	NODE_ETH_EXTENDER,
};


enum uplink_type {
	UL_UNSPEC,
	UL_ETH,
	UL_WIFI,
	UL_DSL,
};

struct uobj_struct {
	object_t id;
	int (*req)(int argc, char **argv);
	void (*resp)(struct ubus_request *r, int t, struct blob_attr *m);
};

struct watchnode {
	unsigned char hwaddr[6];
	struct in_addr ipaddr;
	/* char fh_ifname[16]; */
	unsigned char fh_bssid[6];
	char fh_ssid[33];
	struct timeval tv;
#define WATCHNODE_SCAN_RETRY_MAX   5
	unsigned int scan_retry;
	atimer_t scan_timer;
	atimer_t scanres_timer;
	struct controller *cntlr;
	struct list_head list;
};

/* struct node - maps to a 1905 device */
struct node {
	uint8_t alid[6];
	struct in_addr ipaddr;
	enum nodetype type;
	int depth;                         /** >= 0 or -1 for unknown */
	int ul_type;                       /** uplink type */
	bool scan_supported;               /** whether scanning supported */
	struct controller *cntlr;
#define MAX_UOBJECTS	8
	atimer_t refresh_timer;
	struct ubus_event_handler evh;
	//struct agent_policy *ap;
	struct node_policy *np;
	uint8_t ap_cap;
	uint8_t map_profile;		   /** profile info of agent node */
	struct list_head radiolist;        /** list of netif_radio */
	struct list_head stalist;
	struct list_head list;
};

#define NODE_STATS_INTERVAL		30000       /** 30 secs */

enum cntlr_state {
	CNTLR_INIT, /* while initializing, only look for ACS answer */
	CNTLR_IDLE, /* TODO: while idle, do nothing in a loop till awakened */
	CNTLR_START /* normal */
};

struct steering {
	int channels_num;
	uint8_t channels[64];
};

struct controller {
	enum cntlr_state state;
	unsigned char almac[6];
	void *comm;
	struct ubus_object obj;
	struct ubus_object obj_dbg; /* ubus debug object */
	struct ubus_context *ubus_ctx;
	struct ubus_event_handler evh;
	atimer_t heartbeat;
	atimer_t acs;
	atimer_t dfs_cleanup;
	int num_nodes;
	int num_tx_links;
	int num_rx_links;
	struct list_head nodelist;
	struct list_head stalist; /* list of sta */
	struct list_head bcnreqlist;
	struct list_head linklist;
	atimer_t radar_timer;
	atimer_t discovery_timer;
	atimer_t start_timer;
	atimer_t signal_handler;
	atimer_t query_nodes;
	struct allmac_htable mac_table; /* mac addr hash table */
	struct hlist_head *as_table; /** active sta hash table */
	struct controller_config cfg;
	struct cmdu_ackq cmdu_ack_q;
	struct steering steer_params;

	/* Autoconfig */
	uint16_t mid_5g;
	uint16_t mid_2g;

	/* i1905.map registration */
	uint32_t map_oid;
	mapmodule_cmdu_mask_t cmdu_mask;
	void *subscriber;
	bool subscribed;

	struct list_head sclist;	/* steer_control module list */
	struct steer_control *sctrl;	/* active steer-control module */

	struct wifi_data_element dlem; /* wifi data elements */
};

struct sta_channel_report {
	uint8_t opclass;
	uint8_t num_channel;
	uint8_t channel[128];
};

#define MAX_UNASSOC_STAMACS 10
struct unassoc_sta_metric {
	uint8_t channel;
	uint8_t num_sta;
	struct {
		uint8_t macaddr[6];
	} sta[MAX_UNASSOC_STAMACS];
};

struct sta_error_response {
	uint8_t sta_mac[6];
	uint8_t response;
};

#define COMM_HANDLE(c)	(((struct controller *)(c))->ubus_ctx)

struct node *cntlr_alloc_node(struct controller *c, uint8_t *hwaddr);
struct netif_iface *find_interface_by_ssid(struct controller *c,
		struct node *n, char *ssid);
struct netif_radio *find_radio_by_ssid(struct controller *c,
		struct node *n, char *ssid);
struct netif_link *alloc_link_init(struct controller *c,
		uint8_t *upstream, uint8_t *downstream);
struct netif_radio *find_radio_by_node(struct controller *c, struct node *n,
		uint8_t *radio);
struct netif_radio *find_radio_by_mac(struct controller *c, uint8_t *mac);
struct netif_radio *find_radio_by_bssid(struct controller *c, uint8_t *bssid);
struct node *cntlr_find_node(struct controller *c, uint8_t *mac);
struct node *cntlr_find_node_by_iface(struct controller *c, uint8_t *bssid);
struct netif_iface *find_interface_by_mac(struct controller *c,
		struct netif_radio *r, uint8_t *hwaddr);
struct netif_iface *find_interface_by_mac_nor(struct controller *c,
		uint8_t *hwaddr);
struct node_policy *agent_find_policy(struct controller *c, uint8_t *agent);
struct radio_policy *agent_find_radio_policy(struct controller *c, uint8_t *bssid);
struct node *cntlr_add_node(struct controller *c, uint8_t *almac);
struct netif_radio *cntlr_node_add_radio(struct controller *c, struct node *n,
		uint8_t *radio);
struct netif_iface *cntlr_radio_add_interface(struct controller *c,
		struct netif_radio *r, uint8_t *hwaddr);
struct netif_iface *cntlr_iterate_fbss(struct controller *c, uint8_t *mac);
void cntlr_update_sta_steer_counters(struct controller *c, uint8_t *sta_mac,
		uint8_t *src_bssid, uint8_t *dst_bssid,
		uint32_t mode, enum steer_trigger trigger);
struct steer_control_config *get_steer_control_config(struct controller *c);
struct sta *cntlr_add_sta(struct controller *c, uint8_t *macaddr);
struct sta *cntlr_find_sta(struct controller *c, uint8_t *mac);
struct bcnreq *cntlr_find_bcnreq(struct controller *c, uint8_t *sta, uint8_t *alid);
struct netif_iface *cntlr_get_fbss_by_mac(struct controller *c, struct node *n,
		uint8_t *mac);
bool cntlr_resync_config(struct controller *c, bool reload);

int cntlr_radio_clean_scanlist_el(struct wifi_scanres_element *el);
void free_bcn_metrics(struct controller *c, struct sta *s);
void cntlr_mark_old_bcn_metrics(struct controller *c, struct sta *s);
void free_usta_metrics(struct controller *c, struct sta *s);

uint8_t cntlr_get_classid_ht20(struct wifi_radio_element *radio, uint8_t channel);
int cntlr_radio_pref_opclass_add(struct wifi_radio_element *radio, uint8_t opclass,
				 uint8_t channel, uint8_t preference);
void cntlr_radio_pref_opclass_reset(struct wifi_radio_element *radio);
void cntlr_radio_pref_opclass_dump(struct wifi_radio_element *radio);

int cntlr_radio_cur_opclass_add(struct wifi_radio_element *radio, uint8_t opclass,
				uint8_t channel, uint8_t txpower);
void cntlr_radio_cur_opclass_reset(struct wifi_radio_element *radio);
void cntlr_radio_cur_opclass_dump(struct wifi_radio_element *radio);
bool cntlr_node_pref_opclass_expired(struct node *node);
void cntlr_radio_pref_opclass_set_pref(struct wifi_radio_element *radio, uint8_t id, uint8_t preference);

int cntlr_sync_dyn_controller_config(struct controller *c, uint8_t *agent);

void cntlr_load_steer_modules(struct controller *c);
void cntlr_unload_steer_modules(struct controller *c);

#endif /* CNTLR_H */
