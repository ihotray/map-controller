/*
 * wifi_dataelements.h
 * WiFi DataElements-v2.0 definitions header.
 *
 * Copyright (C) 2019-2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#ifndef WIFI_DATAELEMENTS_H
#define WIFI_DATAELEMENTS_H

#include <stdint.h>
#include <stdbool.h>
#include <sys/time.h>

#ifdef __cplusplus
extern "C" {
#endif

#define WIFI_DATAELEMENTS_VER_1_0	"1.0"
#define WIFI_DATAELEMENTS_VER_2_0	"2.0"


typedef char timestamp_t[32];
typedef uint8_t guid_t[16];
typedef uint8_t macaddr_t[6], node_id_t[6];

enum wifi_bsstype {
	AP_WIFI_FBSS,
	AP_WIFI_BBSS,
	AP_WIFI_COMBINED,
};

#define WIFI_RADIO_OPCLASS_MOST_PREFERRED    15 << 4
#define WIFI_RADIO_OPCLASS_NON_OPERABLE      0

enum wifi_radio_opclass_dfs {
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_NONE,        /**< CAC not required */
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_USABLE,      /**< CAC required but not done yet */
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_AVAILABLE,   /**< CAC required and done; channel is available */
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_NOP,         /**< channel unavailable; in NOP state after radar hit */
	WIFI_RADIO_OPCLASS_CHANNEL_DFS_CAC,         /**< Pre-ISM CAC ongoing */
};

struct wifi_radio_opclass_channel {
	uint8_t channel;
	uint8_t preference;               /**< preference value */
	enum wifi_radio_opclass_dfs dfs;  /**< DFS channel state */
	uint32_t cac_time;                /**< CAC time needed */
	uint32_t nop_time;                /**< remaining nop time */
	uint8_t ctrl_channels[32];
};

struct wifi_radio_opclass_entry {
	uint8_t id;                       /**< opclass id */
	int bandwidth;
	int max_txpower;                  /**< max allowed Tx power in dBm */
	int num_channel;
	struct wifi_radio_opclass_channel channel[64];  /**< channel list */
};

struct wifi_radio_opclass {
	struct timespec entry_time;
	int num_opclass;
	struct wifi_radio_opclass_entry opclass[64];
};

struct wifi_sta_meas_report {
	struct list_head list;

	uint8_t opclass;
	uint8_t channel;
	uint64_t meas_start_time; /* measuring STA's TSF timer */
	uint16_t meas_duration;
	uint8_t rfi; /* Reported Frame Information */
	uint8_t rcpi;
	uint8_t rsni;
	uint8_t bssid[6];
	//uint8_t antena_id;
	//uint32_t parent_tsf;

	bool requested;	/* matching query sent by cntlr for this report */
	bool stale;	/* outdated report got before most recent request sent */

	uint32_t num_opt_subelem;
	uint8_t optional[];
};

struct wifi_cac_available_channel {
	uint8_t opclass;
	uint8_t channel;
	uint32_t cleared;	// in minutes since available
	struct list_head list;
};

struct wifi_cac_nop_channel {
	uint8_t opclass;
	uint8_t channel;
	uint32_t remaining;	// in secs
	struct list_head list;
};

struct wifi_cac_active_channel {
	uint8_t opclass;
	uint8_t channel;
	uint32_t remaining;	// in secs
	struct list_head list;
};

struct wifi_cac_status {
	timestamp_t tsp;
	struct list_head available_chlist;	/* list of wifi_cac_available_channel */
	struct list_head nop_chlist;		/* list of wifi_cac_nop_channel */
	struct list_head cac_chlist;		/* list of wifi_cac_active_channel */
	struct list_head list;
};

struct wifi_tid_queuesize {
	uint8_t tid;
	uint32_t size;
	struct list_head list;
};

struct wifi_akm_suite {
	uint8_t oui[3];
	uint8_t type;
};

//TODO_ redfine. why needed?
struct wifi_mcs {
	uint16_t vht_mcs_rxmap;
	uint16_t vht_mcs_txmap;
};

struct wifi_wifi6_capabilities {
	bool he160;
	bool he8080;
	//mcs
	//nss
	bool su_beamformer;
	bool su_beamformee;
	bool mu_beamformer;
	bool beamformee_le80;
	bool beamformee_gt80;
	bool ul_mumimo;
	bool ul_ofdma;
	bool dl_ofdma;
	uint8_t max_dl_mumimo;
	uint8_t max_ul_mumimo;
	uint8_t max_dl_ofdma;
	uint8_t max_ul_ofdma;
	bool rts;
	bool mu_rts;
	bool multi_bssid;
	bool mu_edca;
	bool twt_requester;
	bool twt_responder;
};

/* maps to capability bytes in respective TLVs */
struct wifi_caps_element {
#define HT_CAP_VALID       0x4
#define VHT_CAP_VALID      0x8
#define HE_CAP_VALID       0x20
	uint8_t ht;
	uint8_t vht[6];
	uint8_t he[15];		/* 1 (supp-mcs-len), 12 (Tx Rx mcs), 2 (others) */
	uint8_t wifi6[20];	/* max bytes per-role */
	uint32_t valid;		/* caps validity */
	struct wifi_mcs mcs;
};

struct wifi_opclass_supported_element {
	uint8_t id;                     /* class number */
	int8_t max_txpower;
	uint32_t num_exclude_channels;
	uint8_t *exclude_chanlist;      /* list of non-operable channels */
	uint32_t num_channels;
	uint8_t *chanlist;
	struct list_head list;
};

struct wifi_opclass_current_element {
	timestamp_t tsp;
	uint8_t id;
	uint8_t channel;
	int8_t txpower;
};

struct wifi_opclass_disallowed_element {
	bool enabled;
	uint8_t opclass;
	uint32_t num_channels;
	uint8_t *chanlist;
};

#define STEER_STATS_NO_DATA	UINT64_MAX

struct wifi_steer_summary {
	uint64_t no_candidate_cnt;
	uint64_t blacklist_attempt_cnt;
	uint64_t blacklist_success_cnt;
	uint64_t blacklist_failure_cnt;
	uint64_t btm_attempt_cnt;
	uint64_t btm_success_cnt;
	uint64_t btm_failure_cnt;
	uint64_t btm_query_resp_cnt;

	/* Time Associated Device was last attempted to be steered
	 * Note: Calculate delta from now (secs) for reporting.
	 * Note: field not used for per Network statistics.
	 */
	struct timespec last_attempt_tsp;

	/* Private fields */
	struct timespec last_steer_tsp;
	int failed_steer_attempts;
	int latest_assoc_cntrl_mid;
};

enum steer_trigger {
	STEER_TRIGGER_UNKNOWN,
	STEER_TRIGGER_UTIL,
	STEER_TRIGGER_LINK_QUALITY,
	STEER_TRIGGER_BK_UTIL
};

//FIXME: why enums are different?
enum steer_method {
	STEER_METHOD_UNKNOWN,
	STEER_METHOD_ASYNC_BTM,
	STEER_METHOD_BTM_REQ,
	STEER_METHOD_ASSOC_CTL
};

struct wifi_apsta_steer_history {
	struct list_head list;
	struct timespec time;
	uint8_t src_bssid[6];
	enum steer_trigger trigger;
	enum steer_method method;
	uint8_t dst_bssid[6];
	/* Failed attempt will leave this 0 */
	uint32_t duration; /* seconds */
};

struct wifi_multiap_sta {
	time_t assoc_time;
	uint8_t anpi;                             /* avg noise to power indicator */
	struct wifi_steer_summary stats;
#define MAX_STEER_HISTORY 10
	uint8_t num_steer_hist;
	struct wifi_apsta_steer_history steer_history[MAX_STEER_HISTORY];
	int pending_btm_resp_num;
};

struct wifi_sta_element {
	struct list_head list;
	int invalidate;
	time_t tsp;
	uint8_t macaddr[6];
	//wifi6caps
	//clientcaps
	struct wifi_caps_element caps;
	uint32_t dl_rate;             /* latest data rate in Kbps: ap -> sta */
	uint32_t ul_rate;             /* latest data rate in Kbps: sta -> ap */
	unsigned long ul_utilization; /* time in msecs for receive from sta */
	unsigned long dl_utilization; /* time in msecs for transmit to sta */
	uint32_t dl_est_thput;        /* in Mbps */
	uint32_t ul_est_thput;        /* in Mbps */
	uint8_t rcpi;
	uint32_t conn_time;           /* in secs since last associated */
	uint64_t tx_bytes;            /* transmit bytes count: ap -> sta */
	uint64_t rx_bytes;            /* receive bytes count: sta -> ap */
	uint32_t tx_pkts;
	uint32_t rx_pkts;
	uint32_t tx_errors;
	uint32_t rx_errors;
	uint32_t rtx_pkts;            /* total retransmitted packets */
	struct ip_address ipv4_addr;
	struct ip_address ipv6_addr;
	char hostname[256];
	uint8_t num_meas_reports;
	struct list_head meas_reportlist;	/* list of wifi_sta_meas_report */

	size_t reassoc_framelen;
	uint8_t *reassoc_frame;
	struct list_head tid_qsizelist;	/* list of wifi_tid_queuesize */
	struct wifi_multiap_sta mapsta;
};

struct wifi_multiap_steering {
	uint64_t blacklist_attempt_cnt;
	uint64_t btm_attempt_cnt;
	uint64_t btm_query_resp_cnt;
};

enum wifi_sta_event_pending {
	WIFI_STA_EV_NONE,
	WIFI_STA_EV_ASSOC    = 1 << 0,
	WIFI_STA_EV_DISASSOC = 1 << 1,
	WIFI_STA_EV_FAIL     = 1 << 2,
};

struct wifi_sta_events {
	uint32_t pending;	/* bitmap of WIFI_STA_EV_* */
	uint32_t num_assoc;
	uint32_t num_disassoc;
	uint32_t num_fail;
	struct list_head assoclist;
	struct list_head disassoclist;
	struct list_head failconnlist;
};


enum counter_unit { COUNTER_UNIT_KB = 1, COUNTER_UNIT_MB = 2 };

struct wifi_bss_element {
	struct list_head list;
	int invalidate;
	time_t tsp;
	uint8_t bssid[6];
	char ssid[33];
	bool enabled;
	uint32_t uptime; /* 'LastChange' in TR-181 */
	uint64_t tx_ucast_bytes;
	uint64_t rx_ucast_bytes;
	uint64_t tx_mcast_bytes;
	uint64_t rx_mcast_bytes;
	uint64_t tx_bcast_bytes;
	uint64_t rx_bcast_bytes;
	enum counter_unit unit;
#define ESP_AC_BE	0x80
#define ESP_AC_BK	0x40
#define ESP_AC_VO	0x20
#define ESP_AC_VI	0x10
	uint8_t esp_ac;	/** Estimated Service Parameters Information */
	uint8_t est_wmm_be[3];
	uint8_t est_wmm_bk[3];
	uint8_t est_wmm_vi[3];
	uint8_t est_wmm_vo[3];
	uint32_t num_stations;
	struct list_head stalist;	/* list of wifi_sta_element */

	bool p1_bsta_disallowed;
	bool p2_bsta_disallowed;
	bool sta_assoc_allowed;
	bool is_bbss;
	bool is_fbss;
	bool r1_disallowed;
	bool r2_disallowed;
	bool multi_bssid;
	bool transmitted_bssid;

	struct wifi_multiap_steering steer_stats;

	uint8_t ch_util;
};

struct wifi_radio_scan_capabilities {
	bool boot_only;
	uint8_t impact;
	uint32_t interval;
	struct wifi_radio_opclass opclass;
};

struct wifi_radio_cac_capabilities {
	enum wifi_cac_method method;
	uint32_t num_seconds;
	size_t num_opclass;
	struct list_head supp_opclasslist;
};

/* represents a scanned AP entry */
struct wifi_scanres_neighbor_element {
	struct list_head list;
	uint8_t bssid[6];
	char ssid[33];
	int rssi;
	uint32_t bw;
	uint8_t utilization;
	uint32_t num_stations;
};

struct wifi_scanres_channel_element {
	struct list_head list;
	timestamp_t tsp;
	uint8_t channel;
	uint8_t utilization;
	uint8_t anpi;
	uint32_t num_neighbors;
	struct list_head nbrlist;	/* list of wifi_scanres_neighbor_element */
	bool report_independent_scan;
};

struct wifi_scanres_opclass_element {
	struct list_head list;
	uint8_t opclass;
	uint32_t num_channels_scanned;
	struct list_head channel_scanlist;	/* list of wifi_scanres_channel_element */
};

struct wifi_scanres_element {
	struct list_head list;
	struct timeval tv;
	timestamp_t tsp;
	uint32_t num_opclass_scanned;
	struct list_head opclass_scanlist;	/* list of wifi_scanres_opclass_element */
};

struct wifi_backhaul_element {
	uint8_t macaddr[6];
};

struct wifi_unassoc_sta_element {
	struct list_head list;
	uint8_t macaddr[6];
	uint8_t rcpi;
	//struct wifi_sta_measurement meas;
};

struct wifi_radio_element {
	struct list_head list;
	int invalidate;
	uint8_t macaddr[6];
	bool enabled;
	struct wifi_radio_element_report {
		uint8_t sta_rcpi_threshold;       /* 0 = disable; else 1..220 */
		uint8_t sta_rcpi_margin_override; /* 0 = disable; else value */
		uint8_t channel_util_threshold;   /* 0 = disable; else value */
		bool include_sta_stats;           /* bit7 = include stats */
		bool include_sta_metrics;         /* bit6 = include link metrics */
		bool include_wifi6_metrics;
	} report;

	uint8_t steer_policy;                     /* 0, 1 or 2 */
	uint8_t channel_util_threshold;           /* 0..220 */
	uint8_t rcpi_steer_threshold;             /* 0..220 */
	uint8_t anpi;                             /* avg noise to power indicator */
	uint8_t total_utilization;                /** in %age, linearly scaled 0..255 */
	uint8_t tx_utilization;
	uint8_t rx_utilization;
	uint8_t other_utilization;
	uint8_t tx_streams;
	uint8_t rx_streams;
	char country_code[4];

	uint8_t max_bssnum;
	uint32_t num_bss;
	uint32_t num_unassoc_sta;
	uint32_t num_scanresult;

	struct wifi_backhaul_element bsta;

	struct wifi_caps_element caps;

	struct wifi_radio_opclass supp_opclass; /* supported opclasses reported by device */
	struct wifi_radio_opclass pref_opclass;	/* preferred opclasses reported by device */
	struct wifi_radio_opclass cur_opclass;	/* current opclasses reported by device */

	struct list_head bsslist;		/* list of wifi_bss_element */
	struct list_head unassoc_stalist;	/* list of wifi_unassoc_sta_element */
	struct list_head scanlist;		/* list of wifi_scanres_element */

	int ts_combined_fronthaul;
	int ts_combined_backhaul;

	char vendor[64];			/* chipset vendor */
	struct wifi_radio_scan_capabilities scan_caps;
	struct wifi_radio_cac_capabilities cac_caps;

	struct list_head fbss_akmlist;		/* fBSS AKM list */
	struct list_head bbss_akmlist;		/* bBSS AKM list */
};

struct wifi_default_8021q {
	uint8_t pvid;
	uint8_t pcp;
	struct list_head list;
};

struct ieee1905_security_caps {
	uint8_t onboarding_protocol;
	uint8_t integrity;
	uint8_t encryption;
};

struct wifi_sp_rule {
	uint32_t id;
	uint8_t priority;
	uint8_t output;
	bool always_match;
	struct list_head list;
};

struct wifi_backhaul_stats {
	timestamp_t tsp;
	uint64_t tx_bytes;
	uint64_t rx_bytes;
	uint32_t tx_pkts;
	uint32_t rx_pkts;
	uint32_t tx_errors;
	uint32_t rx_errors;
	uint8_t link_utilization;	/* in %age */
	uint8_t rcpi;
	uint32_t dl_rate;             /* latest data rate in Kbps: ap -> bsta */
	uint32_t ul_rate;             /* latest data rate in Kbps: bsta -> ap */
};

enum network_link_type {
	LINK_TYPE_NONE = 0,
	LINK_TYPE_WIFI = 1,
	LINK_TYPE_ETH = 2,
	LINK_TYPE_MOCA = 3,
	LINK_TYPE_GHN = 4,
	LINK_TYPE_HPNA = 5,
	LINK_TYPE_HOME = 6,
	LINK_TYPE_UPA = 7,
};

struct wifi_network_device_backhaul {
	enum network_link_type linktype;
	uint8_t bsta_macaddr[6];
	uint8_t upstream_device_macaddr[6];
	uint8_t upstream_bbss_macaddr[6];
	uint32_t num_curr_opclass;
	struct list_head curr_opclasslist;	/* list of wifi_opclass_current_element */

	struct wifi_backhaul_stats stats;
};

enum operation_mode {
	NOT_SUPPORTED = 0,
	SUPPORTED = 1,
	RUNNING = 2,
};

struct wifi_multi_ap_device {
	uint8_t oui[3];
	timestamp_t last_contacttime;
	struct wifi_network_device *dev_ref;
	enum operation_mode controller_opmode;
	enum operation_mode agent_opmode;
	struct wifi_network_device_backhaul backhaul;
};

struct wifi_network_device {
	void *priv;		/* application private opaque context data */
	bool invalid;
	uint8_t macaddr[6];        /* unique device-id: eui-48 address */
	uint8_t multiap_caps;      /* from ap-capability tlv */
	uint32_t collect_int;      /* data collection interval in msecs */
	struct wifi_network_device_report {
		uint8_t ap_metrics_int;      /* 0 = disable; 1-255 in seconds */
		bool independent_scans;
		uint32_t sta_assoc_fails;    /* 0 = disable; max-rate/minute */
		bool include_wifi6_metrics;
	} report;

	uint32_t map_profile;		/* MAP-Profile; 1, 2, 3 etc. */
	uint32_t num_radios;
	struct list_head radiolist;	/* list of wifi_radio_element */

	struct wifi_sta_events ev;

	time_t last_contacttime;
	char manufacturer[65];
	uint8_t oui[3];
	char serial[33];
	char model[33];
	char swversion[65];            /* Indentfier of SW (firmware) version installed on device */
	char execenv[65];              /* Identifier of operating system */

	uint32_t num_cacstatus;
	uint32_t num_sprules;

	struct list_head sta_steer_disallowlist;
	struct list_head sta_btmsteer_disallowlist;
	struct list_head default_8021qlist;		/* list of wifi_default_8021q */
#define MAX_CAC_STATUS_HISTORY 3
	struct list_head cac_statuslist;		/* list of wifi_cac_status */
	struct list_head sp_rulelist;			/* list of wifi_sp_rule */

	struct wifi_multi_ap_device multi_ap_device;

	uint8_t dscp_mapping[64];
	uint8_t max_prules;
	bool support_sp;
	bool support_dpp;
	bool support_ts;
	size_t max_vids;
	struct ieee1905_security_caps i1905_seccap;
	char country_code[4];
	bool dfs_enabled;
	bool sta_steering_state;
	bool ts_allowed;
	bool sp_allowed;

	uint32_t num_anticipated_channels;
	//anticipated_chanlist
	//anticipated_chanlist.usage
	uint8_t has_easymesh_controller;	// 0, 1 or 2
	uint8_t has_easymesh_agent;		// 0, 1 or 2

	struct list_head list;
};

/* ssids in the multiap network */
struct wifi_network_ssid {
	bool enabled;
	size_t ssidlen;
	uint8_t ssid[32];
	uint32_t band;
	uint32_t security;
	uint16_t vid;
	uint8_t multi_ap;
	enum wifi_bsstype type;
	struct list_head list;
};

struct wifi_network {
	void *priv;		/* application private opaque context data */
	timestamp_t tsp;
	char id[16];               /* network id: guid */
	uint8_t cntlr_id[6];       /* controller id: macaddress */
	uint32_t num_ssid;
	struct list_head ssidlist; /* list of wifi_network_ssid */
	uint16_t primary_vid;
	uint16_t default_pcp;
	macaddr_t *disallow_scslist;
	macaddr_t *disallow_mscslist;
	uint32_t num_devices;
	struct wifi_steer_summary steer_summary;
	struct list_head devicelist;	/* list of wifi_network_device */
};

struct wifi_data_element {
	timestamp_t tsp;
	char version[32];
	struct wifi_network network;
};

struct wifi_assoc_event {
	timestamp_t tsp;
	uint8_t macaddr[6];
	uint8_t bssid[6];
	uint16_t status_code;
	struct wifi_caps_element caps;
	struct list_head list;
};

struct wifi_disassoc_event {
	timestamp_t tsp;
	uint8_t macaddr[6];
	uint8_t bssid[6];
	uint16_t reason_code;
	struct wifi_sta_element sta;
	struct list_head list;
};

struct wifi_channel_data {
	uint8_t channel;
	uint8_t utilization;
	uint8_t anpi;
};

struct radio_event_data {
	uint8_t macaddr[6];
	uint32_t num_cdata;
	struct wifi_channel_data *cdata;
};

struct wifi_radio_events {
	uint32_t num_radios;
	struct radio_event_data *rdata;
};

#ifdef __cplusplus
}
#endif
#endif /* WIFI_DATAELEMENTS_H */
