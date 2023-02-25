/*
 * config.h - MAP Controller configuration header file
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef CONFIG_H
#define CONFIG_H

#include <i1905_wsc.h>
#include <uci.h>

#include "wifi_dataelements.h"

#define CONFIG_DEFAULT_RCPI_TH_6G 86
#define CONFIG_DEFAULT_RCPI_TH_5G 86
#define CONFIG_DEFAULT_RCPI_TH_2G 70

/* defined in main.c */
extern int verbose;

enum cred_diff {
	CONFIG_DIFF_BASE             = 1 << 0,
	CONFIG_DIFF_CREDENTIALS      = 1 << 1,
	CONFIG_DIFF_AGENT_POLICY     = 1 << 2,
	CONFIG_DIFF_VLAN             = 1 << 3,
	CONFIG_DIFF_AGENT_POLICY_CNT = 1 << 4,
};

struct stax {
	char macstring[32];     /* ':' separated mac address string */
	struct list_head list;
};

struct agent {
	uint8_t agent_id[6];     /* ':' separated mac address string */
	struct list_head list;
};

struct iface_credential {
	enum wifi_band band;
	enum wifi_security sec;
	uint8_t key[65];
	uint8_t bssid[6];
	uint8_t ssid[33];
	uint16_t vlanid;
	uint8_t multi_ap;
	enum wifi_bsstype mode;
	uint8_t disallow_bsta;
	bool enabled;
	struct list_head list;
#define VEN_IES_MAX 16
	uint8_t num_ven_ies;
	struct wsc_vendor_ie ven_ies[VEN_IES_MAX];
	/* wps attributes */
	char manufacturer[65];
	char model_name[33];
	char device_name[33];
	char model_number[33];
	char serial_number[33];
	uint8_t device_type[8];
};

enum agent_steer_policy {
	AGENT_STEER_DISALLOW,                /* agent shall not steer based on rcpi */
	AGENT_STEER_RCPI_MANDATE,            /* agent shall steer based on rcpi */
	AGENT_STEER_RCPI_ALLOW,              /* agent may steer based on rcpi */
};

enum backhaul_type {
	BK_TYPE_NONE
};

struct node_policy {
	uint8_t agent_id[6];
	uint8_t bk_ul_mac[6];
	uint8_t bk_dl_mac[6];
	enum backhaul_type type;
	uint8_t pvid;
	uint8_t pcp;
	bool report_scan;                     /* report independent scans */
	bool report_sta_assocfails;           /* report STA assoc fails */
	uint32_t report_sta_assocfails_rate;  /* reporting rate for STA assoc fails (attempts per minute) */
	uint8_t report_metric_periodic;       /* 0 = disable, else 1 - 255 in secs */
	bool steer_disallow;
	bool coordinated_cac;
	bool traffic_separation;

	int num_steer_stas;                   /* num of stas excluded from steering */
	int num_btmsteer_stas;                /* num of stas excluded from BTM steering */
	bool sta_steer;

	bool is_policy_diff;                  /* whether section changed when reloaded */

	struct list_head list;                /* attached to nodelist */
	/* custom policies follow */
	struct list_head radiolist;           /* list of configured radio sections */
	struct list_head steer_exlist;	      /* exclude stas from steering */
	struct list_head btmsteer_exlist;     /* exclude stas from BTM steering */
};

struct radio_policy {
	uint8_t macaddr[6];
	uint8_t agent_id[6];
	enum wifi_band band;                  /* frequency band */
	enum agent_steer_policy policy;       /* 0, 1, 2 - see MultiAP specs */
	uint8_t util_threshold;               /* utilization as in BSS load IE */
	uint8_t rcpi_threshold;               /* 0 - 220 */
	uint8_t report_rcpi_threshold;        /* 0, or 1 - 220 */
	uint8_t report_util_threshold;        /* 0, or channel utilization value */
	uint8_t report_rcpi_hysteresis_margin;/* 0, or > 0 - hysteresis margin */
	bool include_sta_stats;               /* sta stats in AP metric response */
	bool include_sta_metric;              /* sta metric in AP metric response */
#if (EASYMESH_VERSION > 2)
	bool include_wifi6_sta_status;        /* wifi6 sta status report in AP metric responce */
#endif

	struct list_head list;                /* link to next policy */
};

struct steer_control_config {
	char name[64];
	bool plugin_enabled;
	bool enable_sta_steer;
	bool enable_bsta_steer;
	bool use_bcn_metrics;
	bool use_usta_metrics;
	bool bandsteer;
	unsigned int diffsnr;
	uint8_t rcpi_threshold_2g;            /* 0 - 220 */
	uint8_t rcpi_threshold_5g;            /* 0 - 220 */
	uint8_t rcpi_threshold_6g;            /* 0 - 220 */
	uint8_t report_rcpi_threshold_2g;     /* 0, or 1 - 220 */
	uint8_t report_rcpi_threshold_5g;     /* 0, or 1 - 220 */
	uint8_t report_rcpi_threshold_6g;     /* 0, or 1 - 220 */
	struct list_head list;
};

struct controller_config {
	bool enabled;
	bool has_registrar_6g;
	bool has_registrar_5g;
	bool has_registrar_2g;
	int debug_level;
	int resend_num;
#define BCN_METRICS_MAX_NUM 10
	int bcn_metrics_max_num;  /* max num of metrics stored per STA */
	bool initial_channel_scan;
	int num_bss;
	int num_apolicy;
	int acs_timeout;
	int dfs_cleanup_timeout;
	unsigned int primary_vid;
	unsigned int default_pcp;
	int map_profile;
	bool enable_ts;
	struct list_head nodelist;
	struct list_head aplist;
	struct list_head radiolist;
	struct list_head scclist;		/* list of steer_control_config */
};

struct controller;

int set_value_by_string(const char *package, const char *section,
		const char *key, const char *value, enum uci_option_type type);
int cntlr_config_add_node(struct controller_config *c, char *al_mac);
int cntlr_config_add_node_radio(struct controller_config *c, char *al_mac,
		char *radio_mac, char *band);
bool uci_set_option(char *package_name, char *section_type,
		char *search_key, char *search_val,
		char *option, char *value);

uint8_t cntlr_config_reload(struct controller_config *cfg);
int cntlr_config_defaults(struct controller *c, struct controller_config *cfg);
void cntlr_config_dump(struct controller_config *cfg);
int cntlr_config_clean(struct controller_config *cfg);
#endif
