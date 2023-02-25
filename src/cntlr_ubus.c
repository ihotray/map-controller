/*
 * cntlr_ubus.c - provides map controller management object
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include <easy/easy.h>
#include <cmdu.h>
#include <i1905_wsc.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "timer.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "cntlr.h"
#include "allsta.h"
#include "cntlr_map.h"
#include "cntlr_ubus.h"
#include "cntlr_tlv.h"

#include "cntlr_tlv.h"
#include "cntlr_cmdu.h"

#include "cntlr_acs.h"
#include "wifi_opclass.h"

#define MULTICAST_ADDR_STR "01:80:c2:00:00:13"

enum {
	AP_POLICY_AGENT,
	/* TODO: filter on cntlr side based on bssid */
	//AP_POLICY_BSSID,
	__AP_POLICY_MAX,
};

static const struct blobmsg_policy ap_caps_policy_params[__AP_POLICY_MAX] = {
	[AP_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	/* TODO: filter on cntlr side based on bssid */
	//[AP_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING }
};


enum {
	STA_POLICY_AGENT,
	STA_POLICY_STA,
	STA_POLICY_BSSID,
	__STA_POLICY_MAX,
};

static const struct blobmsg_policy sta_caps_policy_params[__STA_POLICY_MAX] = {
	[STA_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[STA_POLICY_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[STA_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING }
};

enum {
	CHANNEL_PREF_POLICY_AGENT,
	__CHANNEL_PREF_POLICY_MAX,
};

static const struct blobmsg_policy channel_pref_policy_params[__CHANNEL_PREF_POLICY_MAX] = {
	[CHANNEL_PREF_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING }
};

enum {
	CHANNEL_RECALC_POLICY_AGENT,
	CHANNEL_RECALC_POLICY_SKIP_DFS,
	__CHANNEL_RECALC_POLICY_MAX,
};

static const struct blobmsg_policy channel_recalc_policy_params[__CHANNEL_RECALC_POLICY_MAX] = {
	[CHANNEL_RECALC_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CHANNEL_RECALC_POLICY_SKIP_DFS] = { .name = "skip_dfs", .type = BLOBMSG_TYPE_BOOL },
};

enum {
	CHANNEL_CLEANUP_POLICY_AGENT,
	__CHANNEL_CLEANUP_POLICY_MAX,
};

static const struct blobmsg_policy channel_cleanup_policy_params[__CHANNEL_CLEANUP_POLICY_MAX] = {
	[CHANNEL_CLEANUP_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING }
};

enum {
	CHANNEL_SEL_POLICY_AGENT,
	CHANNEL_SEL_POLICY_RADIO_ID,
	CHANNEL_SEL_POLICY_CLASS_ID,
	CHANNEL_SEL_POLICY_CHANNEL,
	CHANNEL_SEL_POLICY_PREF,
	CHANNEL_SEL_POLICY_TRANSMIT_POWER,
	__CHANNEL_SEL_POLICY_MAX,
};

static const struct blobmsg_policy channel_select_policy_params[__CHANNEL_SEL_POLICY_MAX] = {
	[CHANNEL_SEL_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CHANNEL_SEL_POLICY_RADIO_ID] = { .name = "radio_id", .type = BLOBMSG_TYPE_STRING },
	[CHANNEL_SEL_POLICY_CLASS_ID] = { .name = "class_id", .type = BLOBMSG_TYPE_INT32 },
	[CHANNEL_SEL_POLICY_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_ARRAY },
	[CHANNEL_SEL_POLICY_PREF] = { .name = "preference", .type = BLOBMSG_TYPE_INT32 },
	[CHANNEL_SEL_POLICY_TRANSMIT_POWER] = { .name = "transmit_power", .type = BLOBMSG_TYPE_INT32 }
};

#if 0
enum {
	CFG_POLICY_AGENT,
	CFG_POLICY_RADIO,
	CFG_POLICY_BSSID,
	__CFG_POLICY_MAX,
};

static const struct blobmsg_policy config_policy_params[__CFG_POLICY_MAX] = {
	[CFG_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CFG_POLICY_RADIO] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
	[CFG_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
};
#endif

enum {
	RECFG_POLICY_AGENT,
	__RECFG_POLICY_MAX,
};

static const struct blobmsg_policy reconfig_policy_params[__RECFG_POLICY_MAX] = {
	[RECFG_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING }
};

enum {
	BK_STEER_POLICY_AGENT,
	BK_STEER_POLICY_BSSID,
	BK_STEER_POLICY_CHANNEL,
	BK_STEER_POLICY_OP_CLASS,
	BK_STEER_POLICY_STA_MAC,
	__BK_STEER_POLICY_MAX,
};

static const struct blobmsg_policy bk_steer_policy_params[__BK_STEER_POLICY_MAX] = {
	[BK_STEER_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[BK_STEER_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
	[BK_STEER_POLICY_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
	[BK_STEER_POLICY_OP_CLASS] = { .name = "op_class", .type = BLOBMSG_TYPE_INT32 },
	[BK_STEER_POLICY_STA_MAC] = { .name = "bksta", .type = BLOBMSG_TYPE_STRING },
};

enum {
	AP_POLICY_CONFIG_AGENT,
	AP_POLICY_CONFIG_RADIOS,
	AP_POLICY_CONFIG_BSS,
	__AP_POLICY_CONFIG_MAX,
};

static const struct blobmsg_policy ap_policy_config_params[__AP_POLICY_CONFIG_MAX] = {
	[AP_POLICY_CONFIG_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[AP_POLICY_CONFIG_RADIOS] = { .name = "radiolist", .type = BLOBMSG_TYPE_ARRAY },
	[AP_POLICY_CONFIG_BSS] = { .name = "bsslist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	STEERING_POLICY_AGENT,
	STEERING_POLICY_FROM_BSSID,
	STEERING_POLICY_STA,
	STEERING_POLICY_TARGET_BSSID,
	STEERING_POLICY_STEER_TIMEOUT,
	STEERING_POLICY_BTM_TIMEOUT,
	STEERING_POLICY_REQUEST_MODE,
#if profile2
	STEERING_POLICY_TARGET_BSSID_MULTIBAND,
	STEERING_POLICY_STA_MULTIBAND,
#endif
	__STEERING_POLICY_MAX,
};

static const struct blobmsg_policy client_steering_policy_params[__STEERING_POLICY_MAX] = {
	[STEERING_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[STEERING_POLICY_FROM_BSSID] = { .name = "src_bssid", .type = BLOBMSG_TYPE_STRING },
	[STEERING_POLICY_STA] = { .name = "sta", .type = BLOBMSG_TYPE_ARRAY},
	[STEERING_POLICY_TARGET_BSSID] = { .name = "target_bssid", .type = BLOBMSG_TYPE_ARRAY },
	[STEERING_POLICY_STEER_TIMEOUT] = { .name = "steer_timeout", .type = BLOBMSG_TYPE_INT32 },
	[STEERING_POLICY_BTM_TIMEOUT] = { .name = "btm_timeout", .type = BLOBMSG_TYPE_INT32 },
	[STEERING_POLICY_REQUEST_MODE] = { .name = "steer_req_mode", .type = BLOBMSG_TYPE_BOOL },
#if profile2
	[STEERING_POLICY_TARGET_BSSID_MULTIBAND] = { .name = "target_bssid_multiband", .type = BLOBMSG_TYPE_ARRAY },
	[STEERING_POLICY_STA_MULTIBAND] = { .name = "sta_multiband", .type = BLOBMSG_TYPE_ARRAY },
#endif
};

enum {
	CLIENT_POLICY_ASSOC_CONTROL_AGENT,
	CLIENT_POLICY_ASSOC_CONTROL_BSSID,
	CLIENT_POLICY_ASSOC_CONTROL_MODE,
	CLIENT_POLICY_ASSOC_CONTROL_VALID_TIME,
	CLIENT_POLICY_ASSOC_CONTROL_STALIST,
	__CLIENT_POLICY_ASSOC_CONTROL_MAX,
};

static const struct blobmsg_policy client_assoc_cntrl_policy_config_params[__CLIENT_POLICY_ASSOC_CONTROL_MAX] = {
	[CLIENT_POLICY_ASSOC_CONTROL_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CLIENT_POLICY_ASSOC_CONTROL_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
	[CLIENT_POLICY_ASSOC_CONTROL_MODE] = { .name = "assoc_cntl_mode", .type = BLOBMSG_TYPE_INT32 },
	[CLIENT_POLICY_ASSOC_CONTROL_VALID_TIME] = { .name = "assoc_valid_timeout", .type = BLOBMSG_TYPE_INT32 },
	[CLIENT_POLICY_ASSOC_CONTROL_STALIST] = { .name = "stalist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	AP_METRIC_QUERY_AGENT,
	AP_METRIC_QUERY_BSS,
	AP_METRIC_QUERY_RADIO,
	__AP_METRIC_QUERY_MAX,
};

static const struct blobmsg_policy ap_metric_query_params[__AP_METRIC_QUERY_MAX] = {
	[AP_METRIC_QUERY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[AP_METRIC_QUERY_BSS] = { .name = "bsslist", .type = BLOBMSG_TYPE_ARRAY },
	[AP_METRIC_QUERY_RADIO] = { .name = "radiolist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	SCAN_POLICY_AGENT,
	SCAN_POLICY_RADIO,
	SCAN_POLICY_CLASSID,
	SCAN_POLICY_CHANNEL,
	SCAN_POLICY_FRESH_SCAN,
	__SCAN_POLICY_MAX,
};

static const struct blobmsg_policy scan_policy_params[__SCAN_POLICY_MAX] = {
	[SCAN_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[SCAN_POLICY_RADIO] = { .name = "radio", .type = BLOBMSG_TYPE_ARRAY },
	[SCAN_POLICY_CLASSID] = { .name = "opclass", .type = BLOBMSG_TYPE_ARRAY },
	[SCAN_POLICY_CHANNEL] = { .name = "channel", .type = BLOBMSG_TYPE_ARRAY },
	[SCAN_POLICY_FRESH_SCAN] = { .name = "fresh_scan", .type = BLOBMSG_TYPE_BOOL }
};

enum {
	SCAN_RESULTS_RADIO,
	__SCAN_RESULTS_MAX,
};

static const struct blobmsg_policy scan_results_params[__SCAN_RESULTS_MAX] = {
	[SCAN_RESULTS_RADIO] = { .name = "radio", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	STA_METRIC_QUERY_AGENT,
	STA_METRIC_QUERY_STA,
	__STA_METRIC_QUERY_MAX,
};

static const struct blobmsg_policy sta_metric_query_params[__STA_METRIC_QUERY_MAX] = {
	[STA_METRIC_QUERY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[STA_METRIC_QUERY_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
};

enum {
	UNASSOC_STA_LM_QUERY_AGENT,
	UNASSOC_STA_LM_QUERY_OPCLASS,
	UNASSOC_STA_LM_QUERY_METRICS,
	__UNASSOC_STA_LM_QUERY_MAX,
};

static const struct blobmsg_policy unassoc_sta_lm_query_params[__UNASSOC_STA_LM_QUERY_MAX] = {
	[UNASSOC_STA_LM_QUERY_AGENT] = { .name = "agent",
			.type = BLOBMSG_TYPE_STRING },
	[UNASSOC_STA_LM_QUERY_OPCLASS] = { .name = "opclass",
			.type = BLOBMSG_TYPE_INT32 },
	[UNASSOC_STA_LM_QUERY_METRICS] = { .name = "metrics",
			.type = BLOBMSG_TYPE_ARRAY },
};

enum {
	BK_CAPS_POLICY_AGENT,
	__BK_CAPS_POLICY_MAX,
};

enum {
	BCN_METRICS_AGENT,
	BCN_METRICS_STA,
	BCN_METRICS_OPCLASS,
	BCN_METRICS_CHANNEL,
	BCN_METRICS_BSSID,
	BCN_METRICS_REPORTING_DETAIL,
	BCN_METRICS_SSID,
	BCN_METRICS_CHAN_REPORT,
	BCN_METRICS_ELEMENT_IDS,
	__BCN_METRICS_QUERY_MAX,
};

static const struct blobmsg_policy
		bcn_metrics_query_params[__BCN_METRICS_QUERY_MAX] = {
	[BCN_METRICS_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_OPCLASS] = { .name = "opclass",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_CHANNEL] = { .name = "channel",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_REPORTING_DETAIL] = { .name = "reporting_detail",
			.type = BLOBMSG_TYPE_INT32 },
	[BCN_METRICS_SSID] = { .name = "ssid", .type = BLOBMSG_TYPE_STRING },
	[BCN_METRICS_CHAN_REPORT] = { .name = "channel_report",
			.type = BLOBMSG_TYPE_ARRAY },
	[BCN_METRICS_ELEMENT_IDS] = { .name = "request_element",
			.type = BLOBMSG_TYPE_ARRAY },

};

enum {
	BCN_METRICS_RESP_STA,
	__BCN_METRICS_RESP_MAX,
};

static const struct blobmsg_policy
		bcn_metrics_resp_params[__BCN_METRICS_RESP_MAX] = {
	[BCN_METRICS_RESP_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
};

static const struct blobmsg_policy bk_caps_policy_params[__BK_CAPS_POLICY_MAX] = {
	[BK_CAPS_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
};

enum {
	TOPOLOGY_QUERY_AGENT,
	__TOPOLOGY_QUERY_MAX,
};

static const struct blobmsg_policy topology_query_params[__TOPOLOGY_QUERY_MAX] = {
	[TOPOLOGY_QUERY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
};

enum {
	CAC_REQ_AGENT,
	CAC_REQ_RADIOLIST,
	__CAC_REQ_MAX,
};

static const struct blobmsg_policy cac_req_params[__CAC_REQ_MAX] = {
	[CAC_REQ_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CAC_REQ_RADIOLIST] = { .name = "radiolist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	CAC_TERM_AGENT,
	CAC_TERM_RADIOLIST,
	__CAC_TERM_MAX,
};

static const struct blobmsg_policy cac_term_params[__CAC_TERM_MAX] = {
	[CAC_TERM_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[CAC_TERM_RADIOLIST] = { .name = "radiolist", .type = BLOBMSG_TYPE_ARRAY },
};

enum {
	HLD_AGENT,
	HLD_PROTOCOL,
	HLD_DATA,
	_HLD_MAX,
};

static const struct blobmsg_policy higher_layer_data_params[_HLD_MAX] = {
	[HLD_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[HLD_PROTOCOL] = { .name = "protocol", .type = BLOBMSG_TYPE_INT32 },
	[HLD_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};

enum {
	STEER_HISTORY_STA,
	__STEER_HISTORY_MAX,
};

static const struct blobmsg_policy steer_history_params[__STEER_HISTORY_MAX] = {
	[STEER_HISTORY_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING },
};

enum {
	STEER_SUMMARY_STA,
	__STEER_SUMMARY_MAX,
};

static const struct blobmsg_policy steer_summary_params[__STEER_SUMMARY_MAX] = {
	[STEER_SUMMARY_STA] = { .name = "sta", .type = BLOBMSG_TYPE_STRING},
};

#if 0
enum {
	LINK_POLICY_TYPE,
	LINK_POLICY_DATA,
	__LINK_POLICY_MAX,
};

static const struct blobmsg_policy link_metric_policy_params[__LINK_POLICY_MAX] = {
	[LINK_POLICY_TYPE] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
	[LINK_POLICY_DATA] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
};
#endif

static char *cntrl_status_reason(uint8_t reason)
{
	switch (reason) {
	case CHANNEL_PREF_REASON_UNSPEC:
		return "none";
	case CHANNEL_PREF_REASON_NON11_INTERFERENCE:
		return "non11-interference";
	case CHANNEL_PREF_REASON_INT_OBSS_INTERFERENCE:
		return "int-obss-interference";
	case CHANNEL_PREF_REASON_EXT_OBSS_INTERFERENCE:
		return "ext-obss-interference";
	case CHANNEL_PREF_REASON_REDUCED_COVERAGE:
		return "reduced-coverage";
	case CHANNEL_PREF_REASON_REDUCED_THROUGHPUT:
		return "reduced-throughput";
	case CHANNEL_PREF_REASON_IN_DEVICE_INTERFERENCE:
		return "in-device-interference";
	case CHANNEL_PREF_REASON_DFS_NOP:
		return "dfs-nop";
	case CHANNEL_PREF_REASON_SHARED_BHAUL_PREVENT:
		return "shared-bhaul-prevent";
	case CHANNEL_PREF_REASON_DFS_USABLE:
		return "dfs-usable";
	case CHANNEL_PREF_REASON_DFS_AVAILABLE:
		return "dfs-available";
	case CHANNEL_PREF_REASON_REG_DISALLOWED:
		return "reg-disallowed";
	default:
		break;
	}

	return "unknown";
}

static void cntlr_status_add_opclass(struct blob_buf *bb, struct wifi_radio_opclass *opclass,
				const char *name, int opclass_id)
{
	char age[64];
	void *a, *aa, *t, *tt;
	uint8_t reas, pref;
	int j, k;

	/* Add age */
	snprintf(age, sizeof(age), "%s_age", name);
	blobmsg_add_u32(bb, age, (uint32_t) timestamp_elapsed_sec(&opclass->entry_time));

	a = blobmsg_open_array(bb, name);
	for (j = 0; j < opclass->num_opclass; j++) {
		if (opclass_id && opclass->opclass[j].id != opclass_id)
			continue;
		t = blobmsg_open_table(bb, "");
		blobmsg_add_u32(bb, "opclass", opclass->opclass[j].id);
		blobmsg_add_u32(bb, "bandwidth", opclass->opclass[j].bandwidth);
		if (strstr(name, "cur"))
			blobmsg_add_u32(bb, "txpower", opclass->opclass[j].max_txpower);
		aa = blobmsg_open_array(bb, "channels");
		for (k = 0; k < opclass->opclass[j].num_channel; k++) {
			tt = blobmsg_open_table(bb, "");
			blobmsg_add_u32(bb, "channel", opclass->opclass[j].channel[k].channel);
			if (!strstr(name, "cur")) {
				pref = (opclass->opclass[j].channel[k].preference & CHANNEL_PREF_MASK) >> 4;
				reas = opclass->opclass[j].channel[k].preference & CHANNEL_PREF_REASON;
				blobmsg_add_u32(bb, "preference", pref);
				blobmsg_add_string(bb, "reason", cntrl_status_reason(reas));
			}
			blobmsg_close_table(bb, tt);
		}
		blobmsg_close_array(bb, aa);
		blobmsg_close_table(bb, t);
	}
	blobmsg_close_array(bb, a);
}

enum {
	COMB_POLICY_AGENT,
	COMB_POLICY_BSSID,
	__COMB_POLICY_MAX,
};

static const struct blobmsg_policy send_combined_metrics_params[__COMB_POLICY_MAX] = {
	[COMB_POLICY_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[COMB_POLICY_BSSID] = { .name = "bssid", .type = BLOBMSG_TYPE_STRING },
};

static void add_array_meas_reportlist(struct blob_buf *bb,
		struct sta *s)
{
	void *t;
	struct wifi_sta_meas_report *bcn;
	char bssstr[18] = {0};

	t = blobmsg_open_array(bb, "meas_reportlist");
	list_for_each_entry(bcn, &s->de_sta->meas_reportlist, list) {
		void *tt;

		tt = blobmsg_open_table(bb, "");

		blobmsg_add_u16(bb, "channel", bcn->channel);
		blobmsg_add_u16(bb, "opclass", bcn->opclass);
		blobmsg_add_u16(bb, "rcpi", bcn->rcpi);
		blobmsg_add_u16(bb, "rsni", bcn->rsni);
		hwaddr_ntoa(bcn->bssid, bssstr);
		blobmsg_add_string(bb, "bssid", bssstr);
		blobmsg_add_u32(bb, "requested", bcn->requested);
		blobmsg_add_u32(bb, "stale", bcn->stale);
		blobmsg_add_u64(bb, "meas_start_time", bcn->meas_start_time);
		blobmsg_close_table(bb, tt);
	}

	blobmsg_close_array(bb, t);
}

static int _cntlr_status(struct ubus_context *ctx, struct ubus_object *obj,
			 struct ubus_request_data *req, const char *method,
			 struct blob_attr *msg, bool full)
{
	struct controller *c = container_of(obj, struct controller, obj);
	//struct hlist_head *stalist = c->as_table;
	struct blob_buf bb;
	struct node *n;
	struct sta *s;
	uint8_t cur_opclass_id;
	void *a, *b;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	blobmsg_add_u32(&bb, "num_nodes", c->num_nodes);
	//blobmsg_add_u32(&bb, "num_nodes", list_num_entries(&c->nodelist));
	a = blobmsg_open_array(&bb, "node");
	list_for_each_entry(n, &c->nodelist, list) {
		void *t, *tt;
		char hwaddrstr[18] = {0};
		struct netif_radio *p = NULL;

		hwaddr_ntoa(n->alid, hwaddrstr);
		t = blobmsg_open_table(&bb, "");
		blobmsg_add_string(&bb, "ieee1905id", hwaddrstr);
		blobmsg_add_u32(&bb, "profile", n->map_profile);


		b = blobmsg_open_array(&bb, "radios");
		list_for_each_entry(p, &n->radiolist, list) {
			char macaddrstr[18] = {0};
			char bssidstr[18] = {0};
			void *tttt, *ttttt;
			struct netif_iface *fh = NULL;

			hwaddr_ntoa(p->radio_el->macaddr, macaddrstr);
			tt = blobmsg_open_table(&bb, "");
			blobmsg_add_string(&bb, "macaddr", macaddrstr);

			/* Show current/prefered opclasses */
			cntlr_status_add_opclass(&bb, &p->radio_el->cur_opclass, "cur_opclass", 0);

			/* Limit opclass output if possible */
			if (p->radio_el->cur_opclass.num_opclass)
				cur_opclass_id = p->radio_el->cur_opclass.opclass[0].id;
			else
				cur_opclass_id = 0;

			if (full) {
				cur_opclass_id = 0;
				cntlr_status_add_opclass(&bb, &p->radio_el->supp_opclass, "supp_opclass", cur_opclass_id);
			}

			cntlr_status_add_opclass(&bb, &p->radio_el->pref_opclass, "pref_opclass", cur_opclass_id);

			tttt = blobmsg_open_array(&bb, "interfaces");
			list_for_each_entry(fh, &p->iflist, list) {
				char type[32] = {0};

				if (!fh->bss->enabled)
					continue;

				memset(bssidstr, 0, sizeof(bssidstr));
				hwaddr_ntoa(fh->bss->bssid, bssidstr);
				ttttt = blobmsg_open_table(&bb, "");
				if (fh->bss->is_fbss) {
					blobmsg_add_string(&bb, "bssid", bssidstr);
					strcpy(type, "fronthaul");
					blobmsg_add_string(&bb, "ssid", fh->bss->ssid);
				} else if (fh->bss->is_bbss) {
					blobmsg_add_string(&bb, "bssid", bssidstr);
					strcpy(type, "backhaul");
					blobmsg_add_string(&bb, "ssid", fh->bss->ssid);
				} else {
					blobmsg_add_string(&bb, "macaddr", bssidstr);
					strcpy(type, "station");
				}
				blobmsg_add_string(&bb, "type", type);
				if (!hwaddr_is_zero(fh->upstream_bssid)) {
					hwaddr_ntoa(fh->upstream_bssid, bssidstr);
					blobmsg_add_string(&bb, "bssid", bssidstr);
				}

				blobmsg_close_table(&bb, ttttt);
			}

			blobmsg_close_array(&bb, tttt);
			blobmsg_close_table(&bb, tt);
		}

		blobmsg_close_array(&bb, b);
		blobmsg_close_table(&bb, t);
	}

	blobmsg_close_array(&bb, a);

	a = blobmsg_open_array(&bb, "stations");
	list_for_each_entry(s, &c->stalist, list) {
		void *ttt;
		char stastr[18] = {0};
		char bssstr[18] = {0};

		hwaddr_ntoa(s->de_sta->macaddr, stastr);
		hwaddr_ntoa(s->bssid, bssstr);

		ttt = blobmsg_open_table(&bb, "");

		blobmsg_add_string(&bb, "macaddr", stastr);
		blobmsg_add_string(&bb, "bssid", bssstr);
		blobmsg_add_u16(&bb, "conntime", s->de_sta->conn_time);
		blobmsg_add_u32(&bb, "time_delta", s->time_delta);
		blobmsg_add_u32(&bb, "dl_rate", s->de_sta->dl_rate);
		blobmsg_add_u32(&bb, "ul_rate", s->de_sta->ul_rate);
		blobmsg_add_u32(&bb, "dl_utilization", s->de_sta->dl_utilization);
		blobmsg_add_u32(&bb, "ul_utilization", s->de_sta->ul_utilization);
		blobmsg_add_u32(&bb, "dl_est_thput", s->de_sta->dl_est_thput);
		blobmsg_add_u32(&bb, "ul_est_thput", s->de_sta->ul_est_thput);
		blobmsg_add_u32(&bb, "ul_rcpi", s->de_sta->rcpi);
		//blobmsg_add_u32(&bb, "last_steer_time", s->stats.last_steer_time);
		blobmsg_add_u32(&bb, "failed_steer_attempts", s->de_sta->mapsta.stats.failed_steer_attempts);

		add_array_meas_reportlist(&bb, s);

		blobmsg_close_table(&bb, ttt);
	}

	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);
	return UBUS_STATUS_OK;
}

static int cntlr_status(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	return _cntlr_status(ctx, obj, req, method, msg, false);
}

static int cntlr_status_full(struct ubus_context *ctx, struct ubus_object *obj,
			     struct ubus_request_data *req, const char *method,
			     struct blob_attr *msg)
{
	return _cntlr_status(ctx, obj, req, method, msg, true);
}

static int cntlr_timers(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_buf bb = {0};
	struct controller *c = container_of(obj, struct controller, obj);
	void *t;

	blob_buf_init(&bb, 0);
	t = blobmsg_open_table(&bb, "channel_planning");
	blobmsg_add_u32(&bb, "channel_plan", timer_remaining_ms(&c->acs));
	blobmsg_add_u32(&bb, "allow_bgdfs", timer_remaining_ms(&c->dfs_cleanup));
	blobmsg_close_table(&bb, t);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

const char *steer_method2str(enum steer_method type)
{
	switch (type) {
	case STEER_METHOD_ASSOC_CTL:
		return "assoc_ctl";
	case STEER_METHOD_BTM_REQ:
		return "btm";
	case STEER_METHOD_ASYNC_BTM:
		return "async_btm";
	default:
		return "unknown";
	}
}

const char *steer_trigger2str(enum steer_trigger type)
{
	switch (type) {
	case STEER_TRIGGER_UNKNOWN:
		return "unknown";
	case STEER_TRIGGER_UTIL:
		return "channel_util";
	case STEER_TRIGGER_LINK_QUALITY:
		return "link_quality";
	case STEER_TRIGGER_BK_UTIL:
		return "bk_link_util";
	}
	return "unknown";
}

static int cntlr_steer_history(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__STEER_HISTORY_MAX];
	struct blob_buf bb = {0};
	struct sta *s = NULL;
	void *a;
	uint8_t macaddr[6] = {0};
	char sta[18] = {0};

	blobmsg_parse(steer_history_params, __STEER_HISTORY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[STEER_HISTORY_STA]) {
		strncpy(sta, blobmsg_data(tb[STEER_HISTORY_STA]),
				sizeof(sta) - 1);
		if (!hwaddr_aton(sta, macaddr)) {
			dbg("|%s:%d|Must provide valid STA address!\n",
					__func__, __LINE__);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

	}

	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "sta");
	list_for_each_entry(s, &c->stalist, list) {
		void *ttt, *tttt, *t;
		time_t tmp_t;
		struct tm *info;
		char macstr[18] = {0};
		char str_tm[32] = {0};
		uint8_t num_attempts;
		int size;
		int i;

		if (!hwaddr_is_zero(macaddr) &&
				memcmp(s->de_sta->macaddr, macaddr, 6))
			continue;

		t = blobmsg_open_table(&bb, "");
		hwaddr_ntoa(s->de_sta->macaddr, macstr);

		ttt = blobmsg_open_array(&bb, macstr);
		num_attempts = s->de_sta->mapsta.num_steer_hist;
		size = num_attempts < MAX_STEER_HISTORY ?
				num_attempts : MAX_STEER_HISTORY;
		for (i = 0; i < size; i++) {
			struct wifi_apsta_steer_history *attempt =
					&s->de_sta->mapsta.steer_history[i];

			tttt = blobmsg_open_table(&bb, "");
			/* TODO: fix dummy values */

			tmp_t = attempt->time.tv_sec;
			info = localtime(&tmp_t);
			strftime(str_tm, sizeof(str_tm), "%Y-%m-%dT%H:%M:%SZ", info);
			blobmsg_add_string(&bb, "time", str_tm);
			hwaddr_ntoa(attempt->src_bssid, macstr);
			blobmsg_add_string(&bb, "ap", macstr);
			blobmsg_add_string(&bb, "trigger", steer_trigger2str(attempt->trigger));
			blobmsg_add_string(&bb, "method", steer_method2str(attempt->method));
			hwaddr_ntoa(attempt->dst_bssid, macstr);
			blobmsg_add_string(&bb, "target_ap", macstr);
			blobmsg_add_u32(&bb, "duration", attempt->duration);
			blobmsg_close_table(&bb, tttt);
		}
		blobmsg_close_array(&bb, ttt);
		blobmsg_close_table(&bb, t);
	}

	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);
	return UBUS_STATUS_OK;
}

static int cntlr_steer_summary(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__STEER_SUMMARY_MAX];
	struct blob_buf bb = {0};
	struct sta *s = NULL;
	uint8_t macaddr[6] = {0};
	char sta[18] = {0};

	blobmsg_parse(steer_summary_params, __STEER_SUMMARY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[STEER_SUMMARY_STA]) {
		strncpy(sta, blobmsg_data(tb[STEER_SUMMARY_STA]),
				sizeof(sta) - 1);
		if (!hwaddr_aton(sta, macaddr)) {
			dbg("|%s:%d|Must provide valid STA address!\n",
					__func__, __LINE__);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	blob_buf_init(&bb, 0);

	if (!hwaddr_is_zero(macaddr)) {

		/* The summary of statistics for and individual STA
		 * on the Wi-Fi network.
		 */

		blobmsg_add_string(&bb, "macaddr", sta);
		s = cntlr_find_sta(c, macaddr);

		if (s) {
			blobmsg_add_u64(&bb, "fail_no_candidate",
					s->de_sta->mapsta.stats.no_candidate_cnt);
			blobmsg_add_u64(&bb, "assoc_cntlr_attempts",
					s->de_sta->mapsta.stats.blacklist_attempt_cnt);
			blobmsg_add_u64(&bb, "assoc_cntlr_success",
					s->de_sta->mapsta.stats.blacklist_success_cnt);
			blobmsg_add_u64(&bb, "assoc_cntlr_fail",
					s->de_sta->mapsta.stats.blacklist_failure_cnt);
			blobmsg_add_u64(&bb, "btm_attempts",
					s->de_sta->mapsta.stats.btm_attempt_cnt);
			blobmsg_add_u64(&bb, "btm_success",
					s->de_sta->mapsta.stats.btm_success_cnt);
			blobmsg_add_u64(&bb, "btm_fail",
					s->de_sta->mapsta.stats.btm_failure_cnt);
			blobmsg_add_u64(&bb, "btm_query_resp",
					s->de_sta->mapsta.stats.btm_query_resp_cnt);
			blobmsg_add_u32(&bb, "time_since_steer_attempt",
					timestamp_elapsed_sec(&s->de_sta->mapsta.stats.last_attempt_tsp));
			blobmsg_add_u32(&bb, "time_since_steer",
					timestamp_elapsed_sec(&s->de_sta->mapsta.stats.last_steer_tsp));
		}
	} else {
		/* The summary of statistics per Wi-Fi network. */

		blobmsg_add_u64(&bb, "fail_no_candidate",
				c->dlem.network.steer_summary.no_candidate_cnt);
		blobmsg_add_u64(&bb, "assoc_cntlr_attempts",
				c->dlem.network.steer_summary.blacklist_attempt_cnt);
		blobmsg_add_u64(&bb, "assoc_cntlr_success",
				c->dlem.network.steer_summary.blacklist_success_cnt);
		blobmsg_add_u64(&bb, "assoc_cntlr_fail",
				c->dlem.network.steer_summary.blacklist_failure_cnt);
		blobmsg_add_u64(&bb, "btm_attempts",
				c->dlem.network.steer_summary.btm_attempt_cnt);
		blobmsg_add_u64(&bb, "btm_success",
				c->dlem.network.steer_summary.btm_success_cnt);
		blobmsg_add_u64(&bb, "btm_fail",
				c->dlem.network.steer_summary.btm_failure_cnt);
		blobmsg_add_u64(&bb, "btm_query_resp",
				c->dlem.network.steer_summary.btm_query_resp_cnt);
	}

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}


int cntlr_ap_caps(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	trace("|%s:%d| Parsing the message\n", __func__, __LINE__);
	struct blob_attr *tb[__AP_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	uint8_t hwaddr[6] = {0};
	char agent[18] = {0};
	struct cmdu_buff *cmdu;

	blobmsg_parse(ap_caps_policy_params, __AP_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[AP_POLICY_AGENT]) {
		dbg("Must provide agent mac address\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[AP_POLICY_AGENT]),
			sizeof(agent) - 1);
	if (!hwaddr_aton(agent, hwaddr))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = cntlr_gen_ap_capability_query(c, hwaddr);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	return 0;
}

static int cntlr_channel_pref(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__CHANNEL_PREF_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent[18] = {0};
	uint8_t agent_mac[6] = {0};
	struct cmdu_buff *cmdu;
	struct node *n;

	blobmsg_parse(channel_pref_policy_params, __CHANNEL_PREF_POLICY_MAX, tb,
		blob_data(msg), blob_len(msg));

	/* If no agent param, send to all nodes */
	if (!tb[CHANNEL_PREF_POLICY_AGENT]) {
		list_for_each_entry(n, &c->nodelist, list) {
			cmdu = cntlr_gen_channel_preference_query(c, n->alid);
			if (!cmdu)
				continue;
			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
		}

		return UBUS_STATUS_OK;
	}

	strncpy(agent, blobmsg_data(tb[CHANNEL_PREF_POLICY_AGENT]),
			sizeof(agent) - 1);
	if (!hwaddr_aton(agent, agent_mac))
		goto error;

	cmdu = cntlr_gen_channel_preference_query(c, agent_mac);
	if (!cmdu)
		goto error;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
error:
	return UBUS_STATUS_UNKNOWN_ERROR;
}


static int cntlr_channel_recalc(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	struct blob_attr *tb[__CHANNEL_RECALC_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char alidstr[18] = {};
	char *agent = NULL;
	bool skip_dfs = 0;
	struct node *n = NULL;

	blobmsg_parse(channel_recalc_policy_params, __CHANNEL_RECALC_POLICY_MAX, tb,
		blob_data(msg), blob_len(msg));

	if (tb[CHANNEL_RECALC_POLICY_AGENT])
		agent = blobmsg_data(tb[CHANNEL_RECALC_POLICY_AGENT]);

	if (tb[CHANNEL_RECALC_POLICY_SKIP_DFS])
		skip_dfs = blobmsg_data(tb[CHANNEL_RECALC_POLICY_SKIP_DFS]);

	list_for_each_entry(n, &c->nodelist, list) {
		hwaddr_ntoa(n->alid, alidstr);
		if (agent && strcmp(agent, alidstr))
			continue;

		cntlr_acs_node_channel_recalc(n, skip_dfs);
	}

	return UBUS_STATUS_OK;
}

static int cntlr_channel_cleanup(struct ubus_context *ctx, struct ubus_object *obj,
				 struct ubus_request_data *req, const char *method,
				 struct blob_attr *msg)
{
	struct blob_attr *tb[__CHANNEL_CLEANUP_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char alidstr[18] = {};
	char *agent = NULL;
	struct node *node = NULL;

	blobmsg_parse(channel_recalc_policy_params, __CHANNEL_CLEANUP_POLICY_MAX, tb,
		blob_data(msg), blob_len(msg));

	if (tb[CHANNEL_CLEANUP_POLICY_AGENT])
		agent = blobmsg_data(tb[CHANNEL_CLEANUP_POLICY_AGENT]);

	list_for_each_entry(node, &c->nodelist, list) {
		hwaddr_ntoa(node->alid, alidstr);
		if (agent && strcmp(agent, alidstr))
			continue;

		/* Action here */
		cntlr_dfs_node_cleanup(node);
	}

	return UBUS_STATUS_OK;
}

static int cntlr_channel_select(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CHANNEL_SEL_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent[18] = {0};
	char radio_id[18] = {0};
	uint8_t radio_mac[6] = {0};
	uint8_t channel_nr = 0;
	uint8_t class_id = 0, pref = 0, transmit_power = 0;
	uint8_t *chanlist = NULL;
	struct blob_attr *cur;
	int rem, ret, l = 0;
	uint16_t mid = 0;
	struct cmdu_buff *cmdu;
	int pref_val = 0;
	int err = UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = cmdu_alloc_simple(CMDU_CHANNEL_SELECTION_REQ, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	blobmsg_parse(channel_select_policy_params, __CHANNEL_SEL_POLICY_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (!tb[CHANNEL_SEL_POLICY_AGENT]) {
		fprintf(stderr, "%s: provide Agent " \
				"address in format 11:22:33...\n", __func__);
		err = UBUS_STATUS_INVALID_ARGUMENT;
		goto fail_cmdu;
	}

	strncpy(agent, blobmsg_data(tb[CHANNEL_SEL_POLICY_AGENT]), sizeof(agent) - 1);
	if (!hwaddr_aton(agent, cmdu->origin))
		goto fail_cmdu;

	if (tb[CHANNEL_SEL_POLICY_RADIO_ID]) {
		strncpy(radio_id, blobmsg_data(tb[CHANNEL_SEL_POLICY_RADIO_ID]),
			sizeof(radio_id) - 1);
		if (!hwaddr_aton(radio_id, radio_mac))
			goto fail_cmdu;
	}

	if (tb[CHANNEL_SEL_POLICY_CLASS_ID])
		class_id = (uint8_t) blobmsg_get_u32(tb[CHANNEL_SEL_POLICY_CLASS_ID]);

	if (tb[CHANNEL_SEL_POLICY_CHANNEL]) {
		channel_nr = blobmsg_check_array(tb[CHANNEL_SEL_POLICY_CHANNEL],
				BLOBMSG_TYPE_INT32);
		l = 0;

		if (channel_nr > 0) {
			chanlist = calloc(channel_nr, sizeof(uint8_t));
			if (!chanlist)
				goto fail_cmdu;
		}

		blobmsg_for_each_attr(cur, tb[CHANNEL_SEL_POLICY_CHANNEL], rem)
			chanlist[l++] = (uint8_t) blobmsg_get_u32(cur);
	}

	if (tb[CHANNEL_SEL_POLICY_PREF]) {
		pref_val = blobmsg_get_u32(tb[CHANNEL_SEL_POLICY_PREF]);

		if ((pref_val < 0) || (pref_val > 0x0f)) {
			fprintf(stderr, "%s: provide preference value in " \
					"[0-15] range\n", __func__);
			err = UBUS_STATUS_INVALID_ARGUMENT;
			goto fail_cmdu;
		}

		pref = (uint8_t) pref_val;
	}


	if (tb[CHANNEL_SEL_POLICY_TRANSMIT_POWER])
		transmit_power =
			(uint8_t) blobmsg_get_u32(tb[CHANNEL_SEL_POLICY_TRANSMIT_POWER]);


	if (tb[CHANNEL_SEL_POLICY_RADIO_ID] &&
			tb[CHANNEL_SEL_POLICY_CLASS_ID] &&
			tb[CHANNEL_SEL_POLICY_PREF]) {

		ret = cntlr_gen_channel_pref(c, cmdu, radio_mac, class_id,
				channel_nr, chanlist, pref);
		if (ret)
			goto fail_cmdu;
	}

	if (tb[CHANNEL_SEL_POLICY_RADIO_ID] &&
			tb[CHANNEL_SEL_POLICY_TRANSMIT_POWER]) {

		ret = cntlr_gen_txpower_limit(c, cmdu,
				radio_mac, transmit_power);
		if (ret)
			goto fail_cmdu;
	}

	if (chanlist)
		free(chanlist);

	cmdu_put_eom(cmdu);
	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;

fail_cmdu:
	if (chanlist)
		free(chanlist);

	cmdu_free(cmdu);

	return err;
}

static void cntlr_update_sta_steering_stats(struct controller *c, uint8_t *bssid,
					    uint32_t sta_nr, uint8_t sta_id[][6],
					    uint32_t bssid_nr, uint8_t target_bbsid[][6])
{
	int i;

	/* Number of STAs and BSSIDs are equal, map STA to BSSID */
	if (sta_nr == bssid_nr) {
		for (i = 0; i < sta_nr; i++) {
			cntlr_update_sta_steer_counters(c,
							sta_id[i],
							bssid,
							target_bbsid[i],
							STEER_MODE_BTM_REQ,
							STEER_TRIGGER_UNKNOWN);
		}
	/* Multiple STAs and single BSSID - one attempt per STA */
	} else if (sta_nr > 0 && bssid_nr == 1) {
		for (i = 0; i < sta_nr; i++) {
			cntlr_update_sta_steer_counters(c,
							sta_id[i],
							bssid,
							target_bbsid[0],
							STEER_MODE_BTM_REQ,
							STEER_TRIGGER_UNKNOWN);
		}
	}
	/* No STA provided, request applies to ALL associated STAs */
	else if (sta_nr == 0 && bssid_nr == 1) {
		struct sta *s = NULL;

		list_for_each_entry(s, &c->stalist, list) {
			if (!memcmp(s->bssid, bssid, 6)) {
				cntlr_update_sta_steer_counters(c,
								s->de_sta->macaddr,
								bssid,
								target_bbsid[0],
								STEER_MODE_BTM_REQ,
								STEER_TRIGGER_UNKNOWN);
			}
		}
	}
	/* No BSSID specified for the STAs - automatic best */
	else if (sta_nr > 0 && bssid_nr == 0) {
		for (i = 0; i < sta_nr; i++) {
			cntlr_update_sta_steer_counters(c,
							sta_id[i],
							bssid,
							NULL,
							STEER_MODE_BTM_REQ,
							STEER_TRIGGER_UNKNOWN);
		}
	}
}

static int cntlr_client_steering(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__STEERING_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	uint8_t bss_id[6] = {0};
	uint8_t sta_id[18][6] = {0};
	//uint8_t sta_multi_id[18][6] = {0};
	uint8_t target_bbsid[18][6] = {0};
	//uint8_t target_bbsid_multi[18][6] = {0};
	uint32_t timeout = 0;
	uint32_t sta_nr = 0, bssid_nr = 0/*, sta_multi_nr = 0, bssid_multi_nr = 0*/;
	uint32_t request_mode = 0, request_mode_present = -1;
	uint32_t sta_present = -1,/*sta_multi_present = -1,*/ bssid_present = -1;
	uint32_t target_bssid_present = -1/*, target_bssid_multi_present = -1*/;
	struct blob_attr *cur;
	int rem, l = 0, ret;
	uint32_t steer_timeout = 0, btm_timeout = 0;
	struct cmdu_buff *cmdu;
	uint16_t mid = 0;

	cmdu = cmdu_alloc_simple(CMDU_CLIENT_STEERING_REQUEST, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	blobmsg_parse(client_steering_policy_params, __STEERING_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[STEERING_POLICY_AGENT])
		hwaddr_aton(blobmsg_get_string(tb[STEERING_POLICY_AGENT]), cmdu->origin);

	if (tb[STEERING_POLICY_FROM_BSSID]) {
		hwaddr_aton(blobmsg_get_string(tb[STEERING_POLICY_FROM_BSSID]), bss_id);
		bssid_present = 1;
	}

	if (tb[STEERING_POLICY_STA]) {
		sta_present = 1;
		sta_nr = blobmsg_check_array(tb[STEERING_POLICY_STA],
				BLOBMSG_TYPE_STRING);
		l = 0;
		blobmsg_for_each_attr(cur, tb[STEERING_POLICY_STA], rem) {
			hwaddr_aton(blobmsg_get_string(cur), sta_id[l++]);
		}
	}

	if (tb[STEERING_POLICY_TARGET_BSSID]) {
		target_bssid_present = 1;
		bssid_nr = blobmsg_check_array(tb[STEERING_POLICY_TARGET_BSSID],
				BLOBMSG_TYPE_STRING);
		l = 0;
		blobmsg_for_each_attr(cur, tb[STEERING_POLICY_TARGET_BSSID], rem) {
			hwaddr_aton(blobmsg_get_string(cur), target_bbsid[l++]);
		}
	}

	if (tb[STEERING_POLICY_STEER_TIMEOUT])
		steer_timeout = (int) blobmsg_get_u32(tb[STEERING_POLICY_STEER_TIMEOUT]);

	if (tb[STEERING_POLICY_REQUEST_MODE]) {
		request_mode = blobmsg_get_bool(tb[STEERING_POLICY_REQUEST_MODE]) ?
			STEER_MODE_BTM_REQ : STEER_MODE_OPPORTUNITY;
		request_mode_present = 1;
	}

	if (tb[STEERING_POLICY_BTM_TIMEOUT])
		btm_timeout = (int) blobmsg_get_u32(tb[STEERING_POLICY_BTM_TIMEOUT]);

	UNUSED(btm_timeout);
	UNUSED(target_bssid_present);
	UNUSED(sta_present);

#ifdef PROFILE2

	if (tb[STEERING_POLICY_TARGET_BSSID_MULTIBAND]) {
		target_bssid_multi_present = 1;
		bssid_multi_nr = blobmsg_check_array(
				tb[STEERING_POLICY_TARGET_BSSID_MULTIBAND],
				BLOBMSG_TYPE_INT32);
		l = 0;
		blobmsg_for_each_attr(cur, tb[STEERING_POLICY_TARGET_BSSID_MULTIBAND], rem) {
			hwaddr_aton(blobmsg_get_string(cur), target_bbsid_multi[l++]);
		}
	}

	if (tb[STEERING_POLICY_STA_MULTIBAND]) {
		sta_multi_present = 1;
		sta_multi_nr = blobmsg_check_array(tb[STEERING_POLICY_STA_MULTIBAND],
				BLOBMSG_TYPE_INT32);
		l = 0;
		blobmsg_for_each_attr(cur, tb[STEERING_POLICY_STA_MULTIBAND], rem) {
			hwaddr_aton(blobmsg_get_string(cur), target_bbsid_multi[l++]);
		}
	}

#endif

	dbg("bssid presne t %d req mode pres %d\n", bssid_present, request_mode_present);

	if (bssid_present == 1 && request_mode_present == 1) {
		trace("values are: requestmode %d timeout %d sta_cnt %d bssid_nr %d\n",
			request_mode, timeout, sta_nr,
			bssid_nr);

		/* Client Steering Request TLV */
		ret = cntlr_gen_tlv_steer_request(c, cmdu,
				MAP_TLV_STEERING_REQUEST, bss_id,
				steer_timeout, sta_nr, sta_id, bssid_nr,
				target_bbsid, request_mode);
		if (ret)
			goto fail_cmdu;
	}

#ifdef PROFILE2

	//Here we need to add tlv for 17.2.57
	if (bssid_present == 1 && request_mode_present != 1 &&
		(target_bssid_multi_present != -1 ||
					sta_multi_present != -1)) {

		/* Client Steering Request TLV 17.2.57 */
		ret = cntlr_gen_tlv_steer_request(c, cmdu,
				MAP_TLV_PROFILE2_STEERING_REQ, bss_id,
				steer_timeout, sta_multi_nr, sta_multi_id,
				bssid_multi_nr, target_bbsid_multi, request_mode);
		if (ret)
			goto fail_cmdu;
	}

	UNUSED(target_bssid_multi_present);
	UNUSED(bssid_multi_nr);
	UNUSED(sta_multi_nr);
#endif

	cntlr_update_sta_steering_stats(c, bss_id, sta_nr, sta_id,
					bssid_nr, target_bbsid);

	cmdu_put_eom(cmdu);
	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;

fail_cmdu:
	cmdu_free(cmdu);
	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int client_assoc_cntlr(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct blob_attr *tb[__CLIENT_POLICY_ASSOC_CONTROL_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent[18] = {0};
	char bss_id[18] = {0};
	uint32_t bssid_present = -1, sta_present = -1;
	uint32_t assoc_timeout_present = -1;
	uint32_t l = 0;
	struct blob_attr *cur;
	int rem = 0, ret = 0;
	uint8_t agent_mac[6] = {0};
	uint8_t bss_mac[6] = {0};
	uint8_t assoc_cntl_mode = 0, sta_nr = 0;
	uint16_t assoc_timeout = 0;
	uint8_t *stalist = NULL;
	uint16_t mid = 0;

	blobmsg_parse(client_assoc_cntrl_policy_config_params,
			__CLIENT_POLICY_ASSOC_CONTROL_MAX, tb,
	blob_data(msg), blob_len(msg));

	if (tb[CLIENT_POLICY_ASSOC_CONTROL_AGENT]) {
		strncpy(agent, blobmsg_data(tb[CLIENT_POLICY_ASSOC_CONTROL_AGENT]),
			sizeof(agent) - 1);
		if (!hwaddr_aton(agent, agent_mac))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[CLIENT_POLICY_ASSOC_CONTROL_BSSID]) {
		strncpy(bss_id, blobmsg_data(tb[CLIENT_POLICY_ASSOC_CONTROL_BSSID]),
			sizeof(bss_id) - 1);
		if (!hwaddr_aton(bss_id, bss_mac))
			return UBUS_STATUS_INVALID_ARGUMENT;

		bssid_present = 1;
	}

	if (tb[CLIENT_POLICY_ASSOC_CONTROL_MODE])
		assoc_cntl_mode = (uint8_t) blobmsg_get_u32(
					tb[CLIENT_POLICY_ASSOC_CONTROL_MODE]);

	if (tb[CLIENT_POLICY_ASSOC_CONTROL_VALID_TIME]) {
		assoc_timeout_present = 1;
		assoc_timeout = (uint16_t) blobmsg_get_u32(
				tb[CLIENT_POLICY_ASSOC_CONTROL_VALID_TIME]);
	}

	if (tb[CLIENT_POLICY_ASSOC_CONTROL_STALIST]) {
		char mac[18];

		sta_present = 1;
		sta_nr = blobmsg_check_array(tb[CLIENT_POLICY_ASSOC_CONTROL_STALIST],
				BLOBMSG_TYPE_STRING);
		if (sta_nr > 0) {
			stalist = calloc(sta_nr, 6 * sizeof(uint8_t));
			if (!stalist)
				return UBUS_STATUS_UNKNOWN_ERROR;
		}

		l = 0;
		memset(mac, 0, sizeof(mac));
		blobmsg_for_each_attr(cur, tb[CLIENT_POLICY_ASSOC_CONTROL_STALIST], rem) {
			strncpy(mac, blobmsg_get_string(cur), sizeof(mac) - 1);
			hwaddr_aton(mac, &stalist[l * 6]);
			l++;
		}

		/* no valid sta data */
		if (l == 0)
			goto error;
	}

	if ((bssid_present != 1) || (sta_present != 1) ||
			(assoc_timeout_present != 1) ||
			(assoc_cntl_mode != 0 && assoc_cntl_mode != 1)) {
		trace("required fields are incorrect/missing.!!\n");
		goto error;
	}

	trace("|%s:%d| assoc_mode %d assoc_timeout %d sta_cnt %d\n",
		  __func__, __LINE__, assoc_cntl_mode, assoc_timeout, sta_nr);

	ret = cntlr_send_client_assoc_ctrl_request(c, agent_mac, bss_mac,
			assoc_cntl_mode, assoc_timeout, sta_nr, stalist, &mid);

error:
	if (stalist)
		free(stalist);

	if (ret)
		return UBUS_STATUS_UNKNOWN_ERROR;

	return UBUS_STATUS_OK;
}

static int cntlr_ap_metric_query(struct ubus_context *ctx,
		struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *msg)
{
	int rem, index;
	int num_bss = 0, num_radio = 0;
	uint8_t agent_mac[6] = {0};
	uint8_t *bsslist = NULL;
	uint8_t *radiolist = NULL;
	uint8_t *new_data = NULL;
	char agent[18] = {0};
	struct cmdu_buff *cmdu;
	struct blob_attr *attr = NULL;
	struct blob_attr *tb[__AP_METRIC_QUERY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);

	blobmsg_parse(ap_metric_query_params, __AP_METRIC_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[AP_METRIC_QUERY_AGENT] || !tb[AP_METRIC_QUERY_BSS]) {
		fprintf(stderr, "Agent policy config: provide Agent and BSS " \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[AP_METRIC_QUERY_AGENT]),
			sizeof(agent) - 1);
	if (!hwaddr_aton(agent, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	/* fetch bsslist */
	blobmsg_for_each_attr(attr, tb[AP_METRIC_QUERY_BSS], rem) {
		uint8_t bssid[6] = {0};
		char bss[18] = {0};

		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
			continue;

		strncpy(bss, blobmsg_data(attr), sizeof(bss) - 1);
		if (!hwaddr_aton(bss, bssid)) {
			fprintf(stderr, "AP metric query: provide bss " \
					"address in format 11:22:33...\n");

			if (bsslist)
				free(bsslist);

			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		num_bss++;
		new_data = (uint8_t *)realloc(bsslist,
				6 * num_bss * sizeof(uint8_t));
		if (!new_data) {
			if (bsslist)
				free(bsslist);

			return UBUS_STATUS_UNKNOWN_ERROR;
		} else
			bsslist = new_data;

		index = (num_bss - 1) * 6;
		memcpy(bsslist + index, bssid, 6);
	}

	if (num_bss == 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	/* fetch radio id's */
	blobmsg_for_each_attr(attr, tb[AP_METRIC_QUERY_RADIO], rem) {
		uint8_t radioid[6] = {0};
		char radio[18] = {0};

		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
			continue;

		memset(radio, 0, sizeof(radio));
		strncpy(radio, blobmsg_data(attr), sizeof(radio)-1);
		if (!hwaddr_aton(radio, radioid)) {
			fprintf(stderr, "Agent policy config: provide radio " \
					"address in format 11:22:33...\n");
			goto fail_parsing;
		}

		num_radio++;
		new_data = (uint8_t *)realloc(radiolist,
				6 * num_radio * sizeof(uint8_t));
		if (!new_data)
			goto fail_parsing;
		else
			radiolist = new_data;

		index = (num_radio - 1) * 6;
		memcpy(radiolist + index, radioid, 6);
	}

	cmdu = cntlr_gen_ap_metrics_query(c, agent_mac, num_bss,
			bsslist, num_radio, radiolist);
	if (!cmdu)
		goto fail_parsing;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	if (radiolist)
		free(radiolist);

	free(bsslist);

	return UBUS_STATUS_OK;

fail_parsing:
	if (radiolist)
		free(radiolist);

	free(bsslist);

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int cntlr_sta_caps(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	uint8_t agent[6] = {0};
	uint8_t sta[6] = {0};
	uint8_t bssid[6] = {0};
	char mac[18];
	struct cmdu_buff *cmdu;
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__STA_POLICY_MAX];

	blobmsg_parse(sta_caps_policy_params, __STA_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[STA_POLICY_AGENT] || !tb[STA_POLICY_STA] ||
			!tb[STA_POLICY_BSSID]) {
		fprintf(stderr, "STA Capability Query: must provide Agent, "\
				"STA and BSSID\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(mac, 0, sizeof(mac));
	strncpy(mac, blobmsg_data(tb[AP_POLICY_AGENT]), sizeof(mac) - 1);
	if (!hwaddr_aton(mac, agent))
		return UBUS_STATUS_UNKNOWN_ERROR;

	memset(mac, 0, sizeof(mac));
	strncpy(mac, blobmsg_data(tb[STA_POLICY_STA]), sizeof(mac) - 1);
	if (!hwaddr_aton(mac, sta))
		return UBUS_STATUS_UNKNOWN_ERROR;

	memset(mac, 0, sizeof(mac));
	strncpy(mac, blobmsg_data(tb[STA_POLICY_BSSID]), sizeof(mac) - 1);
	if (!hwaddr_aton(mac, bssid))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = cntlr_gen_client_caps_query(c, agent, sta, bssid);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;
}

#if 0
static int cntlr_teardown_ap(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	return 0;
}
#endif

static int cntlr_reconfig_ap(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__RECFG_POLICY_MAX];
	char agent[18] = {0};
	uint8_t hwaddr[6] = {0};
	struct cmdu_buff *cmdu;
	//int i, tlv_index = 0;

	blobmsg_parse(reconfig_policy_params, __RECFG_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[RECFG_POLICY_AGENT]) {
		fprintf(stderr, "Provide ALMAC address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}


	strncpy(agent, blobmsg_data(tb[RECFG_POLICY_AGENT]),
			sizeof(agent) - 1);
	if (!hwaddr_aton(agent, hwaddr))
		return UBUS_STATUS_UNKNOWN_ERROR;


	cmdu = cntlr_gen_ap_autoconfig_renew(c, hwaddr);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	return UBUS_STATUS_OK;
}

#if 0
static struct netif_radio *cntlr_radio_to_bssid(struct controller *c, const char *radio)
{
	struct netif_radio *r;

	list_for_each_entry(r, &c->radiolist, list) {
		if (!strncmp(r->name, radio, 16))
			return r;
	}

	return NULL;
}
#endif

static int higher_layer_data(struct ubus_context *ctx, struct ubus_object *obj,
		      struct ubus_request_data *req, const char *method,
		      struct blob_attr *msg)
{
	struct controller *a = container_of(obj, struct controller, obj);
	struct cmdu_buff *cmdu;
	struct blob_attr *tb[_HLD_MAX];
	uint8_t agent_mac[6];
	uint8_t proto;
	int len, tmp;
	uint8_t *data;
	char *datastr;

	blobmsg_parse(higher_layer_data_params, _HLD_MAX, tb, blob_data(msg),
			blob_len(msg));

	if (!tb[HLD_AGENT]) {
		dbg("%s(): ADDR not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	len = blobmsg_data_len(tb[HLD_AGENT]);
	if (len < 17) {
		dbg("%s(): wrong ADDR length %d!\n", __func__, len);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	if (hwaddr_aton(blobmsg_data(tb[HLD_AGENT]), agent_mac) == NULL) {
		dbg("%s(): wrong ADDR!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[HLD_PROTOCOL]) {
		dbg("%s(): PROTOCOL not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	tmp = blobmsg_get_u32(tb[HLD_PROTOCOL]);
	if (tmp < 0 || tmp > 255) {
		dbg("%s(): PROTOCOL not withing the 0-255 range !\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	proto = (uint8_t) tmp;

	if (!tb[HLD_DATA]) {
		dbg("%s(): DATA not specified!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}
	datastr = blobmsg_get_string(tb[HLD_DATA]);
	len = blobmsg_data_len(tb[HLD_DATA]);
	if (len % 2 != 1) {
		/* expect n*2 hex digits + '\0' termination character  */
		dbg("%s(): wrong DATA length %d!\n", __func__, len);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	len = len / 2;
	data = calloc(len, sizeof(uint8_t));
	if (!data) {
		dbg("%s(): alloc failure!\n", __func__);
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (strtob(datastr, len, data) == NULL) {
		dbg("%s(): wrong DATA %d!\n", __func__, len);
		goto error;
	}

	cmdu = cntlr_gen_higher_layer_data(a, agent_mac, proto, data, len);
	if (!cmdu)
		goto error;

	free(data);

	send_cmdu(a, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;

error:
	free(data);
	return UBUS_STATUS_UNKNOWN_ERROR;
}

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
enum {
	DYN_CNTLR_SYNC_FOR_AGENT,
	_DYN_CNTLR_SYNC_CONFIG_MAX,
};

static const struct blobmsg_policy cntlr_sync_config_policy[_DYN_CNTLR_SYNC_CONFIG_MAX] = {
	[DYN_CNTLR_SYNC_FOR_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
};

static int dyn_cntlr_sync_config(struct ubus_context *ctx, struct ubus_object *obj,
				 struct ubus_request_data *req, const char *method,
				 struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[_DYN_CNTLR_SYNC_CONFIG_MAX];
	char agent[18] = {0};
	uint8_t agent_mac[6] = {0};


	blobmsg_parse(cntlr_sync_config_policy, _DYN_CNTLR_SYNC_CONFIG_MAX, tb,
		      blob_data(msg), blob_len(msg));

	if (tb[DYN_CNTLR_SYNC_FOR_AGENT]) {
		strncpy(agent, blobmsg_data(tb[DYN_CNTLR_SYNC_FOR_AGENT]), sizeof(agent) - 1);
		if (!hwaddr_aton(agent, agent_mac))
			return UBUS_STATUS_INVALID_ARGUMENT;
	}

	return cntlr_sync_dyn_controller_config(c, agent_mac);
}
#endif

#if (EASYMESH_VERSION > 2)
enum {
	DPP_CCE_AGENT,
	DPP_CCE_ADVERISE_FLAG,
	__DPP_CCE_MAX,
};

static const struct blobmsg_policy dpp_cce_params[__DPP_CCE_MAX] = {
	[DPP_CCE_AGENT] = { .name = "agent", .type = BLOBMSG_TYPE_STRING },
	[DPP_CCE_ADVERISE_FLAG] = { .name = "cce_advertise", .type = BLOBMSG_TYPE_BOOL },
};

static int cntlr_dpp_cce_indication(struct ubus_context *ctx, struct ubus_object *obj,
		struct ubus_request_data *req, const char *method,
		struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct cmdu_buff *cmdu;
	struct blob_attr *tb[__DPP_CCE_MAX];
	uint8_t agent[6] = {0};
	bool cce_advertise = false;
	int len;

	blobmsg_parse(dpp_cce_params, __DPP_CCE_MAX, tb, blob_data(msg), blob_len(msg));
	if (!tb[DPP_CCE_AGENT]) {
		dbg("%s: provide agent in '11:22:33...' format\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[DPP_CCE_ADVERISE_FLAG]) {
		dbg("%s: provide cce_advertise 'true' or 'false'\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	len = blobmsg_data_len(tb[DPP_CCE_AGENT]);
	if (len < 17) {
		dbg("%s: wrong ADDR length %d!\n", __func__, len);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (hwaddr_aton(blobmsg_data(tb[DPP_CCE_AGENT]), agent) == NULL) {
		dbg("%s: wrong ADDR!\n", __func__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	cce_advertise = blobmsg_get_bool(tb[DPP_CCE_ADVERISE_FLAG]);
	cmdu = cntlr_gen_dpp_cce_indication(c, agent, cce_advertise);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;
}
#endif

#if 0
static int cntlr_config_ap(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__CFG_POLICY_MAX];
	char agent[18] = {0};
	uint8_t hwaddr[6] = {0};
	struct cmdu_cstruct *cmdu;
	struct agent_policy *a, *found = NULL;
	struct tlv_ap_radio_identifier *p = NULL;
	struct tlv_default_8021q_settings *p1;
	struct tlv_traffic_sep_policy *p2;
	int i, tlv_index = 0;

	blobmsg_parse(config_policy_params, __CFG_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[CFG_POLICY_AGENT] ||
			(!tb[CFG_POLICY_RADIO] && !tb[CFG_POLICY_BSSID])) {
		fprintf(stderr, "STA Capability Query: provide BSSID " \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[CFG_POLICY_AGENT]), sizeof(agent) - 1);
	if (!hwaddr_aton(agent, hwaddr))
		return UBUS_STATUS_UNKNOWN_ERROR;

	list_for_each_entry(a, &c->cfg.policylist, list) {
		if (!memcmp(hwaddr, a->agent_id, sizeof(hwaddr))) {
			found = a;
			break;
		}
	}

	if (!found)
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = (struct cmdu_cstruct *)calloc(1, sizeof(struct cmdu_cstruct));
	if (!cmdu) {
		fprintf(stderr, "failed to malloc cmdu\n");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	memcpy(cmdu->origin, hwaddr, sizeof(hwaddr));
	cmdu->message_type = CMDU_TYPE_AP_AUTOCONFIGURATION_WSC;
	cmdu->message_id = 1;

	if (tb[CFG_POLICY_BSSID]) {
		char bssid[18] = {0};
		uint8_t hwaddr[6] = {0};

		strncpy(bssid, blobmsg_data(tb[CFG_POLICY_BSSID]),
				sizeof(bssid) - 1);
		if (!hwaddr_aton(bssid, hwaddr)) {
			free(cmdu);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
		p = cntlr_gen_ap_radio_identifier(c, cmdu, hwaddr);
	} else if (tb[CFG_POLICY_RADIO]) {
		char radio[18] = {0};
		struct netif_radio *r;

		strncpy(radio, blobmsg_data(tb[CFG_POLICY_RADIO]),
				sizeof(radio) - 1);
		r = cntlr_radio_to_bssid(c, radio);
		if (!r) {
			free(cmdu);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		p = cntlr_gen_ap_radio_identifier(c, cmdu, r->hwaddr);
	}
	/*
	else { // TODO: all radios
		struct netif_radio *r;

		list_for_each_entry(r, &c->radiolist, list) {
			int i;

			cntlr_gen_config_ap_tlv(c, cmdu, r->hwaddr);
			send_cmdu(c, cmdu);

			for (i = 0; i < cmdu->num_tlvs; i++)
				free(cmdu->tlvs[i]);
			free(cmdu->tlvs);
			cmdu->num_tlvs = 0;
		}
	}
	*/
	if (!p)
		goto fail_cmdu;

	cmdu->num_tlvs++;

	p1 = (struct tlv_default_8021q_settings *) calloc(1, sizeof(*p1));
	if (!p1)
		goto fail_p;

	cmdu->num_tlvs++;
	p1->tlv_type = MAP_TLV_DEFAULT_8021Q_SETTINGS;
	p1->primary_vid = c->cfg->pvid;
	p1->pcp = a->pcp_default;

	p2 = (struct tlv_traffic_sep_policy *) calloc(1, sizeof(*p2));
	if (!p2)
		goto fail_p1;

	cmdu->num_tlvs++;
	p2->tlv_type = MAP_TLV_TRAFFIC_SEPARATION_POLICY;
	p2->nbr_ssid = c->cfg.num_fh;
	p2->data = calloc(p2->nbr_ssid, sizeof(*(p2->data)));
	if (!p2->data)
		goto fail_p2;

	for (i = 0; i < p2->nbr_ssid; i++) {
		int len;

		len = strlen((char *)c->cfg.fh[i].ssid);

		p2->data[i].ssid_len = len;
		p2->data[i].vid = c->cfg.fh[i].vlanid;
		p2->data[i].ssid = calloc(1, len + 1);
		if (!p2->data[i].ssid)
			continue;

		strncpy(p2->data[i].ssid, (char *)c->cfg.fh[i].ssid, len);
	}

	cmdu->tlvs = (uint8_t **)calloc(cmdu->num_tlvs, sizeof(uint8_t *));
	if (!cmdu->tlvs)
		goto fail_p2_data;
	cmdu->tlvs[tlv_index++] = (uint8_t *)p;
	cmdu->tlvs[tlv_index++] = (uint8_t *)p1;
	cmdu->tlvs[tlv_index++] = (uint8_t *)p2;

	// TODO: ff:ff:ff:ff:ff:ff = send to all agents

	send_cmdu(c, cmdu);
	map_free_cmdu(cmdu);
	return 0;

fail_p2_data:
	free(p2->data);
fail_p2:
	free(p2);
fail_p1:
	free(p1);
fail_p:
	free(p);
fail_cmdu:
	free(cmdu);
	return UBUS_STATUS_UNKNOWN_ERROR;
}
#endif

static int cntlr_bk_steer(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct blob_attr *tb[__BK_STEER_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent_str[18] = {0}, bssid_str[18] = {0}, bkhaul_str[18] = {0};
	uint8_t agent[6] = {0}, target_bssid[6] = {0}, bkhaul[6] = {0};
	struct cmdu_buff *cmdu;
	uint8_t op_class = 0, channel = 0;
	struct sta *s;

	blobmsg_parse(bk_steer_policy_params, __BK_STEER_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[BK_STEER_POLICY_BSSID] || !tb[BK_STEER_POLICY_STA_MAC]) {
		trace("BSSID and bSTA MAC required\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(bssid_str, blobmsg_data(tb[BK_STEER_POLICY_BSSID]),
			sizeof(bssid_str) - 1);
	strncpy(bkhaul_str, blobmsg_data(tb[BK_STEER_POLICY_STA_MAC]),
			sizeof(bkhaul_str) - 1);

	if (!hwaddr_aton(bssid_str, target_bssid) || !hwaddr_aton(bkhaul_str, bkhaul)) {
		trace("MAC must be in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (tb[BK_STEER_POLICY_AGENT]) {
		strncpy(agent_str, blobmsg_data(tb[BK_STEER_POLICY_AGENT]),
				sizeof(agent_str) - 1);
		trace("Received agent %s\n", agent_str);
		if (!hwaddr_aton(agent_str, agent))
			return UBUS_STATUS_INVALID_ARGUMENT;
	} else {
		s = cntlr_find_sta(c, bkhaul);
		if (!s)
			return UBUS_STATUS_UNKNOWN_ERROR;
		memcpy(agent, s->fh->agent->alid, 6);
	}

	if (tb[BK_STEER_POLICY_CHANNEL])
		channel = blobmsg_get_u8(tb[BK_STEER_POLICY_CHANNEL]);
	if (tb[BK_STEER_POLICY_OP_CLASS])
		op_class = blobmsg_get_u8(tb[BK_STEER_POLICY_OP_CLASS]);

	cmdu = cntlr_gen_backhaul_steer_request(c, agent, bkhaul, target_bssid,
							op_class, channel);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
}

static int cntlr_ap_policy_config(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	char agent[18] = {0};
	char radio[18] = {0};
	char bss[18] = {0};
	uint8_t hwaddr[6] = {0};
	struct cmdu_buff *cmdu;
	struct blob_attr *attr = NULL;
	uint8_t *radiolist = NULL;
	uint8_t *bsslist = NULL;
	uint8_t *new_data = NULL;
	int rem, num_radio = 0, num_bss = 0;
	struct blob_attr *tb[__AP_POLICY_CONFIG_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	struct node_policy *np;

	blobmsg_parse(ap_policy_config_params, __AP_POLICY_CONFIG_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[AP_POLICY_CONFIG_AGENT] || !tb[AP_POLICY_CONFIG_RADIOS]) {
		fprintf(stderr, "Agent policy config: provide Agent or Radio " \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[AP_POLICY_CONFIG_AGENT]), sizeof(agent) - 1);
	if (!hwaddr_aton(agent, hwaddr))
		return UBUS_STATUS_UNKNOWN_ERROR;


	np = agent_find_policy(c, hwaddr);
	if (!np)
		return UBUS_STATUS_INVALID_ARGUMENT;

	/* fetch radio id's */
	blobmsg_for_each_attr(attr, tb[AP_POLICY_CONFIG_RADIOS], rem) {
		uint8_t bssid[6] = {0};

		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
			continue;

		memset(radio, 0, sizeof(radio));
		strncpy(radio, blobmsg_data(attr), sizeof(radio)-1);
		if (!hwaddr_aton(radio, bssid)) {
			fprintf(stderr, "Agent policy config: provide radio " \
					"address in format 11:22:33...\n");
			if (radiolist)
				free(radiolist);

			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		num_radio++;
		new_data = (uint8_t *)realloc(radiolist, 6 * num_radio * sizeof(uint8_t));
		if (!new_data) {
			if (radiolist)
				free(radiolist);

			return UBUS_STATUS_UNKNOWN_ERROR;
		} else
			radiolist = new_data;

		memcpy(&radiolist[(num_radio-1)*6], bssid, 6);
	}

	if (num_radio == 0)
		return UBUS_STATUS_UNKNOWN_ERROR;

	/* fetch BSS list */
	blobmsg_for_each_attr(attr, tb[AP_POLICY_CONFIG_BSS], rem) {
		uint8_t bssid[6] = {0};

		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
			continue;

		memset(bss, 0, sizeof(bss));
		strncpy(bss, blobmsg_data(attr), sizeof(bss)-1);
		if (!hwaddr_aton(bss, bssid)) {
			fprintf(stderr, "Agent policy config: provide bssid " \
					"address in format 11:22:33...\n");
			goto fail_parsing;
		}

		num_bss++;
		new_data = (uint8_t *)realloc(bsslist, 6 * num_bss * sizeof(uint8_t));
		if (!new_data)
			goto fail_parsing;
		else
			bsslist = new_data;

		memcpy(&bsslist[(num_bss-1)*6], bssid, 6);
	}

	cmdu = cntlr_gen_policy_config_req(c, hwaddr, np, num_radio,
			radiolist, num_bss, bsslist);
	if (!cmdu)
		goto fail_parsing;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	if (bsslist)
		free(bsslist);

	free(radiolist);

	return UBUS_STATUS_OK;

fail_parsing:
	if (bsslist)
		free(bsslist);

	free(radiolist);

	return UBUS_STATUS_UNKNOWN_ERROR;
}

static int cntlr_scan(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	trace("|%s:%d| Parsing the message\n", __func__, __LINE__);

	struct blob_attr *tb[__SCAN_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char mac_str[18] = {0};
	uint8_t agent_mac[6] = {0};
	uint8_t num_radios; /* number of radios */
	uint8_t num_ch_arrays = 0, num_opclass = 0;
	int rem, rem1, i, j, k;
	struct blob_attr *attr, *cur;
	struct scan_req_data scan_req_data = {};
	uint8_t classid = 0;
	int num_channel;
	int ret = UBUS_STATUS_OK;

	blobmsg_parse(scan_policy_params, __SCAN_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[SCAN_POLICY_AGENT]) {
		dbg("Must provide agent mac address\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[SCAN_POLICY_RADIO]) {
		dbg("Must provide radio mac address\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[SCAN_POLICY_CHANNEL] && !tb[SCAN_POLICY_CLASSID]) {
		dbg("Must provide channel list or opclass id for each radio\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(mac_str, blobmsg_data(tb[SCAN_POLICY_AGENT]), sizeof(mac_str) - 1);

	if (!hwaddr_aton(mac_str, agent_mac)) {
		dbg("failed to hwaddr cmdu origin\n");
		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	if (tb[SCAN_POLICY_FRESH_SCAN])
		scan_req_data.is_fresh_scan = blobmsg_get_bool(tb[SCAN_POLICY_FRESH_SCAN]);
	else
		/* always request for a fresh scan if not specified explicitly */
		scan_req_data.is_fresh_scan = true;

	dbg("|%s:%d| is_fresh_scan:%d\n",
	    __func__, __LINE__, scan_req_data.is_fresh_scan ? 1 : 0);

	if (tb[SCAN_POLICY_CHANNEL])
		num_ch_arrays = blobmsg_check_array(tb[SCAN_POLICY_CHANNEL], BLOBMSG_TYPE_ARRAY);

	if (tb[SCAN_POLICY_CLASSID])
		num_opclass = blobmsg_check_array(tb[SCAN_POLICY_CLASSID], BLOBMSG_TYPE_INT32);

	if (!num_ch_arrays && !num_opclass) {
		dbg("Either channel list or opclass id must be provided for each radio\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	num_radios = blobmsg_check_array(tb[SCAN_POLICY_RADIO], BLOBMSG_TYPE_STRING);

	if (num_radios > SCAN_REQ_MAX_NUM_RADIO) {
		dbg("Number of radios exceeds maximum of %d\n",
		    SCAN_REQ_MAX_NUM_RADIO);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (num_ch_arrays && num_ch_arrays != num_radios) {
		dbg("Number of channel arrays has to be the same as number of radios\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (num_opclass && num_opclass != num_radios) {
		dbg("Number of opclass ids has to be the same as number of radios\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	scan_req_data.num_radio = num_radios;
	for (i = 0; i < num_radios; i++) {
		/* Bottom layer limitation - one opclass per radio */
		scan_req_data.radios[i].num_opclass = 1;
	}

	i = 0;
	rem = 0;
	rem1 = 0;

	/* Current usage:
	 * ubus call map.controller scan '{"agent":"46:d4:37:6a:f4:c0",
	 * "radio":["44:d4:37:6a:f4:ce"], "channel":[[1]], "opclass":[81], "fresh_scan":TRUE}'
	 */

	/* Radio */
	blobmsg_for_each_attr(attr, tb[SCAN_POLICY_RADIO], rem) {
		if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING) {
			dbg("|%s:%d| Radios have to be string.\n", __func__, __LINE__);
			continue;
		}

		strncpy(mac_str, blobmsg_data(attr), 17);
		if (!hwaddr_aton(mac_str, scan_req_data.radios[i].radio_mac)) {
			dbg("|%s:%d| Failed to parse radio MAC.\n", __func__, __LINE__);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		i++;
	}

	/* Input is an array of channels (attr - current channel array) */
	k = 0;
	blobmsg_for_each_attr(attr, tb[SCAN_POLICY_CHANNEL], rem) {

		num_channel = blobmsg_check_array(attr, BLOBMSG_TYPE_INT32);
		if (num_channel < 0 || num_channel > SCAN_REQ_MAX_NUM_CHAN) {
			dbg("|%s:%d| Channel list invalid.\n", __func__, __LINE__);
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		scan_req_data.radios[k].opclasses[0].num_channel = num_channel;

		dbg("|%s:%d| Radio: " MACFMT " | scan request, num_channel = %d\n",
		    __func__, __LINE__,
		    MAC2STR(scan_req_data.radios[k].radio_mac), num_channel);

		/* Channels (cur - current channel) */
		j = 0;
		classid = 0;
		blobmsg_for_each_attr(cur, attr, rem1) {
			uint8_t ch = (uint8_t) blobmsg_get_u32(cur);

			/* Get opclass id (once) if not provided explicitly */
			if (!classid && !num_opclass)  { // cppcheck-suppress knownConditionTrueFalse
				struct netif_radio *r;

				r = find_radio_by_mac(c, scan_req_data.radios[k].radio_mac);
				if (!r) {
					dbg("|%s:%d| Could not find netif radio: " MACFMT "\n",
					    __func__, __LINE__,
					    MAC2STR(scan_req_data.radios[k].radio_mac));
					return UBUS_STATUS_UNKNOWN_ERROR;
				}

				classid = cntlr_get_classid_ht20(r->radio_el, ch);
				/* one classid per radio */
				scan_req_data.radios[k].opclasses[0].classid = classid;
			}

			scan_req_data.radios[k].opclasses[0].channels[j] = ch;
			j++;
		}
		k++;
	}

	if (tb[SCAN_POLICY_CHANNEL] && k != num_radios) {
		dbg("|%s:%d| number of elements in radio & channel arrays differ.\n",
		    __func__, __LINE__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	/* Opclasses (cur - current opclass id) */
	k = 0;
	blobmsg_for_each_attr(cur, tb[SCAN_POLICY_CLASSID], rem1) {

		classid = (uint8_t) blobmsg_get_u32(cur);
		/* classid provided explicitly - override the HT20 one if set */
		scan_req_data.radios[k].opclasses[0].classid = classid;

		dbg("|%s:%d| Radio: " MACFMT " | scan request's class id = %d\n",
		    __func__, __LINE__,
		    MAC2STR(scan_req_data.radios[k].radio_mac), classid);

		k++;
	}

	if (tb[SCAN_POLICY_CLASSID] && k != num_radios) {
		dbg("|%s:%d| number of elements in radio & opclass arrays differ.\n",
		    __func__, __LINE__);
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	trace("%s: Sending channel scan request to the agent " MACFMT ".\n",
	      __func__, MAC2STR(agent_mac));

	ret = cntlr_send_channel_scan_request(c, agent_mac, &scan_req_data);

	return ret;
}

static int cntlr_scan_results(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_buf bb;
	struct node *n;
	void *b;
	struct blob_attr *tb[__SCAN_RESULTS_MAX];
	int num_radio_queried = 0;
	uint8_t radio_ids[MAX_NUM_RADIO][6] = {};

	blobmsg_parse(scan_results_params, __SCAN_RESULTS_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[SCAN_RESULTS_RADIO]) {
		int rem;
		struct blob_attr *attr;
		char mac_str[18] = {0};

		if (!blobmsg_check_array(tb[SCAN_RESULTS_RADIO], BLOBMSG_TYPE_STRING))
			return UBUS_STATUS_INVALID_ARGUMENT;

		blobmsg_for_each_attr(attr, tb[SCAN_RESULTS_RADIO], rem) {
			if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING) {
				dbg("|%s:%d| Radios have to be string.\n", __func__, __LINE__);
				return UBUS_STATUS_INVALID_ARGUMENT;
			}

			strncpy(mac_str, blobmsg_data(attr), sizeof(mac_str) - 1);
			if (!hwaddr_aton(mac_str, radio_ids[num_radio_queried])) {
				return UBUS_STATUS_UNKNOWN_ERROR;
			}

			num_radio_queried++;
		}
	}

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);

	b = blobmsg_open_array(&bb, "radios");

	list_for_each_entry(n, &c->nodelist, list) {
		struct netif_radio *p = NULL;

		list_for_each_entry(p, &n->radiolist, list) {
			char macaddrstr[18] = {0};
			void *t1, *t2;
			struct wifi_scanres_element *el = NULL;
			int i;

			if (num_radio_queried) {
				bool is_radio_queried = false;

				for (i = 0; i < num_radio_queried; i++) {
					if (!memcmp(p->radio_el->macaddr, radio_ids[i], 6))
						is_radio_queried = true;
				}

				if (!is_radio_queried)
					/* try next radio from radiolist */
					continue;
			}

			hwaddr_ntoa(p->radio_el->macaddr, macaddrstr);

			t1 = blobmsg_open_table(&bb, "");

			blobmsg_add_string(&bb, "radio", macaddrstr);
			blobmsg_add_u32(&bb, "num_scanresult", p->radio_el->num_scanresult);

			t2 = blobmsg_open_array(&bb, "scanlist");

			list_for_each_entry(el, &p->radio_el->scanlist, list) {
				void *tt1, *tt2;
				struct wifi_scanres_opclass_element *op = NULL;

				tt1 = blobmsg_open_table(&bb, "");

				blobmsg_add_string(&bb, "tsp", el->tsp);
				blobmsg_add_u32(&bb, "num_opclass_scanned", el->num_opclass_scanned);

				tt2 = blobmsg_open_array(&bb, "opclasses");

				list_for_each_entry(op, &el->opclass_scanlist, list) {
					void *ttt1, *ttt2;
					struct wifi_scanres_channel_element *ch = NULL;

					ttt1 = blobmsg_open_table(&bb, "");

					blobmsg_add_u32(&bb, "opclass", op->opclass);

					ttt2 = blobmsg_open_array(&bb, "channels");

					list_for_each_entry(ch, &op->channel_scanlist, list) {
						void *tttt1, *tttt2;
						struct wifi_scanres_neighbor_element *nbr = NULL;
						char bssstr[18] = {0};

						tttt1 = blobmsg_open_table(&bb, "");

						blobmsg_add_string(&bb, "tsp", ch->tsp);
						blobmsg_add_u32(&bb, "channel", ch->channel);
						blobmsg_add_u32(&bb, "utilization", ch->utilization);
						blobmsg_add_u32(&bb, "anpi", ch->anpi);
						blobmsg_add_u32(&bb, "num_neighbors", ch->num_neighbors);

						tttt2 = blobmsg_open_array(&bb, "nbrlist");

						list_for_each_entry(nbr, &ch->nbrlist, list) {
							void *ttttt;

							if (!ch->num_neighbors)
								break;

							ttttt = blobmsg_open_table(&bb, "");

							hwaddr_ntoa(nbr->bssid, bssstr);
							blobmsg_add_string(&bb, "bssid", bssstr);
							blobmsg_add_string(&bb, "ssid", nbr->ssid);
							blobmsg_add_u32(&bb, "rssi", nbr->rssi);
							blobmsg_add_u32(&bb, "bw", nbr->bw);
							blobmsg_add_u32(&bb, "utilization", nbr->utilization);
							blobmsg_add_u32(&bb, "num_stations", nbr->num_stations);

							blobmsg_close_table(&bb, ttttt);
						}
						blobmsg_close_table(&bb, tttt2);
						blobmsg_close_table(&bb, tttt1);
					}
					blobmsg_close_table(&bb, ttt2);
					blobmsg_close_table(&bb, ttt1);
				}
				blobmsg_close_table(&bb, tt2);
				blobmsg_close_table(&bb, tt1);
			}
			blobmsg_close_array(&bb, t2);
			blobmsg_close_table(&bb, t1);
		}

	}
	blobmsg_close_array(&bb, b);

	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

static int cntlr_sta_metric_query(struct ubus_context *ctx,
		struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *msg)
{
	struct cmdu_buff *cmdu;
	char mac_str[18];
	uint8_t agent_mac[6] = { 0 };
	uint8_t sta[6] = { 0 };
	struct blob_attr *tb[__STA_METRIC_QUERY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);

	blobmsg_parse(sta_metric_query_params, __STA_METRIC_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[STA_METRIC_QUERY_AGENT] || !tb[STA_METRIC_QUERY_STA]) {
		fprintf(stderr, "STA link metric query: provide Agent and STA " \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(mac_str, 0, sizeof(mac_str));
	strncpy(mac_str, blobmsg_data(tb[STA_METRIC_QUERY_AGENT]),
			sizeof(mac_str) - 1);
	if (!hwaddr_aton(mac_str, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	memset(mac_str, 0, sizeof(mac_str));
	strncpy(mac_str, blobmsg_data(tb[STA_METRIC_QUERY_STA]),
			sizeof(mac_str) - 1);
	if (!hwaddr_aton(mac_str, sta))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = cntlr_gen_sta_metric_query(c, agent_mac, sta);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;
}

static int cntlr_unassoc_sta_lm_query(struct ubus_context *ctx,
		struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *msg)
{
	struct cmdu_buff *cmdu;
	char mac_str[18];
	uint8_t agent_mac[6] = { 0 };
	struct blob_attr *tb[__UNASSOC_STA_LM_QUERY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	uint8_t opclass = 0;
	int num_metrics = 0;
	struct unassoc_sta_metric *metrics = NULL;
	int ret = UBUS_STATUS_OK;

	blobmsg_parse(unassoc_sta_lm_query_params, __UNASSOC_STA_LM_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[UNASSOC_STA_LM_QUERY_AGENT]) {
		fprintf(stderr, "Unassociated STA link metric query: provide Agent" \
				"address in format aa:bb:cc:dd:ee:ff\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(mac_str, 0, sizeof(mac_str));
	strncpy(mac_str, blobmsg_data(tb[UNASSOC_STA_LM_QUERY_AGENT]),
			sizeof(mac_str) - 1);
	if (!hwaddr_aton(mac_str, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[UNASSOC_STA_LM_QUERY_OPCLASS])
		opclass = (int) blobmsg_get_u32(
				tb[UNASSOC_STA_LM_QUERY_OPCLASS]);

	if (!opclass) {
		fprintf(stderr, "unassoc_sta_lm_query: missing opclass\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	/* Example ubus call:
	 * ubus call map.controller unassoc_sta_lm_query '{"agent":
	 * "44:d4:37:42:47:b9", "opclass":81, "metrics":
	 * [{"channel":11, "stamacs": ["44:d4:37:42:3a:c6", "44:d4:37:42:47:be"]}]}'
	 *
	 * ubus call map.controller unassoc_sta_lm_query '{"agent":
	 * "44:d4:37:42:47:b9", "opclass":128,
	 * "metrics":[{"channel":36,"stamacs: ["e0:d4:e8:79:c4:ef"]}]}'
	 */

	if (tb[UNASSOC_STA_LM_QUERY_METRICS]) {
		struct blob_attr *cur;
		static const struct blobmsg_policy supp_attrs[2] = {
				[0] = { .name = "channel",
						.type = BLOBMSG_TYPE_INT32 },
				[1] = { .name = "stamacs",
						.type = BLOBMSG_TYPE_ARRAY },
		};
		int rem, i = 0;

		num_metrics = blobmsg_check_array(tb[UNASSOC_STA_LM_QUERY_METRICS],
				BLOBMSG_TYPE_TABLE);
		if (!num_metrics) {
			fprintf(stderr, "unassoc_sta_lm_query: missing metrics\n");
			return UBUS_STATUS_INVALID_ARGUMENT;
		}

		/* TODO: consider dynamic allocation for number of STAs on the list */
		metrics = calloc(num_metrics, sizeof(struct unassoc_sta_metric));
		if (!metrics) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(cur, tb[UNASSOC_STA_LM_QUERY_METRICS], rem) {
			int remm, j = 0;
			struct blob_attr *data[2], *attr;
			char mac[18];

			blobmsg_parse(supp_attrs, 2, data, blobmsg_data(cur),
					blobmsg_data_len(cur));

			if (!data[0] || !data[1])
				continue;

			metrics[i].channel = (uint8_t) blobmsg_get_u32(data[0]);
			metrics[i].num_sta = blobmsg_check_array(
					data[1], BLOBMSG_TYPE_STRING);

			if (!metrics[i].channel) {
				fprintf(stderr, "unassoc_sta_lm_query: missing channel \
						for metrics [%d]\n", i);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			if (!metrics[i].num_sta) {
				fprintf(stderr, "unassoc_sta_lm_query: no stations for \
						channel %d\n", metrics[i].channel);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			if (metrics[i].num_sta > MAX_UNASSOC_STAMACS) {
				fprintf(stderr, "unassoc_sta_lm_query: max 10 stations \
						allowed per channel!\n");
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			/* Iterate through all metrics of given channel */
			blobmsg_for_each_attr(attr, data[1], remm) {
				if (blobmsg_type(attr) != BLOBMSG_TYPE_STRING)
					continue;

				/* STA list */
				strncpy(mac, blobmsg_get_string(attr), sizeof(mac) - 1);
				hwaddr_aton(mac, metrics[i].sta[j].macaddr);

				j++;
			}

			if (metrics[i].num_sta != j) {
				dbg("%s(): invalid metric [%d]!\n", __func__, i);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			i++;
		}

		if (num_metrics != i) {
			dbg("%s(): invalid metrics!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	cmdu = cntlr_gen_unassoc_sta_metric_query(c, agent_mac,
				opclass, num_metrics, metrics);
	if (!cmdu) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

out:
	if (metrics)
		free(metrics);

	return ret;
}

int cntlr_bcn_metrics_query(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__BCN_METRICS_QUERY_MAX];
	char agent[18] = {0};
	char sta[18] = {0};
	char bssid[18] = {0};
	uint8_t agent_mac[6] = {0};
	uint8_t sta_mac[6] = {0};
	uint8_t bssid_mac[6] = {0};
	uint8_t opclass = 0;
	uint8_t channel = 0;
	uint8_t reporting_detail = 0;
	char ssid[33] = {0};
	uint8_t num_report = 0;
	struct sta_channel_report *reports = NULL;
	uint8_t num_element = 0;
	uint8_t *element = NULL;
	int ret = UBUS_STATUS_OK;
	struct cmdu_buff *cmdu = NULL;

	trace("%s:--->\n", __func__);

	blobmsg_parse(bcn_metrics_query_params, __BCN_METRICS_QUERY_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (!tb[BCN_METRICS_AGENT] || !tb[BCN_METRICS_STA]) {
		fprintf(stderr, "Beacon metrics query:" \
				" provide agent & STA" \
				" in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(agent, blobmsg_data(tb[BCN_METRICS_AGENT]),
			sizeof(agent) - 1);
	strncpy(sta, blobmsg_data(tb[BCN_METRICS_STA]),
			sizeof(sta) - 1);

	if (tb[BCN_METRICS_BSSID])
		strncpy(bssid, blobmsg_data(tb[BCN_METRICS_BSSID]),
				sizeof(bssid) - 1);
	else
		strcpy(bssid, "ff:ff:ff:ff:ff:ff");

	if (!hwaddr_aton(agent, agent_mac)
			|| !hwaddr_aton(sta, sta_mac)
			|| !hwaddr_aton(bssid, bssid_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	if (tb[BCN_METRICS_OPCLASS])
		opclass = (int) blobmsg_get_u32(
				tb[BCN_METRICS_OPCLASS]);

	if (tb[BCN_METRICS_CHANNEL])
		channel = (int) blobmsg_get_u32(
				tb[BCN_METRICS_CHANNEL]);

	if (tb[BCN_METRICS_REPORTING_DETAIL])
		reporting_detail = (int) blobmsg_get_u32(
				tb[BCN_METRICS_REPORTING_DETAIL]);

	if (tb[BCN_METRICS_SSID])
		strncpy(ssid, blobmsg_data(tb[BCN_METRICS_SSID]),
				sizeof(ssid) - 1);

	/* Example ubus call:
	 * ubus call map.controller bcn_metrics_query '{"agent":
	 * "44:d4:37:42:47:b9", "sta":"44:d4:37:4d:84:83",
	 * "bssid":"44:d4:37:42:47:bf", "ssid":"MAP-$BASEMAC-5GHz",
	 * "channel_report":[{"opclass":81,"channels": [1, 6, 13]},
	 * {"opclass":82, "channels": [1, 6, 13]}],
	 * "reporting_detail":1, "request_element": [7, 33]}'
	 */

	if (tb[BCN_METRICS_CHAN_REPORT]) {
		struct blob_attr *cur;
		static const struct blobmsg_policy supp_attrs[2] = {
				[0] = { .name = "opclass",
						.type = BLOBMSG_TYPE_INT32 },
				[1] = { .name = "channels",
						.type = BLOBMSG_TYPE_ARRAY },
		};
		int rem, i = 0;

		num_report = blobmsg_check_array(tb[BCN_METRICS_CHAN_REPORT],
				BLOBMSG_TYPE_TABLE);

		reports = calloc(num_report, sizeof(struct sta_channel_report));
		if (!reports) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(cur, tb[BCN_METRICS_CHAN_REPORT], rem) {
			int remm, j = 0;
			struct blob_attr *data[2], *attr;

			blobmsg_parse(supp_attrs, 2, data, blobmsg_data(cur),
					blobmsg_data_len(cur));

			if (!data[0] || !data[1])
				continue;

			reports[i].opclass = (uint8_t) blobmsg_get_u32(data[0]);
			reports[i].num_channel = blobmsg_check_array(
					data[1], BLOBMSG_TYPE_INT32);

			// Iterate through all channels of the opclass
			blobmsg_for_each_attr(attr, data[1], remm) {
				if (blobmsg_type(attr) != BLOBMSG_TYPE_INT32)
					continue;

				/* Channel List */
				reports[i].channel[j++]
					= (uint8_t) blobmsg_get_u32(attr);
			}

			if (reports[i].num_channel != j) {
				dbg("%s(): invalid channel!\n", __func__);
				ret = UBUS_STATUS_INVALID_ARGUMENT;
				goto out;
			}

			i++;
		}

		if (num_report != i) {
			dbg("%s(): invalid report!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	/* TODO: consider overriding reporting_detail */
	if (tb[BCN_METRICS_ELEMENT_IDS] && reporting_detail == 1) {
		struct blob_attr *attr_id;
		int rem_id, k = 0;

		num_element = blobmsg_check_array(
				tb[BCN_METRICS_ELEMENT_IDS],
				BLOBMSG_TYPE_INT32);

		element = calloc(num_element, sizeof(uint8_t));
		if (!element) {
			ret = UBUS_STATUS_UNKNOWN_ERROR;
			goto out;
		}

		blobmsg_for_each_attr(attr_id,
				tb[BCN_METRICS_ELEMENT_IDS], rem_id) {
			if (blobmsg_type(attr_id) != BLOBMSG_TYPE_INT32)
				continue;
			element[k] = (uint8_t) blobmsg_get_u32(attr_id);
			k++;
		}

		if (k != num_element) {
			dbg("%s(): invalid element ID!\n", __func__);
			ret = UBUS_STATUS_INVALID_ARGUMENT;
			goto out;
		}
	}

	cmdu = cntlr_gen_beacon_metrics_query(c, agent_mac,
				sta_mac, opclass, channel, bssid_mac,
				reporting_detail, ssid, num_report, reports,
				num_element, element);

	if (!cmdu) {
		ret = UBUS_STATUS_UNKNOWN_ERROR;
		goto out;
	}

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

out:
	if (element)
		free(element);
	if (reports)
		free(reports);

	return ret;
}

int cntlr_bcn_metrics_resp(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj);
	struct blob_attr *tb[__BCN_METRICS_RESP_MAX];
	struct blob_buf bb = {0};
	struct sta *s = NULL;
	char sta[18] = {0};
	uint8_t sta_mac[6] = {0};
	void *a;

	trace("%s:--->\n", __func__);

	blobmsg_parse(bcn_metrics_resp_params, __BCN_METRICS_RESP_MAX,
			tb, blob_data(msg), blob_len(msg));

	if (tb[BCN_METRICS_RESP_STA]) {
		strncpy(sta, blobmsg_data(tb[BCN_METRICS_RESP_STA]),
				sizeof(sta) - 1);

		if (!hwaddr_aton(sta, sta_mac)) {
			dbg("|%s:%d|Must provide valid STA address!\n",
					__func__, __LINE__);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}
	}

	/* Example ubus call:
	 * ubus call map.controller bcn_metrics_resp '{
	 * "sta":"44:d4:37:4d:84:83"}'
	 */

	blob_buf_init(&bb, 0);

	a = blobmsg_open_array(&bb, "stations");
	list_for_each_entry(s, &c->stalist, list) {
		void *ttt;
		char stastr[18] = {0};

		if (!hwaddr_is_zero(sta_mac) &&
				memcmp(s->de_sta->macaddr, sta_mac, 6))
			continue;

		hwaddr_ntoa(s->de_sta->macaddr, stastr);

		ttt = blobmsg_open_table(&bb, "");

		blobmsg_add_string(&bb, "macaddr", stastr);

		add_array_meas_reportlist(&bb, s);

		blobmsg_close_table(&bb, ttt);
	}

	blobmsg_close_array(&bb, a);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

static int cntlr_bk_caps(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	trace("%s:--->\n", __func__);
	struct blob_attr *tb[__BK_CAPS_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent[18] = { 0 };
	uint8_t agent_mac[6] = { 0 };
	struct cmdu_buff *cmdu_data;

	blobmsg_parse(bk_caps_policy_params, __BK_CAPS_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));

	// are the ubus method parameter empty?
	if (!tb[BK_CAPS_POLICY_AGENT]) {
		dbg("Must provide agent mac address\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(agent, 0, sizeof(agent));
	strncpy(agent, blobmsg_data(tb[STA_METRIC_QUERY_AGENT]),
			sizeof(agent) - 1);
	if (!hwaddr_aton(agent, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu_data = cntlr_gen_bk_caps_query(c, agent_mac);
	if (!cmdu_data)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu_data);
	cmdu_free(cmdu_data);

	return UBUS_STATUS_OK;
}

static int cntlr_topology_query(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	trace("%s:--->\n", __func__);
	struct blob_attr *tb[__TOPOLOGY_QUERY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);
	char agent[18] = { 0 };
	uint8_t agent_mac[6] = { 0 };
	struct cmdu_buff *cmdu_data;

	blobmsg_parse(topology_query_params, __TOPOLOGY_QUERY_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (tb[TOPOLOGY_QUERY_AGENT]) {
		strncpy(agent, blobmsg_data(tb[TOPOLOGY_QUERY_AGENT]),
			sizeof(agent) - 1);
	} else {
		strncpy(agent, MULTICAST_ADDR_STR, 18);
	}
	if (!hwaddr_aton(agent, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu_data = cntlr_gen_topology_query(c, agent_mac);
	if (!cmdu_data)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu_data);
	cmdu_free(cmdu_data);

	return UBUS_STATUS_OK;
}

/* i.e.
 * ubus call map.controller cac_req '{"agent":"96:d2:de:a8:a3:54","radiolist":
 * [{"radio":"11:22:11:22:11:22","opclass":2,"channel":11,"cac_method":0,"cac_action":0},
 * {"radio":"aa:bb:bb:cc:dd:ee","opclass":4,"channel":13,"cac_method":1,"cac_action":1}]}'
 *
 * TODO:
 * need to extend netif_radio to store cac info i.e. cac state
 * need to store cac capabilties to make sure cac should not be outside of agent's recently cac capabilities
 */
static int cntlr_cac_req(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	trace("%s:--->\n", __func__);

	uint8_t agent[6] = {0};
	int rem, num_data = 0;
	char mac[18] = {0};
	void *tmp = NULL;
	struct cmdu_buff *cmdu;
	struct blob_attr *cur;
	struct cac_data *cac_data = NULL;
	struct blob_attr *tb[__CAC_TERM_MAX];
	struct controller *c = container_of(obj, struct controller, obj);

	blobmsg_parse(cac_term_params, __CAC_TERM_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[CAC_TERM_AGENT] || !tb[CAC_TERM_RADIOLIST]) {
		dbg("required argument missing.!!\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(mac, blobmsg_data(tb[CAC_TERM_AGENT]), sizeof(mac) - 1);
	if (!hwaddr_aton(mac, agent))
		return UBUS_STATUS_UNKNOWN_ERROR;

	blobmsg_for_each_attr(cur, tb[CAC_TERM_RADIOLIST], rem) {
		uint8_t radio_id[6] = {0};
		int idx = 0;
		uint8_t cac_method, cac_action;
		struct blob_attr *tbb[5];
		static const struct blobmsg_policy supp_attrs[] = {
			[0] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "opclass", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
			[3] = { .name = "cac_method", .type = BLOBMSG_TYPE_INT32 },
			[4] = { .name = "cac_action", .type = BLOBMSG_TYPE_INT32 },
		};

		blobmsg_parse(supp_attrs, 5, tbb,
				blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tbb[0] || !tbb[1] || !tbb[2] || !tbb[3] || !tbb[4]) {
			dbg("provide radiolist data in format:\n"
					"[radio:,opclass:,channel:,"
					"cac_method:,cac_action]\n");
			continue;
		}

		memset(mac, 0, sizeof(mac));
		strncpy(mac, blobmsg_data(tbb[0]), sizeof(mac) - 1);
		if (!hwaddr_aton(mac, radio_id)) {
			dbg("provide radio address in format 11:22:33...\n");
			continue;
		}

		cac_method = (uint8_t)blobmsg_get_u32(tbb[3]);
		cac_action = (uint8_t)blobmsg_get_u32(tbb[4]);
		if ((cac_method != 0) && (cac_method != 2)) {
			dbg("unsupported cac method: %d\n", cac_method);
			dbg("supported cac method: '0' or '2'\n");
			continue;
		}

		if ((cac_action != 0) && (cac_action != 1)) {
			dbg("unsupported cac action: %d\n", cac_action);
			dbg("supported cac action: '0' or '1'\n");
			continue;
		}

		tmp = realloc((void *)cac_data, (num_data + 1) * sizeof(*cac_data));
		if (!tmp) {
			dbg("%s:%d -ENOMEM\n", __func__, __LINE__);
			if (cac_data)
				free(cac_data);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		cac_data = tmp;
		idx = num_data;
		memcpy(cac_data[idx].radio, radio_id, 6);
		cac_data[idx].opclass = (uint8_t)blobmsg_get_u32(tbb[1]);
		cac_data[idx].channel = (uint8_t)blobmsg_get_u32(tbb[2]);
		cac_data[idx].cac_method = cac_method;
		cac_data[idx].cac_action = cac_action;
		num_data++;
	}

	if (!cac_data)
		return UBUS_STATUS_UNKNOWN_ERROR;

#if 0
	int x;

	fprintf(stderr, "num_data: %d\n", num_data);
	for (x = 0; x < num_data; x++) {
		fprintf(stderr, "radio: " MACFMT "\t", MAC2STR(cac_data[x].radio));
		fprintf(stderr, "opclass: %d\t", cac_data[x].opclass);
		fprintf(stderr, "channel: %d\t", cac_data[x].channel);
		fprintf(stderr, "cac_method: %d\t", cac_data[x].cac_method);
		fprintf(stderr, "cac_action: %d\n", cac_data[x].cac_action);
	}
#endif

	cmdu = cntlr_gen_cac_req(c, agent, num_data, cac_data);
	if (!cmdu) {
		free(cac_data);

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	free(cac_data);

	return UBUS_STATUS_OK;
}

/* i.e.
 * ubus call map.controller cac_term '{"agent":"96:d2:de:a8:a3:54","radiolist":
 * [{"radio":"11:22:11:22:11:22","opclass":2,"channel":11},
 * {"radio":"aa:bb:bb:cc:dd:ee","opclass":4,"channel":13}]}'
 */
static int cntlr_cac_term(struct ubus_context *ctx, struct ubus_object *obj,
				struct ubus_request_data *req, const char *method,
				struct blob_attr *msg)
{
	trace("%s:--->\n", __func__);

	uint8_t agent[6] = {0};
	int rem, num_data = 0;
	char mac[18] = {0};
	void *tmp = NULL;
	struct cmdu_buff *cmdu;
	struct blob_attr *cur;
	struct cac_data *term_data = NULL;
	struct blob_attr *tb[__CAC_TERM_MAX];
	struct controller *c = container_of(obj, struct controller, obj);

	blobmsg_parse(cac_term_params, __CAC_TERM_MAX, tb,
			blob_data(msg), blob_len(msg));

	if (!tb[CAC_TERM_AGENT] || !tb[CAC_TERM_RADIOLIST]) {
		dbg("required argument missing.!!\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	strncpy(mac, blobmsg_data(tb[CAC_TERM_AGENT]), sizeof(mac) - 1);
	if (!hwaddr_aton(mac, agent))
		return UBUS_STATUS_UNKNOWN_ERROR;

	blobmsg_for_each_attr(cur, tb[CAC_TERM_RADIOLIST], rem) {
		uint8_t radio_id[6] = {0};
		int idx = 0;
		struct blob_attr *tbb[3];
		static const struct blobmsg_policy supp_attrs[] = {
			[0] = { .name = "radio", .type = BLOBMSG_TYPE_STRING },
			[1] = { .name = "opclass", .type = BLOBMSG_TYPE_INT32 },
			[2] = { .name = "channel", .type = BLOBMSG_TYPE_INT32 },
		};

		blobmsg_parse(supp_attrs, 3, tbb,
				blobmsg_data(cur), blobmsg_data_len(cur));
		if (!tbb[0] || !tbb[1] || !tbb[2]) {
			dbg("provide radiolist data in format:\n"
					"[radio:,opclass:,channel:]\n");
			continue;
		}

		memset(mac, 0, sizeof(mac));
		strncpy(mac, blobmsg_data(tbb[0]), sizeof(mac) - 1);
		if (!hwaddr_aton(mac, radio_id)) {
			dbg("provide radio address in format 11:22:33...\n");
			continue;
		}

		tmp = realloc(term_data, (num_data + 1) * sizeof(*term_data));
		if (!tmp) {
			dbg("%s:%d -ENOMEM\n", __func__, __LINE__);
			if (term_data)
				free(term_data);
			return UBUS_STATUS_UNKNOWN_ERROR;
		}

		term_data = tmp;
		idx = num_data;
		memcpy(term_data[idx].radio, radio_id, 6);
		term_data[idx].opclass = (uint8_t)blobmsg_get_u32(tbb[1]);
		term_data[idx].channel = (uint8_t)blobmsg_get_u32(tbb[2]);

		/* these fields are not required for cac termination
		 * fill to allign with struct _cac_data
		 */
		term_data[idx].cac_method = 0xff;
		term_data[idx].cac_action = 0xff;
		num_data++;
	}

	if (!term_data)
		return UBUS_STATUS_UNKNOWN_ERROR;

#if 0
	int x;

	fprintf(stderr, "num_data: %d\n", num_data);
	for (x = 0; x < num_data; x++) {
		fprintf(stderr, "radio: " MACFMT "\t", MAC2STR(term_data[x].radio));
		fprintf(stderr, "opclass: %d\t", term_data[x].opclass);
		fprintf(stderr, "channel: %d\t", term_data[x].channel);
		fprintf(stderr, "cac_method: %02x\t", term_data[x].cac_method);
		fprintf(stderr, "cac_action: %02x\n", term_data[x].cac_action);
	}
#endif

	cmdu = cntlr_gen_cac_term(c, agent, num_data, term_data);
	if (!cmdu) {
		free(term_data);

		return UBUS_STATUS_UNKNOWN_ERROR;
	}

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	free(term_data);

	return UBUS_STATUS_OK;
}

void cntlr_notify_event(struct controller *c, void *ev_type, void *ev_data)
{
	struct blob_buf b;

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);
	if (ev_data)
		blobmsg_add_json_from_string(&b, (char *)ev_data);

	ubus_send_event(c->ubus_ctx, (char *)ev_type, b.head);
	blob_buf_free(&b);
}

int cntlr_comb_metrics(struct ubus_context *ctx,
		struct ubus_object *obj, struct ubus_request_data *req,
		const char *method, struct blob_attr *msg)
{
	trace("%s: -->\n", __func__);
	struct cmdu_buff *cmdu;
	char mac_str[18], bssid_str[18];
	uint8_t agent_mac[6] = { 0 };
	uint8_t bssid_mac[6] = { 0 };
	struct blob_attr *tb[__COMB_POLICY_MAX];
	struct controller *c = container_of(obj, struct controller, obj);

	blobmsg_parse(send_combined_metrics_params, __COMB_POLICY_MAX, tb,
			blob_data(msg), blob_len(msg));
	if (!tb[COMB_POLICY_AGENT]) {
		trace("Comb metric query: provide agent" \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	if (!tb[COMB_POLICY_BSSID]) {
		trace("Comb metric query: provide bssid" \
				"address in format 11:22:33...\n");
		return UBUS_STATUS_INVALID_ARGUMENT;
	}

	memset(mac_str, 0, sizeof(mac_str));
	strncpy(mac_str, blobmsg_data(tb[COMB_POLICY_AGENT]),
			sizeof(mac_str) - 1);
	if (!hwaddr_aton(mac_str, agent_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	memset(bssid_str, 0, sizeof(bssid_str));
	strncpy(bssid_str, blobmsg_data(tb[COMB_POLICY_BSSID]),
			sizeof(bssid_str) - 1);
	if (!hwaddr_aton(bssid_str, bssid_mac))
		return UBUS_STATUS_UNKNOWN_ERROR;

	cmdu = cntlr_gen_comb_infra_metrics_query(c, agent_mac, bssid_mac);
	if (!cmdu)
		return UBUS_STATUS_UNKNOWN_ERROR;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return UBUS_STATUS_OK;
}

int cntlr_publish_object(struct controller *c, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[] = {
		UBUS_METHOD_NOARG("status", cntlr_status),
		UBUS_METHOD_NOARG("status_full", cntlr_status_full),
		UBUS_METHOD_NOARG("timers", cntlr_timers),
		UBUS_METHOD("steer_summary", cntlr_steer_summary,
				steer_summary_params),
		UBUS_METHOD("steer_history", cntlr_steer_history,
				steer_history_params),
		UBUS_METHOD("ap_caps", cntlr_ap_caps,
				ap_caps_policy_params),
		UBUS_METHOD("sta_caps", cntlr_sta_caps,
				sta_caps_policy_params),
		UBUS_METHOD("channel_pref", cntlr_channel_pref,
				channel_pref_policy_params),
		UBUS_METHOD("channel_recalc", cntlr_channel_recalc,
				channel_recalc_policy_params),
		UBUS_METHOD("channel_cleanup", cntlr_channel_cleanup,
				channel_cleanup_policy_params),
		UBUS_METHOD("bk_steer", cntlr_bk_steer, bk_steer_policy_params),
		UBUS_METHOD("agent_policy", cntlr_ap_policy_config,
				ap_policy_config_params),
		UBUS_METHOD("channel_select", cntlr_channel_select,
				channel_select_policy_params),
		UBUS_METHOD("reconfig_ap", cntlr_reconfig_ap,
				reconfig_policy_params),
		UBUS_METHOD("steer", cntlr_client_steering,
				client_steering_policy_params),
		UBUS_METHOD("client_assoc_cntlr", client_assoc_cntlr,
				client_assoc_cntrl_policy_config_params),
		UBUS_METHOD("ap_metric_query", cntlr_ap_metric_query,
				ap_metric_query_params),
		UBUS_METHOD("scan", cntlr_scan, scan_policy_params),
		UBUS_METHOD("scan_results", cntlr_scan_results,
				scan_results_params),
		UBUS_METHOD("sta_metric_query", cntlr_sta_metric_query,
				sta_metric_query_params),
		UBUS_METHOD("unassoc_sta_lm_query", cntlr_unassoc_sta_lm_query,
				unassoc_sta_lm_query_params),
		UBUS_METHOD("bcn_metrics_query", cntlr_bcn_metrics_query,
				bcn_metrics_query_params),
		UBUS_METHOD("bcn_metrics_resp", cntlr_bcn_metrics_resp,
				bcn_metrics_resp_params),
		UBUS_METHOD("bk_caps", cntlr_bk_caps,
				bk_caps_policy_params),
		UBUS_METHOD("topology_query", cntlr_topology_query,
				topology_query_params),
		UBUS_METHOD("cac_req", cntlr_cac_req,
				cac_req_params),
		UBUS_METHOD("cac_term", cntlr_cac_term,
				cac_term_params),
		UBUS_METHOD("higher_layer_data", higher_layer_data,
				higher_layer_data_params),
		UBUS_METHOD("send_combined_metrics", cntlr_comb_metrics,
				send_combined_metrics_params),

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
		UBUS_METHOD("sync", dyn_cntlr_sync_config, cntlr_sync_config_policy),
#endif

#if (EASYMESH_VERSION > 2)
		UBUS_METHOD("dpp_cce_indication", cntlr_dpp_cce_indication,
				dpp_cce_params),
#endif
		/*
		UBUS_METHOD("teardown_ap", cntlr_teardown_ap,
				config_policy_params),
		UBUS_METHOD("config_ap", cntlr_config_ap, config_policy_params),
		*/
	};
	int num_methods = ARRAY_SIZE(m);
	int ret;

	obj = &c->obj;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = objname;
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));
	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(c->ubus_ctx, obj);
	if (ret) {
		err("Failed to add '%s' err = %s\n",
				objname, ubus_strerror(ret));
		free(obj_methods);
		free(obj_type);
		return ret;
	}

	info("Published '%s' object\n", objname);

	return 0;
}

void cntlr_remove_object(struct controller *c)
{
	if (c->ubus_ctx && c->obj.id != OBJECT_INVALID) {
		ubus_remove_object(c->ubus_ctx, &c->obj);
		free(c->obj.type);
		free((void *)c->obj.methods);
	}
}

int ubus_call_object(struct controller *c, uint32_t obj,
		     const char *method,
		     void (*response_cb)(struct ubus_request *, int, struct blob_attr *),
		     void *priv)
{
	struct blob_buf bb = {};
	int ret;

	blob_buf_init(&bb, 0);
	ret = ubus_invoke(c->ubus_ctx, obj, method, bb.head,
				response_cb, priv, 2 * 1000);
	if (ret) {
		err("Failed to get '%s' (ret = %d)\n", method, ret);
		blob_buf_free(&bb);
		return -1;
	}

	blob_buf_free(&bb);
	return 0;
}

static void ieee1905_buildcmdu_lm_cb(struct ubus_request *req, int type,
				  struct blob_attr *msg)
{
	char tlv_str[500] = {0};
	int len, b_len;
	uint16_t msg_type;
	uint8_t *tlv = NULL;
	struct cmdu_buff *cmdu = NULL;
	struct controller *c;
	uint16_t mid = 0;
	struct blob_attr *tb[2];
	static const struct blobmsg_policy cb_attr[2] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_INT32 },
		[1] = { .name = "data", .type = BLOBMSG_TYPE_STRING },
	};

	blobmsg_parse(cb_attr, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[1] || !tb[0])
		return;

	c  = (struct controller *)req->priv;
	msg_type = (uint16_t)blobmsg_get_u32(tb[0]);
	strncpy(tlv_str, blobmsg_data(tb[1]), sizeof(tlv_str) - 1);
	len = strlen(tlv_str);
	b_len = (len/2);
	tlv = (uint8_t *) malloc((b_len) * sizeof(uint8_t));
	if (tlv == NULL) {
		err("No Memory\n");
		return;
	}
	strtob(tlv_str, b_len, tlv);

	if (msg_type == CMDU_TYPE_LINK_METRIC_RESPONSE) {
		struct node *n;

		cmdu = cmdu_alloc_custom(msg_type, &mid, NULL, c->almac, tlv, b_len);
		if (!cmdu)
			goto out;
		n = cntlr_find_node(c, c->almac);
		if (!n)
			goto out;

		handle_link_metrics_response(c, cmdu, n);
		cmdu_free(cmdu);
	}

out:
	free(tlv);
	return;
}

int ieee1905_buildcmdu_linkmetric_resp(struct controller *c, uint16_t msg_type)
{
	struct blob_buf b = { 0 };
	int ret = 0;
	uint32_t id;

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_u32(&b, "type", (uint32_t)msg_type);

	if (!c->ubus_ctx)
		trace("I think that the ubus_ctx is NULL\n");
	if (ubus_lookup_id(c->ubus_ctx, "ieee1905", &id)) {
		dbg("[%s:%d] not present i1905", __func__, __LINE__);
		goto out;
	}

	trace("\t\t%s: %d\n", __func__, __LINE__);

	ret = ubus_invoke(c->ubus_ctx, id, "buildcmdu",
			b.head, ieee1905_buildcmdu_lm_cb, c, 5000);
	if (ret) {
		dbg("[%s:%d] ubus call failed for |i1905 buildcmdu|",
			 __func__, __LINE__);
		goto out;
	}
out:
	blob_buf_free(&b);
	return ret;
}


int cntlr_wait_for_object_timeout(struct controller *c, void *object,
				  uint32_t tmo_msecs, void *res)
{
	uint32_t obj;

	//TODO: handle tmo_msecs
	// -1 = forever

	for (;;) {
		int ret;

		ret = ubus_lookup_id(c->ubus_ctx, (char *)object, &obj);
		if (!ret) {
			*((uint32_t *)res) = obj;
			return 0;
		}

		trace("%s not up yet, sleeping for 2s!\n", (char *)object);
		sleep(1);
	}
}

static void ieee1905_cb_get_almac(struct ubus_request *req, int type,
				  struct blob_attr *msg)
{
	uint8_t *macaddr = (uint8_t *)req->priv;
	struct blob_attr *tb[1];
	static const struct blobmsg_policy ieee_attrs[1] = {
		[0] = { .name = "ieee1905id", .type = BLOBMSG_TYPE_STRING },
	};

	blobmsg_parse(ieee_attrs, 1, tb, blob_data(msg), blob_len(msg));

	if (tb[0]) {
		uint8_t almac[6] = {0};
		char *mac;

		mac = blobmsg_get_string(tb[0]);
		if (hwaddr_aton(mac, almac)) {
			memcpy(macaddr, almac, 6);
			dbg("almac = " MACFMT "\n", MAC2STR(macaddr));
		}
	}
}

int cntlr_get_ieee1905_almac(struct controller *c, uint8_t *almac)
{
	uint32_t obj;
	int ret;

	if (!almac)
		return -1;

	memset(almac, 0, 6);
	ret = cntlr_wait_for_object_timeout(c, "ieee1905", -1, &obj);
	if (!ret)
		ret = ubus_call_object(c, obj, "info", ieee1905_cb_get_almac, almac);

	return ret;
}
