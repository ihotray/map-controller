/*
 * cntlr_cmdu.c - cmdu building function
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <pthread.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <i1905_wsc.h>

#include <uci.h>

#include <easy/easy.h>

#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "config.h"
#include "cntlr.h"
#include "cntlr_tlv.h"
#include "cntlr_cmdu.h"
#include "cntlr_map.h"


struct cmdu_buff *cntlr_gen_ap_autoconfig_renew(struct controller *c,
		uint8_t *dst)
{
	struct cmdu_buff *resp;
	int ret;
	uint16_t mid = 0;

	resp = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_RENEW, &mid);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = cntlr_gen_supp_role(c, resp, IEEE80211_ROLE_REGISTRAR);
	if (ret)
		goto out;

	ret = cntlr_gen_al_mac(c, resp, c->almac);
	if (ret)
		goto out;

	/* Hard-code dummy 5GHz, ignored by agent according to spec */
	ret = cntlr_gen_supported_freq_band(c, resp, IEEE80211_FREQUENCY_BAND_5_GHZ);
	if (ret)
		goto out;

	cmdu_put_eom(resp);
	memcpy(resp->origin, dst, 6);
	return resp;
out:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *cntlr_gen_ap_capability_query(struct controller *c,
		uint8_t *origin)
{
	uint16_t mid = 0;
	struct cmdu_buff *resp;

	/* Allocate the cmdu_data structure */
	resp = cmdu_alloc_simple(CMDU_AP_CAPABILITY_QUERY, &mid);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
}

struct cmdu_buff *cntlr_gen_client_caps_query(struct controller *c,
		uint8_t *origin, uint8_t *sta, uint8_t *bssid)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *req;

	req = cmdu_alloc_simple(CMDU_CLIENT_CAPABILITY_QUERY, &mid);
	if (!req) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(req->origin, origin, 6);

	ret = cntlr_gen_client_info(c, req, sta, bssid);
	if (ret)
		goto error;

	cmdu_put_eom(req);

	return req;
error:
	cmdu_free(req);

	return NULL;
}

struct bcnreq *cntlr_add_bcnreq(struct controller *c, uint8_t *sta_mac,
		uint8_t *agent_mac, int num_req)
{
	struct bcnreq *br;

	dbg("%s: adding STA " MACFMT " to list of active bcn requests\n",
		    __func__, MAC2STR(sta_mac));

	br = cntlr_find_bcnreq(c, sta_mac, agent_mac);
	if (br) {
		timestamp_update(&br->tsp);
		return br;
	}

	br = calloc(1, sizeof(struct bcnreq));
	if (!br)
		return NULL;

	memcpy(br->sta_mac, sta_mac, 6);
	memcpy(br->agent_mac, agent_mac, 6);
	timestamp_update(&br->tsp);
	br->request_num = num_req;

	list_add(&br->list, &c->bcnreqlist);

	return br;
}

struct cmdu_buff *cntlr_gen_beacon_metrics_query(struct controller *c,
		uint8_t *agent_mac, uint8_t *sta_addr, uint8_t opclass,
		uint8_t channel, uint8_t *bssid,
		uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, uint8_t *element)
{
	struct cmdu_buff *resp = NULL;
	int ret = 0;
	uint16_t mid = 0;

	trace("%s:--->\n", __func__);

	if (!agent_mac || !sta_addr || !bssid)
		return NULL;


	resp = cmdu_alloc_simple(CMDU_BEACON_METRICS_QUERY, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* Beacon metrics query TLV */
	ret = cntlr_gen_tlv_beacon_metrics_query(c, resp,
			sta_addr, opclass, channel, bssid,
			reporting_detail, ssid, num_report,
			report, num_element, element);

	if (ret)
		goto fail;

	/* destination agent */
	memcpy(resp->origin, agent_mac, 6);

	cmdu_put_eom(resp);

	cntlr_add_bcnreq(c, sta_addr, agent_mac, num_report);

	return resp;
fail:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *cntlr_gen_backhaul_steer_request(struct controller *c,
		uint8_t *origin, uint8_t *bkhaul, uint8_t *target_bssid,
		uint8_t op_class, uint8_t channel)
{
	int ret;
	struct cmdu_buff *resp;

	resp = cmdu_alloc_frame(1500);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	cmdu_set_type(resp, CMDU_BACKHAUL_STEER_REQUEST);

	ret = cntlr_gen_backhaul_steer_req(c, resp, bkhaul, target_bssid, op_class,
						channel);
	if (ret)
		return NULL;

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
}

struct cmdu_buff *cntlr_gen_1905_link_metric_query(struct controller *c,
		uint8_t *origin)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *req;

	req = cmdu_alloc_simple(CMDU_TYPE_LINK_METRIC_QUERY, &mid);
	if (!req) {
		fprintf(stderr, "%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(req->origin, origin, 6);

	/* 1905 Link Metric Query TLV */
	ret = cntlr_gen_1905_link_metric_tlv(c, req);
	if (ret)
		goto out;

	cmdu_put_eom(req);
	return req;
out:
	cmdu_free(req);
	return NULL;
}

struct cmdu_buff *cntlr_gen_ap_metrics_query(struct controller *c,
		uint8_t *origin, int num_bss, uint8_t *bsslist,
		int num_radio, uint8_t *radiolist)
{
	int i, ret;
	uint16_t mid = 0;
	struct cmdu_buff *req;

	req = cmdu_alloc_simple(CMDU_AP_METRICS_QUERY, &mid);
	if (!req) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(req->origin, origin, 6);

	/* AP Metric Query TLV */
	ret = cntlr_gen_ap_metric_query(c, req, num_bss, bsslist);
	if (ret)
		goto out;

// #ifdef PROFILE2
	/* AP Radio Identifier TLV */
	for (i = 0; i < num_radio; i++) {
		uint8_t radio_mac[6] = {0};

		memcpy(radio_mac, &radiolist[i * 6], 6);
		ret = cntlr_gen_ap_radio_identifier(c, req, radio_mac);
		if (ret)
			goto out;
	}
// #endif
	cmdu_put_eom(req);
	return req;
out:
	cmdu_free(req);
	return NULL;
}

struct cmdu_buff *cntlr_gen_policy_config_req(struct controller *c,
		uint8_t *agent_id, struct node_policy *found,
		int num_radio, uint8_t *radiolist,
		int num_bss, uint8_t *bsslist)
{
	int i, ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm;

	frm = cmdu_alloc_simple(CMDU_POLICY_CONFIG_REQ, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, agent_id, 6);

	/* Steering Policy TLV */
	ret = cntlr_gen_steering_policy(c, found, frm,
			num_radio, radiolist);
	if (ret)
		goto out;

	/* Metric Reporting Policy TLV */
	ret = cntlr_gen_metric_report_policy(c, found, frm,
			num_radio, radiolist);
	if (ret)
		goto out;

// #ifdef PROFILE2
	if (c->cfg.enable_ts) {
		/* Default 802.1Q setting TLV */
		ret = cntlr_gen_8021q_settings(c, frm);
		if (ret)
			goto out;

		/* Traffic Seperation Policy TLV */
		ret = cntlr_gen_traffic_sep_policy(c, frm);
		if (ret)
			goto out;
	}

	/* Channel Scan Reporting Policy TLV */
	ret = cntlr_gen_ch_scan_rep_policy(c, found, frm);
	if (ret)
		goto out;

	/* Unsuccessful Association Policy TLV */
	ret = cntlr_gen_unsuccess_assoc_policy(c, found, frm);
	if (ret)
		goto out;

	/* Backhaul BSS Configuration TLV */
	for (i = 0; i < num_bss; i++) {
		uint8_t bssid[6] = {0};

		memcpy(bssid, &bsslist[i*6], 6);
		ret = cntlr_gen_backhaul_bss_config(c, found, frm, bssid);
		if (ret)
			goto out;
	}
// #endif
	cmdu_put_eom(frm);

	return frm;
out:
	cmdu_free(frm);

	return NULL;
}

struct cmdu_buff *cntlr_gen_sta_metric_query(struct controller *c,
		uint8_t *origin, uint8_t *sta)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm;

	frm = cmdu_alloc_simple(CMDU_ASSOC_STA_LINK_METRICS_QUERY, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, origin, 6);

	/* STA MAC Address type TLV */
	ret = cntlr_gen_sta_mac(c, frm, sta);
	if (ret)
		goto out;

	cmdu_put_eom(frm);
	return frm;

out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_unassoc_sta_metric_query(struct controller *c,
		uint8_t *origin, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm;
	struct node *n;

	/* A Multi-AP Controller shall not send an Unassociated
	 * STA Link Metrics Query message to a Multi-AP Agent that
	 * does not indicate support for Unassociated STA Link
	 * Metrics in the AP Capability TLV.
	 */
	n = cntlr_find_node(c, origin);
	dbg("%s %d ap_cap = 0x%02x\n", __func__, __LINE__, n->ap_cap);
	if (!(n->ap_cap & (UNASSOC_STA_REPORTING_ONCHAN | UNASSOC_STA_REPORTING_OFFCHAN))) {
		dbg("%s: Unassoc STA metric not supported by " MACFMT "\n",
		    __func__, MAC2STR(origin));
		return NULL;
	}

	frm = cmdu_alloc_simple(CMDU_UNASSOC_STA_LINK_METRIC_QUERY, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(frm->origin, origin, 6);

	/* Unassociated STA link metrics query TLV */
	ret = cntlr_gen_unassociated_sta_link_metrics(c, frm,
				opclass, num_metrics, metrics);
	if (ret)
		goto out;

	cmdu_put_eom(frm);
	return frm;

out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_bk_caps_query(struct controller *c,
		uint8_t *origin)
{
	uint16_t mid = 0;
	struct cmdu_buff *resp;

	/* Allocate the cmdu_data structure */
	resp = cmdu_alloc_frame(3000);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}
	cmdu_set_type(resp, CMDU_BACKHAUL_STA_CAPABILITY_QUERY);
	cmdu_set_mid(resp, mid);

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
}

struct cmdu_buff *cntlr_gen_ap_autoconfig_search(struct controller *c,
		uint8_t profile, uint8_t band)
{
	struct cmdu_buff *frm = NULL;
	int ret = 0;
	uint16_t mid = 0;
	uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};
	uint8_t role;

	frm = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	CMDU_SET_RELAY_MCAST(frm->cdata);

	ret = cntlr_gen_al_mac(c, frm, c->almac);
	if (ret)
		goto out;

	ret = cntlr_gen_searched_role(c, frm, IEEE80211_ROLE_REGISTRAR);
	if (ret)
		goto out;

	ret = cntlr_gen_autoconf_freq_band(c, frm, band);
	if (ret)
		goto out;

	role = (c->state == CNTLR_INIT ? SUPPORTED_SERVICE_MULTIAP_AGENT :
			SUPPORTED_SERVICE_MULTIAP_CONTROLLER);
	ret = cntlr_gen_supp_service(c, frm, role);
	if (ret)
		goto out;

	ret = cnltr_gen_searched_service(c, frm,
			SEARCHED_SERVICE_MULTIAP_CONTROLLER);
	if (ret)
		goto out;

	ret = cntlr_gen_map_profile(c, frm, c->cfg.map_profile);
	if (ret)
		goto out;

#if (EASYMESH_VERSION > 2)
	if (c->cfg.map_profile > MULTIAP_PROFILE_2) {
		ret = cntlr_gen_chirp_value_tlv(c, frm);
		if (ret)
			goto out;
	}
#endif

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);
	return frm;
out:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_ap_autoconfig_response(struct controller *c,
		uint8_t *dest, uint8_t band, uint16_t mid)
{
	struct cmdu_buff *resp;
	int ret;

	resp = cmdu_alloc_simple(CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE, &mid);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = cntlr_gen_supp_role(c, resp, IEEE80211_ROLE_REGISTRAR);
	if (ret)
		goto out;

	ret = cntlr_gen_supported_freq_band(c, resp, band);
	if (ret)
		goto out;

	ret = cntlr_gen_supp_service(c, resp, SUPPORTED_SERVICE_MULTIAP_CONTROLLER);
	if (ret)
		goto out;

	ret = cntlr_gen_map_profile(c, resp, c->cfg.map_profile);
	if (ret)
		goto out;

#if (EASYMESH_VERSION > 2)
	if (c->cfg.map_profile > MULTIAP_PROFILE_2) {
		ret = cntlr_gen_device_1905_layer_security_cap(c, resp);
		if (ret)
			goto out;

		ret = cntlr_gen_chirp_value_tlv(c, resp);
		if (ret)
			goto out;

		ret = cntlr_gen_cntlr_capability(c, resp);
		if (ret)
			goto out;
	}
#endif

	cmdu_put_eom(resp);
	memcpy(resp->origin, dest, 6);
	return resp;
out:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *cntlr_gen_ap_autoconfig_wsc(struct controller *c,
		struct cmdu_buff *rx_cmdu, uint8_t *radio_id, struct tlv *wsc,
		uint16_t mid)
{
	struct iface_credential *cred;
	struct cmdu_buff *resp;
	uint16_t msglen;
	uint8_t *msg;
	uint16_t e_auth = 0;
	uint8_t e_band = 0;
	uint16_t attrlen = 0;
	int ret;
	char macstr[18] = {0}, alidstr[18] = {0}, band[2] = {0};

	resp = cmdu_alloc_frame(6400);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	cmdu_set_type(resp, CMDU_TYPE_AP_AUTOCONFIGURATION_WSC);
	cmdu_set_mid(resp, mid);

	msglen = tlv_length(wsc);
	msg = wsc->data;

	ret = wsc_msg_get_attr(msg, msglen, ATTR_RF_BANDS, &e_band, &attrlen);
	if (ret) {
		trace("Error getting band from wsc msg\n");
		goto out;
	}

	ret = wsc_msg_get_attr(msg, msglen, ATTR_AUTH_TYPE_FLAGS,
			       (uint8_t *) &e_auth, &attrlen);
	if (ret) {
		trace("Error getting auth from wsc msg\n");
		goto out;
	}

	e_auth = buf_get_be16((uint8_t *) &e_auth);

	if (c->cfg.enable_ts) {
		ret = cntlr_gen_8021q_settings(c, resp);
		if (ret)
			goto out;

		ret = cntlr_gen_traffic_sep_policy(c, resp);
		if (ret)
			goto out;
	}

	ret = cntlr_gen_ap_radio_identifier(c, resp, radio_id);
	if (ret)
		goto out;

	list_for_each_entry(cred, &c->cfg.aplist, list) {
		if (cred->band != e_band)
			continue;

		/* Will return non-zero if band did not match OR on failure */
		cntlr_gen_wsc(c, resp, cred, msg, msglen, e_band, e_auth);
	}

	hwaddr_ntoa(radio_id, macstr);
	hwaddr_ntoa(rx_cmdu->origin, alidstr);
	if (e_band == BAND_2)
		strcpy(band, "2");
	if (e_band == BAND_5)
		strcpy(band, "5");
	if (e_band == BAND_6)
		strcpy(band, "6");

	/* only add radio sections for discovered agents */
	if (agent_find_policy(c, rx_cmdu->origin)) {
		cntlr_config_add_node_radio(&c->cfg, alidstr, macstr, band);
		cntlr_resync_config(c, true);
	}

	memcpy(resp->origin, rx_cmdu->origin, 6);
	cmdu_put_eom(resp);
	return resp;
out:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *cntlr_gen_topology_query(struct controller *c,
		uint8_t *origin)
{
	struct cmdu_buff *resp;
	uint16_t mid = 0;
	int ret = 0;

	resp = cmdu_alloc_simple(CMDU_TYPE_TOPOLOGY_QUERY, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = cntlr_gen_map_profile(c, resp, c->cfg.map_profile);
	if (!ret)
		goto error;

	memcpy(resp->origin, origin, 6);
	cmdu_put_eom(resp);
	return resp;
error:
	cmdu_free(resp);
	return NULL;

}

struct cmdu_buff *cntlr_gen_cmdu_1905_ack(struct controller *c,
		struct cmdu_buff *rx_cmdu,
		struct sta_error_response *sta_resp, uint32_t sta_count)
{
	struct cmdu_buff *resp = NULL;
	uint16_t mid = cmdu_get_mid(rx_cmdu);
	int j;

	trace("%s:--->\n", __func__);

	resp = cmdu_alloc_simple(CMDU_1905_ACK, &mid);
	if (!resp) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(resp->origin, rx_cmdu->origin, 6);

	/* Error Code TLV 17.2.36 */
	for (j = 0; j < sta_count; j++) {
		cntlr_gen_tlv_error_code(c, resp, sta_resp[j].sta_mac,
				sta_resp[j].response);
	}

	cmdu_put_eom(resp);
	return resp;
}

struct cmdu_buff *cntlr_gen_channel_scan_request(struct controller *c,
		uint8_t *agent_mac, struct scan_req_data *req_data)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *resp;

	/* Allocate the cmdu_data structure */
	resp = cmdu_alloc_frame(3000);
	if (!resp) {
		trace("%s: -ENOMEM\n", __func__);
		return NULL;
	}
	cmdu_set_type(resp, CMDU_CHANNEL_SCAN_REQUEST);
	cmdu_set_mid(resp, mid);
	ret = cntlr_gen_channel_scan_req(c, resp, req_data);
	if (ret)
		goto error;

	memcpy(resp->origin, agent_mac, 6);
	cmdu_put_eom(resp);

	return resp;
error:
	cmdu_free(resp);
	return NULL;
}

struct cmdu_buff *cntlr_gen_channel_preference_query(
		struct controller *c, uint8_t *agent)
{
	uint16_t mid = 0;
	struct cmdu_buff *req;

	req = cmdu_alloc_simple(CMDU_CHANNEL_PREFERENCE_QUERY, &mid);
	if (!req) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	memcpy(req->origin, agent, 6);
	cmdu_put_eom(req);

	return req;
}

int cntrl_send_channel_preference_query(struct controller *c, uint8_t *agent)
{
	struct cmdu_buff *cmdu;

	cmdu = cntlr_gen_channel_preference_query(c, agent);
	if (!cmdu)
		return -1;
	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int cntrl_send_channel_selection(struct controller *c, uint8_t *agent, uint8_t *radio,
				 uint8_t channel, uint8_t opclass, uint8_t pref)
{
	uint16_t mid = 0;
	struct cmdu_buff *cmdu;
	uint8_t chanlist[1] = {};

	chanlist[0] = channel;

	cmdu = cmdu_alloc_simple(CMDU_CHANNEL_SELECTION_REQ, &mid);
	if (!cmdu)
		return -1;

	memcpy(cmdu->origin, agent, 6);
	if (cntlr_gen_channel_pref(c, cmdu, radio, opclass, ARRAY_SIZE(chanlist), chanlist, pref)) {
		cmdu_free(cmdu);
		return -1;
	}

	cmdu_put_eom(cmdu);
	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
}

struct cmdu_buff* cntlr_gen_cac_req(struct controller *c, uint8_t *agent,
		int num_data, struct cac_data *data)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *req;

	if (!agent || !data)
		return NULL;

	req = cmdu_alloc_simple(CMDU_CAC_REQUEST, &mid);
	if (!req)
		return NULL;

	memcpy(req->origin, agent, 6);

	ret = cntlr_gen_cac_tlv(c, req, MAP_TLV_CAC_REQ,
			num_data, data);
	if (ret) {
		cmdu_free(req);
		return NULL;
	}

	return req;
}

struct cmdu_buff* cntlr_gen_cac_term(struct controller *c, uint8_t *agent,
		int num_data, struct cac_data *data)
{
	uint16_t mid = 0;
	int ret;
	struct cmdu_buff *req;

	if (!agent || !data)
		return NULL;

	req = cmdu_alloc_simple(CMDU_CAC_TERMINATION, &mid);
	if (!req)
		return NULL;

	memcpy(req->origin, agent, 6);

	ret = cntlr_gen_cac_tlv(c, req, MAP_TLV_CAC_TERMINATION,
			num_data, data);
	if (ret) {
		cmdu_free(req);
		return NULL;
	}

	return req;

}

int cntlr_send_channel_scan_request(struct controller *c, uint8_t *agent_mac,
			struct scan_req_data *data)
{
	struct cmdu_buff *cmdu_data = NULL;

	cmdu_data = cntlr_gen_channel_scan_request(c, agent_mac, data);

	if (!cmdu_data)
		return -1;

	send_cmdu(c, cmdu_data);
	cmdu_free(cmdu_data);

	return 0;
}

int cntlr_send_cac_req(struct controller *c, uint8_t *agent,
		       int num_data, struct cac_data *data)
{
	struct cmdu_buff *cmdu;

	cmdu = cntlr_gen_cac_req(c, agent, num_data, data);
	if (!cmdu)
		return -1;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
}

int cntlr_send_cac_term(struct controller *c, uint8_t *agent,
		        int num_data, struct cac_data *data)
{
	struct cmdu_buff *cmdu;

	cmdu = cntlr_gen_cac_term(c, agent, num_data, data);
	if (!cmdu)
		return -1;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return 0;
}

struct cmdu_buff *cntlr_gen_client_assoc_ctrl_request(struct controller *c,
		uint8_t *agent_mac, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist)
{
	struct cmdu_buff *frm;
	uint16_t mid = 0;
	int ret = 0;

	frm = cmdu_alloc_simple(CMDU_CLIENT_ASSOC_CONTROL_REQUEST, &mid);
	if (!frm) {
		trace("%s |%d|: cmdu alloc error\n", __func__, __LINE__);
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* Client ASSOC CONTROL TLV REQUEST 17.2.31 */
	ret = cntlr_gen_tlv_assoc_ctrl_request(c, frm, bssid,
			assoc_cntl_mode, assoc_timeout, sta_nr, stalist);

	if (ret)
		goto error;

	memcpy(frm->origin, agent_mac, 6);
	cmdu_put_eom(frm);
	return frm;

error:
	cmdu_free(frm);
	return NULL;
}

int cntlr_send_client_assoc_ctrl_request(struct controller *c,
		uint8_t *agent_mac, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist, uint16_t *mid)
{
	struct cmdu_buff *cmdu_data = NULL;

	cmdu_data = cntlr_gen_client_assoc_ctrl_request(c, agent_mac,
					bssid, assoc_cntl_mode, assoc_timeout,
					sta_nr, stalist);

	if (!cmdu_data)
		return -1;

	*mid = cmdu_get_mid(cmdu_data);

	send_cmdu(c, cmdu_data);
	cmdu_free(cmdu_data);

	return 0;
}

struct cmdu_buff *cntlr_gen_higher_layer_data(struct controller *c, uint8_t *addr,
					      uint8_t proto, uint8_t *data,
					      int len)
{
	struct cmdu_buff *frm;
	int ret;

	frm = cmdu_alloc_frame(len + 128);
	if (!frm)
		return NULL;

	cmdu_set_type(frm, CMDU_HIGHER_LAYER_DATA);
	memcpy(frm->origin, addr, 6);

	ret = cntlr_gen_tlv_higher_layer_data(c, frm, proto, data, len);
	if (ret)
		goto error;

	cmdu_put_eom(frm);
	return frm;

error:
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_client_steer_request(struct controller *c,
		uint8_t *origin, uint8_t *bssid, uint32_t steer_timeout,
		uint32_t sta_nr, uint8_t stas[][6], uint32_t bssid_nr,
		uint8_t target_bssid[][6], uint32_t request_mode)
{
	struct cmdu_buff *frm;
	uint16_t mid = 0;
	int ret;

	frm = cmdu_alloc_simple(CMDU_CLIENT_STEERING_REQUEST, &mid);
	if (!frm) {
		warn("%s: Failed to generate cmdu for steering sta!\n", __func__);
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	dbg("%s %d sta_id " MACFMT "\n", __func__, __LINE__, MAC2STR(stas[0]));

	ret = cntlr_gen_tlv_steer_request(c, frm,
			MAP_TLV_STEERING_REQUEST, bssid,
			steer_timeout, sta_nr, stas, bssid_nr,
			target_bssid, request_mode);
	if (ret)
		goto error;

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);
	return frm;

error:
	cmdu_free(frm);
	return NULL;
}

int cntlr_send_client_steer_request(struct controller *c,
			uint8_t *agent_mac, uint8_t *bssid,
			uint32_t steer_timeout, uint32_t sta_nr, uint8_t stas[][6],
			uint32_t bssid_nr, uint8_t target_bssid[][6], uint32_t request_mode)
{
	struct cmdu_buff *cmdu_data = NULL;

	trace("%s:--->\n", __func__);

	cmdu_data = cntlr_gen_client_steer_request(c, agent_mac, bssid, steer_timeout,
					sta_nr, stas, bssid_nr, target_bssid, request_mode);

	if (!cmdu_data)
		return -1;

	send_cmdu(c, cmdu_data);
	cmdu_free(cmdu_data);

	return 0;
}

struct cmdu_buff *cntlr_gen_comb_infra_metrics_query(struct controller *c, uint8_t *origin, uint8_t *bssid)
{
	struct cmdu_buff *frm;
	uint16_t mid = 0;
	int ret;

	frm = cmdu_alloc_simple(CMDU_COMBINED_INFRA_METRICS, &mid);
	if (!frm) {
		trace("%s |%d|: cmdu alloc error\n", __func__, __LINE__);
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	ret = cntlr_gen_comb_infra_metrics(c, frm, bssid);
	if (ret)
		goto error;

	memcpy(frm->origin, origin, 6);
	cmdu_put_eom(frm);
	return frm;

error:
	trace("%s |%d|: cmdu gen error\n", __func__, __LINE__);
	cmdu_free(frm);
	return NULL;
}

#if (EASYMESH_VERSION > 2)
struct cmdu_buff *cntlr_gen_direct_encap_dpp(struct controller *c)
{
	struct cmdu_buff *frm;
	uint16_t mid = 0;

	/* TODO: Pass direct_encap_dpp_data parameter */

	frm = cmdu_alloc_simple(CMDU_PROXIED_ENCAP_DPP, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* One DPP Message TLV */
	if (cntlr_gen_dpp_message_tlv(c, frm)) {
		dbg("%s: cntlr_gen_dpp_message_tlv failed.\n", __func__);
		goto out;
	}

	cmdu_put_eom(frm);
	return frm;

out:
	trace("%s |%d|: cmdu gen error\n", __func__, __LINE__);
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_proxied_encap_dpp(struct controller *c)
{
	struct cmdu_buff *frm;
	uint16_t mid = 0;

	/* TODO: Pass proxied_encap_dpp_data parameter */

	frm = cmdu_alloc_simple(CMDU_DIRECT_ENCAP_DPP, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* One 1905 Encap DPP TLV */
	if (cntlr_gen_1905_encap_dpp_tlv(c, frm)) {
		dbg("%s: cntlr_gen_1905_encap_dpp_tlv failed.\n", __func__);
		goto out;
	}

	/* Zero or One Chirp Value TLV */
	if (cntlr_gen_chirp_value_tlv(c, frm)) {
		dbg("%s: cntlr_gen_chirp_value_tlv failed.\n", __func__);
		goto out;
	}

	cmdu_put_eom(frm);
	return frm;

out:
	trace("%s |%d|: cmdu gen error\n", __func__, __LINE__);
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntrl_gen_bss_configuration_response(struct controller *c, struct cmdu_buff *request_cmdu)
{
	struct cmdu_buff *resp_cmdu;
	uint16_t mid = 0;

	resp_cmdu = cmdu_alloc_simple(CMDU_BSS_CONFIG_RESPONSE, &mid);
	if (!resp_cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* One or more BSS Configuration Response TLV */
	if (cntlr_gen_bss_config_response_tlv(c, resp_cmdu)) {
		dbg("%s: cntlr_gen_bss_config_response_tlv failed.\n", __func__);
		goto out;
	}

	if (c->cfg.enable_ts) {
		/* Zero or one Default 802.1Q Settings TLV */
		if (cntlr_gen_8021q_settings(c, resp_cmdu)) {
			dbg("%s: cntlr_gen_8021q_settings failed.\n", __func__);
			goto out;
		}

		/* Zero or one Traffic Separation Policy TLV */
		if (cntlr_gen_traffic_sep_policy(c, resp_cmdu)) {
			dbg("%s: cntlr_gen_traffic_sep_policy failed.\n", __func__);
			goto out;
		}
	}

	cmdu_put_eom(resp_cmdu);
	memcpy(resp_cmdu->origin, request_cmdu->origin, 6);
	return resp_cmdu;

out:
	cmdu_free(resp_cmdu);
	return NULL;
}

struct cmdu_buff *cntlr_gen_dpp_cce_indication(struct controller *c,
		uint8_t *agent, bool cce_advertise)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *frm;

	frm = cmdu_alloc_simple(CMDU_DPP_CCE_INDICATION, &mid);
	if (!frm) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}
	ret = cntlr_gen_dpp_cce_indication_tlv(c, frm, cce_advertise);
	if (ret)
		goto error;


	memcpy(frm->origin, agent, 6);
	cmdu_put_eom(frm);

	return frm;

error:
	trace("%s: cmdu gen error\n", __func__);
	cmdu_free(frm);
	return NULL;
}

struct cmdu_buff *cntlr_gen_agent_list(struct controller *c)
{
	int ret;
	uint16_t mid = 0;
	struct cmdu_buff *cmdu;

	cmdu = cmdu_alloc_simple(CMDU_AGENT_LIST, &mid);
	if (!cmdu) {
		dbg("%s: -ENOMEM\n", __func__);
		return NULL;
	}

	/* 1905 AgentList TLV */
	ret = cntlr_gen_agent_list_tlv(c, cmdu);
	if (ret)
		goto out;

	cmdu_put_eom(cmdu);
	return cmdu;
out:
	cmdu_free(cmdu);
	return NULL;
}

int send_agent_list_to_all_nodes(struct controller *c)
{
	struct cmdu_buff *cmdu;
	struct node *node;
	int ret;

	dbg("%s: --->\n", __func__);

	cmdu = cntlr_gen_agent_list(c);

	if (!cmdu) {
		dbg("cntlr_gen_agent_list failed.\n");
		return -1;
	}

	ret = 0;
	list_for_each_entry(node, &c->nodelist, list) {
		memcpy(cmdu->origin, node->alid, 6);
		if (send_cmdu(c, cmdu) == 0xffff)
			ret = -1;
	}

	cmdu_free(cmdu);

	return ret;
}

#endif /* EASYMESH_VERSION > 2 */
