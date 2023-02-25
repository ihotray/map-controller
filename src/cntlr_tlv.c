/*
 * cntlr_tlv.c - tlv building function
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

#include <easy/easy.h>
#include <i1905_wsc.h>

#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include <uci.h>

#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "cntlr.h"
#include "cntlr_ubus.h"

#include "cntlr_map_debug.h"
#include "cntlr_tlv.h"

/**
 * TODO: move to appropriate utils file
 * Convert wifi_security format to WSC format
 */
uint16_t wifi_sec_to_auth_types(enum wifi_security sec)
{
	uint16_t auth_type = 0;

	if (sec >= BIT(WIFI_SECURITY_WPA)) {
		if (sec == BIT(WIFI_SECURITY_WPA2)) {
			auth_type = WPS_AUTH_WPA;
		} else if (sec == BIT(WIFI_SECURITY_WPA)) {
			auth_type = WPS_AUTH_WPA;
		} else if ((sec & BIT(WIFI_SECURITY_WPA)) && (sec & BIT(WIFI_SECURITY_WPA2))) {
			auth_type |= WPS_AUTH_WPA;
			auth_type |= WPS_AUTH_WPA2;
		}
	} else if (sec >= BIT(WIFI_SECURITY_WPAPSK)) {
		if (sec == BIT(WIFI_SECURITY_WPA3PSK)) {
			auth_type = WPS_AUTH_SAE;
		} else if (sec == BIT(WIFI_SECURITY_WPA3PSK_T)) {
			auth_type = WPS_AUTH_WPA3_T;
		} else if ((sec & BIT(WIFI_SECURITY_WPA3PSK)) && (sec & BIT(WIFI_SECURITY_WPA3PSK_T))) {
			auth_type = WPS_AUTH_WPA3_T;
		} else if (sec == BIT(WIFI_SECURITY_WPA2PSK)) {
			auth_type = WPS_AUTH_WPA2PSK;
		} else if (sec == BIT(WIFI_SECURITY_WPAPSK)) {
			auth_type = WPS_AUTH_WPAPSK;
		} else if ((sec & BIT(WIFI_SECURITY_WPAPSK)) && (sec & BIT(WIFI_SECURITY_WPA2PSK))) {
			auth_type |= WPS_AUTH_WPAPSK;
			auth_type |= WPS_AUTH_WPA2PSK;
		}
	} else if (sec == BIT(WIFI_SECURITY_NONE))
		auth_type = WPS_AUTH_OPEN;
	//TODO: ciphers (if any)

	return auth_type;
}


uint8_t *extract_tlv_by_type(struct cmdu_buff *cmdu, uint8_t tlv_type)
{
	return NULL;
//	uint8_t *tlv;
//	int i;
//
//	for (i = 0; i < cmdu->num_tlvs; i++) {
//		tlv = cmdu->tlvs[i];
//		if (*tlv == tlv_type)
//			return tlv;
//	}
//
//	return NULL;
//
}

int cntlr_gen_8021q_settings(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_default_8021q_settings *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_DEFAULT_8021Q_SETTINGS;
	t->len = sizeof(*data);

	data = (struct tlv_default_8021q_settings *) t->data;
	BUF_PUT_BE16(data->pvid, c->cfg.primary_vid);
	data->pcp = (c->cfg.default_pcp << 5) & PCP_MASK;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_traffic_sep_policy(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_traffic_sep_policy *ts;
	int ret;
	struct iface_credential *cred = NULL;
	uint8_t *ptr;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_TRAFFIC_SEPARATION_POLICY;
	t->len = 1;

	ts = (struct tlv_traffic_sep_policy *) t->data;
	ts->num_ssid = 0;
	ptr = (uint8_t *) ts + 1;

	list_for_each_entry(cred, &c->cfg.aplist, list) {
		uint8_t len;
		int i;
		bool found = false;

		len = strlen((char *)cred->ssid);

		/**
		 * Don't add duplicate SSIDs.
		 * Having one SSID mapping to multiple VLAN IDs is not supported.
		 */
		for (i = 0; i < ts->num_ssid; i++) {
			struct ssid_info *info;
			uint8_t *p = (uint8_t *) ts + 1;
			int j;

			for (j = 0; j < i; j++) {
				p += *p; /* ssid len */
				p++; /* len */
				p += 2; /* vid */
			}

			info = (struct ssid_info *) p;

			if (len != info->len)
				continue;

			if (memcmp(cred->ssid, info->ssid, len))
				continue;

			found = true;
			break;
		}

		/* skip duplicate */
		if (found)
			continue;

		t->len++; /* len */
		*ptr = len;
		ptr++;

		t->len += len; /* ssid */
		memcpy(ptr, cred->ssid, len);
		ptr += len;

		t->len += 2; /* vid */
		buf_put_be16(ptr, cred->vlanid);
		ptr += 2;

		ts->num_ssid++;
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_wsc(struct controller *c, struct cmdu_buff *frm,
		struct iface_credential *iface_cred, uint8_t *msg, uint16_t msglen,
		uint8_t band, uint16_t m1_auth)
{
	struct tlv *t;
	struct wps_credential cred = {0};
	uint8_t *m2;
	uint16_t m2_size;
	uint16_t cred_auth;
	int ret;

#define ATTR_ENABLED (0x4C) /* IOPSYS m2 vendor extension */

	t = cmdu_reserve_tlv(frm, 1000);
	if (!t)
		return -1;

	t->type = TLV_TYPE_WSC;
	cred.band = band;
	memcpy(cred.ssid, (char *)iface_cred->ssid, strlen((char *)iface_cred->ssid));
	cred.ssidlen = strlen((char *)iface_cred->ssid);
	cred.auth_type = wifi_sec_to_auth_types(iface_cred->sec);
	if (cred.auth_type == WPS_AUTH_OPEN)
		cred.enc_type = WPS_ENCR_NONE;
	else /* by default use encryption type AES */
		cred.enc_type = WPS_ENCR_AES; /* TODO: TKIP? */

	memcpy(cred.key, (char *)iface_cred->key, strlen((char *)iface_cred->key));
	cred.keylen = strlen((char *)iface_cred->key);

	/* backhaul BSS */
	cred.mapie |= (iface_cred->multi_ap & 0x01) << 6;
	/* fronthaul BSS */
	cred.mapie |= (iface_cred->multi_ap & 0x02) << 4;
	/* backhaul STA */
	cred.mapie |= (iface_cred->disallow_bsta << 2);
	/* teardown bit */
	cred_auth = wifi_sec_to_auth_types(iface_cred->sec);

	/* if m1 does not support cred auth or cred auth is strictly higher,
	 * reject and teardown
	 */
	if ((cred_auth & m1_auth) != cred_auth) {
		cred.mapie |= 1 << 4;
		warn("|%s:%d| setting teardown bit (m1 auth:%04x "\
		     "creds auth:%04x)\n", __func__, __LINE__,
		     m1_auth, cred_auth);
	}

	strncpy(cred.manufacturer, iface_cred->manufacturer, 64);
	strncpy(cred.model_name, iface_cred->model_name, 32);
	strncpy(cred.device_name, iface_cred->device_name, 32);
	memcpy(cred.model_number, iface_cred->model_number, 32);
	memcpy(cred.serial_number, iface_cred->serial_number, 32);
	memcpy(cred.device_type, iface_cred->device_type, 8);

	ret = wsc_build_m2(msg, msglen, &cred,
			   (struct wsc_vendor_ie *) iface_cred->ven_ies,
			   iface_cred->num_ven_ies, &m2, &m2_size);
	if (ret) {
		dbg("Error building m2!\n");
		return ret;
	}

	t->len = m2_size;

	memcpy(t->data, m2, m2_size);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		free(m2);
		return -1;
	}

	free(m2);
	return 0;
}

int cntlr_gen_ap_radio_identifier(struct controller *c,
		struct cmdu_buff *frm, uint8_t *hwaddr)
{
	struct tlv *t;
	struct tlv_ap_radio_identifier *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_RADIO_IDENTIFIER;
	t->len = 6;

	data = (struct tlv_ap_radio_identifier *) t->data;
	memcpy(data->radio, hwaddr, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_supp_role(struct controller *c, struct cmdu_buff *frm,
		uint8_t role)
{
	struct tlv *t;
	struct tlv_supported_role *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_SUPPORTED_ROLE;
	t->len = 1;

	data = (struct tlv_supported_role *) t->data;
	data->role = role;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		err("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_supp_service(struct controller *c, struct cmdu_buff *frm,
		uint8_t service)
{
	struct tlv *t;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_SUPPORTED_SERVICE;
	t->len = 2;
	t->data[0] = 0x1;
	t->data[1] = service;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_map_profile(struct controller *c, struct cmdu_buff *frm,
		uint8_t profile)
{
	struct tlv *t;
	struct tlv_map_profile *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_MULTIAP_PROFILE;
	t->len = 1;
	data = (struct tlv_map_profile *) t->data;
	data->profile = profile;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_ch_scan_rep_policy( struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm)
{
	int ret;
	struct tlv *t;
	struct tlv_channel_scan_report_policy *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_CHANNEL_SCAN_REPORTING_POLICY;
	t->len = sizeof(*data);
	data = (struct tlv_channel_scan_report_policy *) t->data;

	if (a->report_scan)
		data->report = REPORT_CHANNEL_SCANS;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_al_mac(struct controller *c, struct cmdu_buff *frm,
		uint8_t *hwaddr)
{
	struct tlv *t;
	struct tlv_aladdr *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_AL_MAC_ADDRESS_TYPE;
	t->len = 6;

	dbg("hwaddr " MACFMT "\n", MAC2STR(hwaddr));

	data = (struct tlv_aladdr *) t->data;
	memcpy(data->macaddr, hwaddr, 6);

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_unsuccess_assoc_policy(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm)
{
	int ret;
	struct tlv *t;
	struct tlv_unsuccess_assoc_policy *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_UNSUCCESS_ASSOCIATION_POLICY;
	t->len = sizeof(*data);
	data = (struct tlv_unsuccess_assoc_policy *) t->data;

	if (a->report_sta_assocfails)
		data->report = UNSUCCESSFUL_ASSOC_REPORT;

	BUF_PUT_BE32(data->max_report_rate, a->report_sta_assocfails_rate);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_supported_freq_band(struct controller *c, struct cmdu_buff *frm,
		uint8_t freq_band)
{
	struct tlv *t;
	struct tlv_supported_band *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = TLV_TYPE_SUPPORTED_FREQ_BAND;
	t->len = 1;
	data = (struct tlv_supported_band *) t->data;
	data->band = freq_band;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_backhaul_bss_config(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm,
		const uint8_t *bssid)
{
	int ret;
	struct tlv *t;
	struct tlv_bbss_config *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_BACKHAUL_BSS_CONFIG;
	t->len = sizeof(*data);
	data = (struct tlv_bbss_config *) t->data;

	memcpy(data->bssid, bssid, 6);

#if 0
	if (a->disallow_bsta_p1)
#endif
	data->config |= BBSS_CONFIG_P1_BSTA_DISALLOWED;
#if 0
	if (a->disallow_bsta_p2)
		data->config |= BBSS_CONFIG_P2_BSTA_DISALLOWED;
#endif
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_steering_policy(struct controller *c, struct node_policy *a,
		struct cmdu_buff *frm, int num_radio, uint8_t *radiolist)
{
	int ret, i;
	int offset = 0;
	struct tlv *t;
	struct stax *x;
	uint8_t sta_mac[6] = {0};
	uint8_t num_nosteer_index = 0;
	uint8_t num_nobtmsteer_index = 0;
	uint8_t num_nosteer = 0;
	uint8_t num_nobtmsteer = 0;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_STEERING_POLICY;

	num_nosteer_index = offset++;
	list_for_each_entry(x, &a->steer_exlist, list) {
		num_nosteer++;
		hwaddr_aton(x->macstring, sta_mac);
		memcpy(t->data + offset, sta_mac, 6);
		offset += 6;
	}
	t->data[num_nosteer_index] = num_nosteer;

	num_nobtmsteer_index = offset++;
	list_for_each_entry(x, &a->btmsteer_exlist, list) {
		num_nobtmsteer++;
		hwaddr_aton(x->macstring, sta_mac);
		memcpy(t->data + offset, sta_mac, 6);
		offset += 6;
	}
	t->data[num_nobtmsteer_index] = num_nobtmsteer;

	t->data[offset++] = num_radio;
	for (i = 0; i < num_radio; i++) {
		struct radio_policy *rp;

		rp = agent_find_radio_policy(c, &radiolist[i*6]);
		if (!rp)
			continue;

		memcpy(t->data + offset, &radiolist[i*6], 6);
		offset += 6;
		t->data[offset++] = rp->policy;
		t->data[offset++] = rp->util_threshold;
		t->data[offset++] = rp->rcpi_threshold;
	}

	/* update the tlv len */
	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_metric_report_policy(struct controller *c, struct node_policy *a,
		struct cmdu_buff *frm, int num_radio, uint8_t *radiolist)
{
	int ret, i;
	struct tlv *t;
	int offset = 0;
	uint8_t include_flag = 0x00;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_METRIC_REPORTING_POLICY;

	t->data[offset++] = a->report_metric_periodic;
	t->data[offset++] = num_radio;

	for (i = 0; i < num_radio; i++) {
		struct radio_policy *rp;

		rp = agent_find_radio_policy(c, &radiolist[i*6]);
		if (!rp)
			continue;

		memcpy(t->data + offset, &radiolist[i*6], 6);
		offset += 6;
		t->data[offset++] = rp->report_rcpi_threshold;
		t->data[offset++] = rp->report_rcpi_hysteresis_margin;
		t->data[offset++] = rp->report_util_threshold;

		if (rp->include_sta_stats)
			include_flag |= INCLUDE_STA_STATS;

		if (rp->include_sta_metric)
			include_flag |= INCLUDE_STA_LINK_METRICS;

#if (EASYMESH_VERSION > 2)
		if (rp->include_wifi6_sta_status)
			include_flag |= INCLUDE_STA_STATUS_REPORT;
#endif

		t->data[offset++] = include_flag;
	}

	/* update the tlv length */
	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

struct tlv_supported_role *cntlr_gen_supported_role(struct controller *c,
		uint8_t role)
{
	return NULL;
//	struct tlv_supported_role *p;
//
//	p = calloc(1, sizeof(struct tlv_supported_role));
//	if (!p)
//		return NULL;
//
//	p->tlv_type = TLV_TYPE_SUPPORTED_ROLE;
//	p->role = role;
//
//	return p;
}

int cntlr_gen_client_info(struct controller *c, struct cmdu_buff *frm,
		uint8_t *sta, uint8_t *bssid)
{
	int ret;
	struct tlv *t;
	struct tlv_client_info *data;

	t = cmdu_reserve_tlv(frm, 40);
	if (!t)
		return -1;

	t->type = MAP_TLV_CLIENT_INFO;
	t->len = sizeof(*data);
	data = (struct tlv_client_info *)t->data;
	memcpy(data->bssid, bssid, 6);
	memcpy(data->macaddr, sta, 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_backhaul_steer_req(struct controller *c, struct cmdu_buff *frm,
		uint8_t *bkhaul, uint8_t *target_bssid, uint8_t op_class,
		uint8_t channel)
{
	struct tlv *t;
	struct tlv_backhaul_steer_request *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_BACKHAUL_STEERING_REQUEST;
	t->len = 14;
	data = (struct tlv_backhaul_steer_request *) t->data;
	memcpy(data->target_bssid, target_bssid, 6);
	memcpy(data->macaddr, bkhaul, 6);
	data->target_opclass = op_class;
	data->target_channel = channel;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tlv_steer_request(struct controller *c,
		struct cmdu_buff *frm, uint8_t tlv_type,
		uint8_t *bssid, uint32_t steer_timeout,
		uint32_t sta_nr, uint8_t sta_id[][6],
		uint32_t bssid_nr, uint8_t target_bbsid[][6],
		uint32_t request_mode)
{
	int ret, offset = 0;
	int i;
	uint8_t mode = 0x00;
	struct tlv *t;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = tlv_type;
	memcpy(&t->data[offset], bssid, 6);	/* bssid */
	offset += 6;

	/* here we need to know if this is for
	 * STA mandate or STA opportunity
	 */
	if (request_mode == STEER_MODE_BTM_REQ) {
		mode |= STEER_REQUEST_MODE;
		t->data[offset++] = mode;	/* request mode */
		BUF_PUT_BE16(t->data[offset], 0x0000);	/* opportunity window */
		offset += 2;
	} else if (request_mode == STEER_MODE_OPPORTUNITY) {
		t->data[offset++] = mode;	/* request mode */
		BUF_PUT_BE16(t->data[offset++], steer_timeout);	/* opportunity window */
		offset += 2;
	} else {
		dbg("Unknown request mode\n");
		return -1;
	}

	BUF_PUT_BE16(t->data[offset], 0x0000);	/* dummy value; BTM Disassociation Timer */
	offset += 2;
	t->data[offset++] = (uint8_t) sta_nr;	/* sta count */
	for (i = 0; i < sta_nr; i++) {
		dbg("%s %d\n", __func__, __LINE__);

		dbg("%s %d sta_id " MACFMT "\n",
		    __func__, __LINE__, MAC2STR(sta_id[i]));

		memcpy(&t->data[offset], sta_id[i], 6);	/* sta mac */
		dbg("%s %d\n", __func__, __LINE__);

		offset += 6;
	}

	if (request_mode == 1) {
		t->data[offset++] = (uint8_t) bssid_nr;		/* BSSID list count */

		for (i = 0; i < bssid_nr; i++) {
			dbg("%s %d target_bssid " MACFMT "\n",
			    __func__, __LINE__, MAC2STR(target_bbsid[i]));

			memcpy(&t->data[offset], target_bbsid[i], 6);	/* bssid */
			dbg("%s %d\n", __func__, __LINE__);
			offset += 6;
			t->data[offset++] = 0x00;	/* bss opclass */
			t->data[offset++] = 0x00;	/* bss channel */

			if (tlv_type == MAP_TLV_PROFILE2_STEERING_REQ)
				t->data[offset++] = 0x00;	/* reason code */
		}
	} else
		t->data[offset++] = 0x00;	/* BSSID list count */

	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tlv_assoc_ctrl_request(struct controller *c,
		struct cmdu_buff *frm, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist)
{
	int i, ret, offset = 0;
	struct tlv *t;
	struct tlv_client_assoc_ctrl_request *data;

	if (!stalist)
		return -1;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_CLIENT_ASSOCIATION_CONTROL_REQUEST;
	offset = sizeof(*data);
	data = (struct tlv_client_assoc_ctrl_request *)t->data;

	memcpy(data->bssid, bssid, 6);
	data->control = assoc_cntl_mode;
	BUF_PUT_BE16(data->validity_period, assoc_timeout);
	data->num_sta = sta_nr;
	for (i = 0; i < sta_nr; i++) {
		memcpy(&t->data[offset], &stalist[i * 6], 6);
		offset += 6;
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tlv_beacon_metrics_query(struct controller *c,
		struct cmdu_buff *frm, uint8_t *sta_addr,
		uint8_t opclass, uint8_t channel,
		uint8_t *bssid, uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, const uint8_t *element)
{
	struct tlv *t;
	struct tlv_beacon_metrics_query *data;
	uint8_t *data_p;
	struct ssid_query *ssidq;
	size_t ssid_len = strlen(ssid);
	int i, ret;

	/* TODO: check size */
	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_BEACON_METRICS_QUERY;
	/* It will be increased later for variable params */
	t->len = sizeof(struct tlv_beacon_metrics_query);

	/* Note: this cast holds only till 'reporting_detail' field */
	data = (struct tlv_beacon_metrics_query *) t->data;

	memcpy(data->sta_macaddr, sta_addr, 6);
	data->opclass = opclass;
	data->channel = channel;
	memcpy(data->bssid, bssid, 6);
	data->reporting_detail = reporting_detail;

	/* Flexible array in the middle of the struct - cast to ssid_query */
	ssidq = (struct ssid_query *) &data->ssid;
	ssidq->ssidlen = ssid_len;
	memcpy(ssidq->ssid, ssid, ssid_len);

	t->len += ssid_len;

	/* No more direct use of tlv_beacon_metrics_query structure layout
	 * from here on: data->num_report doesn't point to num_report anymore!
	 * From now on just use the data pointer to pack the data manually.
	 */
	data_p = &(ssidq->ssidlen) + 1 + ssid_len;

	/* Channel reports */
	if (channel != 255 || !num_report || !report) {
		/* 17.2.27: If the value of Channel Number field is not set
		 *          to 255, Number of AP Channel Reports is set to 0.
		 */
		dbg("%s: no reports will be included!\n", __func__);

		/* data->num_report */
		*(data_p++) = 0;

		/* decrease by one report already counted for in sizeof (query) */
		t->len -= sizeof(struct ap_channel_report);

	} else {

		/* data->num_report */
		*(data_p++) = num_report;

		/* data->report */
		/* -1: one report always counted for in sizeof (query) */
		t->len += (num_report - 1) * sizeof(struct ap_channel_report);

		for (i = 0; i < num_report; i++) {
			struct ap_channel_report *ch_rep =
					(struct ap_channel_report *) data_p;
			int num_channel = report[i].num_channel;

			ch_rep->opclass = report[i].opclass;
			/* opclass + channel[] */
			ch_rep->len = 1 + num_channel;
			memcpy(ch_rep->channel, report[i].channel, num_channel);

			/* Increase t->len by number of channels = sizeof(channel[]) */
			t->len += num_channel;
			/* (len + opclass) + channel[] */
			data_p += 2 + num_channel;
		}
	}

	/* Request elements */
	if (reporting_detail != 1 || !num_element || !element) {
		/* 17.2.27: If the value of Reporting Detail fields is not
		 *          set to 1, Number of element IDs is set to 0.
		 */
		dbg("%s: no element IDs will be included!\n", __func__);
		/* data->num_element */
		*(data_p++) = 0;
	} else {
		/* data->num_element */
		*(data_p++) = num_element;

		/* data->element */
		t->len += num_element;
		for (i = 0; i < num_element; i++) {
			*data_p = element[i];
			data_p++;
		}
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_1905_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm)
{
	int ret;
	struct tlv *t;
	struct tlv_linkmetric_query *data;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = TLV_TYPE_LINK_METRIC_QUERY;
	t->len = sizeof(*data);
	data = (struct tlv_linkmetric_query *) t->data;
	data->nbr_type = LINKMETRIC_QUERY_NEIGHBOR_ALL;
	/* data->nbr_mac is not present because of
		default LINKMETRIC_QUERY_NEIGHBOR_ALL */
	data->query_type = LINKMETRIC_QUERY_TYPE_BOTH;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_ap_metric_query(struct controller *c,
		struct cmdu_buff *frm, uint8_t num_bss, uint8_t *bsslist)
{
	int i, ret;
	struct tlv *t;
	struct tlv_ap_metric_query *data;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_METRIC_QUERY;
	t->len = sizeof(*data) + (6 * num_bss);
	data = (struct tlv_ap_metric_query *) t->data;

	data->num_bss = num_bss;
	for (i = 0; i < data->num_bss; i++)
		memcpy(data->bss[i].bssid, &bsslist[i * 6], 6);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_ap_metrics_tlv(struct controller *c,
		struct cmdu_buff *frm, uint8_t *listbss)
{
	int ret, index;
	struct tlv *t;
	struct tlv_ap_metrics *data;

	struct netif_iface *ifc;
	struct wifi_bss_element *bss;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_AP_METRICS;
	t->len = sizeof(*data);
	data = (struct tlv_ap_metrics *) t->data;
	ifc = cntlr_iterate_fbss(c, listbss);
	if (!ifc) {
		trace("Incorrect bssid!\n");
		return -1;
	}
	bss = ifc->bss;
	memcpy(data->bssid, bss->bssid, 6);
	data->channel_utilization = bss->ch_util;
	data->num_station = bss->num_stations;
	data->esp_ac = bss->esp_ac;

	/* Mandatory ESP Information field for BE */
	if (!(bss->esp_ac & ESP_AC_BE)) {
		dbg("|%s %d|: BE not set, forcing 1\n", __func__, __LINE__);
		/* Easy Mesh Spec 17.2.22: "This field shall be set to one" */
		data->esp_ac |= ESP_AC_BE;
	}
	memcpy(data->esp_be, bss->est_wmm_be, 3);

	/* Optional ESP Information Fields for BK, VO & VI */
	index = 0;
	if (bss->esp_ac & ESP_AC_BK) {
		memcpy(data->esp + index, bss->est_wmm_bk, 3);
		index += 3;
	}
	if (bss->esp_ac & ESP_AC_VO) {
		memcpy(data->esp + index, bss->est_wmm_vo, 3);
		index += 3;
	}
	if (bss->esp_ac & ESP_AC_VI)
		memcpy(data->esp + index, bss->est_wmm_vi, 3);

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tx_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm, struct netif_link *link_info)
{
	int ret;
	struct tlv *t;
	struct tlv_tx_linkmetric *data;
	struct tx_link_info *info;
	struct node *n;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = TLV_TYPE_TRANSMITTER_LINK_METRIC;
	data = (struct tlv_tx_linkmetric *) t->data;
	n = cntlr_find_node_by_iface(c, link_info->upstream->bss->bssid);
	memcpy(data->aladdr, n->alid, 6);
	n = cntlr_find_node_by_iface(c, link_info->downstream->bss->bssid);
	memcpy(data->neighbor_aladdr, n->alid, 6);
	t->len = 12; /* link */
	for (int i = 0; i < c->num_tx_links; i++) {
		info = (struct tx_link_info *)&data->link[i];
		memcpy(info->local_macaddr, link_info->upstream->bss->bssid, 6);
		memcpy(info->neighbor_macaddr, link_info->downstream->bss->bssid, 6);
		BUF_PUT_BE16(info->mediatype, link_info->metrics->type);
		info->has_bridge = link_info->metrics->bridge;
		BUF_PUT_BE32(info->errors, link_info->metrics->packet_tx_error);
		BUF_PUT_BE32(info->packets, link_info->metrics->packet_trans);
		BUF_PUT_BE16(info->max_throughput, link_info->metrics->thp);
		BUF_PUT_BE16(info->availability, link_info->metrics->link_av);
		BUF_PUT_BE16(info->phyrate, link_info->metrics->phy_rate);
		t->len += 29;
	}
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_rx_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm, struct netif_link *link_info)
{
	int ret;
	struct tlv *t;
	struct tlv_rx_linkmetric *data;
	struct rx_link_info *info;
	//struct link_metrics *metric_info;
	struct node *n;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = TLV_TYPE_RECEIVER_LINK_METRIC;
	data = (struct tlv_rx_linkmetric *) t->data;
	n = cntlr_find_node_by_iface(c, link_info->upstream->bss->bssid);
	memcpy(data->aladdr, n->alid, 6);
	n = cntlr_find_node_by_iface(c, link_info->downstream->bss->bssid);
	memcpy(data->neighbor_aladdr, n->alid, 6);
	t->len = 12; /* link */
	for (int i = 0; i < c->num_rx_links; i++) {
		info = (struct rx_link_info *)&data->link[i];
		memcpy(info->local_macaddr, link_info->upstream->bss->bssid, 6);
		memcpy(info->neighbor_macaddr, link_info->downstream->bss->bssid, 6);
		BUF_PUT_BE16(info->mediatype, link_info->metrics->type);
		BUF_PUT_BE32(info->errors, link_info->metrics->packet_rx_error);
		BUF_PUT_BE32(info->packets, link_info->metrics->packet_rec);
		info->rssi = link_info->metrics->rssi;
		t->len += 23;
	}
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_comb_infra_metrics(struct controller *c,
		struct cmdu_buff *frm, uint8_t *bssid)
{
	int ret = 0;
	struct netif_link *l = NULL;

	/* Add one AP Metrics TLV */
	ret = cntlr_gen_ap_metrics_tlv(c, frm, bssid);
	if (ret) {
		trace("%s |%d|: tlv gen error\n", __func__, __LINE__);
		return -1;
	}

	/* Add the 1905 Link Metric TLVs */
	/* For each agent */
	list_for_each_entry(l, &c->linklist, list) {
		ret = cntlr_gen_tx_link_metric_tlv(c, frm, l);
		if (ret) {
			trace("%s |%d|: tlv gen error\n", __func__, __LINE__);
			return -1;
		}
		ret = cntlr_gen_rx_link_metric_tlv(c, frm, l);
		if (ret) {
			trace("%s |%d|: tlv gen error\n", __func__, __LINE__);
			return -1;
		}
	}

	return 0;
}

int cntlr_gen_sta_mac(struct controller *c,
		struct cmdu_buff *frm, uint8_t *sta)
{
	int ret;
	struct tlv *t;
	struct tlv_sta_mac *data;

	t = cmdu_reserve_tlv(frm, 20);
	if (!t)
		return -1;

	t->type = MAP_TLV_STA_MAC_ADDRESS;
	t->len = sizeof(*data);
	data = (struct tlv_sta_mac *) t->data;

	memcpy(data->macaddr, sta, 6);
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_unassociated_sta_link_metrics(struct controller *c,
		struct cmdu_buff *frm, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics)
{
	int ret, i, j, num_sta;
	struct tlv *t;
	struct tlv_unassoc_sta_link_metrics_query *data;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_UNASSOCIATED_STA_LINK_METRICS_QUERY;
	t->len = sizeof(struct tlv_unassoc_sta_link_metrics_query);

	data = (struct tlv_unassoc_sta_link_metrics_query *) t->data;
	data->opclass = opclass;
	data->num_channel = num_metrics;

	for (i = 0; i < num_metrics; i++) {
		t->len += 2; /* two bytes: channel & num_sta */

		data->ch[i].channel = metrics[i].channel;
		num_sta = metrics[i].num_sta;

		if (num_sta > MAX_UNASSOC_STAMACS) {
			dbg("%s: error: num_sta (%d) greater than %d\n",
				__func__, num_sta, MAX_UNASSOC_STAMACS);
			num_sta = MAX_UNASSOC_STAMACS;
		}

		t->len += (num_sta * 6); /* six bytes: macaddr */

		data->ch[i].num_sta = num_sta;
		for (j = 0; j < num_sta; j++)
			memcpy(data->ch[i].sta[j].macaddr,
			       metrics[i].sta[j].macaddr, 6);
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_searched_role(struct controller *c, struct cmdu_buff *frm,
		uint8_t role)
{
	struct tlv *t;
	struct tlv_searched_role *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = TLV_TYPE_SEARCHED_ROLE;
	t->len = 1;
	data = (struct tlv_searched_role *) t->data;
	data->role = role;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cnltr_gen_searched_service(struct controller *c, struct cmdu_buff *frm,
		uint8_t service)
{
	struct tlv *t;
	int ret;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = MAP_TLV_SEARCHED_SERVICE;
	t->len = 2;
	t->data[0] = 0x1;
	t->data[1] = service;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_autoconf_freq_band(struct controller *c, struct cmdu_buff *frm,
		uint8_t band)
{
	struct tlv *t;
	struct tlv_autoconfig_band *data;
	int ret;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = TLV_TYPE_AUTOCONFIG_FREQ_BAND;
	t->len = 1;
	data = (struct tlv_autoconfig_band *) t->data;
	data->band = band;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tlv_error_code(struct controller *c,
	struct cmdu_buff *frm, uint8_t *macaddr, uint8_t reason_code)
{
	struct tlv *t;
	struct tlv_error_code *data;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_ERROR_CODE;
	t->len = 7;

	data = (struct tlv_error_code *) t->data;
	data->reason = reason_code;

	if (macaddr)
		memcpy(data->macaddr, macaddr, 6);

	if (cmdu_put_tlv(frm, t)) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_channel_scan_req(struct controller *c, struct cmdu_buff *frm,
		struct scan_req_data *req_data)
{
	struct tlv *t;
	struct tlv_channel_scan_request *data;
	struct channel_scan_request_radio *radio_data;
	struct channel_scan_request_opclass *opclass_data;
	int num_channel;
	uint8_t *channel_data;
	int ret, offset;

	/* Allocate the TLV of the cmdu_data */
	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	/* Define the TLV */
	t->type = MAP_TLV_CHANNEL_SCAN_REQ;
	data = (struct tlv_channel_scan_request *) t->data;
	if (req_data->is_fresh_scan)
		data->mode |= SCAN_REQUEST_FRESH_SCAN;

	data->num_radio = req_data->num_radio;
	offset = sizeof(*data);

	if (data->num_radio > SCAN_REQ_MAX_NUM_RADIO)
		return -1;

	for (int i = 0; i < data->num_radio; i++) {
		radio_data = (struct channel_scan_request_radio *)&t->data[offset];
		memcpy(radio_data->radio, req_data->radios[i].radio_mac, 6); /* radio id */

		if (req_data->is_fresh_scan)
			radio_data->num_opclass = req_data->radios[i].num_opclass;
		else
			/* If a Multi-AP Controller sends a Channel Scan Request
			 * to a Multi-AP Agent with the Perform Fresh Scan bit set
			 * to zero, it shall set the Number of Operating Classes
			 * field for each radio listed to zero.
			 */
			radio_data->num_opclass = 0;

		if (radio_data->num_opclass > SCAN_REQ_MAX_NUM_OPCLASS)
			return -1;
		offset += sizeof(*radio_data);

		for (int j = 0; j < radio_data->num_opclass; j++) {
			opclass_data = (struct channel_scan_request_opclass *) &t->data[offset];
			opclass_data->classid = req_data->radios[i].opclasses[j].classid;
			num_channel = req_data->radios[i].opclasses[j].num_channel;
			if (num_channel > SCAN_REQ_MAX_NUM_CHAN)
				return -1;
			opclass_data->num_channel = num_channel;
			offset += sizeof(*opclass_data);

			if (num_channel) {
				channel_data = (uint8_t *) &t->data[offset];
				memcpy(channel_data, req_data->radios[i].opclasses[j].channels, num_channel);
				offset += num_channel;
			}
		}
	}
	/* Update the TLV length */
	t->len = offset;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_channel_pref(struct controller *c, struct cmdu_buff *frm,
		uint8_t *radio_id, uint8_t class_id, uint8_t channel_nr,
		const uint8_t *chanlist, uint8_t pref)
{
	int ret, offset = 0;
	int i, j, num_opclass = 1;
	struct tlv *t;
	uint8_t preference = 0x00;
	uint8_t reason_code = 0x00;

	t = cmdu_reserve_tlv(frm, 256);
	if (!t)
		return -1;

	t->type = MAP_TLV_CHANNEL_PREFERENCE;

	memcpy(&t->data[offset], radio_id, 6);	/* radio id */
	offset += 6;
	t->data[offset++] = num_opclass;	/* num opclass */

	for (i = 0; i < num_opclass; i++) {
		t->data[offset++] = class_id;	/* class id */
		t->data[offset++] = channel_nr;	/* num channel */
		for (j = 0; j < channel_nr; j++)
			t->data[offset++] = chanlist[j];

		preference |= ((pref << 4) & CHANNEL_PREF_MASK);	/* preference */
		preference |= (reason_code & CHANNEL_PREF_REASON);	/* reason code */
		t->data[offset++] = preference;
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_txpower_limit(struct controller *c, struct cmdu_buff *frm,
		uint8_t *radio_id, uint8_t txpower_limit)
{
	int ret;
	struct tlv *t;
	struct tlv_txpower_limit *data;

	t = cmdu_reserve_tlv(frm, 40);
	if (!t)
		return -1;

	t->type = MAP_TLV_TRANSMIT_POWER_LIMIT;
	t->len = sizeof(*data);
	data = (struct tlv_txpower_limit *)t->data;

	memcpy(data->radio, radio_id, 6);
	data->limit = txpower_limit;

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_cac_tlv(struct controller *c, struct cmdu_buff *frm,
		      uint8_t tlv_type, int num_data, struct cac_data *cac_data)
{
	int i, ret, offset = 0;
	struct tlv *t;

	if (!cac_data)
		return -1;

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = tlv_type;
	t->data[offset++] = num_data;
	for (i = 0; i < num_data; i++) {
		uint8_t mode = 0x00;
		uint8_t cac_method, cac_action;

		memcpy(&t->data[offset], cac_data[i].radio, 6);
		offset+= 6;
		t->data[offset++] = cac_data[i].opclass;
		t->data[offset++] = cac_data[i].channel;
		cac_method = cac_data[i].cac_method;
		cac_action = cac_data[i].cac_action;

		if (tlv_type == MAP_TLV_CAC_REQ) {
			mode = (cac_method << 5) & CAC_REQUEST_METHOD;
			mode |= (cac_action << 3) & CAC_REQUEST_COMPLETE_ACTION;
			t->data[offset++] = mode;
		}
	}

	t->len = offset;
	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		dbg("%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}

int cntlr_gen_tlv_higher_layer_data(struct controller *c, struct cmdu_buff *frm,
		uint8_t proto, uint8_t *data, int len)
{
	struct tlv *t;

	t = cmdu_reserve_tlv(frm, len + 1);
	if (!t)
		return -1;

	t->type = MAP_TLV_HIGHER_LAYER_DATA;
	t->len = len + 1;
	t->data[0] = proto;
	if (data)
		memcpy(t->data + 1, data, len);

	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

#if (EASYMESH_VERSION > 2)
int cntlr_gen_bss_config_response_tlv(struct controller *c, struct cmdu_buff *cmdu)
{
	struct tlv *tlv;
	int data_len;

	// todo:
	/* One or more JSON encoded DPP Configuration Object attributes */
	const char *data =
	"{\
		\"wi-fi_tech\": \"infra\",\
		\"discovery\": {\
			\"ssid\": \"mywifi\"\
		},\
		\"cred\": {\
			\"akm\": \"dpp\",\
			\"signedConnector\": \"eyJ0eXAiOiJkcHBDb24iLCJraWQiOiJrTWNlZ0RCUG1OWlZha0FzQlpPek9vQ3N2UWprcl9uRUFwOXVGLUVEbVZFIiwi\",\
			\"csign\": {\
				\"kty\": \"EC\",\
				\"crv\": \"P-256\",\
				\"x\": \"MKBCTNIcKUSDii11ySs3526iDZ8AiTo7Tu6KPAqv7D4\",\
				\"y\": \"4Etl6SRW2YiLUrN5vfvVHuhp7x8PxltmWWlbbM4IFyM\",\
				\"kid\": \"kMcegDBPmNZVakAsBZOzOoCsvQjkr_nEAp9uF-EDmVE\"\
			},\
			\"ppKey\": {\
				\"kty\": \"EC\",\
				\"crv\": \"P-256\",\
				\"x\": \"XX_ZuJR9nMDSb54C_okhGiJ7OjCZOlWOU9m8zAxgUrU\",\
				\"y\": \"Fekm5hyGii80amM_REV5sTOG3-sl1H6MDpZ8TSKnb7c\"\
			}\
		}\
	}";

	data_len = strlen(data);

	tlv = cmdu_reserve_tlv(cmdu, data_len);
	if (!tlv)
		return -1;
	tlv->type = MAP_TLV_BSS_CONFIGURATION_RESPONSE;
	tlv->len = data_len;

	memcpy(tlv->data, data, data_len);

	if (cmdu_put_tlv(cmdu, tlv))
		return -1;

	return 0;
}

int cntlr_gen_dpp_cce_indication_tlv(struct controller *c,
		struct cmdu_buff *frm, bool cce_advertise)
{
	struct tlv *t;
	struct tlv_dpp_cce *data;

	t = cmdu_reserve_tlv(frm, 10);
	if (!t)
		return -1;

	t->type = MAP_TLV_DPP_CCE_INDICATION;
	t->len = sizeof(*data);
	data = (struct tlv_dpp_cce *)t->data;

	data->enable = cce_advertise;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

/* TODO: fill the DPP frame field */
int cntlr_gen_dpp_message_tlv(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	int offset = 0;
	/* dummy values */
	int framelen = 1;
	uint8_t frame[1] = { 0xff };

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_DPP_MESSAGE;

	/* DPP Frame length */
	t->data[offset++] = framelen;

	/* DPP Frame */
	memcpy(&t->data[offset], frame, framelen);
	offset += framelen;

	t->len = offset;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

/* TODO: fill the following fields
 * Encap DPP flag (DPP Frame indicator & MAC addr present)
 * Enrollee MAC, Frame Type & Encapsulated Frame
 */
int cntlr_gen_1905_encap_dpp_tlv(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	int offset = 0;
	uint8_t flag = 0x10; /* bit 5: 0 DPP Public Action Frame, 1 GAS frame */
	uint8_t frametype = 255;
	bool mac_present;

	/* dummy values */
	uint8_t enrollee[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int framelen = 1;
	uint8_t frame[1] = { 0xff };

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_1905_ENCAP_DPP;

	/* Enrolee MAC Address Present & DPP Frame Indicator */
	t->data[offset++] = flag;
	mac_present = (flag & ENCAP_DPP_ENROLLEE_MAC_PRESENT) ? true : false;
	if (mac_present) {
		memcpy(&t->data[offset], enrollee, 6);
		offset += 6;
	}

	/* Frame Type */
	t->data[offset++] = frametype;

	/* Encapsulated frame length field */
	t->data[offset++] = framelen;

	/* Encapsulated frame */
	memcpy(&t->data[offset], frame, framelen);
	offset += framelen;

	t->len = offset;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

/* TODO: fill the following fields
 * DPP flag (Hash Validity & MAC addr present)
 * Enrollee MAC & hash
 */
int cntlr_gen_chirp_value_tlv(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	int offset = 0;
	uint8_t flag = 0x00;
	bool specify_enrollee;

	/* dummy values */
	uint8_t enrollee[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	int hashlen = 1;
	uint8_t hash[1] = { 0xff };

	t = cmdu_reserve_tlv(frm, 512);
	if (!t)
		return -1;

	t->type = MAP_TLV_DPP_CHIRP_VALUE;
	t->data[offset++] = flag;
	specify_enrollee = (flag & DPP_CHIRP_ENROLLEE_MAC_PRESENT) ? true : false;
	if (specify_enrollee) {
		memcpy(&t->data[offset], enrollee, 6);
		offset += 6;
	}

	t->data[offset++] = hashlen;
	memcpy(&t->data[offset], hash, hashlen);
	offset += hashlen;

	t->len = offset;
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int cntlr_gen_device_1905_layer_security_cap(struct controller *c,
		struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_1905_security_cap *data;

	t = cmdu_reserve_tlv(frm, 10);
	if (!t)
		return -1;

	t->type = MAP_TLV_1905_SECURITY_CAPS;
	data = (struct tlv_1905_security_cap *)t->data;

	t->len = sizeof(*data);
	/* TODO: need to do the mapping */
	data->protocol = SECURITY_PROTOCOL_DPP;
	data->mic = SECURITY_MIC_HMAC_SHA256;
	data->enc = SECURITY_ENC_AES_SIV;

	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int cntlr_gen_cntlr_capability(struct controller *c, struct cmdu_buff *frm)
{
	struct tlv *t;
	struct tlv_controller_cap *data;

	t = cmdu_reserve_tlv(frm, 128);
	if (!t)
		return -1;

	t->type = MAP_TLV_CONTROLLER_CAPS;
	data = (struct tlv_controller_cap *)t->data;

	/* TODO: fill proper values */
	data->flag = 0x00;

	t->len = sizeof(*data);
	if (cmdu_put_tlv(frm, t))
		return -1;

	return 0;
}

int cntlr_gen_agent_list_tlv(struct controller *c, struct cmdu_buff *frm)
{
	int ret;
	struct tlv *t;
	struct tlv_agent_list *tlv_data;
	struct node *n;
	int i;
	const uint16_t max_tlv_len = 512;

	dbg("%s: --->\n", __func__);
	t = cmdu_reserve_tlv(frm, max_tlv_len);
	if (!t)
		return -1;

	tlv_data = (struct tlv_agent_list *)t->data;
	tlv_data->num_agent = c->num_nodes;

	dbg("num_agent = %d\n", tlv_data->num_agent);

	t->type = MAP_TLV_AGENT_LIST;
	/* t->len = 1 + num_agents * (6 + 1 + 1) bytes */
	t->len = sizeof(tlv_data->num_agent) +
		 tlv_data->num_agent * sizeof(tlv_data->agent[0]);

	if (t->len > max_tlv_len)
		return -1;

	i = 0;
	list_for_each_entry(n, &c->nodelist, list) {
		dbg("\tagent[%d]:\n", i);

		/* node aladdr */
		memcpy(tlv_data->agent[i].aladdr, n->alid, 6);
		dbg("\t\tagent_id: " MACFMT "\n", MAC2STR(tlv_data->agent[i].aladdr));

		/* map profile */
		tlv_data->agent[i].profile = n->map_profile;
		dbg("\t\tprofile: %d\n", tlv_data->agent[i].profile);

		/* TODO: Here we need to fill the security */
		tlv_data->agent[i].security = 0xFF;
		dbg("\t\tsecurity: %d\n", tlv_data->agent[i].security);

		++i;
	}

	ret = cmdu_put_tlv(frm, t);
	if (ret) {
		fprintf(stderr, "%s: error: cmdu_put_tlv()\n", __func__);
		return -1;
	}

	return 0;
}
#endif /* EASYMESH_VERSION > 2 */
