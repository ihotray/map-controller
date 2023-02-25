/*
 * cntlr_map.c - implements MAP2 CMDUs handling
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
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
#include <uci.h>

#include <easy/easy.h>
#include <easy/utils.h>

#include <cmdu.h>
#include <i1905_wsc.h>
#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
#include <cntlrsync.h>
#endif
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "timer.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "utils/liblist.h"
#include "config.h"
#include "cntlr.h"
#include "cntlr_ubus.h"

#include "cntlr_map_debug.h"
#include "cntlr_cmdu.h"
#include "cntlr_tlv.h"
#include "cmdu_validate.h"
#include "wifi_opclass.h"
#include "cntlr_map.h"


/* Max size is 256 as per the Multi-ap r2 spec */
#define TIMESTAMP_MAX_LEN 256

#ifndef IEEE80211_FREQUENCY_BAND_6_GHZ
#define IEEE80211_FREQUENCY_BAND_6_GHZ	(0x04)
#endif


typedef int (*map_cmdu_handler_t)(void *cntlr, struct cmdu_buff *cmdu,
				  struct node *n);

struct map_cmdu_calltable_t {
	map_cmdu_handler_t handle;
	map_cmdu_handler_t debug;
};

struct tlv *map_cmdu_get_tlv(struct cmdu_buff *cmdu, uint8_t type)
{
	struct tlv *t;

	if (!cmdu || !cmdu->cdata) {
		map_error = MAP_STATUS_ERR_CMDU_MALFORMED;
		return NULL;
	}

	t = cmdu_peek_tlv(cmdu, type);
	if (!t) {
		map_error = MAP_STATUS_ERR_CMDU_MALFORMED;
		return NULL;
	}

/*
	if (tlv_length(t) < tlv_minsize(type)) {
		map_error = MAP_STATUS_ERR_TLV_MALFORMED;
		return NULL;
	}
*/

	return t;
}

int handle_topology_discovery(void *cntlr, struct cmdu_buff *cmdu,
				  struct node *n)
{
	uint8_t almac[6] = {0};
	struct controller *c = (struct controller *) cntlr;
	struct tlv_aladdr *aladdr;
	struct tlv *t;
	trace("%s: --->\n", __func__);

	t = map_cmdu_get_tlv(cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard topology notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = cntlr_add_node(c, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}

	return 0;
}

int handle_topology_notification(void *cntlr, struct cmdu_buff *cmdu,
				  struct node *n)
{
	uint8_t almac[6] = {0};
	struct tlv *tv[2][16] = {0};
	struct controller *c = (struct controller *) cntlr;
	struct tlv_aladdr *aladdr;
	struct tlv *t;
	trace("%s: --->\n", __func__);

	t = map_cmdu_get_tlv(cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard topology notification from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = cntlr_add_node(c, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}

	if (!validate_topology_notification(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [TOPOLOGY_NOTIFICATION] failed\n");
		return -1;
	}

	return 0;
}

static void _cntlr_update_steer_params(struct controller *c, struct wifi_radio_opclass *op)
{
	int i, j, k;
	bool found;
	struct wifi_radio_opclass_entry *oe;
	struct steering *sp;

	for (i = 0; i < op->num_opclass; i++) {
		oe = &op->opclass[i];
		for (j = 0; j < oe->num_channel; j++) {
			sp = &c->steer_params;
			found = false;
			for (k = 0; k < sp->channels_num; k++) {
				if(sp->channels[k] == oe->channel[j].channel) {
					found = true;
					break;
				}
			}

			if (!found) {
				sp->channels[sp->channels_num] = oe->channel[j].channel;
				sp->channels_num++;
			}
		}
	}
}

static void cntlr_update_steer_params(struct controller *c, struct sta *s)
{
    struct netif_iface *p = NULL;  /* fh anf bk iface */
    struct netif_radio *r = NULL;
    struct node *n = NULL;

    list_for_each_entry(n, &c->nodelist, list) {
        list_for_each_entry(r, &n->radiolist, list) {
            list_for_each_entry(p, &r->iflist, list) {
		if (s->fh && !memcmp(p->bss->ssid, s->fh->bss->ssid, 33))
			_cntlr_update_steer_params(c, &r->radio_el->cur_opclass);
            }
        }
    }
}

int handle_topology_query(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
#if 0 // Disable due to ieee1905 topology plugin sending without profile
	struct controller *c = (struct controller *) cntlr;

	cntlr_set_link_profile(c, n, cmdu);
#endif
	return 0;
}

#ifdef EASYMESH_VENDOR_EXT
static int topology_response_vext(struct controller *c, struct node *n, struct tlv *tv[16])
{
	int num = 0;

	/* vendor tlv containing backhaul interfaces only */
	while (num < 16 && tv[num]) {
		struct tlv_vendor_bbss *tlv;
		int i, offset = 0;
		uint8_t oui2[3];  /* TODO: use the same vendor oui-type */

		tlv = (struct tlv_vendor_bbss *)tv[num]->data;
		if (!tlv)
			return -1;

		/* oui (3 bytes) */
		memcpy(oui2, EASYMESH_VENDOR_EXT_OUI, 3);
		oui2[2]++;

		if (memcmp(tlv->oui, oui2, 3)) {
			num++;
			continue;
		}

		offset += 3; /* oui */

		offset += 1; /* num_radios */

		for (i = 0; i < tlv->num_radios; i++) {
			uint8_t num_bss = 0;
			struct netif_radio *r;
			int j;

			r = cntlr_node_add_radio(c, n,
					(uint8_t *)&tv[num]->data[offset]);
			if (!r)
				return -1; /* FIXME: continue + proper offset shift */

			offset += 6; /* macaddr */

			memcpy(&num_bss, &tv[num]->data[offset], 1);

			offset += 1; /* num_bss */

			for (j = 0; j < num_bss; j++) {
				struct netif_iface *fh;

				fh = cntlr_radio_add_interface(c, r,
						(uint8_t *)&tv[num]->data[offset]);
				if (!fh)
					return -1; /* FIXME: continue + proper offset shift */

				fh->bss->is_bbss = true;
				fh->bss->is_fbss = false;

				offset += 6; /* macaddr */
			}
		}

		num++;
	}

	return 0;
}
#endif

int handle_topology_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	struct controller *c = (struct controller *) cntlr;
	struct tlv *tv[12][16] = {0};

	cntlr_set_link_profile(c, n, cmdu);

	if (!validate_topology_response(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [TOPOLOGY_RESPONSE] failed, EMP %d, ifce \"%s\"\n",
				n->map_profile, cmdu->dev_ifname);
		return -1;
	}

	if (tv[7][0]) {
		struct tlv_ap_oper_bss *tlv;
		uint8_t *tv_data;
		int i, offset = 0;

		tlv = (struct tlv_ap_oper_bss *)tv[7][0]->data;
		if (!tlv)
			return -1;

		tv_data = (uint8_t *)tlv;

		offset += 1; /* num_radio */

		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t num_bss = 0;
			struct netif_radio *r = NULL;
			struct netif_iface *p = NULL;
			int j;

			r = cntlr_node_add_radio(c, n, &tv_data[offset]);
			if (!r)
				return -1; /* FIXME: continue + proper offset shift */

			offset += 6; /* macaddr */

			/* disable all prior stored fh/bh interfaces */
			list_for_each_entry(p, &r->iflist, list) {
				if (!p->bss->is_fbss && !p->bss->is_bbss)
					/* it is a bsta */
					continue;
				p->bss->enabled = false;
				p->bss->is_fbss = true;
				p->bss->is_bbss = false;
			}

			memcpy(&num_bss, &tv_data[offset], 1);

			offset += 1; /* num_bss */

			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0, len;
				struct netif_iface *fh;

				fh = cntlr_radio_add_interface(c, r, &tv_data[offset]);
				if (!fh)
					return -1; /* FIXME: continue + proper offset shift */

				offset += 6; /* macaddr */

				memcpy(&ssidlen, &tv_data[offset], 1);

				offset += 1; /* ssidlen */

				memset(fh->bss->ssid, 0, sizeof(fh->bss->ssid));
				len = (ssidlen > sizeof(fh->bss->ssid) - 1
						? sizeof(fh->bss->ssid) - 1 : ssidlen);
				memcpy(fh->bss->ssid, &tv_data[offset], len);

				offset += ssidlen; /* ssid */

				/* Update measurement time */
				time(&fh->bss->tsp);
			}
		}
	}

	/* map profile info stored for each node */
	if (tv[9][0])
		dbg("\t agent profile %d\n", n->map_profile);

#ifdef EASYMESH_VENDOR_EXT
	// EASYMESH_VENDOR_EXT is always last (no matter cmdu matches R2 or R4 profile),
	// validate_topology_response() works this way
	if (topology_response_vext(c, n, tv[11]))
		return -1;
#endif /*EASYMESH_VENDOR_EXT*/

#if (EASYMESH_VERSION > 2)
	if (tv[10][0] && n->map_profile > MULTIAP_PROFILE_2) {
		struct tlv_bss_configuration_report *tlv;
		uint8_t *tv_data;
		int i, offset = 0;

		tlv = (struct tlv_bss_configuration_report *)tv[10][0]->data;
		if (!tlv)
			return -1;

		tv_data = (uint8_t *)tlv;

		offset += 1; /* num_radio */

		dbg("\tradios_nr: %d\n", tlv->num_radio);
		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t num_bss = 0;
			struct netif_radio *r = NULL;
			struct netif_iface *p = NULL;
			int j;
			uint8_t *radio_macaddr = &tv_data[offset];

			dbg("\t\tradio_id: " MACFMT "\n", MAC2STR(radio_macaddr));
			r = cntlr_node_add_radio(c, n, &tv_data[offset]);
			if (!r)
				return -1; /* FIXME: continue + proper offset shift */

			offset += 6; /* macaddr */

			/* disable all prior stored fh/bh interfaces */
			list_for_each_entry(p, &r->iflist, list) {
				if (!p->bss->is_fbss && !p->bss->is_bbss)
					/* it is a bsta */
					continue;
				p->bss->is_fbss = false;
				p->bss->is_bbss = false;
			}
			memcpy(&num_bss, &tv_data[offset], 1);

			offset += 1; /* num_bss */

			dbg("\t\tbss_nr: %d\n", num_bss);
			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0, len;
				struct netif_iface *fh;
				uint8_t report = 0;

				dbg("\t\t\tbssid: " MACFMT "\n",
					MAC2STR(&tv_data[offset]));

				fh = cntlr_radio_add_interface(c, r, &tv_data[offset]);
				if (!fh)
					return -1; /* FIXME: continue + proper offset shift */

				offset += 6; /* bssid macaddr */

				/*Here we need to mask bitwise to get the report*/
				memcpy(&report, &tv_data[offset], 1);
				dbg("\t\t\treport: 0x%02x\n", report);
				dbg("\t\t\treport: %d\n", report);
				fh->bss->is_bbss = (report & BSS_CONFIG_BBSS) ? 1 : 0 ;
				fh->bss->is_fbss = (report & BSS_CONFIG_FBSS) ? 1 : 0 ;
				fh->bss->r1_disallowed = (report & BSS_CONFIG_R1_DISALLOWED) ? 1 : 0 ;
				fh->bss->r2_disallowed = (report & BSS_CONFIG_R2_DISALLOWED) ? 1 : 0 ;
				fh->bss->multi_bssid = (report & BSS_CONFIG_MBSSID) ? 1 : 0 ;
				fh->bss->transmitted_bssid = (report & BSS_CONFIG_TX_MBSSID) ? 1 : 0 ;
				offset += 1; /*report*/

				offset += 1; /* reserved byte*/

				memcpy(&ssidlen, &tv_data[offset], 1);
				dbg("\t\t\tssid_len: %d\n",
					ssidlen);
				offset += 1; /* ssidlen */

				memset(fh->bss->ssid, 0, sizeof(fh->bss->ssid));
				len = (ssidlen > sizeof(fh->bss->ssid) - 1
					? sizeof(fh->bss->ssid) - 1 : ssidlen);
				memcpy(fh->bss->ssid, &tv_data[offset], len);
				dbg("\t\t\tssid: %.*s\n",
					ssidlen,
					&tv_data[offset]);

				offset += ssidlen; /* ssid */

				/* Update measurement time */
				time(&fh->bss->tsp);
			}
		}
	}
#endif

	if (tv[8][0]) {
		struct tlv_assoc_client *tlv;
		uint8_t *tv_data;
		int i, offset = 0;

		tlv = (struct tlv_assoc_client *)tv[8][0]->data;
		if (!tlv)
			return -1;

		tv_data = (uint8_t *)tlv;

		offset += 1; /* num_bss */

		for (i = 0; i < tlv->num_bss; i++) {
			struct netif_iface *fh;
			uint8_t bssid[6] = {0};
			uint16_t num_client = 0;
			int j;

			memcpy(bssid, &tv_data[offset], 6);

			offset += 6; /* radio_id */

			num_client = BUF_GET_BE16(tv_data[offset]);

			offset += 2; /* num_client */

			fh = cntlr_iterate_fbss(c, bssid);
			if (!fh) {
				/* num_client * (macaddr + conntime) */
				offset += (num_client * 8);

				continue;
			}

			for (j = 0; j < num_client; j++) {
				uint8_t macaddr[6] = {0};
				uint16_t conntime;
				struct sta *s;
				struct netif_iface *bsta;

				memcpy(macaddr, &tv_data[offset], 6);

				offset += 6; /* macaddr */

				conntime = BUF_GET_BE16(tv_data[offset]);

				offset += 2; /* conntime */

				s = cntlr_add_sta(c, macaddr);
				if (!s)
					continue;

				memcpy(s->bssid, bssid, 6);
				s->fh = fh;
				s->de_sta->conn_time = conntime;

				bsta = cntlr_iterate_fbss(c, macaddr);
				if (bsta) {
					/* The client is an agent and the iface is a bSTA */
					memcpy(bsta->upstream_bssid, bssid, 6);
					/* bsta - unmark bbss & fbss */
					bsta->bss->is_bbss = false;
					bsta->bss->is_fbss = false;
					bsta->bss->enabled = true;
					s->type = IEEE1905;
					s->agent = bsta->agent;
					//s->de_sta->mapsta.stats.failed_steer_attempts = 0;
					//timestamp_reset(s->stats.last_steer_time);
				}

				/* Get STA data for steering and beacon requests */
				cntlr_update_steer_params(c, s);
			}
		}
	}

	/* Check opclass preferency age */
	if (cntlr_node_pref_opclass_expired(n)) {
		trace("node " MACFMT " pref opclass expired\n", MAC2STR(n->alid));
		cntrl_send_channel_preference_query(c, n->alid);
	}

	return 0;
}

static inline uint16_t c_cmdu_expect_response(uint16_t req_type)
{
	switch (req_type) {
		case CMDU_AP_CAPABILITY_QUERY:
			return CMDU_AP_CAPABILITY_REPORT;
		case CMDU_POLICY_CONFIG_REQ:
			return CMDU_1905_ACK;
		case CMDU_CHANNEL_PREFERENCE_QUERY:
			return CMDU_CHANNEL_PREFERENCE_REPORT;
		case CMDU_CHANNEL_SELECTION_REQ:
			return CMDU_CHANNEL_SELECTION_RESPONSE;
		case CMDU_OPERATING_CHANNEL_REPORT:
			return CMDU_1905_ACK;
		case CMDU_CLIENT_CAPABILITY_QUERY:
			return CMDU_CLIENT_CAPABILITY_REPORT;
		case CMDU_AP_METRICS_QUERY:
			return CMDU_AP_METRICS_RESPONSE;
		case CMDU_ASSOC_STA_LINK_METRICS_QUERY:
			return CMDU_ASSOC_STA_LINK_METRICS_RESPONSE;
		case CMDU_UNASSOC_STA_LINK_METRIC_QUERY:
			return CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE;
		case CMDU_BEACON_METRICS_QUERY:
			return CMDU_BEACON_METRICS_RESPONSE;
		case CMDU_COMBINED_INFRA_METRICS:
			return CMDU_1905_ACK;
		case CMDU_CLIENT_STEERING_REQUEST:
			// FIX THIS: we need ACK ?
			return CMDU_CLIENT_STEERING_BTM_REPORT;
		case CMDU_CLIENT_ASSOC_CONTROL_REQUEST:
			return CMDU_1905_ACK;
		case CMDU_STEERING_COMPLETED:
			return CMDU_1905_ACK;
		case CMDU_HIGHER_LAYER_DATA:
			return CMDU_1905_ACK;
		case CMDU_BACKHAUL_STEER_REQUEST:
			return CMDU_BACKHAUL_STEER_RESPONSE;
		case CMDU_CHANNEL_SCAN_REQUEST:
			return CMDU_CHANNEL_SCAN_REPORT;
		case CMDU_CAC_REQUEST:
			return CMDU_TYPE_NONE;
		case CMDU_CAC_TERMINATION:
			return CMDU_TYPE_NONE;
		case CMDU_CLIENT_DISASSOCIATION_STATS:
			return CMDU_TYPE_NONE;
		case CMDU_ERROR_RESPONSE:
			return CMDU_TYPE_NONE;
		case CMDU_ASSOCIATION_STATUS_NOTIFICATION:
			return CMDU_TYPE_NONE;
		case CMDU_BACKHAUL_STA_CAPABILITY_QUERY:
			return CMDU_BACKHAUL_STA_CAPABILITY_REPORT;
		case CMDU_FAILED_CONNECTION:
			return CMDU_TYPE_NONE;
#if (EASYMESH_VERSION > 2)
		case CMDU_BSS_CONFIG_RESPONSE:
			return CMDU_BSS_CONFIG_RESULT;
#endif
		default:
			break;
	}

	return CMDU_TYPE_NONE;
}

static uint16_t cntlr_cmdu_expect_response(struct controller *c, uint16_t req_type)
{
	uint16_t resp_type = c_cmdu_expect_response(req_type);

	if (resp_type == CMDU_TYPE_NONE)
		return CMDU_TYPE_NONE;

	if (map_cmdu_mask_isset(c->cmdu_mask, resp_type))
		return resp_type;
	else
		return CMDU_TYPE_NONE;
}

void send_cmdu_cb(struct ubus_request *req, int type, struct blob_attr *msg)
{
	struct json_object *jobj = NULL;
	struct json_object *tmp;
	uint16_t *mid;
	char *str;

	if (!msg || !req->priv) {
		fprintf(stderr, "%s:Message received is NULL\n", __func__);
		return;
	}

	mid = (uint16_t *)req->priv;

	str = (char *)blobmsg_format_json_indent(msg, true, -1);
	if (str) {
		jobj = json_tokener_parse(str);
		free(str);
	}

	if (jobj == NULL)
		return;

	if (json_object_object_get_ex(jobj, "mid", &tmp)) {
		*mid = json_object_get_int(tmp);
		fprintf(stdout, "%s:%d cntlr map-mid:%d\n", __func__, __LINE__, *mid); // typo ||
	}

	json_object_put(jobj);
}

int send_cmdu_ubus(struct controller *c, struct cmdu_buff *cmdu)
{
	struct blob_buf b = { 0 };
	char dst_addr[18] = { 0 };
	uint16_t msgid = 0;
	int ret = 0;
	uint32_t id;

	trace("|%s:%d| Entry\n", __func__, __LINE__);

	memset(&b, 0, sizeof(struct blob_buf));
	blob_buf_init(&b, 0);

	blobmsg_add_u32(&b, "type", cmdu_get_type(cmdu));

	hwaddr_ntoa(cmdu->origin, dst_addr);
	blobmsg_add_string(&b, "dst", dst_addr);

	blobmsg_add_u32(&b, "mid", (uint32_t)cmdu_get_mid(cmdu));

	if (c->cfg.enable_ts && is_vid_valid(c->cfg.primary_vid))
		blobmsg_add_u32(&b, "vid", (uint32_t)c->cfg.primary_vid);


	trace("|%s:%d|cmdu:0x%04x|dst:%s|mid:%u|fid:%u|vid:%u|\n", __func__, __LINE__,
			cmdu_get_type(cmdu), dst_addr, cmdu_get_mid(cmdu),
			cmdu_get_fid(cmdu), c->cfg.primary_vid);

	if (cmdu->datalen) {
		char *tlv_str = NULL;
		uint16_t len = 0;

		len = (cmdu->datalen * 2) + 1;
		tlv_str = (char *)calloc(len, sizeof(char));
		if (!tlv_str)
			goto out;

		btostr(cmdu->data, cmdu->datalen, tlv_str);
		tlv_str[len-1] = '\0';
		blobmsg_add_string(&b, "data", tlv_str);
		trace("|%s:%d|data:%s|\n", __func__, __LINE__, tlv_str);
		free(tlv_str);
	}

	if (ubus_lookup_id(c->ubus_ctx, "ieee1905", &id)) {
		trace("[%s:%d] not present ieee1905", __func__, __LINE__);
		goto out;
	}

	ret = ubus_invoke(c->ubus_ctx, id, "cmdu",
				b.head, send_cmdu_cb,
				&msgid,
				1000);
	if (ret) {
		trace("[%s:%d] ubus call failed for |ieee1905 send|",
					__func__, __LINE__);
		goto out;
	}

	trace("|%s:%d| msgid = %d\n", __func__, __LINE__, msgid);
	blob_buf_free(&b);
	return msgid;

out:
	blob_buf_free(&b);
	return -1;
}

uint16_t send_cmdu(struct controller *a, struct cmdu_buff *cmdu)
{
	uint16_t resp_type;
	int ret;
	void *cookie = NULL;
	const int resend_num = a->cfg.resend_num;
	uint16_t msgid, old_mid;

	if (hwaddr_is_ucast(cmdu->origin)) {
		resp_type = cntlr_cmdu_expect_response(a, cmdu_get_type(cmdu));
		if (resp_type != CMDU_TYPE_NONE)
			cookie = cmdu_clone(cmdu);
	}

	ret = send_cmdu_ubus(a, cmdu);
	if (ret < 0) {
		err("fail to send cmdu %04x over ubus\n", cmdu_get_type(cmdu));
		goto error;
	}

	msgid = ret;

	old_mid = cmdu_get_mid(cmdu);
	if (old_mid == 0)
		cmdu_set_mid(cmdu, msgid);
	else if (old_mid != msgid)
		warn("msgid differs %d %d for cmdu %04x\n", old_mid, msgid,
		     cmdu_get_type(cmdu));

	if (cookie) {
		ret = cmdu_ackq_enqueue(&a->cmdu_ack_q, resp_type,
					cmdu_get_mid(cmdu), cmdu->origin,
					CMDU_DEFAULT_TIMEOUT, resend_num,
					cookie);
		if (ret < 0) {
			err("cmdu_ackq enqueue failed\n");
			goto error;
		}
	}

	return msgid;

error:
	cmdu_free((struct cmdu_buff *) cookie);
	return 0xffff;
}


static int handle_supported_service(struct controller *c, uint8_t *almac, struct tlv *t)
{
	struct tlv_supported_service *ss;
	int i;

	if (!t)
		return -1;

	ss = (struct tlv_supported_service *) t->data;

	/* if supports agent, add to config */
	for (i = 0; i <= ss->num_services; i++) {
		if (ss->services[i] == SUPPORTED_SERVICE_MULTIAP_AGENT) {
			if (c->state == CNTLR_INIT) {
				dbg("|%s:%d| Discard ap-autoconfig search from"\
						" agent during INIT phase\n",
						__func__, __LINE__);
				return -1;
			}
		} else if (ss->services[i] == SUPPORTED_SERVICE_MULTIAP_CONTROLLER) {
			if (!memcmp(almac, c->almac, 6)) {
				trace("%s: Discard ap-autoconfig search"\
						" from self\n", __func__);
				return -1;
			}

			if (c->state == CNTLR_INIT) {
				uint32_t uci_obj;
				int res;

				trace("Disable and exit\n");
				set_value_by_string("mapcontroller",
						"controller",
						"enabled", "0",
						UCI_TYPE_STRING);

				res = ubus_lookup_id(c->ubus_ctx, "uci", &uci_obj);
				if (!res) {
					struct blob_buf bb = {0};

					/* trigger commit in order to reload mapcontroller
					* and not cause crash reports by procd
					*/

					blob_buf_init(&bb, 0);
					blobmsg_add_string(&bb, "config",
							"mapcontroller");
					res = ubus_invoke(c->ubus_ctx, uci_obj,
							"commit", bb.head,
							NULL, NULL,
							2 * 1000);
					if (res)
						err("Failed to get 'commit' (ret = %d), exit anyway\n",
								res);
					blob_buf_free(&bb);
				}

				exit(0); /* TODO: exiting! */
			} else {
				char data[128] = {0};

				snprintf(data, sizeof(data), "{\"type\":\"error\", \"reason\":\"multiple controllers\", \"data\": {\"remote_almac\":\""MACFMT"\"}}", MAC2STR(almac));
				cntlr_notify_event(c, "map.controller", data);
			}
		} else {
			dbg("|%s:%d| Invalid Supported Service value, return\n",
					__func__, __LINE__);
			return -1;
		}

		break; /* TODO: why do we need to break? */
	}

	return 0;
}

int handle_ap_autoconfig_search(void *cntlr, struct cmdu_buff *rx_cmdu,
				struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *c = (struct controller *) cntlr;
	struct tlv_autoconfig_band *freq;
	struct tlv_aladdr *aladdr;
	struct tlv *t;
	struct cmdu_buff *cmdu;
	uint8_t almac[6] = {0};
	struct tlv *tv[7][16] = {0};
	int ret = 0;
	char freq_band[8] = {0};

	t = map_cmdu_get_tlv(rx_cmdu, TLV_TYPE_AL_MAC_ADDRESS_TYPE);
	if (!t) {
		dbg("|%s:%d| Malformed topology notification!\n", __func__,
		    __LINE__);
		return -1;
	}

	aladdr = (struct tlv_aladdr *) t->data;

	memcpy(almac, aladdr->macaddr, 6);

	if (hwaddr_is_zero(almac)) {
		trace("%s: Discard ap-autoconfig search from aladdr = 0!\n",
			__func__);

		return -1;
	}

	n = cntlr_add_node(c, almac);
	if (!n) {
		err("|%s:%d| node allocation for "MACFMT" failed!\n",
		      __func__, __LINE__, MAC2STR(almac));
		return -1;
	}

	cntlr_set_link_profile(c, n, rx_cmdu);

	if (!validate_ap_autoconfig_search(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_SEARCH] failed\n");
		return -1;
	}

	// todo: handle tv[6] i.e. MAP_TLV_DPP_CHIRP_VALUE
	if (tv[1][0]->data[0] != IEEE80211_ROLE_REGISTRAR) {
		trace("%s: Discard ap-autoconfig search for role != registrar\n",
			__func__);
		return -1;
	}

	freq = (struct tlv_autoconfig_band *)tv[2][0]->data;
	if (freq->band != IEEE80211_FREQUENCY_BAND_2_4_GHZ &&
	    freq->band != IEEE80211_FREQUENCY_BAND_5_GHZ &&
	    freq->band != IEEE80211_FREQUENCY_BAND_6_GHZ) {
		trace("%s: Discard ap-autoconfig search for invalid WiFi band %d\n",
			__func__, freq->band);
		return -1;
	}

	if (freq->band == IEEE80211_FREQUENCY_BAND_2_4_GHZ) {
		if (!c->cfg.has_registrar_2g)
			return -1;
	} else if (freq->band == IEEE80211_FREQUENCY_BAND_5_GHZ) {
		if (!c->cfg.has_registrar_5g)
			return -1;
	} else if (freq->band == IEEE80211_FREQUENCY_BAND_6_GHZ) {
		if (!c->cfg.has_registrar_6g)
			return -1;
	} else
		return -1;

	switch (freq->band) {
	case IEEE80211_FREQUENCY_BAND_2_4_GHZ:
		sprintf(freq_band, "%d", 2);
		break;
	case IEEE80211_FREQUENCY_BAND_5_GHZ:
		sprintf(freq_band, "%d", 5);
		break;
	case IEEE80211_FREQUENCY_BAND_6_GHZ:
		sprintf(freq_band, "%d", 6);
		break;
	default:
		return -1;
	}

	/* SupportedService TLV */
	if (tv[3][0])
		handle_supported_service(c, almac, tv[3][0]);

	trace("%s: sending autoconfig response for band = %d, node %p\n",
			__func__, freq->band, n);
	cmdu = cntlr_gen_ap_autoconfig_response(cntlr, almac,
			freq->band,
			cmdu_get_mid(rx_cmdu));
	if (!cmdu)
		return -1;

	ret = send_cmdu(c, cmdu);

	cmdu_free(cmdu);

	UNUSED(ret);

	return 0;
}

/* disable and quit on controller response */
int handle_ap_autoconfig_response(void *cntlr, struct cmdu_buff *rx_cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	struct controller *c = (struct controller *) cntlr;
	bool has_cntlr = false;
	struct tlv *tv[7][16] = {0};
	int self_response = !memcmp(rx_cmdu->origin, c->almac, 6);

	cntlr_set_link_profile(c, n, rx_cmdu);

	if (!validate_ap_autoconfig_response(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_RESPONSE] failed\n");
		return -1;
	}
	/*
	 * todo:
	 * 4: MAP_TLV_1905_SECURITY_CAPS
	 * 5: MAP_TLV_DPP_CHIRP_VALUE\
	 * 6: MAP_TLV_CONTROLLER_CAPS
	 *
	 */

	/* find if supported services containts controller */
	if (tv[2][0]) {
		int i;

		for (i = 0; i < tv[2][0]->data[0]; i++) {
			if (tv[2][0]->data[(i+1)] ==
					SUPPORTED_SERVICE_MULTIAP_CONTROLLER) {
				has_cntlr = true;
				break;
			}
		}
	}

	/* if does not support controller - return */
	if (!has_cntlr) {
		dbg("autoconfig response does not support controller!\n");
		return -1;
	}


	/* discard self response */
	if (self_response)
		return 0;

	trace("Received AP-Autoconfig Response which was not from self, EMP %d\n", n->map_profile);

	if (c->state == CNTLR_INIT) {
		uint32_t uci_obj;
		int res;

		trace("Disable and exit\n");
		set_value_by_string("mapcontroller", "controller", "enabled", "0",
				UCI_TYPE_STRING);
		res = ubus_lookup_id(c->ubus_ctx, "uci", &uci_obj);
		if (!res) {
			struct blob_buf bb = {0};

			/* trigger commit in order to reload mapcontroller
			 * and not cause crash reports by procd
			 */

			blob_buf_init(&bb, 0);
			blobmsg_add_string(&bb, "config",
					"mapcontroller");
			res = ubus_invoke(c->ubus_ctx, uci_obj,
					"commit", bb.head,
					NULL, NULL,
					2 * 1000);
			if (res)
				err("Failed to get 'commit' (ret = %d), "\
					"exit anyway\n", res);
			blob_buf_free(&bb);
		}

		exit(0);
	} else {
		char data[128] = {0};

		snprintf(data, sizeof(data), "{\"type\":\"error\", \"reason\":\"multiple controllers\", \"data\": {\"remote_almac\":\""MACFMT"\"}}", MAC2STR(rx_cmdu->origin));
		cntlr_notify_event(c, "map.controller", data);
	}

	return 0;
}

int handle_ap_autoconfig_wsc(void *cntlr, struct cmdu_buff *rx_cmdu,
			     struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *c = (struct controller *) cntlr;
	struct cmdu_buff *cmdu;
	struct tlv *tv[4][16] = {0};
	struct tlv_ap_radio_basic_cap *ap_caps;
	uint8_t wildcard[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
	struct node_policy *np;

	if (!validate_ap_autoconfig_wsc(rx_cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_AUTOCONFIG_WSC] failed\n");
		return -1;
	}

	ap_caps = (struct tlv_ap_radio_basic_cap *) tv[0][0]->data;

	trace("%s: prepare autoconfig wsc response\n", __func__);
	cmdu = cntlr_gen_ap_autoconfig_wsc(cntlr, rx_cmdu, ap_caps->radio,
					   tv[3][0], cmdu_get_mid(rx_cmdu));
	if (!cmdu)
		return -1;

	send_cmdu(c, cmdu);

	cmdu_free(cmdu);

	np = agent_find_policy(c, rx_cmdu->origin);
	if (!np) {
		dbg("|%s:%d| missing node policy for node almac:" MACFMT \
		    "not sending policy config request\n", __func__, __LINE__,
		    MAC2STR(rx_cmdu->origin));
		return -1;
	}

	trace("%s: sending policy config request\n", __func__);
	cmdu = cntlr_gen_policy_config_req(cntlr, rx_cmdu->origin, np, 1,
			ap_caps->radio, 1, wildcard);
	if (!cmdu)
		return -1;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);
	return 0;
}

#define REASON_STA_ASSOC_BSS 0x01
int handle_1905_ack(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *c = (struct controller *) cntlr;
	struct tlv *tv[1][16] = {0};
	int idx;

	trace("parsing 1905 ack |" MACFMT "|\n", MAC2STR(cmdu->origin));

	if (!validate_1905_ack(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [CMDU_1905_ACK] failed, ifce \"%s\"\n",
				cmdu->dev_ifname);
		return -1;
	}

	idx = 0;
	while (tv[0][idx]) {
		struct tlv_error_code *data;
		struct tlv *t = (struct tlv *)tv[0][idx++];
		uint16_t mid = cmdu_get_mid(cmdu);
		struct sta *s;


		data = (struct tlv_error_code *)t->data;

		/* Update failed steer attempts in case one tries to
		 * assoc control STA that has been associated.
		 */
		if (data->reason == REASON_STA_ASSOC_BSS) {
			s = cntlr_find_sta(c, data->macaddr);
			if (!s)
				continue;

			dbg("%s: cmdu->cdata->hdr.mid %u\n", __func__, mid);

			if (s->latest_assoc_cntrl_mid == mid)
				s->de_sta->mapsta.stats.failed_steer_attempts++;

		}
	}

	return 0;
}

static void cntlr_scan_caps_opclass_dump(struct wifi_radio_scan_capabilities *scan_caps)
{
	int i, j;

	dbg(">>> scan caps: opclass num: %d\n", scan_caps->opclass.num_opclass);
	for (i = 0; i < scan_caps->opclass.num_opclass; i++) {
		dbg("opclass: %u\n", scan_caps->opclass.opclass[i].id);
		for (j = 0; j < scan_caps->opclass.opclass[i].num_channel; j++) {
			dbg("\tchan %u\n", scan_caps->opclass.opclass[i].channel[j].channel);
		}
	}
	dbg("<<<\n");
}

/* Issue initial channel scan based upon received scan capabilities */
static void cntlr_initial_channel_scan_from_caps(struct controller *c, struct node *n,
		uint8_t (*macs)[6], int num_radio)
{
	trace("%s: --->\n", __func__);

	struct scan_req_data srd = {};
	struct netif_radio *r = NULL;
	int i;

	for (i = 0; i < num_radio; i++) {
		r = find_radio_by_node(c, n, macs[i]);
		if (!r)
			/* no such radio - try next */
			continue;

		/* TODO: improve by scanning when newest tsp gets old enough */

		/* There're no scan results - mark for initial channel scan */
		if (list_empty(&r->radio_el->scanlist)) {
			int j;

			if (r->radio_el->scan_caps.boot_only)
				srd.is_fresh_scan = false;
			else
				srd.is_fresh_scan = true;

			/* TODO: utilize scan_caps's impact */

			memcpy(&srd.radios[srd.num_radio].radio_mac,
					r->radio_el->macaddr,
					6);

			/* limitation of bottom layers - only one opclass can be scanned */
			if (r->radio_el->scan_caps.opclass.num_opclass > 1)
				warn("%s: only first opclass from the caps will get scanned\n", __func__);
			srd.radios[srd.num_radio].num_opclass = 1;
			srd.radios[srd.num_radio].opclasses[0].classid =
				r->radio_el->scan_caps.opclass.opclass[0].id;

			srd.radios[srd.num_radio].opclasses[0].num_channel =
				r->radio_el->scan_caps.opclass.opclass[0].num_channel;

			for (j = 0; j < r->radio_el->scan_caps.opclass.opclass[0].num_channel; j++) {
				srd.radios[srd.num_radio].opclasses[0].channels[j] =
					r->radio_el->scan_caps.opclass.opclass[0].channel[j].channel;
			}

			srd.num_radio++;
		}
	}
	/* Issue channel scan for all radios at once */
	cntlr_send_channel_scan_request(c, n->alid, &srd);
}

/* Check Channel Scan Capabilities TLV */
static int cntlr_parse_radio_scan_caps(struct controller *c, struct node *n,
		struct tlv *t)
{
	struct tlv_channel_scan_capability *tlv;
	uint8_t *tv_data;
	int i, j, k, offset = 0;
	uint8_t radio_id[MAX_NUM_RADIO][6] = {};
	int num_radio = 0;

	tlv = (struct tlv_channel_scan_capability *)t->data;
	tv_data = (uint8_t *)tlv;

	offset += sizeof(*tlv); /* num_radio */

	for (i = 0; i < tlv->num_radio; i++) {
		struct netif_radio *nr;
		struct wifi_radio_scan_capabilities caps;
		struct channel_scan_capability_radio *csr =
			(struct channel_scan_capability_radio *)&tv_data[offset];

		caps.boot_only = !!(csr->cap & SCAN_CAP_ON_BOOT_ONLY);
		caps.impact = !!(csr->cap & SCAN_CAP_IMPACT);
		caps.interval = csr->min_scan_interval;

		caps.opclass.num_opclass = csr->num_opclass;

		offset += sizeof(*csr); /* radio, cap, min_scan_interval, num_opclass */

		for (j = 0; j < csr->num_opclass; j++) {
			struct channel_scan_capability_opclass *opc =
				(struct channel_scan_capability_opclass *)&tv_data[offset];

			caps.opclass.opclass[j].id = opc->classid;
			caps.opclass.opclass[j].num_channel = opc->num_channel;

			offset += sizeof(*opc); /* classid & num_channel */

			for (k = 0; k < opc->num_channel; k++) {
				caps.opclass.opclass[j].channel[k].channel = opc->channel[k];
			}

			offset += opc->num_channel;
		}

		/* scan capabilities debug dump */
		cntlr_scan_caps_opclass_dump(&caps);

		nr = find_radio_by_node(c, n, csr->radio);
		if (!nr)
			/* no such radio - try next */
			continue;

		/* updt caps: no pointers - let the compiler optimize */
		nr->radio_el->scan_caps = caps;


		/* put addr into an array of radio MACs to be scanned */
		if (c->cfg.initial_channel_scan)
			memcpy(&radio_id[num_radio],
					nr->radio_el->macaddr,
					6);

		num_radio++;
	}

	/* issue a channel scan on reported radios */
	if (c->cfg.initial_channel_scan)
		cntlr_initial_channel_scan_from_caps(c, n, radio_id, num_radio);

	return 0;
}

int handle_ap_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	trace("parsing AP capabilities of |" MACFMT "|\n", MAC2STR(cmdu->origin));
	int index = 0;
	int i = 0;
	int offset = 0;
	struct controller *c = (struct controller *) cntlr;
	struct tlv *tv[13][16];

	if (!validate_ap_caps_report(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_CAPS_REPORT] failed, ifce \"%s\"\n",
				cmdu->dev_ifname);
		return -1;
	}
	/*
	 * todo: handle tlv[9] .. [12]
	 * 	MAP_TLV_AP_WIFI6_CAPS, MAP_TLV_1905_SECURITY_CAPS, MAP_TLV_DEVICE_INVENTORY,
	 * 	and MAP_TLV_AP_RADIO_ADV_CAPABILITY
	 *
	 *  debug_ap_caps_report() does this.
	 */

	/* AP Capability TLV */
	if (tv[0][0]) {
		struct tlv_ap_cap *p = (struct tlv_ap_cap *)tv[0][0]->data;

		dbg("%s %d AP capability is 0x%02x\n", __func__, __LINE__, p->cap);
		n->ap_cap = p->cap;
	}

	index = 0;
	/* Parse AP Radio Basic Capabilities TLV */
	while (tv[1][index] && (index < 16)) {
		struct wifi_radio_opclass e4 = {};
		struct wifi_radio_opclass *opclass;
		struct netif_radio *r;
		struct wifi_radio_element *re;
		uint8_t *tv_data = (uint8_t *)tv[1][index++]->data;
		struct tlv_ap_radio_basic_cap *p =
			(struct tlv_ap_radio_basic_cap *)tv_data;
		int j, k;

		r = find_radio_by_node(c, n, p->radio);
		if (!r)
			continue;

		re = r->radio_el;
		opclass = &re->supp_opclass;

		wifi_opclass_e4(&e4);
		wifi_opclass_reset(opclass);

		offset = sizeof(*p);

		/* k */
		for (i = 0; i < p->num_opclass; i++) {
			struct ap_radio_basic_cap_opclass *op =
				(struct ap_radio_basic_cap_opclass *)&tv_data[offset];
			struct wifi_radio_opclass_entry *e4_entry;
			struct wifi_radio_opclass_entry *entry;
			struct wifi_radio_opclass_channel *channel;

			e4_entry = wifi_opclass_find_entry(&e4, op->classid);
			if (!e4_entry)
				continue;

			/* m  == 0 - all channels supported */
			if (op->num_nonop_channel == 0) {
				wifi_opclass_add_entry(opclass, e4_entry);
				wifi_opclass_id_set_preferences(opclass, e4_entry->id, WIFI_RADIO_OPCLASS_MOST_PREFERRED);
				offset += sizeof(*op);
				continue;
			}

			/* Create new entry */
			entry = wifi_opclass_new_entry(opclass);
			if (!entry)
				continue;

			entry->id = e4_entry->id;
			entry->bandwidth = e4_entry->bandwidth;
			entry->max_txpower = op->max_txpower;

			for (j = 0; j < e4_entry->num_channel; j++) {
				channel = &e4_entry->channel[j];
				for (k = 0; k < op->num_nonop_channel; k++) {
					if (channel->channel == op->nonop_channel[k])
						break;
				}

				if (k != op->num_nonop_channel)
					channel->preference = WIFI_RADIO_OPCLASS_NON_OPERABLE;
				else
					channel->preference = WIFI_RADIO_OPCLASS_MOST_PREFERRED;

				wifi_opclass_add_channel(entry, channel);
			}

			offset += sizeof(*op) + op->num_nonop_channel;
		}

		wifi_opclass_dump(opclass);
	}


	index = 0;
	/* AP HT Capabilities TLV */
	while (tv[2][index] && (index < 16)) {
		struct netif_radio *r;
		uint8_t *tv_data = (uint8_t *)tv[2][index++]->data;
		struct tlv_ap_ht_cap *ht_caps =
			(struct tlv_ap_ht_cap *)tv_data;

		r = find_radio_by_node(c, n, ht_caps->radio);
		if (!r)
			continue;

		r->radio_el->caps.ht = ht_caps->cap;
	}

	index = 0;
	/* AP VHT Capabilities TLV */
	while (tv[3][index] && (index < 16)) {
		struct netif_radio *r;
		uint8_t *tv_data = (uint8_t *)tv[3][index++]->data;
		struct tlv_ap_vht_cap *vht_caps =
			(struct tlv_ap_vht_cap *)tv_data;

		r = find_radio_by_node(c, n, vht_caps->radio);
		if (!r)
			continue;

		/* TODO: update when caps.vht is defined as separate fields */
		memcpy(r->radio_el->caps.vht, tv_data + sizeof(vht_caps->radio),
		       sizeof(r->radio_el->caps.vht));
	}

	offset = 0;
	index = 0;
	/* AP HE Capabilities TLV */
	while (tv[4][index] && (index < 16)) {
		struct netif_radio *r;
		uint8_t *tv_data = (uint8_t *)tv[4][index++]->data;
		struct tlv_ap_he_cap *he_caps =
			(struct tlv_ap_he_cap *)tv_data;

		r = find_radio_by_node(c, n, he_caps->radio);
		if (!r)
			continue;

		offset += sizeof(he_caps->radio);

		/* TODO: update when caps.he is defined as separate fields */
		r->radio_el->caps.he[0] = he_caps->hemcs.len;

		offset += sizeof(he_caps->hemcs.len);

		memcpy(&(r->radio_el->caps.he[1]), tv_data + offset, he_caps->hemcs.len);

		offset += he_caps->hemcs.len;

		memcpy(&(r->radio_el->caps.he[1 + he_caps->hemcs.len]), tv_data + offset, 2);
	}

	/* Channel scan capabilities TLV */
	if (tv[5][0])
		cntlr_parse_radio_scan_caps(c, n, tv[5][0]);

	return 0;
}

int handle_channel_pref_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int idx, offset = 0;
	int i, j;
	struct tlv *tv[4][16] = { 0 };
	struct netif_radio *r;
	int ret;

	trace("%s: --->\n", __func__);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 4, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx = 0;
	while (tv[0][idx]) {
		struct tlv *t = (struct tlv *)tv[0][idx++];
		uint8_t mac[6] = { 0 };
		int num_opclass;

		offset = 0;
		memcpy(mac, &t->data[offset], 6);
		offset += 6;
		num_opclass = t->data[offset++];

		r = find_radio_by_node(cntlr, n, mac);
		if (!r)
			continue;

		cntlr_radio_pref_opclass_reset(r->radio_el);

		for (i = 0; i < num_opclass; i++) {
			uint8_t opclass;
			uint8_t num_channel;
			uint8_t preference;
			uint8_t channel;

			opclass = t->data[offset++];
			num_channel = t->data[offset++];		/* k */
			preference = t->data[offset + num_channel];

			if (num_channel == 0) {
				/* k == 0 */
				cntlr_radio_pref_opclass_set_pref(r->radio_el, opclass, preference);
			} else {
				for (j = 0; j < num_channel; j++) {
					channel = t->data[offset++];
					if (cntlr_radio_pref_opclass_add(r->radio_el, opclass, channel, preference))
						warn("opclass_add %u %u %u failed\n", opclass, channel, preference);
				}
			}

			/* last preference - simple move offset */
			offset++;

		}

		cntlr_radio_pref_opclass_dump(r->radio_el);
	}

	return 0;
}

int handle_channel_sel_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_oper_channel_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int idx = 0;
	struct controller *c = (struct controller *) cntlr;
	int ret;
	struct tlv *tv[2][16];
	/*
	 * [0] MAP_TLV_OPERATING_CHANNEL_REPORT
	 * todo:
	 * [1] MAP_TLV_SPATIAL_REUSE_REPORT
	 */

	trace("%s: --->\n", __func__);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs ( ..,EMP=%d) failed,  err = (%d) '%s'\n", __func__,
		    n->map_profile, map_error, map_strerror(map_error));
		return ret;
	}

	while (tv[0][idx]) {
		int i;
		int offset = 0;
		uint8_t mac[6] = {0};
		uint8_t *p = (uint8_t *)tv[0][idx++]->data;
		struct netif_radio *r;
		uint8_t channel;
		uint8_t opclass;
		uint8_t txpower;
		int num_opclass;

		memcpy(mac, &p[offset], 6);
		offset += 6;

		r = find_radio_by_node(c, n, mac);
		if (!r) {
			r = cntlr_node_add_radio(c, n, mac);
			if (!r)
				continue;
		}

		/* Reset current settings */
		cntlr_radio_cur_opclass_reset(r->radio_el);

		num_opclass = p[offset++];
		txpower = p[offset + 2 * num_opclass];
		for (i = 0; i < num_opclass; i++) {
			opclass = p[offset++];
			channel = p[offset++];
			if (WARN_ON(cntlr_radio_cur_opclass_add(r->radio_el, opclass, channel, txpower)))
				continue;
		}
		offset++;

		cntlr_radio_cur_opclass_dump(r->radio_el);
	}

	return 0;
}

int handle_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
//	trace("parsing AP capabilities of |%s:" MACFMT "|\n",
//			cmdu->intf_name, MAC2STR(cmdu->origin));
	return 0;
}

int handle_ap_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	int idx, index;
	struct controller *c = (struct controller *) cntlr;
	//struct netif_radio *r;
	struct netif_iface *ifc;
	struct wifi_bss_element *b;
	//struct link_metrics *link;
	struct tlv *tv[7][16] = { 0 };
	struct tlv_ap_metrics *p;

	if (!cmdu) {
		trace("error: NO CMDU\n");
		return -1;
	}

	trace("Storing AP metrics of |" MACFMT "|\n", MAC2STR(cmdu->origin));

	// todo: tv[6] i.e. MAP_TLV_ASSOCIATED_WIFI6_STA_STATUS

	if (!validate_ap_metrics_response(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [AP_METRICS_RESPONSE] failed, ifce \"%s\"\n",
				cmdu->dev_ifname);
		return -1;
	}

	/* Storing AP Metrics TLV */
	idx = 0;
	while (tv[0][idx]) {
		p = (struct tlv_ap_metrics *) tv[0][idx++]->data;
		if (!p)
			continue;

		ifc = cntlr_iterate_fbss(c, p->bssid);
		if (!ifc)
			continue;

		b = ifc->bss;
		b->ch_util = p->channel_utilization;
		b->num_stations = p->num_station;
		/* Estimated service parameter fields for AC */
		b->esp_ac = p->esp_ac;

		/* AC=BE is mandatory */
		if (p->esp_ac & ESP_AC_BE)
			memcpy(b->est_wmm_be, p->esp_be, 3);
		else
			/* Easy Mesh Spec 17.2.22: "This field shall be set to one" */
			dbg("|%s %d| AC=BE is not set in TLV\n", __func__, __LINE__);

		/* Optional (0 or 3 octets) for AC=BK, AC=VO & AC=VI */
		index = 0;
		if (p->esp_ac & ESP_AC_BK) {
			memcpy(b->est_wmm_bk, p->esp + index, 3);
			index += 3;
		}
		if (p->esp_ac & ESP_AC_VO) {
			memcpy(b->est_wmm_vo, p->esp + index, 3);
			index += 3;
		}
		if (p->esp_ac & ESP_AC_VI)
			memcpy(b->est_wmm_vi, p->esp + index, 3);
	}

		/* trying to print out what is stored */
		// size_t out_len;
		// index = 0;
		// list_for_each_entry(n, &c->nodelist, list) {
		// list_for_each_entry(r, &n->radiolist, list) {
		// list_for_each_entry(ifc, &r->iflist, list) {

		// b = ifc->bss;
		// unsigned char est_str[16];
		// trace("STORED:\n");
		// trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
		// trace("\tchannel_utilization: %d\n", b->ch_util);
		// trace("\tnum_station: %d\n", BUF_GET_BE16(b->num_stations));
		// trace("\tesp_ac: %d\n", b->esp_ac);
		// if (b->esp_ac & ESP_AC_BE) {
		// 	out_len = sizeof(est_str);
		// 	memset(est_str, 0, sizeof(est_str));
		// 	base64_encode(b->est_wmm_be, 3, est_str, &out_len);
		// 	trace("\tservice_param_info_be:%s\n", (char *)est_str);
		// }
		// if (b->esp_ac & ESP_AC_BK) {
		// 	out_len = sizeof(est_str);
		// 	memset(est_str, 0, sizeof(est_str));
		// 	base64_encode(b->est_wmm_bk, 3, est_str, &out_len);
		// 	trace("\tservice_param_info_bk:%s\n", (char *)est_str);
		// 	index += 3;
		// }
		// if (b->esp_ac & ESP_AC_VO) {
		// 	out_len = sizeof(est_str);
		// 	memset(est_str, 0, sizeof(est_str));
		// 	base64_encode(b->est_wmm_vo, 3, est_str, &out_len);
		// 	trace("\tservice_param_info_vo:%s\n", (char *)est_str);
		// 	index += 3;
		// }
		// if (b->esp_ac & ESP_AC_VI) {
		// 	out_len = sizeof(est_str);
		// 	memset(est_str, 0, sizeof(est_str));
		// 	base64_encode(a->est_wmm_vi, 3, est_str, &out_len);
		// 	trace("\tservice_param_info_vi:%s\n", (char *)est_str);
		// }
		// }}}

	return 0;
}

static int cntlr_request_usta_metrics(struct controller *c,
		struct node *n, struct sta *s)
{
	struct cmdu_buff *usta_cmdu = NULL;
	struct unassoc_sta_metric metrics[1] = {};
	struct netif_radio *r;
	struct netif_iface *fh;
	int j;

	trace("%s: --->\n", __func__);

	if (!n || !s)
		return -1;

	trace("%s %d ap_cap = 0x%02x\n", __func__, __LINE__, n->ap_cap);

	if (n->ap_cap & UNASSOC_STA_REPORTING_OFFCHAN)
		/* TODO: off channel measurements */
		dbg("%s: Offchannel Unassoc STA metric not supported", __func__);

	if (n->ap_cap & UNASSOC_STA_REPORTING_ONCHAN) {

		r = find_radio_by_ssid(c, n, s->fh->bss->ssid);
		fh = find_interface_by_ssid(c, n, s->fh->bss->ssid);

		if (!r || !fh)
			return -1;

		for (j = 0; j < r->radio_el->cur_opclass.num_opclass; j++) {
			/* TODO: refactor to allow more than one channel */
			metrics[0].channel = r->radio_el->cur_opclass.opclass[0].channel[0].channel;
			metrics[0].num_sta = 1;
			memcpy(metrics[0].sta[0].macaddr, s->de_sta->macaddr, 6);

			usta_cmdu = cntlr_gen_unassoc_sta_metric_query(c,
					n->alid, r->radio_el->cur_opclass.opclass[j].id, 1, metrics);

			if (usta_cmdu) {
				send_cmdu(c, usta_cmdu);
				cmdu_free(usta_cmdu);
			}
		}

	} else {
		dbg("%s: Unassoc STA metric not supported by " MACFMT "\n",
		    __func__, MAC2STR(n->alid));
	}

	return 0;
}

static void cntlr_request_bcn_metrics_bsta(struct controller *c, struct sta *s)
{
	struct cmdu_buff *bcn_cmdu;
	uint8_t wildcard[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

	dbg("%s: --->\n", __func__);

	bcn_cmdu = cntlr_gen_beacon_metrics_query(c,
			s->fh->agent->alid, s->de_sta->macaddr, 0, 0,
			wildcard, 0, s->fh->bss->ssid, 0, NULL, 0, NULL);

	if (bcn_cmdu) {
		send_cmdu(c, bcn_cmdu);
		cmdu_free(bcn_cmdu);
	}
}

static int cntlr_request_bcn_metrics_sta(struct controller *c, struct sta *s)
{
	struct cmdu_buff *bcn_cmdu;
	uint8_t wildcard[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
	uint8_t opclass = 0;
	uint8_t channel = 0;
	struct sta_channel_report *reports = NULL;
	struct netif_radio *nr;
	struct steering *sp;
	uint8_t num_report = 0;
	struct {
		uint8_t	opclass;
		uint8_t	channel;
	} op_ch[16];
	uint8_t opc;
	int i;

	trace("%s: --->\n", __func__);

	nr = find_radio_by_bssid(c, s->bssid);
	if (!nr)
		return -1;

	sp = &c->steer_params;

	dbg("|%s:%d| channels_num = %d\n", __func__, __LINE__, sp->channels_num);

	if (sp->channels_num < 1 || sp->channels_num > 16)
		return -1;

	if (sp->channels_num == 1) {
		/* won't use channel report */
		opclass = cntlr_get_classid_ht20(nr->radio_el, sp->channels[0]); /* /20 */
		if (!opclass)
			return -1;
		channel = sp->channels[0];
		num_report = 0;
	} else {
		opclass = 0;
		channel = 255; /* use channel report */
		for (i = 0; i < sp->channels_num; i++) {
			opc = cntlr_get_classid_ht20(nr->radio_el, sp->channels[i]);
			if (!opc)
				continue;
			op_ch[num_report].opclass = opc;
			op_ch[num_report].channel = sp->channels[i];
			num_report++;
		}

		if (!num_report)
			return -1;

		reports = calloc(num_report, sizeof(struct sta_channel_report));
		if (!reports)
			return -ENOMEM;

		for (i = 0; i < num_report; i++) {
			reports[i].opclass = op_ch[i].opclass;
			reports[i].num_channel = 1;
			reports[i].channel[0] = op_ch[i].channel;
		}
	}

	dbg("|%s:%d| alid " MACFMT " s->de_sta->macaddr " MACFMT " num_report = %d\n",
	    __func__, __LINE__,
	    MAC2STR(s->fh->agent->alid),
	    MAC2STR(s->de_sta->macaddr),
	    num_report);

	bcn_cmdu = cntlr_gen_beacon_metrics_query(c,
			s->fh->agent->alid, s->de_sta->macaddr,
			opclass, channel,
			wildcard, 0, s->fh->bss->ssid,
			num_report, reports, 0, NULL);

	if (bcn_cmdu) {
		send_cmdu(c, bcn_cmdu);
		cmdu_free(bcn_cmdu);
	}

	if (reports)
		free(reports);

	/* returns expected number of requests in agents */
	return (num_report ? num_report : 1);
}

static int update_txlink_metric_data(struct controller *c, struct tlv_tx_linkmetric *txl, int len)
{
	int i = 0;
	int size = 0;
	struct tx_link_info *txlinfo;
	struct netif_link *txlink;
	struct link_metrics *metrics;

	/* For each tx link in the mesg */
	size = len - (sizeof(struct tlv_tx_linkmetric));
	size = size / (sizeof(struct tx_link_info));
	for (i = 0; i < size; i++) {
		txlinfo = (struct tx_link_info *)&txl->link[i];
		/* Find or alloc the backhaul link to the controller */
		txlink = alloc_link_init(c, txlinfo->local_macaddr, txlinfo->neighbor_macaddr);
		if (!txlink) {
			trace("No link!\n");
			return -1;
		}
		metrics = txlink->metrics;
		metrics->l = txlink;
		memcpy(metrics->l->upstream->bss->bssid, txlinfo->local_macaddr, 6);
		memcpy(metrics->l->downstream->bss->bssid, txlinfo->neighbor_macaddr, 6);
		metrics->type = BUF_GET_BE16(txlinfo->mediatype);
		metrics->bridge = txlinfo->has_bridge;
		metrics->packet_tx_error = BUF_GET_BE32(txlinfo->errors);
		metrics->packet_trans = BUF_GET_BE32(txlinfo->packets);
		metrics->thp = BUF_GET_BE16(txlinfo->max_throughput);
		metrics->link_av = BUF_GET_BE16(txlinfo->availability);
		metrics->phy_rate = BUF_GET_BE16(txlinfo->phyrate);
	}
	c->num_tx_links += size;
	return 0;
}

static int update_rxlink_metric_data(struct controller *c, struct tlv_rx_linkmetric *rxl, int len)
{
	int i = 0;
	int size = 0;
	struct rx_link_info *rxlinfo;
	struct netif_link *rxlink;
	struct link_metrics *metrics;

	/* For each rx link in the mesg */
	size = len - (sizeof(struct tlv_rx_linkmetric));
	size = size / (sizeof(struct rx_link_info));
	for (i = 0; i < size; i++) {
		rxlinfo = (struct rx_link_info *)&rxl->link[i];
		/* Find or alloc the backhaul link to the controller */
		rxlink = alloc_link_init(c, rxlinfo->local_macaddr, rxlinfo->neighbor_macaddr);
		if (!rxlink) {
			trace("No link!\n");
			return 0;
		}
		metrics = rxlink->metrics;
		metrics->l = rxlink;
		memcpy(metrics->l->upstream->bss->bssid, rxlinfo->local_macaddr, 6);
		memcpy(metrics->l->downstream->bss->bssid, rxlinfo->neighbor_macaddr, 6);
		metrics->type = BUF_GET_BE16(rxlinfo->mediatype);
		metrics->packet_rec = BUF_GET_BE32(rxlinfo->packets);
		metrics->packet_rx_error = BUF_GET_BE32(rxlinfo->errors);
		metrics->rssi = rxlinfo->rssi;
	}
	c->num_rx_links += size;
	return 0;
}

/* selfdevice link metrics */
int handle_link_metrics_response(struct controller *c, struct cmdu_buff *cmdu,
				 struct node *n)
{
	trace("%s: --->\n", __func__);
	struct tlv *tv[2][16];
	int num = 0;
	int ret;

	if (cmdu == NULL || c == NULL)
		return -1;

	/* Reset number of links */
	c->num_tx_links = 0;
	c->num_rx_links = 0;

	/* Parsing 1905 Link Metrics TLV */
	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	/* Storing 1905 Link Metrics TLV */
	while (tv[0][num]) {
		struct tlv_tx_linkmetric *txl =
			(struct tlv_tx_linkmetric *)tv[0][num]->data;

		if (hwaddr_is_zero(txl->aladdr) ||
			hwaddr_is_zero(txl->neighbor_aladdr)) {
			trace("%s: Discard Tx-link response\n", __func__);
			return -1;
		}
		/* Storing tx 1905 Link Metric data */
		ret = update_txlink_metric_data(c, txl, BUF_GET_BE16(tv[0][num]->len));
		if (ret) {
			trace("|update_txlink_metric_data| Link not found!\n");
			return -1;
		}
		num++;
	}

	num = 0;
	while (tv[1][num]) {
		struct tlv_rx_linkmetric *rxl =
			(struct tlv_rx_linkmetric *)tv[1][num]->data;

		if (hwaddr_is_zero(rxl->aladdr) ||
			hwaddr_is_zero(rxl->neighbor_aladdr)) {
			trace("%s: Discard Tx-link response\n", __func__);
			return -1;
		}
		/* Storing rx 1905 Link Metric data */
		ret = update_rxlink_metric_data(c, rxl, BUF_GET_BE16(tv[0][num]->len));
		if (ret) {
			trace("|update_txlink_metric_data| Link not found!\n");
			return -1;
		}
		num++;
	}

	return 0;
}

int handle_sta_link_metrics_response(void *cntlr, struct cmdu_buff *cmdu,
				     struct node *n)
{
	int i, idx = 0;
	int offset = 0;
	struct controller *c = (struct controller *) cntlr;
	struct tlv *tv[3][16] = { 0 };
	int ret;

	trace("%s: --->\n", __func__);

	dbg("parsing sta link metric response |" MACFMT ", node %p\n",
			MAC2STR(cmdu->origin), n);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	/* TODO: use while[0][idx]*/
	if (tv[0][0]) {
		struct sta *s;
		uint8_t *tv_data = (uint8_t *)tv[0][0]->data;
		struct tlv_assoc_sta_link_metrics *p =
			(struct tlv_assoc_sta_link_metrics *)tv_data;
		struct netif_radio *r;
		struct radio_policy *rp;
		struct steer_control_config *scc;

		scc = get_steer_control_config(c);
		if (!scc)
			return -1;

		s = cntlr_find_sta(c, p->macaddr);
		if (!s)
			return -1;

		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct assoc_sta_link_metrics_bss *b =
				(struct assoc_sta_link_metrics_bss *)&tv_data[offset];

			memcpy(s->bssid, b->bssid, 6);
			s->de_sta->dl_est_thput = BUF_GET_BE32(b->dl_thput);
			s->de_sta->ul_est_thput = BUF_GET_BE32(b->ul_thput);
			s->time_delta = BUF_GET_BE32(b->time_delta);
			/* Update measurement time */
			time(&s->de_sta->tsp);
			s->de_sta->rcpi = b->ul_rcpi;

			offset += sizeof(*b);
		}

		r = find_radio_by_bssid(c, s->bssid);
		if (!r)
			return -1;

		rp = agent_find_radio_policy(c, r->radio_el->macaddr);
		if (!rp)
			return -1;

		if (s->type == IEEE1905 &&
				s->de_sta->rcpi < rp->report_rcpi_threshold) {

			if (!scc->enable_bsta_steer) {
				dbg("|%s:%d| rcpi below %d, but will not query for any " \
				    "metrics as 'enable_bsta_steer' is not set!\n",
				    __func__, __LINE__, rp->rcpi_threshold);
				return 0;
			}

			/* Get bcn metrics for bsta */
			if (scc->use_bcn_metrics) {
				dbg("|%s:%d| request bcn metrics from bsta\n",
				    __func__, __LINE__);
				cntlr_mark_old_bcn_metrics(c, s);
				cntlr_request_bcn_metrics_bsta(c, s);
				/* TODO: set timeout here (?) */
			}

		} else if (s->type == NON_IEEE1905 &&
				s->de_sta->rcpi < rp->report_rcpi_threshold) {

			if (!scc->enable_sta_steer) {
				dbg("|%s:%d| rcpi below %d, but will not query for any " \
				    "metrics as 'enable_sta_steer' is not set!\n",
				    __func__, __LINE__, rp->rcpi_threshold);
				return 0;
			}

			/* Get bcn metrics */
			if (scc->use_bcn_metrics) {
				int num_req = 0;

				/* FIXME: consider dynamic timer value */
				if (timestamp_expired(&s->last_bcn_metrics_query, 20 * 1000)) {
					dbg("|%s:%d| requesting bcn metrics from sta\n",
					    __func__, __LINE__);
					cntlr_mark_old_bcn_metrics(c, s);
					num_req = cntlr_request_bcn_metrics_sta(c, s);
					if (num_req > 0) {
						timestamp_update(&s->last_bcn_metrics_query);
						timer_set(&s->bcn_metrics_timer, num_req * 3 * 1000);
					}
				} else {
					dbg("|%s:%d| skip requesting bcn metrics - up to date\n",
					    __func__, __LINE__);
				}
			}

			/* Get usta metrics for each agent in mesh */
			if (scc->use_usta_metrics) {
				struct node *no = NULL;

				dbg("|%s:%d| request usta metrics from sta\n",
				      __func__, __LINE__);
				free_usta_metrics(c, s);
				list_for_each_entry(no, &c->nodelist, list) {
					cntlr_request_usta_metrics(c, no, s);
				}
			}
		}
	}

	idx = 0;
	while (tv[2][idx]) {
		struct sta *s;
		uint8_t *tv_data = (uint8_t *)tv[2][idx]->data;
		struct tlv_sta_ext_link_metric *p =
			(struct tlv_sta_ext_link_metric *)tv_data;

		s = cntlr_find_sta(c, p->macaddr);
		if (!s)
			return -1;


		s = cntlr_find_sta(c, p->macaddr);
		if (!s)
			return -1;

		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct sta_ext_link_metric_bss *b =
				(struct sta_ext_link_metric_bss *)&tv_data[offset];

			memcpy(s->bssid, b->bssid, 6);

			s->de_sta->dl_rate = BUF_GET_BE32(b->dl_rate);
			s->de_sta->ul_rate = BUF_GET_BE32(b->ul_rate);
			s->de_sta->dl_utilization = BUF_GET_BE32(b->rx_util);
			s->de_sta->ul_utilization = BUF_GET_BE32(b->tx_util);

			offset += sizeof(*b);
		}
		idx++;
	}

	return 0;
}

int cntlr_send_1905_acknowledge(void *cntlr,
	struct cmdu_buff *rx_cmdu,
	struct sta_error_response *sta_resp, uint32_t sta_count)
{
	struct cmdu_buff *response;
	struct controller *c = (struct controller *) cntlr;

	trace("%s: --->\n", __func__);

	response = cntlr_gen_cmdu_1905_ack(c, rx_cmdu, sta_resp, sta_count);
	if (!response)
		return -1;

	send_cmdu(c, response);
	cmdu_free(response);
	return 0;
}

struct una_sta_metrics *cntlr_find_usta_metric(struct controller *c,
		struct sta *s, uint8_t *mac)
{
	struct una_sta_metrics *u = NULL;

	list_for_each_entry(u, &s->unassoclist, list) {
		dbg("%s %d mac "MACFMT" alid " MACFMT"\n", __func__, __LINE__,
				MAC2STR(u->agent->alid), MAC2STR(mac));
		if (!memcmp(u->agent->alid, mac, 6))
			return u;
	}

	return NULL;
}

#define USTA_STEER_UL_RCPI_DELTA 10

/* use unassociated STA measurements to steer */
void cntlr_check_usta_steer(struct controller *c, struct sta *s)
{
	struct una_sta_metrics *best = NULL, *u = NULL;
	struct node *n = s->fh->agent;
	struct netif_iface *best_fh;
	struct steer_control_config *scc;

	scc  = get_steer_control_config(c);
	if (!scc)
		return;

	if (!scc->use_usta_metrics) {
		dbg("%s %d Will not use unassociated STA metrics \
		    data to steer\n", __func__, __LINE__);
		return;
	}

	dbg("%s %d for "MACFMT" attached to bssid " MACFMT " node = " \
	    MACFMT "\n", __func__, __LINE__, MAC2STR(s->de_sta->macaddr),
	    MAC2STR(s->bssid), MAC2STR(n->alid));

	list_for_each_entry(u, &s->unassoclist, list) {
		dbg("%s %d check usta node "MACFMT"\n",
		    __func__, __LINE__, MAC2STR(u->agent->alid));

		if (!best) {
			best = u;
			continue;
		}

		dbg("%s %d best ul_rcpi %u this ul_rcpi %u\n", __func__, __LINE__,
				best->ul_rcpi, u->ul_rcpi);

		if ((best->ul_rcpi - u->ul_rcpi) > USTA_STEER_UL_RCPI_DELTA) {
			dbg("%s %d new best usta node "MACFMT" with ul_rcpi %d\n",
					__func__, __LINE__,
					MAC2STR(u->agent->alid),
					u->ul_rcpi);
			best = u;
		}
	}

	if (!best)
		return;

	/* Get appropriate netif on best node based on current ssid */
	best_fh = find_interface_by_ssid(c, best->agent, s->fh->bss->ssid);

	if (best_fh && !hwaddr_is_zero(best_fh->bss->bssid)
			&& memcmp(best_fh->bss->bssid, s->bssid, 6)) {

		struct cmdu_buff *cmdu;
		int ret = 0;

		if ((s->type == IEEE1905 && !scc->enable_bsta_steer) ||
		    (s->type == NON_IEEE1905 && !scc->enable_sta_steer)) {
			trace("|%s:%d| better bssid found, but will not steer "MACFMT",\
			       because the 'enable_(b)sta_steer' is not set!\n",
			       __func__, __LINE__, MAC2STR(s->de_sta->macaddr));
			return;
		}

		dbg("%s %d better bssid found! try to steer " MACFMT " \
		    from " MACFMT " to " MACFMT "\n",
		    __func__, __LINE__,
		    MAC2STR(s->de_sta->macaddr), MAC2STR(s->bssid),
		    MAC2STR(best_fh->bss->bssid));

		if (s->type == IEEE1905) {
			cmdu = cntlr_gen_backhaul_steer_request(c, s->agent->alid,
					s->de_sta->macaddr, best_fh->bss->bssid, 0, 0);
			if (cmdu) {
				send_cmdu(c, cmdu);
				cmdu_free(cmdu);
			}
		}
		else {
			ret = cntlr_send_client_steer_request(c, s->fh->agent->alid,
					s->bssid, 0,
					1, (uint8_t (*)[6])s->de_sta->macaddr,
					1, (uint8_t (*)[6])best_fh->bss->bssid,
					STEER_MODE_BTM_REQ); /* mandate */
			if (ret)
				warn("%s: Failed to send cmdu for steering sta!\n", __func__);
		}
	}
}

int handle_unassoc_sta_link_metrics_response(void *cntlr,
		struct cmdu_buff *cmdu, struct node *n)
{
	struct controller *c = (struct controller *) cntlr;
	struct tlv *tv[1][16] = {0};
	int i = 0;
	int ret = 0;

	trace("%s: --->\n", __func__);

	if (!cntlr || !cmdu)
		return -1;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	/* If a Multi-AP Controller receives an Unassociated STA
	 * Link Metrics Response message, then it shall respond
	 * within one second with a 1905 Ack message.
	 */
	cntlr_send_1905_acknowledge(cntlr, cmdu, NULL, 0);

	if (tv[0][0]) {
		int offset = 0;
		uint8_t *tv_data = (uint8_t *)tv[0][0]->data;
		struct tlv_unassoc_sta_link_metrics_resp *resp =
			(struct tlv_unassoc_sta_link_metrics_resp  *)tv_data;

		offset = sizeof(*resp);
		for (i = 0; i < resp->num_sta; i++) {
			struct una_sta_metrics *u;
			struct unassoc_sta_link_metrics_sta *b =
				(struct unassoc_sta_link_metrics_sta *)&tv_data[offset];
			/* TODO: use wifi_radio_element.unassoc_stalist */
			struct sta *s = cntlr_find_sta(c, b->macaddr);

			if (!s) {
				dbg("|%s:%d| unassociated STA "MACFMT" not found!\n",
				__func__, __LINE__, MAC2STR(b->macaddr));
				continue;
			}

			u = cntlr_find_usta_metric(c, s, cmdu->origin); /* alid */
			if (!u) {
				u = calloc(1, sizeof(*u));
				if (!u)
					continue;

				list_add(&u->list, &s->unassoclist);
				u->agent = cntlr_find_node(c, cmdu->origin);
				dbg("%s %d\n", __func__, __LINE__);
			}

			u->channel = b->channel;
			u->time_delta = BUF_GET_BE32(b->time_delta);
			u->ul_rcpi = b->ul_rcpi;

			trace("\t\tu->agent.alid: " MACFMT "\n", MAC2STR(u->agent->alid));
			trace("\t\tu->channel: %d\n", u->channel);
			trace("\t\tu->time_delta: %u\n",BUF_GET_BE32(u->time_delta));
			trace("\t\tu->ul_rcpi: %d\n", u->ul_rcpi);

			offset += sizeof(*b);

			/* Steer if (b)STA would benefit from it */
			cntlr_check_usta_steer(c, s);
		}
	}

	return ret;
}

int handle_beacon_metrics_response(void *cntlr, struct cmdu_buff *cmdu,
				   struct node *n)
{
	struct controller *c = (struct controller *) cntlr;
	struct tlv_beacon_metrics_resp *resp;
	struct tlv *tv[1][16] = {0};
	uint8_t *ppos;
	struct sta *s;
	struct bcnreq *br;
	bool requested = false;
	int i, ret = 0;

	trace("%s: --->\n", __func__);

	if (!cntlr || !cmdu)
		return -1;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	/* If a Multi-AP Controller receives a Beacon Metrics Response message,
	 * then it shall respond within one second with a 1905 Ack message.
	 */
	cntlr_send_1905_acknowledge(cntlr, cmdu, NULL, 0);

	resp = (struct tlv_beacon_metrics_resp *) tv[0][0]->data;

	br = cntlr_find_bcnreq(c, resp->sta_macaddr, cmdu->origin);
	if (br && !timestamp_expired(&br->tsp, br->request_num * 5 * 1000))
		/* matching request found for this response */
		requested = true;
	else {
		dbg("|%s:%d| no active request for metrics "\
			"of STA "MACFMT" on agent "MACFMT"\n",
			__func__, __LINE__,
			MAC2STR(resp->sta_macaddr),
			MAC2STR(cmdu->origin));
		requested = false;
	}

	s = cntlr_find_sta(c, resp->sta_macaddr);
	if (!s) {
		dbg("|%s:%d| beacon metrics client "MACFMT" not found!\n",
				__func__, __LINE__, MAC2STR(resp->sta_macaddr));
		return -1;
	}

	ppos = resp->element;
	for (i = 0; i < resp->num_element; i++) {
		struct bcn_meas_element *elem;
		struct wifi_sta_meas_report *b;

		elem = (struct bcn_meas_element *) ppos;

		if (elem->tag_number != 0x27) {
			warn("|%s:%d| received beacon report with" \
				 "unexpected data\n", __func__, __LINE__);
			ppos = ppos + elem->tag_length + 2;
			continue;
		}

		if (hwaddr_is_zero(elem->bssid)) {
			/* Move to the next measurement report */
			ppos = ppos + elem->tag_length + 2;
			continue;
		}

		b = calloc(1, sizeof(*b));
		if (!b)
			return -ENOMEM;

		/* Keep only MAX_NUM_MEAS_REPORT results per STA */
		if (s->de_sta->num_meas_reports >= c->cfg.bcn_metrics_max_num) {
			struct wifi_sta_meas_report *rep = NULL;

			dbg("%s %d removing oldest bcn measurement from the list\n",
			    __func__, __LINE__);
			/* remove oldest element */
			rep = list_last_entry(&s->de_sta->meas_reportlist, struct wifi_sta_meas_report, list);
			if (rep) {
				list_del(&rep->list);
				free(rep);
				s->de_sta->num_meas_reports--;
			}
		}

		dbg("%s %d adding new bcn measurement to the list\n",
		    __func__, __LINE__);

		/* add new measurement to the queue */
		list_add(&b->list, &s->de_sta->meas_reportlist);
		s->de_sta->num_meas_reports++;

		/* fill in new measurement with data */
		memcpy(b->bssid, elem->bssid, 6);
		b->channel = elem->channel;
		b->opclass = elem->op_class;
		b->rcpi = elem->rcpi;
		b->rsni = elem->rsni;
		b->requested = requested;
		/* TODO: only most recent measurement marked as fresh */
		b->stale = false;
		memcpy(&b->meas_start_time, &elem->start_time, 8);

		/* Move to the next measurement report */
		ppos = ppos + elem->tag_length + 2;
	}

	return ret;
}

static struct wifi_apsta_steer_history *sta_lookup_steer_attempt(
		struct sta *s, uint8_t *src, uint8_t *dst)
{
	int i;
	uint8_t num_attempts = s->de_sta->mapsta.num_steer_hist;
	int size = (num_attempts < MAX_STEER_HISTORY) ?
				num_attempts : MAX_STEER_HISTORY;
	struct wifi_multiap_sta *mapsta;

	trace("%s: --->\n", __func__);

	mapsta = &s->de_sta->mapsta;

	/* Target BSSID is empty (error): use most recent unanswered attempt */
	if (!dst) {
		for (i = size - 1; i >= 0 ; i--) {
			if (!mapsta->steer_history[i].duration &&
					!memcmp(mapsta->steer_history[i].src_bssid, src, 6)) {
				dbg("|%s:%d| empty dst bssid - updated first unused attempt!\n",
				    __func__, __LINE__);
				return &mapsta->steer_history[i];
			}
		}
		return NULL;
	}

	dbg("|%s:%d| src="MACFMT", dst="MACFMT"\n",
	    __func__, __LINE__, MAC2STR(src), MAC2STR(dst));

	/* Target BSSID non-empty - lookup attempt based on that */
	for (i = 0; i < size; i++) {
		if (!mapsta->steer_history[i].duration &&
				!memcmp(mapsta->steer_history[i].src_bssid, src, 6) &&
				!memcmp(mapsta->steer_history[i].dst_bssid, dst, 6))
			return &mapsta->steer_history[i];
	}

	dbg("|%s:%d| dst "MACFMT" not found on attempt list!\n",
		__func__, __LINE__, MAC2STR(dst));

	/* Target BSSID not found. Check if provided in an attempt */
	for (i = 0; i < size; i++) {
		if (!mapsta->steer_history[i].duration &&
		    !memcmp(mapsta->steer_history[i].src_bssid, src, 6))
			return &mapsta->steer_history[i];
	}

	dbg("|%s:%d| auto bssid not found on attempt list!\n",
		__func__, __LINE__);

	return NULL;
}

int handle_sta_steer_btm_report(void *cntlr, struct cmdu_buff *cmdu,
				struct node *n)
{
	struct controller *c = (struct controller *) cntlr;
	struct tlv_steer_btm_report *resp;
	struct tlv *tv[1][16] = {0};
	struct sta *s;
	struct wifi_apsta_steer_history *attempt;
	int ret = 0;

	trace("%s: --->\n", __func__);

	if (!cntlr || !cmdu)
		return -1;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	/* If a Multi-AP Controller receives a Client Steering BTM Report message,
	 * then it shall respond within one second with a 1905 Ack message.
	 */
	cntlr_send_1905_acknowledge(cntlr, cmdu, NULL, 0);

	resp = (struct tlv_steer_btm_report *) tv[0][0]->data;

	s = cntlr_find_sta(c, resp->sta_macaddr);
	if (!s) {
		dbg("|%s:%d| steer btm report: sta "MACFMT" not found!\n",
		    __func__, __LINE__, MAC2STR(resp->sta_macaddr));
		return -1;
	}

	attempt = sta_lookup_steer_attempt(s, resp->bssid,
				resp->status ? NULL : resp->target_bssid[0]);

	if (!attempt) {
		warn("|%s:%d| could not find an attempt matching this btm report\n",
		    __func__, __LINE__);
		return 0;
	}

	if (resp->status != 0x00) { /* error code */
		if (s->de_sta->mapsta.pending_btm_resp_num > 0) {
			/* This is an expected btm response before btm timer
			 * expired. Hence update Steering Stats already.
			 */
			s->de_sta->mapsta.stats.failed_steer_attempts++;
			s->de_sta->mapsta.stats.btm_failure_cnt++;
			c->dlem.network.steer_summary.btm_failure_cnt++;
		}
		/* else: counters already updated in cntlr_btm_req_timer_cb */

		/* 'A failed steering attempt will leave this parameter 0' */
		attempt->duration = 0;
	} else { /* success */
		s->de_sta->mapsta.stats.failed_steer_attempts = 0;
		/* Update Steering Summary Stats */
		s->de_sta->mapsta.stats.btm_success_cnt++;
		c->dlem.network.steer_summary.btm_success_cnt++;

		if (s->de_sta->mapsta.pending_btm_resp_num == 0) {
			/* Received succesful btm report, after the btm timeout,
			 * meaning that failure counter have been increased
			 * in cntlr_btm__req_timer_cb and must be decreased.
			 */
			s->de_sta->mapsta.stats.btm_failure_cnt--;
			c->dlem.network.steer_summary.btm_failure_cnt--;
		}

		/* Record tsp for most recent steer success */
		timestamp_update(&s->de_sta->mapsta.stats.last_steer_tsp);

		attempt->duration = timestamp_elapsed_sec(&attempt->time);
	}

	/* Number of asynchronous BTM Queries for which a BTM
	 * Request was issued to this Associated Device.
	 */
	s->de_sta->mapsta.stats.btm_query_resp_cnt++;
	c->dlem.network.steer_summary.btm_query_resp_cnt++;

	/* Decrease expected (pending) responses count */
	if (s->de_sta->mapsta.pending_btm_resp_num > 0)
		s->de_sta->mapsta.pending_btm_resp_num--;

	return ret;
}

int handle_sta_steer_complete(void *cntlr, struct cmdu_buff *cmdu,
			      struct node *n)
{
	/* TODO: implement CMDU_STEERING_COMPLETED */
	trace("%s: --->\n", __func__);
	return 0;
}

static int cntlr_hld_event(struct controller *c, uint8_t proto, uint8_t *data,
			int data_len)
{
	const int len = data_len*2 + 128;
	char *str;
	int idx;

	str = calloc(len, sizeof(char));
	if (!str)
		return -1;

	idx = snprintf(str, len, "{\"protocol\":%d,\"data\":\"", proto);
	btostr(data, data_len, str + idx);
	idx += data_len*2;
	snprintf(str + idx, len - idx, "\"}");

	cntlr_notify_event(c, "map.controller.higher_layer_data", str);

	free(str);

	return 0;
}

int handle_hld_message(void *cntlr, struct cmdu_buff *rx_cmdu, struct node *n)
{
	struct controller *c = (struct controller *) cntlr;
	struct tlv *t;
	uint8_t proto;
	uint8_t *data;
	int data_len;
	int ret;
	uint8_t origin[6] = {0};

	trace("%s: --->\n", __func__);

	t = cmdu_peek_tlv(rx_cmdu, MAP_TLV_HIGHER_LAYER_DATA);
	if (!t) {
		dbg("%s: higher layer data TLV not found\n", __func__);
		return -1;
	}

	data_len = tlv_length(t) - 1;
	proto = t->data[0];
	data = t->data + 1;

	dbg("%s TLV received proto %u data_len %u!!\n", __func__, proto, data_len);

	if (!hwaddr_is_zero(rx_cmdu->origin)) {
		memcpy(origin, rx_cmdu->origin, 6);

		n = cntlr_find_node(c, origin);
		if (!n)
			return -1;
	}

	dbg("Received HLD from " MACFMT "\n", MAC2STR(origin));

	ret = cntlr_hld_event(c, proto, data, data_len);
	if (ret == 0)
		cntlr_send_1905_acknowledge(c, rx_cmdu, NULL, 0);

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
	if (proto == 0xac) {
		struct sync_config cfg = {0};
		uint16_t sync_config_respsize = 0;
		uint8_t *sync_config_resp = NULL;
		struct cmdu_buff *cmdu;

		dbg("******** Handle dyn-cntlr-sync-config-request ******\n");
		/* if (n->sync_config_req)
			free(n->sync_config_req);

		n->sync_config_reqsize = 0;
		n->sync_config_req = calloc(data_len, sizeof(uint8_t));
		if (n->sync_config_req) {
			memcpy(n->sync_config_req, data, data_len);
			n->sync_config_reqsize = data_len;
			fprintf(stderr, "%s: -- %d --\n", __func__, __LINE__);
		}
		*/
		ret = readfrom_configfile("/etc/config/mapcontroller", &cfg.data, &cfg.len);
		if (ret) {
			err("error reading controller config file\n");
			return -1;
		}

		ret = build_sync_config_response(data, data_len,
						 &cfg,
						 &sync_config_resp,
						 &sync_config_respsize);

		free(cfg.data);

		dbg("dyn-cntlr-sync-config response size = %u\n", sync_config_respsize);

		/* ret = build_sync_config_response(c->sync_config_req,
						 c->sync_config_reqsize,
						 &cfg,
						 &sync_config_resp,
						 &sync_config_respsize); */
		if (ret) {
			dbg("Error building sync-config-response\n");
			return ret;
		}

		cmdu = cntlr_gen_higher_layer_data(c, origin, proto,
						   sync_config_resp,
						   sync_config_respsize);

		free(sync_config_resp);

		if (!cmdu)
			return -1;

		send_cmdu(c, cmdu);
		cmdu_free(cmdu);
	}
#endif

	return ret;
}

int handle_backhaul_sta_steer_response(void *cntlr, struct cmdu_buff *cmdu,
				       struct node *n)
{
	/* TODO: implement */
	trace("%s: --->\n", __func__);
	return 0;
}

static struct wifi_scanres_element *find_scanres_el(struct controller *c,
		uint8_t *radio, char *timestamp)
{
	struct netif_radio *r = NULL;
	struct wifi_scanres_element *b = NULL;

	r = find_radio_by_mac(c, radio);
	if (!r)
		return NULL;

	if (list_empty(&r->radio_el->scanlist))
		return NULL;

	list_for_each_entry(b, &r->radio_el->scanlist, list) {
		if (!strncmp(timestamp, b->tsp, strlen(timestamp)))
			return b;
	}

	return NULL;
}

#define SCANRES_MAX_NUM 4 /* maximum number of stored results per radio */
static struct wifi_scanres_element *get_scanlist_element(struct controller *c,
		uint8_t *radio, char *timestamp)
{
	trace("%s: --->\n", __func__);

	struct wifi_scanres_element *b = NULL;
	struct netif_radio *r;

	/* Reuse element if data from same radio and time */
	b = find_scanres_el(c, radio, timestamp);
	if (!b) {
		r = find_radio_by_mac(c, radio);
		if (!r)
			return NULL;

		b = calloc(1, sizeof(*b));
		if (!b)
			return NULL;

		/* Keep only SCANRES_MAX_NUM results per radio */
		if (r->radio_el->num_scanresult >= SCANRES_MAX_NUM) {
			struct wifi_scanres_element *el = NULL;

			/* remove oldest (fifo queue) element */
			el = list_first_entry(&r->radio_el->scanlist, struct wifi_scanres_element, list);
			if (el) {
				if (!cntlr_radio_clean_scanlist_el(el))
					r->radio_el->num_scanresult--;
			}
		}

		/* add new element (to fifo queue) */
		list_add_tail(&b->list, &r->radio_el->scanlist);
		r->radio_el->num_scanresult++;

		strncpy(b->tsp, timestamp, sizeof(b->tsp) - 1);

		/* Initialize opclass list for the measurement */
		INIT_LIST_HEAD(&b->opclass_scanlist);
	}

	return b;
}

static int add_scanres_element(struct controller *c,
		struct tlv_channel_scan_result *tlv, char *timestamp)
{
	trace("%s: --->\n", __func__);

	struct wifi_scanres_element *el = NULL;
	struct wifi_scanres_opclass_element *op = NULL, *otmp = NULL;
	struct wifi_scanres_channel_element *ch = NULL, *ctmp = NULL;
	uint8_t *tv_data = NULL;
	int offset = 0;

	/* Reuse old or add new element to the list */
	el = get_scanlist_element(c, tlv->radio, timestamp);
	if (!el)
		return -1; /* error condition */

	list_for_each_entry(otmp, &el->opclass_scanlist, list) {
		if (otmp->opclass == tlv->opclass) {
			op = otmp;
			break;
		}
	}

	if (!op) {
		op = calloc(1, sizeof(*op));
		if (!op)
			goto error; /* error condition */

		/* add opclass element to the list */
		list_add(&op->list, &el->opclass_scanlist);
		el->num_opclass_scanned++;

		op->opclass = tlv->opclass;

		/* Initialize channel list for this measurement */
		INIT_LIST_HEAD(&op->channel_scanlist);
	}

	list_for_each_entry(ctmp, &op->channel_scanlist, list) {
		if (ctmp->channel == tlv->channel) {
			dbg("%s: channel %d already on the list\n", __func__, tlv->channel);
			goto error; /* error condition */
		}
	}

	ch = calloc(1, sizeof(*ch));
	if (!ch)
		goto error; /* error condition */

	/* add channel element to the list */
	list_add(&ch->list, &op->channel_scanlist);
	op->num_channels_scanned++;

	/* channel */
	ch->channel = tlv->channel;

	/* tsp */
	memset(ch->tsp, 0, sizeof(ch->tsp)); /* null term */
	memcpy(ch->tsp, tlv->detail[0].tsp.timestamp,
		sizeof(ch->tsp) - 1 < tlv->detail[0].tsp.len ?
		sizeof(ch->tsp) - 1 : tlv->detail[0].tsp.len);

	/* don't use struct detail anylonger due to variable tsp len */
	tv_data = (uint8_t*)&tlv->detail[0];
	offset += sizeof(tlv->detail[0].tsp) + tlv->detail[0].tsp.len;

	ch->utilization = tv_data[offset];
	offset++; /* uint8_t utilization; */
	ch->anpi = tv_data[offset];
	offset++; /* uint8_t noise; */
	ch->num_neighbors = BUF_GET_BE16(tv_data[offset]);
	offset += 2; /* uint16_t num_neighbor; */

	dbg("%s: channel %d, tsp: %s, util: %d, noise: %d, num_nbr: %d\n",
	    __func__, ch->channel, ch->tsp, ch->utilization, ch->anpi, ch->num_neighbors);

	INIT_LIST_HEAD(&ch->nbrlist);

	/* Initialize nbrlist for this channel of current measurement */
	if (ch->num_neighbors) {
		int i;
		struct wifi_scanres_neighbor_element *nbr = NULL;

		for (i = 0; i < ch->num_neighbors; i++) {
			uint8_t len = 0, ssidlen;
			uint8_t info = 0x00;
			uint8_t bw_len;

			nbr = calloc(1, sizeof(*nbr));
			if (!nbr)
				goto error; /* error condition */

			/* add nbr element to the list */
			list_add(&nbr->list, &ch->nbrlist);

			memcpy(nbr->bssid, &tv_data[offset], 6);
			offset += 6;
			ssidlen = tv_data[offset++];
			len = (ssidlen + 1 > sizeof(nbr->ssid)
					? sizeof(nbr->ssid) : ssidlen + 1);
			snprintf(nbr->ssid, len, "%s", (char *)&tv_data[offset]);
			offset += ssidlen;
			nbr->rssi = rcpi_to_rssi(tv_data[offset]);
			offset++;
			bw_len = tv_data[offset++];
			nbr->bw = atoi((char *)&tv_data[offset]);
			offset += bw_len;
			info = tv_data[offset];
			offset++;

			if (info & CH_SCAN_RESULT_BSSLOAD_PRESENT) {
				nbr->utilization = tv_data[offset];
				offset++;
				nbr->num_stations = BUF_GET_BE16(tv_data[offset]);
				offset += 2;
			}
		}
	}
	return 0;

error:
	cntlr_radio_clean_scanlist_el(el);
	return -1;
}

#define SCANRES_MAX_AGE 1800 /* secs */
static void cntlr_radio_remove_old_scanres(struct controller *c)
{
	struct node *n = NULL;
	struct netif_radio *r = NULL;
	struct wifi_scanres_element *el = NULL, *tmp;

	list_for_each_entry(n, &c->nodelist, list) {
		list_for_each_entry(r, &n->radiolist, list) {
			list_for_each_entry_safe(el, tmp, &r->radio_el->scanlist, list) {
				struct timespec ts;

				ts = timestamp_to_timespec(el->tsp, true);
				if (timestamp_expired(&ts, SCANRES_MAX_AGE * 1000)) {
					cntlr_radio_clean_scanlist_el(el);
					r->radio_el->num_scanresult--;
				}
			}
		}
	}
}

static int cntlr_radio_update_scanlist(void *cntlr, char *timestamp,
		struct tlv **tv_scan, int num_result)
{
	struct controller *c = (struct controller *) cntlr;
	int i;

	/* remove outdated entries from all radio scanlists */
	cntlr_radio_remove_old_scanres(c);

	/* Go trhough all results */
	for (i = 0; i < num_result; i++) {
		struct tlv_channel_scan_result *tlv=
				(struct tlv_channel_scan_result *)tv_scan[i]->data;

		dbg("%s: radio " MACFMT " scan status: %d, opclass/channel: %d/%d\n",
		    __func__,  MAC2STR(tlv->radio), tlv->status,
		    tlv->opclass, tlv->channel);

		/* Skip unsuccesfull scans */
		if (tlv->status != CH_SCAN_STATUS_SUCCESS)
			continue;

		if (add_scanres_element(c, tlv, timestamp))
			return -1;
	}

	return 0;
}

int handle_channel_scan_report(void *cntlr, struct cmdu_buff *cmdu,
			       struct node *n)
{
	dbg("%s: --->\n", __func__);

	int num_result = 256;
	struct tlv *tv_tsp[1][16];
	struct tlv *tv_scan[256];
	char timestamp[TIMESTAMP_MAX_LEN] = {0};
	int len;
	struct tlv_timestamp *p = NULL;
	uint8_t *tv_data = NULL;

	if (!validate_channel_scan_report(cmdu, tv_tsp, tv_scan, &num_result, n->map_profile)) {
		dbg("cmdu validation: [CHANNEL_SCAN_REPORT] failed\n");
		return -1;
	}

	tv_data = (uint8_t *)tv_tsp[0][0]->data;
	p = (struct tlv_timestamp *)tv_data;

	if (p->len > (TIMESTAMP_MAX_LEN - 1))
		return -1;

	memset(timestamp, 0, sizeof(timestamp));
	len = (p->len > sizeof(timestamp) - 1
		? sizeof(timestamp) - 1 : p->len);
	memcpy(timestamp, p->timestamp, len);

	dbg("%s: timestamp = %s\n", __func__, timestamp);

	return cntlr_radio_update_scanlist(cntlr, timestamp, tv_scan, num_result);
}

int handle_sta_disassoc_stats(void *cntlr, struct cmdu_buff *cmdu,
			      struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_assoc_status_notification(void *cntlr, struct cmdu_buff *cmdu,
				     struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_tunneled_message(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int handle_backhaul_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu,
				    struct node *n)
{
	uint8_t *tv_data;
	struct tlv *tv[1][16];
	int num = 0;
	struct controller *c = (struct controller *) cntlr;
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs( ..,EMP=%d) failed,  err = (%d) '%s'\n", __func__,
		    n->map_profile, map_error, map_strerror(map_error));
		return ret;
	}

	if (!tv[0][num]) {
		dbg("No TLV_BACKHAUL_STA_RADIO_CAPABILITY received!\n");
		return -1;
	}

	while (tv[0][num]) {
		struct netif_radio *r;
		struct tlv_bsta_radio_cap *p;

		if (tv[0][num]->type != MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY) {
			dbg("Wrong received TLV type!\n");
			return -1;
		}

		tv_data = (uint8_t *)tv[0][num]->data;
		p = (struct tlv_bsta_radio_cap *)tv_data;

		r = find_radio_by_node(c, n, p->radio);
		if (!r) {
			r = cntlr_node_add_radio(c, n, p->radio);
			if (!r)
				continue;
		}

		if (p->macaddr_included) {
			struct netif_iface *fh;

			fh = cntlr_radio_add_interface(c, r, (uint8_t *)p->macaddr);
			if (!fh)
				continue;

			/* bsta - unmark bbss & fbss */
			fh->bss->is_bbss = false;
			fh->bss->is_fbss = false;
		}

		num++;
	}
	return 0;
}

#if (EASYMESH_VERSION > 2)
int handle_proxied_encap_dpp(void *cntlr, struct cmdu_buff *cmdu,
				     struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *controller = (struct controller *)cntlr;
	struct tlv *tlv;
	struct tlv *tlvs[PROXIED_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (!validate_proxied_encap_dpp(cmdu, tlvs)) {
		dbg("cmdu validation: [PROXIED_ENCAP_DPP] failed\n");
		return -1;
	}

	(void) controller;

	/* One Encap 1905 DPP TLV */
	tlv = tlvs[PROXIED_ENCAP_1905_ENCAP_DPP_IDX][0];
	(void) tlv;
	// TODO: process Encap 1905 DPP TLV

	/* Zero or One Chirp Value TLV */
	tlv = tlvs[PROXIED_ENCAP_CHIRP_VALUE_IDX][0];
	(void) tlv;
	// TODO: process Chirp Value TLV


	return 0;
}

int handle_direct_encap_dpp(void *cntlr, struct cmdu_buff *cmdu,
				     struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *controller = (struct controller *)cntlr;
	struct tlv *tlv;
	struct tlv *tlvs[DIRECT_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (!validate_direct_encap_dpp(cmdu, tlvs)) {
		dbg("cmdu validation: [DIRECT_ENCAP_DPP] failed\n");
		return -1;
	}

	/* One DPP Message TLV */
	tlv = tlvs[DIRECT_ENCAP_DPP_MESSAGE_IDX][0];
	(void) tlv;
	(void) controller;

	// TODO: process DPP Message TLV

	return 0;
}

int handle_bss_configuration_request(void *cntlr, struct cmdu_buff *request_cmdu,
				     struct node *n)
{
	trace("%s: --->\n", __func__);
	int res;
	struct cmdu_buff *response_cmdu;
	struct controller *c = (struct controller *)cntlr;
	struct tlv *tlvs[BSS_CFG_REQ_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	cntlr_set_link_profile(c, n, request_cmdu);

	// section 17.1.53

	if (!validate_bss_configuration_request(request_cmdu, tlvs, n->map_profile)) {
		dbg("cmdu validation: [BSS_CONFIGURATION_REQUEST] failed, EMP %d\n", n->map_profile);
		return -1;
	}

	/* One SupportedService TLV */
	/* One AKM Suite Capabilities TLV */
	/* One or more AP Radio Basic Capabilities TLV */
	/* Zero or more Backhaul STA Radio Capabilities TLV */
	/* One Profile-2 AP Capability TLV */
	/* One or more AP Radio Advanced Capabilities TLV */
	/* One BSS Configuration Request TLV */


	response_cmdu = cntrl_gen_bss_configuration_response(c, request_cmdu);

	if (!response_cmdu)
		return -1;

	res = send_cmdu(c, response_cmdu);
	if (res == 0xffff) {
		res = -1;
		dbg("%s: agent_send_cmdu failed.\n", __func__);
	} else {
		res = 0;
		dbg("%s: bss configuration response sent.\n", __func__);
	}

	cmdu_free(response_cmdu);

	return res;
}

int handle_bss_configuration_result(void *cntlr, struct cmdu_buff *cmdu,
				    struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *c = (struct controller *)cntlr;
	struct tlv *tlv;

	struct tlv *tlvs[BSS_CFG_RESULT_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (!validate_bss_configuration_result(cmdu, tlvs, n->map_profile)) {
		dbg("cmdu validation: [BSS_CONFIGURATION_RESULT] failed\n");
		return -1;
	}

	// todo: process tlvs
	/* One BSS Configuration Report TLV */
	tlv = tlvs[BSS_CFG_RESULT_BSS_CONFIG_REPORT_IDX][0];
	(void) tlv;
	(void) c;

	if (send_agent_list_to_all_nodes(c) != 0)
		dbg("send_agent_list_to_all_nodes failed.\n");

	return 0;
}

int handle_dpp_bootstraping_uri_notificiation(void *cntlr, struct cmdu_buff *cmdu,
				    struct node *n)
{
	trace("%s: --->\n", __func__);

	struct controller *controller = (struct controller *)cntlr;
	struct tlv *tlv;
	struct tlv *tlvs[DPP_BOOTSTRAP_URI_NOTIF_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (!validate_dpp_bootstraping_uri_notification(cmdu, tlvs)) {
		dbg("cmdu validation: [DPP_BOOTSTRAP_URI_NOTIF] failed\n");
		return -1;
	}

	/* One DPP Bootstraping URI Notification TLV */
	tlv = tlvs[DPP_BOOTSTRAP_URI_NOTIF_IDX][0];
	(void) tlv;
	(void) controller;

	// TODO: process DPP Boootstraping URI Notification TLV

	return 0;
}
#endif /* EASYMESH_VERSION > 2 */

int handle_failed_connection_msg(void *cntlr, struct cmdu_buff *cmdu,
				 struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}


//#define CMDU_TYPE_1905_START	0x0001
//#define CMDU_TYPE_1905_END	0x0009


#define CMDU_TYPE_MAP_START	0x8000
#define CMDU_TYPE_MAP_END	0x8033

/* mind the holes in the following two tables */
static const struct map_cmdu_calltable_t i1905ftable[] = {
	[0x00] = {
		.handle = handle_topology_discovery,
		.debug = debug_topology_discovery
	},
	[0x01] = {
		.handle = handle_topology_notification,
		.debug = debug_topology_notification
	},
	[0x02] = {
		.handle = handle_topology_query,
		.debug = debug_topology_query
	},
	[0x03] = {
		.handle = handle_topology_response,
		.debug = debug_topology_response
	},
	// [0x06] = {
	// 	.handle = handle_link_metric_response,
	// 	.debug = debug_link_metrics_response
	// },
	[0x07] = {
		.handle = handle_ap_autoconfig_search,
		.debug = debug_ap_autoconfig_search
	},
	[0x08] = {
		.handle = handle_ap_autoconfig_response,
		.debug = debug_ap_autoconfig_response
	},
	[0x09] = {
		.handle = handle_ap_autoconfig_wsc,
		.debug = debug_ap_autoconfig_wsc
	},
};


static const struct map_cmdu_calltable_t cntlr_mapftable[] = {
	[0x00] = {
		.handle = handle_1905_ack,
		.debug = debug_1905_ack
	},
	[0x02] = {
		.handle = handle_ap_caps_report,
		.debug = debug_ap_caps_report
	},
	[0x05] = {
		.handle = handle_channel_pref_report,
		.debug = debug_channel_pref_report
	},
	[0x07] = {
		.handle = handle_channel_sel_response,
		.debug = debug_channel_sel_response
	},
	[0x08] = {
		.handle = handle_oper_channel_report,
		.debug = debug_oper_channel_report
	},
	[0x0a] = {
		.handle = handle_sta_caps_report,
		.debug = debug_sta_caps_report
	},
	[0x0c] = {
		.handle = handle_ap_metrics_response,
		.debug = debug_ap_metrics_response
	},
	[0x0e] = {
		.handle = handle_sta_link_metrics_response,
		.debug = debug_sta_link_metrics_response
	},
	[0x10] = {
		.handle = handle_unassoc_sta_link_metrics_response,
		.debug = debug_unassoc_sta_link_metrics_response
	},
	[0x12] = {
		.handle = handle_beacon_metrics_response,
		.debug = debug_beacon_metrics_response
	},
	[0x15] = {
		.handle = handle_sta_steer_btm_report,
		.debug = debug_sta_steer_btm_report
	},
	[0x17] = {
		.handle = handle_sta_steer_complete,
		.debug = debug_sta_steer_complete
	},
	[0x18] = {
		.handle = handle_hld_message,
		.debug = debug_hld_message
	},
	[0x1a] = {
		.handle = handle_backhaul_sta_steer_response,
		.debug = debug_backhaul_sta_steer_response
	},
	[0x1c] = {
		.handle = handle_channel_scan_report,
		.debug = debug_channel_scan_report
	},
	[0x22] = {
		.handle = handle_sta_disassoc_stats,
		.debug = debug_sta_disassoc_stats
	},
	[0x25] = {
		.handle = handle_assoc_status_notification,
		.debug = debug_assoc_status_notification
	},
	[0x26] = {
		.handle = handle_tunneled_message,
		.debug = debug_tunneled_message
	},
	[0x28] = {
		.handle = handle_backhaul_sta_caps_report,
		.debug = debug_backhaul_sta_caps_report
	},
#if (EASYMESH_VERSION > 2)
	[0x29] = {
		.handle = handle_proxied_encap_dpp,
		.debug = debug_proxied_encap_dpp
	},
	[0x2a] = {
		.handle = handle_direct_encap_dpp,
		.debug = debug_direct_encap_dpp
	},
	[0x2c] = {
		.handle = handle_bss_configuration_request,
		.debug = debug_bss_configuration_request
	},
	[0x2e] = {
		.handle = handle_bss_configuration_result,
		.debug = debug_bss_configuration_result
	},
	[0x31] = {
		.handle = handle_dpp_bootstraping_uri_notificiation,
		.debug = debug_dpp_bootstraping_uri_notificiation
	},
#endif
	[0x33] = {
		.handle = handle_failed_connection_msg,
		.debug = debug_failed_connection_msg
	},

};


bool is_cmdu_for_us(void *module, uint16_t type)
{
	struct controller *c = (struct controller *)module;

	/* TODO: handle cmdu types relevant for operating profile. */

	/* discard responses that are not to ACS during initilization */
	if (c->state == CNTLR_INIT &&
			(type != CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE &&
			 type != CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH)) {
		trace("Controller is initializing, waitfor ACS response or "\
				"start timer (%ds) to finish\n",
				timer_remaining_ms(&c->start_timer));
		return false;
	}

	if (type >= CMDU_TYPE_1905_START && type <= CMDU_TYPE_1905_END) {
		if (i1905ftable[type].handle)
			return true;
	} else if (type >= CMDU_TYPE_MAP_START && type <= CMDU_TYPE_MAP_END) {
		if (cntlr_mapftable[type - CMDU_TYPE_MAP_START].handle)
			return true;
	}

	return false;
}

int cntlr_handle_map_event(void *module, uint16_t cmdutype, uint16_t mid,
		char *rxif, uint8_t *src, uint8_t *origin, uint8_t *tlvs, int len)
{
	struct controller *c = (struct controller *)module;
	const struct map_cmdu_calltable_t *f;
	struct cmdu_buff *cmdu = NULL;
	int ret = 0;
	int idx;
	uint16_t resp_type;
	void *cookie;
	struct cmdu_ackq_entry *entry;
	struct node *n;

	trace("%s: ---> cmdu = %d (%04x), ifce \"%s\"\n", __func__, cmdutype, cmdutype,
			rxif);

	/* If request CMDU is from us, do not process is. This is for
	 * situation where controller and agent are on the same device,
	 * share the same MAC address and send CMDU's to each other. */
	if (hwaddr_equal(c->almac, origin)) {
		// Do we expect response for this CMDU ?
		resp_type = cntlr_cmdu_expect_response(c, cmdutype);
		entry = cmdu_ackq_lookup(&c->cmdu_ack_q, resp_type, mid, origin);
		if (entry)
			return 0;
	}

	ret = cmdu_ackq_dequeue(&c->cmdu_ack_q, cmdutype, mid, origin, &cookie);
	if (ret == 0)
		cmdu_free((struct cmdu_buff *) cookie);

	if (cmdutype >= CMDU_TYPE_MAP_START) {
		idx = cmdutype - CMDU_TYPE_MAP_START;
		f = cntlr_mapftable;
	} else {
		idx = cmdutype;
		f = i1905ftable;
	}

	n = cntlr_find_node(c, origin);
	if (!n) {
		if (cmdutype != CMDU_TYPE_TOPOLOGY_DISCOVERY &&
		    cmdutype != CMDU_TYPE_TOPOLOGY_NOTIFICATION &&
		    cmdutype != CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH)
			return -1;
	}

	cmdu = cmdu_alloc_custom(cmdutype, &mid, rxif, src, tlvs, len);
	if (!cmdu) {
		dbg("%s: cmdu_alloc_custom() failed!\n", __func__);
		return -1;
	}
	memcpy(cmdu->origin, origin, 6);
	dbg("%s: cmdu_alloc_custom() succeeded! cmdu->cdata->hdr.mid %u\n", __func__, cmdu_get_mid(cmdu));

	if (f[idx].handle)
		ret = f[idx].handle(c, cmdu, n);

	if (f[idx].debug)
		ret = f[idx].debug(c, cmdu, n);

	//TODO: check ret

	cmdu_free(cmdu);
	return ret;
}

int cntlr_set_link_profile(struct controller *c, struct node *n,
			   struct cmdu_buff *cmdu)
{
	int p = c->cfg.map_profile;
	int np = map_cmdu_get_multiap_profile(cmdu);

	if (p <= MULTIAP_PROFILE_1) {
		n->map_profile = MULTIAP_PROFILE_1;
		return n->map_profile;
	}

	if (np > p) {
		n->map_profile = p;
		return p;
	}

	n->map_profile = np;
	return np;
}
