/*
 * cntlr_map_debug.c - implements MAP2 CMDUs debug/test handling
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <string.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif
#include <easy/easy.h>
#include <wifidefs.h>


#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>


#include "utils/utils.h"
#include "utils/debug.h"

#include "cntlr.h"
#include "cntlr_map_debug.h"
#include "cmdu_validate.h"
#include "tlv_debug.h"
#include "cntlr_map.h"

int debug_topology_notification(void *cntlr, struct cmdu_buff *cmdu,
				struct node *n)
{
	return 0;
//	uint8_t *tlv = NULL;
//	trace("%s: --->\n", __func__);
//	tlv = (uint8_t *) cmdu->tlvs[0];
//	trace("\nCMDU type: %s\n", map_stringify_tlv_type(*tlv));
//	struct tlv_client_assoc_event *p =
//			(struct tlv_client_assoc_event *)tlv;
//	trace("\tclient_addr: " MACFMT "\n", MAC2STR(p->client_addr));
//	trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
//	trace("\tassoc_event: %d\n\n", p->assoc_event);
//	return 0;
}

int debug_topology_discovery(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int debug_topology_query(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int debug_topology_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	/* TODO: TODO: debug base TLVs */
	struct tlv *tv[12][16] = {0};

	if (!validate_topology_response(cmdu, tv, n->map_profile)) {
		dbg("cmdu validation: [TOPOLOGY_RESPONSE] failed\n");
		return -1;
	}

	if (tv[6][0]) {
		int i;
		uint8_t *tlv = (uint8_t *) tv[6][0]->data;

		trace("TLV: supported service\n");

		trace("\tsupported_services_list: %d\n",
			tlv[0]);
		for (i = 0; i < tlv[0]; i++) {
			trace("\t\tservice: %s\n",
				(tlv[(i+1)] ?
				"Multi-AP Agent" : "Multi-AP Controller"));
		}
	}

	if (tv[7][0]) {
		struct tlv_ap_oper_bss *tlv = (struct tlv_ap_oper_bss *)tv[7][0]->data;
		uint8_t *pos = tv[7][0]->data;
		int i, offset = 0;

		offset += 1;

		trace("TLV: oper bss\n");

		trace("\tradios_nr: %d\n", tlv->num_radio);
		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t *radio_macaddr = &pos[offset];
			uint8_t num_bss = 0;
			int j;

			trace("\t\tradio_id: " MACFMT "\n", MAC2STR(radio_macaddr));
			offset += 6;

			memcpy(&num_bss, &pos[offset], 1);
			offset += 1;

			trace("\t\tbss_nr: %d\n",
				num_bss);
			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0;

				trace("\t\t\tbssid: " MACFMT "\n",
					MAC2STR(&pos[offset]));
				offset += 6;

				memcpy(&ssidlen, &pos[offset], 1);
				trace("\t\t\tssid_len: %d\n",
					ssidlen);
				offset += 1;

				trace("\t\t\tssid: %.*s\n",
					ssidlen,
					&pos[offset]);
				offset += ssidlen;
			}
		}
	}

	if (tv[8][0]) {
		struct tlv_assoc_client *tlv = (struct tlv_assoc_client *)tv[8][0]->data;
		uint8_t *pos = tv[8][0]->data;
		int i, offset = 0;

		offset += 1;

		trace("TLV: assoc client\n");


		trace("\tbss_nr: %d\n", tlv->num_bss);
		for (i = 0; i < tlv->num_bss; i++) {
			uint16_t num_client = 0;
			int j;

			trace("\t\tbssid: " MACFMT "\n",
				MAC2STR(&pos[offset]));
			offset += 6;

			num_client = BUF_GET_BE16(pos[offset]);
			offset += 2;

			trace("\t\tassoc_clients_nr: %u\n", num_client);
			for (j = 0; j < num_client; j++) {
				uint16_t conntime = 0;

				trace("\t\t\tclient_addr: " MACFMT "\n",
					MAC2STR(&pos[offset]));
				offset += 6;

				conntime = BUF_GET_BE16(pos[offset]);
				offset += 2;
				trace("\t\t\tuptime: 0x%04x\n", conntime);
			}
		}
	}

	if (tv[9][0]) {
		struct tlv_map_profile *tlv = (struct tlv_map_profile *)tv[9][0]->data;

		trace("TLV: map profile\n");
		trace("\tprofile: %d\n", tlv->profile);
	}

	return 0;
}

int debug_ap_autoconfig_search(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int debug_ap_autoconfig_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

int debug_ap_autoconfig_wsc(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}


int debug_1905_ack(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int idx;
	struct tlv *tv[1][16] = {0};
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	trace("%s: --->\n", __func__);
	trace("parsing 1905 ack |" MACFMT "|\n", MAC2STR(cmdu->origin));

	idx = 0;

	while (tv[0][idx]) {
		struct tlv_error_code *data;
		struct tlv *t = (struct tlv *)tv[0][idx++];
		data = (struct tlv_error_code *)t->data;

		trace("\nTLV type: MAP_TLV_ERROR_CODE\n");
		trace("\treason code: %d\n", data->reason);
		trace("\tsta addr:" MACFMT "\n", MAC2STR(data->macaddr));
		trace("\n");
	}

	return 0;
}

int debug_ap_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	int i, j;
	int index = 0;
	int offset = 0;
	struct tlv *tv[13][16];
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 13, n->map_profile);

	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}


	/* AP Capability TLV */
	if (tv[0][0]) {
		struct tlv_ap_cap *p = (struct tlv_ap_cap *)tv[0][0]->data;
		trace("\nTLV type: MAP_TLV_AP_CAPABILITY\n");
		trace("\tcap: %d\n", p->cap);
		trace("\n");
	}

	index = 0;
	/* Parse AP Radio Basic Capabilities TLV */
	while (tv[1][index] && (index < 16)) {
		uint8_t *tv_data = (uint8_t *)tv[1][index++]->data;

		trace_tlv_ap_radio_basic_cap((struct tlv_ap_radio_basic_cap *)tv_data);
	}

	index = 0;
	/* Parse AP HT Capabilities TLV */
	while (tv[2][index] && (index < 16)) {
		struct tlv_ap_ht_cap *p =
			(struct tlv_ap_ht_cap *)tv[2][index++]->data;
		trace("\nTLV type: MAP_TLV_AP_HT_CAPABILITIES\n");
		trace("\tradio:" MACFMT "\n", MAC2STR(p->radio));
		trace("\tcap: %d\n", p->cap);
		trace("\n");
	}

	index = 0;
	/* AP VHT Capabilities TLV */
	while (tv[3][index] && (index < 16)) {
		struct tlv_ap_vht_cap *p =
			(struct tlv_ap_vht_cap *)tv[3][index++]->data;

		trace("\nTLV type: MAP_TLV_AP_VHT_CAPABILITIES,\n");
		trace("\tradio:" MACFMT "\n", MAC2STR(p->radio));
		trace("\ttx_mcs_supported: %d\n", p->tx_mcs_supported);
		trace("\trx_mcs_supported: %d\n", p->rx_mcs_supported);
		trace("\tcap_0: %d\n", p->cap[0]);
		trace("\tcap_1: %d\n", p->cap[1]);
		trace("\n");
	}

	index = 0;
	/* Parse AP HE Capabilities TLV */
	while (tv[4][index] && (index < 16)) {
		uint8_t *tv_data = (uint8_t *)tv[4][index++]->data;
		struct tlv_ap_he_cap *p =
			(struct tlv_ap_he_cap *)tv_data;

		trace("\nTLV type: MAP_TLV_AP_HE_CAPABILITIES,\n");
		trace("\tradio:" MACFMT "\n", MAC2STR(p->radio));

		struct ap_he_cap_mcs *hemcs =
				(struct ap_he_cap_mcs *)&tv_data[6];
		trace("\tlen: %d\n", hemcs->len);
		for (i = 0; i < hemcs->len; i++)
			trace("\tmcs: %d\n", hemcs->mcs[i]);
		trace("\tcap_0: %d\n", p->cap[0]);
		trace("\tcap_1: %d\n", p->cap[1]);
		trace("\n");
	}

	/* Parse Channel Scan Capabilities TLV */
	if (tv[5][0]) {
		uint8_t *tv_data = (uint8_t *)tv[5][0]->data;
		struct tlv_channel_scan_capability *p =
			(struct tlv_channel_scan_capability *)tv_data;

		UNUSED(p);
	}
	/* Parse CAC Capabilities TLV */
	if (tv[6][0]) {
		int h, k;
		uint8_t *tv_data = (uint8_t *)tv[6][0]->data;
		struct tlv_cac_cap *p =
			(struct tlv_cac_cap *)tv_data;
		offset = sizeof(*p);
		trace("\nTLV type: MAP_TLV_CAC_CAPABILITY\n");
		trace("\tcountry: %d%d\n", p->country[0], p->country[1]);
		trace("\tnum_radio: %d\n", p->num_radio);
		for (h = 0; h < p->num_radio; h++) {
			struct cac_cap_radio *r =
					(struct cac_cap_radio *)&tv_data[offset];
			offset += sizeof(*r);
			trace("\tradio: " MACFMT "\n", MAC2STR(r->radio));
			trace("\tnum_cac: %d\n", r->num_cac);
			for (i = 0; i < r->num_cac; i++) {
				struct cac_cap_cac *c =
					(struct cac_cap_cac *)&tv_data[offset];
				offset += sizeof(*c);
				trace("\tsupp_method: %d\n", c->supp_method);
				trace("\tduration: %d%d%d\n", c->duration[0], c->duration[1], c->duration[2]);
				trace("\tnum_opclass: %d\n", c->num_opclass);
				for (j = 0; j < c->num_opclass; j++) {
					struct cac_cap_opclass *o =
						(struct cac_cap_opclass *)&tv_data[offset];
					offset += 2 + o->num_channel;
					trace("\tclassid: %d\n", o->classid);
					trace("\tnum_clannel: %d\n", o->num_channel);
					trace("\tchannel:");
					for (k = 0; k < o->num_channel; k++)
						trace(" %d", o->channel[k]);
					trace("\n");
				}
			}
		}
		trace("\n");

	}
	/* Parse Profile-2 AP Capability TLV */
	if (tv[7][0]) {
		struct tlv_profile2_ap_cap *p =
			(struct tlv_profile2_ap_cap *)tv[7][0]->data;
		trace_tlv_profile2_ap_cap(p);
	}

	/* Parse Metric Collection Interval TLV */
	if (tv[8][0]) {
		struct tlv_metric_collection_int *p =
			(struct tlv_metric_collection_int *)tv[5][0]->data;
		trace("\nTLV type: MAP_TLV_METRIC_COLLECTION_INTERVAL\n");
		trace("\tinterval: %d\n", p->interval);
		trace("\n");
	}

#if (EASYMESH_VERSION > 2)
	/* Device 1905 Layer Security Capability TLV */
	if (tv[10][0]) {
		struct tlv_1905_security_cap *p =
			(struct tlv_1905_security_cap *)tv[10][0]->data;

		trace("\nTLV type: MAP_TLV_1905_SECURITY_CAPS\n");
		trace("\tOnborading Protocol: %02x\n", p->protocol);
		trace("\tMIC Algorithm: %02x\n", p->mic);
		trace("\tEncryption Algorithm: %02x\n", p->enc);
	}

	/* Device Inventory TLV */
	if (tv[11][0]) {
		int i, offset = 0;
		uint8_t *p = (uint8_t *)tv[11][0]->data;
		int lsn, lsv, lee, num_radios;

		trace("\nTLV type: MAP_TLV_DEVICE_INVENTORY\n");
		lsn = p[offset++];
		trace("\tSerial Number len: %d\n", lsn);
		if (lsn > 0) {
			char buf[65] = {0};

			memcpy(buf, &p[offset], lsn);
			trace("\tSerial Number: %s\n", buf);
			offset += lsn;
		}

		lsv = p[offset++];
		trace("\tSoftware Version len: %d\n", lsv);
		if (lsv > 0) {
			char buf[65] = {0};

			memcpy(buf, &p[offset], lsv);
			trace("\tSoftware Version: %s\n", buf);
			offset += lsv;
		}

		lee = p[offset++];
		trace("\tExecution Env len: %d\n", lee);
		if (lee > 0) {
			char buf[65] = {0};

			memcpy(buf, &p[offset], lee);
			trace("\tExecution Env: %s\n", buf);
			offset += lee;
		}

		num_radios = p[offset++];
		trace("\tnum radio: %d\n", num_radios);
		for (i = 0; i < num_radios; i++) {
			struct device_inventory_radio *ir =
				(struct device_inventory_radio *)&p[offset];

			trace("\n\t\tmacaddr: " MACFMT "\n", MAC2STR(ir->ruid));
			trace("\t\tvendor id len: %d\n", ir->lcv);
			if (ir->lcv > 0) {
				char buf[65] = {0};

				memcpy(buf, ir->cv, ir->lcv);
				trace("\t\t vendor: %s\n", buf);
			}
		}
	}
#endif

	return 0;
}


int debug_channel_pref_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int idx, offset = 0;
	int i, j;
	struct tlv *tv[4][16] = { 0 };
	int ret;

	trace("%s: --->\n", __func__);
	trace("parsing channel pref of |:" MACFMT "|\n",
			MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 4, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx = 0;
	while (tv[0][idx]) {
		int num_opclass;
		uint8_t mac[6] = { 0 };
		struct tlv *t = (struct tlv *)tv[0][idx++];

		offset = 0;
		memcpy(mac, &t->data[offset], 6);
		trace("\tradio_id: " MACFMT "\n", MAC2STR(mac));
		offset += 6;
		num_opclass = t->data[offset++];
		trace("\tnum_opclass: %d\n", num_opclass);

		for (i = 0; i < num_opclass; i++) {
			uint8_t num_channel;
			uint8_t preference;

			trace("\t\tclass_id: %d\n", t->data[offset++]);
			num_channel = t->data[offset++];
			trace("\t\tnum_channel: %d\n", num_channel);

			for (j = 0; j < num_channel; j++)
				trace("\t\t\tchannel: %d\n", t->data[offset++]);

			preference = t->data[offset++];
			trace("\t\tpreference: %d\n",
					(preference & CHANNEL_PREF_MASK) >> 4);
			trace("\t\tpreference_reason: %d\n",
					preference & CHANNEL_PREF_REASON);
		}
	}

	idx = 0;
	while (tv[1][idx]) {
		uint8_t mac[6] = { 0 };
		int num_opclass;
		struct tlv *t = (struct tlv *)tv[1][idx++];

		offset = 0;
		memcpy(mac, &t->data[offset], 6);
		offset += 6;
		trace("\tradio_id: " MACFMT "\n", MAC2STR(mac));
		num_opclass = t->data[offset++];
		trace("\tnum_restricted_op_class: %d\n", num_opclass);

		for (i = 0; i < num_opclass; i++) {
			int num_channel;

			trace("\t\top_class: %d\n", t->data[offset++]);
			num_channel = t->data[offset++];
			trace("\t\top_channel_nr: %d\n", num_channel);

			for (j = 0; j < num_channel; j++) {
				trace("\t\t\tchannel: %d\n", t->data[offset++]);
				trace("\t\t\tmin_freq_sep: %d\n", t->data[offset++]);
			}
		}
	}

	if (tv[2][0]) {
		uint8_t num_radio;
		uint8_t num_pairs;
		struct tlv *t = (struct tlv *)tv[2][0];

		offset = 0;
		num_radio = t->data[offset++];
		trace("\tnbr_radios: %d\n", num_radio);

		for (i = 0; i < num_radio; i++) {
			uint8_t mac[6] = { 0 };

			memcpy(mac, &t->data[offset], 6);
			offset += 6;
			trace("\t\tradio_id: " MACFMT "\n", MAC2STR(mac));
			trace("\t\top_class: %d\n", t->data[offset++]);
			trace("\t\tchannel: %d\n", t->data[offset++]);
			trace("\t\tcompletion_status %d\n", t->data[offset++]);
			num_pairs = t->data[offset++];
			trace("\t\tnbr_pairs %d\n", num_pairs);

			for (j = 0; j < num_pairs; j++) {
				trace("\t\t\top_class_detected: %d\n",
						t->data[offset++]);
				trace("\t\t\tch_detected: %d\n",
						t->data[offset++]);
			}
		}
	}

	if (tv[3][0]) {
		uint8_t num_channels;
		uint8_t num_pairs;
		struct tlv *t = (struct tlv *)tv[3][0];

		offset = 0;
		num_channels = t->data[offset++];
		trace("\tnbr_available_ch: %d\n", num_channels);
		for (i = 0; i < num_channels; i++) {
			trace("\t\top_class: %d\n", t->data[offset++]);
			trace("\t\tchannel: %d\n", t->data[offset++]);
			trace("\t\ttime: %d\n", BUF_GET_BE16(t->data[offset]));
			offset += 2;
		}

		num_pairs = t->data[offset++];
		trace("\tnbr_pairs_duration: %d\n", num_pairs);
		for (i = 0; i < num_pairs; i++) {
			trace("\t\top_class: %d\n", t->data[offset++]);
			trace("\t\tchannel: %d\n", t->data[offset++]);
			trace("\t\ttime: %d\n", BUF_GET_BE16(t->data[offset]));
			offset += 2;
		}

		num_pairs = t->data[offset++];
		trace("\tnbr_pairs_coundown: %d\n", num_pairs);
		for (i = 0; i < num_pairs; i++) {
			trace("\t\top_class: %d\n", t->data[offset++]);
			trace("\t\tchannel: %d\n", t->data[offset++]);
			trace("\t\ttime: %d\n", BUF_GET_BE16(t->data[offset]));
			offset += 2;
		}
	}

	return 0;
}

int debug_channel_sel_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	trace("parsing channel selection response of |" MACFMT "|\n",
			MAC2STR(cmdu->origin));

	int idx;
	struct tlv *tv[1][16];
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx = 0;
	while (tv[0][idx]) {
		struct tlv_channel_selection_resp *p =
			(struct tlv_channel_selection_resp *)tv[0][idx++]->data;

		trace("\tradio_id: " MACFMT "\n", MAC2STR(p->radio));
		trace("\tresponse_code: %d\n", p->response);
	}

	return 0;
}

int debug_oper_channel_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	trace("parsing operating channel report of |" MACFMT "|\n",
		MAC2STR(cmdu->origin));

	int idx;
	int ret;
	struct tlv *tv[2][16];
	/*
	 * [0] MAP_TLV_OPERATING_CHANNEL_REPORT
	 * todo:
	 * [1] MAP_TLV_SPATIAL_REUSE_REPORT
	 */

	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx= 0;
	while (tv[0][idx]) {
		int i, num_opclass;
		int offset = 0;
		uint8_t mac[6] = {0};
		uint8_t *p = (uint8_t *)tv[0][idx++]->data;

		memcpy(mac, &p[offset], 6);
		offset += 6;
		trace("\tradio_id: " MACFMT "\n", MAC2STR(mac));
		num_opclass = p[offset++];

		trace("\tch_preference_op_class_nr: %d\n", num_opclass);
		for (i = 0; i < num_opclass; i++) {
			trace("\t\top_class: %d\n", p[offset++]);
			trace("\t\top_channel: %d\n", p[offset++]);
		}

		trace("\tcurr_tx_power: %d\n", p[offset++]);
	}

	return 0;
}

int debug_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	struct tlv *tv[3][16];
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		struct tlv_client_info *p =
			(struct tlv_client_info *)tv[0][0]->data;

		trace("MAP_TLV_CLIENT_INFO:\n");
		trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
		trace("\tmacaddr: "MACFMT "\n", MAC2STR(p->macaddr));
	}

	if (tv[1][0]) {
		struct tlv *t = tv[1][0];
		struct tlv_client_cap_report *p =
			(struct tlv_client_cap_report *)t->data;

		trace("MAP_TLV_CLIENT_CAPABILITY_REPORT\n");
		trace("\tresult: 0x%02x\n", p->result);
		if (p->result == 0x00) {
			char *frame;
			uint16_t len = 0;

			len = BUF_GET_BE16(t->len) - 1; /* result code */
			trace("\tframe len: %d\n", len);

			frame = (char *)calloc(sizeof(char),
					((2 * len) + 1));
			if (frame) {
				btostr(p->frame, len, frame);
				trace("\tframe: %s\n", frame);
				free(frame);
			}
		}
	}

	if (tv[2][0]) {
		struct tlv_error_code *p =
			(struct tlv_error_code *)tv[2][0]->data;

		trace("MAP_TLV_ERROR_CODE\n");
		trace("\treason: 0x%02x\n", p->reason);
		trace("\tmacaddr: " MACFMT "\n", MAC2STR(p->macaddr));
	}

	return 0;
}

int debug_ap_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int i;
	int offset, idx = 0;
	struct tlv *tv[7][16] = { 0 };
	int ret;

	trace("%s: --->\n", __func__);
	trace("parsing ap metric response |" MACFMT "\n",
			MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	idx = 0;
	while (tv[0][idx]) {
		size_t out_len;
		int index = 0;
		unsigned char est_str[16];
		struct tlv_ap_metrics *p = (struct tlv_ap_metrics *) tv[0][idx++]->data;

		trace("MAP_TLV_AP_METRICS:\n");
		trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
		trace("\tchannel_utilization: %d\n", p->channel_utilization);
		trace("\tnum_station: %d\n", BUF_GET_BE16(p->num_station));
		trace("\tesp_ac: %d\n", p->esp_ac);
		if (p->esp_ac & ESP_AC_BE) {
			out_len = sizeof(est_str);
			memset(est_str, 0, sizeof(est_str));
			base64_encode(p->esp_be, 3, est_str, &out_len);
			trace("\tservice_param_info_be:%s\n", (char *)est_str);
		}
		if (p->esp_ac & ESP_AC_BK) {
			out_len = sizeof(est_str);
			memset(est_str, 0, sizeof(est_str));
			base64_encode(p->esp + index, 3, est_str, &out_len);
			trace("\tservice_param_info_bk:%s\n", (char *)est_str);
			index += 3;
		}
		if (p->esp_ac & ESP_AC_VO) {
			out_len = sizeof(est_str);
			memset(est_str, 0, sizeof(est_str));
			base64_encode(p->esp + index, 3, est_str, &out_len);
			trace("\tservice_param_info_vo:%s\n", (char *)est_str);
			index += 3;
		}
		if (p->esp_ac & ESP_AC_VI) {
			out_len = sizeof(est_str);
			memset(est_str, 0, sizeof(est_str));
			base64_encode(p->esp + index, 3, est_str, &out_len);
			trace("\tservice_param_info_vi:%s\n", (char *)est_str);
		}
	}

	idx = 0;
	while (tv[1][idx]) {
		struct tlv_assoc_sta_traffic_stats *p =
			(struct tlv_assoc_sta_traffic_stats *) tv[1][idx++]->data;

		trace("MAP_TLV_ASSOCIATED_STA_TRAFFIC_STATS:\n");
		trace("\tsta: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tbytes_sent: %u\n", BUF_GET_BE32(p->tx_bytes));
		trace("\tbytes_received: %u", BUF_GET_BE32(p->rx_bytes));
		trace("\tpackets_sent: %u\n", BUF_GET_BE32(p->tx_packets));
		trace("\tpackets_received: %u\n", BUF_GET_BE32(p->rx_packets));
		trace("\ttx_packets_err: %u\n", BUF_GET_BE32(p->tx_err_packets));
		trace("\trx_packets_err: %u\n", BUF_GET_BE32(p->rx_err_packets));
		trace("\tretransmission_cnt: %u\n", BUF_GET_BE32(p->rtx_packets));
	}

	idx = 0;
	while (tv[2][idx]) {
		uint8_t *tv_data = (uint8_t *)tv[2][idx++]->data;
		struct tlv_assoc_sta_link_metrics *p =
			(struct tlv_assoc_sta_link_metrics *)tv_data;

		trace("MAP_TLV_ASSOCIATED_STA_LINK_METRICS:\n");
		trace("\tsta: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tnum_bss: %d\n", p->num_bss);
		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct assoc_sta_link_metrics_bss *b =
				(struct assoc_sta_link_metrics_bss *)&tv_data[offset];

			trace("\t\tbssid: " MACFMT "\n", MAC2STR(b->bssid));
			trace("\t\ttime_delta: %u\n",
					BUF_GET_BE32(b->time_delta));
			trace("\t\tdl_thput: %u\n",
					BUF_GET_BE32(b->dl_thput));
			trace("\t\tul_thput: %u\n",
					BUF_GET_BE32(b->ul_thput));
			trace("\t\tul_rcpi: %d\n", b->ul_rcpi);
			offset += sizeof(*b);
		}
	}

	idx = 0;
	while (tv[3][idx]) {
		struct tlv_ap_ext_metrics *p =
			(struct tlv_ap_ext_metrics *) tv[3][idx++]->data;

		trace("MAP_TLV_AP_EXTENDED_METRICS:\n");
		trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
		trace("\ttx_bytes_ucast: %u\n", BUF_GET_BE32(p->tx_bytes_ucast));
		trace("\trx_bytes_ucast: %u\n", BUF_GET_BE32(p->rx_bytes_ucast));
		trace("\ttx_bytes_mcast: %u\n", BUF_GET_BE32(p->tx_bytes_mcast));
		trace("\trx_bytes_mcast: %u\n", BUF_GET_BE32(p->rx_bytes_mcast));
		trace("\ttx_bytes_bcast: %u\n", BUF_GET_BE32(p->tx_bytes_bcast));
		trace("\trx_bytes_bcast: %u\n", BUF_GET_BE32(p->rx_bytes_bcast));
	}

	idx = 0;
	while (tv[4][idx]) {
		struct tlv_radio_metrics *p =
			(struct tlv_radio_metrics *) tv[4][idx++]->data;

		trace("MAP_TLV_RADIO_METRICS:\n");
		trace("\tradio_id: " MACFMT "\n", MAC2STR(p->radio));
		trace("\tnoise: %d\n", p->noise);
		trace("\ttransmit: %d\n", p->transmit);
		trace("\treceive_self: %d\n", p->receive_self);
		trace("\treceive_other: %d\n", p->receive_other);
	}

	idx = 0;
	while (tv[5][idx]) {
		uint8_t *tv_data = (uint8_t *)tv[5][idx++]->data;
		struct tlv_sta_ext_link_metric *p =
			(struct tlv_sta_ext_link_metric *)tv_data;

		trace("MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS:\n");
		trace("\tsta: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tnum_bss: %d\n", p->num_bss);
		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct sta_ext_link_metric_bss *b =
				(struct sta_ext_link_metric_bss *)&tv_data[offset];

			trace("\t\tbssid: " MACFMT "\n", MAC2STR(b->bssid));
			trace("\t\tdl_rate: %u\n", BUF_GET_BE32(b->dl_rate));
			trace("\t\tul_rate: %u\n", BUF_GET_BE32(b->ul_rate));
			trace("\t\trx_util: %u\n", BUF_GET_BE32(b->rx_util));
			trace("\t\ttx_util: %u\n", BUF_GET_BE32(b->tx_util));
			offset += sizeof(*b);
		}
	}

	return 0;
}

int debug_link_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	return 0;
}

int debug_sta_link_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	int i;
	int offset = 0;
	struct tlv *tv[3][16] = { 0 };
	int ret;

	trace("%s: --->\n", __func__);
	trace("parsing sta link metric response |" MACFMT "\n",
			MAC2STR(cmdu->origin));
	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		uint8_t *tv_data = (uint8_t *)tv[0][0]->data;
		struct tlv_assoc_sta_link_metrics *p =
			(struct tlv_assoc_sta_link_metrics *)tv_data;

		trace("MAP_TLV_ASSOCIATED_STA_LINK_METRICS:\n");
		trace("\tsta: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tnum_bss: %d\n", p->num_bss);
		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct assoc_sta_link_metrics_bss *b =
				(struct assoc_sta_link_metrics_bss *)&tv_data[offset];

			trace("\t\tbssid: " MACFMT "\n", MAC2STR(b->bssid));
			trace("\t\ttime_delta: %u\n",
					BUF_GET_BE32(b->time_delta));
			trace("\t\tdl_thput: %u\n",
					BUF_GET_BE32(b->dl_thput));
			trace("\t\tul_thput: %u\n",
					BUF_GET_BE32(b->ul_thput));
			trace("\t\tul_rcpi: %d\n", b->ul_rcpi);
			offset += sizeof(*b);
		}
	}

	if (tv[1][0]) {
		struct tlv_error_code *p =
			(struct tlv_error_code *)tv[1][0]->data;

		trace("MAP_TLV_ERROR_CODE:\n");
		trace("\treason_code: %d\n", p->reason);
		trace("\taddr: " MACFMT "\n", MAC2STR(p->macaddr));
	}

	if (tv[2][0]) {
		uint8_t *tv_data = (uint8_t *)tv[2][0]->data;
		struct tlv_sta_ext_link_metric *p =
			(struct tlv_sta_ext_link_metric *)tv_data;

		trace("MAP_TLV_ASSOCIATED_STA_EXT_LINK_METRICS:\n");
		trace("\tsta: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tnum_bss: %d\n", p->num_bss);
		offset = sizeof(*p);
		for (i = 0; i < p->num_bss; i++) {
			struct sta_ext_link_metric_bss *b =
				(struct sta_ext_link_metric_bss *)&tv_data[offset];

			trace("\t\tbssid: " MACFMT "\n", MAC2STR(b->bssid));
			trace("\t\tdl_rate: %u\n", BUF_GET_BE32(b->dl_rate));
			trace("\t\tul_rate: %u\n", BUF_GET_BE32(b->ul_rate));
			trace("\t\trx_util: %u\n", BUF_GET_BE32(b->rx_util));
			trace("\t\ttx_util: %u\n", BUF_GET_BE32(b->tx_util));
			offset += sizeof(*b);
		}
	}

	return 0;
}

int debug_unassoc_sta_link_metrics_response(void *cntlr,
		struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	int i;
	int offset = 0;
	struct tlv *tv[1][16];
	int ret;

	trace("parsing unassociated sta link metric response |" \
		   MACFMT "\n", MAC2STR(cmdu->origin));
	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		uint8_t *tv_data = (uint8_t *)tv[0][0]->data;
		struct tlv_unassoc_sta_link_metrics_resp *p =
			(struct tlv_unassoc_sta_link_metrics_resp *)tv_data;

		trace("MAP_TLV_UNASSOCIATED_STA_LINK_METRICS:\n");
		trace("\topclass: %d\n", p->opclass);
		trace("\tnum_sta: %d\n", p->num_sta);

		offset = sizeof(*p);
		for (i = 0; i < p->num_sta; i++) {
			struct unassoc_sta_link_metrics_sta *b =
				(struct unassoc_sta_link_metrics_sta *)&tv_data[offset];

			trace("\t\tmacaddr: " MACFMT "\n", MAC2STR(b->macaddr));
			trace("\t\tchannel: %d\n", b->channel);
			trace("\t\ttime_delta: %u\n",
					BUF_GET_BE32(b->time_delta));
			trace("\t\tul_rcpi: %d\n", b->ul_rcpi);
			offset += sizeof(*b);
		}
	}

	return 0;
}

int debug_beacon_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	struct tlv *tv[1][16] = {0};
	int ret = 0;

	trace("%s: --->\n", __func__);
	dbg("parsing beacon metrics response |" \
		   MACFMT "\n", MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return -1;
	}

	if (tv[0][0]) {
		uint8_t *tv_data = (uint8_t *)tv[0][0]->data;
		struct tlv_beacon_metrics_resp *resp =
			(struct tlv_beacon_metrics_resp *) tv_data;
		uint8_t *ppos = resp->element;
		struct bcn_meas_element *elem;
		int i;

		trace("MAP_TLV_BEACON_METRICS_RESPONSE:\n");
		trace("\tsta_macaddr: " MACFMT "\n", MAC2STR(resp->sta_macaddr));
		trace("\tnum_element: %d\n", resp->num_element);

		for (i = 0; i < resp->num_element; i++) {
			elem = (struct bcn_meas_element *) ppos;

			if (elem->tag_number == 0x27) {
				trace("\t\telement: %d\n", i);
				trace("\t\top_class: %d\n", elem->op_class);
				trace("\t\tchannel: %d\n", elem->channel);
				trace("\t\trcpi: %d\n", elem->rcpi);
				trace("\t\trsni: %d\n", elem->rsni);
				trace("\t\tbssid: " MACFMT "\n", MAC2STR(elem->bssid));
			}

			/* Move to the next measurement report */
			ppos = ppos + elem->tag_length + 2;
		}
	}

	return ret;
}

int debug_sta_steer_btm_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	trace("parsing steer btm report of |:" MACFMT "|\n",
			MAC2STR(cmdu->origin));

	struct tlv *tv[1][16];
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		struct tlv_steer_btm_report *p =
			(struct tlv_steer_btm_report *)tv[0][0]->data;

		trace("\tbssid: " MACFMT "\n", MAC2STR(p->bssid));
		trace("\tsta_macaddr: " MACFMT "\n", MAC2STR(p->sta_macaddr));
		trace("\tstatus_code: %d\n", p->status);

		if (p->status == 0x00)
			trace("\ttarget_bbsid: " MACFMT "\n",
					MAC2STR((uint8_t*)p->target_bssid));
	}

	return 0;
}

int debug_sta_steer_complete(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	trace("parsing sta steer complete of |:" MACFMT "|\n",
			MAC2STR(cmdu->origin));
	return 0;
}

int debug_hld_message(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	struct tlv *t;
	uint8_t proto;
	uint8_t *data;
	int data_len;

	trace("%s: --->\n", __func__);

	t = cmdu_peek_tlv(cmdu, MAP_TLV_HIGHER_LAYER_DATA);
	if (!t) {
		dbg("%s: higher layer data TLV not found\n", __func__);
		return -1;
	}

	data_len = tlv_length(t) - 1;
	proto = t->data[0];
	data = t->data + 1;

	UNUSED(data);

	trace("%s TLV received proto %u data_len %u!!\n", __func__,
		proto, data_len);
	return 0;
}


int debug_backhaul_sta_steer_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	return 0;
//	int i;
//	uint8_t *tlv = NULL;
//
//	trace("%s: --->\n", __func__);
//	trace("parsing backhaul sta steer response of |%s:" MACFMT "|\n",
//			cmdu->intf_name, MAC2STR(cmdu->origin));
//
//	for (i = 0; i < cmdu->num_tlvs; i++) {
//		tlv = cmdu->tlvs[i];
//		trace("CMDU type: %s\n", map_stringify_tlv_type(*tlv));
//		switch (*tlv) {
//		case MAP_TLV_BACKHAUL_STEERING_RESPONSE:
//			{
//				struct tlv_backhaul_steer_resp *p =
//						(struct tlv_backhaul_steer_resp *)tlv;
//
//				trace("\tbssid: " MACFMT "\n",
//						MAC2STR(p->bssid));
//				trace("\taddr: " MACFMT "\n",
//						MAC2STR(p->addr));
//
//				trace("\tres_code: 0x%02x\n", p->res_code);
//
//				break;
//			}
//		case MAP_TLV_ERROR_CODE:
//			{
//				struct tlv_error_code *p =
//						(struct tlv_error_code *)tlv;
//
//				trace("\treason_code: 0x%02x\n", p->reason_code);
//				break;
//			}
//		default:
//			fprintf(stdout, "unknown TLV in CMDU:|%s|",
//					map_stringify_cmdu_type(cmdu->message_type));
//			break;
//		}
//		trace("\n");
//	}
//
//	return 0;
}

#define TIMESTAMP_MAX_LEN 256
int debug_channel_scan_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	int i, j, num = 256;
	int offset = 0;
	uint8_t time_len;
	uint16_t num_neightbor;
	uint8_t bw_len;
	uint8_t *tv_data = NULL;
	struct tlv *tv_tsp[1][16];
	struct tlv *tv_scan[256];
	char timestamp[TIMESTAMP_MAX_LEN] = {0};
	struct tlv_timestamp *p = NULL;


	if (!validate_channel_scan_report(cmdu, tv_tsp, tv_scan, &num, n->map_profile)) {
		dbg("cmdu validation: [CHANNEL_SCAN_REPORT] failed\n");
		return -1;
	}

	trace("\nTLV type: MAP_TLV_TIMESTAMP\n");
	tv_data = (uint8_t *)tv_tsp[0][0]->data;
	p = (struct tlv_timestamp *)tv_data;

	trace("\tlen: %d\n", p->len);

	/*Max size is 256 as per the Multi-ap r2 spec*/
	if (p->len > (TIMESTAMP_MAX_LEN - 1))
		return -1;

	strncpy(timestamp, (char *)p->timestamp, p->len);
	timestamp[p->len] = '\0';

	trace("\ttimestamp: %s\n", timestamp);
	trace("\n");

	for (i = 0; i < num; i++) {
		uint8_t info = 0x00;
		tv_data = (uint8_t *)tv_scan[i]->data;
		struct tlv_channel_scan_result *p1 = (struct tlv_channel_scan_result *)tv_data;

		trace("\nTLV type: MAP_TLV_CHANNEL_SCAN_RES\n");
		trace("\tradio: " MACFMT "\n", MAC2STR(p1->radio));
		trace("\topclass: %d\n", p1->opclass);
		trace("\tchannel: %d\n", p1->channel);
		trace("\tstatus: 0x%02x\n", p1->status);

		offset = sizeof(*p1);
		if (p1->status == 0x00) {
			time_len = tv_data[offset++];

			trace("\tlen: %d\n", time_len - 1);
			trace("\ttimestamp: ");
			for (j = 0; j < time_len; j++) {
				trace("%c", tv_data[offset]);
				offset++;
			}
			trace("\n");

			trace("\tutilization: %d\n", tv_data[offset]);
			offset++;
			trace("\tnoise: %d\n", tv_data[offset]);
			offset++;
			num_neightbor = BUF_GET_BE16(tv_data[offset]);
			trace("\tnum_neighbor: %d\n", num_neightbor);
			offset += 2;
			for (j = 0; j < num_neightbor; j++) {
				char ssidstr[33] = {0};
				uint8_t len = 0, ssidlen;

				trace("\n\t\tbssid: " MACFMT "\n", MAC2STR(&tv_data[offset]));
				offset += 6;
				ssidlen = tv_data[offset++];
				trace("\t\tlen: %d\n", ssidlen);
				len = (ssidlen + 1 > sizeof(ssidstr)
						? sizeof(ssidstr) : ssidlen + 1);
				snprintf(ssidstr, len, "%s", (char *)&tv_data[offset]);
				trace("\t\tssid: %s\n", ssidstr);
				offset += ssidlen;
				trace("\t\trcpi: %d\n", (int)tv_data[offset]);
				offset++;
				bw_len = tv_data[offset++];
				trace("\t\tlen: %d\n", bw_len);
				trace("\t\tbwstr: %d\n", atoi((char *)&tv_data[offset]));
				offset += bw_len;
				info = tv_data[offset];
				trace("\t\tinfo: %d\n", info);
				offset++;

				if (info & CH_SCAN_RESULT_BSSLOAD_PRESENT) {
					trace("\t\t\tch_util: %d\n", tv_data[offset]);
					offset++;
					trace("\t\t\tsta_count: %d\n", tv_data[offset]);
					offset += 2;
				}
			}
		}
		trace("\n");
	}

	return 0;
}

int debug_sta_disassoc_stats(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	struct tlv *tv[3][16];
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (!tv[0][0] || !tv[1][0] || !tv[2][0])
		return -1;

	if (tv[0][0]) {
		struct tlv_sta_mac *p = (struct tlv_sta_mac *)tv[0][0]->data;

		trace("\taddr: " MACFMT "\n", MAC2STR(p->macaddr));
	}

	if (tv[1][0]) {
		struct tlv_reason_code *p = (struct tlv_reason_code *)tv[1][0]->data;

		trace("\treason_code: %d\n", BUF_GET_BE16(p->code));
	}

	if (tv[2][0]) {
		struct tlv_assoc_sta_traffic_stats *p =
			(struct tlv_assoc_sta_traffic_stats *)tv[2][0]->data;

		trace("\taddr: " MACFMT "\n", MAC2STR(p->macaddr));
		trace("\tbytes_sent: %d\n", BUF_GET_BE32(p->tx_bytes));
		trace("\tbytes_received: %d\n", BUF_GET_BE32(p->rx_bytes));
		trace("\tpackets_sent: %d\n", BUF_GET_BE32(p->tx_packets));
		trace("\tpackets_received: %d\n", BUF_GET_BE32(p->rx_packets));
		trace("\ttx_packets_err: %d\n", BUF_GET_BE32(p->tx_err_packets));
		trace("\trx_packets_err: %d\n", BUF_GET_BE32(p->tx_err_packets));
		trace("\tretransmission_cnt: %d\n", BUF_GET_BE32(p->rtx_packets));
	}

	return 0;
}

int debug_assoc_status_notification(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	uint8_t *p;
	int i, num_bss;
	int offset = 0;
	struct tlv *tv[1][16];
	int ret;

	trace("%s: ---> origin: " MACFMT "\n", __func__, MAC2STR(cmdu->origin));
	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (!tv[0][0])
		return -1;

	p = (uint8_t *)tv[0][0]->data;
	num_bss = p[offset++];
	trace("num_bss: %d\n", num_bss);
	for (i = 0; i < num_bss; i++) {
		trace("\tbssid: " MACFMT "\n", MAC2STR(&p[offset]));
		offset += 6;
		trace("\tstatus: %d\n", p[offset++]);
	}

	return 0;
}

int debug_tunneled_message(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	struct tlv *tv[3][16] = { 0 };
	int ret;

	trace("%s: --->\n", __func__);
	trace("parsing tunnel message |" MACFMT "\n",
			MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 3, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (tv[0][0]) {
		struct tlv_source_info *p =
			(struct tlv_source_info *) tv[0][0]->data;

		trace("\tmac: " MACFMT "\n", MAC2STR(p->macaddr));
	}

	if (tv[1][0]) {
		struct tlv_tunnel_msg_type *p =
			(struct tlv_tunnel_msg_type *) tv[1][0]->data;

		trace("\ttunnel_protocol_type: %d\n", p->type);
	}

	if (tv[2][0]) {
		struct tlv *t = (struct tlv *)tv[2][0];
		char *framestr = NULL;
		uint16_t frame_len;
		struct tlv_tunneled *p =
			(struct tlv_tunneled *) tv[2][0]->data;

		frame_len = BUF_GET_BE16(t->len);
		trace("\tlen: %d\n", frame_len);
		if (frame_len > 0) {
			framestr = calloc((2 * frame_len) + 1,
					sizeof(char));
		}

		if (framestr) {
			btostr(p->frame, frame_len, framestr);
			trace("\tframe_body: %s\n", framestr);
			free(framestr);
		}
	}

	return 0;
}

int debug_backhaul_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	uint8_t *tv_data;
	struct tlv *tv[1][16];
	int num = 0;
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, n->map_profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return ret;
	}

	if (!tv[0][num]) {
		dbg("No TLV_BACKHAUL_STA_RADIO_CAPABILITY received!\n");
		return -1;
	}

	while (tv[0][num]) {
		if (tv[0][num]->type != MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY) {
			dbg("Wrong received TLV type!\n");
			return -1;
		}
		tv_data = (uint8_t *)tv[0][num]->data;
		struct tlv_bsta_radio_cap *p = (struct tlv_bsta_radio_cap *)tv_data;

		trace("\nTLV type: MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY\n");
		trace("\tradio: " MACFMT "\n", MAC2STR(p->radio));
		trace("\tmacaddr_included: %d\n", p->macaddr_included);
		if (p->macaddr_included)
			trace("\tmacaddr: " MACFMT "\n", MAC2STR((uint8_t *)p->macaddr));
		num++;
	}
	return 0;
}


int debug_failed_connection_msg(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	return 0;
}

#if (EASYMESH_VERSION > 2)
int debug_proxied_encap_dpp(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	const int easymesh_rev = 4;
	struct tlv *tlvs[PROXIED_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (map_cmdu_parse_tlvs(cmdu, tlvs, PROXIED_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	/* One 1905 Encap DPP TLV */
	trace_tlv_1905_encap_dpp(tlvs[PROXIED_ENCAP_1905_ENCAP_DPP_IDX][0]);

	/* Zero or One Chirp Value TLV */
	if (tlvs[PROXIED_ENCAP_CHIRP_VALUE_IDX][0])
		trace_tlv_dpp_chirp_value(tlvs[PROXIED_ENCAP_CHIRP_VALUE_IDX][0]);

	return 0;
}

int debug_direct_encap_dpp(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	const int easymesh_rev = 4;
	struct tlv *tlvs[DIRECT_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (map_cmdu_parse_tlvs(cmdu, tlvs, DIRECT_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	/* One DPP Message TLV */
	trace_tlv_direct_encap_dpp(tlvs[DIRECT_ENCAP_DPP_MESSAGE_IDX][0]);

	return 0;
}

int debug_bss_configuration_request(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);

	int easymesh_rev = n->map_profile;
	const int max_num_of_tlvs = 16;
	struct tlv *tlvs[BSS_CFG_REQ_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };
	const struct tlv *tlv;
	int i;

	if (map_cmdu_parse_tlvs(cmdu, tlvs, BSS_CFG_REQ_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	/* One Multi-AP Profile TLV */
	tlv = tlvs[BSS_CFG_REQ_MULTIAP_PROFILE_IDX][0];
	trace_tlv_map_profile((struct tlv_map_profile *)tlv->data);

	/* One SupportedService TLV */
	tlv = tlvs[BSS_CFG_REQ_SUPPORTED_SERVICE_IDX][0];
	trace_tlv_supported_service((struct tlv_supported_service *)tlv->data);

	/* One AKM Suite Capabilities TLV */
	tlv = tlvs[BSS_CFG_REQ_AKM_SUITE_CAPS_IDX][0];
	trace_tlv_akm_suite_caps((struct tlv_akm_suite_caps *)tlv->data);

	/* One or more AP Radio Basic Capabilities TLV */
	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_AP_RADIO_BASIC_CAPS_IDX][i]) {

		tlv = tlvs[BSS_CFG_REQ_AP_RADIO_BASIC_CAPS_IDX][i++];
		trace_tlv_ap_radio_basic_cap((struct tlv_ap_radio_basic_cap *)tlv->data);
	}

	/* Zero or more Backhaul STA Radio Capabilities TLV */
	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_BACKHAUL_STA_RADIO_CAPS_IDX][i]) {

		tlv = tlvs[BSS_CFG_REQ_BACKHAUL_STA_RADIO_CAPS_IDX][i++];
		trace_tlv_bsta_radio_cap((struct tlv_bsta_radio_cap  *)tlv->data);
	}

	/* One Profile-2 AP Capability TLV */
	tlv = tlvs[BSS_CFG_REQ_PROFILE2_AP_CAP_IDX][0];
	trace_tlv_profile2_ap_cap((struct tlv_profile2_ap_cap *)tlv->data);

	/* One or more AP Radio Advanced Capabilities TLV */
	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_AP_RADIO_ADVANCED_CAPS_IDX][i]) {

		tlv = tlvs[BSS_CFG_REQ_AP_RADIO_ADVANCED_CAPS_IDX][i++];
		trace_tlv_ap_radio_adv_cap((struct tlv_ap_radio_adv_cap  *)tlv->data);
	}

	/* One BSS Configuration Request TLV */
	tlv = tlvs[BSS_CFG_REQ_CONFIG_REQUEST_IDX][0];
	trace_tlv_bss_configuration(tlv);

	return 0;
}

int debug_bss_configuration_result(void *cntlr, struct cmdu_buff *cmdu, struct node *n)
{
	trace("%s: --->\n", __func__);
	int easymesh_rev = n->map_profile;

	struct tlv *tlvs[BSS_CFG_RESULT_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (map_cmdu_parse_tlvs(cmdu, tlvs, BSS_CFG_RESULT_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	/* One BSS Configuration Report TLV */
	trace_tlv_bss_configuration_report(
		(struct tlv_bss_configuration_report *)
			tlvs[BSS_CFG_RESULT_BSS_CONFIG_REPORT_IDX][0]->data);

	return 0;
}

int debug_dpp_bootstraping_uri_notificiation(void *cntlr, struct cmdu_buff *cmdu,
				    struct node *n)
{
	trace("%s: --->\n", __func__);

	const int easymesh_rev = 4;
	struct tlv *tlvs[DPP_BOOTSTRAP_URI_NOTIF_MAX_NUMBER_OF_TLV_TYPES][16] = { 0 };

	if (map_cmdu_parse_tlvs(cmdu, tlvs, DPP_BOOTSTRAP_URI_NOTIF_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	/* One DPP Bootstraping URI Notification TLV */
	trace_tlv_dpp_bootstraping_uri_notification(tlvs[DPP_BOOTSTRAP_URI_NOTIF_IDX][0]);

	return 0;
}
#endif /* EASYMESH_VERSION > 2 */
