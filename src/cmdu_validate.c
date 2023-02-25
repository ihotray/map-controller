
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <json-c/json.h>
#include <libubus.h>
#include <uci.h>

#include <easy/easy.h>
#include <wifidefs.h>

#include <easymesh.h>
#include <1905_tlvs.h>
#include <i1905_wsc.h>
#include <cmdu.h>
#include <map_module.h>

#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "cntlr.h"
#include "cntlr_cmdu.h"
#include "cntlr_tlv.h"
#include "cmdu_validate.h"
#include "cntlr_map.h"

static int check_serialized_tlv(struct tlv *t, uint16_t len)
{
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);

	if (tlv_len != len)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	return 0;
}

/* Check AP Radio Basic Capabilities TLV */
static int check_ap_radio_basic_cap_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len = 0;
	struct tlv_ap_radio_basic_cap *tlv;
	int i, offset = 0;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv = (struct tlv_ap_radio_basic_cap *) t->data;
	if (!tlv)
		return -1;

	tv_data = (uint8_t *)tlv;

	/* radio (6 bytes), max_bssnum (1), num_opclass (1) */
	if (offset + sizeof(*tlv) > tlv_len)
		return -1;

	offset += sizeof(*tlv);

	for (i = 0; i < tlv->num_opclass; i++) {
		struct ap_radio_basic_cap_opclass *op =
			(struct ap_radio_basic_cap_opclass *)&tv_data[offset];

		/* classid (1), max_txpower(1), num_nonomp_channel (1) */
		if (offset + sizeof(*op) > tlv_len)
			return -1;

		offset += sizeof(*op);

		/* nonop_channel (num_nonop_channel bytes) */
		if (offset + op->num_nonop_channel > tlv_len)
			return -1;

		offset += op->num_nonop_channel;
	}

	return 0;
}

/* Check AP HT Capabilities TLV */
static int check_ap_ht_cap_tlv(struct tlv *t)
{
	/* Confirms proper TLV struct defintion & prevents TLV data lost */
	if (tlv_length(t) != sizeof(struct tlv_ap_ht_cap))
		return -1;

	return 0;
}

/* Check AP VHT Capabilities TLV */
static int check_ap_vht_cap_tlv(struct tlv *t)
{
	/* Confirms proper TLV struct defintion & prevents TLV data lost */
	if (tlv_length(t) != sizeof(struct tlv_ap_vht_cap))
		return -1;

	return 0;
}

/* Check AP HE Capabilities TLV */
static int check_ap_he_cap_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len = 0;
	struct tlv_ap_he_cap *tlv = NULL;
	struct ap_he_cap_mcs *hemcs = NULL;
	int offset = 0;

	tlv_len = tlv_length(t);
	if (!tlv_len || tlv_len < sizeof(struct tlv_ap_he_cap))
		return -1;

	tlv = (struct tlv_ap_he_cap *)t->data;
	if (!tlv)
		return -1;

	tv_data = (uint8_t *)tlv;

	/* radio (6 bytes) */
	if (offset + 6 > tlv_len)
		return -1;
	offset += 6;

	hemcs = (struct ap_he_cap_mcs *)&tv_data[offset];
	if (!hemcs)
		return -1;

	/* hemcs->len + hemcs->mcs[] + cap[2] */
	if (offset + 1 + hemcs->len + 2 > tlv_len)
		return -1;


	return 0;
}

/* Check Channel Scan Capabilities TLV */
static int check_channel_scan_cap_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len = 0;
	struct tlv_channel_scan_capability *tlv;
	int i, j, offset = 0;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv = (struct tlv_channel_scan_capability *)t->data;
	if (!tlv)
		return -1;

	tv_data = (uint8_t *)tlv;

	if (offset + sizeof(*tlv) > tlv_len)
		return -1;

	offset += sizeof(*tlv); /* num_radio */

	for (i = 0; i < tlv->num_radio; i++) {
		struct channel_scan_capability_radio *radio =
			(struct channel_scan_capability_radio *)&tv_data[offset];

		if (offset + sizeof(*radio) > tlv_len)
			return -1;

		offset += sizeof(*radio); /* radio, cap, min_scan_interval, num_opclass */

		for (j = 0; j < radio->num_opclass; j++) {
			struct channel_scan_capability_opclass *opc =
				(struct channel_scan_capability_opclass *)&tv_data[offset];

			if (offset + sizeof(*opc) > tlv_len)
				return -1;

			offset += sizeof(*opc); /* classid & num_channel */

			if (offset + opc->num_channel > tlv_len)
				return -1;

			offset += opc->num_channel;
		}
	}

	return 0;
}

/* Check Channel Scan Capabilities TLV */
static int check_cac_cap_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len = 0;
	struct tlv_cac_cap *tlv;
	int i, j, k, offset = 0;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv = (struct tlv_cac_cap *) t->data;
	if (!tlv)
		return -1;

	tv_data = (uint8_t *)tlv;

	if (offset + sizeof(*tlv) > tlv_len)
		return -1;

	offset += sizeof(*tlv); /* country & num_radio */

	for (i = 0; i < tlv->num_radio; i++) {
		struct cac_cap_radio *radio =
			(struct cac_cap_radio *)&tv_data[offset];

		if (offset + sizeof(*radio) > tlv_len)
			return -1;

		offset += sizeof(*radio); /* radio & num_cac */

		for (j = 0; j < radio->num_cac; j++) {
			struct cac_cap_cac *cac =
				(struct cac_cap_cac *)&tv_data[offset];

			if (offset + sizeof(*cac) > tlv_len)
				return -1;

			offset += sizeof(*cac); /* supp_method, duration & num_opclass */

			for (k = 0; k < cac->num_opclass; k++) {
				struct cac_cap_opclass *opc =
					(struct cac_cap_opclass *)&tv_data[offset];

				if (offset + sizeof(*opc) > tlv_len)
					return -1;

				offset += sizeof(*opc); /* classid, num_channel */

				if (offset + opc->num_channel > tlv_len)
					return -1;

				offset += opc->num_channel;
			}
		}
	}

	return 0;

}

/* Check Profile-2 AP Capability TLV */
static int check_profile2_ap_cap_tlv(struct tlv *t)
{
	/* 4 bytes */
	return check_serialized_tlv(t,
		sizeof(struct tlv_profile2_ap_cap));
}

/* Check AP Radio Advanced Capabilities TLV */
static int check_ap_radio_adv_cap_tlv(struct tlv *t)
{
	/* radio (6) + cap (1 byte) */
	return check_serialized_tlv(t,
		sizeof(struct tlv_ap_radio_adv_cap));
}

/* Check MultiAP Profile TLV */
static int check_map_profile_tlv(struct tlv *t)
{
	/* profile (1 byte) */
	return check_serialized_tlv(t,
				sizeof(struct tlv_map_profile));
}

static int check_service_tlv(struct tlv *t)
{
	int offset = 0;
	uint8_t num_services;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	/* at least 1 byte: num_services */
	if (tlv_len < 1)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	num_services = tv_data[offset++];

	/* services (num_services bytes) */
	if (offset + num_services > tlv_len)
		return -1;

	return 0;
}

/* Check SupportedService TLV */
static int check_supported_service_tlv(struct tlv *t)
{
	return check_service_tlv(t);
}

/* Check SearchedService TLV */
static int check_searched_service_tlv(struct tlv *t)
{
	return check_service_tlv(t);
}

/* Check AP Metrics TLV */
static int check_ap_metrics_tlv(struct tlv *t)
{
	uint16_t tlv_len = 0;
	struct tlv_ap_metrics *tlv;
	int offset = 0;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv = (struct tlv_ap_metrics *) t->data;
	if (!tlv)
		return -1;

	/* bssid(6), channel_utilization(1), num_station(1), esp_ac(1), esp_be(3) */
	if (offset + sizeof(*tlv) > tlv_len)
		return -1;

	offset += sizeof(*tlv);

	/* esp_be */
	if (!(tlv->esp_ac & ESP_AC_BE))
		return -1;

	/* esp[] */
	if (tlv->esp_ac & ESP_AC_BK)
			offset += 3;
	if (tlv->esp_ac & ESP_AC_VO)
			offset += 3;
	if (tlv->esp_ac & ESP_AC_VI)
			offset += 3;

	if (offset > tlv_len)
		return -1;

	return 0;
}

/* Check Associated STA Traffic Stats TLV */
static int check_assoc_sta_traffic_stats_tlv(struct tlv *t)
{
	return check_serialized_tlv(t,
		sizeof(struct tlv_assoc_sta_traffic_stats));
}

/* Check Associated STA Link Metrics TLV */
static int check_assoc_sta_link_metrics_tlv(struct tlv *tlv)
{
	int offset = 0;
	uint8_t num_bss;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!tlv)
		return -1;

	tlv_len = tlv_length(tlv);
	if (tlv_len < sizeof(struct tlv_assoc_sta_link_metrics))
		return -1;

	tv_data = (uint8_t *)tlv->data;
	if (!tv_data)
		return -1;

	offset += 6;	/* bssid */
	num_bss = tv_data[offset++];

	if (offset + num_bss * sizeof(struct assoc_sta_link_metrics_bss) > tlv_len)
		return -1;

	return 0;
}

/* Check AP Extended Metrics TLV */
static int check_ap_ext_metrics_tlv(struct tlv *t)
{
	return check_serialized_tlv(t,
		sizeof(struct tlv_ap_ext_metrics));
}

/* Check Radio Metrics TLV */
static int check_radio_metrics_tlv(struct tlv *t)
{
	return check_serialized_tlv(t,
		sizeof(struct tlv_radio_metrics));
}

/* Check Associated STA Extended Link Metrics TLV */
static int check_assoc_sta_ext_link_metrics_tlv(struct tlv *tlv)
{
	int offset = 0;
	uint8_t num_bss;
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!tlv)
		return -1;

	tlv_len = tlv_length(tlv);
	if (tlv_len < sizeof(struct tlv_sta_ext_link_metric))
		return -1;

	tv_data = (uint8_t *)tlv->data;
	if (!tv_data)
		return -1;

	offset += 6;	/* bssid */
	num_bss = tv_data[offset++];

	if (offset + num_bss * sizeof(struct sta_ext_link_metric_bss) > tlv_len)
		return -1;

	return 0;
}

bool validate_1905_ack(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int num = 0;
	int ret;

	ret = map_cmdu_parse_tlvs(cmdu, tv, 1, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs( ..,profile=%d) failed, err = (%d) '%s'\n", __func__,
				profile, map_error, map_strerror(map_error));
		return false;
	}

	/* Parse Error Code TLVs */
	while (tv[0][num]) {
		if (tv[0][num]->type != MAP_TLV_ERROR_CODE) {
			dbg("Wrong TLV type, expected ERROR CODE!\n");
			return false;
		}
		num++;
	}

	if (!num)
		dbg("|%s:%d| Received ACK without any ERROR CODE.\n",
		    __func__, __LINE__);

	return true;
}

#if (EASYMESH_VERSION > 2)
static int check_bss_configuration_report_tlv(struct tlv *t)
{
	const struct tlv_bss_configuration_report *tlv;
	const uint8_t *const tlv_data = t->data;
	const uint16_t tlv_len = tlv_length(t);
	int i, offset = 0;

	if (!tlv_len)
		return -1;

	if (!tlv_data)
		return -1;

	tlv = (struct tlv_bss_configuration_report *)t->data;

	/* num_radio (1 byte) */
	offset += 1;
	if (offset > tlv_len)
		return -1;

	for (i = 0; i < tlv->num_radio; i++) {
		uint8_t num_bss = 0;
		int j;

		/* RUID/macaddr (6 bytes) */
		offset += 6;
		if (offset > tlv_len)
			return -1;

		/* num_bss (1 byte) */
		offset += 1;
		if (offset > tlv_len)
			return -1;

		num_bss = tlv_data[offset - sizeof(num_bss)];

		for (j = 0; j < num_bss; j++) {
			uint8_t ssid_len = 0;

			/* BSSID/macaddr (6 bytes) */
			offset += 6;
			if (offset > tlv_len)
				return -1;

			/* report flags (1 byte) */
			offset += 1;
			if (offset > tlv_len)
				return -1;

			/* reserved flags (1 bytes) */
			offset += 1;
			if (offset > tlv_len)
				return -1;

			/* ssidlen (1 byte) */
			offset += 1;
			if (offset > tlv_len)
				return -1;

			ssid_len = tlv_data[offset - sizeof(ssid_len)];

			/* ssid (ssidlen bytes) */
			offset += ssid_len;
			if (offset > tlv_len)
				return -1;
		}
	}

	return 0;
}

static int check_1905_encap_dpp_tlv(struct tlv *t)
{
	const struct tlv_1905_encap_dpp *tlv;
	const uint8_t *tlv_data;
	uint16_t tlv_len;
	int offset = 0;
	int len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv_data = t->data;
	if (!tlv_data)
		return -1;

	tlv = (struct tlv_1905_encap_dpp *)t->data;

	/* flag (1 byte) */
	offset = sizeof(tlv->dst);
	if (offset > tlv_len)
		return -1;

	if (tlv->dst.flag & ENCAP_DPP_ENROLLEE_MAC_PRESENT) {
		/* addr (6 bytes) */
		offset += sizeof(macaddr_t);
		if (offset > tlv_len)
			return -1;
	}

	/* type + len (3 bytes) */
	offset += sizeof(tlv->frame);
	if (offset > tlv_len)
		return -1;

	len = tlv_data[offset - sizeof(tlv->frame.len)];

	/* encapsulated frame (len bytes) */
	offset += len;
	if (offset > tlv_len)
		return -1;

	/* TODO: Check Encapsulated frame integrity (DPP / GAS) */

	return 0;
}


static int check_chirp_value_tlv(struct tlv *t)
{
	const struct tlv_dpp_chirp *tlv;
	const uint8_t *tlv_data;
	uint16_t tlv_len;
	int hashlen;
	int offset = 0;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tlv_data = t->data;
	if (!tlv_data)
		return -1;

	tlv = (struct tlv_dpp_chirp *)t->data;

	/* flag (1 byte) */
	offset = sizeof(tlv->dst);
	if (offset > tlv_len)
		return -1;

	if (tlv->dst.flag & DPP_CHIRP_ENROLLEE_MAC_PRESENT) {
		/* addr (6 bytes) */
		offset += sizeof(macaddr_t);
		if (offset > tlv_len)
			return -1;
	}

	/* hashlen (1 byte) */
	offset += sizeof(tlv->hashlen);
	if (offset > tlv_len)
		return -1;

	hashlen = tlv_data[offset - sizeof(tlv->hashlen)];

	/* hash (hashlen bytes) */
	offset += hashlen;
	if (offset > tlv_len)
		return -1;

	/* TODO: check hash integrity depending on validity flag */

	return 0;
}

static int check_dpp_message_tlv(struct tlv *t)
{
	const struct tlv_dpp_message *tlv;
	const uint8_t *const tlv_data = t->data;
	const uint16_t tlv_len = tlv_length(t);

	if (!tlv_len)
		return -1;

	if (!tlv_data)
		return -1;

	tlv = (struct tlv_dpp_message *)t->data;

	/* DPP message (tlv_len bytes) */
	// TODO: validate DPP message (Authentication Req/Rsp, ...)
	(void) tlv;

	return 0;
}

static int check_dpp_bootstraping_uri_notification_tlv(struct tlv *t)
{
	const struct tlv_dpp_uri_bootstrap *tlv;
	const uint8_t *const tlv_data = t->data;
	const uint16_t tlv_len = tlv_length(t);
	int offset = 0;

	if (!tlv_len)
		return -1;

	if (!tlv_data)
		return -1;

	tlv = (struct tlv_dpp_uri_bootstrap *)t->data;

	/* ruid/macaddr (6 bytes) */
	offset += 6;
	if (offset > tlv_len)
		return -1;

	if(hwaddr_is_zero(tlv->ruid))
		return -1;

	/* bssid/macaddr (6 bytes) */
	offset += 6;
	if (offset > tlv_len)
		return -1;

	if(hwaddr_is_zero(tlv->bssid))
		return -1;

	/* bsta/macaddr (6 bytes) */
	offset += 6;
	if (offset > tlv_len)
		return -1;

	if(hwaddr_is_zero(tlv->bsta))
		return -1;

	/* DPP uri (n bytes) */
	// TODO: check Bootstraping Information Format

	return 0;
}

static int check_akm_suite_caps_tlv(struct tlv *t)
{
	const uint16_t tlv_len = tlv_length(t);
	uint16_t offset;

	const struct bbss_akm_suite *bbss;
	const struct fbss_akm_suite *fbss;

	if (!tlv_len)
		return -1;

	bbss = (const struct bbss_akm_suite *)t->data;

	offset = sizeof(bbss->num);
	if (offset > tlv_len)
		return -1;

	offset += bbss->num * sizeof(bbss->suite[0]);
	if (offset > tlv_len)
		return -1;

	fbss = (const struct fbss_akm_suite *)(t->data + offset);

	offset += sizeof(fbss->num);
	if (offset > tlv_len)
		return -1;

	offset += fbss->num * sizeof(fbss->suite[0]);
	if (offset > tlv_len)
		return -1;

	return 0;
}

static int check_backhaul_sta_radio_caps_tlv(struct tlv *t)
{
	const uint16_t tlv_len = tlv_length(t);
	uint16_t offset;
	const struct tlv_bsta_radio_cap *bsta_radio_cap =
		(const struct tlv_bsta_radio_cap *)t->data;

	if (!tlv_len)
		return -1;

	offset = sizeof(*bsta_radio_cap);

	if (offset > tlv_len)
		return -1;

	if (bsta_radio_cap->macaddr_included & BSTA_MACADDRESS_INCLUDED) {
		offset += sizeof(macaddr_t);
		if (offset > tlv_len)
			return -1;
	}

	return 0;
}

static int check_bss_config_request_tlv(struct tlv *t)
{
	const uint16_t tlv_len = tlv_length(t);
	json_tokener *tok;
	json_object *jsobj;
	int result;

	if (!tlv_len)
		return -1;

	/* Check whether TLV is valid JSON object */
	tok = json_tokener_new();
	if (!tok)
		return -1;

	result = 0;
	jsobj = json_tokener_parse_ex(tok, (const char *)t->data, tlv_len);
	if (!jsobj || !json_object_is_type(jsobj, json_type_object))
		result = -1;

	json_tokener_free(tok);

	return result;
}
#endif /* EASYMESH_VERSION > 2 */

bool validate_topology_notification(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig search\n",
		  __func__, MAC2STR(cmdu->origin));

	ret = map_cmdu_parse_tlvs(cmdu, tv, 2, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	return true;
}

bool validate_ap_caps_report(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret = 0;
	int idx;

	trace("%s |" MACFMT "|CMDU: ap caps report, profile %d\n",
		  __func__, MAC2STR(cmdu->origin), profile);

	/* Parsing AP Caps Report TLV */
	ret = map_cmdu_parse_tlvs(cmdu, tv, 13, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs( ,profile=%d) failed,  err = (%d) '%s'\n", __func__, profile,
		    map_error, map_strerror(map_error));
		if (map_error == CMDU_STATUS_ERR_TLV_NUM_LESS) {
			for (idx = 0, ret = 0; idx < 13; idx++)
				if (!tv[idx][0])
					ret |= 1 << idx;
			dbg("%s:%d missing tlvs %04x\n", __func__, __LINE__, ret);
		}
		return false;
	}

	/* AP Radio Basic Capabilities TLV */
	idx = 0;
	while (tv[1][idx] && (idx < 16)) {
		if (check_ap_radio_basic_cap_tlv(tv[1][idx]))
			return false;
		idx++;
	}

	/* AP HT Capabilities TLV */
	idx = 0;
	while (tv[2][idx] && (idx < 16)) {
		if (check_ap_ht_cap_tlv(tv[2][idx]))
			return false;
		idx++;
	}

	idx = 0;
	/* AP VHT Capabilities TLV */
	while (tv[3][idx] && (idx < 16)) {
		if (check_ap_vht_cap_tlv(tv[3][idx]))
			return false;
		idx++;
	}

	/* AP HE Capabilities TLV */
	idx = 0;
	while (tv[4][idx] && (idx < 16)) {
		if (check_ap_he_cap_tlv(tv[4][idx]))
			return false;
		idx++;
	}

	// Not found in profile 1
	if (profile > MULTIAP_PROFILE_1) {
		/* Parse Channel Scan Capabilities TLV */
		if (check_channel_scan_cap_tlv(tv[5][0]))
			return false;

		/* Parse CAC Capabilities TLV */
		if (check_cac_cap_tlv(tv[6][0]))
			return false;
	}
	return true;
}

bool validate_ap_metrics_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret = 0;
	int idx;

	trace("%s |" MACFMT "|CMDU: ap metrics response, profile %d\n",
		  __func__, MAC2STR(cmdu->origin), profile);

	/* Parsing AP Metrics TLV */
	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (!tv[0][0] || !tv[3][0]) {
		dbg("%s: Missing one or more mandatory TLV!\n", __func__);
		return false;
	}

	idx = 0;
	while (tv[0][idx]) {
		/* Parse AP Metrics TLV */
		if (check_ap_metrics_tlv(tv[0][idx]))
			return false;
		idx++;
	}

	idx = 0;
	while (tv[1][idx]) {
		/* Parse Associated STA Traffic Stats TLV */
		if (check_assoc_sta_traffic_stats_tlv(tv[1][idx]))
			return false;
		idx++;
	}

	idx = 0;
	while (tv[2][idx]) {
		/* Parse Associated STA Link Metrics TLV */
		if (check_assoc_sta_link_metrics_tlv(tv[2][idx]))
			return false;
		idx++;
	}

	idx = 0;
	while (tv[3][idx]) {
		/* Parse AP Extended Metrics TLV */
		if (check_ap_ext_metrics_tlv(tv[3][idx]))
			return false;
		idx++;
	}

	idx = 0;
	while (tv[4][idx]) {
		/* Parse Radio Metrics TLV */
		if (check_radio_metrics_tlv(tv[4][idx]))
			return false;
		idx++;
	}

	idx = 0;
	while (tv[5][idx]) {
		/* Parse Associated STA Extended Link Metrics TLV */
		if (check_assoc_sta_ext_link_metrics_tlv(tv[5][idx]))
			return false;
		idx++;
	}

	return true;
}

bool validate_channel_scan_report(struct cmdu_buff *cmdu, struct tlv *tv_tsp[][16],
		struct tlv *tv_scan[], int *num, uint8_t profile)
{
	int i, j;
	int ret = 0;
	struct tlv_policy d_policy_scan[] = {
		[0] = {
			.type = MAP_TLV_CHANNEL_SCAN_RES,
			.present = TLV_PRESENT_MORE,
			.minlen = 9
		}
	};

	ret = map_cmdu_parse_tlvs(cmdu, tv_tsp, 2, profile);
	if (ret) {
		dbg("%s: cmdu_parse_tlvs( profile=%d) failed, err = (%d) '%s'\n", __func__, profile,
		    ieee1905_error, ieee1905_strerror(ieee1905_error));
		return false;
	}

	ret = cmdu_parse_tlv_single(cmdu, tv_scan, d_policy_scan, num);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (!tv_tsp[0][0]) {
		dbg("%s: No TIMESTAMP_TLV received!\n", __func__);
		return false;
	}

	if (!tv_scan[0]) {
		dbg("%s: No RESULT_TLV received!\n", __func__);
		return false;
	}

	if (tv_tsp[0][0]) {
		int offset = 0;
		int tsp_len = 0;
		uint8_t *t = NULL;
		uint16_t tlv_len = tlv_length(tv_tsp[0][0]);

		t = (uint8_t *)tv_tsp[0][0]->data;
		if (!t)
			return false;

		/* offset within provided minlen(1) */
		tsp_len = t[offset];
		offset += 1;
		if ((offset + tsp_len) > tlv_len)
			return false;
	}

	for (i = 0; i < *num; i++) {
		int offset = 0;
		uint8_t status = 0x00;
		uint8_t *t = NULL;
		uint16_t tlv_len = tlv_length(tv_scan[i]);
		int ts_len = 0;
		uint16_t num_nb = 0;

		t = (uint8_t *)tv_scan[i]->data;
		if (!t)
			return false;

		/* offset within provided minlen(9) */
		offset += 6;	/* radio id */
		offset += 1;	/* opclass */
		offset += 1;	/* channel */
		status = t[offset];
		offset += 1;	/* status */

		if (status == CH_SCAN_STATUS_SUCCESS) {

			if ((offset + 1) > tlv_len)
				return false;

			ts_len = t[offset];
			offset += 1;	/* timestamp len */
			if ((offset + ts_len + 4) > tlv_len)
				return false;

			offset += ts_len;	/* timestamp */
			offset += 1;		/* utilization */
			offset += 1;		/* noise */
			num_nb = BUF_GET_BE16(t[offset]);
			offset += 2;		/* num neightbors */

			for (j = 0; j < num_nb; j++) {
				int ssid_len = 0;
				int bw_len = 0;
				uint8_t info = 0x00;

				if ((offset + 7) > tlv_len)
					return false;

				offset += 6;	/* bssid */
				ssid_len = t[offset];
				offset += 1;	/* ssid len */
				if ((offset + ssid_len + 2) > tlv_len)
					return false;

				offset += ssid_len;	/* ssid */
				offset += 1;		/* rcpi */
				bw_len = t[offset];
				offset += 1;		/* bw len */
				if ((offset + bw_len + 1) > tlv_len)
					return false;

				offset += bw_len;	/* bandwidth */
				info = t[offset];
				offset += 1;		/* info */

				if (info & CH_SCAN_RESULT_BSSLOAD_PRESENT) {
					if ((offset + 3) > tlv_len)
						return false;

					offset += 1;	/* channel utilization */
					offset += 2;	/* station count */
				}
			}

			if ((offset + 5) > tlv_len)
				return false;

			offset += 4;	/* total scan duration */
			offset += 1;	/* scan type */
		}
	}

	return true;
}


#ifdef EASYMESH_VENDOR_EXT
static int validate_topology_response_vext(struct tlv *tv[16])
{
	int num = 0;

	while (num < 16 && tv[num]) {
		uint16_t tlv_len = 0;
		struct tlv_vendor_bbss *tlv;
		int i, offset = 0;
		uint8_t oui2[3];  /* TODO: use the same vendor oui-type */

		tlv_len = tlv_length(tv[num]);
		if (!tlv_len)
			return -1;

		tlv = (struct tlv_vendor_bbss *)tv[num]->data;
		if (!tlv)
			return -1;

		/* oui (3 bytes) */
		if (offset + 3 > tlv_len)
			return -1;

		memcpy(oui2, EASYMESH_VENDOR_EXT_OUI, 3);
		oui2[2]++;
		if (memcmp(tlv->oui, oui2, 3)) {
			num++;
			continue;
		}

		offset += 3;

		/* num_radios (1 byte) */
		if (offset + 1 > tlv_len)
			return -1;

		offset += 1;

		for (i = 0; i < tlv->num_radios; i++) {
			uint8_t num_bss = 0;

			/* macaddr (6 bytes) */
			if (offset + 6 > tlv_len)
				return -1;

			offset += 6;

			/* num_bss (1 byte) */
			if (offset + 1 > tlv_len)
				return -1;

			memcpy(&num_bss, &tv[num]->data[offset], 1);

			offset += 1;

			/* bss macaddrs (num_bss * 6 bytes) */
			if (offset + (num_bss * 6) > tlv_len)
				return -1;

			offset += num_bss * 6;
		}

		num++;
	}

	return 0;
}

#endif

bool validate_topology_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	trace("%s: --->\n", __func__);

	int ret = 0;

#ifdef EASYMESH_VENDOR_EXT
	struct tlv_policy vendor_ext_policy[] = {
			{ .type = TLV_TYPE_VENDOR_SPECIFIC,
					.present = TLV_PRESENT_OPTIONAL_MORE,
					.minlen = 3, /* tlv_vendor_bbss:oui+num_radios */
			},
	};
#endif

	trace("parsing topology response |" MACFMT "|CMDU: topology response (profile %d)\n",
			MAC2STR(cmdu->origin), profile);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 11, profile); // last one tv set is reserved for optional vendor_ext tlv
#ifdef EASYMESH_VENDOR_EXT
	if (!ret)
		ret = cmdu_parse_tlvs(cmdu, &tv[11], vendor_ext_policy, 1) << 1;
#endif
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs( profile=%d) failed, err = (%d) '%s', %d\n", __func__, profile,
				map_error, map_strerror(map_error), ret);
		return false;
	}

	/* Parse SupportedService TLV */
	if (check_supported_service_tlv(tv[6][0]))
		return false;

	/* MAP_TLV_AP_OPERATIONAL_BSS */
	if (tv[7][0]) {
		struct tlv_ap_oper_bss *tlv;
		uint8_t *tv_data;
		uint16_t tlv_len = 0;
		int i, offset = 0;

		tlv_len = tlv_length(tv[7][0]);
		if (!tlv_len)
			return false;

		tlv = (struct tlv_ap_oper_bss *)tv[7][0]->data;
		if (!tlv)
			return false;

		tv_data = (uint8_t *)tlv;

		/* num_radio (1 byte) */
		if (offset + 1 > tlv_len)
			return false;

		offset += 1;

		for (i = 0; i < tlv->num_radio; i++) {
			uint8_t num_bss = 0;
			int j;

			/* macaddr (6 bytes) */
			if (offset + 6 > tlv_len)
				return false;

			offset += 6;

			/* num_bss (1 byte) */
			if (offset + 1 > tlv_len)
				return false;

			memcpy(&num_bss, &tv_data[offset], 1);

			offset += 1;

			for (j = 0; j < num_bss; j++) {
				uint8_t ssidlen = 0;

				/* macaddr (6 bytes) */
				if (offset + 6 > tlv_len)
					return false;

				offset += 6;

				/* ssidlen (1 byte) */
				if (offset + 1 > tlv_len)
					return false;

				memcpy(&ssidlen, &tv_data[offset], 1);

				offset += 1;

				/* ssid (ssidlen bytes) */
				if (offset + ssidlen > tlv_len)
					return false;

				offset += ssidlen;
			}
		}
	}

	/* MAP_TLV_ASSOCIATED_CLIENTS */
	if (tv[8][0]) {
		uint16_t tlv_len = 0;
		struct tlv_assoc_client *tlv;
		uint8_t *tv_data;
		int i, offset = 0;

		tlv_len = tlv_length(tv[8][0]);
		if (!tlv_len)
			return false;

		tlv = (struct tlv_assoc_client *)tv[8][0]->data;
		if (!tlv)
			return false;

		tv_data = (uint8_t *)tlv;

		/* num_bss (1 byte) */
		if (offset + 1 > tlv_len)
			return false;

		offset += 1;

		for (i = 0; i < tlv->num_bss; i++) {
			uint16_t num_client = 0;

			/* radio id (6 bytes) */
			if (offset + 6 > tlv_len)
				return false;

			offset += 6;

			/* num_client (2 bytes) */
			if (offset + 2 > tlv_len)
				return false;

			num_client = BUF_GET_BE16(tv_data[offset]);

			offset += 2;

			 /* num_client * (macaddr + conntime) */
			if (offset + (num_client * 8) > tlv_len)
				return false;

			offset += (num_client * 8);
		}
	}

	/* Parse MultiAP Profile TLV */
	if (check_map_profile_tlv(tv[9][0]))
		return false;

#ifdef EASYMESH_VENDOR_EXT
	/* TLV_TYPE_VENDOR_SPECIFIC */
	if (validate_topology_response_vext(tv[11]))
		return false;
#endif /*EASYMESH_VENDOR_EXT*/

#if (EASYMESH_VERSION > 2)
	/* MAP_TLV_BSS_CONFIGURATION_REPORT */
	if (profile > MULTIAP_PROFILE_2) {
		dbg("Inside %s MAP_TLV_BSS_CONFIGURATION_REPORT\n", __func__);
		if (check_bss_configuration_report_tlv(tv[10][0]))
			return false;
	}
#endif

	return true;
}

#define ATTR_MSG_TYPE   (0x1022)
#define MSG_TYPE_M1	 (0x04)
static int validate_wsc_m1(uint8_t *m1, uint16_t m1_size)
{
	uint8_t *data;
	uint8_t *m1_end;
	int ret = -1;

	if (!m1 || !m1_size)
		return -1;

	data = m1;
	m1_end = m1 + m1_size;

	while ((data - m1) < m1_size - 4) {
		uint16_t attr_type;
		uint16_t attr_len;

		attr_type = buf_get_be16(data);
		data += 2;
		attr_len = buf_get_be16(data);
		data += 2;

		if (data + attr_len > m1_end) {
			dbg("%s: parse_wsc_m1 failed\n", __func__);
			ret = -1;
			break;
		}

		if (attr_type == ATTR_MSG_TYPE) {
			if (attr_len != 1) {
				ret = -1;
				break;
			}
			if (*data == MSG_TYPE_M1)
				ret = 0;
		}

		data += attr_len;
	}

	/* 0 if msg type is M1 & data never goes OOB */
	return ret;
}

/* Check WSC TLV (containing M1) */
static int check_wsc_tlv(struct tlv *t)
{
	uint8_t *tv_data;
	uint16_t tlv_len;

	if (!t)
		return -1;

	tlv_len = tlv_length(t);
	if (!tlv_len)
		return -1;

	tv_data = (uint8_t *)t->data;
	if (!tv_data)
		return -1;

	return validate_wsc_m1(tv_data, tlv_len);
}

bool validate_ap_autoconfig_wsc(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	struct tlv_policy a_policy[] = {
		[0] = { .type = MAP_TLV_AP_RADIO_BASIC_CAPABILITIES,
				.present = TLV_PRESENT_ONE,
				.minlen = 8, /* tlv_ap_radio_basic_cap */
		},
		[1] = { .type = MAP_TLV_PROFILE2_AP_CAPABILITY,
				.present = TLV_PRESENT_ONE,
				.minlen = 4, /* tlv_profile2_ap_cap */
				.maxlen = 4
		},
		[2] = { .type = MAP_TLV_AP_RADIO_ADV_CAPABILITY,
				.present = TLV_PRESENT_ONE,
				.minlen = 7, /* tlv_ap_radio_adv_cap */
				.maxlen = 7
		},
		[3] = { .type = TLV_TYPE_WSC,
				.present = TLV_PRESENT_ONE
		}
	};
	int ret = 0;

	trace("%s |" MACFMT "|CMDU: ap autoconfig response\n",
		  __func__, MAC2STR(cmdu->origin));

	ret = cmdu_parse_tlvs(cmdu, tv, a_policy, 4);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (!tv[0][0] || !tv[1][0] || !tv[2][0] || !tv[3][0]) {
		dbg("%s: Missing one or more mandatory TLV!\n", __func__);
		return false;
	}

	/* Parse AP Radio Basic Capabilities TLV */
	if (check_ap_radio_basic_cap_tlv(tv[0][0]))
		return false;

	/* Parse Profile-2 AP Capability TLV */
	if (check_profile2_ap_cap_tlv(tv[1][0]))
		return false;

	/* Parse AP Radio Advanced Capabilities TLV */
	if (check_ap_radio_adv_cap_tlv(tv[2][0]))
		return false;

	/* Parse WSC TLV (containing M1) */
	if (check_wsc_tlv(tv[3][0]))
		return false;

	return true;
}

/* 0: 1905.1 AL MAC address type TLV
 * 1: SearchedRole TLV
 * 2: AutoconfigFreqBand TLV
 * 3: SupportedService TLV
 * 4: SearchedService TLV
 * 5: MultiAP Profile TLV
 * 6: MAP_TLV_DPP_CHIRP_VALUE
 **/
bool validate_ap_autoconfig_search(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig search, profile %d\n",
		  __func__, MAC2STR(cmdu->origin), profile);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs( .., profile=%d) failed,  err = (%d) '%s'\n", __func__,
		    profile, map_error, map_strerror(map_error));
		return false;
	}

	if (tv[3][0] && check_supported_service_tlv(tv[3][0]))
		return false;

	if (tv[4][0] && check_searched_service_tlv(tv[4][0]))
		return false;

	return true;
}

/* 0: SupportedRole TLV
 * 1: SupportedFreqBand TLV
 * 2: SupportedService TLV
 * 3: MultiAP Profile TLV
 * 4: MAP_TLV_1905_SECURITY_CAPS
 * 5: MAP_TLV_DPP_CHIRP_VALUE\
 * 6: MAP_TLV_CONTROLLER_CAPS
 **/
bool validate_ap_autoconfig_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile)
{
	int ret;

	trace("%s |" MACFMT "|CMDU: ap autoconfig response, profile %d\n",
		  __func__, MAC2STR(cmdu->origin), profile);

	ret = map_cmdu_parse_tlvs(cmdu, tv, 7, profile);
	if (ret) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (check_supported_service_tlv(tv[2][0]))
		return false;

	return true;
}

#if (EASYMESH_VERSION > 2)
bool validate_proxied_encap_dpp(struct cmdu_buff *cmdu, struct tlv *tlvs[][16])
{
	const int easymesh_rev = 4;

	if (map_cmdu_parse_tlvs(cmdu, tlvs, PROXIED_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (check_1905_encap_dpp_tlv(tlvs[PROXIED_ENCAP_1905_ENCAP_DPP_IDX][0])) {
		dbg("%s: check_1905_encap_dpp_tlv failed.\n", __func__);
		return false;
	}

	if (tlvs[PROXIED_ENCAP_CHIRP_VALUE_IDX][0]) /* Zero or One */
		if (check_chirp_value_tlv(tlvs[PROXIED_ENCAP_CHIRP_VALUE_IDX][0])) {
			dbg("%s: check_chirp_value_tlv failed.\n", __func__);
			return false;
		}


	return true;
}

bool validate_direct_encap_dpp(struct cmdu_buff *cmdu, struct tlv *tlvs[][16])
{
	const int easymesh_rev = 4;

	if (map_cmdu_parse_tlvs(cmdu, tlvs, DIRECT_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (check_dpp_message_tlv(tlvs[DIRECT_ENCAP_DPP_MESSAGE_IDX][0])) {
		dbg("%s: check_direct_encap_dpp_tlv failed.\n", __func__);
		return false;
	}

	return true;
}

bool validate_bss_configuration_request(struct cmdu_buff *cmdu, struct tlv *tlvs[][16], uint8_t profile)
{
	const int max_num_of_tlvs = 16;
	int i;


	if (map_cmdu_parse_tlvs(cmdu, tlvs, BSS_CFG_REQ_MAX_NUMBER_OF_TLV_TYPES, profile)) {
		dbg("%s: cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    ieee1905_error, ieee1905_strerror(ieee1905_error));
		return false;
	}

	if (check_map_profile_tlv(tlvs[BSS_CFG_REQ_MULTIAP_PROFILE_IDX][0])) {
		dbg("%s: check_map_profile_tlv failed.\n", __func__);
		return false;
	}

	if (check_supported_service_tlv(tlvs[BSS_CFG_REQ_SUPPORTED_SERVICE_IDX][0])) {
		dbg("%s: check_supported_service_tlv failed.\n", __func__);
		return false;
	}

	if (check_akm_suite_caps_tlv(tlvs[BSS_CFG_REQ_AKM_SUITE_CAPS_IDX][0])) {
		dbg("%s: check_akm_suite_caps_tlv failed.\n", __func__);
		return false;
	}

	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_AP_RADIO_BASIC_CAPS_IDX][i]) {
		if (check_ap_radio_basic_cap_tlv(tlvs[BSS_CFG_REQ_AP_RADIO_BASIC_CAPS_IDX][i])) {
			dbg("%s: check_ap_radio_basic_cap_tlv failed.\n", __func__);
			return false;
		}

		++i;
	}

	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_BACKHAUL_STA_RADIO_CAPS_IDX][i]) {
		if (check_backhaul_sta_radio_caps_tlv(tlvs[BSS_CFG_REQ_BACKHAUL_STA_RADIO_CAPS_IDX][i])) {
			dbg("%s: check_backhaul_sta_radio_caps_tlv failed.\n", __func__);
			return false;
		}

		++i;
	}

	if (check_profile2_ap_cap_tlv(tlvs[BSS_CFG_REQ_PROFILE2_AP_CAP_IDX][0])) {
		dbg("%s: check_profile2_ap_cap_tlv failed.\n", __func__);
		return false;
	}

	i = 0;
	while ((i < max_num_of_tlvs) && tlvs[BSS_CFG_REQ_AP_RADIO_ADVANCED_CAPS_IDX][i]) {
		if (check_ap_radio_adv_cap_tlv(tlvs[BSS_CFG_REQ_AP_RADIO_ADVANCED_CAPS_IDX][i])) {
			dbg("%s: check_ap_radio_adv_cap_tlv failed.\n", __func__);
			return false;
		}

		++i;
	}

	if (check_bss_config_request_tlv(tlvs[BSS_CFG_REQ_CONFIG_REQUEST_IDX][0])) {
		dbg("%s: check_bss_config_request_tlv failed.\n", __func__);
		return false;
	}

	return true;
}

bool validate_bss_configuration_result(struct cmdu_buff *cmdu,
				       struct tlv *tlvs[][16], uint8_t profile)
{

	if (map_cmdu_parse_tlvs(cmdu, tlvs, BSS_CFG_RESULT_MAX_NUMBER_OF_TLV_TYPES, profile)) {
		dbg("%s: cmdu_parse_tlvs failed, err = (%d) '%s'\n", __func__,
		    ieee1905_error, ieee1905_strerror(ieee1905_error));
		return false;
	}

	if (check_bss_configuration_report_tlv(tlvs[BSS_CFG_RESULT_BSS_CONFIG_REPORT_IDX][0])) {
		dbg("%s: check_bss_configuration_report_tlv failed.\n", __func__);
		return false;
	}

	return true;
}

bool validate_dpp_bootstraping_uri_notification(struct cmdu_buff *cmdu,
				       struct tlv *tlvs[][16])
{
	const int easymesh_rev = 4;

	if (map_cmdu_parse_tlvs(cmdu, tlvs, DPP_BOOTSTRAP_URI_NOTIF_MAX_NUMBER_OF_TLV_TYPES, easymesh_rev)) {
		dbg("%s: map_cmdu_parse_tlvs failed,  err = (%d) '%s'\n", __func__,
		    map_error, map_strerror(map_error));
		return false;
	}

	if (check_dpp_bootstraping_uri_notification_tlv(tlvs[DPP_BOOTSTRAP_URI_NOTIF_IDX][0])) {
		dbg("%s: check_dpp_bootstraping_uri_notification_tlv failed.\n", __func__);
		return false;
	}

	return true;
}
#endif /* EASYMESH_VERSION > 2 */
