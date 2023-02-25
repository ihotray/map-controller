#include <string.h>
#include "tlv_debug.h"
#include "utils/debug.h"

#include <easy/easy.h>
#include <easy/utils.h>
#include <wifidefs.h>
#include <easymesh.h>
#include <1905_tlvs.h>

#include "utils/utils.h"
#include "utils/debug.h"

void trace_tlv_map_profile(const struct tlv_map_profile *map_profile)
{
	if (!map_profile)
		return;

	trace("\nTLV type: MAP_TLV_MULTIAP_PROFILE\n");
	trace("\tprofile: %d\n", map_profile->profile);

	trace("\n");
}

void trace_tlv_supported_service(const struct tlv_supported_service *supp_service)
{
	int i;

	if (!supp_service)
		return;

	trace("\nTLV type: MAP_TLV_SUPPORTED_SERVICE\n");
	trace("\tNumber of services: %d\n", supp_service->num_services);

	for (i = 0; i < supp_service->num_services; ++i)
		trace("\tservice[%d]: 0x%X\n", i, supp_service->services[i]);

	trace("\n");
}
#if (EASYMESH_VERSION > 2)
void trace_tlv_akm_suite_caps(const struct tlv_akm_suite_caps *akm_suite_caps)
{
	const struct bbss_akm_suite *bbss_akm_suite =
		(const struct bbss_akm_suite *)akm_suite_caps;
	const struct fbss_akm_suite *fbss_akm_suite;
	const uint8_t *tlv_data = (const uint8_t *)akm_suite_caps;

	int i;

	if (!akm_suite_caps)
		return;

	trace("\nTLV type: MAP_TLV_AKM_SUITE_CAPS\n");
	trace("\tNum Backhaul BSS AKM Suite Selectors: %d\n", bbss_akm_suite->num);

	for (i = 0; i < bbss_akm_suite->num; ++i) {
		const struct akm_suite *suite = bbss_akm_suite->suite + i;

		trace("\t\tbbss_akm_suite[%d]: oui[0]: 0x%X, oui[1]: 0x%X, oui[2]: 0x%X, type: 0x%X\n",
		      i, suite->oui[0], suite->oui[1], suite->oui[2], suite->type);
	}

	fbss_akm_suite =
		(struct fbss_akm_suite *)(tlv_data + sizeof(bbss_akm_suite->num) +
					  (bbss_akm_suite->num * sizeof(bbss_akm_suite->suite[0])));

	trace("\tNum Fronthaul BSS AKM Suite Selectors: %d\n", fbss_akm_suite->num);

	for (i = 0; i < fbss_akm_suite->num; ++i) {
		const struct akm_suite *suite = fbss_akm_suite->suite + i;

		trace("\t\tfbss_akm_suite[%d]: oui[0]: 0x%X, oui[1]: 0x%X, oui[2]: 0x%X, type: 0x%X\n",
		      i, suite->oui[0], suite->oui[1], suite->oui[2], suite->type);
	}

	trace("\n");
}
#endif /* EASYMESH_VERSION > 2 */
void trace_tlv_ap_radio_basic_cap(const struct tlv_ap_radio_basic_cap *ap_radio_basic_cap)
{
	uint8_t *tlv_data = (uint8_t *)ap_radio_basic_cap;
	int offset;
	int i;

	if (!ap_radio_basic_cap)
		return;

	trace("\nTLV type: MAP_TLV_AP_RADIO_BASIC_CAPABILITIES\n");
	trace("\tradio:" MACFMT "\n", MAC2STR(ap_radio_basic_cap->radio));
	trace("\tmax_bssnum: %d\n", ap_radio_basic_cap->max_bssnum);
	trace("\tnum_opclass: %d\n", ap_radio_basic_cap->num_opclass);

	offset = sizeof(*ap_radio_basic_cap);

	for (i = 0; i < ap_radio_basic_cap->num_opclass; ++i) {
		int j;
		const struct ap_radio_basic_cap_opclass *op =
			(struct ap_radio_basic_cap_opclass *)&tlv_data[offset];

		trace("\t\tclassid: %d\n", op->classid);
		trace("\t\tmax_txpower: %d\n", op->max_txpower);
		trace("\t\tnum_nonop_channel: %d\n", op->num_nonop_channel);

		for (j = 0; j < op->num_nonop_channel; ++j)
			trace("\t\t\tnonop_channel: %d\n", op->nonop_channel[j]);

		offset += sizeof(*op) + op->num_nonop_channel;
	}

	trace("\n");
}

void trace_tlv_bsta_radio_cap(const struct tlv_bsta_radio_cap *bsta_radio_cap)
{
	if (!bsta_radio_cap)
		return;

	const bool macaddr_included =
		(bsta_radio_cap->macaddr_included & BSTA_MACADDRESS_INCLUDED);

	trace("\nTLV type: MAP_TLV_BACKHAUL_STA_RADIO_CAPABILITY\n");
	trace("\tradio:" MACFMT "\n", MAC2STR(bsta_radio_cap->radio));
	trace("\tmacaddr_included: %s\n", macaddr_included ? "yes" : "no");

	if (macaddr_included)
		trace("\tmacaddr:" MACFMT "\n", MAC2STR(bsta_radio_cap->macaddr[0]));

	trace("\n");
}

void trace_tlv_profile2_ap_cap(const struct tlv_profile2_ap_cap *profile2_ap_cap)
{
	if (!profile2_ap_cap)
		return;

	trace("\nTLV type: MAP_TLV_PROFILE2_AP_CAPABILITY\n");
	trace("\treserved: 0x%X\n", profile2_ap_cap->reserved);
#if (EASYMESH_VERSION > 2)
	trace("\tmax_prio_rules: %d\n", profile2_ap_cap->max_prio_rules);
	trace("\tcaps: 0x%X\n", profile2_ap_cap->caps);
#else
	trace("\tunit: 0x%X\n", profile2_ap_cap->unit);
#endif /* EASYMESH_VERSION */
	trace("\tmax_vids: %d\n", profile2_ap_cap->max_vids);

	trace("\n");
}

void trace_tlv_ap_radio_adv_cap(const struct tlv_ap_radio_adv_cap *ap_radio_adv_cap)
{
	if (!ap_radio_adv_cap)
		return;

	trace("\nTLV type: MAP_TLV_AP_RADIO_ADV_CAPABILITY\n");
	trace("\tradio:" MACFMT "\n", MAC2STR(ap_radio_adv_cap->radio));
	trace("\tcap: 0x%X\n", ap_radio_adv_cap->cap);

	trace("\n");
}

#if (EASYMESH_VERSION > 2)
void trace_tlv_1905_encap_dpp(const struct tlv *t)
{
	if (!t)
		return;

	const struct tlv_1905_encap_dpp *encap_dpp;
	uint8_t body[2048] = {};
	bool mac_present = false;
	bool is_dpp_frame = false;
	int offset = 0;
	struct encap_dpp_frame *frm;

	trace("\nTLV type: MAP_TLV_1905_ENCAP_DPP\n");

	encap_dpp = (struct tlv_1905_encap_dpp *)t->data;

	/* Flags */
	mac_present = (encap_dpp->dst.flag & ENCAP_DPP_ENROLLEE_MAC_PRESENT);
	is_dpp_frame = (encap_dpp->dst.flag & ENCAP_DPP_FRAME_INDICATOR);

	trace("\t\tis_enrolee_mac_addr_present: %d\n", mac_present);
	trace("\t\tis_dpp_frame: %d\n", is_dpp_frame);

	offset += sizeof(encap_dpp->dst);

	/* Destination STA MAC Address */
	if (mac_present) {
		trace("\tdst_sta_mac_addr:" MACFMT "\n", MAC2STR(encap_dpp->dst.addr[0]));
		offset += 6; /* dst sta mac addr */
	}

	frm = (struct encap_dpp_frame *)&t->data[offset];

	/* Frame type */
	trace("\t\tframe_type: %d\n", frm->type);

	/* Encapsulated frame length */
	trace("\t\tframe_len: %d\n", frm->len);

	if (WARN_ON(frm->len > ARRAY_SIZE(body) - 1)) {
		trace("\n");
		return;
	}

	/* null terminate Encapsulated frame */
	memcpy(body, frm->frame, frm->len);

	/* Encapsulated frame (DPP or GAS) */
	trace("\t\tframe: %.*s\n\n", frm->len, (const char *)frm->frame);

	trace("\n");
}

void trace_tlv_dpp_chirp_value(const struct tlv *t)
{
	if (!t)
		return;

	const struct tlv_dpp_chirp *dpp_chirp;
	uint8_t hash[2048] = {};
	uint8_t hashlen;
	bool mac_present = false;
	bool hash_validity = false;
	uint8_t *data = NULL;
	int offset = 0;

	trace("\nTLV type: MAP_TLV_1905_ENCAP_DPP\n");

	dpp_chirp = (struct tlv_dpp_chirp *)t->data;

	/* Flags */
	mac_present = (dpp_chirp->dst.flag & DPP_CHIRP_ENROLLEE_MAC_PRESENT);
	hash_validity = (dpp_chirp->dst.flag & DPP_CHIRP_HASH_VALIDITY);

	trace("\t\tis_enrolee_mac_addr_present: %d\n", mac_present);
	trace("\t\thash_validity: %s\n", hash_validity ? "establish" : "purge");

	offset += sizeof(dpp_chirp->dst);

	/* Destination STA MAC Address */
	if (mac_present) {
		trace("\tdst_sta_mac_addr:" MACFMT "\n", MAC2STR(dpp_chirp->dst.addr[0]));
		offset += 6; /* dst sta mac addr */
	}

	data = (uint8_t *)t->data;
	if (!data)
		return;

	hashlen = data[offset];
	offset += 1; /* hashlen */

	/* Hash Length */
	trace("\t\thash_length: %d\n", hashlen);

	if (WARN_ON(hashlen > ARRAY_SIZE(hash) - 1)) {
		trace("\n");
		return;
	}

	/* null terminate Hash Value */
	memcpy(hash, &data[offset], hashlen);

	/* Hash Value */
	trace("\t\thash_value: %.*s\n\n", hashlen, (const char *)&data[offset]);

	trace("\n");
}

void trace_tlv_direct_encap_dpp(const struct tlv *t)
{
	if (!t)
		return;

	const struct tlv_dpp_message *dpp_msg;
	int dpp_msg_len;
	uint8_t frame[2048] = {};

	trace("\nTLV type: MAP_TLV_DIRECT_ENCAP_DPP\n");

	dpp_msg = (struct tlv_dpp_message *)t->data;

	/* DPP message length must be calculated based on TLV length */
	dpp_msg_len = t->len;

	/* DPP message length */
	trace("\t\tdpp_msg_len: %d\n", dpp_msg_len);

	if (WARN_ON(dpp_msg_len > ARRAY_SIZE(frame) - 1)) {
		trace("\n");
		return;
	}

	/* null terminated DPP frame body */
	memcpy(frame, dpp_msg->frame, dpp_msg_len);

	/* frame as a string */
	trace("\t\tframe: %.*s\n\n", dpp_msg_len, (const char *)dpp_msg);

	trace("\n");
}

void trace_tlv_bss_configuration(const struct tlv *t)
{
	if (!t)
		return;

	if (t->type == MAP_TLV_BSS_CONFIGURATION_REQUEST)
		trace("\nTLV type: MAP_TLV_BSS_CONFIGURATION_REQUEST\n");

	if (t->type == MAP_TLV_BSS_CONFIGURATION_RESPONSE)
		trace("\nTLV type: MAP_TLV_BSS_CONFIGURATION_RESPONSE\n");

	trace("%.*s\n", t->len, (const char *)t->data);

	trace("\n");
}

void trace_tlv_bss_configuration_report(
	const struct tlv_bss_configuration_report *configuration_report)
{
	if (!configuration_report)
		return;

	const uint8_t *tlv_data = (const uint8_t *)configuration_report;
	int i;
	int offset = 0;

	trace("\nTLV type: MAP_TLV_BSS_CONFIGURATION_REPORT\n");

	/* num_radio (1 byte) */
	trace("\nnum_radio: %d\n", configuration_report->num_radio);
	offset += sizeof(configuration_report->num_radio);

	for (i = 0; i < configuration_report->num_radio; ++i) {

		const struct bss_configuration_report_radio *radio =
			(struct bss_configuration_report_radio *)(tlv_data + offset);
		int j;

		/* RUID/macaddr (6 bytes) */
		trace("\truid:" MACFMT "\n", MAC2STR(radio->ruid));
		offset += sizeof(radio->ruid);

		/* num_bss (1 byte) */
		trace("\tnum_bss: %d\n", radio->num_bss);
		offset += sizeof(radio->num_bss);

		for (j = 0; j < radio->num_bss; ++j) {

			const struct bss_configuration_report_bss *config_report =
				(struct bss_configuration_report_bss *)(tlv_data + offset);

			/* BSSID/macaddr (6 bytes) */
			trace("\t\tbssid:" MACFMT "\n", MAC2STR(config_report->bssid));
			offset += sizeof(config_report->bssid);

			/* report flags (1 byte) */
			trace("\t\tflag: 0x%X\n", config_report->flag);
			offset += sizeof(config_report->flag);

			/* reserved flags (1 bytes) */
			trace("\t\trsvd: 0x%X\n", config_report->rsvd);
			offset += sizeof(config_report->rsvd);

			/* ssidlen (1 byte) */
			trace("\t\tssidlen: %d\n", config_report->ssidlen);
			offset += sizeof(config_report->ssidlen);

			/* ssid (ssidlen bytes) */
			trace("\t\tssid: %.*s\n\n", config_report->ssidlen,
			      (const char *)config_report->ssid);
			offset += config_report->ssidlen;
		}
	}

	trace("\n");
}

void trace_tlv_dpp_bootstraping_uri_notification(const struct tlv *t)
{
	if (!t)
		return;

	const struct tlv_dpp_uri_bootstrap *dpp_uri_notif;
	int uri_len;
	uint8_t uri[2048] = {};

	trace("\nTLV type: MAP_TLV_DPP_BOOTSTRAPING_URI_NOTIFICATION\n");

	dpp_uri_notif = (struct tlv_dpp_uri_bootstrap *)t->data;

	/* RUID/macaddr */
	trace("\truid:" MACFMT "\n", MAC2STR(dpp_uri_notif->ruid));

	/* BSSID/macaddr */
	trace("\t\tbssid:" MACFMT "\n", MAC2STR(dpp_uri_notif->bssid));

	/* BSTA/macaddr */
	trace("\t\tbsta:" MACFMT "\n", MAC2STR(dpp_uri_notif->bsta));

	/* URI length must be calculated based on TLV length */
	uri_len = t->len - sizeof(dpp_uri_notif);

	/* URI length */
	trace("\t\turi_len: %d\n", uri_len);

	if (WARN_ON(uri_len > ARRAY_SIZE(uri) - 1)) {
		trace("\n");
		return;
	}

	/* null terminate URI string */
	memcpy(uri, dpp_uri_notif->uri, uri_len);

	/* URI string */
	trace("\t\turi: %.*s\n\n", uri_len, (const char *)uri);

	trace("\n");
}
#endif /* EASYMESH_VERSION > 2 */
