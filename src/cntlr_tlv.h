/*
 * cntlr_tlv.h - tlv building function declarations
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#ifndef CNTLR_TLV_GEN_H
#define CNTLR_TLV_GEN_H

#ifdef EASYMESH_VENDOR_EXT
struct tlv_vendor_bbss {
	uint8_t oui[3];
	uint8_t num_radios;
	struct __attribute__((packed)) radio {
		uint8_t radio_id[6];
		uint8_t num_bbss;
		struct __attribute__((packed)) backhaul_bss {
			uint8_t bssid[6];
		} bbss[];
	} radios[];
} __attribute__((packed));
#endif

uint8_t *extract_tlv_by_type(struct cmdu_buff *cmdu, uint8_t tlv_type);
int cntlr_gen_8021q_settings(struct controller *c, struct cmdu_buff *frm);
int cntlr_gen_traffic_sep_policy(struct controller *c, struct cmdu_buff *frm);
int cntlr_gen_wsc(struct controller *c, struct cmdu_buff *frm,
		struct iface_credential *iface_cred, uint8_t *msg, uint16_t msglen,
		uint8_t band, uint16_t auth);
int cntlr_gen_ap_radio_identifier(struct controller *c, struct cmdu_buff *frm,
		uint8_t *hwaddr);
int cntlr_gen_supp_role(struct controller *c, struct cmdu_buff *frm,
		uint8_t role);
int cntlr_gen_supp_service(struct controller *c, struct cmdu_buff *cmdu,
		uint8_t service);
int cntlr_gen_map_profile(struct controller *c, struct cmdu_buff *frm,
		uint8_t profile);
int cntlr_gen_steering_policy(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm,
		int num_radio, uint8_t *radiolist);
int cntlr_gen_metric_report_policy(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm,
		int num_radio, uint8_t *radiolist);
int cntlr_gen_ch_scan_rep_policy(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm);
int cntlr_gen_unsuccess_assoc_policy(struct controller *c,
		struct node_policy *a, struct cmdu_buff *frm);
int cntlr_gen_backhaul_bss_config(struct controller *c, struct node_policy *a,
		struct cmdu_buff *frm, const uint8_t *bssid);
int cntlr_gen_al_mac(struct controller *c, struct cmdu_buff *frm,
		uint8_t *hwaddr);
int cntlr_gen_supported_freq_band(struct controller *c, struct cmdu_buff *frm,
		uint8_t freq_band);
struct tlv_supported_role *cntlr_gen_supported_role(struct controller *c,
		uint8_t role);
int cntlr_gen_client_info(struct controller *c, struct cmdu_buff *frm,
		uint8_t *sta, uint8_t *bssid);
int cntlr_gen_backhaul_steer_req(struct controller *c, struct cmdu_buff *frm,
		uint8_t *macaddr, uint8_t *target_bssid, uint8_t op_class,
		uint8_t channel);
int cntlr_gen_channel_scan_req(struct controller *c, struct cmdu_buff *frm,
		struct scan_req_data *req_data);
int cntlr_gen_tlv_steer_request(struct controller *c,
		struct cmdu_buff *frm, uint8_t tlv_type,
		uint8_t *bss_id, uint32_t steer_timeout,
		uint32_t sta_nr, uint8_t sta_id[][6], uint32_t bssid_nr,
		uint8_t target_bbsid[][6], uint32_t request_mode);
int cntlr_gen_tlv_assoc_ctrl_request(struct controller *c,
		struct cmdu_buff *frm, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist);
int cntlr_gen_tlv_beacon_metrics_query(struct controller *c,
		struct cmdu_buff *frm, uint8_t *sta_addr,
		uint8_t opclass, uint8_t channel,
		uint8_t *bssid, uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, const uint8_t *element);
int cntlr_gen_1905_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm);
int cntlr_gen_ap_metric_query(struct controller *c,
		struct cmdu_buff *frm, uint8_t num_bss, uint8_t *bsslist);
int cntlr_gen_ap_metrics_tlv(struct controller *c,
		struct cmdu_buff *frm, uint8_t *listbss);
int cntlr_gen_tx_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm, struct netif_link *link_info);
int cntlr_gen_rx_link_metric_tlv(struct controller *c,
		struct cmdu_buff *frm, struct netif_link *link_info);
int cntlr_gen_comb_infra_metrics(struct controller *c,
		struct cmdu_buff *frm, uint8_t *bssid);
int cntlr_gen_sta_mac(struct controller *c,
		struct cmdu_buff *frm, uint8_t *sta);
int cntlr_gen_unassociated_sta_link_metrics(struct controller *c,
		struct cmdu_buff *frm, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics);
int cntlr_gen_searched_role(struct controller *c, struct cmdu_buff *frm,
		uint8_t role);
int cntlr_gen_autoconf_freq_band(struct controller *c, struct cmdu_buff *frm,
		uint8_t band);
int cnltr_gen_searched_service(struct controller *c, struct cmdu_buff *frm,
		uint8_t service);
int agent_gen_tlv_error_code(struct controller *c,
		struct cmdu_buff *cmdu, uint8_t *macaddr, uint8_t reason_code);
int cntlr_gen_channel_pref(struct controller *c, struct cmdu_buff *frm,
		uint8_t *radio_id, uint8_t class_id, uint8_t channel_nr,
		const uint8_t *chanlist, uint8_t pref);
int cntlr_gen_txpower_limit(struct controller *c, struct cmdu_buff *frm,
		uint8_t *radio_id, uint8_t txpower_limit);
int cntlr_gen_cac_tlv(struct controller *c, struct cmdu_buff *frm,
		uint8_t tlv_type, int num_data, struct cac_data *data);
int cntlr_gen_tlv_error_code(struct controller *c,
	struct cmdu_buff *frm, uint8_t *macaddr, uint8_t reason_code);
int cntlr_gen_tlv_higher_layer_data(struct controller *c, struct cmdu_buff *frm,
		uint8_t proto, uint8_t *data, int len);

#if (EASYMESH_VERSION > 2)
int cntlr_gen_dpp_message_tlv(struct controller *c,
		struct cmdu_buff *frm);
int cntlr_gen_1905_encap_dpp_tlv(struct controller *c,
		struct cmdu_buff *frm);
int cntlr_gen_chirp_value_tlv(struct controller *c,
		struct cmdu_buff *frm);
int cntlr_gen_bss_config_response_tlv(struct controller *c,
				      struct cmdu_buff *cmdu);
int cntlr_gen_dpp_cce_indication_tlv(struct controller *c, struct cmdu_buff *frm,
				     bool cce_advertise);
int cntlr_gen_device_1905_layer_security_cap(struct controller *c,
		struct cmdu_buff *frm);
int cntlr_gen_cntlr_capability(struct controller *c, struct cmdu_buff *frm);
int cntlr_gen_agent_list_tlv(struct controller *c, struct cmdu_buff *frm);
#endif /* EASYMESH_VERSION > 2 */

#endif /* CNTLR_TLV_GEN_H */
