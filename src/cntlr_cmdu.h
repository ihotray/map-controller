/*
 * cntlr_cmdu.h - cmdu building function declarations
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#ifndef CNTLR_CMDU_GEN_H
#define CNTLR_CMDU_GEN_H

struct cmdu_buff *cntlr_gen_ap_autoconfig_renew(struct controller *c,
		uint8_t *dst);
struct cmdu_buff *cntlr_gen_ap_capability_query(struct controller *c,
		uint8_t *origin);
struct cmdu_buff *cntlr_gen_client_caps_query(struct controller *c,
		uint8_t *origin, uint8_t *sta, uint8_t *bssid);
struct cmdu_buff *cntlr_gen_beacon_metrics_query(struct controller *c,
		uint8_t *agent_mac, uint8_t *sta_addr, uint8_t opclass,
		uint8_t channel, uint8_t *bssid,
		uint8_t reporting_detail, char *ssid,
		uint8_t num_report, struct sta_channel_report *report,
		uint8_t num_element, uint8_t *element);
struct cmdu_buff *cntlr_gen_backhaul_steer_request(struct controller *c,
		uint8_t *origin, uint8_t *bkhaul, uint8_t *target_bssid,
		uint8_t op_class, uint8_t channel);
struct cmdu_buff *cntlr_gen_1905_link_metric_query(struct controller *c,
		uint8_t *origin);
struct cmdu_buff *cntlr_gen_ap_metrics_query(struct controller *c,
		uint8_t *origin, int num_bss, uint8_t *bsslist,
		int num_radio, uint8_t *radiolist);
struct cmdu_buff *cntlr_gen_policy_config_req(struct controller *c,
		uint8_t *agent_id, struct node_policy *found,
		int num_radio, uint8_t *radiolist,
		int num_bss, uint8_t *bsslist);
struct cmdu_buff *cntlr_gen_sta_metric_query(struct controller *c,
		uint8_t *origin, uint8_t *sta);
struct cmdu_buff *cntlr_gen_unassoc_sta_metric_query(struct controller *c,
		uint8_t *origin, uint8_t opclass,
		uint8_t num_metrics, struct unassoc_sta_metric *metrics);
struct cmdu_buff *cntlr_gen_ap_autoconfig_search(struct controller *c,
		uint8_t profile, uint8_t band);
struct cmdu_buff *cntlr_gen_ap_autoconfig_response(struct controller *c,
		uint8_t *dest, uint8_t band, uint16_t mid);
struct cmdu_buff *cntlr_gen_ap_autoconfig_wsc(struct controller *c,
		struct cmdu_buff *rec_cmdu, uint8_t *radio_id, struct tlv *wsc,
		uint16_t mid);
struct cmdu_buff *cntlr_gen_topology_query(struct controller *c,
		uint8_t *origin);
struct cmdu_buff *cntlr_gen_cmdu_1905_ack(struct controller *c,
		struct cmdu_buff *rx_cmdu,
		struct sta_error_response *sta_resp, uint32_t sta_count);
struct cmdu_buff *cntlr_gen_channel_scan_request(struct controller *c,
		uint8_t *agent, struct scan_req_data *req_data);
struct cmdu_buff *cntlr_gen_channel_preference_query(struct controller *c,
		uint8_t *agent);
struct cmdu_buff* cntlr_gen_cac_req(struct controller *c, uint8_t *agent,
		int num_data, struct cac_data *data);
struct cmdu_buff* cntlr_gen_cac_term(struct controller *c, uint8_t *agent,
		int num_data, struct cac_data *data);
struct cmdu_buff *cntlr_gen_bk_caps_query(struct controller *c,
		uint8_t *origin);
struct cmdu_buff *cntlr_gen_client_assoc_ctrl_request(struct controller *c,
		uint8_t *agent_mac, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist);
struct cmdu_buff *cntlr_gen_higher_layer_data(struct controller *c,
		uint8_t *addr, uint8_t proto, uint8_t *data, int len);
struct cmdu_buff *cntlr_gen_client_steer_request(struct controller *c,
		uint8_t *origin, uint8_t *bssid, uint32_t steer_timeout,
		uint32_t sta_nr, uint8_t stas[][6], uint32_t bssid_nr,
		uint8_t target_bssid[][6], uint32_t request_mode);
struct cmdu_buff *cntlr_gen_comb_infra_metrics_query(struct controller *c,
		uint8_t *origin, uint8_t *bssid_mac);
int cntrl_send_channel_preference_query(struct controller *c, uint8_t *agent);
int cntrl_send_channel_selection(struct controller *c, uint8_t *agent, uint8_t *radio,
				 uint8_t channel, uint8_t opclass, uint8_t pref);
int cntlr_send_channel_scan_request(struct controller *c, uint8_t *agent_mac,
		struct scan_req_data *data);
int cntlr_send_client_assoc_ctrl_request(struct controller *c,
		uint8_t *agent_mac, uint8_t *bssid,
		uint8_t assoc_cntl_mode, uint16_t assoc_timeout,
		uint8_t sta_nr, uint8_t *stalist, uint16_t *mid);
int cntlr_send_cac_req(struct controller *c, uint8_t *agent,
		       int num_data, struct cac_data *data);
int cntlr_send_cac_term(struct controller *c, uint8_t *agent,
		        int num_data, struct cac_data *data);
int cntlr_send_client_steer_request(struct controller *c,
			uint8_t *agent_mac, uint8_t *bssid,
			uint32_t steer_timeout, uint32_t sta_nr, uint8_t stas[][6],
			uint32_t bssid_nr, uint8_t target_bssid[][6], uint32_t request_mode);

#if (EASYMESH_VERSION > 2)
struct cmdu_buff *cntlr_gen_proxied_encap_dpp(struct controller *c);
struct cmdu_buff *cntlr_gen_direct_encap_dpp(struct controller *c);
struct cmdu_buff *cntrl_gen_bss_configuration_response(struct controller *c, struct cmdu_buff *request_cmdu);
struct cmdu_buff *cntlr_gen_dpp_cce_indication(struct controller *c,
		uint8_t *agent, bool cce_advertise);
struct cmdu_buff *cntlr_gen_agent_list(struct controller *c);
int send_agent_list_to_all_nodes(struct controller *c);
#endif /* EASYMESH_VERSION > 2 */

#endif /* CNTLR_CMDU_GEN_H */
