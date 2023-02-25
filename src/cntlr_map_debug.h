/*
 * cntlr_map_debug.h - debug function declarations
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: jakob.olsson@iopsys.eu
 *
 */

#ifndef CNTLR_MAP_DEBUG_H
#define CNTLR_MAP_DEBUG_H

int debug_topology_discovery(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_topology_notification(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_topology_query(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_topology_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_ap_autoconfig_search(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_ap_autoconfig_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_ap_autoconfig_wsc(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_1905_ack(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_ap_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_channel_pref_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_channel_sel_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_oper_channel_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_ap_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_link_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_sta_link_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_unassoc_sta_link_metrics_response(void *cntlr,
	struct cmdu_buff *cmdu, struct node *n);
int debug_beacon_metrics_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_sta_steer_btm_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_sta_steer_complete(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_hld_message(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_backhaul_sta_steer_response(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_channel_scan_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_sta_disassoc_stats(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_assoc_status_notification(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_tunneled_message(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_backhaul_sta_caps_report(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_failed_connection_msg(void *cntlr, struct cmdu_buff *cmdu, struct node *n);

#if (EASYMESH_VERSION > 2)
int debug_proxied_encap_dpp(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_direct_encap_dpp(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_bss_configuration_request(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_bss_configuration_result(void *cntlr, struct cmdu_buff *cmdu, struct node *n);
int debug_dpp_bootstraping_uri_notificiation(void *cntlr, struct cmdu_buff *cmdu,
	struct node *n);
#endif /* EASYMESH_VERSION > 2 */

#endif /* CNTLR_MAP_DEBUG_H */
