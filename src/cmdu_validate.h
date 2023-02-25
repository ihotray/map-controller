

#ifndef CMDU_VALIDATE
#define CMDU_VALIDATE

bool validate_topology_notification(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_1905_ack(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_caps_report(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_metrics_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_channel_scan_report(struct cmdu_buff *cmdu, struct tlv *tv_tsp[][16],
				  struct tlv *tv_scan[], int *num, uint8_t profile);
bool validate_topology_response(struct cmdu_buff *cmdu, struct tlv *tv_tsp[][16], uint8_t profile);
bool validate_ap_autoconfig_wsc(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_search(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);
bool validate_ap_autoconfig_response(struct cmdu_buff *cmdu, struct tlv *tv[][16], uint8_t profile);

#if (EASYMESH_VERSION > 2)
/**
 * @enum enum direct_encap_dpp_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_direct_encap_dpp function.
 */
enum proxied_encap_dpp_order {
	PROXIED_ENCAP_1905_ENCAP_DPP_IDX, // 0
	PROXIED_ENCAP_CHIRP_VALUE_IDX,

	PROXIED_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_proxied_encap_dpp(struct cmdu_buff *cmdu, struct tlv *tlvs[][16]);

/**
 * @enum enum direct_encap_dpp_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_direct_encap_dpp function.
 */
enum direct_encap_dpp_order {
	DIRECT_ENCAP_DPP_MESSAGE_IDX, // 0

	DIRECT_ENCAP_DPP_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_direct_encap_dpp(struct cmdu_buff *cmdu, struct tlv *tlvs[][16]);

/**
 * @enum enum bss_configuration_request_tlvs_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_bss_configuration_request function.
 */
enum bss_configuration_request_tlvs_order {
	BSS_CFG_REQ_MULTIAP_PROFILE_IDX, // 0
	BSS_CFG_REQ_SUPPORTED_SERVICE_IDX,
	BSS_CFG_REQ_AKM_SUITE_CAPS_IDX,
	BSS_CFG_REQ_AP_RADIO_BASIC_CAPS_IDX,
	BSS_CFG_REQ_BACKHAUL_STA_RADIO_CAPS_IDX,
	BSS_CFG_REQ_PROFILE2_AP_CAP_IDX,
	BSS_CFG_REQ_AP_RADIO_ADVANCED_CAPS_IDX,
	BSS_CFG_REQ_CONFIG_REQUEST_IDX,

	BSS_CFG_REQ_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_bss_configuration_request(struct cmdu_buff *cmdu,
					struct tlv *tlvs[][16], uint8_t profile);

/**
 * @enum enum bss_configuration_result_tlvs_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_bss_configuration_result function.
 */
enum bss_configuration_result_tlvs_order {
	BSS_CFG_RESULT_BSS_CONFIG_REPORT_IDX, // 0

	BSS_CFG_RESULT_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_bss_configuration_result(struct cmdu_buff *cmdu,
				       struct tlv *tlvs[][16],
				       uint8_t profile);

/**
 * @enum enum dpp_bootstraping_uri_notification_order
 * @brief specifies order of output TLVs and max. number of different TLVs
 *		for validate_dpp_bootstraping_uri_notification function.
 */
enum dpp_bootstraping_uri_notification_order {
	DPP_BOOTSTRAP_URI_NOTIF_IDX, // 0

	DPP_BOOTSTRAP_URI_NOTIF_MAX_NUMBER_OF_TLV_TYPES
};

bool validate_dpp_bootstraping_uri_notification(struct cmdu_buff *cmdu,
				       struct tlv *tlvs[][16]);

#endif /* EASYMESH_VERSION> 2 */

#endif /* CMDU_VALIDATE */
