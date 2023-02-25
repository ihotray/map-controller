#ifndef TLV_DEBUG_H
#define TLV_DEBUG_H

#include <cmdu.h>
#include <easymesh.h>

void trace_tlv_map_profile(const struct tlv_map_profile *t);
void trace_tlv_supported_service(const struct tlv_supported_service *t);
#if (EASYMESH_VERSION > 2)
void trace_tlv_akm_suite_caps(const struct tlv_akm_suite_caps *t);
#endif
void trace_tlv_ap_radio_basic_cap(const struct tlv_ap_radio_basic_cap *t);
void trace_tlv_bsta_radio_cap(const struct tlv_bsta_radio_cap *t);
void trace_tlv_profile2_ap_cap(const struct tlv_profile2_ap_cap *t);
void trace_tlv_ap_radio_adv_cap(const struct tlv_ap_radio_adv_cap *t);
#if (EASYMESH_VERSION > 2)
void trace_tlv_1905_encap_dpp(const struct tlv *t);
void trace_tlv_dpp_chirp_value(const struct tlv *t);
void trace_tlv_direct_encap_dpp(const struct tlv *t);
void trace_tlv_bss_configuration(const struct tlv *t);
void trace_tlv_bss_configuration_report(const struct tlv_bss_configuration_report *t);
void trace_tlv_dpp_bootstraping_uri_notification(const struct tlv *t);
#endif

#endif /* TLV_DEBUG_H */
