# MAP Controller

[Map-Controller](https://dev.iopsys.eu/iopsys/map-controller)


## Introduction

This package provides the mapcontroller daemon, which implements the WiFi
Alliances Easymesh Controller component.

## Overview

This README will show how to properly setup the mapcontroller configuration file
and explain some features of map-controller:

* Policy Configuration
* AP-Autoconfig Renew
* Channel Planning
* STA Steering
* Dynamic Controller Sync
* Enabling Traffic Separation
* Passing custom vendor extensions with WSC M2
* IOPSYS Vendor Extensions

## UCI Configuration

A default configuration file which will propagate one fronthaul and one backhaul
interface for the 5GHz and 2.4GHz bands respectively may look as such:

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'
	option debug '0'
	option bcn_metrics_max_num '10'
	option initial_channel_scan '0'
	option primary_vid '1'
	option enable_ts '0'
	option primary_pcp '0'
	option allow_bgdfs '0'
	option channel_plan '0'

config sta_steering
	option steer_module 'rcpi'
	option enabled '1'
	option enable_sta_steer '0'
	option enable_bsta_steer '0'
	option use_bcn_metrics '0'
	option use_usta_metrics '0'
	option bandsteer '0'
	option diffsnr '8'
	option rcpi_threshold_2g '70'
	option rcpi_threshold_5g '86'
	option rcpi_threshold_6g '86'
	option report_rcpi_threshold_2g '80'
	option report_rcpi_threshold_5g '96'
	option report_rcpi_threshold_6g '96'

config ap
	option band '5'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'

config ap
	option band '2'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'

config ap
	option band '5'
	option ssid 'MAP-021000000001-BH-5GHz'
	option encryption 'sae'
	option type 'backhaul'
	option vid '1'
	option key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'

config ap
	option band '2'
	option ssid 'MAP-021000000001-BH-2.4GHz'
	option encryption 'sae'
	option type 'backhaul'
	list disallow_bsta '0'
	option vid '1'
	option key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'
```


### Credentials

The `ap` sections are access point credentials that will be passed to agents in
the network, which will setup the local wireless configuration accordingly.

### Fronthaul Credentials

Fronthaul AP credentials are identified by the human readable option
`type 'fronthaul'`. Once propagated to agents, these interfaces are written with
`option multi_ap '2'` to the wireless configuration.

As such, the following mapcontroller sections will generate the respective
wireless sections, after handled by an agent:

```
config ap
	option band '5'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'

config ap
	option band '2'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'

```

```
config wifi-iface 'default_wl0'
	option device 'wl0'
	option network 'lan'
	option ifname 'wl0'
	option mode 'ap'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option uuid 'c8f1402f-1ef9-4801-9a68-021000000001'
	option multi_ap '2'
	option ssid 'iopsysWrt-021000000001'
	option key '7NTx-APvX-pba7-tvd7'
	option encryption 'sae-mixed+aes'
	option ieee80211w '1'
	option start_disabled '0'
	option multicast_to_unicast '1'
	option isolate '0'
	option multi_ap_backhaul_ssid 'MAP-021000000001-BH-5GHz'
	option multi_ap_backhaul_key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'

config wifi-iface 'default_wl1'
	option device 'wl1'
	option network 'lan'
	option ifname 'wl1'
	option mode 'ap'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option uuid 'c8f1402f-1ef9-4801-9a68-021000000001'
	option multi_ap '2'
	option ssid 'iopsysWrt-021000000001'
	option key '7NTx-APvX-pba7-tvd7'
	option encryption 'sae-mixed+aes'
	option ieee80211w '1'
	option start_disabled '0'
	option multicast_to_unicast '1'
	option isolate '0'
	option multi_ap_backhaul_ssid 'MAP-021000000001-BH-2.4GHz'
	option multi_ap_backhaul_key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'
```

### Backhaul Credentials

Backhaul AP credentials are identified by `type 'backhaul'`. Once propagated to
agents, these interfaces are written with `option multi_ap '1'` to the wireless
configuration. These will be the APs that backhaul stations (other IEEE1905 and
EasyMesh complianet devices) can connect to, in a Multi-AP environment.

The following mapcontroller sections will be corresponding to the respective
wireless sections, after handled by an agent:

```
config ap
	option band '2'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'

config ap
	option band '5'
	option ssid 'MAP-021000000001-BH-5GHz'
	option encryption 'sae'
	option type 'backhaul'
	option vid '1'
	option key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'

```

```
config wifi-iface 'default_wl1_1'
	option device 'wl1'
	option mode 'ap'
	option ifname 'wl1.1'
	option multi_ap '1'
	option network 'lan'
	option hidden '1'
	option uuid 'c8f1402f-1ef9-4801-9a68-021000000001'
	option ieee80211k '1'
	option ssid 'MAP-021000000001-BH-2.4GHz'
	option key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'
	option encryption 'sae+aes'
	option ieee80211w '2'
	option start_disabled '0'
	option wps_device_type '6-0050f204-1'
	option multicast_to_unicast '0'
	option isolate '0'

config wifi-iface 'default_wl0_1'
	option device 'wl0'
	option mode 'ap'
	option ifname 'wl0.1'
	option multi_ap '1'
	option network 'lan'
	option hidden '1'
	option uuid 'c8f1402f-1ef9-4801-9a68-021000000001'
	option ieee80211k '1'
	option ssid 'MAP-021000000001-BH-5GHz'
	option key '569dfdc9447e494da231d4def3441ed92c8f63985d8992cb521d77e1763c00d'
	option encryption 'sae+aes'
	option ieee80211w '2'
	option start_disabled '0'
	option wps_device_type '6-0050f204-1'
	option multicast_to_unicast '0'
	option isolate '0'
```

### Combined Front/Back

If combined fronthaul and backhaul interfaces are to be used, a `config ap`
section with the option `type 'combined'` shall be provided:

```
config ap
	option band '2'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'combined'
```

In turn map-agent will create the interface with the option `multi_ap '3'`,
meaning combined fronthaul/backhaul interface.

```
config wifi-iface 'default_wl0'
	option device 'wl0'
	option network 'lan'
	option ifname 'wl0'
	option mode 'ap'
	option wps '1'
	option wps_pushbutton '1'
	option ieee80211k '1'
	option bss_transition '1'
	option uuid 'c8f1402f-1ef9-4801-9a68-021000000001'
	option multi_ap '3'
	option ssid 'iopsysWrt-021000000001'
	option key '7NTx-APvX-pba7-tvd7'
	option encryption 'sae-mixed+aes'
	option ieee80211w '1'
	option start_disabled '0'
	option multicast_to_unicast '1'
	option isolate '0'
```

### Policy Configuration

Agent, and agent radio specific configuration can be set from mapcontroller
configuration, and propagated via Multi-AP Policy Configuration Request CMDU.

#### Agent Specific Configuration

Whenever the mapcontroller discovers an agent (via AP-Autoconfig Search
messages), it will add a skeleton configuration sections with the bare minimum,
assuming default values for the rest:

```
config node 'node_ee6c9a52b027'
	option agent_id 'ee:6c:9a:52:b0:27'
# the following values are not explicitly set and the default values are used
	option backhaul_ul_macaddr '00:00:00:00:00:00'
	option backhaul_dl_macaddr '00:00:00:00:00:00'
	option backhaul_type 'none'
	option primary_vid '1'
	option primary_pcp '0'
	option report_sta_assocfails '0'
	option report_sta_assocfails_rate '0'
	option report_metric_periodic '0'
	option report_scan '0'
	option steer_exclude '0'
	option steer_exclude_btm '0'
	option steer_disallow '0'
	option coordinated_cac '0'
	option traffic_separation '0'
	option sta_steer '0'
```

If these values are modified, a `SIGHUP` can be triggered to mapcontroller and
the options will be propagated to the agent(s).

#### Radio Specific Configuration

When an agent is discovered it will proceed to complete AP-Autoconfiguration.
During AP-Autoconfiguration, each radio on the agent will send an
AP-Autoconfiguration WSC (M1), these radios will have their own sections created
in the mapcontroller configuration with necessary policies. Each section maps to
an agent section by `agent_id`.

```
config radio 'radio_ec6c9a52acb9'
	option agent_id 'ee:6c:9a:52:ac:b7'
	option macaddr 'ec:6c:9a:52:ac:b9'
	option band '5'
# the following values are not explicitly set and the default values are used
	option steer_policy '0'
	option util_threshold '0'
	option rcpi_threshold '86'                # 70 for 2.4GHz band
	option report_rcpi_threshold '96'         # 80 for 2.4GHz band
	option report_util_threshold '0'
	option report_rcpi_hysteresis_margin '0'
	option include_sta_stats '1'
	option include_sta_metric '1'
```

If these values are modified, a `SIGHUP` can be triggered to mapcontroller and
the options will be propagated to the agent(s).


## AP-Autoconfig Renew (Network Reconfiguration)

Autoconfig Renew will trigger all agents to be reconfigured with updated
credentials.

### Trigger

Mapcontroller will re-read the mapcontroller credentials and policies upon
receiving `SIGHUP`. In order to trigger AP-Autoconfig Renew the mapcontroller
credentials loaded in memory at runtime, must differ from the ones in the
config, causing mapcontroller to generate a AP-Autoconfig Renew for all agents
to be reconfigured. Meaning i.e. an `ap` section SSID has changed.

## Channel Planning

Map-controller supports channel planning in the form of channel selection, and
background CAC (if supported) to clear channels. Each locked behind their own
UCI configuration options.

Additionally, there are ubus methods available to do it manually:

* ubus call map.controller scan '{"agent":"46:d4:37:71:be:80", "radio":["44:d4:37:71:be:8f"], "channel":[[]]}' - best call before channel_pref – to get fresh preference counters
* ubus call map.controller channel_pref – get/update channel preferences from all nodes
* ubus call map.controller channel_cleanup – run background CAC (preCAC) on nodes if required
* ubus call map.controller channel_recalc – base on channel preference score choose best channel for each node and radio and request node to switch to this channel

### Channel Selection

Map-controller will send a Channel Preference Query to its agents and collect
the results. Whenever the channel selection periodic timer is hit,
map-controller will calculate the best channel for the network.

This feature is enabled by the UCI configuration:
```
config controller 'controller'
	option channel_plan '0'
```

The `channel_plan` value corresponds to the timeout in seconds at which channel
planning will be triggered. Any value less than 180 will be treated as invalid
and default to 3600 * 3 seconds (three hours). Setting to 0 means disabled.

Do note that this feature will not kick in for any radio which has a downstream
agent wirelessly connected.

### Background DFS

If enabled, map-controller will periodically trigger background dfs in each
agent that supports it, based on bandwidth, channel and DFS availability.

This feature is enabled by the UCI configuration:
```
config controller 'controller'
	option allow_bgdfs '0'
```

The `allow_bgdfs` value corresponds to the timeout in seconds at which
background DFS will be triggered. Any value less than 120 will be treated as
invalid and default to 120 seconds (two minutes). Setting to 0 means disabled.


## STA Steering

Map-controller initiated mandate steering based on beacon measurement is
supported. For STA to be able to be steered its drivers must support 802.11k
(RRM for beacon measurements) and 802.11v.

To enable STA steering feature one must add following section in map-controller
UCI config:
```
config sta_steering
	option steer_module 'rcpi'
	option enabled '1'
	option enable_sta_steer '1'
	option use_bcn_metrics '1'
```

The steer_module maps to the rcpi plugin in /usr/lib/mapcontroller/rcpi.so
Sometimes it may also be needed to enable initial channel scan.

```
config controller 'controller'
	 option initial_channel_scan '1'
```

BTM steering may also work fine w/o the initial_channel_scan set - it
depends on the bottom layer implementation (independent channel scan).

Setting the initial_channel_scan option itself will cause a radio scan request
to be issued towards given node and it's reported radios, providing there was
no prior scan results reported on given radio. This radio channel scan will
be issued once controller obtains first scan capability information tlv from
given node. Radios, opclasses and channels to scan depend on these scan caps.

The steering decision is based upon drop of the STA RCPI below report rcpi
threshold, which can be modified globally using sta_steering section separately
for each radio band

```
config sta_steering
	option report_rcpi_threshold_2g '80'
	option report_rcpi_threshold_5g '96'
	option report_rcpi_threshold_6g '96'
```

Or per radio via radio section of UCI config:

```
config radio 'radio_44d4376af4cf'            
        option agent_id '46:d4:37:6a:f4:c0'  
        option macaddr '44:d4:37:6a:f4:cf'   
        option band '5'
        option rcpi_threshold '86'
        option report_rcpi_threshold '96'
```

In case the rcpi_threshold is not set it defaults in code to 86 for 5GHz & 6Ghz
and to 70 for 2.4GHz.

Once the signal strength goes below the report_rcpi_threshold it’ll trigger
link metrics response from agent to controller, causing controller to send
beacon metrics request for the given STA on all operating classes/channels of
nodes in the mesh. The beacon metrics results will be parsed and if there’s a
better (at least 10dB difference in RSSI) BSS found for given STA, controller
will try to to move STA to that BSS using BTM. Providing the signal dropped
further below second tier thershold in the meanwhile

```
config sta_steering
	option rcpi_threshold_2g '70'
	option rcpi_threshold_5g '86'
	option rcpi_threshold_6g '86'
```

rcpi_threshold_Xg can be set per radio similarily to report_rcpi_threshold_Xg

Also the difference of RSSI of a new and an old AP must be above the diffsnr
threshold for the steer to trigger

```
config sta_steering
	option diffsnr '8'
```

### Steer Exclude

There are two steering disallowed lists maintained in the controller:
- steer_exclude (per node) – exclude STA from steering completely
- steer_exclude_btm (per node) – do not allow to steer of the STA using BTM
steering (but association control based steering will be possible in the future – once implemented).

To put the STA on either of two lists one must just add a list entry per node in
mapcontroller UCI config as in example:

```
config node 'node_46d4376af4c0'       
        option agent_id '46:d4:37:6a:f4:c0'      
        list steer_exclude 'e0:d4:e8:79:c4:ee'   
        list steer_exclude 'e0:d4:e8:79:c4:11'   
        list steer_exclude_btm 'aa:bb:cc:dd:ee:ff'
```
Removing STA MAC from the list will result in immediate allowing of the STA to
be (BTM) steered again.


## Dynamic Controller Sync

In a mesh where the controller node may change and taken by any device in the
network, it is important to keep all mapcontroller configs in-sync. If not, the
credentials, polices etc. may change upon a new device taking the controller
role resulting in disruption for the clients in the network. While the logic for
this primarily resides in the map-agent, it does have to be compile-time
selected into mapcontroller in order for it to be supported.

This compile-time flag for map-controller is
`CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG`.

Additionally, in ieee1905 and map-agent:
* map-agent - `AGENT_SYNC_DYNAMIC_CNTLR_CONFIG`
* ieee1905 - `MULTIAP_DYNAMIC_CNTLR_SYNC_CONFIG`

## Traffic Separation

For a more in-depth README on Traffic Separation see [link](https://dev.iopsys.eu/iopsys/map-agent/-/blob/devel/docs/README-Traffic_Separation.md).
For instructions on how to setup layer 3 Traffic Separation, see [link](https://dev.iopsys.eu/iopsys/map-agent/-/blob/devel/docs/README-Layer3ts.md).

To enable Guest WiFi and Easymesh Traffic Segregation, the option 'primary_vid'
and 'enable_ts' must be set to a non-zero value in the map-controller config's
global section.

NOTE: Currently, only primary_vid = '1' is supported:

```
config controller 'controller'
	option enabled '1'
	option registrar '5 2'
	option primary_vid '1'
	option primary_pcp '0'
	option enable_ts '1'
```

To create a Guest WiFi network, a new 'ap' configuration section must be added
to the map-controller configuration, with a VID different from the primary.
Alternatively, an existing section may have its VID changed.

```
config ap
	option band '5'
	option ssid 'iopsysWrt-GUEST-5'
	option encryption 'sae-mixed'
	option key '1234567890'
	option vid '10'
	option type 'fronthaul'
```

After changing as above, issue a `SIGHUP` to map-controller in order to reload
the new configuration and propagate them to the map-agents in the Multi-AP
network.


## Dynamic Vendor Extensions

UCI configurable vendor extensions can be passed by the map-controller within
the AP-Autoconfiguration WSC M2 frame to its agents.

These vendor extensions are UCI configurable by `list vendor_ie <hex string>`, from the
map-controller AP section in the format of:

```
section ap
	option band '5'
	option ssid 'iopsysWrt-021000000001'
	option encryption 'sae-mixed'
	option key '7NTx-APvX-pba7-tvd7'
	option vid '1'
	option type 'fronthaul'
	list vendor_ie '<oui><data>'   # oui must be 3 bytes
```


Values that are not provided as full bytes (i.e. not even number of characters)
are discarded.

Each vendor_ie will be appended with Vendor Extension attribute ID 0x1049 in the
WSC M2 payload. When received by map-agent, they will be parsed and added to the
respective ap section in the same format.

Example configuration -
From the map-controller AP section:

```
config ap
      option band '5'
      option ssid 'iopsysWrt-021000000001'
      option encryption 'sae-mixed'
      option key '7NTx-APvX-pba7-tvd7'
      option vid '1'
      option type 'fronthaul'
      list vendor_ie '00112211'
```

As seen added to map-agent AP sections:

```
config ap
      option ifname 'wl0'
      option band '5'
      option device 'wl0'
      option type 'fronthaul'
      option encryption 'sae-mixed+aes'
      option vid '1'
      option ssid 'iopsysWrt-021000000001'
      option key '7NTx-APvX-pba7-tvd7'
      option enabled '1'
      list vendor_ie '00112211'            # custom vendor extension
```
## IOPSYS Vendor Extensions

Map-controller supports a set of less impactful vendor extensions. All vendor
extensions are optionally included via the compile-time flag
`EASYMESH_VENDOR_EXT`.

The OUI used by the vendor extensions can be selected by passing them with the
compile-time flag `EASYMESH_VENDOR_EXT_OUI`. If vendor extensions are enabled
but no OUI flag is passed, it will default to use the oui 0x001122.

### Enabled SSID

Under an `ap` section there is an `enabled` option, which has different behavor
when vendor extensions are compiled and not.

```
config ap
	option band '5'
	option ssid 'iopsysWrt-44D43771BB20'
	option encryption 'sae-mixed'
	option key '1234567890'
	option vid '1'
	option type 'fronthaul'
	option enabled '0'
```

When `EASYMESH_VENDOR_EXT` is compiled in, the 'ap' section (as above) will be
propagated within an AP-Autoconfig WSC CMDU. A wsc vendor attribute gets
included inside the WSC-M2 TLV (with a custom attribute 0x4c), which carries
this 'enabled=0' information.

If the receiving map-agent also has EASYMESH_VENDOR_EXT enabled and compiled in,
this 'ap' section received through the AP-autoconfiguration will have disabled =
'true' set when written to the 'wireless' and corresponding 'hostapd'
configuration.

If `EASYMESH_VENDOR_EXT` is not included (*default*), map-controller will skip
this 'ap' section entirely, and the section will not be included in any
AP-Autoconfiguration WSC-M2 TLVs.

### Backhaul BSS Identifying

To easily identify a backhaul BSS, a vendor extension TLV is optionally added to
Topology Response CMDUs and parsed by map-controller. This is merely a cosmetic
improvement in the map-controller `status` UBUS API.

## UBUS APIs

Map-controller offers a variety of UBUS APIs, most of them map to CMDU request
messages. The exceptions to this are:
* `status` - Shows mapcontrollers view of the network and some stored data for
each agent
* `timers` - Will show time remaining till certain internal timers are triggered
(so far only channel planning timers are added)
* `steer_summary` and `steer_history` - Maps to TR-181 data model.

```
root@iopsys-021000000001:~# ubus -v list map.controller
'map.controller' @35515cda
	"status":{}
	"timers":{}
	"steer_summary":{"sta":"String"}
	"steer_history":{"sta":"String"}
	"ap_caps":{"agent":"String"}
	"sta_caps":{"agent":"String","sta":"String","bssid":"String"}
	"channel_pref":{"agent":"String"}
	"channel_recalc":{"agent":"String","skip_dfs":"Boolean"}
	"channel_cleanup":{"agent":"String"}
	"bk_steer":{"agent":"String","bssid":"String","channel":"Integer","op_class":"Integer","bksta":"String"}
	"agent_policy":{"agent":"String","radiolist":"Array","bsslist":"Array"}
	"channel_select":{"agent":"String","radio_id":"String","class_id":"Integer","channel":"Array","preference":"Integer","transmit_power":"Integer"}
	"reconfig_ap":{"agent":"String"}
	"steer":{"agent":"String","src_bssid":"String","sta":"Array","target_bssid":"Array","steer_timeout":"Integer","btm_timeout":"Integer","steer_req_mode":"Boolean"}
	"client_assoc_cntlr":{"agent":"String","bssid":"String","assoc_cntl_mode":"Integer","assoc_valid_timeout":"Integer","stalist":"Array"}
	"ap_metric_query":{"agent":"String","bsslist":"Array","radiolist":"Array"}
	"scan":{"agent":"String","radio":"Array","opclass":"Array","channel":"Array","fresh_scan":"Boolean"}
	"scan_results":{"radio":"Array"}
	"sta_metric_query":{"agent":"String","sta":"String"}
	"unassoc_sta_lm_query":{"agent":"String","opclass":"Integer","metrics":"Array"}
	"bcn_metrics_query":{"agent":"String","sta":"String","opclass":"Integer","channel":"Integer","bssid":"String","reporting_detail":"Integer","ssid":"String","channel_report":"Array","request_element":"Array"}
	"bcn_metrics_resp":{"sta":"String"}
	"bk_caps":{"agent":"String"}
	"topology_query":{"agent":"String"}
	"cac_req":{"agent":"String","radiolist":"Array"}
	"cac_term":{"agent":"String","radiolist":"Array"}
	"higher_layer_data":{"agent":"String","protocol":"Integer","data":"String"}
	"send_combined_metrics":{"agent":"String","bssid":"String"}
	"sync":{"agent":"String"}
```
