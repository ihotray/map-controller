
# STA steering

Current version of software supports controller initiated mandate steering based on beacon measurement. For STA to be able to be steered its drivers must support 802.11k (RRM for beacon measurements) and 802.11v (this is usually implemented in MAC, needed for BTM steering).

## Usage & UCI Configuration

In order to enable STA steering please set at least *enable_sta_steer* and *use_bcn_metrics* in mapcontroller file to **1** .
There're also other UCI parameters that will be used for steering:

**/etc/config/mapcontroller**

``` shell
...
config sta_steering
...
        option steer_module 'rcpi'
        # the name must match the /usr/lib/mapcontroller/<name>.so plugin file
        option enabled '1'
        # load this plugin if 1, skip loading otherwise
        option enable_sta_steer '1'
        # enable steering of (non-bsta) client stations
        option enable_bsta_steer '0'
        # enable steering of backhauls (experimental)
        option use_bcn_metrics '1'
        # use rcpi from beacon metrics to decide on best bssid to steer to
        option use_usta_metrics '0'
        # use ul_rcpi measured as an unassociated sta as additional trigger for steering (experimental)
        option bandsteer '0'
		# if 1 then steering from 5g/6g to 2.4g is alowed
        option diffsnr '8'
		# minimal RSSI diff (dest RSSI - src RSSI) for the BTM to kick in (default 8dB)
		option rcpi_threshold_2g '70'
		# global default rcpi threshold to trigger steering on 2GHZ band
		option rcpi_threshold_5g '86'
		# global default rcpi threshold to trigger steering on 5GHZ band
		option rcpi_threshold_6g '86'
		# global default rcpi threshold to trigger steering on 6GHZ band
		option report_rcpi_threshold_2g '80'
		# global default rcpi threshold to start reporing on 2GHZ band
		option report_rcpi_threshold_5g '96'
		# global default rcpi threshold to start reporing on 5GHZ band
		option report_rcpi_threshold_6g '96'
		# global default rcpi threshold to start reporing on 6GHZ band

...
```

Please note, that the steer_module must be present in the system, that is the map-controller is expecting to find rcpi plugin in /usr/lib/mapcontroller/rcpi.so. Otherwise it will not be able to load the steering decision plugin, and therefore the steering will be effectively disabled. More than one plugin can be present in system and in config file - each with own set of steering parameters, first one will be used for steering.

**/etc/config/mapcontroller**

``` shell
...
config radio 'radio_44d4376af4cf'            
        option agent_id '46:d4:37:6a:f4:c0'  
        option macaddr '44:d4:37:6a:f4:cf'   
        option band '5'
        option report_rcpi_threshold '96'
        option rcpi_threshold '86'
...
```

This will be synchronized to mapagents in the mesh – radio sections in /etc/config/mapagent for each agent will be updated accordingly.
Please note, that the rcpi_threshold & report_rcpi_threshold - if set - will override the global values set earlier in sta_steering section.

**/etc/config/mapagent**

``` shell
...
config wifi-radio
...
        option util_threshold '0'
        # radio utilization - if non-zero, then checked every 5 seconds
        # it may cause sending of associated sta link metrics to the controller
        # mandate steering may be trigerred by controller in handler of the above
...
        option report_rcpi_threshold '96'
        # going below threshold value will trigger sending of associated sta link metrics to the controller
        # mandate steering may be trigerred by controller in handler of the above
...
        option rcpi_threshold '86'
		# steer once ul rcpi goes below this threshold, providing there's enough bcn metrics data available
...
        option include_sta_metric '1'
        # additional trigger point on top of the previous two
        # notify controller on current link metrics (send link metrics) along the AP metrics response
        # mandate steering may be trigerred by controller in handler of the above
...
```

In case the rcpi_threshold is not set explicitly in configuration file it will default to:
#define CONFIG_DEFAULT_RCPI_TH_6G 86
#define CONFIG_DEFAULT_RCPI_TH_5G 86
#define CONFIG_DEFAULT_RCPI_TH_2G 70

In case the report_rcpi_threshold is not set explicitly in configuration file it will default to:
**report_rcpi_threshold = rcpi_threshold + 10**

## Working functionality (automatic beacon metrcis based BTM steering)

Controller initiated mandate steering is now working as follows:

Once the STA – AP rcpi goes below given value, map-agent sends the Associated STA Link Metrics Response to the map-controller. This in turn will cause map-controller to send beacon metrics request for given STA on all operating classes/channels of nodes operating in the mesh and SSID value set to current network. After some time (depends on number of opclass/channel pairs) – the beacon metrics results will be parsed. Once there’s a better (diffsnr of at least 8dB is a default) BSS found for given STA, controller will try to to move STA to that BSS using BTM request.

Depending on the settings there'll be more or less frequent checks done by the controller. - Frequency of the checks depends on the frequency of the associated sta link metrics responses received from the nodes, which depends on the settings as explained earlier (util_threshold, report_rcpi_threshold, rcpi_threshold, include_sta_metric). Controller will check if RCPI goes below the reporting threshold. If so, then controller will request for beacon metrics and/or unassociated STA link metrics for given client. After some time it will then compare current RCPI of that given station with the values obtained in metrics and only try to (BTM) steer that station if there's a better candidate found. - The delta RCPI of at least 8 is required (difference in beacon metrics RCPI of source and target). Additionally the current uplink RCPI will be always compared with rcpi_threshold in the plugin, and steering will not take place if it's above that trigger.

## Unassociated STA link metrics (experimental)
Additionally one can try to use unassociated STA link metrics on top or instead of beacon metrics for getting of the (uplink) rcpi of given STA, for that one must set following in map-controller config

**/etc/config/mapcontroller**

``` shell
config sta_steering
	option use_usta_metrics '1'
```

This will enable unassociated STA link metrics as an additional trigger for mandate steering.
The check is triggered on same occasion as for beacon metrics –upon drop of the signal strength below given threshold. In such case if there’s a BSS with better link towards steered STA found (in terms of better uplink RCPI - difference of at least 10) controller will send BTM steer request towards this STA.

## Steer exclusion lists
Additionally there’re two steering disallowed lists maintained in the controller:
- steer_exclude (per node) – exclude STA from steering completely
- steer_exclude_btm (per node) – do not allow to steer of the STA using BTM steering (but association control based opportunity steering will be possible in the future – once implemented). To put the STA on either of two lists one must just add a list entry per node in controller UCI config as in example:

**/etc/config/mapcontroller**

``` shell
config node 'node_46d4376af4c0'       
        option agent_id '46:d4:37:6a:f4:c0'      
        list steer_exclude 'e0:d4:e8:79:c4:ee'   
        list steer_exclude 'e0:d4:e8:79:c4:11'   
        list steer_exclude_btm 'aa:bb:cc:dd:ee:ff'
```

Removing STA MAC from the list will result in immediate allowing of the STA to be (BTM) steered again.

## RCPI plugin
The plugin is used for separating steering decision algorithm from the steering code itself. Current example implementation is using diffsnr and rcpi_threshold values in order for the map-controller rcpi plugin to decide if there’s a better bssid found in per-STA measurements list.
The source for the default rcpi plugin can be found in map-controller source under plugins/steer/rcpi. If one wants to use their own decision algorithm they need to create new directory under plugins/steer/<plugin name> and update appropriate Makefiles.

## Band steer
There’s an additional option in sta_steering section of map-controller config

**(/etc/config/mapcontroller)**

``` shell
config sta_steering
	option bandsteer ‘1’
```

This option is also passed down to rcpi plugin. If set then rcpi plugin will allow for steering between bands (from 2.4 to 5 and from 5 to 2.4), basing its decision only on the difference in rssi. If not set then only steering across BSSs operating on current band will be allowed.


## UBUS call inititated steering
In order to steer the STA one can also use a map-controller UBUS API as follows

``` shell
ubus call map.controller steer '{"agent":"46:d4:37:6a:f7:d0", "src_bssid":"7e:d4:37:6a:f7:d8", "sta":["e0:d4:e8:79:c4:ee"], "steer_req_mode":true, "target_bssid":["44:d4:37:6a:f4:cf"]}'

```

The parameters are:
- agent - alid of the agent node of the source BSSID
- src_bssid - source BSSID to which the STA is currently connected
- sta - MAC address of the STA to be steered
- steer_req_mode - true for mandate, false for opportunity (experimental)
- target_bssid - target BSSID to which the STA is requested to connect

## Other UBUS commands

Get independent (from the algorithm) beacon metrics for one opclass/channel pair:
``` shell
ubus call map.controller bcn_metrics_query '{"agent":"46:d4:37:6a:f4:c0", "sta":"e0:d4:e8:79:c4:ee", "ssid":"44:d4:37:6a:f4:cf", "opclass":115, "channel":36}'
```

Get independent (from the algorithm) beacon metrics for more than one opclass/channel:
``` shell
ubus call map.controller bcn_metrics_query '{"agent":"46:d4:37:6a:f4:c0", "sta":"e0:d4:e8:79:c4:ee", "bssid":"ff:ff:ff:ff:ff:ff", "opclass":0, "channel":255, "ssid":"iopsysWrt-44D4376AF4C0", "channel_report":[{"opclass":115,"channels":[36,40,44,48]}, {"opclass":118,"channels":[52,56,60,64]}]}'
```

Displaying of the currently stored beacon metrics:
``` shell
ubus call map.controller bcn_metrics_resp
ubus call map.controller bcn_metrics_resp '{"sta":"e0:d4:e8:79:c4:ee"}
```

## Known issues & limitations

- report_rcpi_threshold & rcpi_threshold are set separately per radio in controller config and can only be set after succesfull onboarding.
- hysteresis parameter is not implemented.
- There's no initial channel scan - independent channel scan must be executed on each node.
  i.e. `ubus call wifi.radio.wl0 list_neighbor` must include target (to:) bss when run on src (from:) node
One shall set the
``` shell
config controller 'controller'
	option initial_channel_scan ‘1’
```
in controller section of the controller config (/etc/config/mapcontroller) in order for the BTM steering to work robustly all the times.
Otherwise the neighbor_list on target interface may be empty, causing the BTM steering to that given BSSID to fail by ESL (“bssid not on neighbor list” type of error).
We’re currently working on removal of that check in ESL, so that neighbor_list can be empty on given interface (ubus call wifi.ap.wlX list_neighbor), as we already know the neighbors in map. We’ll then provide all the necessary neighbor data directly from the map daemons (bssid, channel, opclass, phy & bssid_info) – without depending on the channel scan functionality that would normally cause the neighbor list in wifi to be filled in.
- Only beacon metrics that were obtained after steering request sent are being used as steering data base. Others are marked 'stale'.
- One must set RCPI (report_rcpi_threshold & rcpi_threshold) using /etc/config/mapcontroller separately for each device & radio.
- One must remember to set up following configuration in controller, as it's not there by default:
``` shell
  list steer_module 'rcpi'
```
- bandsteer check is not implemented in 6.5

## Source code guide

Function(s) from where the steering method of the steer plugin gets called & how the result/verdict is handled

if (RCPI < rcfg.report_rcpi_threshold)
then send 'Associated STA Link Metrics Response' to the Controller

**src/agent.c**
``` C
w->rcpi_threshold_timer.cb = agent_rcpi_thresold_timer_cb;
agent_rcpi_thresold_timer_cb()
	list_for_each_entry(s, &fh->stalist, list) {
		rcpi = rssi_to_rcpi(s->rssi[0]);
            	if (rcpi < rcfg->rcpi_threshold) {
			cmdu = agent_gen_assoc_sta_metric_responsex(a, a->cntlr_almac, s, fh);
```

**src/cntlr_map.c**
``` C
handle_sta_link_metrics_response()
```

if (c->cfg.use_bcn_metrics)
then
    1. num_req = cntlr_request_bcn_metrics_sta(c, s);
    2. uloop_timeout_set(&s->bcn_metrics_timer, num_req * 3 * 1000);

**src/cntlr.c**
``` C
s->bcn_metrics_timer.cb = cntlr_bcn_metrics_parse;
```

in cntlr_bcn_metrics_parse():
    1. verdict = cntlr_maybe_steer_sta()
    2. if (verdict == OK)
then
cntlr_steer_sta() => cntlr_gen_client_steer_request() => issue BTM in ESL via hostap


**src/steer_module.c**

cntlr_maybe_steer_sta() is the function, that uses plugin in following way

``` C
cntlr_maybe_steer_sta()
struct steer_control *sc

sc->steer(sc->priv, s);
```

**src/plugins/steer/rcpi/rcpi.c**
``` C
struct steer_control rcpi = {
    .name = "rcpi",
    .init = rcpi_steer_init,
    .config = rcpi_steer_config,
    .exit = rcpi_steer_exit,
    .steer = rcpi_steer,
};
```
``` C
int rcpi_steer(void *priv, struct steer_sta *s)

if ((b->rcpi - s->best->rcpi) > sctrl->diffsnr)
            s->best = b;

    s->reason = STEER_REASON_LOW_RCPI;
    s->verdict = STEER_VERDICT_OK;
    return 0;
```

Functions for setting reporting conditions

Limitations:
- Currently it's possible to configure bandsteer (allow steering to another band) and diffsnr via config.
- The RCPI we use in config is only used for STA Link trigger in agents (report_rcpi_threshold).
- these are the only configurable checks we have in plugin:
	a. if (current_bss_rcpi >= sctrl->rcpi_threshold)
	don't try to steer until RCPI goes below some threshold
	b. if (b->rcpi > s->best->rcpi)
	find out best BSS in the mesh based on the RCPI
	c. if (sctrl->bandsteer)
	allow/disallow steering to lower band BSS
	d. if (s->best->rcpi - current_bss_rcpi < sctrl->diffsnr)
	steer only if the best found BSS has RCPI good enough
	e. if (!memcmp(s->best->bssid, s->s->bssid, 6))
	do not steer to current BSS


**src/cntlr.c**
``` C
void run_controller(void)

	if (!list_empty(&c->sclist)) {
		cntlr_assign_steer_module_default(c);
```

``` C
static void cntlr_bcn_metrics_parse(struct uloop_timeout *t)

	if (c->cfg.enable_sta_steer) {
        cntlr_configure_steer(c, s);
        cntlr_try_steer_sta(c, s);
    }
```

``` C
static void cntlr_configure_steer(struct controller *c, struct sta *s)

    /* RCPI threshold */
    if (rp->rcpi_threshold > 0)
        scfg.rcpi_threshold = rp->rcpi_threshold;
    else
        scfg.rcpi_threshold = DEFAULT_RCPI_THRESHOLD; /* 86 */

    scfg.rcpi_hysteresis = 5; /* TODO: unused */

    /* diffsnr */
    if (c->cfg.diffsnr > 0)
        scfg.rcpi_diffsnr = c->cfg.diffsnr;
    else
        scfg.rcpi_diffsnr = DEFAULT_RCPI_DIFFSNR; /* 8dB */

    /* bandsteer */
    scfg.bandsteer = c->cfg.bandsteer; /* default disabled */

    cntlr_configure_steer_module(c, &scfg);

```

**src/steer_module.c**
``` C
int cntlr_configure_steer_module(struct controller *c, struct steer_config *cfg)
        return sc->config(sc->priv, cfg);
```

**src/plugins/steer/rcpi/rcpi.c**
``` C
struct steer_control rcpi = {
    .name = "rcpi",
    .init = rcpi_steer_init,
    .config = rcpi_steer_config,
    .exit = rcpi_steer_exit,
    .steer = rcpi_steer,
};
```

``` C
static int rcpi_steer_config(void *priv, struct steer_config *cfg)
{
    p->rcpi_threshold = cfg->rcpi_threshold;
    p->hysteresis = cfg->rcpi_hysteresis;
    p->diffsnr = cfg->rcpi_diffsnr;
    p->bandsteer = cfg->bandsteer;
}
```
