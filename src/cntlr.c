/*
 * cntlr.c - Multi-AP controller
 *
 * Copyright (C) 2020-2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for source code license information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <easy/easy.h>

#include <cmdu.h>
#include <1905_tlvs.h>
#include <i1905_wsc.h>
#include <easymesh.h>
#include <map_module.h>
#include <uci.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "timer.h"
#include "utils/debug.h"
#include "utils/utils.h"
#include "cntlr.h"
#include "allsta.h"
#include "allmac.h"
#include "cntlr_ubus.h"
#include "cntlr_ubus_dbg.h"
#include "cntlr_map.h"
#include "cntlr_cmdu.h"
#include "steer_module.h"
#include "cntlr_acs.h"
#include "wifi_opclass.h"

#define map_plugin	"ieee1905.map"


extern bool waitext;

/* find interface by macaddress - no radio argument */
struct netif_iface *find_interface_by_mac_nor(struct controller *c,
		uint8_t *hwaddr)
{
	struct netif_iface *p = NULL;	/* fh anf bk iface */
	struct netif_radio *r = NULL;
	struct node *n = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		list_for_each_entry(r, &n->radiolist, list) {
			list_for_each_entry(p, &r->iflist, list) {
				if (!memcmp(p->bss->bssid, hwaddr, 6))
					return p;
			}
		}
	}

	return NULL;
}

/* find interface by macaddress */
struct netif_iface *find_interface_by_mac(struct controller *c,
		struct netif_radio *r, uint8_t *hwaddr)
{
	struct netif_iface *p = NULL;

	list_for_each_entry(p, &r->iflist, list) {
		if (!memcmp(p->bss->bssid, hwaddr, 6))
			return p;
	}

	return NULL;
}

/* find radio by ssid */
struct netif_radio *find_radio_by_ssid(struct controller *c,
		struct node *n, char *ssid)
{
	struct netif_radio *r = NULL;

	list_for_each_entry(r, &n->radiolist, list) {

		struct netif_iface *p = NULL;

		list_for_each_entry(p, &r->iflist, list) {
			if (!memcmp(p->bss->ssid, ssid, 33))
				return r;
		}
	}

	return NULL;
}

/* find netif by ssid */
struct netif_iface *find_interface_by_ssid(struct controller *c,
		struct node *n, char *ssid)
{
	struct netif_radio *r = NULL;

	list_for_each_entry(r, &n->radiolist, list) {

		struct netif_iface *p = NULL;

		list_for_each_entry(p, &r->iflist, list) {
			if (!memcmp(p->bss->ssid, ssid, 33))
				return p;
		}
	}

	return NULL;
}

/* find radio by node */
struct netif_radio *find_radio_by_node(struct controller *c, struct node *n,
		uint8_t *radio_mac)
{
	struct netif_radio *p = NULL;

	list_for_each_entry(p, &n->radiolist, list) {
		if (!memcmp(p->radio_el->macaddr, radio_mac, 6))
			return p;
	}

	return NULL;
}

/* find radio by macaddress, search all nodes */
struct netif_radio *find_radio_by_mac(struct controller *c, uint8_t *mac)
{
	struct node *n = NULL;
	struct netif_radio *r = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		r = find_radio_by_node(c, n, mac);
		if (r)
			return r;
	}

	return NULL;
}

/* finds radio struct from interface macaddr */
struct netif_radio *find_radio_by_bssid(struct controller *c, uint8_t *bssid)
{
	struct node *n = NULL;
	struct netif_radio *r = NULL;
	struct netif_iface *p = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		list_for_each_entry(r, &n->radiolist, list) {
			list_for_each_entry(p, &r->iflist, list) {
				if (!memcmp(p->bss->bssid, bssid, 6))
					return r;
			}
		}
	}

	return NULL;
}

/* find link by macaddress */
struct netif_link *find_link_by_mac(struct controller *c, uint8_t *upstream, uint8_t *downstream)
{
	struct netif_link *l = NULL;

	list_for_each_entry(l, &c->linklist, list) {
		if (!memcmp(l->upstream->bss->bssid, upstream, 6)
				&& !memcmp(l->downstream->bss->bssid, downstream, 6))
			return l;
	}

	return NULL;
}

/* find node by macaddress */
struct node *cntlr_find_node(struct controller *c, uint8_t *almac)
{
	struct node *n = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		if (!memcmp(n->alid, almac, 6))
			return n;
	}

	return NULL;
}

/* find sta by macaddress */
struct sta *cntlr_find_sta(struct controller *c, uint8_t *mac)
{
	struct sta *s = NULL;

	list_for_each_entry(s, &c->stalist, list) {
		if (!memcmp(s->de_sta->macaddr, mac, 6))
			return s;
	}

	return NULL;
}

struct bcnreq *cntlr_find_bcnreq(struct controller *c, uint8_t *sta, uint8_t *alid)
{
	struct bcnreq *br = NULL;

	dbg("%s: --->\n", __func__);

	list_for_each_entry(br, &c->bcnreqlist, list) {
		if (!memcmp(br->sta_mac, sta, 6) && !memcmp(br->agent_mac, alid, 6))
			return br;
	}

	return NULL;
}

#if 0
/* find node by macaddress */
struct netif_iface *cntlr_get_fbss_by_mac(struct controller *c, struct node *n,
		uint8_t *mac)
{
	struct netif_iface *p;

	list_for_each_entry(p, &n->iflist, list) {
		if (!memcmp(p->bss->bssid, mac, 6))
			return p;
	}

	return NULL;
}
#endif
/* find fbss based on macaddr */
struct netif_iface *cntlr_iterate_fbss(struct controller *c, uint8_t *mac)
{
	struct node *n = NULL;
	struct netif_radio *r = NULL;
	struct netif_iface *p = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		list_for_each_entry(r, &n->radiolist, list) {
			list_for_each_entry(p, &r->iflist, list) {
				if (!memcmp(p->bss->bssid, mac, 6))
					return p;
			}
		}
	}

	return NULL;
}

/* find node based on bssid */
struct node *cntlr_find_node_by_iface(struct controller *c, uint8_t *bssid)
{
	struct node *n = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		struct netif_radio *r;

		list_for_each_entry(r, &n->radiolist, list) {
			struct netif_iface *p = NULL;

			list_for_each_entry(p, &r->iflist, list) {
				if (!memcmp(p->bss->bssid, bssid, 6))
					return n;
			}
		}
	}

	return NULL;
}

#if 0
/* find node by ip address */
static struct node *find_node_by_ip(struct controller *c, const char *ip)
{
	struct node *p;
	struct in_addr ipn;

	if (ip && strlen(ip) && !inet_aton(ip, &ipn)) {
		warn("Invalid ipaddr: %s\n", ip);
		return NULL;
	}

	list_for_each_entry(p, &c->nodelist, list) {
		if (!memcmp(&p->ipaddr, &ipn, sizeof(struct in_addr)))
			return p;
	}

	return NULL;
}
#endif

struct node_policy *agent_find_policy(struct controller *c, uint8_t *agent)
{
	struct node_policy *a = NULL;

	list_for_each_entry(a, &c->cfg.nodelist, list) {
		if (!memcmp(agent, a->agent_id, 6))
			return a;
	}

	return NULL;
}

struct radio_policy *agent_find_radio_policy(struct controller *c, uint8_t *radio_mac)
{
	struct node_policy *a = NULL;

	list_for_each_entry(a, &c->cfg.nodelist, list) {
		struct radio_policy *r = NULL;

		list_for_each_entry(r, &a->radiolist, list) {
			if (!memcmp(radio_mac, r->macaddr, 6))
				return r;
		}
	}


	return NULL;
}

#if 0
/* find node by any of its fh-bssid */
struct node *get_node_by_bssid(struct controller *c, unsigned char *bssid)
{
	struct node *n;
	struct netif_iface *p;

	list_for_each_entry(n, &c->nodelist, list) {
		list_for_each_entry(p, &n->iflist, list) {
			if (memcmp(bssid, p->bss->bssid, 6))
				continue;

			return n;
		}
	}

	return NULL;
}
#endif

struct node *cntlr_add_node(struct controller *c, uint8_t *almac)
{
	struct node *n;
	char mac_str[18] = {0};
	int ret;

	if (!hwaddr_ntoa(almac, mac_str))
		return NULL;

	n = cntlr_find_node(c, almac);
	if (!n) {
		n = cntlr_alloc_node(c, almac);
		if (!n) {
			err("|%s:%d| failed to allocate node "MACFMT"\n",
			    __func__, __LINE__, MAC2STR(almac));
			return NULL;
		}
	} else {
		return n;
	}

	ret = cntlr_config_add_node(&c->cfg, mac_str);
	if (!ret) {
		dbg("|%s:%d| resync config\n", __func__, __LINE__);
		cntlr_resync_config(c, true);
	}

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
	if (!hwaddr_equal(c->almac, almac))
		cntlr_sync_dyn_controller_config(c, almac);
#endif

	return n;
}

static void cntlr_log_nodes(struct controller *c)
{
	struct node *n;
	int i = 0;

	list_for_each_entry(n, &c->nodelist, list) {
		cntlr_dbg("  %d | agent = %p,  hwaddr = '"MACFMT"')\n",
				i++, n, MAC2STR(n->alid));
	}
}


#if 0
static int forall_node_update_neighbors(struct controller *c)
{
	return 0;
}
#endif

void cntlr_update_sta_steer_counters(struct controller *c,
				     uint8_t *sta_mac,
				     uint8_t *src_bssid,
				     uint8_t *dst_bssid,
				     uint32_t mode,
				     enum steer_trigger trigger)
{
	trace("%s:--->\n", __func__);

	struct wifi_apsta_steer_history *a;
	struct sta *s = cntlr_find_sta(c, sta_mac);
	struct wifi_multiap_sta *mapsta;

	if (!s) {
		dbg("|%s:%d| Unrecognized STA "MACFMT", skip!\n",
		    __func__, __LINE__, MAC2STR(sta_mac));
		return;
	}

	mapsta = &s->de_sta->mapsta;
	if (mapsta->num_steer_hist >= MAX_STEER_HISTORY) {
		int i;

		for (i = 0; i < MAX_STEER_HISTORY - 1; i++) {
			memcpy(&mapsta->steer_history[i], &mapsta->steer_history[i+1],
					sizeof(struct wifi_apsta_steer_history));
		}
		a = &mapsta->steer_history[MAX_STEER_HISTORY - 1];
	} else {
		a = &mapsta->steer_history[mapsta->num_steer_hist];
	}

	/* Update SteeringHistory */
	timestamp_update(&a->time);

	if (src_bssid)
		memcpy(a->src_bssid, src_bssid, 6);

	if (dst_bssid)
		memcpy(a->dst_bssid, dst_bssid, 6);

	a->trigger = trigger;
	switch (mode) {
	case STEER_MODE_ASSOC_CTL:
		a->method = STEER_METHOD_ASSOC_CTL;
		break;
	case STEER_MODE_BTM_REQ:
		a->method = STEER_METHOD_BTM_REQ;
		/* Update SteeringSummaryStats - per STA & per Network */
		s->de_sta->mapsta.stats.btm_attempt_cnt++;
		c->dlem.network.steer_summary.btm_attempt_cnt++;
		break;
	case STEER_MODE_OPPORTUNITY:
		a->method = STEER_METHOD_ASYNC_BTM;
		/*TODO: add counter for opportunity (incl blacklis count) */
		break;
	default:
		a->method = STEER_METHOD_UNKNOWN;
		break;
	}
	a->duration = 0;

	/* Record tsp for most recent steer attempt */
	timestamp_update(&s->de_sta->mapsta.stats.last_attempt_tsp);
	mapsta->num_steer_hist += 1;
}

#if 0
static int invoke_disconnect_sta(struct node *n, struct netif_iface *p,
		uint8_t *sta_mac)
{
	/* TODO implement */
	return 0;
}
#endif

static int invoke_disconnect_sta_by_bssid(struct controller *c, unsigned char *bssid,
						uint8_t *sta_mac)
{
	/* TODO implement */

	/* The intention of this function is to force disconnect of the STA with given MAC
	 * address by means other than BTM steering. I.e. find out the way to inform agent
	 * on the necessity to deatuthenticate / disassociate the STA connected to one of
	 * its BSSes immediately. This is because association control only disallows new
	 * STAs from connecting to given BSS, but - according to spec - is not meant to
	 * cause disconnection of already connected STA from that BSS (error scenario).
	 */

	return 0;
}

static void cntlr_btm_req_timer_cb(atimer_t *t)
{
	trace("%s:--->\n", __func__);

	struct sta *s = container_of(t, struct sta, btm_req_timer);
	struct node *n = s->fh->agent;
	struct controller *c = n->cntlr;

	if (s->de_sta->mapsta.pending_btm_resp_num > 0) {
		s->de_sta->mapsta.stats.failed_steer_attempts +=
				s->de_sta->mapsta.pending_btm_resp_num;
		s->de_sta->mapsta.stats.btm_failure_cnt +=
				s->de_sta->mapsta.pending_btm_resp_num;
		c->dlem.network.steer_summary.btm_failure_cnt +=
				s->de_sta->mapsta.pending_btm_resp_num;
		s->de_sta->mapsta.pending_btm_resp_num = 0;
	}
}

static int cntlr_steer_sta(struct controller *c, struct sta *s,
			   struct wifi_sta_meas_report *to, uint32_t mode,
			   uint32_t reason)
{
	int ret = 0;
	uint16_t mid;

	trace("%s:--->\n", __func__);

	if (!to || hwaddr_is_zero(to->bssid)) {
		dbg("%s: steer verdict = OK, but target AP = NULL!\n", __func__);
		return 0;
	}

	if (!memcmp(to->bssid, s->bssid, 6)) {
		s->de_sta->mapsta.stats.no_candidate_cnt++;
		c->dlem.network.steer_summary.no_candidate_cnt++;
		dbg("%s: " MACFMT " connected to best AP! No steer needed.\n",
		    __func__, MAC2STR(s->de_sta->macaddr));
		return 0;
	}

	dbg("%s: Try to steer " MACFMT " from " MACFMT " to " MACFMT "\n",
	     __func__, MAC2STR(s->de_sta->macaddr), MAC2STR(s->bssid), MAC2STR(to->bssid));

	UNUSED(reason);

	switch (mode) {
	case STEER_MODE_ASSOC_CTL:
		/* Issue client assoc control */
		invoke_disconnect_sta_by_bssid(c, s->bssid, s->de_sta->macaddr);
		ret = cntlr_send_client_assoc_ctrl_request(c, s->fh->agent->alid,
					s->bssid, 0, 10, /* block bssid for 10 sec */
					1, s->de_sta->macaddr, &mid);
		if (ret) {
			warn("%s: Failed to send cmdu for assoc control!\n", __func__);
			//s->de_sta->mapsta.stats.failed_steer_attempts++;
			return ret;
		}
		/* Keep mid & check assoc control succesful in ACK msg */
		s->latest_assoc_cntrl_mid = mid;
		dbg("%s: cmdu->cdata->hdr.mid %u\n", __func__, mid);
		break;
	case STEER_MODE_BTM_REQ:
	case STEER_MODE_OPPORTUNITY:
		ret = cntlr_send_client_steer_request(c, s->fh->agent->alid,
					s->bssid, 0,
					1, (uint8_t (*)[6])s->de_sta->macaddr,
					1, (uint8_t (*)[6])to->bssid,
					mode);
		if (ret) {
			warn("%s: Failed to send cmdu for steering sta!\n", __func__);
			return ret;
		}

		/* Expect btm-resp from STA forwarded to cntlr */
		s->de_sta->mapsta.pending_btm_resp_num++;
		timer_set(&s->btm_req_timer, BTM_RESP_EXP_TIMEOUT * 1000);

		break;
	case STEER_MODE_UNDEFINED:
	default:
		dbg("%s: steer mode is undefined\n", __func__);
		return 0;
	}

	cntlr_update_sta_steer_counters(c, s->de_sta->macaddr, s->bssid, to->bssid,
				mode, STEER_TRIGGER_LINK_QUALITY);

	return 0;
}

/* returns steer_control_config for current steer_control */
struct steer_control_config *get_steer_control_config(struct controller *c)
{
	struct steer_control_config *e = NULL;
	struct steer_control *sc;

	if (!c)
		return NULL;

	sc = cntlr_get_steer_control(c);

	if (!sc)
		/* steer plugin is not loaded yet */
		return NULL;

	list_for_each_entry(e, &c->cfg.scclist, list) {
		if (!strncmp(e->name, sc->name, 63))
			return e;
	}

	return NULL;
}

static void cntlr_configure_steer(struct controller *c, struct sta *s,
			struct steer_control_config *e)
{
	struct netif_radio *r;
	struct radio_policy *rp = NULL;
	struct steer_config scfg = {};

	r = find_radio_by_bssid(c, s->bssid);
	if (!r)
		return;

	if (!e)
		return;

	/* Ensure band is set in interface data struct */
	s->fh->band = wifi_opclass_get_band(r->radio_el->cur_opclass.opclass[0].id);

	rp = agent_find_radio_policy(c, r->radio_el->macaddr);
	if (!rp)
		return;

	/* RCPI threshold */
	if (rp->rcpi_threshold > 0)
		scfg.rcpi_threshold = rp->rcpi_threshold; /* band dependent */
	else {
		switch (rp->band) {
			case BAND_5:
				scfg.rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_5G;
				break;
			case BAND_6:
				scfg.rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_6G;
				break;
			case BAND_DUAL:
			case BAND_2:
			default:
				scfg.rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_2G;
		}
	}

	scfg.rcpi_hysteresis = 5; /* TODO: unused */

	/* diffsnr */
	if (e->diffsnr > 0)
		scfg.rcpi_diffsnr = e->diffsnr;
	else
		scfg.rcpi_diffsnr = 8; /* default diffsnr */

	/* bandsteer */
	scfg.bandsteer = e->bandsteer;

	/* maximum number of btm tries before assoc control */
	/* TODO: use c->cfg */
	scfg.max_btm_attempt = DEFAULT_MAX_BTM_ATTEMPT;

	cntlr_configure_steer_module(c, &scfg);
}

static void cntlr_try_steer_sta(struct controller *c, struct sta *s)
{
	trace("%s:--->\n", __func__);
	struct steer_sta candidate = {
		.sta = s->de_sta,
		.nbrlist = NULL,
		.meas_reportlist = &s->de_sta->meas_reportlist,
		.best = NULL,
		.band = s->fh->band,
	};
	int ret;

	memcpy(candidate.bssid, s->bssid, 6);

	/* check if sta should be steered */
	ret = cntlr_maybe_steer_sta(c, &candidate);
	if (ret) {
		dbg("cntlr_maybe_steer_sta() ret = %d\n", ret);
		return;
	}

	switch (candidate.verdict) {
	case STEER_VERDICT_OK:
		if (!timestamp_expired(&s->de_sta->mapsta.stats.last_attempt_tsp,
					STEER_ATTEMPT_MIN_ITV)) {
			dbg("%s: last steer attempt < %us ago; skip steering\n",
			    __func__, STEER_ATTEMPT_MIN_ITV / 1000);
			return;
		}
		if (!timestamp_expired(&s->de_sta->mapsta.stats.last_steer_tsp,
					STEER_SUCCESS_MIN_ITV)) {
			dbg("%s: last successful steer < %us ago; skip steering\n",
			    __func__, STEER_SUCCESS_MIN_ITV / 1000);
			return;
		}
		cntlr_steer_sta(c, s, candidate.best, candidate.mode, candidate.reason);
		break;
	case STEER_VERDICT_NOK:
		return;
	case STEER_VERDICT_MAYBE:
		/* TODO: check next steer-control ? */
		break;
	case STEER_VERDICT_EXCLUDE:
		/* STA excluded from subsequent steer attempts */
		dbg("%s: sticky STA excluded from steering, elapsed %us of %us\n", __func__,
		    timestamp_elapsed_sec(&s->de_sta->mapsta.stats.last_attempt_tsp),
		    STEER_ATTEMPT_STICKY_ITV / 1000);
		if (timestamp_expired(&s->de_sta->mapsta.stats.last_attempt_tsp,
					STEER_ATTEMPT_STICKY_ITV))
			/* time up, allow steering again */
			s->de_sta->mapsta.stats.failed_steer_attempts = 0;

		/* TODO: consider update of BTM steering disallowed STA list in agent */
		break;
	default:
		break;
	}

}

static void cntlr_bcn_metrics_parse(atimer_t *t)
{
	trace("%s:--->\n", __func__);

	struct sta *s = container_of(t, struct sta, bcn_metrics_timer);
	struct node *n = s->fh->agent;
	struct controller *c = n->cntlr;
	struct netif_iface *bss = NULL;
	struct wifi_sta_meas_report *b = NULL, *tmp;
	struct steer_control_config *scc;

	dbg("%s: STA " MACFMT" connected to " MACFMT " in Node " MACFMT"\n",
	    __func__, MAC2STR(s->de_sta->macaddr), MAC2STR(s->bssid), MAC2STR(n->alid));

	list_for_each_entry_safe(b, tmp, &s->de_sta->meas_reportlist, list) {
		dbg("bcn-report from " MACFMT "\n", MAC2STR(b->bssid));

		/* Skip entry not in our network */
		bss = cntlr_iterate_fbss(c, b->bssid);
		if (!bss) {
			list_del(&b->list);
			free(b);
			s->de_sta->num_meas_reports--;
			dbg("Delete alien entry "MACFMT"\n", MAC2STR(b->bssid));
		}
	}

	scc = get_steer_control_config(c);
	if (!scc)
		return;

	if (scc->enable_sta_steer) {
		/* configure individually for each STA */
		cntlr_configure_steer(c, s, scc);
		cntlr_try_steer_sta(c, s);
	}

	dbg("%s exiting\n", __func__);
}

/* TODO: deprecate after assoc control steering added */
static void cntlr_init_sta_steer_counters(struct sta *s)
{
	if (!s || !s->de_sta)
		return;

	s->de_sta->mapsta.stats = (struct wifi_steer_summary){0};

	/* TODO: implement stats marked as NO_DATA */
	s->de_sta->mapsta.stats.blacklist_attempt_cnt = STEER_STATS_NO_DATA;
	s->de_sta->mapsta.stats.blacklist_success_cnt = STEER_STATS_NO_DATA;
	s->de_sta->mapsta.stats.blacklist_failure_cnt = STEER_STATS_NO_DATA;
}

struct wifi_sta_element *cntlr_wifi_alloc_sta(struct controller *c,
		uint8_t *macaddr)
{
	struct wifi_sta_element *wse = NULL;

	wse = calloc(1, sizeof(struct wifi_sta_element));
	if (!wse)
		return NULL;

	INIT_LIST_HEAD(&wse->meas_reportlist);
	wse->num_meas_reports = 0;
	memcpy(wse->macaddr, macaddr, 6);
	wse->mapsta.pending_btm_resp_num = 0;

	return wse;
}

struct sta *cntlr_add_sta(struct controller *c, uint8_t *macaddr)
{
	struct sta *s;

	s = cntlr_find_sta(c, macaddr);
	if (s)
		return s;

	s = calloc(1, sizeof(struct sta));
	if (!s)
		return NULL;

	INIT_LIST_HEAD(&s->unassoclist);
	list_add(&s->list, &c->stalist);
	timer_init(&s->bcn_metrics_timer, cntlr_bcn_metrics_parse);
	timer_init(&s->btm_req_timer, cntlr_btm_req_timer_cb);

	s->de_sta = cntlr_wifi_alloc_sta(c, macaddr);
	if (!s->de_sta) {
		free(s);
		return NULL;
	}

	allmac_insert(&c->mac_table, macaddr, MAC_ENTRY_BSTA, (void *)s);

	cntlr_init_sta_steer_counters(s);

	return s;
}

static void forall_node_get_sta_metrics(struct controller *c)
{
	struct sta *s = NULL;

	list_for_each_entry(s, &c->stalist, list) {
		struct cmdu_buff *cmdu;

		cmdu = cntlr_gen_sta_metric_query(c, s->fh->agent->alid, s->de_sta->macaddr);
		if (!cmdu)
			continue;

		send_cmdu(c, cmdu);
		cmdu_free(cmdu);
	}
}

struct wifi_bss_element *cntlr_wifi_bss(struct controller *c,
					      uint8_t *hwaddr)
{
	struct wifi_bss_element *bss = NULL;

	bss = calloc(1, sizeof(struct wifi_bss_element));
	if (!bss)
		return NULL;

	//INIT_LIST_HEAD(&bss->stalist);
	memcpy(bss->bssid, hwaddr, 6);

	return bss;
}

struct netif_iface *cntlr_radio_add_interface(struct controller *c,
					      struct netif_radio *r,
					      uint8_t *hwaddr)
{
	struct netif_iface *n;

	n = find_interface_by_mac(c, r, hwaddr);
	if (n) {
		n->bss->enabled = true;
		return n;
	}

	n = calloc(1, sizeof(*n));
	if (!n)
		return NULL;

	n->bss = cntlr_wifi_bss(c, hwaddr);
	if (!n->bss) {
		free(n);
		return NULL;
	}

	n->band = wifi_opclass_get_band(r->radio_el->cur_opclass.opclass[0].id);
	n->bss->is_fbss = true;
	n->bss->is_bbss = false;
	n->bss->enabled = true;
	list_add(&n->list, &r->iflist);
	n->agent = r->agent;

	allmac_insert(&c->mac_table, hwaddr, MAC_ENTRY_FBSS, (void *)n);

	return n;
}

static struct wifi_radio_element *cntlr_create_wifi_radio(struct controller *c)
{
	struct wifi_radio_element *radio_el = NULL;

	radio_el = calloc(1, sizeof(struct wifi_radio_element));
	if (!radio_el)
		return NULL;

	INIT_LIST_HEAD(&radio_el->scanlist);

	return radio_el;
}

struct netif_radio *cntlr_node_add_radio(struct controller *c, struct node *n,
		uint8_t *radio)
{
	struct netif_radio *r;

	r = find_radio_by_node(c, n, radio);
	// trace("-------------------> %s : raadio added "MACFMT"\n", MAC2STR(r->hwaddr));
	if (r)
		return r;

	r = calloc(1, sizeof(*r));
	if (!r)
		return NULL;

	INIT_LIST_HEAD(&r->iflist);
	list_add(&r->list, &n->radiolist);
	r->agent = n;
	r->radio_el = cntlr_create_wifi_radio(c);
	if (!r->radio_el) {
		free(r);
		return NULL;
	}
	memcpy(r->radio_el->macaddr, radio, 6);

	allmac_insert(&c->mac_table, radio, MAC_ENTRY_RADIO, (void *)r);

	return r;
}

uint8_t cntlr_get_classid_ht20(struct wifi_radio_element *radio, uint8_t channel)
{
	return wifi_opclass_get_id(&radio->pref_opclass, channel, 20);
}

void cntlr_radio_pref_opclass_reset(struct wifi_radio_element *radio)
{
	/*
	 * Build initial preferred opclasses from supported opclasses
	 * we receive in basic radio capabilities.
	 */
	memcpy(&radio->pref_opclass, &radio->supp_opclass, sizeof(radio->pref_opclass));
	wifi_opclass_set_preferences(&radio->pref_opclass, 15 << 4);
}

int cntlr_radio_pref_opclass_add(struct wifi_radio_element *radio, uint8_t classid,
				 uint8_t channel, uint8_t preference)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel chan = {};
	struct wifi_radio_opclass *opclass;

	opclass = &radio->pref_opclass;

	entry = wifi_opclass_find_entry(opclass, classid);
	if (!entry)
		return -1;

	entry->id = classid;
	entry->bandwidth = wifi_opclass_get_bw(classid);

	chan.channel = channel;
	chan.preference = preference;

	timestamp_update(&opclass->entry_time);
	return wifi_opclass_add_channel(entry, &chan);
}

void cntlr_radio_pref_opclass_dump(struct wifi_radio_element *radio)
{
	wifi_opclass_dump(&radio->pref_opclass);
}

void cntlr_radio_cur_opclass_reset(struct wifi_radio_element *radio)
{
	wifi_opclass_reset(&radio->cur_opclass);
}

int cntlr_radio_cur_opclass_add(struct wifi_radio_element *radio, uint8_t classid,
				uint8_t channel, uint8_t txpower)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass_channel chan = {};

	entry = wifi_opclass_find_entry(&radio->cur_opclass, classid);
	if (!entry)
		entry = wifi_opclass_new_entry(&radio->cur_opclass);
	if (!entry)
		return -1;

	entry->id = classid;
	entry->bandwidth = wifi_opclass_get_bw(classid);
	entry->max_txpower = txpower;

	chan.channel = channel;
	chan.preference = 15 << 4;

	timestamp_update(&radio->cur_opclass.entry_time);
	return wifi_opclass_add_channel(entry, &chan);
}

void cntlr_radio_pref_opclass_set_pref(struct wifi_radio_element *radio, uint8_t id, uint8_t preference)
{
	wifi_opclass_id_set_preferences(&radio->pref_opclass, id, preference);
}

void cntlr_radio_cur_opclass_dump(struct wifi_radio_element *radio)
{
	wifi_opclass_dump(&radio->cur_opclass);
}

static bool cntlr_radio_pref_opclass_expired(struct wifi_radio_element *radio)
{
	return wifi_opclass_expired(&radio->pref_opclass, 120);
}

bool cntlr_node_pref_opclass_expired(struct node *node)
{
	struct netif_radio *r= NULL;
	bool expired = false;

	list_for_each_entry(r, &node->radiolist, list) {
		expired |= cntlr_radio_pref_opclass_expired(r->radio_el);
	}

	return expired;
}

#if 0
static enum wifi_band cntlr_radio_opclass_get_band(struct opclass *opclass)
{
	enum wifi_band band;
	enum wifi_band ret = 0;
	int i;

	for (i = 0; i < opclass->opclass_entry_num; i++) {
		band = get_op_class_band(opclass->opclass_entry[i].opclass);
		if (band == BAND_UNKNOWN)
			continue;
		ret |= band;
	}

	return ret;
}
#endif

struct node *cntlr_alloc_node(struct controller *c, uint8_t *almac)
{
	struct node *n;
	struct cmdu_buff *cmdu;

	n = calloc(1, sizeof(struct node));
	if (!n) {
		warn("OOM: node malloc failed!\n");
		return NULL;
	}

	n->cntlr = c;
	n->depth = -1;
	n->scan_supported = true;
	n->np = NULL; //c->cfg.apolicy;
	memcpy(n->alid, almac, 6);
	n->map_profile = MULTIAP_PROFILE_1;

	//INIT_LIST_HEAD(&n->stalist);
	INIT_LIST_HEAD(&n->radiolist);
	list_add(&n->list, &c->nodelist);
	c->num_nodes++;

	allmac_insert(&c->mac_table, almac, MAC_ENTRY_ALID, (void *)n);

	dbg("%s %d --------- " MACFMT "\n", __func__, __LINE__, MAC2STR(almac));


	cmdu = cntlr_gen_bk_caps_query(c, n->alid);
	if (!cmdu)
		return n;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	cmdu = cntlr_gen_ap_capability_query(c, n->alid);
	if (!cmdu)
		return n;

	send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	return n;
}

void cntlr_clean_stalist(struct controller *c)
{
	struct sta *s = NULL, *tmp;

	list_for_each_entry_safe(s, tmp, &c->stalist, list) {
		/* FIXME: del s->de_sta->list */
		free_bcn_metrics(c, s);
		free(s->de_sta);
		list_del(&s->list);
		free(s);
	}
}

void cntlr_clean_bcnreqlist(struct controller *c)
{
	struct bcnreq *b = NULL, *tmp;

	list_for_each_entry_safe(b, tmp, &c->bcnreqlist, list) {
		list_del(&b->list);
		free(b);
	}
}

void cntlr_clean_linklist(struct controller *c)
{
        struct netif_link *l = NULL, *tmp;

        list_for_each_entry_safe(l, tmp, &c->linklist, list) {
		free(l->metrics);
                list_del(&l->list);
                free(l);
        }
}

static void radio_clean_iflist(struct netif_radio *r)
{
	struct netif_iface *ni = NULL, *tmp;

	list_for_each_entry_safe(ni, tmp, &r->iflist, list) {
		free(ni->bss);
		list_del(&ni->list);
		free(ni);
	}
}

int cntlr_radio_clean_scanlist_el(struct wifi_scanres_element *el)
{
	struct wifi_scanres_opclass_element *op = NULL, *otmp;
	struct wifi_scanres_channel_element *ch = NULL, *ctmp;
	struct wifi_scanres_neighbor_element *nbr = NULL, *ntmp;

	if (!el)
		return -1; /* error condition */

	list_for_each_entry_safe(op, otmp, &el->opclass_scanlist, list) {
		list_for_each_entry_safe(ch, ctmp, &op->channel_scanlist, list) {
			list_for_each_entry_safe(nbr, ntmp, &ch->nbrlist, list) {
				list_del(&nbr->list);
				free(nbr);
			}
			list_del(&ch->list);
			free(ch);
		}
		list_del(&op->list);
		free(op);
	}

	list_del(&el->list);
	free(el);

	return 0;
}

static void radio_clean_radio_el(struct netif_radio *r)
{
	struct wifi_scanres_element *b = NULL, *tmp;

	list_for_each_entry_safe(b, tmp, &r->radio_el->scanlist, list) {
		cntlr_radio_clean_scanlist_el(b);
	}
	free(r->radio_el);
}

static void node_clean_radiolist(struct node *n)
{
	struct netif_radio *r = NULL, *tmp;

	list_for_each_entry_safe(r, tmp, &n->radiolist, list) {
		radio_clean_radio_el(r);
		list_del(&r->list);
		radio_clean_iflist(r);
		free(r);
	}
}

static void cntlr_clean_mac_hashtable(struct controller *c)
{
	allmac_clean_table(&c->mac_table);
}

static void cntlr_clean_nodelist(struct controller *c)
{
	struct node *n = NULL, *tmp;

	list_for_each_entry_safe(n, tmp, &c->nodelist, list) {
		node_clean_radiolist(n);
		list_del(&n->list);
		free(n);
	}
}

void free_bcn_metrics(struct controller *c, struct sta *s)
{
	struct wifi_sta_meas_report *b = NULL, *tmp;

	list_for_each_entry_safe(b, tmp, &s->de_sta->meas_reportlist, list) {
		list_del(&b->list);
		free(b);
		s->de_sta->num_meas_reports--;
	}
}

void cntlr_mark_old_bcn_metrics(struct controller *c, struct sta *s)
{
	struct wifi_sta_meas_report *b = NULL, *tmp;

	list_for_each_entry_safe(b, tmp, &s->de_sta->meas_reportlist, list) {
		/* TODO: only most recent measurement marked as fresh */
		b->stale = true;
	}
}

void free_usta_metrics(struct controller *c, struct sta *s)
{
	struct una_sta_metrics *u = NULL, *tmp;

	list_for_each_entry_safe(u, tmp, &s->unassoclist, list) {
		list_del(&u->list);
		free(u);
	}
}

struct netif_link *alloc_link_init(struct controller *c,
		uint8_t *upstream, uint8_t *downstream)
{
	struct netif_link *l;

	l = find_link_by_mac(c, upstream, downstream);
	if (l)
		return l;

	l = calloc(1, sizeof(struct netif_link));
	if (!l)
		return NULL;

	l->metrics = calloc(1, sizeof(struct link_metrics));
	if (!l->metrics)
		goto out;

	l->upstream = find_interface_by_mac_nor(c, upstream);
	if (!l->upstream)
		goto out_metrics;

	l->downstream = find_interface_by_mac_nor(c, downstream);
	if (!l->downstream)
		goto out_metrics;

	trace("Adding link | " MACFMT " <---> " MACFMT " |\n",
		  MAC2STR(l->upstream->bss->bssid),
		  MAC2STR(l->downstream->bss->bssid));
	list_add(&l->list, &c->linklist);

	return l;

out_metrics:
	free(l->metrics);
out:
	free(l);
	return NULL;
}

void free_watchnode_cleanup(struct controller *c, struct watchnode *wn)
{
	timer_del(&wn->scan_timer);
	timer_del(&wn->scanres_timer);
	list_del(&wn->list);
	free(wn);
}

static void cntlr_radar_exit(atimer_t *t)
{
	/*TODO: before change channel due to radar, save old chandef.
	 * Restore that chandef upon exit from radar nop.
	 */
}

static void cntlr_ieee1905_cmdu_event_handler(void *cntlr,
		struct blob_attr *msg)
{
	static const struct blobmsg_policy cmdu_attrs[6] = {
		[0] = { .name = "type", .type = BLOBMSG_TYPE_INT16 },
		[1] = { .name = "mid", .type = BLOBMSG_TYPE_INT16 },
		[2] = { .name = "ifname", .type = BLOBMSG_TYPE_STRING },
		[3] = { .name = "source", .type = BLOBMSG_TYPE_STRING },
		[4] = { .name = "origin", .type = BLOBMSG_TYPE_STRING },
		[5] = { .name = "cmdu", .type = BLOBMSG_TYPE_STRING },
	};
	struct controller *c = (struct controller *)cntlr;
	char in_ifname[16] = {0};
	struct blob_attr *tb[6];
	char src[18] = { 0 }, src_origin[18] = { 0 };
	uint8_t *tlv = NULL;
	char *tlvstr = NULL;
	uint16_t type;
	uint8_t srcmac[6], origin[6];
	uint16_t mid = 0;
	int len = 0;
	sigset_t waiting_mask;

	sigpending(&waiting_mask);
	if (sigismember(&waiting_mask, SIGINT) ||
			sigismember(&waiting_mask, SIGTERM))
		return;

	blobmsg_parse(cmdu_attrs, 6, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	if (tb[0]) {
		int t;

		t = blobmsg_get_u16(tb[0]);
		if (t < 0)
			return;

		type = (uint16_t)t;
		if (!is_cmdu_for_us(c, type))
			return;
	}

	if (tb[1])
		mid = (uint16_t)blobmsg_get_u16(tb[1]);


	if (tb[2])
		strncpy(in_ifname, blobmsg_data(tb[2]), 15);

	if (tb[3]) {
		strncpy(src, blobmsg_data(tb[3]), 17);
		hwaddr_aton(src, srcmac);
	}

	if (tb[4]) {
		strncpy(src_origin, blobmsg_data(tb[4]), 17);
		hwaddr_aton(src_origin, origin);
	}


	if (tb[5]) {
		len = blobmsg_data_len(tb[5]) - 16;

		tlvstr = calloc(1, len + 1);

		if (!tlvstr)
			return;

		strncpy(tlvstr, (blobmsg_data(tb[5]) + 16), len);
		len = (len - 1) / 2;
		tlv = calloc(1, len);
		if (!tlv) {
			free(tlvstr);
			return;
		}

		strtob(tlvstr, len, tlv);
		free(tlvstr);
	}
	cntlr_handle_map_event(c, type, mid, in_ifname, srcmac, origin, tlv, len);

	if (tlv)
		free(tlv);
}

static void cntlr_query_nodes(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, query_nodes);
	struct node *n;

	list_for_each_entry(n, &c->nodelist, list) {
		struct cmdu_buff *cmdu;

		cmdu = cntlr_gen_bk_caps_query(c, n->alid);
		if (cmdu) {
			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
		}

		cmdu = cntlr_gen_ap_capability_query(c, n->alid);
		if (cmdu) {
			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
		}

		cmdu = cntlr_gen_topology_query(c, n->alid);
		if (cmdu) {
			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
		}
	}

	timer_set(&c->query_nodes, 60 * 1000);
}

bool cntlr_check_config_diff(struct controller *c, uint8_t diff)
{
	bool reloaded = false;

	if (diff & CONFIG_DIFF_CREDENTIALS || diff & CONFIG_DIFF_VLAN) {
		struct cmdu_buff *cmdu;
		uint8_t origin[6] = {0x01, 0x80, 0xc2, 0x00, 0x00, 0x13};

		trace("Config changed, triggering renew!\n");
		cmdu = cntlr_gen_ap_autoconfig_renew(c, origin);
		if (cmdu) {
			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
			reloaded = true;
		}
	} else if (diff & (CONFIG_DIFF_AGENT_POLICY | CONFIG_DIFF_AGENT_POLICY_CNT)) {
		struct node_policy *p;
		struct node *n = NULL;


		/* TODO/CLEANUP:
		 * as of now, no information is being stored about
		 * the specific agent's radios & BSS,
		 * Also few information i.e. exclude stalist,
		 * rcpi/util threshold is sent along with
		 * 17.2.11 & 17.2.12 tlv.
		 * So for now, dummy radio id & bss id is being used for this
		 * purpose.
		 * ((later on radio id & bss id info for specific agent
		 * will be stored using in Topology Response CMDU.))
		 */

		trace("agent policy config changed\n");

		/* send the policy config cmdu to the marked agent */
		list_for_each_entry(n, &c->nodelist, list) {
			struct cmdu_buff *cmdu;
			int num_bk = 1;
			uint8_t bk_id[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};
			struct radio_policy *rp = NULL;
			uint8_t radio_id[MAX_NUM_RADIO * 6] = {0};
			int num_radio = 0;

			if ((diff & CONFIG_DIFF_AGENT_POLICY) && !n->np->is_policy_diff)
				continue;

			list_for_each_entry(rp, &n->np->radiolist, list) {
				memcpy(&radio_id[num_radio * 6],
					rp->macaddr,
					6);
				num_radio++;
			}

			cmdu = cntlr_gen_policy_config_req(c, n->alid,
					n->np, num_radio, radio_id, num_bk,
					bk_id);
			if (cmdu) {
				send_cmdu(c, cmdu);
				cmdu_free(cmdu);
				reloaded = true;
			}
		}

		/* reset is_policy_diff to false; */
		list_for_each_entry(p, &c->cfg.nodelist, list) {
			p->is_policy_diff = false;
		}
	}

	return reloaded;
}

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
int cntlr_sync_dyn_controller_config(struct controller *c, uint8_t *agent)
{
	struct node *n;
	uint8_t proto = 0xab;
	struct cmdu_buff *cmdu;

	if (agent && !hwaddr_is_zero(agent)) {
		cmdu = cntlr_gen_higher_layer_data(c, agent, proto, NULL, 0);
		if (!cmdu)
			return -1;

		send_cmdu(c, cmdu);
		cmdu_free(cmdu);
	} else {
		list_for_each_entry(n, &c->nodelist, list) {
			if (hwaddr_equal(c->almac, n->alid))
				continue; /* skip locally running agent */

			cmdu = cntlr_gen_higher_layer_data(c, n->alid, proto, NULL, 0);
			if (!cmdu)
				return -1;

			send_cmdu(c, cmdu);
			cmdu_free(cmdu);
		}
	}

	return 0;
}
#endif

bool cntlr_resync_config(struct controller *c, bool reload)
{
	uint8_t diff;
	struct node_policy *np = NULL;

	diff = cntlr_config_reload(&c->cfg);

	list_for_each_entry(np, &c->cfg.nodelist, list) {
		struct node *n;

		n = cntlr_find_node(c, np->agent_id);
		if (n)
			n->np = np;
	}

	if (reload)
		cntlr_check_config_diff(c, diff);

#ifdef CONTROLLER_SYNC_DYNAMIC_CNTLR_CONFIG
	/* in dyn-controller mode, sync controller's config in network */
	if (diff)
		cntlr_sync_dyn_controller_config(c, NULL);
#endif

	return !!diff;
}

static void cntlr_signal_periodic_run(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, signal_handler);
	sigset_t waiting_mask;

	sigpending(&waiting_mask);

	if (sigismember(&waiting_mask, SIGHUP)) {
		dbg("|%s:%d| Received SIGHUP, reload config\n", __func__, __LINE__);
		signal(SIGHUP, SIG_IGN);

		cntlr_resync_config(c, true);
	}

	timer_set(&c->signal_handler, 1 * 1000);
}


static void combined_link_metric_periodic_collection(struct controller *c)
{
	trace("%s: --->\n", __func__);
	struct cmdu_buff *cmdu;
	struct node *p;
	struct netif_radio *r;
	struct netif_iface *bss;
	uint8_t *bsslist = NULL, *new_bsslist = NULL;
	uint8_t *radiolist = NULL, *new_radiolist = NULL;
	int num_bss, num_radio;
	int radio_index, bss_index;
	uint8_t hwaddr[6];

	/* AP metrics query for each agent */
	/* For each agent */
	list_for_each_entry(p, &c->nodelist, list) {
		num_radio = 0;
		num_bss = 0;
		memcpy(hwaddr, p->alid, 6);
		/* For each radio */
		list_for_each_entry(r, &p->radiolist, list) {
			/* Building a radiolist of all radios */
			new_radiolist = (uint8_t *)realloc(radiolist,
							6 * (num_radio + 1) * sizeof(uint8_t));

			if (!new_radiolist) {
				trace("realloc of radiolist failed\n");
				goto error;
			}

			radiolist = new_radiolist;
			num_radio++;
			radio_index = (num_radio - 1) * 6;
			memcpy(radiolist + radio_index, r->radio_el->macaddr, 6);

			/* For each bss in radio */
			list_for_each_entry(bss, &r->iflist, list) {
				if (!bss->bss->is_fbss && !bss->bss->is_bbss)
					/* if bss is a bsta */
					continue;

				/* Building a bsslist of all BSS */
				new_bsslist = (uint8_t *)realloc(bsslist,
							6 * (num_bss + 1) * sizeof(uint8_t));

				if (!new_bsslist) {
					trace("realloc of bsslist failed\n");
					goto error;
				}

				bsslist = new_bsslist;
				num_bss++;
				bss_index = (num_bss - 1) * 6;
				memcpy(bsslist + bss_index, bss->bss->bssid, 6);
			}
		}
		cmdu = cntlr_gen_ap_metrics_query(c, hwaddr, num_bss, bsslist, num_radio, radiolist);
		if (!cmdu) {
			trace("cmdu_gen failed!\n");
			goto error;
		}

		send_cmdu(c, cmdu);

		/* 1905 Link metric query */
		ieee1905_buildcmdu_linkmetric_resp(c, CMDU_TYPE_LINK_METRIC_RESPONSE);	//FIXME: why here?
		cmdu_free(cmdu);
	}
error:
	if (radiolist)
		free(radiolist);
	if (bsslist)
		free(bsslist);
}

static void cntlr_periodic_run(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, heartbeat);

	cntlr_log_nodes(c);

	//forall_node_get_fhinfo(c);   /* replaced from per-node refresh bss */

	forall_node_get_sta_metrics(c);

	/* TODO: */
	//forall_node_get_usta_metrics(c);

	/* TODO: update only when a node is added or removed */
	//forall_node_update_neighbors(c);

	/* Call AP metrics query and 1905 link metrics query for data collection */
	combined_link_metric_periodic_collection(c);

	timer_set(&c->heartbeat, 10 * 1000);
}

static void cntlr_acs_run(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, acs);
	bool skip_dfs = false;

	/* Run ACS recalc here */
	dbg("acs timeout - run recalc\n");
	cntlr_acs_recalc(c, skip_dfs);

	if (c->cfg.acs_timeout)
		timer_set(&c->acs, c->cfg.acs_timeout * 1000);
}

static void cntlr_dfs_cleanup_run(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, dfs_cleanup);

	/* Run background CAC here */
	dbg("dfs bgcac timeout - run cleanup\n");
	cntlr_dfs_cleanup(c);

	if (c->cfg.dfs_cleanup_timeout)
		timer_set(&c->dfs_cleanup, c->cfg.dfs_cleanup_timeout * 1000);
}

static void cntlr_start(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, start_timer);

	if (c->state == CNTLR_INIT) {
		c->state = CNTLR_START;
		cntlr_publish_object(c, "map.controller");
		cntlr_publish_dbg_object(c, "map.controller.dbg");
	}
}

static void cntlr_discovery(atimer_t *t)
{
	struct controller *c = container_of(t, struct controller, discovery_timer);
	struct cmdu_buff *cmdu;

	cmdu = cntlr_gen_ap_autoconfig_search(c, 0x02, 0x00);
	if (!cmdu)
		return;

	c->mid_2g = send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	cmdu = cntlr_gen_ap_autoconfig_search(c, 0x02, 0x01);
	if (!cmdu)
		return;

	c->mid_5g = send_cmdu(c, cmdu);
	cmdu_free(cmdu);

	timer_set(t, 180 * 1000);
}

int cntlr_map_sub_cb(void *bus, void *priv, void *data)
{
	struct blob_attr *msg = (struct blob_attr *)data;
	char *str;


	str = blobmsg_format_json(msg, true);
	trace("Received notification '%s'\n", str);
	free(str);

	cntlr_ieee1905_cmdu_event_handler(priv, msg);

	return 0;
}

int cntlr_map_del_cb(void *bus, void *priv, void *data)
{
	struct controller *c = (struct controller *)priv;
	uint32_t *obj = (uint32_t *)data;

	c->subscribed = false;
	fprintf(stdout, "Object 0x%x no longer present\n", *obj);

	return 0;
}

static int controller_subscribe_for_cmdus(struct controller *c)
{
	mapmodule_cmdu_mask_t cmdu_mask = {0};
	uint32_t map_id;
	int ret;


	map_prepare_cmdu_mask(cmdu_mask,
			CMDU_TYPE_TOPOLOGY_DISCOVERY,
			CMDU_TYPE_TOPOLOGY_NOTIFICATION,
			CMDU_TYPE_TOPOLOGY_QUERY,
			CMDU_TYPE_TOPOLOGY_RESPONSE,
			CMDU_TYPE_VENDOR_SPECIFIC,
			CMDU_TYPE_AP_AUTOCONFIGURATION_SEARCH,
			CMDU_TYPE_AP_AUTOCONFIGURATION_RESPONSE,
			CMDU_TYPE_AP_AUTOCONFIGURATION_WSC,
			CMDU_1905_ACK,
			CMDU_BEACON_METRICS_RESPONSE,
			CMDU_AP_METRICS_RESPONSE,
			CMDU_ASSOC_STA_LINK_METRICS_RESPONSE,
			CMDU_UNASSOC_STA_LINK_METRIC_RESPONSE,
			CMDU_CHANNEL_SCAN_REQUEST,
			CMDU_CHANNEL_SCAN_REPORT,
			CMDU_CLIENT_DISASSOCIATION_STATS,
			CMDU_ASSOCIATION_STATUS_NOTIFICATION,
			CMDU_BACKHAUL_STA_CAPABILITY_QUERY,
			CMDU_BACKHAUL_STA_CAPABILITY_REPORT,
			CMDU_CHANNEL_PREFERENCE_REPORT,
			CMDU_CLIENT_STEERING_BTM_REPORT,
			CMDU_STEERING_COMPLETED,
			CMDU_CHANNEL_SELECTION_RESPONSE,
			CMDU_OPERATING_CHANNEL_REPORT,
			CMDU_AP_CAPABILITY_QUERY,
			CMDU_AP_CAPABILITY_REPORT,
			CMDU_CLIENT_CAPABILITY_REPORT,
			CMDU_HIGHER_LAYER_DATA,
#if (EASYMESH_VERSION > 2)
			CMDU_PROXIED_ENCAP_DPP,
			CMDU_DIRECT_ENCAP_DPP,
			CMDU_BSS_CONFIG_REQUEST,
			CMDU_BSS_CONFIG_RESULT,
			CMDU_DPP_BOOTSTRAPING_URI,
#endif
			-1);
	memcpy(c->cmdu_mask, cmdu_mask, sizeof(c->cmdu_mask));

	trace("%s: wait for map-plugin\n", __func__);
	cntlr_wait_for_object_timeout(c, map_plugin, -1, &map_id);
	c->map_oid = map_id;

	/* register as client to the map module */
	ret = map_subscribe(c->ubus_ctx,
			    &c->map_oid,
			    "mapcontroller", &cmdu_mask, c,
			    cntlr_map_sub_cb,
			    cntlr_map_del_cb,
			    &c->subscriber);
	if (!ret) {
		c->subscribed = true;
	} else {
		trace("Failed to 'register' with %s (err = %s)\n",
		      map_plugin, ubus_strerror(ret));
	}

	return ret;
}

static int cntlr_ackq_timeout_cb(struct cmdu_ackq *q, struct cmdu_ackq_entry *e)
{
	struct controller *a = container_of(q, struct controller, cmdu_ack_q);
	struct cmdu_buff *cmdu = (struct cmdu_buff *) e->cookie;
	int ret;

	trace("%s: ---> cmdu = %04x to "MACFMT" \n", __func__,
		cmdu_get_type(cmdu), MAC2STR(cmdu->origin));

	if (e->resend_cnt-- > 0) {
		ret = send_cmdu_ubus(a, cmdu);
		if (ret < 0)
			err("%s fail to send cmdu\n", __func__);

		return CMDU_ACKQ_TMO_REARM;
	}

	return CMDU_ACKQ_TMO_DELETE;
}

static void cntlr_ackq_delete_cb(struct cmdu_ackq *q, struct cmdu_ackq_entry *e)
{
	struct cmdu_buff *cmdu = (struct cmdu_buff *) e->cookie;

	trace("%s: ---> cmdu = %04x to "MACFMT" \n", __func__,
		cmdu_get_type(cmdu), MAC2STR(cmdu->origin));

	cmdu_free(cmdu);
}

static void uobj_add_event_handler(void *cntlr, struct blob_attr *msg)
{
	char path[32] = {0};
	uint32_t id = 0;
	struct controller *c = (struct controller *) cntlr;
	struct blob_attr *tb[2];
	static const struct blobmsg_policy ev_attr[2] = {
		[0] = { .name = "id", .type = BLOBMSG_TYPE_INT32 },
		[1] = { .name = "path", .type = BLOBMSG_TYPE_STRING }
	};

	blobmsg_parse(ev_attr, 2, tb, blob_data(msg), blob_len(msg));

	if (!tb[0] || !tb[1])
		return;

	strncpy(path, blobmsg_data(tb[1]), sizeof(path) - 1);
	id = (uint32_t) blobmsg_get_u32(tb[0]);
	dbg("|%s:%d| path = [%s] id = [%d] [%u]\n", __func__, __LINE__, path,
			id, id);
	if (!strncmp(path, map_plugin, strlen(map_plugin))) {
		/* TODO: how to handle failure? */
		controller_subscribe_for_cmdus(c);
	}
}


static void cntlr_event_handler(struct ubus_context *ctx,
		struct ubus_event_handler *ev,
		const char *type, struct blob_attr *msg)
{
	int i;
	char *str;
	struct controller *c = container_of(ev, struct controller, evh);
	struct wifi_ev_handler {
		const char *ev_type;
		void (*handler)(void *ctx, struct blob_attr *ev_data);
	} evs[] = {
		{ "ubus.object.add", uobj_add_event_handler }
	};

	str = blobmsg_format_json(msg, true);
	if (!str)
		return;

	info("[ &controller = %p ] Received [event = %s]  [val = %s]\n",
			c, type, str);

	for (i = 0; i < ARRAY_SIZE(evs); i++) {
		if (!strcmp(type, evs[i].ev_type))
			evs[i].handler(c, msg);
	}

	free(str);
}


void run_controller(void)
{
	struct controller *c;
	struct ubus_context *ctx;
	/* struct ubus_event_handler *ev; */
	sigset_t base_mask;
	int ret;

	sigemptyset(&base_mask);
	sigaddset(&base_mask, SIGHUP);

	sigprocmask(SIG_SETMASK, &base_mask, NULL);
	set_sighandler(SIGPIPE, SIG_IGN);

	c = calloc(1, sizeof(struct controller));
	if (!c)
		return;

	cntlr_dbg("Starting wifi_cntlr... (&cntlr = %p), build %s %s, cntlr's supported EMP %d\n", c,
			__DATE__, __TIME__, EASYMESH_VERSION);

	uloop_init();
	ctx = ubus_connect(ubus_socket);
	if (!ctx) {
		err("Failed to connect to ubus\n");
		free(c);
		return;
	}
	c->ubus_ctx = ctx;
	INIT_LIST_HEAD(&c->stalist);
	INIT_LIST_HEAD(&c->nodelist);
	INIT_LIST_HEAD(&c->bcnreqlist);
	c->num_nodes = 0;
	INIT_LIST_HEAD(&c->linklist);
	as_init_table(&c->as_table);
	allmac_init_table(&c->mac_table);

	cmdu_ackq_init(&c->cmdu_ack_q);
	c->cmdu_ack_q.timeout_cb = cntlr_ackq_timeout_cb;
	c->cmdu_ack_q.delete_cb = cntlr_ackq_delete_cb;

	ubus_add_uloop(ctx);

	cntlr_config_defaults(c, &c->cfg);

	ret = cntlr_get_ieee1905_almac(c, c->almac);
	if (ret)
		goto out_exit;

	cntlr_resync_config(c, false);

	if (!c->cfg.enabled)
		goto out_exit;

	{
		/* TODO: diff always 1 after first round, will cause failures on
		 * first reload */
		struct node_policy *np;

		list_for_each_entry(np, &c->cfg.nodelist, list) {
			struct node *n;

			np->is_policy_diff = false;
			n = cntlr_alloc_node(c, np->agent_id);
			if (!n)
				goto out_exit;

			n->np = np;

		}
	}


	//cntlr_register_events(c);

	c->state = CNTLR_INIT;
	timer_init(&c->discovery_timer, cntlr_discovery);
	timer_init(&c->start_timer, cntlr_start);
	timer_init(&c->heartbeat, cntlr_periodic_run);
	timer_init(&c->radar_timer, cntlr_radar_exit);
	timer_init(&c->signal_handler, cntlr_signal_periodic_run);
	timer_init(&c->query_nodes, cntlr_query_nodes);
	timer_init(&c->acs, cntlr_acs_run);
	timer_init(&c->dfs_cleanup, cntlr_dfs_cleanup_run);

	timer_set(&c->heartbeat, 5 * 1000);
	timer_set(&c->discovery_timer, 0);
	timer_set(&c->start_timer, waitext ? 5 * 1000 : 0);
	timer_set(&c->signal_handler, 5 * 1000);
	timer_set(&c->query_nodes, 60 * 1000);

	if (c->cfg.acs_timeout)
		timer_set(&c->acs, c->cfg.acs_timeout * 1000);
	if (c->cfg.dfs_cleanup_timeout)
		timer_set(&c->dfs_cleanup, c->cfg.dfs_cleanup_timeout * 1000);

	c->evh.cb = cntlr_event_handler;
	ubus_register_event_handler(ctx, &c->evh, "ubus.object.*");

	controller_subscribe_for_cmdus(c);

	/* steer-control */
	INIT_LIST_HEAD(&c->sclist);
	cntlr_load_steer_modules(c);
	if (!list_empty(&c->sclist))
		cntlr_assign_steer_module_default(c);

	/* The counters in MultiAPSteeringSummaryStats are all reset on reboot. */
	memset(&c->dlem.network.steer_summary, 0, sizeof(struct wifi_steer_summary));
	cntlr_dbg("current wifi_cntlr profile %d\n", c->cfg.map_profile);

	uloop_run();

out_exit:
	cntlr_unload_steer_modules(c);
	map_unsubscribe(ctx, c->subscriber);
	cntlr_clean_mac_hashtable(c);
	cntlr_clean_stalist(c);
	cntlr_clean_bcnreqlist(c);
	cntlr_clean_linklist(c);
	cntlr_clean_nodelist(c);
	ubus_unregister_event_handler(ctx, &c->evh);
	cntlr_remove_object(c);
	cntlr_remove_dbg_object(c);
	cmdu_ackq_free(&c->cmdu_ack_q);
	cntlr_config_clean(&c->cfg);
	uloop_done();
	free(c);
}
