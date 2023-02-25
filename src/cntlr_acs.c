/*
 * cntlr_acs.c - Auto Channel Selection
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 */
#include <stdio.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>
#include <uci.h>

#include <easy/easy.h>
#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <i1905_wsc.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "cntlr.h"
#include "allsta.h"
#include "cntlr_map.h"
#include "cntlr_ubus.h"
#include "cntlr_tlv.h"

#include "cntlr_tlv.h"
#include "cntlr_cmdu.h"
#include "cntlr_acs.h"

int cntlr_acs_radio_channel_recalc(struct wifi_radio_element *radio, struct acs_params *params)
{
	struct acs_params acs_params[64] = {};
	int acs_params_num = 0;
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass *opclass;
	int chan, pref, reas;
	int pref_best = 0;
	int pref_cur = 0;
	int prefered[64] = {0};
	int i, j, r;

	opclass = &radio->pref_opclass;

	dbg("acs radio channel recalc " MACFMT " opclass %d bw %d skip_dfs %d\n",
	    MAC2STR(radio->macaddr),
	    params->opclass, params->bw, params->skip_dfs);

	for (i = 0; i < opclass->num_opclass; i++) {
		entry = &opclass->opclass[i];

		/* First check if opclass set */
		if (params->opclass && params->opclass != entry->id)
			continue;

		/* Next check if bandwidth set */
		if (params->bw && params->bw != entry->bandwidth)
			continue;

		for (j = 0; j < entry->num_channel; j++) {
			chan = entry->channel[j].channel;
			pref = (entry->channel[j].preference & CHANNEL_PREF_MASK) >> 4;
			reas = entry->channel[j].preference & CHANNEL_PREF_REASON;

			trace("\tacs check/cmp chan %d pref %d reas %d\n", chan, pref, reas);

			/* Always skip disabled channels */
			if (reas == CHANNEL_PREF_REASON_DFS_NOP)
				continue;
			if (reas == CHANNEL_PREF_REASON_REG_DISALLOWED)
				continue;

			/* Skip DFS channels if requested */
			if (params->skip_dfs) {
				if (reas == CHANNEL_PREF_REASON_DFS_AVAILABLE ||
				    reas == CHANNEL_PREF_REASON_DFS_USABLE)
					continue;
			}

			/* Skip non available DFS channels if requested */
			if (params->skip_dfs_not_available && reas != CHANNEL_PREF_REASON_DFS_AVAILABLE)
				continue;

			if (WARN_ON(acs_params_num >= ARRAY_SIZE(acs_params)))
				break;

			/* Current channel preference */
			if (chan == params->best_channel)
				pref_cur = pref;

			/* Kick best value */
			if (pref > pref_best)
				pref_best = pref;

			acs_params[acs_params_num].best_channel = chan;
			acs_params[acs_params_num].best_opclass = entry->id;
			acs_params[acs_params_num].best_bw = entry->bandwidth;
			acs_params[acs_params_num].best_pref = pref;

			acs_params_num++;
		}
	}

	if (!pref_best)
		return -1;

	dbg("acs radio " MACFMT " best pref %d vs current pref %d\n",
	    MAC2STR(radio->macaddr), pref_best, pref_cur);

	/* If current channel equal to best don't switch */
	if (pref_cur == pref_best) {
		dbg("acs skip - current channel %d is the best\n", params->best_channel);
		return -1;
	}

	/* Get random channel from best performance */
	for (i = 0, j = 0; i < acs_params_num; i++) {
		if (acs_params[i].best_pref != pref_best)
			continue;

		if (j >= ARRAY_SIZE(prefered) - 1)
			break;

		/* Save index in table */
		prefered[j] = i;
		j++;
	}

	if (WARN_ON(!j))
		return -1;

	srand(time(NULL));
	r = rand() % j;

	dbg("acs radio " MACFMT " table size %d - rand %d, index %d\n",
	    MAC2STR(radio->macaddr), j, r, prefered[r]);

	if (prefered[r] >= acs_params_num)
		return -1;

	params->best_channel = acs_params[prefered[r]].best_channel;
	params->best_bw = acs_params[prefered[r]].best_bw;
	params->best_opclass = acs_params[prefered[r]].best_opclass;

	dbg("acs radio " MACFMT " best chan %d/%d opclass %d\n",
	    MAC2STR(radio->macaddr),
	    params->best_channel, params->best_bw, params->best_opclass);

	return 0;
}

static bool cntlr_acs_radio_is_bsta_connected(struct netif_radio *radio)
{
	struct netif_iface *iface = NULL;

	list_for_each_entry(iface, &radio->iflist, list) {
		/* Check if sta iface connected */
		if (iface->bss->is_bbss || iface->bss->is_fbss)
			continue;

		if (hwaddr_is_zero(iface->upstream_bssid))
			continue;

		return true;
	}

	return false;
}

static int cntlr_get_current_acs_params(struct wifi_radio_element *radio, struct acs_params *params)
{
	memset(params, 0, sizeof(*params));

	if (!radio->cur_opclass.num_opclass)
		return -1;

	params->opclass = radio->cur_opclass.opclass[0].id;
	params->bw = radio->cur_opclass.opclass[0].bandwidth;

	params->best_channel = radio->cur_opclass.opclass[0].channel[0].channel;
	params->best_bw = params->bw;
	params->best_opclass = params->opclass;

	return 0;
}

void cntlr_acs_node_channel_recalc(struct node *node, bool skip_dfs)
{
	struct acs_params cur_acs_params = {};
	struct acs_params acs_params = {};
	struct netif_radio *r = NULL;
	int ret;

	acs_params.skip_dfs = skip_dfs;

	dbg("acs node channel recalc " MACFMT " skip_dfs %d\n",
	    MAC2STR(node->alid), acs_params.skip_dfs);

	list_for_each_entry(r, &node->radiolist, list) {
		WARN_ON(cntlr_get_current_acs_params(r->radio_el, &cur_acs_params));

		/* Use current opclass - TODO: if no opclass check 80/40/20 */
		acs_params.opclass = cur_acs_params.opclass;
		acs_params.best_channel = cur_acs_params.best_channel;

		ret = cntlr_acs_radio_channel_recalc(r->radio_el, &acs_params);
		if (WARN_ON(ret))
			continue;

		dbg("acs node " MACFMT " radio " MACFMT " new %d/%d opclass %d vs old %d/%d opclass %d\n",
		    MAC2STR(node->alid), MAC2STR(r->radio_el->macaddr), acs_params.best_channel,
		    acs_params.best_bw, acs_params.best_opclass, cur_acs_params.best_channel,
		    cur_acs_params.bw, cur_acs_params.opclass);

		if (cntlr_acs_radio_is_bsta_connected(r))
			continue;

		warn("acs switch to best channel %d/%d\n", acs_params.best_channel, acs_params.best_bw);
		ret = cntrl_send_channel_selection(node->cntlr, node->alid,
						   r->radio_el->macaddr,
						   acs_params.best_channel,
						   acs_params.best_opclass,
						   15);

		if (ret)
			warn("acs switch failed\n");
	}
}

void cntlr_acs_recalc(struct controller *c, bool skip_dfs)
{
	struct node *n = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		cntlr_acs_node_channel_recalc(n, skip_dfs);
	}
}

static bool cntlr_dfs_get_usable(struct wifi_radio_opclass_entry *entry, struct cac_data *cac_data)
{
	uint8_t reas;
	int i;

	for (i = 0; i < entry->num_channel; i++) {
		reas = entry->channel[i].preference & CHANNEL_PREF_REASON;

		/* Usable - we can run CAC */
		if (reas == CHANNEL_PREF_REASON_DFS_USABLE) {
			cac_data->channel = entry->channel[i].channel;
			cac_data->opclass = entry->id;
			return true;
		}
	}

	return false;
}

static bool cntrlr_radio_is_ap_iface(struct netif_radio *radio)
{
	struct netif_iface *iface = NULL;

	list_for_each_entry(iface, &radio->iflist, list) {
		/* Check if AP iface connected */
		if (iface->bss->is_fbss)
			return true;
		if (iface->bss->is_bbss)
			return true;
	}

	return false;
}

static bool cntlr_dfs_get_cac_data(struct wifi_radio_element *radio, struct cac_data *cac_data)
{
	struct wifi_radio_opclass_entry *entry;
	struct wifi_radio_opclass *cur_opclass;
	struct wifi_radio_opclass *opclass;
	int i;

	/* TODO check dfs_region early - skip non EU */

	opclass = &radio->pref_opclass;
	cur_opclass = &radio->cur_opclass;

	for (i = 0; i < opclass->num_opclass; i++) {
		entry = &opclass->opclass[i];

		if (entry->bandwidth != cur_opclass->opclass[0].bandwidth)
			continue;

		if (!cntlr_dfs_get_usable(entry, cac_data))
			continue;

		/* TODO check chan/bw - not only control channel */
		if (cac_data->channel == cur_opclass->opclass[0].channel[0].channel)
			continue;

		/* TODO define this in ieee1905 */
		cac_data->cac_method = 2;
		memcpy(cac_data->radio, radio->macaddr, sizeof(cac_data->radio));

		return true;
	}

	return false;
}

void cntlr_dfs_radio_cleanup(struct node *node, struct netif_radio *radio)
{
	struct cac_data cac_data = {};

	dbg("dfs radio preCAC cleanup " MACFMT "\n", MAC2STR(radio->radio_el->macaddr));
	if (!cntrlr_radio_is_ap_iface(radio)) {
		dbg("dfs radio preCAC no AP ifaces, skip radio\n");
		return;
	}

	if (!cntlr_dfs_get_cac_data(radio->radio_el, &cac_data)) {
		dbg("dfs radio preCAC cleanup no channels left\n");
		return;
	}

	dbg("dfs radio preCAC run chan %d opclass %d\n", cac_data.channel, cac_data.opclass);
	WARN_ON(cntlr_send_cac_req(node->cntlr, node->alid, 1, &cac_data));
}

void cntlr_dfs_node_cleanup(struct node *node)
{
	struct netif_radio *radio = NULL;

	dbg("dfs node preCAC cleanup " MACFMT "\n", MAC2STR(node->alid));

	list_for_each_entry(radio, &node->radiolist, list) {
		cntlr_dfs_radio_cleanup(node, radio);
	}
}

void cntlr_dfs_cleanup(struct controller *c)
{
	struct node *n = NULL;

	list_for_each_entry(n, &c->nodelist, list) {
		cntlr_dfs_node_cleanup(n);
	}
}
