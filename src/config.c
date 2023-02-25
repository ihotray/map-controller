/*
 * config.c - controller configuration handling
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#ifndef _GNU_SOURCE
#define _GNU_SOURCE
#endif

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>
#include <wifidefs.h>

#include <bufutil.h>

#include "utils/debug.h"
#include "utils/utils.h"
#include "config.h"
#include "cntlr.h"
#include "config.h"
#include "easymesh.h"

#define list_copy(a, b, type)                                           \
	({                                                              \
		typeof(type *) ____ptr, ____tmp;                        \
		list_for_each_entry_safe(____ptr, ____tmp, a, list) {   \
			list_del(&____ptr->list);                       \
			list_add_tail(&____ptr->list, b);               \
		}                                                       \
	})



#define list_memcmp(a, b, type, offset)                                      \
	({                                                                   \
		int z = 0;                                                   \
		typeof(type *) ____ptr, ____p;                               \
		____p = list_first_entry(a, type, list);                     \
		list_for_each_entry(____ptr, b, list) {                      \
			if (memcmp(____p, ____ptr, sizeof(type) - offset)) { \
				z = 1;                                       \
				break;                                       \
			}                                                    \
			____p = list_entry(____p->list.next, type, list);    \
		}                                                            \
		z;                                                           \
	})



#define list_policy_memcmp(c, d, t, o)                                       \
	({                                                                   \
		int z = 0;                                                   \
		typeof(t *) ____d, ____c;                                    \
		____c = list_first_entry(c, t, list);                        \
		list_for_each_entry(____d, d, list) {                        \
			if (memcmp(____c, ____d, sizeof(t) - o)) {           \
				z = 1;                                       \
				____d->is_policy_diff = 1;                   \
			} else {                                             \
				if (list_memcmp(&____d->radiolist,           \
				    &____c->radiolist, struct radio_policy,  \
				    (sizeof(struct radio_policy) -           \
				    offsetof(struct radio_policy, list)))) { \
					z = 1;                               \
					____d->is_policy_diff = 1;           \
				}                                            \
			}                                                    \
			____c = list_entry(____c->list.next, t, list);       \
		}                                                            \
		z;                                                           \
	})

#define list_for_multiple_entry(pos, pos1, head, head1, field, field1)					\
	for (pos = list_first_entry(head, __typeof__(*pos), field),					\
			pos1 = list_first_entry(head1, __typeof__(*pos1), field1);			\
			(&pos->field != (head)) && (&pos1->field1 != (head1));				\
			pos = list_entry(pos->field.next, __typeof__(*pos), field),			\
			pos1 = list_entry(pos1->field1.next, __typeof__(*pos1), field1))

static int clean_agentlist(struct node_policy *p)
{
	return 0;
}

static int clean_steer_btm_excl(struct node_policy *p)
{
	struct stax *n = NULL, *tmp;

	list_for_each_entry_safe(n, tmp, &p->btmsteer_exlist, list) {
		list_del(&n->list);
		free(n);
	}

	return 0;
}

static int clean_steer_excl(struct node_policy *p)
{
	struct stax *n = NULL, *tmp;

	list_for_each_entry_safe(n, tmp, &p->steer_exlist, list) {
		list_del(&n->list);
		free(n);
	}

	return 0;
}

int clean_radio_list(struct list_head *radiolist)
{
	struct radio_policy *p = NULL, *tmp;

	list_for_each_entry_safe(p, tmp, radiolist, list) {
		list_del(&p->list);
		free(p);
	}

	return 0;
}

int clean_agent_policies(struct controller_config *cfg)
{
	struct node_policy *p = NULL, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->nodelist, list) {
		clean_steer_btm_excl(p);
		clean_steer_excl(p);
		clean_agentlist(p);
		clean_radio_list(&p->radiolist);
		list_del(&p->list);
		free(p);
	}

	return 0;
}

int clean_vendor_ie(struct wsc_vendor_ie *ext)
{
	free(ext->payload);
	return 0;
}

int clean_vendor_ies(struct iface_credential *iface_cred)
{
	int i;

	for (i = 0; i < iface_cred->num_ven_ies; i++)
		clean_vendor_ie(&iface_cred->ven_ies[i]);

	iface_cred->num_ven_ies = 0;

	return 0;
}

int clean_cred_list(struct controller_config *cfg)
{
	struct iface_credential *p = NULL, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->aplist, list) {
		clean_vendor_ies(p);
		list_del(&p->list);
		free(p);
	}

	return 0;
}

int clean_scclist_list(struct controller_config *cfg)
{
	struct steer_control_config *p = NULL, *tmp;

	list_for_each_entry_safe(p, tmp, &cfg->scclist, list) {
		list_del(&p->list);
		free(p);
	}

	return 0;
}

static void stax_add_entry(struct list_head *h, char *sta_macstr)
{
	struct stax *n;

	n = calloc(1, sizeof(struct stax));
	if (n) {
		snprintf(n->macstring, 18, "%s", sta_macstr);
		list_add(&n->list, h);
	}
}

struct uci_package *uci_load_pkg(struct uci_context **ctx, const char *config)
{
	struct uci_package *pkg;

	if (!*ctx) {
		*ctx = uci_alloc_context();
		if (!*ctx)
			return NULL;
	}

	if (uci_load(*ctx, config, &pkg) != UCI_OK) {
		uci_free_context(*ctx);
		*ctx = NULL;
		return NULL;
	}

	return pkg;
}

int set_value(struct uci_context *ctx, struct uci_package *pkg,
		struct uci_section *section, const char *key,
		const char *value, enum uci_option_type type)
{
	struct uci_ptr ptr = {0};

	ptr.p = pkg;
	ptr.s = section;
	ptr.option = key;
	ptr.value = value;

	if (type == UCI_TYPE_STRING)
		return uci_set(ctx, &ptr);

	if (type == UCI_TYPE_LIST)
		return uci_add_list(ctx, &ptr);

	return -1;
}


int set_value_by_string(const char *package, const char *section,
		const char *key, const char *value, enum uci_option_type type)
{
	struct uci_ptr ptr = {0};
	struct uci_context *ctx;
	int rv = -1;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	ptr.package = package;
	ptr.section = section;
	ptr.option = key;
	ptr.value = value;

	if (type == UCI_TYPE_STRING)
		rv = uci_set(ctx, &ptr);

	if (type == UCI_TYPE_LIST)
		rv = uci_add_list(ctx, &ptr);

	uci_commit(ctx, &ptr.p, false);

	uci_free_context(ctx);
	return rv;
}

bool uci_set_option(char *package_name, char *section_type,
		char *search_key, char *search_val,
		char *option, char *value)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;

	if (!package_name || !search_val || !option || !value)
		return false;

	ctx = uci_alloc_context();
	if (!ctx)
		return false;

	if (uci_load(ctx, package_name, &pkg)) {
		uci_free_context(ctx);
		return false;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, section_type)) {
			struct uci_option *opt = uci_lookup_option(ctx, s,
					search_key);

			if (!opt || opt->type != UCI_TYPE_STRING)
				continue;
			if (strcmp(opt->v.string, search_val) == 0) {
				struct uci_ptr ptr = {0};

				ptr.value = value;
				ptr.package = package_name;
				ptr.section = s->e.name;
				ptr.option = option;
				ptr.target = UCI_TYPE_OPTION;
				if (uci_lookup_ptr(ctx, &ptr, NULL, false) ||
						!UCI_LOOKUP_COMPLETE)
					break;
				if (uci_set(ctx, &ptr) == UCI_OK)
					uci_save(ctx, ptr.p);
				break;
			}
		}
	}
	uci_commit(ctx, &pkg, false);
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return false;
}

struct uci_section *config_get_section(struct uci_context *ctx,
		struct uci_package *pkg, const char *type, const char *key,
		const char *value)
{
	struct uci_element *e;
	struct uci_section *section;

	/* get the wet iface section */
	uci_foreach_element(&pkg->sections, e) {
		const char *c_value;

		section = uci_to_section(e);
		if (strcmp(section->type, type))
			continue;

		c_value = uci_lookup_option_string(ctx, section, key);
		if (c_value && !strcmp(c_value, value))
			return section;
	}

	return NULL;
}

int cntlr_config_add_node(struct controller_config *c, char *al_mac)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	struct uci_ptr ptr = {0};
	char name[32] = { 0 };
	static const char s[2] = ":";
	char *token;
	char mac[18] = { 0 };
	int ret = -1;

	pkg = uci_load_pkg(&ctx, "mapcontroller");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, "node", "agent_id", al_mac);
	if (section)
		goto out_pkg;

	ret = uci_add_section(ctx, pkg, "node", &section);
	if (ret)
		goto out_pkg;

	strncpy(mac, al_mac, sizeof(mac) - 1);
	strncpy(name, "node_", sizeof(name) - 1);

	token = strtok(mac, s);
	while (token != NULL) {
		snprintf(name + strlen(name),
			 (sizeof(name) - strlen(name)),
			 "%s", token);
		token = strtok(NULL, s);
	}

	ptr.p = pkg;
	ptr.s = section;
	ptr.value = name;
	uci_rename(ctx, &ptr);

	ret = uci_save(ctx, pkg);
	if (ret)
		goto out_pkg;

	ret = set_value(ctx, pkg, section, "agent_id", al_mac, UCI_TYPE_STRING);

	uci_commit(ctx, &pkg, false);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}

int cntlr_config_add_node_radio(struct controller_config *c, char *al_mac,
		char *radio_mac, char *band)
{
	struct uci_context *ctx = NULL;
	struct uci_package *pkg;
	struct uci_section *section;
	char name[32] = { 0 };
	static const char s[2] = ":";
	char *token;
	char mac[18] = { 0 };
	struct uci_ptr ptr = {0};
	int ret = -1;

	pkg = uci_load_pkg(&ctx, "mapcontroller");
	if (!pkg)
		return ret;

	section = config_get_section(ctx, pkg, "radio", "macaddr", radio_mac);
	if (section)
		goto out_pkg;

	/* create section */
	ret = uci_add_section(ctx, pkg, "radio", &section);
	if (ret)
		goto out_pkg;

	strncpy(mac, radio_mac, 18);
	strncpy(name, "radio_", sizeof(name));

	token = strtok(mac, s);
	while (token != NULL) {
		snprintf(name + strlen(name),
			(sizeof(name) - strlen(name)),
			"%s", token);
		token = strtok(NULL, s);
	}

	ptr.p = pkg;
	ptr.s = section;
	ptr.value = name;
	uci_rename(ctx, &ptr);

	ret = uci_save(ctx, pkg);
	if (ret)
		goto out_pkg;

	/* add default values */
	ret = set_value(ctx, pkg, section, "agent_id", al_mac, UCI_TYPE_STRING);
	if (ret)
		goto out_pkg;

	ret = set_value(ctx, pkg, section, "macaddr", radio_mac, UCI_TYPE_STRING);
	if (ret)
		goto out_pkg;

	ret = set_value(ctx, pkg, section, "band", band, UCI_TYPE_STRING);
	if (ret)
		goto out_pkg;

	uci_commit(ctx, &pkg, false);

out_pkg:
	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return ret;
}



#if 0
void cntlr_dump_node_policy(struct node_policy *np)
{
	dbg("Dump node policy for agent "MACFMT"\n", MAC2STR(np->agent_id));
	dbg("agent_id "MACFMT"\n", MAC2STR(np->agent_id));
	dbg("bk_ul_mac "MACFMT"\n", MAC2STR(np->bk_ul_mac));
	dbg("bk_dl_mac "MACFMT"\n", MAC2STR(np->bk_dl_mac));
	dbg("type %d\n", np->type);
	dbg("pvid %u\n", np->pvid);
	dbg("pcp %u\n", np->pcp);
	dbg("report_scan %d\n", np->report_scan);
	dbg("report_sta_assocfails %d\n", np->report_sta_assocfails);
	dbg("report_sta_assocfails_rate %d\n", np->report_sta_assocfails_rate);
	dbg("report_metric_periodic %u\n", np->report_metric_periodic);
	dbg("steer_disallow %d\n", np->steer_disallow);
	dbg("coordinated_cac %d\n", np->coordinated_cac);
	dbg("traffic_separation %d\n", np->traffic_separation);
	dbg("sta_steer %d\n", np->sta_steer);
	dbg("num_steer_stas %d\n", np->num_steer_stas);
	dbg("num_btmsteer_stas %d\n", np->num_btmsteer_stas);
}


void cntlr_config_dump(struct controller_config *c)
{
	struct iface_credential *cred;

	dbg("Controller config ---------\n");
	dbg("Enabled: %d\n", c->enabled);
	dbg("Registrar @5Ghz: %d\n", c->has_registrar_5g);
	dbg("Registrar @2Ghz: %d\n", c->has_registrar_2g);
	dbg("Enable STA steer: %d\n", c->enable_sta_steer);
	dbg("Enable BSTA steer: %d\n", c->enable_bsta_steer);
	dbg("Use bcn metrics to steer: %d\n", c->use_bcn_metrics);
	dbg("Use uSTA metrics to steer: %d\n", c->use_usta_metrics);

	dbg("Credentials\n");
	list_for_each_entry(cred, &c->aplist, list) {
		dbg("  Band    : %d\n", cred->band);
		dbg("  Security: 0x%x\n", cred->sec);
		dbg("  Key     :\n");
		dbg("  ssid    : %s\n", cred->ssid);
		dbg("  vlan    : %d\n\n", cred->vlanid);
	}

	dbg("Agents policy: Default\n");
	//dbg("  Id                    : " MACFMT "\n", MAC2STR(c->apolicy.agent_id));
	dbg("  Steer-policy          : %d\n", c->apolicy->policy);
	dbg("  Util-threshold        : %d\n", c->apolicy->util_threshold);
	dbg("  RCPI-threshold        : %d\n", c->apolicy->rcpi_threshold);
	dbg("  Report scan           : %d\n", c->apolicy->report_scan);
	dbg("  Report assocfails     : %d\n", c->apolicy->report_sta_assocfails);
	dbg("  Report assocfails rate: %d\n", c->apolicy->report_sta_assocfails_rate);
	dbg("  Report metric         : %d\n", c->apolicy->report_metric_periodic);
	dbg("  Report RCPI-thresh    : %d\n", c->apolicy->report_rcpi_threshold);
	dbg("  Report Util-thresh    : %d\n", c->apolicy->report_util_threshold);
	dbg("  RCPI hysteresis margin: %d\n", c->apolicy->rcpi_hysteresis_margin);
	dbg("  Include STA stats     : %d\n", c->apolicy->include_sta_stats);
	dbg("  Include STA metric    : %d\n", c->apolicy->include_sta_metric);
	dbg("  Disallow bSTA P1      : %d\n", c->apolicy->disallow_bsta_p1);
	dbg("  Disallow bSTA P2      : %d\n", c->apolicy->disallow_bsta_p2);
	dbg("  Is policy diff        : %d\n", c->apolicy->is_policy_diff);

#if 0
	// INIT_LIST_HEAD(&c->apolicy.steer_exlist); // TODO: remove INIT_LIST_HEAD
	// INIT_LIST_HEAD(&c->apolicy.btmsteer_exlist);
	list_for_each_entry(x, &c->apolicy.steer_exlist, list) {
		dbg("  Disallowed STA        : %s\n", x->macstring);
	}
	list_for_each_entry(x, &c->apolicy.btmsteer_exlist, list) {
		dbg("  Disallowed BTM STA    : %s\n", x->macstring);
	}
#endif

	dbg("---------------------------\n");
}
#endif

int cntlr_config_defaults(struct controller *cntlr, struct controller_config *cfg)
{
	memset(cfg, 0, sizeof(*cfg));
	INIT_LIST_HEAD(&cfg->radiolist);
	INIT_LIST_HEAD(&cfg->nodelist);
	INIT_LIST_HEAD(&cfg->aplist);
	INIT_LIST_HEAD(&cfg->scclist);
	return 0;
}

static int cntlr_config_get_base(struct controller_config *c,
						struct uci_section *s)
{
	enum {
		CNTLR_ENABLED,
		CNTLR_REGISTRAR,
		CNTLR_DEBUG,
		CNTLR_RESEND_NUM,
		CNTLR_BCN_METRICS_MAX_NUM,
		CNTLR_INITIAL_CHANNEL_SCAN,
		CNTLR_CHANNEL_PLAN_TIMEOUT,
		CNTLR_BGDFS_TIMEOUT,
		CNTLR_PRIMARY_VID,
		CNTLR_DEFAULT_PCP,
		CNTLR_ENABLE_TS,
		CNTLR_PROFILE,
		NUM_CNTLR_ATTRS
	};
	const struct uci_parse_option opts[] = {
		{ .name = "enabled", .type = UCI_TYPE_STRING },
		{ .name = "registrar", .type = UCI_TYPE_STRING },
		{ .name = "debug", .type = UCI_TYPE_STRING },
		{ .name = "resend_num", .type = UCI_TYPE_STRING },
		{ .name = "bcn_metrics_max_num", .type = UCI_TYPE_STRING },
		{ .name = "initial_channel_scan", .type = UCI_TYPE_STRING },
		{ .name = "channel_plan", .type = UCI_TYPE_STRING },
		{ .name = "allow_bgdfs", .type = UCI_TYPE_STRING },
		{ .name = "primary_vid", .type = UCI_TYPE_STRING },
		{ .name = "default_pcp", .type = UCI_TYPE_STRING },
		{ .name = "enable_ts", .type = UCI_TYPE_STRING },
		{ .name = "enable_ts", .type = UCI_TYPE_STRING },
		{ .name = "profile", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_CNTLR_ATTRS];

	uci_parse_section(s, opts, NUM_CNTLR_ATTRS, tb);

	if (tb[CNTLR_PROFILE]) {
		c->map_profile = atoi(tb[CNTLR_PROFILE]->v.string);
		if (c->map_profile < MULTIAP_PROFILE_1)
			c->map_profile = MULTIAP_PROFILE_1;
		else if (c->map_profile > EASYMESH_VERSION)
			c->map_profile = EASYMESH_VERSION;
	} else
		c->map_profile = EASYMESH_VERSION;

	if (tb[CNTLR_ENABLED]) {
		const char *val = tb[CNTLR_ENABLED]->v.string;

		c->enabled = atoi(val) == 1 ? true : false;
	}

	if (tb[CNTLR_REGISTRAR]) {
		const char *val = tb[CNTLR_REGISTRAR]->v.string;

		c->has_registrar_6g = !strstr(val, "6") ? false : true;
		c->has_registrar_5g = !strstr(val, "5") ? false : true;
		c->has_registrar_2g = !strstr(val, "2") ? false : true;
	}

	if (tb[CNTLR_DEBUG]) {
		const char *debug = tb[CNTLR_DEBUG]->v.string;

		c->debug_level = atoi(debug);
		if (c->debug_level > verbose)
			verbose = c->debug_level;
	}

	if (tb[CNTLR_RESEND_NUM]) {
		const char *val = tb[CNTLR_RESEND_NUM]->v.string;

		c->resend_num = atoi(val);
	}

	if (tb[CNTLR_BCN_METRICS_MAX_NUM]) {
		const char *val = tb[CNTLR_BCN_METRICS_MAX_NUM]->v.string;

		c->bcn_metrics_max_num = atoi(val);
	} else
		c->bcn_metrics_max_num = BCN_METRICS_MAX_NUM;

	if (tb[CNTLR_INITIAL_CHANNEL_SCAN]) {
		const char *val = tb[CNTLR_INITIAL_CHANNEL_SCAN]->v.string;

		c->initial_channel_scan = atoi(val) == 1 ? true : false;
	}

	if (tb[CNTLR_CHANNEL_PLAN_TIMEOUT]) {
		const char *val = tb[CNTLR_CHANNEL_PLAN_TIMEOUT]->v.string;

		c->acs_timeout = atoi(val);
		/* TODO agree conf param - by default run each 3 hours */
		if (c->acs_timeout < 180)
			c->acs_timeout = 3600 * 3;
	}

	if (tb[CNTLR_BGDFS_TIMEOUT]) {
		const char *val = tb[CNTLR_BGDFS_TIMEOUT]->v.string;

		c->dfs_cleanup_timeout = atoi(val);
		if (c->dfs_cleanup_timeout < 120)
			c->dfs_cleanup_timeout = 120;
	}

	if (tb[CNTLR_PRIMARY_VID]) {
		const char *val = tb[CNTLR_PRIMARY_VID]->v.string;

		c->primary_vid = atoi(val);
		if (c->primary_vid > 0xfff)
			c->primary_vid = 0;
	}

	if (tb[CNTLR_ENABLE_TS]) {
		const char *val = tb[CNTLR_ENABLE_TS]->v.string;

		c->enable_ts = !!atoi(val);
	}

	return 0;
}

static int cntlr_config_get_wsc_attributes(struct controller_config *cfg,
					   struct iface_credential *cred)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;


	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "ieee1905", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);

		if (!strcmp(s->type, "ap")) {
			uint8_t default_dev_type[8] = { 0x00, 0x06, 0x00, 0x50, 0xf2, 0x04, 0x00, 0x01 }; /* default WPS oui */
			const char *manufacturer, *model_name, *device_name;
			const char *model_number, *serial_number, *device_type;
			uint32_t freqband;
			const char *band;

			band = uci_lookup_option_string(ctx, s, "band");
			if (!band || atoi(band) == 0)
				continue;

			if (atoi(band) == 5)
				freqband = BAND_5;
			else if (atoi(band) == 2)
				freqband = BAND_2;
			else if (atoi(band) == 6)
				freqband = BAND_6;
			else
				continue;

			if (cred->band != freqband)
				continue;

			manufacturer = uci_lookup_option_string(ctx, s, "manufacturer");
			if (manufacturer)
				strncpy(cred->manufacturer, manufacturer, 64);

			model_name = uci_lookup_option_string(ctx, s, "model_name");
			if (model_name)
				strncpy(cred->model_name, model_name, 32);

			device_name = uci_lookup_option_string(ctx, s, "device_name");
			if (device_name)
				strncpy(cred->device_name, device_name, 32);

			model_number = uci_lookup_option_string(ctx, s, "model_number");
			if (model_number)
				strncpy(cred->model_number, model_number, 32);

			serial_number = uci_lookup_option_string(ctx, s, "serial_number");
			if (serial_number)
				strncpy(cred->serial_number, serial_number, 32);

			memcpy(cred->device_type, default_dev_type, 8);
			device_type = uci_lookup_option_string(ctx, s, "device_type");
			if (device_type) {
				int ret;
				uint8_t oui[4] = {0};
				uint16_t category = 0, sub_category = 0;

				ret = sscanf(device_type, "%02hu-%02hhx%02hhx%02hhx%02hhx-%02hu",
					     &category,
					     &oui[0], &oui[1], &oui[2], &oui[3],
					     &sub_category);
				if (ret == 6) {
					buf_put_be16(&cred->device_type[0], category);
					memcpy(&cred->device_type[2], oui, 4);
					buf_put_be16(&cred->device_type[6], sub_category);
				}
			}

			break;
		}
	}

	uci_unload(ctx, pkg);
	uci_free_context(ctx);
	return 0;
}

/* returns steer_control_config for given (plugin/section) name */
static struct steer_control_config *find_steer_control_config(
		struct controller_config *cc, char *name)
{
	struct steer_control_config *e = NULL;

	list_for_each_entry(e, &cc->scclist, list) {
		if (!strncmp(e->name, name, 63))
			return e;
	}

	return NULL;
}

static int cntlr_config_get_steer_params(struct controller_config *cc,
						struct uci_section *s)
{
	enum {
		STEER_MODULE,
		STEER_PLUGIN_ENABLED,
		STEER_STA_ENABLE,
		STEER_BSTA_ENABLE,
		STEER_BCN_METRICS,
		STEER_USTA_METRICS,
		STEER_BANDSTEER,
		STEER_DIFFSNR,
		STEER_RCPI_TH_2G,
		STEER_RCPI_TH_5G,
		STEER_RCPI_TH_6G,
		STEER_RPT_RCPI_TH_2G,
		STEER_RPT_RCPI_TH_5G,
		STEER_RPT_RCPI_TH_6G,
		NUM_STEER_ATTRS
	};
	const struct uci_parse_option opts[] = {
		[STEER_MODULE] = { .name = "steer_module", .type = UCI_TYPE_STRING },
		[STEER_PLUGIN_ENABLED] = { .name = "enabled", .type = UCI_TYPE_STRING },
		[STEER_STA_ENABLE] = { .name = "enable_sta_steer", .type = UCI_TYPE_STRING },
		[STEER_BSTA_ENABLE] = { .name = "enable_bsta_steer", .type = UCI_TYPE_STRING },
		[STEER_BCN_METRICS] = { .name = "use_bcn_metrics", .type = UCI_TYPE_STRING },
		[STEER_USTA_METRICS] = { .name = "use_usta_metrics", .type = UCI_TYPE_STRING },
		[STEER_BANDSTEER] = { .name = "bandsteer", .type = UCI_TYPE_STRING },
		[STEER_DIFFSNR] = { .name = "diffsnr", .type = UCI_TYPE_STRING },
		[STEER_RCPI_TH_2G] = { .name = "rcpi_threshold_2g", .type = UCI_TYPE_STRING },
		[STEER_RCPI_TH_5G] = { .name = "rcpi_threshold_5g", .type = UCI_TYPE_STRING },
		[STEER_RCPI_TH_6G] = { .name = "rcpi_threshold_6g", .type = UCI_TYPE_STRING },
		[STEER_RPT_RCPI_TH_2G] = { .name = "report_rcpi_threshold_2g", .type = UCI_TYPE_STRING },
		[STEER_RPT_RCPI_TH_5G] = { .name = "report_rcpi_threshold_5g", .type = UCI_TYPE_STRING },
		[STEER_RPT_RCPI_TH_6G] = { .name = "report_rcpi_threshold_6g", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_STEER_ATTRS];
	struct steer_control_config *sc;
	char name[64];

	uci_parse_section(s, opts, NUM_STEER_ATTRS, tb);

	/* Keep separate params for each steer module (section, plugin) */

	if (!tb[STEER_MODULE]) {
		dbg("|%s:%d| Missing steer module name\n", __func__, __LINE__);
		return -1;
	}

	strncpy(name, tb[STEER_MODULE]->v.string, 63);

	sc = find_steer_control_config(cc, name);
	if (!sc) {
		sc = calloc(1, sizeof(*sc));
		if (!sc) {
			warn("-ENOMEM!\n");
			return -1;
		}
		strncpy(sc->name, name, 63);

		list_add_tail(&sc->list, &cc->scclist);
	}

	dbg("|%s:%d| Steer module: %s ", __func__, __LINE__, sc->name);

	if (tb[STEER_PLUGIN_ENABLED]) {
		const char *val = tb[STEER_PLUGIN_ENABLED]->v.string;

		sc->plugin_enabled = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_STA_ENABLE]) {
		const char *val = tb[STEER_STA_ENABLE]->v.string;

		sc->enable_sta_steer = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_BSTA_ENABLE]) {
		const char *val = tb[STEER_BSTA_ENABLE]->v.string;

		sc->enable_bsta_steer = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_BCN_METRICS]) {
		const char *val = tb[STEER_BCN_METRICS]->v.string;

		sc->use_bcn_metrics = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_USTA_METRICS]) {
		const char *val = tb[STEER_USTA_METRICS]->v.string;

		sc->use_usta_metrics = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_BANDSTEER]) {
		const char *val = tb[STEER_BANDSTEER]->v.string;

		sc->bandsteer = (atoi(val) == 1 ? true : false);
	}

	if (tb[STEER_DIFFSNR]) {
		const char *val = tb[STEER_DIFFSNR]->v.string;
		int diffsnr;

		diffsnr = atoi(val);
		if (diffsnr < 1)
			sc->diffsnr = 1;
		else if (diffsnr > 40)
			sc->diffsnr = 40;
		else
			sc->diffsnr = diffsnr;
	}

	sc->rcpi_threshold_2g = CONFIG_DEFAULT_RCPI_TH_2G;
	sc->rcpi_threshold_5g = CONFIG_DEFAULT_RCPI_TH_5G;
	sc->rcpi_threshold_6g = CONFIG_DEFAULT_RCPI_TH_6G;
	sc->report_rcpi_threshold_2g = CONFIG_DEFAULT_RCPI_TH_2G + 10;
	sc->report_rcpi_threshold_5g = CONFIG_DEFAULT_RCPI_TH_5G + 10;
	sc->report_rcpi_threshold_6g = CONFIG_DEFAULT_RCPI_TH_6G + 10;

	if (tb[STEER_RCPI_TH_2G]) {
		const char *val = tb[STEER_RCPI_TH_2G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->rcpi_threshold_2g = rcpi;
	}

	if (tb[STEER_RCPI_TH_5G]) {
		const char *val = tb[STEER_RCPI_TH_5G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->rcpi_threshold_5g = rcpi;
	}

	if (tb[STEER_RCPI_TH_6G]) {
		const char *val = tb[STEER_RCPI_TH_6G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->rcpi_threshold_6g = rcpi;
	}

	if (tb[STEER_RPT_RCPI_TH_2G]) {
		const char *val = tb[STEER_RPT_RCPI_TH_2G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->report_rcpi_threshold_2g = rcpi;
	}

	if (tb[STEER_RPT_RCPI_TH_5G]) {
		const char *val = tb[STEER_RPT_RCPI_TH_5G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->report_rcpi_threshold_5g = rcpi;
	}

	if (tb[STEER_RPT_RCPI_TH_6G]) {
		const char *val = tb[STEER_RPT_RCPI_TH_6G]->v.string;
		int rcpi;

		rcpi = atoi(val);
		if (rcpi > 0 && rcpi <= 220)
			sc->report_rcpi_threshold_6g = rcpi;
	}

	return 0;
}

static int cntlr_config_get_credentials(struct controller_config *c,
						struct uci_section *s)
{
	enum {
		CRED_BAND,
		CRED_SSID,
		CRED_SEC,
		CRED_KEY,
		CRED_VLAN,
		CRED_TYPE,
		CRED_D_BSTA,
		CRED_ENABLED,
		CRED_VENDOR_IE,
		NUM_CREDS,
	};
	const struct uci_parse_option opts[] = {
		[CRED_BAND] = { .name = "band", .type = UCI_TYPE_STRING },
		[CRED_SSID] = { .name = "ssid", .type = UCI_TYPE_STRING },
		[CRED_SEC] = { .name = "encryption", .type = UCI_TYPE_STRING },
		[CRED_KEY] = { .name = "key", .type = UCI_TYPE_STRING },
		[CRED_VLAN] = { .name = "vid", .type = UCI_TYPE_STRING },
		[CRED_TYPE] = { .name = "type", .type = UCI_TYPE_STRING },
		[CRED_D_BSTA] = { .name = "disallow_bsta", .type = UCI_TYPE_LIST },
		[CRED_ENABLED] = { .name = "enabled", .type = UCI_TYPE_STRING },
		[CRED_VENDOR_IE] = { .name = "vendor_ie", .type = UCI_TYPE_LIST }
	};
	struct uci_option *tb[NUM_CREDS];
	struct iface_credential *cred;
	bool use_default_security = false;

	if (c->num_bss >= 32)
		return -1;

	cred = calloc(1, sizeof(*cred));
	if (!cred)
		return -1;

	uci_parse_section(s, opts, NUM_CREDS, tb);

	cred->enabled = true;
	if (tb[CRED_ENABLED])
		cred->enabled = atoi(tb[CRED_ENABLED]->v.string);

#ifndef EASYMESH_VENDOR_EXT
        if (!(cred->enabled)) {
		free(cred);
		return -1;
	}
#endif

	if (tb[CRED_BAND]) {
		if (atoi(tb[CRED_BAND]->v.string) == 5)
			cred->band = BAND_5;
		else if (atoi(tb[CRED_BAND]->v.string) == 2)
			cred->band = BAND_2;
		else if (atoi(tb[CRED_BAND]->v.string) == 6)
			cred->band = BAND_6;
		else
			cred->band = BAND_UNKNOWN;
	} else
		cred->band = BAND_UNKNOWN;

	if (tb[CRED_SSID])
		strncpy((char *) cred->ssid, tb[CRED_SSID]->v.string, 32);

	if (tb[CRED_SEC]) {
		const char *sec = tb[CRED_SEC]->v.string;

		if (!strncmp(sec, "sae-mixed", 9)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA3PSK);
			cred->sec |= BIT(WIFI_SECURITY_WPA3PSK_T);
		} else if (!strncmp(sec, "sae", 3)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA3PSK);
		} else if (!strncmp(sec, "psk-mixed", 9)) {
			cred->sec |= BIT(WIFI_SECURITY_WPAPSK);
			cred->sec |= BIT(WIFI_SECURITY_WPA2PSK);
		} else if (!strncmp(sec, "psk2", 4)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA2PSK);
		} else if (!strncmp(sec, "psk", 3)) {
			cred->sec |= BIT(WIFI_SECURITY_WPAPSK);
		} else if (!strncmp(sec, "wpa-mixed", 9)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA);
			cred->sec |= BIT(WIFI_SECURITY_WPA2);
		} else if (!strncmp(sec, "wpa2", 4)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA2);
		} else if (!strncmp(sec, "wpa", 3)) {
			cred->sec |= BIT(WIFI_SECURITY_WPA);
		} else if (!strncmp(sec, "none", 4)) {
			cred->sec |= BIT(WIFI_SECURITY_NONE);
		} else if (!strncmp(sec, "open", 4)) {
			cred->sec |= BIT(WIFI_SECURITY_NONE);
		} else {
			free(cred);
			return -1;
		}

		//TODO: ciphers (if any)
	} else {
		use_default_security = true;
	}

	if (tb[CRED_KEY])
		strncpy((char *) cred->key, tb[CRED_KEY]->v.string, 64);

	if (tb[CRED_VLAN])
		cred->vlanid = (uint16_t) atoi(tb[CRED_VLAN]->v.string);

	if (tb[CRED_TYPE]) {
		const char *type = tb[CRED_TYPE]->v.string;

		if (!strcmp(type, "backhaul")) {
			cred->multi_ap = 1;
			cred->mode = AP_WIFI_BBSS;
		} else if (!strcmp(type, "fronthaul")) {
			cred->multi_ap = 2;
			cred->mode = AP_WIFI_FBSS;
		} else if (!strcmp(type, "combined")) {
			cred->multi_ap = 3;
			cred->mode = AP_WIFI_COMBINED;
		} else {
			free(cred);
			return -1;
		}
	} else {
		cred->multi_ap = 2; /* default to fhbss */
		cred->mode = AP_WIFI_FBSS;
	}

	if (use_default_security) {
		cred->sec |= BIT(WIFI_SECURITY_WPA3PSK);
		if (!!(cred->multi_ap & 2))
			cred->sec |= BIT(WIFI_SECURITY_WPA3PSK_T);
	}

	if (tb[CRED_D_BSTA]) {
		struct uci_element *x;

		uci_foreach_element(&tb[CRED_D_BSTA]->v.list, x) {
			cred->disallow_bsta |= atoi(x->name);
		}
	}


#ifdef EASYMESH_VENDOR_EXT
	do {
		/* add iopsys vendor_ies for cred->enabled option */
		struct wsc_vendor_ie *ext;
		uint8_t offset = 0;
		uint8_t attr = 0x4c;
		uint8_t attr_len = 0x01;

		ext = &cred->ven_ies[0];

		memcpy(ext->oui, EASYMESH_VENDOR_EXT_OUI, 3);
		ext->len = 3;
		ext->payload = calloc(1, ext->len);
		if (!ext->payload)
			break;

		/* uses same format as WFA WSC vendor extension:
		 * <attr:8><len:8><data>
		 */
		memcpy(ext->payload,  &attr, 1); /* IOP enabled attr */
		offset += 1;
		memcpy(ext->payload + offset, &attr_len, 1); /* len */
		offset += 1;
		memcpy(ext->payload + offset, &cred->enabled, 1); /* val */

		cred->num_ven_ies++;
	} while (0);
#endif /*EASYMESH_VENDOR_EXT*/
	if (tb[CRED_VENDOR_IE]) {
		struct uci_element *x;

		uci_foreach_element(&tb[CRED_VENDOR_IE]->v.list, x) {
			char *vendor_ie = x->name;
			struct wsc_vendor_ie *ext;
			uint16_t len;
			uint8_t offset = 0;
			uint8_t *buf;

			if (cred->num_ven_ies >= VEN_IES_MAX) {
				dbg("at most %d vendor ies\n", VEN_IES_MAX);
				break;
			}

			len = strlen(vendor_ie);
			if (len % 2 != 0)
				continue;

			len = len / 2;
			if (len < 3) {
				dbg("payload len too short %d\n", len);
				continue;
			}

			buf = calloc(1, len);
			if (!buf)
				continue;

			strtob(vendor_ie, len, buf);

			ext = &cred->ven_ies[cred->num_ven_ies];

			memcpy(ext->oui, (uint8_t *) buf, 3);
			offset += 3;

			if (len > offset) {
				ext->len = len - offset;
				ext->payload = calloc(1, ext->len);
				if (!ext->payload) {
					free(buf);
					continue;
				}

				memcpy(ext->payload,
				       (uint8_t *) (buf + offset),
				       ext->len);
			}

			cred->num_ven_ies++;
			free(buf);
		}
	}

	cntlr_config_get_wsc_attributes(c, cred);

	c->num_bss++;
	list_add_tail(&cred->list, &c->aplist);
	return 0;
}

struct node_policy *cntlr_config_get_node_by_mac(struct controller_config *cfg,
							uint8_t *macaddr)
{
	struct node_policy *node = NULL;

	list_for_each_entry(node, &cfg->nodelist, list) {
		if (!memcmp(node->agent_id, macaddr, 6))
			return node;
	}

	return NULL;
}

static int cntlr_config_get_agent_node(struct controller_config *c,
						struct uci_section *s)
{
	enum {
		NODE_AGENT_ID,
		NODE_BK_UL_MAC,
		NODE_BK_DL_MAC,
		NODE_BK_TYPE,
		NODE_PVID,
		NODE_PCP,
		NODE_RPT_ASSOC_FAILS,
		NODE_RPT_ASSOC_FAILS_RATE,
		NODE_RPT_METRIC_PERIODIC,
		NODE_RPT_SCAN,
		NODE_STEER_EXCLUDE,
		NODE_STEER_EXCLUDE_BTM,
		NODE_STEER_DISALLOW,
		NODE_C_CAC,
		NODE_TRAFFIC_SEPARATION,
		NODE_STA_STEER,
		NUM_POLICIES,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "agent_id", .type = UCI_TYPE_STRING },
		{ .name = "backhaul_ul_macaddr", .type = UCI_TYPE_STRING },
		{ .name = "backhaul_dl_macaddr", .type = UCI_TYPE_STRING },
		{ .name = "backhaul_type", .type = UCI_TYPE_STRING },
		{ .name = "primary_vid", .type = UCI_TYPE_STRING },
		{ .name = "primary_pcp", .type = UCI_TYPE_STRING },
		{ .name = "report_sta_assocfails", .type = UCI_TYPE_STRING },
		{ .name = "report_sta_assocfails_rate", .type = UCI_TYPE_STRING },
		{ .name = "report_metric_periodic", .type = UCI_TYPE_STRING },
		{ .name = "report_scan", .type = UCI_TYPE_STRING },
		{ .name = "steer_exclude", .type = UCI_TYPE_LIST },
		{ .name = "steer_exclude_btm", .type = UCI_TYPE_LIST },
		{ .name = "steer_disallow", .type = UCI_TYPE_STRING },
		{ .name = "coordinated_cac", .type = UCI_TYPE_STRING },
		{ .name = "traffic_separation", .type = UCI_TYPE_STRING },
		{ .name = "sta_steer", .type = UCI_TYPE_STRING },
	};
	struct uci_option *tb[NUM_POLICIES];
	struct node_policy *a;
	struct uci_element *x;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (tb[NODE_AGENT_ID]) {
		a = calloc(1, sizeof(*a));
		if (!a)
			return -1;

		list_add(&a->list, &c->nodelist);

		INIT_LIST_HEAD(&a->radiolist);
		hwaddr_aton(tb[NODE_AGENT_ID]->v.string, a->agent_id);
		INIT_LIST_HEAD(&a->steer_exlist);
		INIT_LIST_HEAD(&a->btmsteer_exlist);

		a->pvid = 0;
	} else
		return -1;

	if (tb[NODE_BK_UL_MAC])
		hwaddr_aton(tb[NODE_BK_UL_MAC]->v.string, a->bk_ul_mac);

	if (tb[NODE_BK_DL_MAC])
		hwaddr_aton(tb[NODE_BK_DL_MAC]->v.string, a->bk_dl_mac);

	if (tb[NODE_BK_TYPE]) {
		char *type = tb[NODE_BK_TYPE]->v.string;

		if (strcmp(type, "none"))
			a->type = BK_TYPE_NONE;
		else
			a->type = BK_TYPE_NONE;
	}

	if (tb[NODE_PVID])
		a->pvid = atoi(tb[NODE_PVID]->v.string);

	if (tb[NODE_PCP])
		a->pcp = atoi(tb[NODE_PCP]->v.string);


	if (tb[NODE_RPT_ASSOC_FAILS]) {
		a->report_sta_assocfails =
			atoi(tb[NODE_RPT_ASSOC_FAILS]->v.string) == 1 ?
					true : false;
	}

	if (tb[NODE_RPT_ASSOC_FAILS_RATE]) {
		a->report_sta_assocfails_rate =
				atoi(tb[NODE_RPT_ASSOC_FAILS_RATE]->v.string);
	}

	if (tb[NODE_STEER_EXCLUDE]) {
		uci_foreach_element(&tb[NODE_STEER_EXCLUDE]->v.list, x) {
			stax_add_entry(&a->steer_exlist, x->name);
			a->num_steer_stas++;
		}
	}

	if (tb[NODE_STEER_EXCLUDE_BTM]) {
		uci_foreach_element(&tb[NODE_STEER_EXCLUDE_BTM]->v.list, x) {
			stax_add_entry(&a->btmsteer_exlist, x->name);
			a->num_btmsteer_stas++;
		}
	}

	if (tb[NODE_RPT_SCAN]) {
		a->report_scan =
			atoi(tb[NODE_RPT_SCAN]->v.string) == 1 ? true : false;
	}

	if (tb[NODE_RPT_METRIC_PERIODIC])
		a->report_metric_periodic = atoi(tb[NODE_RPT_METRIC_PERIODIC]->v.string);

	if (tb[NODE_STEER_DISALLOW])
		a->steer_disallow = atoi(tb[NODE_STEER_DISALLOW]->v.string) == 1 ? true : false;

	if (tb[NODE_C_CAC])
		a->coordinated_cac = atoi(tb[NODE_C_CAC]->v.string) == 1 ? true : false;

	if (tb[NODE_TRAFFIC_SEPARATION])
		a->traffic_separation = atoi(tb[NODE_TRAFFIC_SEPARATION]->v.string) == 1 ? true : false;

	if (tb[NODE_STA_STEER])
		a->sta_steer = atoi(tb[NODE_STA_STEER]->v.string) == 1 ? true : false;

	return 0;
}

static int cntlr_config_get_agent_radio(struct controller_config *cc,
						struct uci_section *s)
{
	enum {
		RADIO_AGENT,
		RADIO_MAC,
		RADIO_BAND,
		RADIO_STEER_POLICY,
		RADIO_UTIL_TH,
		RADIO_RCPI_TH,
		RADIO_RPT_RCPI_TH,
		RADIO_RPT_UTIL_TH,
		RADIO_RPT_HYS_MARGIN,
		RADIO_INC_STA_STATS,
		RADIO_INC_STA_METRIC,
#if (EASYMESH_VERSION > 2)
		RADIO_INC_WIFI6_STA_STATUS,
#endif
		NUM_POLICIES,
	};
	const struct uci_parse_option opts[] = {
		{ .name = "agent_id", .type = UCI_TYPE_STRING },
		{ .name = "macaddr", .type = UCI_TYPE_STRING },
		{ .name = "band", .type = UCI_TYPE_STRING },
		{ .name = "steer_policy", .type = UCI_TYPE_STRING },
		{ .name = "util_threshold", .type = UCI_TYPE_STRING },
		{ .name = "rcpi_threshold", .type = UCI_TYPE_STRING },
		{ .name = "report_rcpi_threshold", .type = UCI_TYPE_STRING },
		{ .name = "report_util_threshold", .type = UCI_TYPE_STRING },
		{ .name = "report_rcpi_hysteresis_margin", .type = UCI_TYPE_STRING },
		{ .name = "include_sta_stats", .type = UCI_TYPE_STRING },
		{ .name = "include_sta_metric", .type = UCI_TYPE_STRING },
#if (EASYMESH_VERSION > 2)
		{ .name = "include_wifi6_sta_status", .type = UCI_TYPE_STRING },
#endif
	};
	struct controller *c = container_of(cc, struct controller, cfg);
	struct uci_option *tb[NUM_POLICIES];
	struct steer_control_config *scc = NULL;
	struct radio_policy *a;
	int band;

	uci_parse_section(s, opts, NUM_POLICIES, tb);

	if (!tb[RADIO_AGENT] || !tb[RADIO_MAC] || !tb[RADIO_BAND]) {
		warn("|%s:%d| invalid radio config! Must hold agent_id, macaddr and band", __func__, __LINE__);
		return -1;
	}

	a = calloc(1, sizeof(*a));
	if (!a)
		return -1;

	hwaddr_aton(tb[RADIO_AGENT]->v.string, a->agent_id);
	hwaddr_aton(tb[RADIO_MAC]->v.string, a->macaddr);
	band = atoi(tb[RADIO_BAND]->v.string);

	scc = get_steer_control_config(c);
	a->band = BAND_UNKNOWN;

	switch (band) {
	case 5:
		a->band = BAND_5;
		if (scc) {
			a->rcpi_threshold = scc->rcpi_threshold_5g;
			a->report_rcpi_threshold = scc->report_rcpi_threshold_5g;
		} else
			a->rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_5G;
		break;
	case 6:
		a->band = BAND_6;
		if (scc) {
			a->rcpi_threshold = scc->rcpi_threshold_6g;
			a->report_rcpi_threshold = scc->report_rcpi_threshold_6g;
		} else
			a->rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_6G;
		break;
	case 2:
		a->band = BAND_2;
		/* no break */
	default:
		if (scc) {
			a->rcpi_threshold = scc->rcpi_threshold_2g;
			a->report_rcpi_threshold = scc->report_rcpi_threshold_2g;
		} else
			a->rcpi_threshold = CONFIG_DEFAULT_RCPI_TH_2G;
		break;
	}

	if (!scc)
		a->report_rcpi_threshold = a->rcpi_threshold + 10;

	a->include_sta_stats = true;
	a->include_sta_metric = true;

	list_add(&a->list, &cc->radiolist);

	if (tb[RADIO_STEER_POLICY])
		a->policy = atoi(tb[RADIO_STEER_POLICY]->v.string);

	if (tb[RADIO_UTIL_TH])
		a->util_threshold = atoi(tb[RADIO_UTIL_TH]->v.string);

	if (tb[RADIO_RCPI_TH]) {
		/* override default value from steer section in config */
		a->rcpi_threshold = atoi(tb[RADIO_RCPI_TH]->v.string);
		a->report_rcpi_threshold = a->rcpi_threshold + 10;
	}

	if (tb[RADIO_RPT_RCPI_TH]) {
		/* override default value from steer section in config */
		a->report_rcpi_threshold =
				atoi(tb[RADIO_RPT_RCPI_TH]->v.string);
	}

	if (tb[RADIO_RPT_UTIL_TH]) {
		a->report_util_threshold =
				atoi(tb[RADIO_RPT_UTIL_TH]->v.string);
	}

	if (tb[RADIO_RPT_HYS_MARGIN]) {
		a->report_rcpi_hysteresis_margin =
				atoi(tb[RADIO_RPT_HYS_MARGIN]->v.string);
	}

	if (tb[RADIO_INC_STA_STATS]) {
		a->include_sta_stats =
			atoi(tb[RADIO_INC_STA_STATS]->v.string) == 1 ?
					true : false;
	}

	if (tb[RADIO_INC_STA_METRIC]) {
		a->include_sta_metric =
			atoi(tb[RADIO_INC_STA_METRIC]->v.string) == 1 ?
					true : false;
	}

#if (EASYMESH_VERSION > 2)
	if (tb[RADIO_INC_WIFI6_STA_STATUS]) {
		a->include_wifi6_sta_status =
			atoi(tb[RADIO_INC_WIFI6_STA_STATUS]->v.string) == 1 ?
					true : false;
	}
#endif

	return 0;
}

static void config_map_radios_to_node(struct controller_config *cfg)
{
	struct radio_policy *r = NULL, *tmp;

	list_for_each_entry_safe(r, tmp, &cfg->radiolist, list) {
		struct node_policy *n;

		n = cntlr_config_get_node_by_mac(cfg, r->agent_id);
		if (!n) {
			list_del(&r->list);
			free(r);
			continue;
		}

		list_del(&r->list);
		list_add(&r->list, &n->radiolist);
	}
}

uint8_t cntlr_policy_exlist_diff(struct list_head *prev_policylist,
		struct list_head *curr_policylist)
{
	uint8_t diff = 0;
	struct node_policy *prev, *curr;

	list_for_multiple_entry(prev, curr, prev_policylist, curr_policylist, list, list) {
		if ((prev->num_steer_stas != curr->num_steer_stas) ||
				(prev->num_btmsteer_stas != curr->num_btmsteer_stas)) {
			trace("num of exclude stas differ\n");
			curr->is_policy_diff = 1;
			diff |= CONFIG_DIFF_AGENT_POLICY;
		} else if (list_memcmp(&prev->steer_exlist, &curr->steer_exlist,
					struct stax, sizeof(struct list_head))) {
			trace("steer_exlist differ\n");
			curr->is_policy_diff = 1;
			diff |= CONFIG_DIFF_AGENT_POLICY;
		} else if (list_memcmp(&prev->btmsteer_exlist, &curr->btmsteer_exlist,
					struct stax, sizeof(struct list_head))) {
			trace("btmsteer_exlist differ\n");
			curr->is_policy_diff = 1;
			diff |= CONFIG_DIFF_AGENT_POLICY;
		}
	}

	return diff;
}

uint8_t cntlr_vendor_ies_diff(struct list_head *prev_credslist,
		struct list_head *curr_credslist)
{
	struct iface_credential *prev, *curr;
	uint8_t diff = 0;

	list_for_multiple_entry(prev, curr, prev_credslist, curr_credslist, list, list) {
		if (prev->num_ven_ies != curr->num_ven_ies) {
			dbg("num of vendor ies differ\n");
			diff |= CONFIG_DIFF_CREDENTIALS;
			break;
		} else {
			int i;

			for (i = 0; i < curr->num_ven_ies; i++) {
				struct wsc_vendor_ie *curr_ie, *prev_ie;
				uint16_t len = 0;

				curr_ie = &curr->ven_ies[i];
				prev_ie = &prev->ven_ies[i];

				len = (prev_ie->len > curr_ie->len ?
				       prev_ie->len : curr_ie->len);

				if (memcmp(curr_ie->payload, prev_ie->payload, len)) {
					diff |= CONFIG_DIFF_CREDENTIALS;
					return diff;
				}
			}
		}
	}

	return diff;
}

uint8_t cntlr_creds_diff(struct controller_config *cfg,
		struct controller_config *prev)
{
	uint8_t diff = 0;

	/* credentials diff */
	if (prev->num_bss != cfg->num_bss) {
		dbg("|%s:%d| number of credentials differed\n", __func__, __LINE__);
		diff |= CONFIG_DIFF_CREDENTIALS;
	} else if (list_memcmp(&prev->aplist, &cfg->aplist,
				struct iface_credential,
				(sizeof(struct iface_credential) -
				offsetof(struct iface_credential, list))
			)) {
		dbg("|%s:%d| bss credentials have changed\n", __func__, __LINE__);
		diff |= CONFIG_DIFF_CREDENTIALS;
	} else {
		/* compare vendor ie list */
		diff |= cntlr_vendor_ies_diff(&prev->aplist, &cfg->aplist);
	}

	return diff;
}

uint8_t cntlr_config_diff(struct controller_config *cfg,
		struct controller_config *prev)
{
	uint8_t diff = 0;

	/* traffic separation change */
	if (prev->primary_vid != cfg->primary_vid ||
	    prev->default_pcp != cfg->default_pcp ||
	    prev->enable_ts != cfg->enable_ts) {
		diff |= CONFIG_DIFF_VLAN;
	}

	/* credentials diff */
	diff |= cntlr_creds_diff(cfg, prev);

	/* agent policy diff */
	if (prev->num_apolicy != cfg->num_apolicy) {
		dbg("|%s:%d| number of agent policy differed\n", __func__, __LINE__);
		diff |= CONFIG_DIFF_AGENT_POLICY_CNT;
	}

	if (list_policy_memcmp(&prev->nodelist, &cfg->nodelist,
				struct node_policy,
				(sizeof(struct node_policy) -
				offsetof(struct node_policy, is_policy_diff))
			)) {
		trace("|%s:%d| agent_policy section have changed\n", __func__, __LINE__);
		diff |= CONFIG_DIFF_AGENT_POLICY;
	} else {
		/* exclude stalist diff */
		diff |= cntlr_policy_exlist_diff(&prev->nodelist, &cfg->nodelist);
	}

	return diff;
}

void config_copy_cntlr_config(struct controller_config *curr,
		struct controller_config *old)
{
	INIT_LIST_HEAD(&old->radiolist);
	INIT_LIST_HEAD(&old->nodelist);
	INIT_LIST_HEAD(&old->aplist);

	memcpy(old, curr, offsetof(struct controller_config, nodelist));

	list_copy(&curr->radiolist, &old->radiolist, struct radio_policy);
	list_copy(&curr->nodelist, &old->nodelist, struct node_policy);
	list_copy(&curr->aplist, &old->aplist, struct iface_credential);
}

uint8_t cntlr_config_reload(struct controller_config *cfg)
{
	struct uci_context *ctx;
	struct uci_package *pkg;
	struct uci_element *e;
	struct controller_config old = {0};
	uint8_t diff = 0;

	ctx = uci_alloc_context();
	if (!ctx)
		return -1;

	if (uci_load(ctx, "mapcontroller", &pkg)) {
		uci_free_context(ctx);
		return -1;
	}

	config_copy_cntlr_config(cfg, &old);

	/* reset counters */
	cfg->num_bss = cfg->num_apolicy = 0;

	uci_foreach_element(&pkg->sections, e) {
		struct uci_section *s = uci_to_section(e);
		if (!strcmp(s->type, "controller")) {
			cntlr_config_get_base(cfg, s);
		} else if (!strcmp(s->type, "sta_steering")) {
			cntlr_config_get_steer_params(cfg, s);
		} else if (!strcmp(s->type, "ap")) {
			cntlr_config_get_credentials(cfg, s);
		} else if (!strcmp(s->type, "node")) {
			cntlr_config_get_agent_node(cfg, s);
		} else if (!strcmp(s->type, "radio")) {
			cntlr_config_get_agent_radio(cfg, s);
		}
	}

	config_map_radios_to_node(cfg);

	/* get bitmap of what sections changed */
	diff = cntlr_config_diff(cfg, &old);

	/* clean old lists */
	clean_cred_list(&old);
	clean_agent_policies(&old); /* cleans nodelist */
	clean_radio_list(&old.radiolist);

	uci_free_context(ctx);

	return diff;
}

int cntlr_config_clean(struct controller_config *cfg)
{
	clean_scclist_list(cfg);
	clean_cred_list(cfg);
	clean_agent_policies(cfg); /* cleans nodelist */
	clean_radio_list(&cfg->radiolist);
	return 0;
}
