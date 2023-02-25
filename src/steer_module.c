/*
 * steer_module.c - STA steering module
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <dlfcn.h>
#include <sys/time.h>

#include <json-c/json.h>
#include <libubox/blobmsg.h>
#include <libubox/blobmsg_json.h>
#include <libubox/uloop.h>
#include <libubox/ustream.h>
#include <libubox/utils.h>
#include <libubus.h>

#include <easy/easy.h>
#include <wifidefs.h>

#include <timer_impl.h>
#include <cmdu.h>
#include <1905_tlvs.h>
#include <i1905_wsc.h>
#include <easymesh.h>
#include <map_module.h>
#include <uci.h>

#include "utils/debug.h"
#include "utils/utils.h"
#include "config.h"
#include "cntlr.h"
#include "steer_module.h"

#define CNTLR_STEER_MODULE_PATH		"/usr/lib/mapcontroller"


static int plugin_load(const char *path, const char *name, void **handle)
{
	char abspath[256] = {0};
	int flags = 0;
	void *h;

	if (!handle || !name || !path)
		return -1;

	flags |= RTLD_NOW | RTLD_GLOBAL;
	snprintf(abspath, sizeof(abspath) - 1, "%s/%s", path, name);
	h = dlopen(abspath, flags);
	if (!h) {
		err("%s: Error: %s\n", __func__, dlerror());
		return -1;
	}

	*handle = h;
	return 0;
}

static int plugin_unload(void *handle)
{
	if (!handle)
		return -1;

	return dlclose(handle);
}

static int cntlr_unload_steer_module(struct steer_control *sc)
{
	int ret;

	ret = plugin_unload(sc->handle);
	list_del(&sc->list);
	free(sc);

	return !ret ? 0 : -1;
}

int cntlr_load_steer_module(struct controller *priv, const char *name,
			    struct steer_control **sc)
{
	struct steer_control *p, *pp = NULL;
	char fname[128] = {0};
	void *handle;
	int ret;


	snprintf(fname, 127, "%s.so", name);
	ret = plugin_load(CNTLR_STEER_MODULE_PATH, fname, &handle);
	if (ret)
		return -1;

	pp = dlsym(handle, name);
	if (!pp) {
		err("Symbol '%s' not found\n", name);
		return -1;
	}

	p = calloc(1, sizeof(struct steer_control));
	if (!p) {
		plugin_unload(handle);
		return -1;
	}

	memcpy(p, pp, sizeof(struct steer_control));
	p->handle = handle;
	*sc = p;

	if (p->init)
		p->init(&p->priv);

	dbg("Registered %s (priv = 0x%p)\n", name, p->priv);
	return 0;
}

static struct steer_control *cntlr_lookup_steer_module(struct controller *c,
						       const char *name)
{
	struct steer_control *sc = NULL;

	list_for_each_entry(sc, &c->sclist, list) {
		if (!strncmp(sc->name, name, strlen(sc->name)))
			return sc;
	}

	return NULL;
}

struct steer_control *cntlr_get_steer_control(struct controller *c)
{
	if (!c)
		return NULL;

	return c->sctrl;
}

void cntlr_assign_steer_module_default(struct controller *c)
{
	c->sctrl = !list_empty(&c->sclist) ?
			/* use first from the list for now */
			list_first_entry(&c->sclist, struct steer_control, list) :
			NULL;
}

void cntlr_assign_steer_module(struct controller *c, const char *name)
{
	if (!name || name[0] == '\0') {
		c->sctrl = NULL;
		return;
	}

	c->sctrl = cntlr_lookup_steer_module(c, name);
}


void cntlr_load_steer_modules(struct controller *c)
{
	struct steer_control_config *e = NULL;

	list_for_each_entry(e, &c->cfg.scclist, list) {
		struct steer_control *sc = NULL;
		int ret = 0;


		if (cntlr_lookup_steer_module(c, e->name)) {
			/* already loaded */
			dbg("Steer module '%s', already loaded\n", e->name);
			continue;
		}

		if (!e->plugin_enabled) {
			/* plugin disabled in config */
			dbg("Steer module '%s', disabled in cfg\n", e->name);
			continue;
		}

		info("Loading steer module '%s'\n", e->name);
		ret = cntlr_load_steer_module(c, e->name, &sc);
		if (!ret)
			list_add_tail(&sc->list, &c->sclist);
	}
}

void cntlr_unload_steer_modules(struct controller *c)
{
	struct steer_control *p = NULL, *tmp;

	list_for_each_entry_safe(p, tmp, &c->sclist, list) {
		if (p->exit)
			p->exit(p->priv);

		list_del(&p->list);
		plugin_unload(p->handle);
		free(p);
	}
}

int cntlr_register_steer_module(struct controller *c, const char *name)
{
	struct steer_control *sc;
	int ret;


	if (!name || name[0] == '\0')
		return -1;

	if (cntlr_lookup_steer_module(c, name)) {
		info("Steer module '%s' already registered\n", name);
		return 0;
	}

	ret = cntlr_load_steer_module(c, name, &sc);
	if (!ret) {
		list_add_tail(&sc->list, &c->sclist);
		return 0;
	}

	return -1;
}

int cntlr_unregister_steer_module(struct controller *c, char *name)
{
	struct steer_control *sc;


	if (!name || name[0] == '\0')
		return -1;

	sc = cntlr_lookup_steer_module(c, name);
	if (!sc)
		return -1;

	return cntlr_unload_steer_module(sc);
}

int cntlr_configure_steer_module(struct controller *c, struct steer_config *cfg)
{
	struct steer_control *sc = cntlr_get_steer_control(c);

	if (sc && sc->config)
		return sc->config(sc->priv, cfg);

	return 0;
}

int cntlr_maybe_steer_sta(struct controller *c, struct steer_sta *s)
{
	struct steer_control *sc = cntlr_get_steer_control(c);

	if (sc && sc->steer)
		return sc->steer(sc->priv, s);

	return 0;
}
