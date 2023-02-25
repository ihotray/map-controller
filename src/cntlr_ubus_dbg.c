/*
 * cntlr_ubus_dbg.c - for testing purpose only
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <fcntl.h>
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
#include <cmdu.h>
#include <i1905_wsc.h>
#include <1905_tlvs.h>
#include <easymesh.h>
#include <map_module.h>

#include <wifidefs.h>
#include "wifi_dataelements.h"

#include "timer.h"
#include "utils/utils.h"
#include "utils/debug.h"
#include "config.h"
#include "cntlr.h"
#include "allsta.h"
#include "allmac.h"
#include "cntlr_map.h"
#include "cntlr_ubus.h"
#include "cntlr_tlv.h"
#include "cntlr_cmdu.h"


#define OBJECT_INVALID	((uint32_t)-1)

#ifndef MAP_CNTLR_DISABLE_UBUS_DBG

static int cntlr_dbg_list_macs(struct ubus_context *ctx, struct ubus_object *obj,
			struct ubus_request_data *req, const char *method,
			struct blob_attr *msg)
{
	struct controller *c = container_of(obj, struct controller, obj_dbg);
	struct map_macaddr_entry *entry = NULL;
	struct blob_buf bb = {0};
	char macaddrstr[18] = {0};
	void *t, *tt;
	int i;

	memset(&bb, 0, sizeof(bb));
	blob_buf_init(&bb, 0);
	t = blobmsg_open_table(&bb, "MAC list");

	for (i = 0; i < MAC_HTBL_SIZE; i++) {
		if (hlist_empty(&c->mac_table.table[i]))
			continue;

		hlist_for_each_entry(entry, &c->mac_table.table[i], hlist) {
			tt = blobmsg_open_table(&bb, "");

			hwaddr_ntoa(entry->macaddr, macaddrstr);
			blobmsg_add_string(&bb, "MAC", macaddrstr);
			blobmsg_add_string(&bb, "type", allmac_type2str(entry->type));

			blobmsg_close_table(&bb, tt);
		}
	}

	blobmsg_close_table(&bb, t);
	ubus_send_reply(ctx, req, bb.head);
	blob_buf_free(&bb);

	return UBUS_STATUS_OK;
}

int cntlr_publish_dbg_object(struct controller *c, const char *objname)
{
	struct ubus_object *obj;
	struct ubus_object_type *obj_type;
	struct ubus_method *obj_methods;
	struct ubus_method m[] = {
		UBUS_METHOD_NOARG("list_macs", cntlr_dbg_list_macs),
	};
	int num_methods = ARRAY_SIZE(m);
	int ret;

	obj = &c->obj_dbg;
	memset(obj, 0, sizeof(*obj));

	obj_type = calloc(1, sizeof(struct ubus_object_type));
	if (!obj_type)
		return -1;

	obj_methods = calloc(num_methods, sizeof(struct ubus_method));
	if (!obj_methods) {
		free(obj_type);
		return -1;
	}

	obj->name = objname;
	memcpy(obj_methods, m, num_methods * sizeof(struct ubus_method));
	obj->methods = obj_methods;
	obj->n_methods = num_methods;

	obj_type->name = obj->name;
	obj_type->n_methods = obj->n_methods;
	obj_type->methods = obj->methods;
	obj->type = obj_type;

	ret = ubus_add_object(c->ubus_ctx, obj);
	if (ret) {
		err("Failed to add '%s' err = %s\n",
				objname, ubus_strerror(ret));
		free(obj_methods);
		free(obj_type);
		return ret;
	}

	info("Published '%s' object\n", objname);

	return 0;
}

void cntlr_remove_dbg_object(struct controller *c)
{
	if (c->ubus_ctx && c->obj_dbg.id != OBJECT_INVALID) {
		ubus_remove_object(c->ubus_ctx, &c->obj_dbg);
		free(c->obj_dbg.type);
		free((void *) c->obj_dbg.methods);
	}
}
#else
int cntlr_publish_dbg_object(struct controller *c, const char *objname)
{
	return 0;
}

void cntlr_remove_object(struct controller *c)
{
	return;
}
#endif /* MAP_CNTLR_DISABLE_UBUS_DBG */
