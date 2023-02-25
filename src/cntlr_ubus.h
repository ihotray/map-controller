/*
 * cntlr_ubus.h - cntlr's ubus object header
 *
 * Copyright (C) 2020 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef CNTLR_UBUS_H
#define CNTLR_UBUS_H

void cntlr_notify_event(struct controller *c, void *ev_type,
		void *ev_data);

extern int cntlr_publish_object(struct controller *c, const char *objname);
extern void cntlr_remove_object(struct controller *c);
extern int cntlr_register_module(struct controller *c);


int ubus_call_object(struct controller *c, uint32_t obj,
		     const char *method,
		     void (*response_cb)(struct ubus_request *, int, struct blob_attr *),
		     void *priv);


int cntlr_wait_for_object_timeout(struct controller *c, void *object,
				  uint32_t tmo_msecs, void *res);

int ieee1905_buildcmdu_linkmetric_resp(struct controller *c, uint16_t msg_type);

int cntlr_get_ieee1905_almac(struct controller *c, uint8_t *almac);

#endif /* CNTLR_UBUS_H */
