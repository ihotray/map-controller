/*
 * cntlr_ubus_dbg.h - for testing purpose only
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 */

#ifndef CNTLR_UBUS_DBG_H
#define CNTLR_UBUS_DBG_H

int cntlr_publish_dbg_object(struct controller *c, const char *objname);
void cntlr_remove_dbg_object(struct controller *c);

#endif /* CNTLR_UBUS_DBG_H */
