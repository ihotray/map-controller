/*
 * steer_module.h - header for steering related stuff
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef STEER_MODULE_H
#define STEER_MODULE_H

#include <stdint.h>
#include <libubox/list.h>

#ifdef __cplusplus
extern "C" {
#endif

#include "steer.h"

#define STEER_ATTEMPT_MIN_ITV		(30 * 1000) 		/* 30 secs */
#define STEER_SUCCESS_MIN_ITV		(3  * 60 * 1000)	/* 3 minutes */
#define STEER_ATTEMPT_STICKY_ITV	(10 * 60 * 1000)	/* 10 minutes */

struct steer_control *cntlr_get_steer_control(struct controller *c);

void cntlr_assign_steer_module_default(struct controller *c);
void cntlr_assign_steer_module(struct controller *c, const char *name);

int cntlr_register_steer_module(struct controller *c, const char *name);
int cntlr_unregister_steer_module(struct controller *c, char *name);
int cntlr_configure_steer_module(struct controller *c, struct steer_config *cfg);
int cntlr_maybe_steer_sta(struct controller *c, struct steer_sta *s);


#ifdef __cplusplus
}
#endif

#endif /* STEER_MODULE_H */
