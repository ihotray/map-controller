/*
 * rcpi.c - RCPI based STA steering.
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * See LICENSE file for license related information.
 *
 */

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <libubox/list.h>

#include <easy/easy.h>
#include <wifidefs.h>
#include "wifi_dataelements.h"
#include "wifi_opclass.h"

#include "utils.h"
#include "debug.h"
#include "steer.h"

#define DEFAULT_RCPI_THRESHOLD 86
#define DEFAULT_RCPI_HYSTERESIS 5
#define DEFAULT_RCPI_DIFFSNR 8

struct rcpi_steer_control {
	uint8_t diffsnr;
	uint8_t low;
	uint8_t hysteresis;
	uint8_t rcpi_threshold;
	uint8_t max_btm_attempt;
	bool bandsteer;
	void *self;
};

static int rcpi_steer_init(void **priv);
static int rcpi_steer_config(void *priv, struct steer_config *cfg);
static int rcpi_steer_exit(void *priv);

static bool is_bandsteer_allowed(void *priv)
{
	struct rcpi_steer_control *sctrl = (struct rcpi_steer_control *)priv;

	if (sctrl->bandsteer)
		return true;

	return false;
}

int rcpi_steer(void *priv, struct steer_sta *s)
{
	trace("%s: --------->\n", __func__);

	struct rcpi_steer_control *sctrl = (struct rcpi_steer_control *)priv;
	struct wifi_sta_meas_report *b;
	uint8_t current_bss_rcpi = s->sta->rcpi;

	s->verdict = STEER_VERDICT_UNDECIDED;
	s->reason = STEER_REASON_UNDEFINED;
	s->mode = STEER_MODE_UNDEFINED;

	if (current_bss_rcpi >= sctrl->rcpi_threshold) {
		/* RCPI stil above threshold level */
		dbg("%s: RCPI above threshold level\n", __func__);
		s->verdict = STEER_VERDICT_NOK; /* TODO: STEER_VERDICT_MAYBE */
		return 0;
	}

	if (s->sta->mapsta.stats.failed_steer_attempts > sctrl->max_btm_attempt) {
		/* skip further checks for sticky candidates */
		s->verdict = STEER_VERDICT_EXCLUDE;
		return 0;
	}

	if (list_empty(s->meas_reportlist)) {
		dbg("%s: report list is empty\n", __func__);
		s->verdict = STEER_VERDICT_NOK;
		return 0;
	}

	/* Set temporary best - fresh for current BSS */
	s->best = NULL;
	list_for_each_entry(b, s->meas_reportlist, list) {
		if (!b->stale && !memcmp(b->bssid, s->bssid, 6)) {
			/* Current BSS's measurement is set as tmp best */
			current_bss_rcpi = b->rcpi;
			s->best = b;
			break;
		}
	}

	if (s->best == NULL) {
		/* Missing fresh meas for current BSS - use first non stale entry */
		list_for_each_entry(b, s->meas_reportlist, list) {
			if (!b->stale) {
				s->best = b;
				break;
			}
		}
	}

	if (s->best == NULL) {
		/* Only stale measurements on the list, do not steer */
		dbg("%s: missing fresh reports\n", __func__);
		s->verdict = STEER_VERDICT_NOK;
		return 0;
	}

	/* Find measurement with best RCPI on the list */
	list_for_each_entry(b, s->meas_reportlist, list) {
		if (b->rcpi > s->best->rcpi) {

			/* Use only non-stale measurements */
			if (b->stale) {
				dbg("%s: ignoring stale bcn report\n", __func__);
				continue;
			}

			if(!is_bandsteer_allowed(priv)
				/* Consider tBSS only from STA's current band */
				&& wifi_opclass_get_band(b->opclass) != s->band)
					continue;

			dbg("%s: new best bcn from "MACFMT" with rcpi %d\n",
			    __func__, MAC2STR(b->bssid), b->rcpi);

			s->best = b;
		}
	}

	if (s->best->rcpi - current_bss_rcpi < sctrl->diffsnr) {
		/* New best rcpi is not good enough */
		dbg("%s: best[%d] - curr[%d] < difssnr[%d]\n",
		    __func__, s->best->rcpi, current_bss_rcpi, sctrl->diffsnr);
		s->verdict = STEER_VERDICT_NOK;
		return 0;
	}

	/* Best bssid is a current one - no need to steer */
	if (!memcmp(s->best->bssid, s->bssid, 6)) {
		dbg("%s: own BSS is best - no need to steer\n", __func__);
		s->verdict = STEER_VERDICT_NOK;
		return 0;
	}

	s->reason = STEER_REASON_LOW_RCPI;
	s->verdict = STEER_VERDICT_OK;
	if (s->sta->mapsta.stats.failed_steer_attempts < sctrl->max_btm_attempt)
		s->mode = STEER_MODE_BTM_REQ;
	else if (s->sta->mapsta.stats.failed_steer_attempts == sctrl->max_btm_attempt)
		s->mode = STEER_MODE_ASSOC_CTL;

	return 0;
}

extern struct steer_control rcpi;
struct steer_control rcpi = {
	.name = "rcpi",
	.init = rcpi_steer_init,
	.config = rcpi_steer_config,
	.exit = rcpi_steer_exit,
	.steer = rcpi_steer,
};

static int rcpi_steer_init(void **priv)
{
	struct rcpi_steer_control *p;

	p = calloc(1, sizeof(struct rcpi_steer_control));
	if (!p)
		return -1;

	*priv = p;
	p->self = &rcpi;
	p->low = 90;
	/* Initial values to be updated with steer_config */
	p->rcpi_threshold = DEFAULT_RCPI_THRESHOLD;
	p->hysteresis = DEFAULT_RCPI_HYSTERESIS;
	p->diffsnr = DEFAULT_RCPI_DIFFSNR;
	p->max_btm_attempt = DEFAULT_MAX_BTM_ATTEMPT;

	dbg("%s: ========================>\n", __func__);
	return 0;
}

static int rcpi_steer_config(void *priv, struct steer_config *cfg)
{
	struct rcpi_steer_control *p = (struct rcpi_steer_control *)priv;

	if (!p)
		return -1;

	p->rcpi_threshold = cfg->rcpi_threshold;
	p->hysteresis = cfg->rcpi_hysteresis;
	p->diffsnr = cfg->rcpi_diffsnr;
	p->bandsteer = cfg->bandsteer;
	p->max_btm_attempt = cfg->max_btm_attempt;

	dbg("%s: <========================\n", __func__);

	return 0;
}

static int rcpi_steer_exit(void *priv)
{
	struct rcpi_steer_control *p = (struct rcpi_steer_control *)priv;

	if (p)
		free(p);

	dbg("%s: <========================\n", __func__);
	return 0;
}

