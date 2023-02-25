/*
 * steer.h - header for defining a new steering module
 *
 * Copyright (C) 2022 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 * See LICENSE file for license related information.
 *
 */

#ifndef STEER_H
#define STEER_H

#include <stdint.h>
#include <libubox/list.h>


#ifdef __cplusplus
extern "C" {
#endif

#define DEFAULT_MAX_BTM_ATTEMPT 3

enum steer_verdict {
	STEER_VERDICT_UNDECIDED,
	STEER_VERDICT_OK,
	STEER_VERDICT_MAYBE,
	STEER_VERDICT_NOK,
	STEER_VERDICT_EXCLUDE,
};

enum steer_reason {
	STEER_REASON_UNDEFINED,
	STEER_REASON_LOW_RCPI,
	STEER_REASON_LOW_THPUT,
	STEER_REASON_HIGH_PER,
	STEER_REASON_OTHER,
};

enum steer_mode {
	STEER_MODE_UNDEFINED,
	STEER_MODE_BTM_REQ,
	STEER_MODE_ASSOC_CTL,
	STEER_MODE_OPPORTUNITY,
};

typedef enum steer_verdict steer_verdict_t;
typedef enum steer_reason steer_reason_t;
typedef enum steer_mode steer_mode_t;

struct steer_config {
	uint8_t rcpi_threshold;
	uint8_t rcpi_hysteresis;
	uint8_t rcpi_diffsnr;
	uint8_t ch_utilization;
	uint8_t max_btm_attempt;
	bool bandsteer;
};

struct steer_sta {
	struct wifi_sta_element *sta;
	struct list_head *nbrlist;
	struct list_head *meas_reportlist;
	steer_verdict_t verdict;
	struct wifi_sta_meas_report *best;
	steer_reason_t reason;
	uint32_t mode;
	uint8_t band;
	uint8_t bssid[6];
};

struct steer_control {
	char name[64];
	//uint8_t rcpi_threshold;
	//uint8_t rcpi_hysteresis;
	uint8_t cbinterval;
	void *priv;
	int (*init)(void **);
	int (*exit)(void *);
	int (*steer)(void *, struct steer_sta *candidate);
	int (*config)(void *, struct steer_config *);
	void *handle;
	struct list_head list;
};


#ifdef __cplusplus
}
#endif

#endif /* STEER_H */
