/*
 * cntlr_acs.c - Auto Channel Selection header
 *
 * Copyright (C) 2021 IOPSYS Software Solutions AB. All rights reserved.
 *
 */
#ifndef CNTLR_ACS_
#define CNTLR_ACS_

struct acs_params {
	int opclass;
	int bw;

	bool skip_dfs;
	bool skip_dfs_not_available;

	int best_channel;
	int best_opclass;
	int best_bw;
	int best_pref;
};

int cntlr_acs_radio_channel_recalc(struct wifi_radio_element *radio, struct acs_params *params);
void cntlr_acs_node_channel_recalc(struct node *node, bool skip_dfs);
void cntlr_dfs_node_cleanup(struct node *node);
void cntlr_acs_recalc(struct controller *c, bool skip_dfs);
void cntlr_dfs_cleanup(struct controller *c);
#endif
