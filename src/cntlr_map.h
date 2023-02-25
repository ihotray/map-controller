
#ifndef CNTLR_MAP_H
#define CNTLR_MAP_H

/* defined in main.c */
extern int verbose;

extern bool is_cmdu_for_us(void *module, uint16_t type);

struct tlv_aladdr *map_cmdu_get_aladdr_tlv(struct cmdu_buff *cmdu);

extern int cntlr_handle_map_event(void *module, uint16_t cmdutype, uint16_t mid,
				  char *rxif, uint8_t *src, uint8_t *origin, uint8_t *tlvs,
				  int len);

void send_cmdu_cb(struct ubus_request *req, int type, struct blob_attr *msg);
int send_cmdu_ubus(struct controller *a, struct cmdu_buff *cmdu);
uint16_t send_cmdu(struct controller *a, struct cmdu_buff *cmdu);


extern int handle_link_metrics_response(struct controller *c, struct cmdu_buff *cmdu, struct node *n);

int cntlr_set_link_profile(struct controller *c, struct node *n, struct cmdu_buff *cmdu);


//struct cntlr_ackq_cookie *cntlr_alloc_ackq_cookie(struct cmdu_buff *cmdu);
//void cntlr_free_ackq_cookie(struct agent_ackq_cookie *c);
#endif /* CNTLR_MAP_H */
