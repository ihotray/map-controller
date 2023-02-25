/*
 * utils.h - utility functions header
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#ifndef UTILS_H
#define UTILS_H

#include <time.h>
#include <stdbool.h>
#include <json-c/json.h>
#include <libubox/list.h>

#ifndef BIT
#define BIT(x)  (1 << (x))
#endif

#define _S(v)	#v
#define S(v)	_S(v)

#define hwaddr_hash(a)	(a[0] ^ a[1] ^ a[2] ^ a[3] ^ a[4] ^ a[5])


#define print_bits(x, len, s) \
do { \
	unsigned long long a__ = (x); \
	size_t bits__ = sizeof(x) * len; \
	while (bits__--) { \
		putchar(a__ & (1 << bits__) ? '1' : '0'); \
		if (!(bits__ % s)) \
			putchar(' '); \
		} \
	putchar('\n'); \
} while (0)

bool match_oui0(const uint8_t *oui, const uint8_t *hwaddr, int ouis);
unsigned char *hwaddr_aton(const char *macstr, unsigned char *mac);
char *hwaddr_ntoa(const unsigned char *mac, char *macstr);
int hwaddr_from_ip(char *ifname, char *ipstr, unsigned char *hw);

void timestamp_reset(struct timespec *ts);
void timestamp_update(struct timespec *ts);
int timestamp_invalid(struct timespec *ts);
uint32_t timestamp_elapsed_sec(struct timespec *ts);
int timestamp_expired(struct timespec *a, unsigned int tmo_ms);
char *time_to_timestamp(time_t *t, char *tsp);
time_t timestamp_to_time(const char *tsp);
struct timespec time_to_timespec(time_t *t);
struct timespec timestamp_to_timespec(const char *tsp, bool adj_rtime);

/* bytes from-to hexstring helper functions */
int hex2byte(const char *hex);
unsigned char *strtob(char *str, int len, unsigned char *bytes);

/* utility wrappers over json-c functions */
int json_get_bool(struct json_object *object, const char *key);
int json_get_int(struct json_object *object, const char *key);
const char *json_get_string(struct json_object *object, const char *key);


/* list utility functions and macros */

#define list_flush(head, type, member)					\
do {									\
	type *__p, *__tmp;						\
									\
	if (!list_empty(head))						\
		list_for_each_entry_safe(__p, __tmp, head, member) {	\
			list_del(&__p->member);				\
			free(__p);					\
		}							\
} while (0)

/**
 * list_func - pointer to private list function type for list manipulation
 */
typedef int (*list_func)(struct list_head *a, struct list_head *b);

/**
 * list_join - joins two sorted lists
 * @a:		head of the first list
 * @b:		head of second list
 * @join:	private join function of type @list_func, which defines the
 *		criteria how the final list is going to be ordered.
 *		The resultant list is stored in @a
 */
#define list_join(a, b, join)						\
do {									\
	struct list_head *p, *q, *t1, *t2;				\
	typeof((list_func) join) __join = (join);			\
									\
	list_for_each_safe(p, t1, a) {					\
		list_for_each_safe(q, t2, b) {				\
			if (__join && __join(p, q) <= 0)		\
				list_move(q, p->prev);			\
		}							\
	}								\
	if (!list_empty(b))						\
		list_splice_tail(b, a);					\
} while (0)

/**
 * list_uniq - remove duplicate entries from a list
 * @a:		head of the list
 * @match:	private match function of type @list_func for duplicate checking
 * @merge:	private merge function of type @list_func for merging duplicate
 *		entries
 */
#define list_uniq(a, match, merge)				\
do {								\
	struct list_head *e, *p, *t, *n;			\
	typeof((list_func) match) __match = (match);		\
	typeof((list_func) merge) __merge = (merge);		\
								\
	list_for_each(e, a) {					\
		p = e;						\
		list_for_each_safe(n, t, p) {			\
			if (__match && __match(e, n)) {		\
				list_del(n);			\
				if (__merge)			\
					__merge(e, n);		\
				/* break; */			\
			}					\
		}						\
	}							\
} while (0)

int list_join_uniq(void *priv, struct list_head *a, struct list_head *b,
		struct list_head *out,
		int (*match)(void *priv, struct list_head *a,
				struct list_head *b),
		struct list_head *(*create_jentry)(void *priv,
				struct list_head *a, struct list_head *b),
		void (*free_jentry)(void *priv, struct list_head *),
		void (*free_entry_a)(struct list_head *),
		void (*free_entry_b)(struct list_head *));

int list_num_entries(struct list_head *h);

int list_dup(struct list_head *h, struct list_head *new,
		void *(*alloc_entry)(void),
		void (*free_entry)(struct list_head *n),
		void (*copy_entry)(struct list_head *from,
				struct list_head *to));


int set_sighandler(int sig, void (*handler)(int));
int unset_sighandler(int sig);
void do_daemonize(const char *pidfile);


int writeto_configfile(const char *filename, void *in, size_t len);
int readfrom_configfile(const char *filename, uint8_t **out, uint32_t *olen);

uint8_t rssi_to_rcpi(int rssi);
int rcpi_to_rssi(uint8_t rcpi);

bool is_vid_valid(uint16_t vid);

#endif /* UTILS_H */
