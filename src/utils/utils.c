/*
 * utils.c - implements utility functions
 *
 * Copyright (C) 2019 IOPSYS Software Solutions AB. All rights reserved.
 *
 * Author: anjan.chanda@iopsys.eu
 *
 */

#include <stdio.h>
#include <string.h>
#include <signal.h>
#define __USE_XOPEN
#include <time.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libubox/list.h>
#include <json-c/json.h>

#include "debug.h"

bool match_oui0(const uint8_t *oui, const uint8_t *hwaddr, int ouis)
{
	int i;

	for (i = 0; i < ouis; i++) {
		if (oui[i] == hwaddr[0])
			return true;
	}

	return false;
}

static int hex2num(char c)
{
	if (c >= '0' && c <= '9')
		return c - '0';
	if (c >= 'a' && c <= 'f')
		return c - 'a' + 10;
	if (c >= 'A' && c <= 'F')
		return c - 'A' + 10;
	return -1;
}

int hex2byte(const char *hex)
{
	int a, b;

	a = hex2num(*hex++);
	if (a < 0)
		return -1;

	b = hex2num(*hex++);
	if (b < 0)
		return -1;

	return (a << 4) | b;
}

/* convert hex string to byte array */
unsigned char *strtob(char *str, int len, unsigned char *bytes)
{
	size_t i;

	for (i = 0; i < len; i++) {
		int a;

		a = hex2byte(str);
		if (a < 0)
			return NULL;

		str += 2;
		bytes[i] = a;
	}

	return bytes;
}

/* Convert "00:11:22:33:44:55" --> \x001122334455 */
unsigned char *hwaddr_aton(const char *macstr, unsigned char *mac)
{
	size_t i;

	for (i = 0; i < 6; i++) {
		int a;

		a = hex2byte(macstr);
		if (a < 0)
			return NULL;

		macstr += 2;
		mac[i] = a;
		if (i < 6 - 1 && *macstr++ != ':')
			return NULL;
	}
	return mac;
}

/* Convert \x001122334455 --> "00:11:22:33:44:55" */
char *hwaddr_ntoa(const unsigned char *mac, char *macstr)
{
	sprintf(macstr, "%02x:%02x:%02x:%02x:%02x:%02x",
			mac[0]&0xff, mac[1]&0xff,
			mac[2]&0xff, mac[3]&0xff,
			mac[4]&0xff, mac[5]&0xff);

	return macstr;
}

/**
 * Get hw address from ip address using ARP cache
 * @ifname:		interface name
 * @ipstr:		ipaddress in dotted decimal string format
 * @hw:			hwaddress returned from arp cache lookup
 */
int hwaddr_from_ip(char *ifname, char *ipstr, unsigned char *hw)
{
	int s;
	struct arpreq r;
	struct in_addr ip;
	struct sockaddr_in *sin;

	if (!ifname)
		return -1;

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
		return -1;

	inet_aton(ipstr, &ip);
	memset(&r, 0, sizeof(struct arpreq));
	snprintf(r.arp_dev, 16, "%s", ifname);
	sin = (struct sockaddr_in *)&r.arp_pa;
	sin->sin_family = AF_INET;
	memcpy(&sin->sin_addr, &ip, sizeof(struct in_addr));
	if (ioctl(s, SIOCGARP, &r) < 0) {
		close(s);
		return -1;
	}

	memcpy(hw, r.arp_ha.sa_data, 6);
	close(s);
	return 0;
}

void timestamp_reset(struct timespec *ts)
{
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
}

void timestamp_update(struct timespec *ts)
{
	if (clock_gettime(CLOCK_REALTIME, ts) < 0) {
		ts->tv_sec = 0;
		ts->tv_nsec = 0;
	}
}

int timestamp_invalid(struct timespec *ts)
{
	return ts->tv_sec == 0 && ts->tv_nsec == 0;
}

/* Time difference in seconds */
uint32_t timestamp_elapsed_sec(struct timespec *ts)
{
	struct timespec now;
	uint32_t elapsed;

	if (ts->tv_sec == 0)
		return -1;

	/* seconds and nanoseconds since the Epoch */
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		now.tv_sec = 0;

	elapsed = now.tv_sec - ts->tv_sec;

	return (elapsed > 0) ? elapsed : 0;
}

/* check if timestamp expired */
int timestamp_expired(struct timespec *a, unsigned int tmo_ms)
{
	struct timespec now;
	unsigned long diff_ns = 0, diff_s = 0;

	/* seconds and nanoseconds since the Epoch */
	if (clock_gettime(CLOCK_REALTIME, &now) < 0)
		return -1;

	diff_s = now.tv_sec - a->tv_sec;
	diff_ns = now.tv_nsec - a->tv_nsec;
	if ((long)diff_ns < 0) {
		diff_ns += 1000000000UL;
		diff_s--;
	}

	if (diff_s * 1000 + diff_ns / 1000000 >= tmo_ms)
		return 1;

	return 0;
}

char *time_to_timestamp(time_t *t, char *tsp)
{
	char tmpbuf[64] = {0};
	struct tm res;
	char sign;
	long int toff, toff_hour, toff_min;

	if (!tsp)
		return NULL;

	/* E.g. "2019-02-11T06:42:31.23039-08:00" */

	localtime_r(t, &res);
	tzset();
	toff = timezone;
	sign = toff > 0 ? '-' : '+';
	toff *= -1L;

	toff_hour = toff / 3600;
	toff_min = (toff % 3600) / 60;

	snprintf(tmpbuf, sizeof(tmpbuf), "%04d-%02d-%02dT%02d:%02d:%02d%c%02ld:%02ld",
			 res.tm_year + 1900, res.tm_mon + 1, res.tm_mday,
			 res.tm_hour, res.tm_min, res.tm_sec,
			 sign, toff_hour, toff_min);

	snprintf(tsp, 64, "%s", tmpbuf);
	return tsp;
}

/* get time adjustment seconds (time(tzone) - time(UTC) secs) */
static long int timestamp_get_off_sec(const char *tsp)
{
	char *tzone;
	long int toff = 0, sign;
	int toff_hour, toff_min;

	/* Example timestamp: "2019-02-11T06:42:31-08:00" */

	tzone = strchr(tsp, '+');
	if (!tzone) {
		tzone = strrchr(tsp, '-'); /* last occurence */
		sign = -1L;
	} else {
		sign = +1L;
	}

	if (tzone) {
		sscanf(tzone+1, "%02d:%02d", &toff_hour, &toff_min);
		toff = toff_hour * 3600 + toff_min * 60; // seconds
		toff *= -sign;
	}

	return toff;
}

time_t timestamp_to_time(const char *tsp)
{
	struct tm tm_time;
	time_t res;

	/* Example timestamp: "2019-02-11T06:42:31-08:00" */
	memset(&tm_time, 0, sizeof(tm_time));
	strptime(tsp, "%Y-%m-%dT%H:%M:%S", &tm_time);

	tzset();
	res = mktime(&tm_time);

	/* Allign by toff to get UTC+0 */
	res += timestamp_get_off_sec(tsp);

	return res;
}

struct timespec time_to_timespec(time_t t)
{
	struct timespec res = {};

	res.tv_sec = t;
	res.tv_nsec = 0;

	return res;
}

/* converts timestamp string to timespec struct
 * adj_rtime true: adjust for realtime (ignore off time)
 */
struct timespec timestamp_to_timespec(const char *tsp, bool adj_rtime)
{
	time_t tt = 0;

	tt = timestamp_to_time(tsp);
	if (adj_rtime)
		tt -= timestamp_get_off_sec(tsp);

	return time_to_timespec(tt);
}


/** list utility functions */
/**
 * list_num_entries - gets number of entries on the list
 * @h:			head of the list
 */
int list_num_entries(struct list_head *h)
{
	struct list_head *e;
	int count = 0;

	list_for_each(e, h)
		count++;

	return count;
}

/**
 * list_dup - duplicates a list
 * @h:			head of the list
 * @new:		head of the duplicate list
 * @alloc_entry:	function to allocate a new entry
 * @free_entry:		function to free entry in case of error
 * @copy_entry:		function to copy an entry
 */
int list_dup(struct list_head *h, struct list_head *new,
		void *(*alloc_entry)(void),
		void (*free_entry)(struct list_head *n),
		void (*copy_entry)(struct list_head *from,
				struct list_head *to))
{
	struct list_head *p, *tmp, *n;

	if (!alloc_entry || !copy_entry)
		return -1;

	list_for_each(p, h) {
		n = alloc_entry();
		if (!n)
			goto rollback_list_dup;

		copy_entry(p, n);
		list_add_tail(n, new);
	}

	return 0;

rollback_list_dup:
	list_for_each_safe(p, tmp, new) {
		list_del(p);
		if (free_entry)
			free_entry(p);
	}
	return -1;
}

/**
 * list_join_uniq - joins two lists merging duplicates based on 'match' criteria
 * @priv:               opaque private data
 * @a:			head of the first list
 * @b:			head of second list
 * @out:		head of the final joined list
 * @match:		matching function which determines duplicate entries
 * @create_entry:	function to create combined merged entry
 * @free_entry:		function to free combined merged entry in case on error
 */
int list_join_uniq_strict(void *priv, struct list_head *a, struct list_head *b,
		struct list_head *out,
		int (*match)(void *priv,
				struct list_head *a, struct list_head *b),
		struct list_head *(*create_entry)(void *priv,
				struct list_head *a, struct list_head *b),
		void (*free_entry)(void *priv, struct list_head *a))
{
	struct list_head *p, *q, *t1, *t2, *n;

	if (!create_entry || !free_entry)
		return -1;

	list_for_each_safe(p, t1, a) {
		list_for_each_safe(q, t2, b) {
			if (match && match(priv, p, q)) {
				n = create_entry(priv, p, q);
				if (!n)
					goto err_list_join_uniq;
				list_add_tail(n, out);
			}
		}
	}
#if 0    /* because returns only matching entries */
	list_for_each_safe(p, t1, a) {
		n = create_entry(priv, p, NULL);
		if (!n)
			goto err_list_join_uniq;
		list_add_tail(n, out);
		list_del(p);
	}
	list_for_each_safe(q, t1, b) {
		n = create_entry(priv, NULL, q);
		if (!n)
			goto err_list_join_uniq;
		list_add_tail(n, out);
		list_del(q);
	}
#endif

	return 0;

err_list_join_uniq:
	list_for_each_safe(p, t1, out) {
		list_del(p);
		free_entry(priv, p);
	}

	return -1;
}

int list_join_uniq(void *priv, struct list_head *a, struct list_head *b,
		struct list_head *out,
		int (*match)(void *priv, struct list_head *a,
				struct list_head *b),
		struct list_head *(*create_jentry)(void *priv,
				struct list_head *a, struct list_head *b),
		void (*free_jentry)(void *priv, struct list_head *),
		void (*free_entry_a)(struct list_head *),
		void (*free_entry_b)(struct list_head *))
{
	struct list_head *p, *q, *t1, *t2, *n;

	if (!create_jentry || !free_jentry)
		return -1;

	list_for_each_safe(p, t1, a) {
		list_for_each_safe(q, t2, b) {
			if (match && match(priv, p, q)) {
				n = create_jentry(priv, p, q);
				if (!n)
					goto err_list_join_uniq;
				list_add_tail(n, out);
				list_del(p);
				free_entry_a(p);
				list_del(q);
				free_entry_b(q);
			}
		}
	}

	list_for_each_safe(p, t1, a) {
		n = create_jentry(priv, p, NULL);
		if (!n)
			goto err_list_join_uniq;
		list_add_tail(n, out);
		list_del(p);
		free_entry_a(p);
	}
	list_for_each_safe(q, t1, b) {
		n = create_jentry(priv, NULL, q);
		if (!n)
			goto err_list_join_uniq;
		list_add_tail(n, out);
		list_del(q);
		free_entry_b(q);
	}

	return 0;

err_list_join_uniq:
	list_for_each_safe(p, t1, out) {
		list_del(p);
		free_jentry(priv, p);
	}
	return -1;
}

/* daemonize process */
void do_daemonize(const char *pidfile)
{
	char buf[128] = {0};
	int flags;
	int f;

	info("daemonizing ...\n");
	daemon(0, 0);

	if (!pidfile)
		return;

	f = open(pidfile, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (f) {
		flags = fcntl(f, F_GETFD);
		if (flags != -1) {
			flags |= FD_CLOEXEC;
			fcntl(f, F_SETFD, flags);
		}
		if (lockf(f, F_TLOCK, 0) < 0) {
			fprintf(stderr, "File '%s' exists. Aborting...\n",
					pidfile);
			exit(-1);
		}
		ftruncate(f, 0);
		snprintf(buf, sizeof(buf), "%ld\n", (long)getpid());
		write(f, buf, strlen(buf));
	}
}

/* install a signal handler */
int set_sighandler(int sig, void (*handler)(int))
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = handler;
	if (sigaction(sig, &sa, NULL) < 0) {
		fprintf(stderr, "Error sigaction %d\n", sig);
		return -1;
	}

	return 0;
}

/* uninstall a signal handler */
int unset_sighandler(int sig)
{
	struct sigaction sa;

	memset(&sa, 0, sizeof(sa));
	sa.sa_flags = 0;
	sigemptyset(&sa.sa_mask);
	sa.sa_handler = SIG_DFL;

	return sigaction(sig, &sa, NULL);
}

/* json helpers copied from uproxyd.c */
const char *json_get_string(struct json_object *object, const char *key)
{
	json_bool ret;
	struct json_object *value;

	if (!object || !json_object_is_type(object, json_type_object))
		return NULL;

	ret = json_object_object_get_ex(object, key, &value);
	if (!ret || !value || !json_object_is_type(value, json_type_string))
		return NULL;

	return json_object_get_string(value);
}

int json_get_int(struct json_object *object, const char *key)
{
	json_bool ret;
	struct json_object *value;

	if (!object || !json_object_is_type(object, json_type_object))
		return -1;

	ret = json_object_object_get_ex(object, key, &value);
	if (!ret || !value || !json_object_is_type(value, json_type_int))
		return -1;

	return json_object_get_int(value);

}

int json_get_bool(struct json_object *object, const char *key)
{
	json_bool ret;
	struct json_object *value;

	if (!object || !json_object_is_type(object, json_type_object))
		return -1;

	ret = json_object_object_get_ex(object, key, &value);
	if (!ret || !value || !json_object_is_type(value, json_type_boolean))
		return -1;

	return json_object_get_boolean(value) ? 1 : 0;

}

int readfrom_configfile(const char *filename, uint8_t **out, uint32_t *olen)
{
	struct stat sb;
	size_t rem;
	ssize_t res = 0;
	uint8_t *pos;
	int ret;
	int fp;



	*olen = 0;
	ret = stat(filename, &sb);
	if (ret == -1)
		return -1;

	fp = open(filename, O_RDONLY);
	if (!fp)
		return -1;

	*out = calloc(1, sb.st_size);
	if (!*out) {
		close(fp);
		return -1;
	}

	*olen = sb.st_size;
	rem = *olen;
	pos = *out;
	while (rem != 0) {
		res = read(fp, pos, rem);
		if (res == -1)
			continue;

		pos += res;
		rem -= res;
	}

	close(fp);
	return 0;
}

int writeto_configfile(const char *filename, void *in, size_t len)
{
	ssize_t rem = 0;
	int fp;


	fp = open(filename, O_WRONLY | O_CREAT);
	if (fp < 0)
		return -1;

	if (!in || len == 0) {
		close(fp);
		return 0;
	}

	while (len != 0) {
		rem = write(fp, in, len);
		if (rem == -1)
			continue;

		len -= rem;
		in = (uint8_t *)in + rem;
	}

	close(fp);
	return 0;
}

uint8_t rssi_to_rcpi(int rssi)
{
    if (!rssi)
        return 255;
    else if (rssi < -110)
        return 0;
    else if (rssi > 0)
        return 220;
    else
        return (rssi + 110) * 2;
}

int rcpi_to_rssi(uint8_t rcpi)
{
	/* FIXME: */

	if (rcpi > 220)
		return 0;
	else
		return ((rcpi / 2) - 110);
}

#define TS_VID_INVALID 0x0FFF
bool is_vid_valid(uint16_t vid)
{
	return (vid < TS_VID_INVALID) && (vid > 0);
}
