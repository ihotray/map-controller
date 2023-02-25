#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <signal.h>
#include <time.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if_arp.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <libubox/list.h>
#include <json-c/json.h>

#include <easy/easy.h>
#include "utils/utils.h"
#include "utils/debug.h"
#include "allsta.h"

/* hash table of all active stas in the network */
struct hlist_head active_sta_htable[AS_HASHSIZE];

void as_init_table(struct hlist_head **as_table)
{
	*as_table = active_sta_htable;
}

int as_clean_entry(struct hlist_head *as_table, unsigned char *hwaddr,
						unsigned char *bssid)
{
	int hidx = as_hash(hwaddr);
	struct active_sta *as;

	as = as_lookup(as_table, hwaddr);
	if (!as)
		return 0;

	/* if it is an old event, only remove that bssid */
	if (memcmp(as->old_bssid, bssid, 6) == 0 &&
			memcmp(as->bssid, bssid, 6) != 0) {
		memset(as->old_bssid, 0, 6);
		return 0;
	}

	hlist_del(&as->hlist, &as_table[hidx]);
	dbg("Remove STA " MACFMT " from active STAs\n",
			MAC2STR(as->hwaddr));
	free(as);
	return 0;
}

struct active_sta *as_lookup_first_idx(struct hlist_head *as_table,
						const uint8_t *hwaddr)
{
	int hidx = as_hash(hwaddr);
	struct active_sta *as = NULL;

	hlist_for_each_entry(as, &as_table[hidx], hlist) {
		return as;
	}

	return NULL;
}

struct active_sta *as_lookup(struct hlist_head *as_table, unsigned char *hwaddr)
{
	int hidx = as_hash(hwaddr);
	struct active_sta *as = NULL;

	if (hwaddr_is_zero(hwaddr))
		return NULL;

	hlist_for_each_entry(as, &as_table[hidx], hlist) {
		if (!memcmp(hwaddr, as->hwaddr, 6))
			return as;
	}

	return NULL;
}

static struct active_sta *create_entry(struct hlist_head *as_table,
				unsigned char *hwaddr, unsigned char *bssid)
{
	/* unsigned char masked_hwaddr[6] = {0}; */
	int hidx = as_hash(hwaddr);
	struct active_sta *as;

	as = calloc(1, sizeof(struct active_sta));
	if (!as) {
		warn("OOM: active_sta calloc failed!\n");
		return NULL;
	}

	memcpy(as->hwaddr, hwaddr, 6);
	memcpy(as->bssid, bssid, 6);
	as->best_nbr_rssi = -127;

	hlist_add_head(&as->hlist, &as_table[hidx]);
	return as;
}

struct active_sta *as_insert(struct hlist_head *as_table, unsigned char *hwaddr,
						unsigned char *bssid)
{
	struct active_sta *as;

	as = as_lookup(as_table, hwaddr);
	if (as) {
		dbg("Set STA " MACFMT " bssid to " MACFMT "\n",
				MAC2STR(hwaddr), MAC2STR(bssid));

		if (memcmp(as->bssid, bssid, 6) != 0)
			memcpy(as->old_bssid, as->bssid, 6);
		memcpy(as->bssid, bssid, 6);
		return as;
	}

	as = create_entry(as_table, hwaddr, bssid);
	if (as)
		dbg("Add STA "
			MACFMT " with bssid " MACFMT "\n",
			MAC2STR(hwaddr),
			MAC2STR(bssid));

	return as;
}

void as_print(struct hlist_head *as_table)
{
	struct active_sta *as;
	int i;

	dbg("Currently active STAs:\n");
	for (i = 0; i < AS_HASHSIZE; i++) {
		if (hlist_empty(&as_table[i]))
			continue;

		hlist_for_each_entry(as, &as_table[i], hlist) {
			dbg("Active STA: " MACFMT ", connected to: "
				MACFMT " (old " MACFMT ")\n",
				MAC2STR(as->hwaddr),
				MAC2STR(as->bssid),
				MAC2STR(as->old_bssid));
		}
	}
}
