#ifndef ALLSTA_H
#define ALLSTA_H

#define AS_HASHSIZE 64

#define as_hash(a) ((a[3] ^ a[4] ^ a[5]) % AS_HASHSIZE)

/* struct active_sta - active sta entry */
struct active_sta {
	unsigned char hwaddr[6];
	unsigned char bssid[6];
	unsigned char old_bssid[6];

	int lowrssi;
	int best_nbr_rssi;
	unsigned char best_nbr[6];

	struct hlist_node hlist;
};

void as_init_table(struct hlist_head **as_table);
struct active_sta *as_lookup_first_idx(struct hlist_head *h,
		const uint8_t *hwaddr);
int as_clean_entry(struct hlist_head *h, unsigned char *hwaddr,
		unsigned char *bssid);
struct active_sta *as_lookup(struct hlist_head *h, unsigned char *hwaddr);
struct active_sta *as_insert(struct hlist_head *h, unsigned char *hwaddr,
				unsigned char *bssid);
void as_print(struct hlist_head *h);

#endif /* ALLSTA_H */
