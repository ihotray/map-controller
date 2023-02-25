#ifndef ALLMAC_H
#define ALLMAC_H

#define MAC_HTBL_SIZE 64

/* Use hash function to get set of shorter lists */
#ifndef MAC_ADDR_HASH
#define MAC_ADDR_HASH(a)    (a[0] ^ a[1] ^ a[2] ^ a[3] ^ a[4] ^ a[5])
#endif

#define mac_hash(a,t)     \
	((MAC_ADDR_HASH(a) ^ (t)) % (MAC_HTBL_SIZE))

enum allmac_type {
	MAC_ENTRY_UNKNOWN = 0,		/**< type unset or unknown */
	MAC_ENTRY_FBSS,				/**< fronthaul iface MAC */
	MAC_ENTRY_BSTA,				/**< backhaul STA MAC */
	MAC_ENTRY_ALID,				/**< node alid MAC */
	MAC_ENTRY_RADIO,			/**< radio MAC */
	_MAC_ENTRY_MAX
};

struct allmac_htable {
	/* hash table of all mac addresses in the network */
	struct hlist_head table[MAC_HTBL_SIZE];
};

/* struct map_macaddr_entry - mac addr entry */
struct map_macaddr_entry {
	uint8_t macaddr[6];
	enum allmac_type type;
	void *data; /* points to data depending on type */

	struct hlist_node hlist;
};

const char *allmac_type2str(enum allmac_type type);
void allmac_init_table(void *htbl);
void allmac_clean_table(void *htbl);
int allmac_clean_entry(void *htbl, unsigned char *macaddr,
		enum allmac_type type);
struct map_macaddr_entry *allmac_lookup(void *htbl,
		unsigned char *macaddr, enum allmac_type type);
struct map_macaddr_entry *allmac_insert(void *htbl,
		unsigned char *macaddr, enum allmac_type type, void *data);
void allmac_print(void *htbl);

#endif /* ALLMAC_H */
