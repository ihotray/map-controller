#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include <easy/easy.h>
#include "utils/utils.h"
#include "utils/debug.h"
#include "allmac.h"


extern void allmac_init_table(void *htbl)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	int i;

	for (i = 0; i < MAC_HTBL_SIZE; i++) {
		INIT_HLIST_HEAD(&htable->table[i]);
	}
}

void allmac_clean_table(void *htbl)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	struct map_macaddr_entry *entry = NULL;
	struct hlist_node *tmp;
	int i;

	for (i = 0; i < MAC_HTBL_SIZE; i++) {
		hlist_for_each_entry_safe(entry, tmp, &htable->table[i], hlist) {
			hlist_del(&entry->hlist, &htable->table[i]);
			free(entry);
		}
	}
}

const char *allmac_type2str(enum allmac_type type)
{
	switch (type) {
	case MAC_ENTRY_FBSS:
		return "fbss";
	case MAC_ENTRY_BSTA:
		return "bsta";
	case MAC_ENTRY_ALID:
		return "alid";
	case MAC_ENTRY_RADIO:
		return "radio";
	case MAC_ENTRY_UNKNOWN:
	default:
		return "unknown";
	}
}

/* Call this function when fbss/bsta/radio/node is removed from mesh */
int allmac_clean_entry(void *htbl, unsigned char *macaddr, enum allmac_type type)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	struct map_macaddr_entry *entry = NULL;
	int hidx;

	if (hwaddr_is_zero(macaddr))
		return -1;

	/* Type must be defined for 'clean' to avoid overcomplicated logic */
	if(WARN_ON(type == MAC_ENTRY_UNKNOWN
			|| type >= _MAC_ENTRY_MAX))
		return -1;

	entry = allmac_lookup(htbl, macaddr, type);
	if (!entry)
		/* Already removed or absent */
		return 0;

	hidx = mac_hash(macaddr, type);
	hlist_del(&entry->hlist, &htable->table[hidx]);
	dbg("Remove MAC "
	    MACFMT " of type %s from MAC hashtable\n",
	    MAC2STR(macaddr),
	    allmac_type2str(type));
	free(entry);
	return 0;
}

static struct map_macaddr_entry *empty_entry_with_dbg(
		unsigned char *macaddr, enum allmac_type type)
{
	/* No entry found for this type & MAC pair */
	dbg("Couldn't find allmac entry for MAC addr "
	    MACFMT " of type %s\n",
	    MAC2STR(macaddr),
	    allmac_type2str(type));

	return NULL;
}

struct map_macaddr_entry *allmac_lookup(void *htbl,
		unsigned char *macaddr, enum allmac_type type)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	struct map_macaddr_entry *entry = NULL;
	int hidx;

	if (hwaddr_is_zero(macaddr)) {
		dbg("%s: Only non zero MAC addresses supported!\n", __func__);
		return NULL;
	}

	if(WARN_ON(type >= _MAC_ENTRY_MAX)) {
		dbg("%s: Unsupported MAC type %d!\n", __func__, type);
		return NULL;
	}

	if (type != MAC_ENTRY_UNKNOWN) {
		/* For known type just lookup hashed row */
		hidx = mac_hash(macaddr, type);
		if (hlist_empty(&htable->table[hidx]))
			/* row for this hash has no entries yet, lookup before insert ? */
			return empty_entry_with_dbg(macaddr, type);

		hlist_for_each_entry(entry, &htable->table[hidx], hlist) {
			if (!memcmp(macaddr, entry->macaddr, 6))
				/* entry found */
				return entry; /* SUCCESS */
		}

		/* entry of known type NOT found */
		return empty_entry_with_dbg(macaddr, type);
	}

	/* For unknown type return first entry of ANY type with matching MAC */
	for (hidx = 0; hidx < MAC_HTBL_SIZE; hidx++) {
		/* search all non-empty rows */
		if (hlist_empty(&htable->table[hidx]))
			/* skip empty rows in hash array */
			continue;

		hlist_for_each_entry(entry, &htable->table[hidx], hlist) {
			if (!memcmp(macaddr, entry->macaddr, 6))
				return entry; /* SUCCESS */
		}
	}

	/* no entry with that macaddr found in whole hash array */
	return empty_entry_with_dbg(macaddr, type);
}

/* Call this function when fbss/bsta/radio/node is added to the mesh */
struct map_macaddr_entry *allmac_insert(void *htbl,
		unsigned char *macaddr, enum allmac_type type, void *data)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	struct map_macaddr_entry *entry = NULL;
	int hidx;

	if (hwaddr_is_zero(macaddr))
		return NULL;

	/* Type must be defined for 'insert' to avoid overcomplicated logic */
	if(WARN_ON(type == MAC_ENTRY_UNKNOWN
			|| type >= _MAC_ENTRY_MAX))
		return NULL;

	entry = allmac_lookup(htbl, macaddr, type);
	if (entry) {
		/* Same MAC entry reinserted - likely an error in cntlr */
		dbg("%s: MAC "
		    MACFMT " of type %s already on the list!\n",
		    __func__, MAC2STR(macaddr), allmac_type2str(entry->type));

		/* Expected same type, otherwise hash func must be broken */
		WARN_ON(entry->type != type);

		/* Let's update data pointer anyway */
		entry->data = data;

		return entry;
	}

	entry = calloc(1, sizeof(struct map_macaddr_entry));
	if (!entry) {
		warn("OOM: map_macaddr_entry calloc failed!\n");
		return NULL;
	}

	dbg("%s: Add MAC entry "
	    MACFMT " of type %s\n",
	    __func__, MAC2STR(macaddr), allmac_type2str(type));

	memcpy(entry->macaddr, macaddr, 6);
	entry->type = type;
	entry->data = data;

	hidx = mac_hash(macaddr, type);
	hlist_add_head(&entry->hlist, &htable->table[hidx]);

	return entry;
}

void allmac_print(void *htbl)
{
	struct allmac_htable *htable = (struct allmac_htable *)htbl;
	struct map_macaddr_entry *entry = NULL;
	int i;

	dbg("MACs on the list:\n");

	for (i = 0; i < MAC_HTBL_SIZE; i++) {
		if (hlist_empty(&htable->table[i]))
			continue;

		hlist_for_each_entry(entry, &htable->table[i], hlist) {
			dbg("MAC: " MACFMT ", of type: %s\n",
			    MAC2STR(entry->macaddr),
			    allmac_type2str(entry->type));
		}
	}
}
