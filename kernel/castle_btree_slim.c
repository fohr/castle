#include <linux/types.h>
#include <linux/compiler.h>     /* (un)likely() */
#include <linux/string.h>
#include <linux/sort.h>
#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"
#include "castle_utils.h"
#include "castle_keys_normalized.h"
#include "castle_unit_tests.h"
#include "castle_versions.h"
#ifdef CASTLE_DEBUG
#include "castle_versions.h"
#endif

/*
 * Key manipulation function definitions.
 */

static const struct castle_norm_key SLIM_MIN_KEY   = { .length = NORM_KEY_LENGTH_MIN_KEY };
static const struct castle_norm_key SLIM_MAX_KEY   = { .length = NORM_KEY_LENGTH_MAX_KEY };
static const struct castle_norm_key SLIM_INVAL_KEY = { .length = NORM_KEY_LENGTH_INVAL_KEY };

/**
 * Construct a slim tree key.
 * @see castle_norm_key_pack
 */
inline static void *castle_slim_key_pack(const c_vl_bkey_t *src, void *dst, size_t *dst_len)
{
    return castle_norm_key_pack(src, dst, dst_len);
}

/**
 * Deconstruct a slim tree key into the standard key structure.
 * @see castle_norm_key_unpack
 */
inline static c_vl_bkey_t *castle_slim_key_unpack(const void *src, c_vl_bkey_t *dst, size_t *dst_len)
{
    return castle_norm_key_unpack(src, dst, dst_len);
}

/**
 * Compare two slim tree keys.
 * @see castle_norm_key_compare
 */
inline static int castle_slim_key_compare(const void *a, const void *b)
{
    return castle_norm_key_compare(a, b);
}

/**
 * Return the space (in bytes) that a slim tree key occupies in memory.
 * @see castle_norm_key_size
 */
inline static size_t castle_slim_key_size(const void *key)
{
    return castle_norm_key_size(key);
}

/**
 * Copy a slim tree key.
 * @see castle_norm_key_copy
 */
static void* castle_slim_key_copy(const void *src, void *dst, size_t *dst_len)
{
    const struct castle_norm_key *key = src;

    /* no need to duplicate static keys */
    if (!dst) {
        if (NORM_KEY_MIN(key))
            return (void *) &SLIM_MIN_KEY;
        if (NORM_KEY_MAX(key))
            return (void *) &SLIM_MAX_KEY;
        if (NORM_KEY_INVAL(key))
            return (void *) &SLIM_INVAL_KEY;
    }

    /* ... unless we're explicitly given a buffer to copy them to */
    else if (NORM_KEY_SPECIAL(key))
        return castle_dup_or_copy(src, sizeof key->length, dst, dst_len);

    return castle_norm_key_copy(src, dst, dst_len);
}

/**
 * Create the "next" key of a given slim tree key.
 * @see castle_norm_key_next
 */
static void* castle_slim_key_next(const void *src, void *dst, size_t *dst_len)
{
    const struct castle_norm_key *key = src;

    /* no successor to the min or invalid key */
    BUG_ON(NORM_KEY_MIN(key) || NORM_KEY_INVAL(key));

    /* the successor to the max key is the invalid key */
    if (NORM_KEY_MAX(key))
        return dst ?
            castle_dup_or_copy(&SLIM_INVAL_KEY, sizeof SLIM_INVAL_KEY, dst, dst_len) :
            (void *) &SLIM_INVAL_KEY;

    return castle_norm_key_next(src, dst, dst_len);
}

/**
 * Produce a "next" key suitable for a hypercube-style range query.
 * @see castle_norm_key_hypercube_next
 */
inline static void *castle_slim_key_hc_next(const void *key, const void *low, const void *high)
{
    return castle_norm_key_hypercube_next(key, low, high);
}

/**
 * Deallocate a slim tree key.
 * @see castle_norm_key_free
 */
static void castle_slim_key_dealloc(void *keyv)
{
    struct castle_norm_key *key = keyv;

    /* should not free static keys */
    if (NORM_KEY_MIN(key) || NORM_KEY_MAX(key) || NORM_KEY_INVAL(key))
    {
        /* should not have allocated them either */
        BUG_ON(key != &SLIM_MIN_KEY && key != &SLIM_MAX_KEY && key != &SLIM_INVAL_KEY);
        return;
    }

    castle_norm_key_free(key);
}

/**
 * Return the number of dimensions of a slim tree key.
 * @see castle_norm_key_nr_dims
 */
static int castle_slim_key_nr_dims(const void *keyv)
{
    const struct castle_norm_key *key = keyv;
    return NORM_KEY_SPECIAL(key) ? 0 : castle_norm_key_nr_dims(key);
}

/**
 * Strip a few dimensions off a slim tree key.
 * @see castle_norm_key_strip
 */
static void *castle_slim_key_strip(const void *src, void *dst, size_t *dst_len, int nr_dims)
{
    return castle_norm_key_strip(src, dst, dst_len, nr_dims);
}

/**
 * Hash a slim tree key.
 * @see castle_norm_key_hash
 */
inline static uint32_t castle_slim_key_hash(const void *key,
                                            c_btree_hash_enum_t type,
                                            uint32_t seed)
{
    return castle_norm_key_hash(key, type, seed);
}

/**
 * Print a slim tree key.
 * @see castle_norm_key_print
 */
static void castle_slim_key_print(int level, const void *key)
{
    castle_norm_key_print(level, key);
}

/*
 * Entry type related definitions.
 */

#define TYPE_NODE(type)                  ((type) == CVT_TYPE_NODE)
#define TYPE_TOMBSTONE(type)             ((type) == CVT_TYPE_TOMBSTONE)
#define TYPE_ON_DISK(type)               ((type) == CVT_TYPE_MEDIUM_OBJECT || \
                                          (type) == CVT_TYPE_LARGE_OBJECT)

/*
 * Structure definitions for leaf node entries.
 */

enum {
    LEAF_ENTRY_DISABLED_FLAG  = 1,
    LEAF_ENTRY_TIMESTAMP_FLAG = 2
};

struct slim_leaf_entry {
    /* align:   2 */
    /* offset:  0 */ c_ver_t      version;
    /*          4 */ uint8_t      type;
    /*          5 */ uint8_t      flags;
    /*          6 */ struct castle_norm_key key;
    /*          8 */ /* value information is stored immediately after the key */
} PACKED;

struct slim_inline_val {
    /* align:   2 */
    /* offset:  0 */ uint16_t     length;
    /*          2 */ uint8_t      data[0];
} PACKED;

struct slim_extern_val {
    /* align:   8 */
    /* offset:  0 */ uint64_t     length;
    /*          8 */ c_ext_pos_t  cep;
    /*         24 */
} PACKED;

#define LEAF_ENTRY_MAX_SIZE              (sizeof(struct slim_leaf_entry) -      \
                                          sizeof(struct castle_norm_key) +      \
                                          sizeof(struct slim_inline_val) +      \
                                          sizeof(castle_user_timestamp_t) +     \
                                          SLIM_TREE_MAX_KEY_SIZE +              \
                                          MAX_INLINE_VAL_SIZE +                 \
                                          4) /* for the index entry */
#define LEAF_ENTRY_BASE_SIZE(key)        (sizeof(struct slim_leaf_entry) - sizeof *(key) + \
                                          castle_norm_key_size(key))
#define LEAF_ENTRY_VAL_PTR(entry)        ((void *) ((char *) (entry) + LEAF_ENTRY_BASE_SIZE(&(entry)->key)))
#define LEAF_ENTRY_INLINE_VAL_END(val)   ((char *) (val) + sizeof(struct slim_inline_val) + (val)->length)
#define LEAF_ENTRY_EXTERN_VAL_END(val)   ((char *) (val) + sizeof(struct slim_extern_val))
#define LEAF_ENTRY_IS_DISABLED(entry)    ((entry)->flags & LEAF_ENTRY_DISABLED_FLAG)
#define LEAF_ENTRY_HAS_TIMESTAMP(entry)  ((entry)->flags & LEAF_ENTRY_TIMESTAMP_FLAG)

/**
 * Calculate the size of a leaf entry of the slim tree.
 * @param entry     the entry to calculate the size of
 */
static size_t leaf_entry_size(const struct slim_leaf_entry *entry)
{
    size_t size = LEAF_ENTRY_BASE_SIZE(&entry->key);

    if (!TYPE_ON_DISK(entry->type))
    {
        const struct slim_inline_val *val =
            (const struct slim_inline_val *) ((const char *) entry + size);
        size += sizeof *val + val->length;
    }
    else size += sizeof(struct slim_extern_val);

    if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
        size += sizeof(castle_user_timestamp_t);

    return size;
}

/**
 * Read the value of the timestamp of a leaf entry.
 * @param pos       the byte position where the timestamp starts; on return it points just
 *                  after the timestamp
 */
inline static castle_user_timestamp_t leaf_entry_timestamp_get(const void **pos)
{
    castle_user_timestamp_t timestamp = *((const castle_user_timestamp_t *) *pos);
    *pos = (const char *) *pos + sizeof(castle_user_timestamp_t);
    return timestamp;
}

/**
 * Write the value of the timestamp of a leaf entry.
 * @param pos       the byte position where the timestamp starts; on return it points just
 *                  after the timestamp
 * @param timestamp the timestamp value to write
 */
inline static void leaf_entry_timestamp_put(void **pos, castle_user_timestamp_t timestamp)
{
    *((castle_user_timestamp_t *) *pos) = timestamp;
    *pos = (char *) *pos + sizeof(castle_user_timestamp_t);
}

/*
 * Structure definitions for internal node entries.
 */

enum {
    INTERN_ENTRY_DISABLED_FLAG = 1
};

struct slim_intern_entry {
    /* align:   2 */
    /* offset:  0 */ c_byte_off_t offset;  /* extent ids are stored in the node header */
    /*          8 */ c_ver_t      version;
    /*         12 */ uint8_t      flags;   /* only needed for T0s, for now */
    /*         13 */ uint8_t      _pad;
    /*         14 */ struct castle_norm_key key;
    /*         16 */
} PACKED;

#define INTERN_ENTRY_MAX_SIZE            (sizeof(struct slim_intern_entry) - \
                                          sizeof(struct castle_norm_key) +   \
                                          SLIM_TREE_MAX_KEY_SIZE +           \
                                          4) /* for the index entry */
#define INTERN_ENTRY_BASE_SIZE(key)      (sizeof(struct slim_intern_entry) - sizeof *(key) + \
                                          castle_norm_key_size(key))
#define INTERN_ENTRY_IS_DISABLED(entry)  ((entry)->flags & INTERN_ENTRY_DISABLED_FLAG)

/**
 * Calculate the size of an internal (i.e., non-leaf) entry of the slim tree.
 * @param entry     the entry to calculate the size of
 */
static size_t intern_entry_size(const struct slim_intern_entry *entry)
{
    return INTERN_ENTRY_BASE_SIZE(&entry->key);
}

/*
 * Structure definitions for the node header.
 */

/* must update the offsets and the size of _unused[] below if this is changed */
#define SLIM_MAX_EXTENTS 4

struct slim_header {
    /* align:   4 */
    /* offset:  0 */ uint8_t      revision;
    /*          1 */ uint8_t      _pad;
    /*          2 */ uint16_t     data_offset; /* from the start of the node */
    /*          4 */ uint32_t     dead_bytes;
    /*          8 */ uint32_t     free_bytes;
    /*         12 */ uint32_t     extent_entries[SLIM_MAX_EXTENTS];
    /*         28 */ c_ext_id_t   extent_ids[SLIM_MAX_EXTENTS];
    /*         60 */ uint8_t      _unused[4];
    /*         64 */
} PACKED;

/* half a kB limit on the total node header size; only needed for max_entries() */
/* note that this includes the size of the node-independent castle_btree_node   */
#define SLIM_HEADER_MAX                  512
#define SLIM_HEADER_PTR(node)            ((struct slim_header *) BTREE_NODE_PAYLOAD(node))

/*
 * Extent array manipulation for internal nodes.
 */

/**
 * Initialize the extents array of internal nodes of the slim tree.
 * @param header    pointer to the node's header structure
 */
static void intern_entry_extents_init(struct slim_header *header)
{
    int i;
    for (i = 0; i < SLIM_MAX_EXTENTS; ++i)
    {
        header->extent_entries[i] = 0;
        header->extent_ids[i] = INVAL_EXT_ID;
    }
}

/**
 * Locate the position of the extents array with the extent ID for the given index.
 * @param header    pointer to the node's header structure
 * @param idx       the index for which to locate the position
 */
static int intern_entry_extent_locate(struct slim_header *header, int idx)
{
    int i, sum;
    for (i = 0, sum = header->extent_entries[0]; sum < idx && i < SLIM_MAX_EXTENTS;
         ++i, sum += header->extent_entries[i]);
    BUG_ON(sum < idx);
    return i;
}

/**
 * Return the extent ID stored in the extents array for a given index.
 * @param header    pointer to the node's header structure
 * @param idx       the index for which to return the extent ID
 */
static c_ext_id_t intern_entry_extent_get(struct slim_header *header, int idx)
{
    int i = intern_entry_extent_locate(header, idx);
    return header->extent_ids[i];
}

/**
 * Add an extent ID to the extents array.
 * @param header    pointer to the node's header structure
 * @param idx       the index for which to store the extent ID
 * @param id        the extent ID to store
 */
static void intern_entry_extent_add(struct slim_header *header, int idx, c_ext_id_t id)
{
    int i = intern_entry_extent_locate(header, idx);

    if (header->extent_entries[i] == 0 || header->extent_ids[i] != id)
    {
        if (header->extent_entries[i] > 0)
            ++i;
        /* only allow a new extent id at the end of the extent array */
        BUG_ON(i == SLIM_MAX_EXTENTS || header->extent_entries[i] != 0);
        header->extent_ids[i] = id;
        ++header->extent_entries[i];
        BUG_ON(intern_entry_extent_get(header, idx) != id);
    }

    else ++header->extent_entries[i];
}

/**
 * Drop the extent IDs from the extents array for a range of indexes.
 * @param header    pointer to the node's header structure
 * @param low       the lower bound of the indexes to drop (inclusive)
 * @param high      the upper bound of the indexes to drop (inclusive)
 */
static void intern_entry_extents_drop(struct slim_header *header, int low, int high)
{
    int i = intern_entry_extent_locate(header, low);

    while (low <= high)
    {
        int count = min((int) header->extent_entries[i], high-low+1);
        BUG_ON(count == 0);
        if ((header->extent_entries[i] -= count) == 0)
        {
            memmove(&header->extent_entries[i], &header->extent_entries[i+1], SLIM_MAX_EXTENTS-i-1);
            memmove(&header->extent_ids[i], &header->extent_ids[i+1], SLIM_MAX_EXTENTS-i-1);
            header->extent_entries[SLIM_MAX_EXTENTS-1] = 0;
            header->extent_ids[SLIM_MAX_EXTENTS-1] = INVAL_EXT_ID;
        }
        low += count;
    }
}

/*
 * Node access function definitions.
 */

/* 1MB maximum node size, because Gregor said so...
   ... but then TR needed it bigger for the DFS resolver! Allowing it to be this big (approx 60MB)
   provides capacity for 50000 worst-case entries. */
#define NODE_SIZE_MAX                    (15162 * C_BLK_SIZE)
#define NODE_SIZE(node)                  ((node)->size * C_BLK_SIZE)
#define NODE_END(node)                   ((char *) (node) + NODE_SIZE(node))
#define NODE_INDEX(node, i)              (*((uint32_t *) NODE_END(node) - ((i)+1)))
#define NODE_INDEX_BOUND(node)           ((char *) &NODE_INDEX(node, (node)->used-1))
#define NODE_ENTRY_PTR(node, i)          ((void *) ((char *) (node) + NODE_INDEX(node, i)))

/**
 * Calculate a conservative estimate of the max number of entries which can fit in a node.
 * @param size      the size of the node, in pages
 */
static size_t castle_slim_max_entries(size_t size)
{
    return (size * C_BLK_SIZE - SLIM_HEADER_MAX) / LEAF_ENTRY_MAX_SIZE;
}

/**
 * Calculate a conservative estimate of the min node size into which the given number of entries
 * may fit.
 * @param size      the number of entries
  *@return          the size of the node, in pages
 */
static size_t castle_slim_min_size(size_t entries)
{
    return (DIV_ROUND_UP(((entries * LEAF_ENTRY_MAX_SIZE) + SLIM_HEADER_MAX), C_BLK_SIZE));
}

static int castle_slim_min_size_vs_max_entries_unit_test(void)
{
    int entries;
    /* Theoretically, a btree node may have to hold up to CASTLE_LIFETIME_VERSIONS_LIMIT items,
       because within a btree we assert that a single node must hold all versions of any given
       key. Therefore, we assert that the node size calculation functions must handle this. */
    for (entries = 0; entries <= CASTLE_LIFETIME_VERSIONS_LIMIT; entries++)
    {
        int min_node_size;
        int max_entries;

        min_node_size = castle_slim_min_size(entries);
        max_entries = castle_slim_max_entries(min_node_size);
        if (max_entries < entries)
        {
            castle_printk(LOG_ERROR, "%s::for entries=%d, got min_node_size=%d, "
                "which got max_entries=%d; somethin ain't right...\n",
                __FUNCTION__, entries, min_node_size, max_entries);
            return -1;
        }
    }
    return 0;
}

int castle_slim_tree_unit_tests_do(void)
{
    int test_seq_id = 0;
    int err = 0;

    test_seq_id++; if (0 != (err = castle_slim_min_size_vs_max_entries_unit_test()) ) goto fail;

    BUG_ON(err);
    castle_printk(LOG_INIT, "%s::%d tests passed.\n", __FUNCTION__, test_seq_id);
    return 0;
fail:
    castle_printk(LOG_ERROR, "%s::test %d failed with return code %d.\n",
            __FUNCTION__, test_seq_id, err);
    return err;
}

/**
 * Decide whether a node of the slim tree needs to be split.
 * @param node      pointer to the node
 * @param split_type the type of split to check for
 */
static int castle_slim_need_split(struct castle_btree_node *node, int split_type)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    size_t avail_bytes = header->free_bytes + header->dead_bytes;

    if (unlikely(node->used == 0))
        return 0;               /* no need to split uninitialized nodes */

    switch (split_type)
    {
        case 0:                 /* version split */
            return BTREE_NODE_IS_LEAF(node) ?
                avail_bytes < LEAF_ENTRY_MAX_SIZE :
                avail_bytes < INTERN_ENTRY_MAX_SIZE * 2;
        case 1:                 /* key split */
            return avail_bytes < (NODE_SIZE(node) - header->data_offset) / 3;
        default:
            BUG();
    }
}

/**
 * Get an entry of a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index of the entry to get
 * @param key       pointer to the location where to store a pointer to the key, if any
 * @param version   pointer to the location where to store the version, if any
 * @param cvt       pointer to the location where to store the value, if any
 * @return          whether the entry is disabled
 */
static int castle_slim_entry_get(struct castle_btree_node *node, int idx,
                                 void **key, c_ver_t *version, c_val_tup_t *cvt)
{
    BUG_ON(idx < 0 || idx >= node->used);

    if (BTREE_NODE_IS_LEAF(node))
    {
        struct slim_leaf_entry *entry = NODE_ENTRY_PTR(node, idx);
        BUG_ON(castle_norm_key_size(&entry->key) > SLIM_TREE_MAX_KEY_SIZE);
        BUG_ON((char *) entry + leaf_entry_size(entry) > NODE_INDEX_BOUND(node));

        if (key)
            *key = &entry->key;
        if (version)
            *version = entry->version;
        if (cvt)
        {
            if (TYPE_ON_DISK(entry->type))
            {
                struct slim_extern_val *val = LEAF_ENTRY_VAL_PTR(entry);
                const void *entry_end = LEAF_ENTRY_EXTERN_VAL_END(val);
                castle_user_timestamp_t timestamp = 0;
                if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
                    timestamp = leaf_entry_timestamp_get(&entry_end);
                *cvt = convert_to_cvt(entry->type, val->length, val->cep, NULL, timestamp);
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_VAL_PTR(entry);
                const void *entry_end = LEAF_ENTRY_INLINE_VAL_END(val);
                castle_user_timestamp_t timestamp = 0;
                if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
                    timestamp = leaf_entry_timestamp_get(&entry_end);
                BUG_ON(TYPE_NODE(entry->type));
                BUG_ON(TYPE_TOMBSTONE(entry->type) && val->length != 0);
                BUG_ON(val->length > MAX_INLINE_VAL_SIZE);
                *cvt = convert_to_cvt(entry->type, val->length, INVAL_EXT_POS, val->data, timestamp);
            }
        }
        return LEAF_ENTRY_IS_DISABLED(entry);
    }

    else
    {
        struct slim_intern_entry *entry = NODE_ENTRY_PTR(node, idx);
        BUG_ON(castle_norm_key_size(&entry->key) > SLIM_TREE_MAX_KEY_SIZE);
        BUG_ON((char *) entry + intern_entry_size(entry) > NODE_INDEX_BOUND(node));

        if (key)
            *key = &entry->key;
        if (version)
            *version = entry->version;
        if (cvt)
        {
            c_ext_pos_t cep = { intern_entry_extent_get(SLIM_HEADER_PTR(node), idx), entry->offset };
            *cvt = convert_to_cvt(CVT_TYPE_NODE, 0, cep, NULL, 0);
        }
        return INTERN_ENTRY_IS_DISABLED(entry);
    }
}

/**
 * Predict the size of a slim tree entry.
 * @param key       the key to be stored in the entry
 * @param cvt       the value to be stored in the entry
 * @param leaf      a flag stating whether this is a leaf entry
 * @param timestamp a flag stating whether the entry has a timestamp
 *
 * This function calculates the space in bytes that a given entry will occupy inside a
 * slim tree node by examining the data which will go into it; there is no need to
 * construct the entry itself in order to do so.
 */
static size_t castle_slim_entry_size_predict(const struct castle_norm_key *key,
                                             c_val_tup_t cvt, int leaf, int timestamp)
{
    if (leaf)
        return LEAF_ENTRY_BASE_SIZE(key) +
            (TYPE_ON_DISK(cvt.type) ?
             sizeof(struct slim_extern_val) :
             sizeof(struct slim_inline_val) + cvt.length) +
            (timestamp ? sizeof(castle_user_timestamp_t) : 0);
    else
        return INTERN_ENTRY_BASE_SIZE(key);
}

/**
 * Calculate the size of a slim tree entry.
 * @param node      pointer to the node in which the entry resides
 * @param idx       the index of the entry in question
 *
 * This merely calls the appropriate function for leaf or internal nodes.
 */
inline static size_t castle_slim_entry_size(const struct castle_btree_node *node, int idx)
{
    const void *entry = NODE_ENTRY_PTR(node, idx);
    return BTREE_NODE_IS_LEAF(node) ? leaf_entry_size(entry) : intern_entry_size(entry);
}

/**
 * Calculate index of an entry that splits the node in equal halfs (as much as possible),
 * according to the definition in castle_btree_type.
 *
 * @param node  pointer to the node scheduled for splitting
 */
static int castle_slim_mid_entry(struct castle_btree_node *node)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    unsigned long half_size, entries_size;
    int mid_entry_idx;

    /* This mustn't be called on nodes not ready for key splitting. */
    BUG_ON(!castle_slim_need_split(node, 1));

    /* Calculate half of the # of bytes consumed by entries. */
    half_size = NODE_SIZE(node);
    half_size -= header->data_offset;
    half_size -= header->free_bytes;
    half_size -= header->dead_bytes;
    half_size /= 2;

    for(mid_entry_idx = 0, entries_size = 0; mid_entry_idx < node->used; mid_entry_idx++)
    {
        /* Work out the size of current entry. Add to the total. */
        entries_size += castle_slim_entry_size(node, mid_entry_idx) + 4 /* for the index entry */;
        if(entries_size > half_size)
        {
            /* The first entry alone cannot be bigger than half the occupied size. */
            BUG_ON(mid_entry_idx == 0);

            return mid_entry_idx;
        }
    }
    BUG();
}

/*
 * Node modification function definitions.
 */

/* comparison function for sort() */
static int offset_cmp(const void *a, const void *b)
{
    return **((const uint32_t **) a) - **((const uint32_t **) b);
}

/**
 * Perform compaction on a slim tree node.
 * @param node      pointer to the node
 *
 * After this function has returned, all dead space in the node, caused either by deleting
 * or replacing entries, has been eliminated. This is achieved by moving the entries to
 * occupy that space, without changing their order within the node.
 */
static void castle_slim_compact(struct castle_btree_node *node)
{
    uint32_t **offsets = castle_alloc(node->used * sizeof *offsets);
    struct slim_header *header = SLIM_HEADER_PTR(node);
    char *base = (char *) node + header->data_offset;
    int i;

    /* sort the entries in ascending offset order */
    for (i = 0; i < node->used; ++i)
        offsets[i] = &NODE_INDEX(node, i);
    sort(offsets, node->used, sizeof *offsets, offset_cmp, NULL);

    /* perform the compaction */
    for (i = 0; i < node->used; ++i)
    {
        char *entry = (char *) node + *offsets[i];
        size_t size = BTREE_NODE_IS_LEAF(node) ?
            leaf_entry_size((const struct slim_leaf_entry *) entry) :
            intern_entry_size((const struct slim_intern_entry *) entry);

        if (entry != base)
        {
            BUG_ON(entry < base);
            memmove(base, entry, size);
            *offsets[i] = base - (char *) node;
        }
        base += size;
    }

    /* clean up */
    header->free_bytes += header->dead_bytes;
    header->dead_bytes = 0;
    BUG_ON(base + header->free_bytes != NODE_INDEX_BOUND(node));
    castle_free(offsets);
}

/**
 * Allocate space for an entry inside a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index to use for the entry
 * @param req_space the space required for the entry -- this includes the index slot
 * @return          whether allocation was successful
 *
 * This assigns space for the entry, updates the index to point to it, and also updates
 * the node's free space accounting information.
 */
static int castle_slim_entry_alloc(struct castle_btree_node *node, int idx, size_t req_space)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    BUG_ON(NODE_SIZE(node) == 0 || NODE_SIZE(node) > NODE_SIZE_MAX);
    BUG_ON(req_space > header->free_bytes + header->dead_bytes);

    if (req_space <= header->free_bytes)
    {
        memmove(&NODE_INDEX(node, node->used), &NODE_INDEX(node, node->used-1), (node->used - idx) * 4);
        NODE_INDEX(node, idx) = NODE_SIZE(node) - node->used * 4 - header->free_bytes;
        ++node->used;
        header->free_bytes -= req_space;
        return 1;
    }
    else return 0;
}

/**
 * Drop entries from a slim tree node.
 * @param node      pointer to the node
 * @param low       the lower bound of the entries to drop (inclusive)
 * @param high      the upper bound of the entries to drop (inclusive)
 *
 * This is the opposite of @see castle_slim_entry_alloc(); it reclaims the space used by
 * the entries and eliminates them from the index.
 */
static void castle_slim_entries_drop(struct castle_btree_node *node, int low, int high)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    int i;

    BUG_ON(low < 0 || high >= node->used || low > high);

    for (i = low; i <= high; ++i)
        header->dead_bytes += castle_slim_entry_size(node, i) + 4;
    memmove(&NODE_INDEX(node, node->used-1 - (high-low+1)),
            &NODE_INDEX(node, node->used-1), (node->used - (high+1)) * 4);
    if (!BTREE_NODE_IS_LEAF(node))
        intern_entry_extents_drop(header, low, high);
    node->used -= high-low+1;
}

/**
 * Construct an entry inside a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index of the entry to construct
 * @param key       the key to use for the entry
 * @param version   the version to use for the entry
 * @param cvt       the value to use for the entry
 *
 * The entry is constructed in place from its constituent parts. This function and @see
 * castle_slim_entry_get() are the only functions which manipulate slim tree entries
 * directly.
 */
static void castle_slim_entry_construct(struct castle_btree_node *node,
                                        int idx,
                                        const struct castle_norm_key *key,
                                        c_ver_t version,
                                        c_val_tup_t cvt)
{
    size_t key_size = castle_norm_key_size(key);
    BUG_ON(key_size > SLIM_TREE_MAX_KEY_SIZE);

    /*
     * The reason this function is copying fields into the entry from end to beginning,
     * and that it's using memmove() to do so instead of memcpy(), is because both the key
     * and/or the inline value can potentially be coming from an entry it is now
     * overwriting.
     */

    if (BTREE_NODE_IS_LEAF(node))
    {
        struct slim_leaf_entry *entry = NODE_ENTRY_PTR(node, idx);
        void *entry_end;
        if (TYPE_ON_DISK(cvt.type))
        {
            struct slim_extern_val *val =
                (struct slim_extern_val *) ((char *) &entry->key + key_size);
            val->cep = cvt.cep;
            val->length = cvt.length;
            entry_end = LEAF_ENTRY_EXTERN_VAL_END(val);
        }
        else
        {
            struct slim_inline_val *val =
                (struct slim_inline_val *) ((char *) &entry->key + key_size);
            BUG_ON(TYPE_NODE(cvt.type));
            BUG_ON(TYPE_TOMBSTONE(cvt.type) && cvt.length != 0);
            BUG_ON(cvt.length > MAX_INLINE_VAL_SIZE);
            if (!TYPE_TOMBSTONE(cvt.type))
                memmove(val->data, CVT_INLINE_VAL_PTR(cvt), cvt.length);
            val->length = cvt.length;
            entry_end = LEAF_ENTRY_INLINE_VAL_END(val);
        }
        memmove(&entry->key, key, key_size);
        entry->flags = BTREE_NODE_HAS_TIMESTAMPS(node) ? LEAF_ENTRY_TIMESTAMP_FLAG : 0;
        entry->type = cvt_type_to_btree_entry_type(cvt.type);
        entry->version = version;
        if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
            leaf_entry_timestamp_put(&entry_end, cvt.user_timestamp);
        BUG_ON((char *) entry + leaf_entry_size(entry) > NODE_INDEX_BOUND(node));
    }

    else
    {
        struct slim_intern_entry *entry = NODE_ENTRY_PTR(node, idx);
        BUG_ON(!TYPE_NODE(cvt.type));
        memmove(&entry->key, key, key_size);
        entry->flags = 0;
        entry->version = version;
        entry->offset = cvt.cep.offset;
        intern_entry_extent_add(SLIM_HEADER_PTR(node), idx, cvt.cep.ext_id);
        BUG_ON((char *) entry + intern_entry_size(entry) > NODE_INDEX_BOUND(node));
    }
}

/**
 * Add an entry to a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index of the entry to add
 * @param key       the key to use for the entry
 * @param version   the version to use for the entry
 * @param cvt       the value to use for the entry
 */
static void castle_slim_entry_add(struct castle_btree_node *node, int idx,
                                  void *key, c_ver_t version, c_val_tup_t cvt)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    const struct castle_norm_key *norm_key = key;
    size_t req_space = castle_slim_entry_size_predict(norm_key, cvt,
                                                      BTREE_NODE_IS_LEAF(node),
                                                      BTREE_NODE_HAS_TIMESTAMPS(node))
        + 4 /* for the index entry */;

    BUG_ON(idx < 0 || idx > node->used);

    /* initialize the node if necessary */
    if (unlikely(node->used == 0))
    {
        header->revision    = 0;
        header->data_offset = sizeof *node + sizeof *header;
        header->dead_bytes  = 0;
        header->free_bytes  = NODE_SIZE(node) - header->data_offset;
        if (!BTREE_NODE_IS_LEAF(node))
            intern_entry_extents_init(header);
    }

    if (!castle_slim_entry_alloc(node, idx, req_space))
    {
        BUG_ON(ptr_in_range(key, node, NODE_SIZE(node)));
        castle_slim_compact(node);
        if (!castle_slim_entry_alloc(node, idx, req_space))
            BUG();
    }

    castle_slim_entry_construct(node, idx, norm_key, version, cvt);
}

/**
 * Replace an entry of a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index of the entry to add
 * @param key       the key to use for the entry
 * @param version   the version to use for the entry
 * @param cvt       the value to use for the entry
 *
 * If possible, the entry is replaced in place, to avoid wasting space and messing up the
 * ordering of the entries inside the node.
 */
static void castle_slim_entry_replace(struct castle_btree_node *node, int idx,
                                      void *key, c_ver_t version, c_val_tup_t cvt)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    const struct castle_norm_key *norm_key = key;
    size_t old_size = castle_slim_entry_size(node, idx);
    size_t new_size = castle_slim_entry_size_predict(norm_key, cvt,
                                                     BTREE_NODE_IS_LEAF(node),
                                                     BTREE_NODE_HAS_TIMESTAMPS(node));

    BUG_ON(idx < 0 || idx > node->used);

    if ((char *) NODE_ENTRY_PTR(node, idx) + old_size + header->free_bytes == NODE_INDEX_BOUND(node)
        && new_size <= old_size + header->free_bytes)
    {
        castle_slim_entry_construct(node, idx, norm_key, version, cvt);
        header->free_bytes += old_size - new_size;
    }
    else if (new_size <= old_size)
    {
        castle_slim_entry_construct(node, idx, norm_key, version, cvt);
        header->dead_bytes += old_size - new_size;
    }
    else
    {
        castle_slim_entries_drop(node, idx, idx);
        castle_slim_entry_add(node, idx, key, version, cvt);
    }
}

/**
 * Disable an entry in a slim tree node.
 * @param node      pointer to the node
 * @param idx       the index of the entry to disable
 */
static void castle_slim_entry_disable(struct castle_btree_node *node, int idx)
{
    if (BTREE_NODE_IS_LEAF(node))
    {
        struct slim_leaf_entry *entry = NODE_ENTRY_PTR(node, idx);
        entry->flags |= LEAF_ENTRY_DISABLED_FLAG;
    }
    else
    {
        struct slim_intern_entry *entry = NODE_ENTRY_PTR(node, idx);
        entry->flags |= INTERN_ENTRY_DISABLED_FLAG;
    }
}

/**
 * Print the contents of a slim tree node.
 * @param node      pointer to the node
 */
static void castle_slim_node_print(struct castle_btree_node *node)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    unsigned int i;

    castle_printk(LOG_DEBUG, "node=%p, version=%u, used=%u, flags=%u\n",
                  node, node->version, node->used, node->flags);
    castle_printk(LOG_DEBUG, "header=%p, revision=%u, offset=%u, dead_bytes=%u, free_bytes=%u\n",
                  header, header->revision, header->data_offset, header->dead_bytes, header->free_bytes);

    if (BTREE_NODE_IS_LEAF(node))
    {
        for (i = 0; i < node->used; ++i)
        {
            struct slim_leaf_entry *entry = NODE_ENTRY_PTR(node, i);
            castle_printk(LOG_DEBUG, "[%u] offset=%ld, type=%u, flags=%u, version=%u, key_size=%lu, key:\n",
                          i, (char *) entry - (char *) node, entry->type, entry->flags, entry->version,
                          castle_norm_key_size(&entry->key));
            castle_norm_key_print(LOG_DEBUG, &entry->key);

            if (TYPE_ON_DISK(entry->type))
            {
                struct slim_extern_val *val = LEAF_ENTRY_VAL_PTR(entry);
                const void *entry_end = LEAF_ENTRY_EXTERN_VAL_END(val);
                castle_user_timestamp_t timestamp = 0;
                if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
                    timestamp = leaf_entry_timestamp_get(&entry_end);
                castle_printk(LOG_DEBUG, "[ext] timestamp=%lu len=%lu cep=" cep_fmt_str_nl,
                              timestamp, val->length, cep2str(val->cep));
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_VAL_PTR(entry);
                const void *entry_end = LEAF_ENTRY_INLINE_VAL_END(val);
                castle_user_timestamp_t timestamp = 0;
                if (LEAF_ENTRY_HAS_TIMESTAMP(entry))
                    timestamp = leaf_entry_timestamp_get(&entry_end);
                castle_printk(LOG_DEBUG, "[inl] timestamp=%lu len=%u\n", timestamp, val->length);
            }
        }
    }
    else
    {
        for (i = 0; i < node->used; ++i)
        {
            struct slim_intern_entry *entry = NODE_ENTRY_PTR(node, i);
            c_ext_pos_t cep = { intern_entry_extent_get(header, i), entry->offset };
            castle_printk(LOG_DEBUG, "[%u] offset=%ld, flags=%u, version=%u, key_size=%lu, key:\n",
                          i, (char *) entry - (char *) node, entry->flags, entry->version,
                          castle_norm_key_size(&entry->key));
            castle_norm_key_print(LOG_DEBUG, &entry->key);
            castle_printk(LOG_DEBUG, "cep=" cep_fmt_str_nl, cep2str(cep));
        }
    }
}

#ifdef CASTLE_DEBUG
/**
 * Validate the contents of a slim tree node.
 * @param node      pointer to the node
 */
static void castle_slim_node_validate(struct castle_btree_node *node)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    uint32_t **offsets;
    size_t header_used_bytes = NODE_SIZE(node) - header->data_offset
        - header->dead_bytes - header->free_bytes;
    size_t used_bytes = 0, dead_bytes = 0, free_bytes = 0;
    c_ver_t save_version;
    struct castle_norm_key *save_key;
    unsigned int i;
    int failed = 0;

    /* disabled by default, as it adds significant overhead */
    return;

    /* global node header checks */
    if (node->magic != BTREE_NODE_MAGIC && (failed = 1))
        castle_printk(LOG_ERROR, "error: expected node magic %u, got %u\n",
                      BTREE_NODE_MAGIC, node->magic);
    if ((NODE_SIZE(node) == 0 || NODE_SIZE(node) > NODE_SIZE_MAX) && (failed = 1))
        castle_printk(LOG_ERROR, "error: invalid node size of %u pages\n",
                      node->size);
    if (node->type != SLIM_TREE_TYPE && (failed = 1))
        castle_printk(LOG_ERROR, "error: expected tree type %u, got %u\n",
                      SLIM_TREE_TYPE, node->type);

    /* sort the entries in ascending offset order */
    offsets = castle_alloc(node->used * sizeof *offsets);
    for (i = 0; i < node->used; ++i)
        offsets[i] = &NODE_INDEX(node, i);
    sort(offsets, node->used, sizeof *offsets, offset_cmp, NULL);

    /* checks performed in offset order */
    for (i = 0; i < node->used; ++i)
    {
        char *entry = (char *) node + *offsets[i];
        size_t size = BTREE_NODE_IS_LEAF(node) ?
            leaf_entry_size((const struct slim_leaf_entry *) entry) :
            intern_entry_size((const struct slim_intern_entry *) entry);

        char *boundary = i < node->used-1 ?
            (char *) node + *offsets[i+1] : NODE_INDEX_BOUND(node);
        if (entry + size > boundary && (failed = 1))
            castle_printk(LOG_ERROR, "error: entry has space for %ld bytes but occupies %lu bytes\n",
                          boundary - entry, size);
        else
        {
            if (i < node->used-1)
                dead_bytes += boundary - (entry + size);
            else
                free_bytes = boundary - (entry + size);
        }
        used_bytes += size + 4 /* for the index entry */;
    }
    castle_free(offsets);

    /* slim header checks */
    if (header->revision != 0 && (failed = 1))
        castle_printk(LOG_ERROR, "error: unknown node revision %u\n", header->revision);
    if (header->data_offset > SLIM_HEADER_MAX && (failed = 1))
        castle_printk(LOG_ERROR, "error: header is too large at %u bytes\n", header->data_offset);

    /* size accounting checks */
    if (dead_bytes != header->dead_bytes && (failed = 1))
        castle_printk(LOG_ERROR, "error: node reports %u dead bytes but found %lu\n",
                      header->dead_bytes, dead_bytes);
    if (free_bytes != header->free_bytes && (failed = 1))
        castle_printk(LOG_ERROR, "error: node reports %u free bytes but found %lu\n",
                      header->free_bytes, free_bytes);
    if (used_bytes != header_used_bytes && (failed = 1))
        castle_printk(LOG_ERROR, "error: node reports %lu used bytes but found %lu\n",
                      header_used_bytes, used_bytes);

    /* extent array checks */
    if (!BTREE_NODE_IS_LEAF(node))
    {
        size_t sum = 0;
        for (i = 0; i < SLIM_MAX_EXTENTS; ++i)
        {
            sum += header->extent_entries[i];
            if (header->extent_entries[i] != 0)
            {
                if (i > 0 && header->extent_entries[i-1] == 0 && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found nonzero after zero entry count in extent array\n");
                if (header->extent_ids[i] == INVAL_EXT_ID && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found invalid extent id in extent array\n");
            }
            else if (header->extent_ids[i] != INVAL_EXT_ID && (failed = 1))
                castle_printk(LOG_ERROR, "error: found valid extent id past the end of the extent array\n");
        }
        if (sum != node->used && (failed = 1))
            castle_printk(LOG_ERROR, "error: wrong number of entries in extent array\n");
    }

    /* checks performed in index order */
    for (i = 0; i < node->used; ++i)
    {
        c_ver_t version;
        struct castle_norm_key *key;

        if (BTREE_NODE_IS_LEAF(node))
        {
            struct slim_leaf_entry *entry = NODE_ENTRY_PTR(node, i);

            if (entry->type != CVT_TYPE_TOMBSTONE     && entry->type != CVT_TYPE_INLINE &&
                entry->type != CVT_TYPE_MEDIUM_OBJECT && entry->type != CVT_TYPE_LARGE_OBJECT &&
                entry->type != CVT_TYPE_COUNTER_SET   && entry->type != CVT_TYPE_COUNTER_ADD &&
                entry->type != CVT_TYPE_COUNTER_ACCUM_SET_SET &&
                entry->type != CVT_TYPE_COUNTER_ACCUM_ADD_SET &&
                entry->type != CVT_TYPE_COUNTER_ACCUM_ADD_ADD && (failed = 1))
                castle_printk(LOG_ERROR, "error: found invalid type %u at position %u\n", entry->type, i);

            if (!LEAF_ENTRY_HAS_TIMESTAMP(entry) != !BTREE_NODE_HAS_TIMESTAMPS(node) && (failed = 1))
                castle_printk(LOG_ERROR, "error: entry timestamp flag does not agree with node at position %u\n", i);

            version = entry->version;
            key = &entry->key;

            if (TYPE_ON_DISK(entry->type))
            {
                struct slim_extern_val *val = LEAF_ENTRY_VAL_PTR(entry);

                if (entry->type == CVT_TYPE_MEDIUM_OBJECT &&
                    (val->length <= MAX_INLINE_VAL_SIZE ||
                     val->length > MEDIUM_OBJECT_LIMIT) && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found a mis-sized medium object at position %u\n", i);
                else if (entry->type == CVT_TYPE_LARGE_OBJECT &&
                         val->length <= MEDIUM_OBJECT_LIMIT && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found a mis-sized large object at position %u\n", i);

                if (val->cep.ext_id == INVAL_EXT_ID && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found invalid extent id at position %u\n", i);
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_VAL_PTR(entry);

                if (entry->type == CVT_TYPE_TOMBSTONE && val->length != 0 && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found tombstone with non-zero length at position %u\n", i);
                else if (val->length > MAX_INLINE_VAL_SIZE && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found a mis-sized inline value at position %u\n", i);
            }
        }
        else
        {
            struct slim_intern_entry *entry = NODE_ENTRY_PTR(node, i);
            version = entry->version;
            key = &entry->key;
        }

        /* key length checks */
        if (key->length == NORM_KEY_LENGTH_MIN_KEY && (failed = 1))
            castle_printk(LOG_ERROR, "error: found min key at position %u\n", i);
        else if (key->length == NORM_KEY_LENGTH_INVAL_KEY && (failed = 1))
            castle_printk(LOG_ERROR, "error: found invalid key at position %u\n", i);
        else if (castle_norm_key_size(key) > SLIM_TREE_MAX_KEY_SIZE && (failed = 1))
            castle_printk(LOG_ERROR, "error: found too large a key at position %u\n", i);

        /* key/version ordering checks */
        if (i > 0)
        {
            int cmp = castle_norm_key_compare(save_key, key);
            if (cmp > 0 && (failed = 1))
                castle_printk(LOG_ERROR, "error: found a wrong key ordering at position %u\n", i);
            else if (cmp == 0 && castle_version_is_ancestor(save_version, version) && (failed = 1))
                castle_printk(LOG_ERROR, "error: found a wrong version ordering at position %u\n", i);
        }
        save_version = version;
        save_key = key;
    }

    BUG_ON(failed);
}
#endif

/*
 * B-tree type structure definition.
 */

struct castle_btree_type castle_slim_tree = {
    .magic         = SLIM_TREE_TYPE,
    .min_key       = (void *) &SLIM_MIN_KEY,
    .max_key       = (void *) &SLIM_MAX_KEY,
    .inv_key       = (void *) &SLIM_INVAL_KEY,
    .max_entries   = castle_slim_max_entries,
    .min_size      = castle_slim_min_size,
    .need_split    = castle_slim_need_split,
    .mid_entry     = castle_slim_mid_entry,
    .key_pack      = castle_slim_key_pack,
    .key_unpack    = castle_slim_key_unpack,
    .key_compare   = castle_slim_key_compare,
    .key_size      = castle_slim_key_size,
    .key_copy      = castle_slim_key_copy,
    .key_next      = castle_slim_key_next,
    .key_hc_next   = castle_slim_key_hc_next,
    .key_dealloc   = castle_slim_key_dealloc,
    .nr_dims       = castle_slim_key_nr_dims,
    .key_strip     = castle_slim_key_strip,
    .key_hash      = castle_slim_key_hash,
    .key_print     = castle_slim_key_print,
    .entry_get     = castle_slim_entry_get,
    .entry_add     = castle_slim_entry_add,
    .entry_replace = castle_slim_entry_replace,
    .entry_disable = castle_slim_entry_disable,
    .entries_drop  = castle_slim_entries_drop,
    .node_print    = castle_slim_node_print,
#ifdef CASTLE_DEBUG
    .node_validate = castle_slim_node_validate,
#endif
};
