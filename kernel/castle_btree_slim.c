#include <linux/types.h>
#include <linux/compiler.h>     /* (un)likely() */
#include <linux/string.h>
#include <linux/sort.h>
#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"             /* XXX: needs to go away */
#include "castle_utils.h"
#include "castle_keys_normalized.h"
#ifdef CASTLE_DEBUG
#include "castle_versions.h"
#endif

/*
 * Key manipulation function definitions.
 */

static const struct castle_norm_key SLIM_MIN_KEY   = { .length = NORM_KEY_LENGTH_MIN_KEY };
static const struct castle_norm_key SLIM_MAX_KEY   = { .length = NORM_KEY_LENGTH_MAX_KEY };
static const struct castle_norm_key SLIM_INVAL_KEY = { .length = NORM_KEY_LENGTH_INVAL_KEY };

inline static void *castle_slim_key_pack(const c_vl_bkey_t *src, void *dst, size_t *dst_len)
{
    return castle_norm_key_pack(src, dst, dst_len);
}

inline static c_vl_bkey_t *castle_slim_key_unpack(const void *src, c_vl_bkey_t *dst, size_t *dst_len)
{
    return castle_norm_key_unpack(src, dst, dst_len);
}

inline static int castle_slim_key_compare(const void *a, const void *b)
{
    return castle_norm_key_compare(a, b);
}

inline static size_t castle_slim_key_size(const void *key)
{
    return castle_norm_key_size(key);
}

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

inline static void *castle_slim_key_hc_next(const void *key, const void *low, const void *high)
{
    return castle_norm_key_hypercube_next(key, low, high);
}

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

inline static uint32_t castle_slim_key_hash(const void *key, uint32_t seed)
{
    return castle_norm_key_hash(key, seed);
}

static void castle_slim_key_print(int level, const void *key)
{
    castle_norm_key_print(level, key);
}

/*
 * Entry type related definitions.
 */

/* only needed for T0s */
#define STRIP_DISABLED(type)             ((type) & ~CVT_TYPE_DISABLED_FLAG)

#define TYPE_NODE(type)                  ((type) == CVT_TYPE_NODE)
#define TYPE_TOMBSTONE(type)             ((type) == CVT_TYPE_TOMBSTONE)
#define TYPE_ON_DISK(type)               ((type) == CVT_TYPE_MEDIUM_OBJECT || \
                                          (type) == CVT_TYPE_LARGE_OBJECT)

/* XXX: lifted from castle_btree_vlba_tree.c; should reside somewhere in common */
inline static int cvt_type_to_entry_type(int type)
{
    /* Local counters will be turned into inline counters. */
    if (type == CVT_TYPE_COUNTER_LOCAL_SET)
        return CVT_TYPE_COUNTER_SET;
    if (type == CVT_TYPE_COUNTER_LOCAL_ADD)
        return CVT_TYPE_COUNTER_ADD;

    /* Otherwise, just use the cvt type directly. */
    return type;
}

/*
 * Structure definitions for leaf node entries.
 */

struct slim_leaf_entry {
    /* align:   2 */
    /* offset:  0 */ c_ver_t      version;
    /*          4 */ uint8_t      type;
    /*          5 */ uint8_t      _pad;
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

#define LEAF_ENTRY_MAX_SIZE              (sizeof(struct slim_leaf_entry) - \
                                          sizeof(struct castle_norm_key) + \
                                          sizeof(struct slim_inline_val) + \
                                          SLIM_TREE_MAX_KEY_SIZE +         \
                                          MAX_INLINE_VAL_SIZE +            \
                                          4) /* for the index entry */
#define LEAF_ENTRY_BASE_SIZE(key)        (sizeof(struct slim_leaf_entry) - sizeof *(key) + \
                                          castle_norm_key_size(key))
#define LEAF_ENTRY_VAL_PTR(entry)        ((char *) (entry) + LEAF_ENTRY_BASE_SIZE(&(entry)->key))
#define LEAF_ENTRY_INLINE_VAL_PTR(entry) ((struct slim_inline_val *) LEAF_ENTRY_VAL_PTR(entry))
#define LEAF_ENTRY_EXTERN_VAL_PTR(entry) ((struct slim_extern_val *) LEAF_ENTRY_VAL_PTR(entry))

inline static size_t leaf_entry_size(const struct slim_leaf_entry *entry)
{
    size_t base_size = LEAF_ENTRY_BASE_SIZE(&entry->key);
    if (!TYPE_ON_DISK(STRIP_DISABLED(entry->type)))
    {
        const struct slim_inline_val *val =
            (const struct slim_inline_val *) ((const char *) entry + base_size);
        return base_size + sizeof *val + val->length;
    }
    else return base_size + sizeof(struct slim_extern_val);
}

/*
 * Structure definitions for internal node entries.
 */

struct slim_intern_entry {
    /* align:   2 */
    /* offset:  0 */ c_byte_off_t offset;  /* extent ids are stored in the node header */
    /*          8 */ c_ver_t      version;
    /*         12 */ uint8_t      type;    /* only needed for T0s */
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

inline static size_t intern_entry_size(const struct slim_intern_entry *entry)
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
    /*          1 */ uint8_t      _pad[3];
    /*          4 */ uint32_t     dead_bytes;
    /*          8 */ uint32_t     free_bytes;
    /*         12 */ uint32_t     extent_entries[SLIM_MAX_EXTENTS];
    /*         28 */ c_ext_id_t   extent_ids[SLIM_MAX_EXTENTS];
    /*         60 */ uint8_t      _unused[4];
    /*         64 */
} PACKED;

#define SLIM_HEADER_PTR(node) ((struct slim_header *) BTREE_NODE_PAYLOAD(node))

/*
 * Extent array manipulation for internal nodes.
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

static int intern_entry_extent_locate(struct slim_header *header, int idx)
{
    int i, sum;
    for (i = 0, sum = header->extent_entries[0]; sum < idx && i < SLIM_MAX_EXTENTS;
         ++i, sum += header->extent_entries[i]);
    BUG_ON(sum < idx);
    return i;
}

static c_ext_id_t intern_entry_extent_get(struct slim_header *header, int idx)
{
    int i = intern_entry_extent_locate(header, idx);
    return header->extent_ids[i];
}

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

/* 1MB maximum node size, because Gregor said so */
#define NODE_SIZE_MAX                    (256 * C_BLK_SIZE)
#define NODE_SIZE(node)                  ((node)->size * C_BLK_SIZE)
#define NODE_END(node)                   ((char *) (node) + NODE_SIZE(node))
#define NODE_INDEX(node, i)              (((uint32_t *) NODE_END(node))[-((i)+1)])
#define NODE_INDEX_BOUND(node)           ((char *) &NODE_INDEX(node, (node)->used-1))
#define NODE_ENTRY_PTR(node, i)          ((char *) (node) + NODE_INDEX(node, i))
#define NODE_LEAF_ENTRY_PTR(node, i)     ((struct slim_leaf_entry *) NODE_ENTRY_PTR(node, i))
#define NODE_INTERN_ENTRY_PTR(node, i)   ((struct slim_intern_entry *) NODE_ENTRY_PTR(node, i))

static size_t castle_slim_max_entries(size_t size)
{
    return (size * C_BLK_SIZE - sizeof(struct castle_btree_node) - sizeof(struct slim_header))
        / LEAF_ENTRY_MAX_SIZE;
}

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
            return avail_bytes < (NODE_SIZE(node) - sizeof *node - sizeof *header) / 3;
        default:
            BUG();
    }
}

static int castle_slim_entry_get(struct castle_btree_node *node, int idx,
                                 void **key, c_ver_t *version, c_val_tup_t *cvt)
{
    BUG_ON(idx < 0 || idx >= node->used);

    if (BTREE_NODE_IS_LEAF(node))
    {
        struct slim_leaf_entry *entry = NODE_LEAF_ENTRY_PTR(node, idx);
        BUG_ON(castle_norm_key_size(&entry->key) > SLIM_TREE_MAX_KEY_SIZE);
        BUG_ON((char *) entry + leaf_entry_size(entry) > NODE_INDEX_BOUND(node));

        if (key)
            *key = &entry->key;
        if (version)
            *version = entry->version;
        if (cvt)
        {
            int type = STRIP_DISABLED(entry->type);
            if (TYPE_ON_DISK(type))
            {
                struct slim_extern_val *val = LEAF_ENTRY_EXTERN_VAL_PTR(entry);
                *cvt = convert_to_cvt(entry->type, val->length, val->cep, NULL, 0);
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_INLINE_VAL_PTR(entry);
                BUG_ON(TYPE_NODE(type));
                BUG_ON(TYPE_TOMBSTONE(type) && val->length != 0);
                BUG_ON(val->length > MAX_INLINE_VAL_SIZE);
                *cvt = convert_to_cvt(entry->type, val->length, INVAL_EXT_POS, val->data, 0);
            }
        }
        return entry->type & CVT_TYPE_DISABLED_FLAG;
    }

    else
    {
        struct slim_intern_entry *entry = NODE_INTERN_ENTRY_PTR(node, idx);
        BUG_ON(castle_norm_key_size(&entry->key) > SLIM_TREE_MAX_KEY_SIZE);
        BUG_ON((char *) entry + intern_entry_size(entry) > NODE_INDEX_BOUND(node));

        if (key)
            *key = &entry->key;
        if (version)
            *version = entry->version;
        if (cvt)
        {
            c_ext_pos_t cep = { intern_entry_extent_get(SLIM_HEADER_PTR(node), idx), entry->offset };
            BUG_ON(!TYPE_NODE(STRIP_DISABLED(entry->type)));
            *cvt = convert_to_cvt(entry->type, 0, cep, NULL, 0);
        }
        return entry->type & CVT_TYPE_DISABLED_FLAG;
    }
}

inline static size_t castle_slim_entry_size_predict(const struct castle_norm_key *key,
                                                    c_val_tup_t cvt, int leaf)
{
    if (leaf)
        return LEAF_ENTRY_BASE_SIZE(key) +
            (TYPE_ON_DISK(cvt.type) ?
             sizeof(struct slim_extern_val) :
             sizeof(struct slim_inline_val) + cvt.length);
    else
        return INTERN_ENTRY_BASE_SIZE(key);
}

inline static size_t castle_slim_entry_size(const struct castle_btree_node *node, int idx)
{
    return BTREE_NODE_IS_LEAF(node) ?
        leaf_entry_size(NODE_LEAF_ENTRY_PTR(node, idx)) :
        intern_entry_size(NODE_INTERN_ENTRY_PTR(node, idx));
}

/*
 * Node modification function definitions.
 */

static int offset_cmp(const void *a, const void *b)
{
    return **((const uint32_t **) a) - **((const uint32_t **) b);
}

static void castle_slim_compact(struct castle_btree_node *node)
{
    uint32_t **offsets = castle_alloc(node->used * sizeof *offsets);
    struct slim_header *header = SLIM_HEADER_PTR(node);
    char *base = (char *) node + sizeof *node + sizeof *header;
    int i;

    /* sort the entries in ascending offset order */
    for (i = 0; i < node->used; ++i)
        offsets[i] = &NODE_INDEX(node, i);
    sort(offsets, node->used, sizeof *offsets, offset_cmp, NULL);

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

    header->free_bytes += header->dead_bytes;
    header->dead_bytes = 0;
    BUG_ON(base + header->free_bytes != NODE_INDEX_BOUND(node));
    castle_free(offsets);
}

/* req_space includes the index entry */
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

static void castle_slim_entries_drop(struct castle_btree_node *node, int low, int high)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);

    BUG_ON(low < 0 || high >= node->used || low > high);

    while (low <= high)
        header->dead_bytes += castle_slim_entry_size(node, low++) + 4;
    memmove(&NODE_INDEX(node, node->used-1 - (high-low+1)),
            &NODE_INDEX(node, node->used-1), (node->used - (high+1)) * 4);
    if (!BTREE_NODE_IS_LEAF(node))
        intern_entry_extents_drop(header, low, high);
    node->used -= high-low+1;
}

static void castle_slim_entry_construct(struct castle_btree_node *node, int idx,
                                        const struct castle_norm_key *key, c_ver_t version, c_val_tup_t cvt)
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
        struct slim_leaf_entry *entry = NODE_LEAF_ENTRY_PTR(node, idx);
        if (TYPE_ON_DISK(cvt.type))
        {
            struct slim_extern_val *val =
                (struct slim_extern_val *) ((char *) &entry->key + key_size);
            val->cep = cvt.cep;
            val->length = cvt.length;
        }
        else
        {
            struct slim_inline_val *val =
                (struct slim_inline_val *) ((char *) &entry->key + key_size);
            BUG_ON(TYPE_NODE(cvt.type));
            BUG_ON(TYPE_TOMBSTONE(cvt.type) && cvt.length != 0);
            BUG_ON(cvt.length > MAX_INLINE_VAL_SIZE);
            memmove(val->data, CVT_INLINE_VAL_PTR(cvt), cvt.length);
            val->length = cvt.length;
        }
        memmove(&entry->key, key, key_size);
        entry->type = cvt_type_to_entry_type(cvt.type);
        entry->version = version;
        BUG_ON((char *) entry + leaf_entry_size(entry) > NODE_INDEX_BOUND(node));
    }

    else
    {
        struct slim_intern_entry *entry = NODE_INTERN_ENTRY_PTR(node, idx);
        BUG_ON(!TYPE_NODE(cvt.type));
        memmove(&entry->key, key, key_size);
        entry->type = cvt_type_to_entry_type(cvt.type);
        entry->version = version;
        entry->offset = cvt.cep.offset;
        intern_entry_extent_add(SLIM_HEADER_PTR(node), idx, cvt.cep.ext_id);
        BUG_ON((char *) entry + intern_entry_size(entry) > NODE_INDEX_BOUND(node));
    }
}

static void castle_slim_entry_add(struct castle_btree_node *node, int idx,
                                  void *key, c_ver_t version, c_val_tup_t cvt)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    const struct castle_norm_key *norm_key = key;
    size_t req_space = castle_slim_entry_size_predict(norm_key, cvt, BTREE_NODE_IS_LEAF(node)) + 4;

    BUG_ON(idx < 0 || idx > node->used);

    /* initialize the node if necessary */
    if (unlikely(node->used == 0))
    {
        header->revision   = 0;
        header->dead_bytes = 0;
        header->free_bytes = NODE_SIZE(node) - sizeof *node - sizeof *header;
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

static void castle_slim_entry_replace(struct castle_btree_node *node, int idx,
                                      void *key, c_ver_t version, c_val_tup_t cvt)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    const struct castle_norm_key *norm_key = key;
    size_t old_size = castle_slim_entry_size(node, idx);
    size_t new_size = castle_slim_entry_size_predict(norm_key, cvt, BTREE_NODE_IS_LEAF(node));

    BUG_ON(idx < 0 || idx > node->used);

    if (NODE_ENTRY_PTR(node, idx) + old_size + header->free_bytes == NODE_INDEX_BOUND(node) &&
        new_size <= old_size + header->free_bytes)
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

static void castle_slim_entry_disable(struct castle_btree_node *node, int idx)
{
    if (BTREE_NODE_IS_LEAF(node))
    {
        struct slim_leaf_entry *entry = NODE_LEAF_ENTRY_PTR(node, idx);
        entry->type |= CVT_TYPE_DISABLED_FLAG;
    }
    else
    {
        struct slim_intern_entry *entry = NODE_INTERN_ENTRY_PTR(node, idx);
        entry->type |= CVT_TYPE_DISABLED_FLAG;
    }
}

static void castle_slim_node_print(struct castle_btree_node *node)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    unsigned int i;

    castle_printk(LOG_DEBUG, "node=%p, version=%u, used=%u, flags=%u\n",
                  node, node->version, node->used, node->flags);
    castle_printk(LOG_DEBUG, "header=%p, dead_bytes=%u, free_bytes=%u\n",
                  header, header->dead_bytes, header->free_bytes);

    if (BTREE_NODE_IS_LEAF(node))
    {
        for (i = 0; i < node->used; ++i)
        {
            struct slim_leaf_entry *entry = NODE_LEAF_ENTRY_PTR(node, i);
            castle_printk(LOG_DEBUG, "[%u] offset=%ld, type=%u, version=%u, key_size=%lu, key:\n",
                          i, (char *) entry - (char *) node, entry->type, entry->version,
                          castle_norm_key_size(&entry->key));
            castle_norm_key_print(LOG_DEBUG, &entry->key);

            if (TYPE_ON_DISK(STRIP_DISABLED(entry->type)))
            {
                struct slim_extern_val *val = LEAF_ENTRY_EXTERN_VAL_PTR(entry);
                castle_printk(LOG_DEBUG, "[ext] len=%lu cep=" cep_fmt_str_nl,
                              val->length, cep2str(val->cep));
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_INLINE_VAL_PTR(entry);
                castle_printk(LOG_DEBUG, "[inl] len=%u\n", val->length);
            }
        }
    }
    else
    {
        for (i = 0; i < node->used; ++i)
        {
            struct slim_intern_entry *entry = NODE_INTERN_ENTRY_PTR(node, i);
            c_ext_pos_t cep = { intern_entry_extent_get(header, i), entry->offset };
            castle_printk(LOG_DEBUG, "[%u] offset=%ld, type=%u, version=%u, key_size=%lu, key:\n",
                          i, (char *) entry - (char *) node, entry->type, entry->version,
                          castle_norm_key_size(&entry->key));
            castle_norm_key_print(LOG_DEBUG, &entry->key);
            castle_printk(LOG_DEBUG, "cep=" cep_fmt_str_nl, cep2str(cep));
        }
    }
}

#ifdef CASTLE_DEBUG
static void castle_slim_node_validate(struct castle_btree_node *node)
{
    struct slim_header *header = SLIM_HEADER_PTR(node);
    uint32_t **offsets;
    size_t header_used_bytes = NODE_SIZE(node) - sizeof *node - sizeof *header
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
        used_bytes += size;
    }
    castle_free(offsets);

    if (header->revision != 0 && (failed = 1))
        castle_printk(LOG_ERROR, "error: unknown node revision %u\n", header->revision);

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
        int type;
        c_ver_t version;
        struct castle_norm_key *key;
        size_t val_len;

        if (BTREE_NODE_IS_LEAF(node))
        {
            struct slim_leaf_entry *entry = NODE_LEAF_ENTRY_PTR(node, i);
            type = STRIP_DISABLED(entry->type);
            if (type != CVT_TYPE_TOMBSTONE && type != CVT_TYPE_INLINE &&
                type != CVT_TYPE_MEDIUM_OBJECT && type != CVT_TYPE_LARGE_OBJECT &&
                type != CVT_TYPE_COUNTER_SET && type != CVT_TYPE_COUNTER_ADD &&
                type != CVT_TYPE_COUNTER_ACCUM_SET_SET && type != CVT_TYPE_COUNTER_ACCUM_ADD_SET &&
                type != CVT_TYPE_COUNTER_ACCUM_ADD_ADD && (failed = 1))
                castle_printk(LOG_ERROR, "error: found invalid type %u at position %u\n", type, i);

            version = entry->version;
            key = &entry->key;
            if (TYPE_ON_DISK(type))
            {
                struct slim_extern_val *val = LEAF_ENTRY_EXTERN_VAL_PTR(entry);
                val_len = val->length;
                if (val->cep.ext_id == INVAL_EXT_ID && (failed = 1))
                    castle_printk(LOG_ERROR, "error: found invalid extent id at position %u\n", i);
            }
            else
            {
                struct slim_inline_val *val = LEAF_ENTRY_INLINE_VAL_PTR(entry);
                val_len = val->length;
            }
        }
        else
        {
            struct slim_intern_entry *entry = NODE_INTERN_ENTRY_PTR(node, i);
            type = STRIP_DISABLED(entry->type);
            if (type != CVT_TYPE_NODE && (failed = 1))
                castle_printk(LOG_ERROR, "error: found invalid type %u at position %u\n", type, i);

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

        /* value length checks */
        if (type == CVT_TYPE_TOMBSTONE && val_len != 0 && (failed = 1))
            castle_printk(LOG_ERROR, "error: found tombstone with non-zero length at position %u\n", i);
        else if (type == CVT_TYPE_INLINE && val_len > MAX_INLINE_VAL_SIZE && (failed = 1))
            castle_printk(LOG_ERROR, "error: found a mis-sized inline value at position %u\n", i);
        else if (type == CVT_TYPE_MEDIUM_OBJECT &&
                 (val_len <= MAX_INLINE_VAL_SIZE || val_len > MEDIUM_OBJECT_LIMIT) && (failed = 1))
            castle_printk(LOG_ERROR, "error: found a mis-sized medium object at position %u\n", i);
        else if (type == CVT_TYPE_LARGE_OBJECT && val_len <= MEDIUM_OBJECT_LIMIT && (failed = 1))
            castle_printk(LOG_ERROR, "error: found a mis-sized large object at position %u\n", i);

        /* key/version ordering checks */
        if (i > 0)
        {
            int cmp = castle_norm_key_compare(save_key, key);
            if (cmp > 0 && (failed = 1))
                castle_printk(LOG_ERROR, "error: found a wrong key ordering at position %u\n", i);
            else if (cmp == 0 && castle_version_is_ancestor(version, save_version) && (failed = 1))
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
    .need_split    = castle_slim_need_split,
    .key_pack      = castle_slim_key_pack,
    .key_unpack    = castle_slim_key_unpack,
    .key_compare   = castle_slim_key_compare,
    .key_size      = castle_slim_key_size,
    .key_copy      = castle_slim_key_copy,
    .key_next      = castle_slim_key_next,
    .key_hc_next   = castle_slim_key_hc_next,
    .key_dealloc   = castle_slim_key_dealloc,
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
