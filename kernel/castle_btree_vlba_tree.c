#include "castle_defines.h"
#include "castle.h"
#include "castle_utils.h"
#include "castle_keys_vlba.h"
#include "castle_versions.h"

/* lifted from castle_btree.c */
#ifndef DEBUG
#define iter_debug(_f, ...)     ((void)0)
#else
#define iter_debug(_f, _a...)   (castle_printk(LOG_DEBUG, "Iterator  :%.60s:%.4d:  " _f,  \
                                                __func__, __LINE__ , ##_a))
#endif

/**********************************************************************************************/
/* Variable length byte array key btree (vlbatree) definitions */

#define VLBA_TREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define VLBA_TREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define VLBA_TREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define VLBA_TREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)) || CVT_LEAF_PTR(*(_slot)))

#define VLBA_TREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMBSTONE(*(_slot))
#define VLBA_TREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define VLBA_ENTRY_IS_COUNTER_SET(_slot)        CVT_COUNTER_SET(*(_slot))
#define VLBA_ENTRY_IS_COUNTER_ADD(_slot)        CVT_COUNTER_ADD(*(_slot))
#define VLBA_TREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define VLBA_TREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define VLBA_TREE_ENTRY_IS_ONDISK(_slot)        CVT_ON_DISK(*(_slot))

typedef struct vlba_key {
    /* align:   4 */
    /* offset:  0 */ uint32_t length;
    /*          4 */ uint8_t _key[0];
    /*          4 */
} PACKED vlba_key_t;

static const vlba_key_t VLBA_TREE_INVAL_KEY = (vlba_key_t){.length = VLBA_TREE_LENGTH_OF_INVAL_KEY};
static const vlba_key_t VLBA_TREE_MIN_KEY = (vlba_key_t){.length = VLBA_TREE_LENGTH_OF_MIN_KEY};
static const vlba_key_t VLBA_TREE_MAX_KEY = (vlba_key_t){.length = VLBA_TREE_LENGTH_OF_MAX_KEY};

#define VLBA_TREE_KEY_INVAL(_key)          ((_key)->length == VLBA_TREE_INVAL_KEY.length)
#define VLBA_TREE_KEY_MIN(_key)            ((_key)->length == VLBA_TREE_MIN_KEY.length)
#define VLBA_TREE_KEY_MAX(_key)            ((_key)->length == VLBA_TREE_MAX_KEY.length)

struct castle_vlba_tree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t                 type;
    /*          1 */ uint8_t                 disabled;
    /*          2 */ uint8_t                 _pad[2];
    /*          4 */ c_ver_t                 version;
    /*          8 */ castle_user_timestamp_t user_timestamp;
    /*         16 */ uint64_t                val_len;
    /*         24 */ c_ext_pos_t             cep;
    /*         40 */ vlba_key_t              key;
    /*         44 *//* Inline values are stored at the end of entry */
} PACKED;

struct castle_vlba_tree_node {
    /* align:   4 */
    /* offset:  0 */ uint32_t    dead_bytes;
    /*          4 */ uint32_t    free_bytes;
    /*          8 */ uint8_t     _unused[56];
    /*         64 */ uint32_t    key_idx[0];
    /*         64 */
} PACKED;

#define VLBA_TREE_NODE_LENGTH(_node)        ({int _ns = (_node)->size;                    \
                                              BUG_ON(_ns == 0 || _ns > 256);              \
                                              (_ns * C_BLK_SIZE); })
#define EOF_VLBA_NODE(_node)                ((uint8_t *) (_node) + VLBA_TREE_NODE_LENGTH(_node))
#define VLBA_KEY_LENGTH(_key)               (VLBA_TREE_KEY_MAX(_key) ? 0 : (_key)->length)
#define VLBA_INLINE_VAL_LENGTH(_entry)                                      \
                (VLBA_TREE_ENTRY_IS_INLINE(_entry) ? (_entry)->val_len : 0)
#define VLBA_ENTRY_LENGTH(_entry)                                           \
                (sizeof(struct castle_vlba_tree_entry) +                    \
                 VLBA_KEY_LENGTH(&(_entry)->key) +                          \
                 VLBA_INLINE_VAL_LENGTH(_entry))
#define MAX_VLBA_ENTRY_LENGTH                                               \
                (sizeof(struct castle_vlba_tree_entry) +                    \
                 VLBA_TREE_MAX_KEY_SIZE +                                   \
                 MAX_INLINE_VAL_SIZE +                                      \
                 sizeof(uint32_t)) /* for the index entry */
#define VLBA_TREE_MAX_ENTRIES(_size)                                        \
                (((_size) * C_BLK_SIZE -                                    \
                  sizeof(struct castle_btree_node) -                        \
                  sizeof(struct castle_vlba_tree_node))                     \
                 / MAX_VLBA_ENTRY_LENGTH)
#define VLBA_ENTRY_PTR(__node, _vlba_node, _i)                              \
                (EOF_VLBA_NODE(__node) - (_vlba_node)->key_idx[_i])
#define VLBA_ENTRY_VAL_PTR(_entry)                                          \
                ((uint8_t *) (_entry) +                                     \
                 sizeof(struct castle_vlba_tree_entry) +                    \
                 VLBA_KEY_LENGTH(&(_entry)->key))

/**
 * Returns maximum number of entries that can be stored in a node of the specified size
 * (assuming that the entries are the biggest possible).
 *
 * @param size     Size of the node in pages.
 */
static size_t castle_vlba_tree_max_entries(size_t size)
{
    return VLBA_TREE_MAX_ENTRIES(size);
}

/* Implementation of heap sort from wiki */
static void min_heap_swap(uint32_t *a, int i, int j)
{
    uint32_t tmp;

    tmp = a[i];
    a[i] = a[j];
    a[j] = tmp;
}

static void min_heap_siftDown(uint32_t *a, uint32_t *idx, int start, int end)
{
    int root = start;
    int child;

    while (root * 2 + 1 <= end)
    {
        child = root * 2 + 1;
        if (child < end && a[child+1] < a[child])
            child++;
        if (a[root] > a[child])
        {
            min_heap_swap(a, root, child);
            min_heap_swap(idx, root, child);

            root = child;
        } else
            return;
    }
}

static void min_heap_heapify(uint32_t *a, uint32_t *idx, int count)
{
    int start = (count - 2)/2;

    while (start >= 0)
    {
        min_heap_siftDown(a, idx, start, count-1);
        start--;
    }
}

static uint32_t min_heap_del_root(uint32_t *a, uint32_t *idx, int count)
{
    min_heap_swap(a, 0, count-1);
    min_heap_swap(idx, 0, count-1);

    min_heap_siftDown(a, idx, 0, count-2);

    return a[count-1];
}

static void castle_vlba_tree_node_compact(struct castle_btree_node *node)
{
    struct castle_vlba_tree_node *vlba_node =
                (struct castle_vlba_tree_node *) BTREE_NODE_PAYLOAD(node);
    uint32_t i, cur_loc = 0;
    uint32_t *a, *idx;
    uint32_t count;

    /* Buffers to keep the minimum heap of entries offsets and corresponding
     * entry index */
    a = castle_alloc(sizeof(uint32_t) * node->used);
    idx = castle_alloc(sizeof(uint32_t) * node->used);
    BUG_ON(!a || !idx);

    memcpy(a, &vlba_node->key_idx[0], (sizeof(uint32_t) * node->used));
    for (i=0, count=0; i < node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;

        idx[i] = i;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);
        count += VLBA_ENTRY_LENGTH(entry);
    }

    /* Check for total length adds upto node length */
    /* node header + vlba header + index table + free bytes + sum of entries + dead bytes */
    BUG_ON( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
            + sizeof(uint32_t) * node->used + vlba_node->free_bytes + count +
            vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH(node));

    /* Store index for each entry to update entries index in the table */
    min_heap_heapify(a, idx, node->used);

    count = node->used;
    cur_loc = 0;
    while (count)
    {
        uint32_t entry_offset, ent_len;
        struct castle_vlba_tree_entry *entry;

        entry_offset = min_heap_del_root(a, idx, count);
        count--;
        entry = (struct castle_vlba_tree_entry *)(EOF_VLBA_NODE(node) - entry_offset);
        ent_len = (uint32_t)VLBA_ENTRY_LENGTH(entry);
        cur_loc += ent_len;

        BUG_ON(entry_offset != a[count]);
        BUG_ON(cur_loc > entry_offset);

        /* If there is no hole before the entry, just leave the entry as it was */
        if (entry_offset == cur_loc)
            continue;

        memmove(EOF_VLBA_NODE(node) - cur_loc, entry, ent_len);
        vlba_node->key_idx[idx[count]] = cur_loc;
    }

    vlba_node->free_bytes += vlba_node->dead_bytes;
    vlba_node->dead_bytes = 0;
#ifdef CASTLE_DEBUG
    memset(EOF_VLBA_NODE(node) - cur_loc - vlba_node->free_bytes, 0xef,
           vlba_node->free_bytes);
#endif

    castle_free(a);
    castle_free(idx);
}


static int castle_vlba_tree_need_split(struct castle_btree_node *node,
                                       int ver_or_key_split)
{
    struct castle_vlba_tree_node *vlba_node =
                (struct castle_vlba_tree_node *) BTREE_NODE_PAYLOAD(node);

    /* Special case, uninitialised node should never be split. */
    if (node->used == 0)
        return 0;

    switch (ver_or_key_split)
    {
        case 0:
            if (BTREE_NODE_IS_LEAF(node))
            {
                if (vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH)
                    return 1;
                return 0;
            } else
            {
                if (vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH*2)
                    return 1;
                return 0;
            }
            BUG();
            break;
        case 1:
            if ((vlba_node->free_bytes + vlba_node->dead_bytes) <
                (VLBA_TREE_NODE_LENGTH(node) - sizeof(struct castle_btree_node) -
                 sizeof(struct castle_vlba_tree_node)) / 3)
                return 1;
            return 0;
        default:
            BUG();
    }

    return -1;
}

static int castle_vlba_tree_key_compare(const void *keyv1, const void *keyv2)
{
    const vlba_key_t *key1 = keyv1;
    const vlba_key_t *key2 = keyv2;
    int key1_min, key2_min, key1_max, key2_max;

    BUG_ON(!key1 || !key2);

    if(unlikely(VLBA_TREE_KEY_INVAL(key1) && VLBA_TREE_KEY_INVAL(key2)))
        return 0;

    if(unlikely(VLBA_TREE_KEY_INVAL(key1)))
        return 1;

    if(unlikely(VLBA_TREE_KEY_INVAL(key2)))
        return -1;

    key1_min = !!VLBA_TREE_KEY_MIN(key1);
    key2_min = !!VLBA_TREE_KEY_MIN(key2);
    if(key1_min || key2_min)
        return key2_min - key1_min;

    key1_max = !!VLBA_TREE_KEY_MAX(key1);
    key2_max = !!VLBA_TREE_KEY_MAX(key2);
    if(key1_max || key2_max)
        return key1_max - key2_max;

    BUG_ON(VLBA_KEY_LENGTH(key1) > VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(VLBA_KEY_LENGTH(key2) > VLBA_TREE_MAX_KEY_SIZE);

    return castle_object_btree_key_compare(keyv1, keyv2);
}

static size_t castle_vlba_tree_key_size(const void *keyv)
{
    const vlba_key_t *key = keyv;
    if (unlikely(VLBA_TREE_KEY_MAX(key) || VLBA_TREE_KEY_INVAL(key)))
        return sizeof key->length;
    return key->length + sizeof key->length;
}

static void *castle_vlba_tree_key_next(const void *src, void *dst, size_t *dst_len)
{
    const vlba_key_t *key = src;

    /* No successor to invalid or min key. */
    BUG_ON(VLBA_TREE_KEY_INVAL(key));
    BUG_ON(VLBA_TREE_KEY_MIN(key));
    /* Successor to max key is the invalid key */
    if(VLBA_TREE_KEY_MAX(key))
    {
        iter_debug("making INVAL_KEY\n");
        return dst ?
            castle_dup_or_copy(&VLBA_TREE_INVAL_KEY, sizeof VLBA_TREE_INVAL_KEY, dst, dst_len) :
            (void *) &VLBA_TREE_INVAL_KEY;
    }

    return castle_object_btree_key_next(src, dst, dst_len);
}

static void *castle_vlba_tree_key_copy(const void *src, void *dst, size_t *dst_len)
{
    const vlba_key_t *key = src;

    /* No need to duplicate static keys */
    if (!dst)
    {
        if (VLBA_TREE_KEY_INVAL(key))
            return (void *) &VLBA_TREE_INVAL_KEY;
        if (VLBA_TREE_KEY_MIN(key))
            return (void *) &VLBA_TREE_MIN_KEY;
        if (VLBA_TREE_KEY_MAX(key))
            return (void *) &VLBA_TREE_MAX_KEY;
    }

    /* ... unless we're explicitly given a buffer to copy them to */
    else if (VLBA_TREE_KEY_INVAL(key) || VLBA_TREE_KEY_MIN(key) || VLBA_TREE_KEY_MAX(key))
        return castle_dup_or_copy(src, sizeof key->length, dst, dst_len);

    return castle_object_btree_key_copy(src, dst, dst_len);
}

static void *castle_vlba_tree_key_pack(const c_vl_bkey_t *src, void *dst, size_t *dst_len)
{
    return castle_vlba_tree_key_copy(src, dst, dst_len);
}

static c_vl_bkey_t *castle_vlba_tree_key_unpack(const void *src, c_vl_bkey_t *dst, size_t *dst_len)
{
    const vlba_key_t *key = src;

    /* handle static keys specially */
    if (VLBA_TREE_KEY_INVAL(key) || VLBA_TREE_KEY_MIN(key) || VLBA_TREE_KEY_MAX(key))
        return castle_dup_or_copy(src, sizeof key->length, dst, dst_len);

    return castle_object_btree_key_copy(src, dst, dst_len);
}

static void *castle_vlba_tree_key_hc_next(const void *key, const void *low, const void *high)
{
    return castle_object_btree_key_hypercube_next(key, low, high);
}

static void castle_vlba_tree_key_dealloc(void *keyv)
{
    vlba_key_t *key = (vlba_key_t *)keyv;

    /* Should not free static keys */
    if (VLBA_TREE_KEY_INVAL(key) || VLBA_TREE_KEY_MIN(key) || VLBA_TREE_KEY_MAX(key))
    {
        /* Should not have allocated them either */
        BUG_ON(!((key == &VLBA_TREE_INVAL_KEY) || (key == &VLBA_TREE_MIN_KEY) ||
                 (key == &VLBA_TREE_MAX_KEY)));
        return;
    }
    castle_object_btree_key_free(keyv);
}

/**
 * Return the number of dimensions in the key.
 */
static int castle_vlba_tree_key_nr_dims(const void *key)
{
    const c_vl_bkey_t *vl_bkey = key;

    return vl_bkey->nr_dims;
}

/**
 * Build a VLBA key of nr_dims.
 *
 * @param nr_dims       [in]    Number of dimensions
 * @param keys[]        [in]    Per-dimension keys
 * @param key_lens[]    [in]    Per-dimension key sizes (of keys[])
 * @param key_flags[]   [in]    Per-dimension key flags
 * @param key           [both]  NULL => Allocate a new key
 *                              *    => Buffer of key_len to build key
 * @param key_len       [in]    Size of key buffer
 *                      [out]   Size of key
 *
 * NOTE: If a key is passed in key_len describes the size of this buffer.
 *
 * NOTE: key_len is always updated to return the size of the constructed key.
 *
 * @return  Allocated key
 */
void * castle_vlba_tree_key_build(int nr_dims,
                                  int *keys,
                                  int *key_lens,
                                  int *key_flags,
                                  void *key,
                                  size_t *key_len)
{
    int key_size, payload_off, i;
    c_vl_bkey_t *vl_bkey = key;

    BUG_ON(nr_dims == 0);
    BUG_ON(!key_lens || !keys);

    /* Calculate the total size of the key. */
    key_size    = castle_object_btree_key_header_size(nr_dims);
    payload_off = key_size;
    for (i = 0; i < nr_dims; i++)
        key_size += key_lens[i];

    /* Allocate and initialise the key. */
    if (key)
        BUG_ON(*key_len >= key_size);
    else
        key = castle_alloc(key_size);
    vl_bkey->length  = key_size - 4; /* length doesn't include length field */
    vl_bkey->nr_dims = nr_dims;
    *((uint64_t *)vl_bkey->_unused) = 0;

    /* Populate key dimensions and flags. */
    for (i = 0; i < nr_dims; i++)
    {
        if (key_flags)
            vl_bkey->dim_head[i] = KEY_DIMENSION_HEADER(payload_off, key_flags[i]);
        else
            vl_bkey->dim_head[i] = KEY_DIMENSION_HEADER(payload_off, 0);
        memcpy(key + payload_off, &keys[i], key_lens[i]);
        payload_off += key_lens[i];
    }

    BUG_ON(payload_off != key_size);

    /* Return size of the constructed key. */
    *key_len = key_size;

    return key;
}

/**
 * Strip all but the first nr_dims from key and replace them with -inf.
 *
 * @param   src     Source key
 * @param   dst     Destination key buffer (can be NULL)
 * @param   dst_len Size of destination key buffer
 * @param   nr_dims Number of dimensions to keep (from beginning of key)
 */
void *castle_vlba_tree_key_strip(const void *src, void *dst, size_t *dst_len, int nr_dims)
{
    const c_vl_bkey_t *vl_bkey = src;

    if (vl_bkey->nr_dims <= 20)
    {
        /* Allocate key dimensions, lengths and flags on the stack. */
        int keys[20], key_lens[20], key_flags[20];
        int i;

        for (i = 0; i < nr_dims; i++)
        {
            keys[i]      = *castle_object_btree_key_dim_get(vl_bkey, i);
            key_lens[i]  =  castle_object_btree_key_dim_length(vl_bkey, i);
            key_flags[i] =  castle_object_btree_key_dim_flags_get(vl_bkey, i);
        }
        for (i = nr_dims; i < vl_bkey->nr_dims; i++)
        {
            //keys[i]      = 0;
            key_lens[i]  = 0;
            key_flags[i] = 0;
        }

        dst = castle_vlba_tree_key_build(vl_bkey->nr_dims,
                                         keys,
                                         key_lens,
                                         key_flags,
                                         dst,
                                         dst_len);
    }
    else
    {
        /* Allocate key dimensions, lengths and flags from the heap. */
        BUG();
    }

    return dst;
}

/**
 * Hash all but the last strip_dims dimensions of the key.
 *
 * @param   key         Key to hash
 * @param   type        Whether to hash the whole key or stripped dimensions
 * @param   seed        Hash seed
 *
 * NOTE: Hashing with type==HASH_STRIPPED_KEYS will result in a collision for
 *       some keys (e.g. [12,34] and [123,4]) because the dimension headers
 *       (which include dimension length) are not hashed.
 *       With type==HASH_WHOLE_KEY everything but the overall key length is
 *       hashed and so a collision is less likely (but not impossible).
 *
 * @return  Key hash    Hash of the key
 */
static uint32_t castle_vlba_tree_key_hash(const void *key, c_btree_hash_enum_t type, uint32_t seed)
{
    const vlba_key_t *vlba_key = key;
    const c_vl_bkey_t *vl_bkey = key;
    int length;

    switch (type)
    {
        case HASH_WHOLE_KEY:
            /* Hash all of the key but the length field. */

            return murmur_hash_32(vlba_key->_key, vlba_key->length, seed);

        case HASH_STRIPPED_KEYS:
            /* Hash the key's relevant stripped dimensions. */

            BUG_ON(vl_bkey->nr_dims <= HASH_STRIPPED_DIMS);

            key += KEY_DIMENSION_OFFSET(vl_bkey->dim_head[0]);

            length  = KEY_DIMENSION_OFFSET(vl_bkey->dim_head[HASH_STRIPPED_DIMS]);
            length -= KEY_DIMENSION_OFFSET(vl_bkey->dim_head[0]);

            return murmur_hash_32(key, length, seed);

        default:
            BUG();
    }
}

static void castle_vlba_tree_key_print(int level, const void *key)
{
    vl_bkey_print(level, key);
}

static int castle_vlba_tree_entry_get(struct castle_btree_node *node,
                                      int                       idx,
                                      void                    **key_p,
                                      c_ver_t                  *version_p,
                                      c_val_tup_t              *cvt_p)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry =
               (struct castle_vlba_tree_entry *) VLBA_ENTRY_PTR(node, vlba_node, idx);

    BUG_ON(idx < 0);
    BUG_ON(idx >= node->used);
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        *cvt_p = convert_to_cvt(entry->type,
                                entry->val_len,
                                entry->cep,
                                VLBA_ENTRY_VAL_PTR(entry),
                                entry->user_timestamp);
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        BUG_ON(VLBA_TREE_ENTRY_IS_INLINE(entry) &&
               (entry->val_len > MAX_INLINE_VAL_SIZE));
        BUG_ON(!BTREE_NODE_IS_LEAF(node) && CVT_LEAF_VAL(*cvt_p));
        BUG_ON(BTREE_NODE_IS_LEAF(node) && CVT_NODE(*cvt_p));
    }

    return entry->disabled;
}

#ifdef CASTLE_DEBUG
static void castle_vlba_tree_node_validate(struct castle_btree_node *node);
#endif

static void castle_vlba_tree_entry_add(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key_v,
                                       c_ver_t                   version,
                                       c_val_tup_t               cvt)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry;
    struct castle_vlba_tree_entry new_entry;
    vlba_key_t *key = (vlba_key_t *)key_v;
    uint32_t key_length = VLBA_KEY_LENGTH(key);
    /* entry header + key length + an entry in index table */
    uint32_t req_space;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(!BTREE_NODE_IS_LEAF(node) && CVT_LEAF_VAL(cvt));
#if 0
    if (BTREE_NODE_IS_LEAF(node) && CVT_NODE(cvt))
    {
        castle_printk(LOG_DEBUG, "%x:%llu\n", (uint32_t)cvt.type, cvt.length);
        BUG();
    }
#endif

    new_entry.version        = version;
    new_entry.type           = cvt_type_to_btree_entry_type(cvt.type);
    new_entry.disabled       = 0;
    new_entry.val_len        = cvt.length;
    new_entry.key.length     = key_length;
    new_entry.user_timestamp = cvt.user_timestamp;
    req_space = VLBA_ENTRY_LENGTH((&new_entry)) + sizeof(uint32_t);

    /* Initialization of node free space structures */
    if (node->used == 0)
    {
        vlba_node->dead_bytes = 0;
        vlba_node->free_bytes = VLBA_TREE_NODE_LENGTH(node) - sizeof(struct castle_btree_node) -
                                sizeof(struct castle_vlba_tree_node);
    }

    BUG_ON(key_length > VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(vlba_node->free_bytes + vlba_node->dead_bytes < req_space);

    if(vlba_node->free_bytes < req_space)
    {
        /* BUG if the key is in the node we are processing (compaction will invalidate the ptr). */
        BUG_ON(ptr_in_range(key, node, VLBA_TREE_NODE_LENGTH(node)));
        castle_vlba_tree_node_compact(node);
    }

    BUG_ON(vlba_node->free_bytes < req_space);

    vlba_node->free_bytes -= req_space;
    /* Free bytes count is already got updated. Adding free bytes count to the end of
     * index table gives us the pointer to new entry. */
    entry = (struct castle_vlba_tree_entry *)(((uint8_t *)&vlba_node->key_idx[node->used+1]) +
                                              vlba_node->free_bytes);
    memmove(&vlba_node->key_idx[idx+1], &vlba_node->key_idx[idx],
            sizeof(uint32_t) * (node->used - idx));

    vlba_node->key_idx[idx] = EOF_VLBA_NODE(node) - ((uint8_t *)entry);
    memcpy(entry, &new_entry, sizeof(struct castle_vlba_tree_entry));
    memcpy(&entry->key, key, sizeof(vlba_key_t) + key_length);

    BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
    if (VLBA_TREE_ENTRY_IS_INLINE(entry))
    {
        BUG_ON(entry->val_len > MAX_INLINE_VAL_SIZE);
        BUG_ON(VLBA_ENTRY_VAL_PTR(entry)+cvt.length > EOF_VLBA_NODE(node));
        memmove(VLBA_ENTRY_VAL_PTR(entry),
                CVT_INLINE_VAL_PTR(cvt),
                cvt.length);
    }
    else
        entry->cep = cvt.cep;

    /* Increment the node used count */
    node->used++;
}

static void castle_vlba_tree_entries_drop(struct castle_btree_node *node,
                                          int                       idx_start,
                                          int                       idx_end)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry;
    uint32_t i;

    BUG_ON(idx_start < 0 || idx_start > node->used);
    BUG_ON(idx_end   < 0 || idx_end   > node->used);
    BUG_ON(idx_start > idx_end);

    /* Calculate space taken by the entries getting dropped */
    for(i=idx_start; i <= idx_end; i++)
    {
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);
        vlba_node->dead_bytes += VLBA_ENTRY_LENGTH(entry) + sizeof(uint32_t);
    }

    /* Move the index table entries forward */
    memmove(&vlba_node->key_idx[idx_start],
            &vlba_node->key_idx[idx_end+1],
            sizeof(uint32_t) * (node->used - (idx_end + 1)));

    /* Decrement the node used count */
    node->used -= (idx_end - idx_start + 1);
}

static void castle_vlba_tree_entry_replace(struct castle_btree_node *node,
                                           int                       idx,
                                           void                     *key_v,
                                           c_ver_t                   version,
                                           c_val_tup_t               cvt)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry =
        (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, idx);
    struct castle_vlba_tree_entry new_entry;
    vlba_key_t *key = (vlba_key_t *)key_v;
    int old_length, new_length;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!BTREE_NODE_IS_LEAF(node) && CVT_LEAF_VAL(cvt));
#if 0
    BUG_ON(BTREE_NODE_IS_LEAF(node) && CVT_NODE(cvt));
#endif
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    new_entry.version        = version;
    new_entry.type           = cvt_type_to_btree_entry_type(cvt.type);
    new_entry.disabled       = 0;
    new_entry.val_len        = cvt.length;
    new_entry.key.length     = key->length;
    new_entry.user_timestamp = cvt.user_timestamp;
    new_length = VLBA_ENTRY_LENGTH((&new_entry));
    old_length = VLBA_ENTRY_LENGTH(entry);

    if (new_length <= old_length)
    {
        vlba_node->dead_bytes += old_length - new_length;

        memcpy(entry, &new_entry, sizeof(struct castle_vlba_tree_entry));
        memcpy(&entry->key, key, sizeof(vlba_key_t) + VLBA_KEY_LENGTH(key));
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        if (VLBA_TREE_ENTRY_IS_INLINE(entry))
        {
            BUG_ON(entry->val_len > MAX_INLINE_VAL_SIZE);
            memcpy(VLBA_ENTRY_VAL_PTR(entry),
                   CVT_INLINE_VAL_PTR(cvt),
                   cvt.length);
        }
        else
            entry->cep      = cvt.cep;
    }
    else
    {
        castle_vlba_tree_entries_drop(node, idx, idx);
        castle_vlba_tree_entry_add(node, idx, key, version, cvt);
    }
}

static void castle_vlba_tree_entry_disable(struct castle_btree_node *node,
                                           int                       idx)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry =
        (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, idx);
    entry->disabled = 1;
}


#ifdef CASTLE_DEBUG
static void castle_vlba_tree_node_validate(struct castle_btree_node *node)
{
    struct castle_vlba_tree_node *vlba_node =
                (struct castle_vlba_tree_node *) BTREE_NODE_PAYLOAD(node);
    uint32_t i, prev_offset = 0, prev_len = 0;
    uint32_t *a, *idx;
    uint32_t count;
    struct castle_vlba_tree_entry *prev_entry;

    if(0 == 0)
        return;
    a = castle_alloc(sizeof(uint32_t) * node->used);
    idx = castle_alloc(sizeof(uint32_t) * node->used);
    BUG_ON(!a || !idx);

    memcpy(a, &vlba_node->key_idx[0], (sizeof(uint32_t) * node->used));
    for (i=0, count=0; i < node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;

        idx[i] = i;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);
        count += VLBA_ENTRY_LENGTH(entry);
    }

    /* Check for total length adds upto node length */
    /* node header + vlba header + index table + free bytes + sum of entries + dead bytes */
    if ( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
            sizeof(uint32_t) * node->used + vlba_node->free_bytes + count +
            vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH(node))
    {
        castle_printk(LOG_ERROR, "sizeof(struct castle_btree_node) + "
                "sizeof(struct castle_vlba_tree_node) + Index Table + Free Bytes "
                "+ Sum of entries + Dead Bytes\n");
        castle_printk(LOG_ERROR, "%u-%u-%u-%u-%u-%u\n",
                (uint32_t)sizeof(struct castle_btree_node),
                (uint32_t)sizeof(struct castle_vlba_tree_node),
                (uint32_t)sizeof(uint32_t) * node->used,
                vlba_node->free_bytes,
                count,
                vlba_node->dead_bytes);
        BUG();
    }

    /* Store index for each entry to update entries index in the table */
    min_heap_heapify(a, idx, node->used);

    count = node->used;
    prev_offset = -1;
    prev_len = 0;
    prev_entry = NULL;
    while (count)
    {
        uint32_t entry_offset, ent_len;
        struct castle_vlba_tree_entry *entry;

        entry_offset = min_heap_del_root(a, idx, count);
        count--;
        entry = (struct castle_vlba_tree_entry *)(EOF_VLBA_NODE(node) - entry_offset);
        ent_len = (uint32_t)VLBA_ENTRY_LENGTH(entry);

        if (((uint8_t *)entry) + ent_len > EOF_VLBA_NODE(node))
        {
            castle_printk(LOG_ERROR, "Entry Overflow: Entry-%p; Length-%u; NodeEnd-%p\n",
                   entry, ent_len, EOF_VLBA_NODE(node));
            BUG();
        }
        if (entry_offset != a[count])
        {
            castle_printk(LOG_ERROR, "Heap sort error\n");
            BUG();
        }
        if ((prev_offset != -1) && (prev_offset + ent_len > entry_offset))
        {
            castle_printk(LOG_ERROR, "Entry overlap: offset:length -> %u:%u-%u:%u\n",
                    prev_offset, prev_len, entry_offset, ent_len);
            BUG();
        }
        prev_offset = entry_offset;
        prev_len = ent_len;
    }

    /* Check whether the keys in the node are in (k, v) order */
    prev_entry = NULL;
    prev_offset = -1;
    prev_len = 0;
    for (i=0; i<node->used; i++)
    {
        uint32_t entry_offset;
        struct castle_vlba_tree_entry *entry;
        uint8_t ret;

        entry_offset = vlba_node->key_idx[i];
        entry = (struct castle_vlba_tree_entry *)(EOF_VLBA_NODE(node) - entry_offset);

        ret = (prev_offset == -1)?0:castle_vlba_tree_key_compare(&prev_entry->key, &entry->key);
        if ((prev_offset != -1) &&
            (ret == 1 ||
             (!ret &&
              castle_version_is_ancestor(prev_entry->version, entry->version))))
        {
            int j;

            castle_printk(LOG_ERROR, "Entry 1:\n");
            castle_printk(LOG_ERROR, "[%d] (", i-1);
            for(j=0; j<VLBA_KEY_LENGTH(&prev_entry->key); j++)
                castle_printk(LOG_ERROR, "%.2x", prev_entry->key._key[j]);
            castle_printk(LOG_ERROR, ", 0x%x) -> "cep_fmt_str_nl,
                prev_entry->version,
                cep2str(prev_entry->cep));

            castle_printk(LOG_ERROR, "Entry 2:\n");
            castle_printk(LOG_ERROR, "[%d] (", i);
            for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
                castle_printk(LOG_ERROR, "%.2x", entry->key._key[j]);
            castle_printk(LOG_ERROR, ", 0x%x) -> "cep_fmt_str_nl,
                entry->version,
                cep2str(entry->cep));
            BUG();
        }

        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        BUG_ON(VLBA_INLINE_VAL_LENGTH(entry) > MAX_INLINE_VAL_SIZE);
    }

    castle_free(a);
    castle_free(idx);
}
#endif

static void castle_vlba_tree_node_print(struct castle_btree_node *node)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    int i, j;

    castle_printk(LOG_DEBUG, "node->used=%d, node=%p, vlba_node=%p, payload=%p\n",
            node->used,
            node,
            vlba_node,
            ((uint8_t*)vlba_node + sizeof(struct castle_vlba_tree_node)));
    for(i=0; i<node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);

        castle_printk(LOG_DEBUG, "[%d] key_idx[%d]=%d, key_length=%d, val_len=%lld, entry_size=%lld (",
                i, i, vlba_node->key_idx[i], VLBA_KEY_LENGTH(&entry->key),
                entry->val_len,
                VLBA_ENTRY_LENGTH(entry));
        for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
            castle_printk(LOG_DEBUG, "%.2x", entry->key._key[j]);
        castle_printk(LOG_DEBUG, ", 0x%x) -> "cep_fmt_str_nl, entry->version, cep2str(entry->cep));
    }
    castle_printk(LOG_DEBUG, "\n");
}


struct castle_btree_type castle_vlba_tree = {
    .magic          = VLBA_TREE_TYPE,
    .min_key        = (void *)&VLBA_TREE_MIN_KEY,
    .max_key        = (void *)&VLBA_TREE_MAX_KEY,
    .inv_key        = (void *)&VLBA_TREE_INVAL_KEY,
    .max_entries    = castle_vlba_tree_max_entries,
    .need_split     = castle_vlba_tree_need_split,
    .key_pack       = castle_vlba_tree_key_pack,
    .key_unpack     = castle_vlba_tree_key_unpack,
    .key_compare    = castle_vlba_tree_key_compare,
    .key_size       = castle_vlba_tree_key_size,
    .key_copy       = castle_vlba_tree_key_copy,
    .key_next       = castle_vlba_tree_key_next,
    .key_hc_next    = castle_vlba_tree_key_hc_next,
    .key_dealloc    = castle_vlba_tree_key_dealloc,
    .nr_dims        = castle_vlba_tree_key_nr_dims,
    .key_strip      = castle_vlba_tree_key_strip,
    .key_hash       = castle_vlba_tree_key_hash,
    .key_print      = castle_vlba_tree_key_print,
    .entry_get      = castle_vlba_tree_entry_get,
    .entry_add      = castle_vlba_tree_entry_add,
    .entry_replace  = castle_vlba_tree_entry_replace,
    .entry_disable  = castle_vlba_tree_entry_disable,
    .entries_drop   = castle_vlba_tree_entries_drop,
    .node_print     = castle_vlba_tree_node_print,
#ifdef CASTLE_DEBUG
    .node_validate  = castle_vlba_tree_node_validate,
#endif
};
