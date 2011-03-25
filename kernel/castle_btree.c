#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_objects.h"
#include "castle_utils.h"
#include "castle_versions.h"
#include "castle_da.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define iter_debug(_f, ...)     ((void)0)
#define enum_debug(_f, ...)     ((void)0)
#define rq_debug(_f, ...)       ((void)0)
#else
#define debug(_f, _a...)        (castle_printk("%s:%.60s:%.4d: " _f,                        \
                                                __FILE__, __func__, __LINE__ , ##_a))
#define iter_debug(_f, _a...)   (castle_printk("Iterator  :%.60s:%.4d:  " _f,               \
                                                __func__, __LINE__ , ##_a))
#define enum_debug(_f, _a...)   (castle_printk("Enumerator:%.60s:%.4d:  " _f,               \
                                                __func__, __LINE__ , ##_a))
#define rq_debug(_f, _a...)     (castle_printk("Range Query:%.60s:%.4d:  " _f,              \
                                                __func__, __LINE__ , ##_a))
#endif

#define __XOR(a, b) (((a) && !(b)) || (!(a) && (b)))

c_val_tup_t convert_to_cvt(uint8_t type, uint64_t length, c_ext_pos_t cep)
{
    c_val_tup_t cvt;

    cvt.type    = type;
    cvt.length  = length;
    if (CVT_LEAF_PTR(cvt) || CVT_NODE(cvt) || CVT_ONDISK(cvt))
    {
        cvt.cep    = cep;
    }
    else if (CVT_TOMB_STONE(cvt))
    {
        cvt.length = 0;
        cvt.cep    = INVAL_EXT_POS;
    }
    else if (CVT_INLINE(cvt))
        cvt.val    = NULL;

    return cvt;
}

static DECLARE_WAIT_QUEUE_HEAD(castle_btree_iters_wq);
static atomic_t castle_btree_iters_cnt = ATOMIC_INIT(0);

struct castle_btree_node_save {
    struct castle_component_tree   *ct;
    c_ext_pos_t                     node_cep;
    uint32_t                        node_size;
    struct work_struct              work;
};


/**********************************************************************************************/
/* Block mapper btree (mtree) definitions */

#define MTREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define MTREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define MTREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define MTREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)) || CVT_LEAF_PTR(*(_slot)))

#define MTREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMB_STONE(*(_slot))
#define MTREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define MTREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define MTREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define MTREE_ENTRY_IS_ONDISK(_slot)        CVT_ONDISK(*(_slot))
#define MTREE_INVAL_BLK          ((block_t)-1)
#define MTREE_MAX_BLK            ((block_t)-2)
#define MTREE_BLK_INVAL(_blk)    ((_blk) == MTREE_INVAL_BLK)

struct castle_mtree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t     type;
    /*          1 */ uint8_t     _pad[3];
    /*          4 */ block_t     block;
    /*          8 */ version_t   version;
    /*         12 */ uint32_t    val_len;
    /*         16 */ c_ext_pos_t cep;
    /*         32 */
} PACKED;

#define MTREE_NODE_ENTRIES  ((MTREE_NODE_SIZE * PAGE_SIZE - sizeof(struct castle_btree_node))  \
                             / sizeof(struct castle_mtree_entry))

/**
 * Size of mtree btree nodes equals MTREE_NODE_SIZE (10 pages).
 */
static uint16_t castle_mtree_node_size(struct castle_component_tree *ct, uint8_t level)
{
    return MTREE_NODE_SIZE;
}

static int castle_mtree_need_split(struct castle_btree_node *node, int ver_or_key_split)
{
    switch(ver_or_key_split)
    {
        case 0:
            return ((node->is_leaf &&  (node->used == MTREE_NODE_ENTRIES)) ||
                    (!node->is_leaf && (MTREE_NODE_ENTRIES - node->used < 2)));
        case 1:
            return (node->used > 2 * MTREE_NODE_ENTRIES / 3);
        default:
            BUG();
    }

    return -1;
}

static int castle_mtree_key_compare(void *key1, void *key2)
{
    block_t blk1 = (block_t)(unsigned long)key1;
    block_t blk2 = (block_t)(unsigned long)key2;

    if(unlikely(MTREE_BLK_INVAL(blk1) && MTREE_BLK_INVAL(blk2)))
        return 0;

    if(unlikely(MTREE_BLK_INVAL(blk1)))
        return -1;

    if(unlikely(MTREE_BLK_INVAL(blk2)))
        return 1;

    if(blk1 < blk2)
        return -1;

    if(blk1 > blk2)
        return 1;

    return 0;
}

static void* castle_mtree_key_duplicate(void *key)
{
    /* No need to do anything in mtree keys, because they are ints (casted to void *). */
    return key;
}

static void* castle_mtree_key_next(void *key)
{
    block_t blk = (block_t)(unsigned long)key;

    /* No successor to invalid block */
    if(MTREE_BLK_INVAL(blk))
        return (void *)(unsigned long)MTREE_INVAL_BLK;

    /* MTREE_INVAL_BLK is the successor of MTREE_MAX_BLK, conviniently */
    return (void *)(unsigned long)(blk+1);
}

static void castle_mtree_key_dealloc(void *key)
{
    /* No need to do anything in mtree keys, because they are ints (casted to void *). */
}

static uint32_t castle_mtree_key_hash(void *key, uint32_t seed)
{
    BUG();
}

static int castle_mtree_entry_get(struct castle_btree_node *node,
                                  int                       idx,
                                  void                    **key_p,
                                  version_t                *version_p,
                                  c_val_tup_t              *cvt_p)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)(unsigned long)entry->block;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        *cvt_p = convert_to_cvt(entry->type, entry->val_len, entry->cep);
        BUG_ON(!CVT_MEDIUM_OBJECT(*cvt_p) && !CVT_NODE(*cvt_p) && !CVT_LEAF_PTR(*cvt_p));
    }

    return 0;
}

static void castle_mtree_entry_add(struct castle_btree_node *node,
                                   int                       idx,
                                   void                     *key,
                                   version_t                 version,
                                   c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) >
                                                MTREE_NODE_SIZE * C_BLK_SIZE);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    /* Make space for the new entry, noop if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    BUG_ON(!CVT_MEDIUM_OBJECT(cvt) && !CVT_NODE(cvt) && !CVT_LEAF_PTR(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}

static void castle_mtree_entry_replace(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key,
                                       version_t                 version,
                                       c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    BUG_ON(!CVT_MEDIUM_OBJECT(cvt) && !CVT_NODE(cvt) && !CVT_LEAF_PTR(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;
}

static void castle_mtree_entry_disable(struct castle_btree_node *node,
                                       int                       idx)
{
    /* This does nothing, which means that we cannot merge MTrees,
       that's fine ATM */
}

static void castle_mtree_entries_drop(struct castle_btree_node *node,
                                      int                       idx_start,
                                      int                       idx_end)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry_start = entries + idx_start;
    struct castle_mtree_entry *entry_end   = entries + idx_end;

    BUG_ON(idx_start < 0 || idx_start > node->used);
    BUG_ON(idx_end   < 0 || idx_end   > node->used);
    BUG_ON(idx_start > idx_end);

    /* Move the node entries forward */
    memmove(entry_start,
            entry_end + 1,
            sizeof(*entry_start) * (node->used - idx_end - 1));
    /* Decrement the node used count */
    node->used -= (idx_end - idx_start + 1);
}

#ifdef CASTLE_DEBUG
static void castle_mtree_node_validate(struct castle_btree_node *node)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->used     > MTREE_NODE_ENTRIES) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        castle_printk("Invalid mtree node used=%d and/or node version=%d\n",
               node->used, node->version);
        BUG();
    }

    for(i=0; i < node->used; i++)
    {
        struct castle_mtree_entry *entry = entries + i;
        /* Fail if node is_leaf doesn't match with the slot. ! needed
           to guarantee canonical value for boolean true */
        BUG_ON(!(node->is_leaf) != !(MTREE_ENTRY_IS_ANY_LEAF(entry)));
    }
}
#endif

static void castle_mtree_node_print(struct castle_btree_node *node)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    castle_printk("Node: used=%d, version=%d, is_leaf=%d\n",
        node->used, node->version, node->is_leaf);
    for(i=0; i<node->used; i++)
        castle_printk("[%d] (0x%x, 0x%x, %s) -> "cep_fmt_str_nl,
            i,
            entries[i].block,
            entries[i].version,
            MTREE_ENTRY_IS_LEAF_PTR(entries + i) ? "leafptr" : "direct ",
            cep2str(entries[i].cep));
    castle_printk("\n");
}


struct castle_btree_type castle_mtree = {
    .magic          = MTREE_TYPE,
    .min_key        = (void *)0,
    .max_key        = (void *)MTREE_MAX_BLK,
    .inv_key        = (void *)MTREE_INVAL_BLK,
    .node_size      = castle_mtree_node_size,
    .need_split     = castle_mtree_need_split,
    .key_compare    = castle_mtree_key_compare,
    .key_duplicate  = castle_mtree_key_duplicate,
    .key_next       = castle_mtree_key_next,
    .key_dealloc    = castle_mtree_key_dealloc,
    .key_hash       = castle_mtree_key_hash,
    .entry_get      = castle_mtree_entry_get,
    .entry_add      = castle_mtree_entry_add,
    .entry_replace  = castle_mtree_entry_replace,
    .entry_disable  = castle_mtree_entry_disable,
    .entries_drop   = castle_mtree_entries_drop,
    .node_print     = castle_mtree_node_print,
#ifdef CASTLE_DEBUG
    .node_validate  = castle_mtree_node_validate,
#endif
};

/**********************************************************************************************/
/* Fixed size byte array key btree (batree) definitions */

#define BATREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define BATREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define BATREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define BATREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)) || CVT_LEAF_PTR(*(_slot)))

#define BATREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMB_STONE(*(_slot))
#define BATREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define BATREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define BATREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define BATREE_ENTRY_IS_ONDISK(_slot)        CVT_ONDISK(*(_slot))

#define BATREE_KEY_SIZE         128      /* In bytes */
typedef struct bakey {
    /* align:   1 */
    /* offset:  0 */ uint8_t _key[BATREE_KEY_SIZE];
    /*        128 */
} PACKED bakey_t;

static const bakey_t BATREE_INVAL_KEY = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0xFF}};
static const bakey_t BATREE_MIN_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0x00}};
static const bakey_t BATREE_MAX_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-2)] = 0xFF,
                                                           [      (BATREE_KEY_SIZE-1)] = 0xFE}};
#define BATREE_KEY_INVAL(_key)          ((_key) == &BATREE_INVAL_KEY)
#define BATREE_KEY_MIN(_key)            ((_key) == &BATREE_MIN_KEY)
#define BATREE_KEY_MAX(_key)            ((_key) == &BATREE_MAX_KEY)

struct castle_batree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t      type;
    /*          1 */ uint8_t      _pad1[3];
    /*          4 */ bakey_t      key;
    /*        132 */ version_t    version;
    /*        136 */ uint32_t     val_len;
    /*        140 */ uint8_t      _pad2[4];
    /*        144 */ c_ext_pos_t  cep;
    /*        160 */
} PACKED;

#define BATREE_NODE_SIZE     (20) /* In blocks */
#define BATREE_NODE_ENTRIES  ((BATREE_NODE_SIZE * PAGE_SIZE - sizeof(struct castle_btree_node)) \
                                / sizeof(struct castle_batree_entry))

static void inline castle_batree_key_print(bakey_t *key)
{
    int i;

    for(i=0; i<BATREE_KEY_SIZE; i++)
        castle_printk("%.2x", key->_key[i]);
}

/**
 * Size of batree btree nodes equals BATREE_NODE_SIZE (20 pages).
 */
static uint16_t castle_batree_node_size(struct castle_component_tree *ct, uint8_t level)
{
    return BATREE_NODE_SIZE;
}

static int castle_batree_need_split(struct castle_btree_node *node, int ver_or_key_split)
{
    switch(ver_or_key_split)
    {
        case 0:
            return ((node->is_leaf &&  (node->used == BATREE_NODE_ENTRIES)) ||
                    (!node->is_leaf && (BATREE_NODE_ENTRIES - node->used < 2)));
        case 1:
            return (node->used > 2 * BATREE_NODE_ENTRIES / 3);
        default:
            BUG();
    }

    return -1;
}

static int castle_batree_key_compare(void *keyv1, void *keyv2)
{
    bakey_t *key1 = (bakey_t *)keyv1;
    bakey_t *key2 = (bakey_t *)keyv2;
    int ret;

    if(unlikely(BATREE_KEY_INVAL(key1) && BATREE_KEY_INVAL(key2)))
        return 0;

    if(unlikely(BATREE_KEY_INVAL(key1)))
        return -1;

    if(unlikely(BATREE_KEY_INVAL(key2)))
        return 1;

    ret = memcmp(key1, key2, sizeof(bakey_t));

    return ret;
}

static void* castle_batree_key_duplicate(void *keyv)
{
    bakey_t *key = (bakey_t *)keyv;
    bakey_t *new_key;

    if (BATREE_KEY_INVAL(key) || BATREE_KEY_MIN(key) || BATREE_KEY_MAX(key))
        return key;

    new_key = castle_malloc(sizeof(bakey_t), GFP_NOIO);
    BUG_ON(!new_key);
    memcpy(new_key, key, sizeof(bakey_t));

    return new_key;
}

static void* castle_batree_key_next(void *keyv)
{
    bakey_t *key = (bakey_t *)keyv;
    bakey_t *succ;
    int i;

    /* No successor to invalid block */
    if(BATREE_KEY_INVAL(key))
        return (void *)&BATREE_INVAL_KEY;

    /* Successor to max key is the invalid key (return the static copy). */
    if(castle_batree_key_compare((void *)&BATREE_MAX_KEY, key) == 0)
        return (void *)&BATREE_INVAL_KEY;

    /* Finally allocate and return the successor key */
    succ = castle_malloc(sizeof(bakey_t), GFP_NOIO);
    /* @TODO: Should this be handled properly? */
    BUG_ON(!succ);
    memcpy(succ, key, sizeof(bakey_t));
    for (i=sizeof(bakey_t)-1; i >= 0; i--)
        if((++succ->_key[i]) != 0)
            break;

    return succ;
}

static void castle_batree_key_dealloc(void *key)
{
    if (BATREE_KEY_INVAL(key) || BATREE_KEY_MIN(key) || BATREE_KEY_MAX(key))
        return;

    castle_free(key);
}

static uint32_t castle_batree_key_hash(void *key, uint32_t seed)
{
    BUG();
}

static int castle_batree_entry_get(struct castle_btree_node *node,
                                   int                       idx,
                                   void                    **key_p,
                                   version_t                *version_p,
                                   c_val_tup_t              *cvt_p)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        BUG_ON(!BATREE_ENTRY_IS_ONDISK(entry) && !BATREE_ENTRY_IS_NODE(entry));
        *cvt_p = convert_to_cvt(entry->type, entry->val_len, entry->cep);
    }

    return 0;
}

static void castle_batree_entry_add(struct castle_btree_node *node,
                                    int                       idx,
                                    void                     *key,
                                    version_t                 version,
                                    c_val_tup_t               cvt)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) >
                                                BATREE_NODE_SIZE * C_BLK_SIZE);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    /* Make space for the new entry, noop if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    BUG_ON(CVT_INVALID(cvt) || CVT_INLINE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}

static void castle_batree_entry_replace(struct castle_btree_node *node,
                                        int                       idx,
                                        void                     *key,
                                        version_t                 version,
                                        c_val_tup_t               cvt)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    BUG_ON(CVT_INVALID(cvt) || CVT_INLINE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;
}

static void castle_batree_entry_disable(struct castle_btree_node *node,
                                        int                       idx)
{
    /* This does nothing, which means that we cannot merge BATrees,
       that's fine ATM */
}

static void castle_batree_entries_drop(struct castle_btree_node *node,
                                       int                       idx_start,
                                       int                       idx_end)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry_start = entries + idx_start;
    struct castle_batree_entry *entry_end   = entries + idx_end;

    BUG_ON(idx_start < 0 || idx_start > node->used);
    BUG_ON(idx_end   < 0 || idx_end   > node->used);
    BUG_ON(idx_start > idx_end);

    /* Move the node entries forward */
    memmove(entry_start,
            entry_end + 1,
            sizeof(*entry_start) * (node->used - idx_end - 1));
    /* Decrement the node used count */
    node->used -= (idx_end - idx_start + 1);
}

#ifdef CASTLE_DEBUG
static void castle_batree_node_validate(struct castle_btree_node *node)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->used     > BATREE_NODE_ENTRIES) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        castle_printk("Invalid batree node used=%d and/or node version=%d\n",
               node->used, node->version);
        BUG();
    }

    for(i=0; i < node->used; i++)
    {
        struct castle_batree_entry *entry = entries + i;
        /* Fail if node is_leaf doesn't match with the slot. ! needed
           to guarantee canonical value for boolean true */
        BUG_ON(!(node->is_leaf) != !(BATREE_ENTRY_IS_ANY_LEAF(entry)));
    }
}
#endif

static void castle_batree_node_print(struct castle_btree_node *node)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    int i, j;

    for(i=0; i<node->used; i++)
    {
        struct castle_batree_entry *entry = entries + i;

        castle_printk("[%d] (", i);
        for(j=0; j<BATREE_KEY_SIZE; j++)
            castle_printk("%.2x", entry->key._key[j]);
        castle_printk(", 0x%x) -> "cep_fmt_str_nl,
            entries[i].version,
            cep2str(entries[i].cep));
    }
    castle_printk("\n");
}


struct castle_btree_type castle_batree = {
    .magic          = BATREE_TYPE,
    .min_key        = (void *)&BATREE_MIN_KEY,
    .max_key        = (void *)&BATREE_MAX_KEY,
    .inv_key        = (void *)&BATREE_INVAL_KEY,
    .node_size      = castle_batree_node_size,
    .need_split     = castle_batree_need_split,
    .key_compare    = castle_batree_key_compare,
    .key_duplicate  = castle_batree_key_duplicate,
    .key_next       = castle_batree_key_next,
    .key_dealloc    = castle_batree_key_dealloc,
    .key_hash       = castle_batree_key_hash,
    .entry_get      = castle_batree_entry_get,
    .entry_add      = castle_batree_entry_add,
    .entry_replace  = castle_batree_entry_replace,
    .entry_disable  = castle_batree_entry_disable,
    .entries_drop   = castle_batree_entries_drop,
    .node_print     = castle_batree_node_print,
#ifdef CASTLE_DEBUG
    .node_validate  = castle_batree_node_validate,
#endif
};


/**********************************************************************************************/
/* Variable length byte array key btree (vlbatree) definitions */

#define VLBA_RW_TREE_NODE_SIZE                  (2)      /**< Size of the RW tree node size.
                                                              Constant independent of the level. */
#define VLBA_RW_TREE_MAX_ENTRIES                (2500UL) /**< Maximum number of entries in any
                                                              of the RW tree entries. */

#define VLBA_TREE_ENTRY_DISABLED                0x80
#define VLBA_TREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define VLBA_TREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define VLBA_TREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define VLBA_TREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)) || CVT_LEAF_PTR(*(_slot)))

#define VLBA_TREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMB_STONE(*(_slot))
#define VLBA_TREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define VLBA_TREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define VLBA_TREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define VLBA_TREE_ENTRY_IS_ONDISK(_slot)        CVT_ONDISK(*(_slot))
#define VLBA_TREE_ENTRY_IS_DISABLED(_slot)      ((_slot)->type & VLBA_TREE_ENTRY_DISABLED)

typedef struct vlba_key {
    /* align:   4 */
    /* offset:  0 */ uint32_t length;
    /*          4 */ uint8_t _key[0];
    /*          4 */
} PACKED vlba_key_t;

static const vlba_key_t VLBA_TREE_INVAL_KEY = (vlba_key_t){.length = 0xFFFFFFFF};
static const vlba_key_t VLBA_TREE_MIN_KEY = (vlba_key_t){.length = 0x00};
static const vlba_key_t VLBA_TREE_MAX_KEY = (vlba_key_t){.length = 0xFFFFFFFE};

#define VLBA_TREE_KEY_INVAL(_key)          ((_key)->length == VLBA_TREE_INVAL_KEY.length)
#define VLBA_TREE_KEY_MIN(_key)            ((_key)->length == VLBA_TREE_MIN_KEY.length)
#define VLBA_TREE_KEY_MAX(_key)            ((_key)->length == VLBA_TREE_MAX_KEY.length)

struct castle_vlba_tree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t      type;
    /*          1 */ uint8_t      _pad[3];
    /*          4 */ version_t    version;
    /*          8 */ uint64_t     val_len;
    /*         16 */ c_ext_pos_t  cep;
    /*         32 */ vlba_key_t   key;
    /*         36 *//* Inline values are stored at the end of entry */
} PACKED;

struct castle_vlba_tree_node {
    /* align:   4 */
    /* offset:  0 */ uint32_t    dead_bytes;
    /*          4 */ uint32_t    free_bytes;
    /*          8 */ uint8_t     _unused[56];
    /*         64 */ uint32_t    key_idx[0];
    /*         64 */
} PACKED;

#define VLBA_TREE_NODE_SIZE(_node)          ((_node)->size)
#define VLBA_TREE_NODE_LENGTH(_node)        ({int _ns = VLBA_TREE_NODE_SIZE(_node);       \
                                              BUG_ON(_ns == 0 || _ns > 256);              \
                                              (_ns * C_BLK_SIZE); })
#define EOF_VLBA_NODE(_node)                (((uint8_t *)_node) + VLBA_TREE_NODE_LENGTH(_node))
#define VLBA_KEY_LENGTH(_key)               (VLBA_TREE_KEY_MAX(_key) ? 0 : (_key)->length)
#define VLBA_INLINE_VAL_LENGTH(_entry)                                      \
                (VLBA_TREE_ENTRY_IS_INLINE(_entry)?(_entry)->val_len:0)
#define VLBA_ENTRY_LENGTH(_entry)                                           \
                (sizeof(struct castle_vlba_tree_entry) +                    \
                VLBA_KEY_LENGTH(&(_entry)->key) +                           \
                VLBA_INLINE_VAL_LENGTH(_entry))
#define MAX_VLBA_ENTRY_LENGTH                                               \
                (sizeof(struct castle_vlba_tree_entry) +                    \
                 VLBA_TREE_MAX_KEY_SIZE +                                   \
                 MAX_INLINE_VAL_SIZE +                                      \
                 sizeof(uint32_t))
#define VLBA_ENTRY_PTR(__node, _vlba_node, _i)                              \
                (EOF_VLBA_NODE(__node) - _vlba_node->key_idx[_i])
#define VLBA_ENTRY_VAL_PTR(_entry)                                          \
                ((uint8_t *)((uint8_t *)_entry +                            \
                 VLBA_ENTRY_LENGTH(_entry) -                                \
                 _entry->val_len))

/**
 * Returns maximum number of entries that can be stored in a node of the specified size.
 *
 * @param node_size     Size of the node in pages.
 */
uint32_t castle_btree_vlba_max_nr_entries_get(uint16_t node_size)
{
    return (((size_t)node_size) * PAGE_SIZE - sizeof(struct castle_btree_node))
                 / MAX_VLBA_ENTRY_LENGTH;
}

/**
 * Size of RW vlba tree nodes (VLBA_RW_TREE_NODE_SIZE, currently equals to 2 pages).
 * This is a constant, which prevents from races between calls to this function, and
 * root splits.
 */
static uint16_t castle_vlba_rw_tree_node_size(struct castle_component_tree *ct, uint8_t level)
{
    return VLBA_RW_TREE_NODE_SIZE;
}

/**
 * Size of RO vlba tree nodes, this is taken from the particular component tree structure.
 * @param ct    Component tree for which node size is to be found.
 * @param level Level, counted from the leafs (which are level=0).
 */
static uint16_t castle_vlba_ro_tree_node_size(struct castle_component_tree *ct, uint8_t level)
{
    BUG_ON(level >= ct->tree_depth);
    return ct->node_sizes[level];
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

    /* Buffers to keep the minimum heap of entries offsets and corresponsding
     * entry index */
    a = castle_malloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = castle_malloc(sizeof(uint32_t) * node->used, GFP_NOIO);
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

    /* Special case, unitialised node should never be split. */
    if(node->used == 0)
        return 0;

    switch(ver_or_key_split)
    {
        case 0:
            if(node->is_leaf)
            {
                if(vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH)
                    return 1;
                return 0;
            } else
            {
                if(vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH*2)
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

static int castle_vlba_tree_key_compare(void *keyv1, void *keyv2)
{
    vlba_key_t *key1 = (vlba_key_t *)keyv1;
    vlba_key_t *key2 = (vlba_key_t *)keyv2;
    int key1_min, key2_min, key1_max, key2_max;

    BUG_ON(!key1 || !key2);

    if(unlikely(VLBA_TREE_KEY_INVAL(key1) && VLBA_TREE_KEY_INVAL(key2)))
        return 0;

    if(unlikely(VLBA_TREE_KEY_INVAL(key1)))
        return -1;

    if(unlikely(VLBA_TREE_KEY_INVAL(key2)))
        return 1;

    key1_min = !!VLBA_TREE_KEY_MIN(key1);
    key2_min = !!VLBA_TREE_KEY_MIN(key2);
    if(key1_min || key2_min)
        return key2_min - key1_min;

    key1_max = !!VLBA_TREE_KEY_MAX(key1);
    key2_max = !!VLBA_TREE_KEY_MAX(key2);
    if(key1_max || key2_max)
        return key1_max - key2_max;

    BUG_ON(VLBA_KEY_LENGTH(key1) >= VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(VLBA_KEY_LENGTH(key2) >= VLBA_TREE_MAX_KEY_SIZE);

    return castle_object_btree_key_compare(keyv1, keyv2);
}

static void* castle_vlba_tree_key_next(void *keyv)
{
    vlba_key_t *key = (vlba_key_t *)keyv;

    /* No successor to invalid or min key. */
    BUG_ON(VLBA_TREE_KEY_INVAL(key));
    BUG_ON(VLBA_TREE_KEY_MIN(key));
    /* Successor to max key is the invalid key */
    if(VLBA_TREE_KEY_MAX(key))
        return (void *)&VLBA_TREE_INVAL_KEY;

    return castle_object_btree_key_next(keyv);
}

static void* castle_vlba_tree_key_duplicate(void *keyv)
{
    vlba_key_t *key = (vlba_key_t *)keyv;

    /* No need to duplicate static keys */
    if (VLBA_TREE_KEY_INVAL(key))
        return (void *)&VLBA_TREE_INVAL_KEY;
    if (VLBA_TREE_KEY_MIN(key))
        return (void *)&VLBA_TREE_MIN_KEY;
    if (VLBA_TREE_KEY_MAX(key))
        return (void *)&VLBA_TREE_MAX_KEY;

    keyv = ((void *)castle_object_btree_key_duplicate(keyv));

    return keyv;
}

static void castle_vlba_tree_key_dealloc(void *keyv)
{
    vlba_key_t *key = (vlba_key_t *)keyv;

    /* Should not free static keys */
    if(VLBA_TREE_KEY_INVAL(key) || VLBA_TREE_KEY_MAX(key) || VLBA_TREE_KEY_MIN(key))
    {
        BUG_ON(!((key == &VLBA_TREE_INVAL_KEY) || (key == &VLBA_TREE_MIN_KEY) ||
                 (key == &VLBA_TREE_MAX_KEY)));
        return;
    }
    castle_object_bkey_free(keyv);
}

static uint32_t castle_vlba_tree_key_hash(void *keyv, uint32_t seed) {
    vlba_key_t *key = (vlba_key_t *)keyv;

    return murmur_hash_32(key->_key, key->length, seed);
}

static int castle_vlba_tree_entry_get(struct castle_btree_node *node,
                                      int                       idx,
                                      void                    **key_p,
                                      version_t                *version_p,
                                      c_val_tup_t              *cvt_p)
{
    struct castle_vlba_tree_node *vlba_node =
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry =
               (struct castle_vlba_tree_entry *) VLBA_ENTRY_PTR(node, vlba_node, idx);

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        *cvt_p = convert_to_cvt(entry->type, entry->val_len, entry->cep);
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        if (VLBA_TREE_ENTRY_IS_INLINE(entry))
        {
            BUG_ON(entry->val_len > MAX_INLINE_VAL_SIZE);
            cvt_p->val = VLBA_ENTRY_VAL_PTR(entry);
        }
        BUG_ON(!node->is_leaf && (CVT_LEAF_PTR(*cvt_p) || CVT_LEAF_VAL(*cvt_p)));
        BUG_ON(node->is_leaf && CVT_NODE(*cvt_p));
    }

    return VLBA_TREE_ENTRY_IS_DISABLED(entry);
}

#ifdef CASTLE_DEBUG
static void castle_vlba_tree_node_validate(struct castle_btree_node *node);
#endif

static void castle_vlba_tree_entry_add(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key_v,
                                       version_t                 version,
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
    BUG_ON(!node->is_leaf && (CVT_LEAF_PTR(cvt) || CVT_LEAF_VAL(cvt)));
#if 0
    if (node->is_leaf && CVT_NODE(cvt))
    {
        castle_printk("%x:%llu\n", (uint32_t)cvt.type, cvt.length);
        BUG();
    }
#endif

    new_entry.version    = version;
    new_entry.type       = cvt.type;
    new_entry.val_len    = cvt.length;
    new_entry.key.length = key_length;
    req_space = VLBA_ENTRY_LENGTH((&new_entry)) + sizeof(uint32_t);

    /* Initialization of node free space structures */
    if (node->used == 0)
    {
        vlba_node->dead_bytes = 0;
        vlba_node->free_bytes = VLBA_TREE_NODE_LENGTH(node) - sizeof(struct castle_btree_node) -
                                sizeof(struct castle_vlba_tree_node);
        BUG_ON( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
                vlba_node->free_bytes + vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH(node));
    }

    BUG_ON(key_length > VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(vlba_node->free_bytes + vlba_node->dead_bytes < req_space);

    if(vlba_node->free_bytes < req_space)
    {
        /* BUG if the key is in the node we are processing (compaction will invalidate the pointer) */
        BUG_ON(((uint8_t *)key <= EOF_VLBA_NODE(node)) &&
            (((uint8_t *)key + key_length + sizeof(vlba_key_t)) >= (uint8_t *)node));
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
        memmove(VLBA_ENTRY_VAL_PTR(entry), cvt.val, cvt.length);
    }
    else
        entry->cep      = cvt.cep;

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
                                           version_t                 version,
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
    BUG_ON(!node->is_leaf && (CVT_LEAF_PTR(cvt) || CVT_LEAF_VAL(cvt)));
#if 0
    BUG_ON(node->is_leaf && CVT_NODE(cvt));
#endif
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    new_entry.version    = version;
    new_entry.type       = cvt.type;
    new_entry.val_len    = cvt.length;
    new_entry.key.length = key->length;
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
            memcpy(VLBA_ENTRY_VAL_PTR(entry), cvt.val, cvt.length);
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

    entry->type |= VLBA_TREE_ENTRY_DISABLED;
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

    /* @TODO: node_validate called in interrupt context, cannot kmalloc GFP_NOIO here */
    if(0 == 0)
        return;
    a = castle_malloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = castle_malloc(sizeof(uint32_t) * node->used, GFP_NOIO);
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
        castle_printk("sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +"
                "Index Table + Free Bytes + Sum of entries + Dead Bytes\n");
        castle_printk("%u-%u-%u-%u-%u-%u\n", (uint32_t)sizeof(struct castle_btree_node)
                                    , (uint32_t)sizeof(struct castle_vlba_tree_node)
                                    , (uint32_t)sizeof(uint32_t) * node->used
                                    , vlba_node->free_bytes
                                    , count
                                    , vlba_node->dead_bytes);
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
            castle_printk("Entry Overflow: Entry-%p; Length-%u; NodeEnd-%p\n",
                   entry, ent_len, EOF_VLBA_NODE(node));
            BUG();
        }
        if (entry_offset != a[count])
        {
            castle_printk("Heap sort error\n");
            BUG();
        }
        if ((prev_offset != -1) && (prev_offset + ent_len > entry_offset))
        {
            castle_printk("Entry overlap: offset:length -> %u:%u-%u:%u\n", prev_offset, prev_len,
                   entry_offset, ent_len);
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
        uint32_t entry_offset, ent_len;
        struct castle_vlba_tree_entry *entry;
        uint8_t ret;

        entry_offset = vlba_node->key_idx[i];
        entry = (struct castle_vlba_tree_entry *)(EOF_VLBA_NODE(node) - entry_offset);
        ent_len = (uint32_t)VLBA_ENTRY_LENGTH(entry);

        ret = (prev_offset == -1)?0:castle_vlba_tree_key_compare(&prev_entry->key, &entry->key);
        if ((prev_offset != -1) &&
            (ret == 1 ||
             (!ret &&
              castle_version_is_ancestor(entry->version, prev_entry->version))))
        {
            int j;

            castle_printk("Entry 1:\n");
            castle_printk("[%d] (", i-1);
            for(j=0; j<VLBA_KEY_LENGTH(&prev_entry->key); j++)
                castle_printk("%.2x", prev_entry->key._key[j]);
            castle_printk(", 0x%x) -> "cep_fmt_str_nl,
                prev_entry->version,
                cep2str(prev_entry->cep));

            castle_printk("Entry 2:\n");
            castle_printk("[%d] (", i);
            for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
                castle_printk("%.2x", entry->key._key[j]);
            castle_printk(", 0x%x) -> "cep_fmt_str_nl,
                entry->version,
                cep2str(entry->cep));
            BUG();
        }

        if (VLBA_TREE_ENTRY_IS_LEAF_PTR(entry) && !node->is_leaf)
        {
            castle_printk("Entry is leaf ptr but node is not a leaf\n");
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

    castle_printk("node->used=%d, node=%p, vlba_node=%p, payload=%p\n",
            node->used,
            node,
            vlba_node,
            ((uint8_t*)vlba_node + sizeof(struct castle_vlba_tree_node)));
    for(i=0; i<node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);

        castle_printk("[%d] key_idx[%d]=%d, key_length=%d, val_len=%lld, entry_size=%lld (",
                i, i, vlba_node->key_idx[i], VLBA_KEY_LENGTH(&entry->key),
                entry->val_len,
                VLBA_ENTRY_LENGTH(entry));
        for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
            castle_printk("%.2x", entry->key._key[j]);
        castle_printk(", 0x%x) -> "cep_fmt_str_nl,
            entry->version,
            cep2str(entry->cep));
    }
    castle_printk("\n");
}


struct castle_btree_type castle_rw_tree = {
    .magic          = RW_VLBA_TREE_TYPE,
    .min_key        = (void *)&VLBA_TREE_MIN_KEY,
    .max_key        = (void *)&VLBA_TREE_MAX_KEY,
    .inv_key        = (void *)&VLBA_TREE_INVAL_KEY,
    .node_size      = castle_vlba_rw_tree_node_size,
    .need_split     = castle_vlba_tree_need_split,
    .key_compare    = castle_vlba_tree_key_compare,
    .key_duplicate  = castle_vlba_tree_key_duplicate,
    .key_next       = castle_vlba_tree_key_next,
    .key_dealloc    = castle_vlba_tree_key_dealloc,
    .key_hash       = castle_vlba_tree_key_hash,
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

struct castle_btree_type castle_ro_tree = {
    .magic          = RO_VLBA_TREE_TYPE,
    .min_key        = (void *)&VLBA_TREE_MIN_KEY,
    .max_key        = (void *)&VLBA_TREE_MAX_KEY,
    .inv_key        = (void *)&VLBA_TREE_INVAL_KEY,
    .node_size      = castle_vlba_ro_tree_node_size,
    .need_split     = castle_vlba_tree_need_split,
    .key_compare    = castle_vlba_tree_key_compare,
    .key_duplicate  = castle_vlba_tree_key_duplicate,
    .key_next       = castle_vlba_tree_key_next,
    .key_dealloc    = castle_vlba_tree_key_dealloc,
    .key_hash       = castle_vlba_tree_key_hash,
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

/**********************************************************************************************/
/* Array of btree types */
#define RW_TREES_MAX_ENTRIES    (max(max(MTREE_NODE_ENTRIES, BATREE_NODE_ENTRIES),  \
                                     VLBA_RW_TREE_MAX_ENTRIES))

static struct castle_btree_type *castle_btrees[1<<(8 * sizeof(btree_t))] =
                                                       {[MTREE_TYPE]        = &castle_mtree,
                                                        [BATREE_TYPE]       = &castle_batree,
                                                        [RW_VLBA_TREE_TYPE] = &castle_rw_tree,
                                                        [RO_VLBA_TREE_TYPE] = &castle_ro_tree};


struct castle_btree_type *castle_btree_type_get(btree_t type)
{
#ifdef CASTLE_DEBUG
    BUG_ON((type != MTREE_TYPE) &&
           (type != BATREE_TYPE) &&
           (type != RW_VLBA_TREE_TYPE) &&
           (type != RO_VLBA_TREE_TYPE));
#endif
    return castle_btrees[type];
}


/**********************************************************************************************/
/* Common modlist btree code */
void castle_btree_ct_lock(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
    {
        down_write(&c_bvec->tree->lock);
        set_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        down_read(&c_bvec->tree->lock);
        clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }

    set_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
}

void castle_btree_ct_unlock(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
    {
        BUG_ON(!test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags));
        up_write(&c_bvec->tree->lock);
    }
    else
    {
        BUG_ON(test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
        up_read(&c_bvec->tree->lock);
    }

    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
}

static inline c_ext_pos_t castle_btree_root_get(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;

    down_read(&att->lock);
    c_bvec->version = att->version;
    up_read(&att->lock);
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_btree_c2b_forget() */
    castle_btree_ct_lock(c_bvec);

    return c_bvec->tree->root_node;
}

static void castle_btree_c2b_forget(c_bvec_t *c_bvec);
static void __castle_btree_submit(c_bvec_t *c_bvec,
                                  c_ext_pos_t  node_cep,
                                  void *parent_key);


static void castle_btree_io_end(c_bvec_t    *c_bvec,
                                c_val_tup_t    cvt,
                                int          err)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_bvec->tree->btree_type);

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_IO_END);
    /* We allow:
       -   valid block and no error
       - invalid block and    error
       - invalid block and no error (reads from non-yet written block)
       We disallow:
       -   valid block and    error
       - invalid block and no error on writes
     */
    BUG_ON((!CVT_INVALID(cvt)) && (err));
    BUG_ON((c_bvec_data_dir(c_bvec) == WRITE) && (CVT_INVALID(cvt)) && (!err));

    /* Deallocate parent_key. */
    if ((c_bvec_data_dir(c_bvec) == WRITE) && c_bvec->parent_key)
    {
        btree->key_dealloc(c_bvec->parent_key);
        c_bvec->parent_key = NULL;
    }

    /* Get reference on objects before reads. */
    if (!err && (c_bvec_data_dir(c_bvec) == READ))
    {
        BUG_ON(!c_bvec->ref_get);
        c_bvec->ref_get(c_bvec, cvt);
    }

    /* Free the c2bs correctly. Call twice to release parent and child
       (if both exist) */
    castle_btree_c2b_forget(c_bvec);
    castle_btree_c2b_forget(c_bvec);
    /* Finish the IO */
    c_bvec->endfind(c_bvec, err, cvt);
}

static void USED castle_btree_node_print(struct castle_btree_type *t, struct castle_btree_node *node)
{
    castle_printk("Printing node version=%d with used=%d, is_leaf=%d\n",
        node->version, node->used, node->is_leaf);

    t->node_print(node);
}

void castle_btree_lub_find(struct castle_btree_node *node,
                                  void *key,
                                  version_t version,
                                  int *lub_idx_p,
                                  int *insert_idx_p)
{
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    version_t version_lub;
    void *key_lub;
    int lub_idx, insert_idx, low, high, mid;

#define insert_candidate(_x)    if(insert_idx < 0) insert_idx=(_x)
    debug("Looking for (k,v) = (%p, 0x%x), node->used=%d\n",
            key, version, node->used);
    /* We should not search for an invalid key */
    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);

    /* Binary search on the keys to find LUB key */
    low = -1;           /* Key in entry pointed to by low is guaranteed
                           to be less than 'key' */
    high = node->used;  /* Key in entry pointed to be high is guaranteed
                           to be higher or equal to the 'key' */
    debug(" (lo,hi) = (%d, %d)\n", low, high);
    while(low != high-1)
    {
        int key_cmp;

        BUG_ON(high <= low);
        mid = (low + high) / 2;
        btree->entry_get(node, mid, &key_lub, NULL, NULL);
        key_cmp = btree->key_compare(key_lub, key);
        debug("mid=%d, key_cmp=%d\n", mid, key_cmp);
        if(key_cmp < 0)
            low = mid;
        else
            high = mid;
        debug(" (lo,hi) = (%d, %d)\n", low, high);
    }
    /* 'high' is now pointing to the LUB key (left-most copy if there are a few instances
        of it in the node), or past the end of the node.
        We should start scanning to the right starting with the entry pointed by high (if
        one exists). Going this direction keys increase and versions go from newest to
        oldest.
        Set the insertion_index as soon as we find a key greater than what we are looking
        for, or if equal keys, when the version is ancestoral (then insert_idx == lub_idx).
     */
    insert_idx = -1;
    for(lub_idx=high; lub_idx < node->used; lub_idx++)
    {
        int cmp;

        btree->entry_get(node, lub_idx, &key_lub, &version_lub, NULL);

        debug(" (k,v) = (%p, 0x%x)\n", key_lub, version_lub);

        /* First (k,v) that's an upper bound is guaranteed to be the correct lub,
           because versions are arranged from newest to oldest */
        cmp = btree->key_compare(key_lub, key);
        BUG_ON(cmp < 0);
        if(cmp > 0)
            insert_candidate(lub_idx);
        if(castle_version_is_ancestor(version_lub, version))
        {
            insert_candidate(lub_idx);
            break;
        }
    }
    BUG_ON(lub_idx > node->used);
    insert_candidate(node->used);
    if(lub_idx == node->used)
        lub_idx = -1;
    /* Return the indices */
    if(lub_idx_p) *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

static void castle_btree_node_save(struct work_struct *work)
{
    static DECLARE_MUTEX(node_save_lock);
    struct castle_btree_node_save *work_st = container_of(work,
                                                       struct castle_btree_node_save,
                                                       work);
    struct castle_component_tree *ct = work_st->ct;
    struct castle_btree_node *node;
    struct castle_btree_type *btree;
    c_ext_pos_t  prev_cep;
    c2_block_t *c2b;

    down(&node_save_lock);
    btree = castle_btree_type_get(ct->btree_type);

    if (unlikely(!atomic64_read(&ct->node_count)))
    {
        BUG_ON(!EXT_POS_INVAL(ct->first_node));
        ct->first_node = work_st->node_cep;
        ct->first_node_size = work_st->node_size;
    }
    else
    {
        prev_cep = ct->last_node;
        c2b = castle_cache_block_get(prev_cep, ct->last_node_size);
        write_lock_c2b(c2b);

        /* If c2b is not up to date, issue a blocking READ to update */
        if(!c2b_uptodate(c2b))
            BUG_ON(submit_c2b_sync(READ, c2b));

        node = c2b_buffer(c2b);
        node->next_node = work_st->node_cep;
        node->next_node_size = work_st->node_size;

        dirty_c2b(c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
    }
    ct->last_node = work_st->node_cep;
    ct->last_node_size = work_st->node_size;
    atomic64_inc(&ct->node_count);
    up(&node_save_lock);
    castle_ct_put(ct, 1 /* write */);

    castle_free(work_st);
}

void castle_btree_node_save_prepare(struct castle_component_tree *ct,
                                    c_ext_pos_t node_cep,
                                    uint16_t node_size)
{
    struct castle_btree_node_save *work_st;

    /* Link the new node to last created node. But, schedule the task for later; as
     * locking the last node while holding lock for current node might lead to a
     * dead-lock */
    work_st = castle_malloc(sizeof(struct castle_btree_node_save), GFP_NOIO);
    BUG_ON(!work_st);
    /* Get a writable reference to the component tree, to stop people from assuming
       the tree is static now */
    castle_ct_get(ct, 1 /* write */);
    work_st->ct = ct;
    work_st->node_cep = node_cep;
    work_st->node_size = node_size;
    CASTLE_INIT_WORK(&work_st->work, castle_btree_node_save);
    queue_work(castle_wq, &work_st->work);
}

/**
 * Initialises btree node header.
 *
 * @param ct          Component tree this node will belong to.
 * @param node        Pointer to where the node lives in memory.
 * @param version     Version of the node.
 * @param rev_level   Level at which this node will be used. Important: counted from the leaves,
 *                    same as for btree_type->node_size().
 */
static void castle_btree_node_init(struct castle_component_tree *ct,
                                   struct castle_btree_node *node,
                                   int version,
                                   uint8_t rev_level)
{
    struct castle_btree_type *btree;
    uint16_t node_size;

    /* This function should only be called for RW vlba trees. */
    btree = castle_btree_type_get(ct->btree_type);
    node_size = btree->node_size(ct, rev_level);
    /* memset the node, so that ftree nodes are easily recognisable in hexdump. */
    memset(node, 0x77, node_size * C_BLK_SIZE);
    node->magic     = BTREE_NODE_MAGIC;
    node->type      = ct->btree_type;
    node->version   = version;
    node->used      = 0;
    node->is_leaf   = (rev_level == 0);
    node->size      = node_size;
    node->next_node = INVAL_EXT_POS;
}

static int castle_btree_node_space_get(struct castle_component_tree *ct,
                                       c_ext_pos_t *cep,
                                       uint16_t node_size,
                                       int was_preallocated)
{
    if (castle_ext_freespace_get(&ct->tree_ext_free,
                                  node_size * C_BLK_SIZE,
                                  was_preallocated,
                                  cep) < 0)
    {
        if (ct != &castle_global_tree)
            castle_printk("****WARNING: Allocating more nodes than pre-allocated: %u****\n",
                    ct->seq);

        return castle_ext_freespace_get(&ct->tree_ext_free,
                                         node_size * C_BLK_SIZE,
                                         0,
                                         cep);
    }

    return 0;
}

/**
 * Allocate and initialise c2b for a ct->type btree node.
 *
 * @param ct               Component tree this node will belong to.
 * @param version          Version of the node.
 * @param rev_level        Level at which this node will be used. Important: counted from leafs,
 *                         same as in btree_type->node_size().
 * @param was_preallocated Has the space for this node been preallocated.
 */
c2_block_t* castle_btree_node_create(struct castle_component_tree *ct,
                                     int version,
                                     uint16_t rev_level,
                                     int was_preallocated)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node;
    c2_block_t *c2b;
    btree_t type;
    c_ext_pos_t cep;
    uint16_t node_size;

    /* Work out the node size. */
    type = ct->btree_type;
    btree = castle_btree_type_get(type);
    node_size = btree->node_size(ct, rev_level);

    /* Allocate freespace for it. */
    BUG_ON(castle_btree_node_space_get(ct, &cep, node_size, was_preallocated) < 0);

    /* Bet the cache block. */
    c2b = castle_cache_block_get(cep, node_size);
    write_lock_c2b(c2b);
    update_c2b(c2b);
    dirty_c2b(c2b);
    node = c2b_buffer(c2b);

    /* Initialise it. */
    castle_btree_node_init(ct, node, version, rev_level);

    return c2b;
}

static c2_block_t* castle_btree_effective_node_create(struct castle_component_tree *ct,
                                                      c_bvec_t *c_bvec,
                                                      c2_block_t *orig_c2b,
                                                      uint8_t level,
                                                      version_t version)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node, *eff_node;
    c2_block_t *c2b;
    void *last_eff_key;
    version_t last_eff_version = 0;
    int i, insert_idx, moved_cnt;
    uint16_t node_size;
    uint8_t rev_level;

    rev_level = c_bvec->btree_levels - level;
    node = c2b_bnode(orig_c2b);
    btree = castle_btree_type_get(node->type);
    node_size = btree->node_size(ct, rev_level);

    /* First build effective node in memory and allocate disk space only if it
     * is not same as original node. */
    eff_node = castle_vmalloc(node_size * C_BLK_SIZE);
    /* rev_level == 0 should be equivalent to node->is_leaf test */
    BUG_ON((rev_level == 0) ^ (node->is_leaf));
    castle_btree_node_init(ct, eff_node, version, rev_level);

    last_eff_key = btree->inv_key;
    BUG_ON(eff_node->used != 0);
    insert_idx = 0;
    moved_cnt = 0;
    for(i=0; i<node->used; i++)
    {
        void        *entry_key;
        version_t    entry_version;
        c_val_tup_t  entry_cvt;
        int          need_move;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_cvt);
        /* Check if slot->version is ancestoral to version. If not,
           reject straigt away. */
        if(!castle_version_is_ancestor(entry_version, version))
            continue;

        /* Ignore all versions of the key except of the left-most (=> newest) one. */
        if(btree->key_compare(last_eff_key, entry_key) == 0)
        {
            /* Check that the version really is older */
            BUG_ON(!castle_version_is_ancestor(entry_version, last_eff_version));
            continue;
        }
        /* Copy directly if:
            - we are not looking at a leaf node
            - the entry is already a leaf pointer
            - we making the entry in the old node unreachable (that will happen
              if the effective node version is the same as the entry version,
              but different from the old node version)
         */
        need_move = (entry_version == version) && (node->version != version);
        if(!node->is_leaf || CVT_LEAF_PTR(entry_cvt) || need_move)
        {
            /* If already a leaf pointer, or a non-leaf entry copy directly. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             entry_cvt);
        } else
        {
            c_val_tup_t cvt;
            CVT_LEAF_PTR_SET(cvt, orig_c2b->nr_pages * C_BLK_SIZE, orig_c2b->cep);
            /* Otherwise construct a new leaf pointer. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             cvt);
        }

        /* Remember what the last key/version was, so that we know whether to take the
           next entry we see in the original node or not */
        last_eff_key = entry_key;
        last_eff_version = entry_version;
        /* If we _moved_ something, we need to remove it from the old node */
        if(need_move)
            btree->entry_disable(node, i);

        insert_idx++;
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL.
       Note that effective node is only identical to the original node if the
       entries match, AND also the version of the node itself also matches.
     */
    if((node->version == version) && (eff_node->used == node->used))
    {
        BUG_ON(moved_cnt > 0);
        castle_vfree(eff_node);

        return NULL;
    }

    /* Effective node is not same as original node - allocate space on the disk
     * now and copy. */
    atomic_dec(&c_bvec->reserv_nodes);
    c2b = castle_btree_node_create(c_bvec->tree, version, rev_level, 1 /* was_preallocated. */);
    memcpy(c2b_buffer(c2b), eff_node, node_size * C_BLK_SIZE);
    castle_vfree(eff_node);

    castle_btree_node_save_prepare(c_bvec->tree, c2b->cep, node_size);

    return c2b;
}

static c2_block_t* castle_btree_node_key_split(c_bvec_t *c_bvec,
                                               c2_block_t *orig_c2b,
                                               uint8_t level)
{
    struct castle_component_tree *ct;
    struct castle_btree_node *node, *sec_node;
    struct castle_btree_type *btree;
    uint16_t node_size;
    c2_block_t *c2b;
    uint8_t rev_level;
    int i;

    void        *entry_key;
    version_t    entry_version;
    c_val_tup_t  entry_cvt;

    rev_level = c_bvec->btree_levels - level;
    node      = c2b_bnode(orig_c2b);
    ct        = c_bvec->tree;
    btree     = castle_btree_type_get(ct->btree_type);
    node_size = btree->node_size(ct, rev_level);
    atomic_dec(&c_bvec->reserv_nodes);
    c2b       = castle_btree_node_create(ct, node->version, rev_level, 1 /* was_preallocated */);
    castle_btree_node_save_prepare(ct, c2b->cep, node_size);
    sec_node  = c2b_bnode(c2b);
    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    BUG_ON(sec_node->used != 0);
    for(i=0; i<node->used >> 1; i++)
    {
        /* Copy the entries */
        btree->entry_get(node,     i, &entry_key, &entry_version, &entry_cvt);
        btree->entry_add(sec_node, i,  entry_key,  entry_version,  entry_cvt);
    }

    BUG_ON(sec_node->used != node->used >> 1);
    btree->entries_drop(node, 0, sec_node->used - 1);

    /* c2b has already been dirtied by the node_create() function, but the orig_c2b
       needs to be dirtied here */
    dirty_c2b(orig_c2b);

    return c2b;
}

static void castle_btree_slot_insert(c2_block_t  *c2b,
                                     int          index,
                                     void        *key,
                                     version_t    version,
                                     c_val_tup_t  cvt)
{
    struct castle_btree_node *node = c2b_buffer(c2b);
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void      *lub_key      = btree->inv_key;
    version_t  lub_version  = INVAL_VERSION;
    c_val_tup_t lub_cvt;

    BUG_ON(index > node->used);

    if (CVT_ONDISK(cvt) || CVT_NODE(cvt) || CVT_LEAF_PTR(cvt))
        debug("Inserting "cep_fmt_str" under index=%d\n", cep2str(cvt.cep), index);
    else
        debug("Inserting an inline value under index=%d\n", index);

    if(index < node->used)
        btree->entry_get(node, index, &lub_key, &lub_version, &lub_cvt);

    /* Special case. Newly inserted block may make another entry unreachable.
       This would cause problems with future splits. And therefore unreachable
       entry has to be replaced by the new one.
       The entry will stop being reachable if:
       - keys match
       - version to insert descendant from the left_version (and different)
       - version to insert the same as the node version
      If all of the above true, replace rather than insert.
      The now unreachable entry must necessarily be the previous LUB entry.
      Therefore it will be pointed to by index.
     */
    if((btree->key_compare(lub_key, key) == 0) &&
       (lub_version != version) &&
        castle_version_is_ancestor(lub_version, version) &&
       (version == node->version))
    {
        /* In leaf nodes the element we are replacing MUST be a leaf pointer,
           because lub_version is strictly ancestoral to the node version.
           It implies that the key hasn't been insterted here, because
           keys are only inserted to weakly ancestoral nodes */
        BUG_ON(!CVT_LEAF_PTR(lub_cvt) && node->is_leaf);
        /* Replace the slot */
        BUG_ON(CVT_LEAF_PTR(cvt));
        btree->entry_replace(node, index, key, version, cvt);
        dirty_c2b(c2b);
        return;
    }
    /* Insert the new entry */
    btree->entry_add(node, index, key, version, cvt);
    BUG_ON(node->used >= RW_TREES_MAX_ENTRIES);
    dirty_c2b(c2b);
}

static void castle_btree_node_insert(c2_block_t *parent_c2b,
                                     c2_block_t *child_c2b)
{
    struct castle_btree_node    *parent = c2b_buffer(parent_c2b);
    struct castle_btree_node    *child  = c2b_buffer(child_c2b);
    struct castle_btree_type    *btree  = castle_btree_type_get(parent->type);
    version_t                    version = child->version;
    void                        *key;
    int                          insert_idx;
    c_val_tup_t                  cvt;

    BUG_ON(castle_btree_type_get(child->type) != btree);
    btree->entry_get(child, child->used-1, &key, NULL, NULL);

    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    CVT_NODE_SET(cvt, child->size * C_BLK_SIZE, child_c2b->cep);
    castle_btree_slot_insert(parent_c2b,
                             insert_idx,
                             key,
                             version,
                             cvt);
}

static void castle_btree_node_under_key_insert(c2_block_t *parent_c2b,
                                               c2_block_t *child_c2b,
                                               void *key,
                                               version_t version)
{
    struct castle_btree_node    *parent = c2b_buffer(parent_c2b);
    struct castle_btree_node    *child  = c2b_buffer(child_c2b);
    struct castle_btree_type    *btree = castle_btree_type_get(parent->type);
    int                          insert_idx;
    c_val_tup_t                  cvt;

    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), "
          "will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    CVT_NODE_SET(cvt, child->size * C_BLK_SIZE, child_c2b->cep);
    castle_btree_slot_insert(parent_c2b,
                             insert_idx,
                             key,
                             version,
                             cvt);
}

static void castle_btree_new_root_create(c_bvec_t *c_bvec, btree_t type)
{
    c2_block_t *c2b;
    struct castle_btree_node *node;
    struct castle_component_tree *ct;

    debug("Creating a new root node, while handling write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Create the node */
    atomic_dec(&c_bvec->reserv_nodes);
    ct = c_bvec->tree;
    c2b = castle_btree_node_create(ct,
                                   0              /* version */,
                                   ct->tree_depth /* level */,
                                   1              /* was preallocated */);
    castle_btree_node_save_prepare(ct, c2b->cep, c2b->nr_pages);
    node = c2b_buffer(c2b);
    /* We should be under write lock here, check if we can read lock it (and BUG) */
    BUG_ON(down_read_trylock(&ct->lock));
    ct->root_node = c2b->cep;
    ct->tree_depth++;
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
    /* Release the version lock (c2b_forget will no longer do that,
       because there will be a parent node). */
    castle_btree_ct_unlock(c_bvec);
    /* Also, make sure that the PARENT_WRITE_LOCKED flag is set, so that the new
       root will get unlocked correctly */
    set_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
}

static int castle_btree_node_split(c_bvec_t *c_bvec)
{
    struct castle_btree_node *node, *eff_node, *split_node, *parent_node;
    c2_block_t *eff_c2b, *split_c2b, *retain_c2b, *parent_c2b;
    struct castle_btree_type *btree;
    void *key = c_bvec->key;
    uint32_t version = c_bvec->version;
    int new_root;

    debug("Node full while inserting (%p,0x%x), creating effective node for it.\n",
            key, version);
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
    eff_c2b = split_c2b = NULL;
    retain_c2b = c_bvec->btree_node;

    BUG_ON(!test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags) ||
           !test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
    /* Create the effective node */
    eff_c2b = castle_btree_effective_node_create(c_bvec->tree,
                                                 c_bvec,
                                                 retain_c2b,
                                                 c_bvec->btree_depth,
                                                 version);
    if(eff_c2b)
    {
        debug("Effective node NOT identical to the original node.\n");
        /* Cast eff_c2b buffer to eff_node */
        eff_node = c2b_buffer(eff_c2b);
        /* We should continue the walk with the effective node, rather than the
           original node */
        retain_c2b = eff_c2b;
    } else
    {
        debug("Effective node identical to the original node.\n");
        /* IMPORTANT: point eff_node to the original node, but DO NOT change eff_c2b.
           We need to remember what needs to be inserted into the parent node later */
        eff_node = node;
    }

    /* Split the effective node if it's more than 2/3s full */
    if(btree->need_split(eff_node, 1 /* key split */))
    {
        void *max_split_key;

        debug("Effective node too full, splitting.\n");
        split_c2b = castle_btree_node_key_split(c_bvec,
                                                eff_c2b ? eff_c2b : c_bvec->btree_node,
                                                c_bvec->btree_depth);
        split_node = c2b_buffer(split_c2b);
        BUG_ON(split_node->version != c_bvec->version);
        /* Work out whether to take the split node for the further btree walk.
           Since in the effective & split node there is at most one version
           for each key, and this version is ancestoral to what we are
           looking for, it's enough to check if the last entry in the
           split node (that's the node that contains left hand side elements
           from the original effective node) is greater-or-equal to the block
           we are looking for */
        btree->entry_get(split_node, split_node->used-1, &max_split_key, NULL, NULL);
        if(btree->key_compare(max_split_key, key) >= 0)
        {
            debug("Retaing the split node.\n");
            retain_c2b = split_c2b;
        }
    }

    /* If we don't have a parent, we have to create a new root node. */
    new_root = 0;
    if(!c_bvec->btree_parent_node)
    {
        /* When we are splitting the root node there must be an effective node
           (i.e. effective node must not be identical to the original node).
           This is because we are writing in a version != 0, and the version of
           root node is always 0 */
        BUG_ON(!eff_c2b);

        debug("Creating new root node.\n");
        castle_btree_new_root_create(c_bvec, node->type);
        new_root = 1;
    }

    /* Work out if we have a parent */
    parent_c2b  = c_bvec->btree_parent_node;
    BUG_ON(!parent_c2b);
    parent_node = c2b_buffer(parent_c2b);
    /* Insert!
       This is a bit complex, due to number of different cases. Each is described below
       in some detail.

       If split node got created then it should be inserted with the
       usual (b,v) in the parent.
     */
    if(split_c2b)
    {
        debug("Inserting split node.\n");
        castle_btree_node_insert(parent_c2b, split_c2b);
    }

    /* If effective node got created (rather than using the original node) then
       it either needs to be inserted in the usual way, or under MAX key if we are
       inserting into the new root. */
    if(eff_c2b)
    {
        if(new_root)
        {
            debug("Inserting effective node under MAX block key.\n");
            castle_btree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               btree->max_key,
                                               c_bvec->version);
        } else
        {
            debug("Inserting effective node under the usual key.\n");
            castle_btree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               c_bvec->parent_key,
                                               c_bvec->version);
        }
    }

    /* Finally, if new root got created, we must also insert the original node into it.
       This should be inserted under MAX_KEY,and version 0 (this is the version of the node). */
    if(new_root)
    {
        debug("Inserting original root node under MAX block key.\n");
        castle_btree_node_under_key_insert(parent_c2b,
                                           c_bvec->btree_node,
                                           btree->max_key,
                                           0);
    }

    /* All nodes inserted. Now, unlock all children nodes, except of the
       one with which we'll continue the walk with (saved in retained_c2b) */
    if(retain_c2b != c_bvec->btree_node)
    {
        debug("Unlocking the original node.\n");
        write_unlock_c2b(c_bvec->btree_node);
        put_c2b(c_bvec->btree_node);
    }
    if(eff_c2b && (retain_c2b != eff_c2b))
    {
        debug("Unlocking the effective node.\n");
        write_unlock_c2b(eff_c2b);
        put_c2b(eff_c2b);
    }
    if(split_c2b && (retain_c2b != split_c2b))
    {
        debug("Unlocking the split node.\n");
        write_unlock_c2b(split_c2b);
        put_c2b(split_c2b);
    }

    /* Save the retained_c2b */
    c_bvec->btree_node = retain_c2b;

    return 0;
}

/**
 * Perform write (insert/replace/delete) on btree specified by c_bvec.
 *
 * @also castle_btree_process()
 * @also castle_btree_read_process()
 */
static void castle_btree_write_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    version_t                    lub_version, version = c_bvec->version;
    int                          lub_idx, insert_idx, ret;
    c_val_tup_t                  lub_cvt = INVAL_VAL_TUP;
    c_val_tup_t                  new_cvt = INVAL_VAL_TUP;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_WPROCESS);

    /* Check if the node needs to be split first.
       A leaf node only needs to be split if there are _no_ empty slots in it.
       Internal nodes, if there are less than 2 free slots in them.
       The exception is, if we got here following a leaf pointer. If that's the
       case, we know that we'll be updating in place.
     */
    if((btree->key_compare(c_bvec->parent_key, btree->inv_key) != 0) &&
       (btree->need_split(node, 0 /* version split */)))
    {
        debug("===> Splitting node: leaf=%d, used=%d\n",
                node->is_leaf, node->used);
        ret = castle_btree_node_split(c_bvec);
        if(ret)
        {
            /* End the IO in failure */
            castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
            return;
        }
        /* Make sure that node now points to the correct node after split */
        node = c_bvec_bnode(c_bvec);
    }

    /* Find out what to follow, and where to insert */
    castle_btree_lub_find(node, key, version, &lub_idx, &insert_idx);
    BUG_ON((insert_idx < 0) || (insert_idx > node->used));
    if(lub_idx >= 0)
        btree->entry_get(node, lub_idx, &lub_key, &lub_version,
                         &lub_cvt);

    /* Deal with non-leaf nodes first */
    if(!node->is_leaf)
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        debug("Following write down the tree.\n");
        if (!CVT_NODE(lub_cvt))
        {
            castle_printk("0x%x-%llu-"cep_fmt_str_nl,
                    lub_cvt.type,
                    (uint64_t)lub_cvt.length,
                   cep2str(lub_cvt.cep));
            BUG();
        }
        __castle_btree_submit(c_bvec, lub_cvt.cep, lub_key);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!node->is_leaf);

    /* Insert an entry if LUB doesn't match our (k,v) precisely. */
    if((lub_idx < 0) ||
       (btree->key_compare(lub_key, key) != 0) ||
       (lub_version != version))
    {
        if ((ret = c_bvec->cvt_get(c_bvec, INVAL_VAL_TUP, &new_cvt)))
        {
            /* End the IO in failure */
            castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
            return;
        }

        atomic64_inc(&c_bvec->tree->item_count);
        /* @TODO: should memset the page to zero (because we return zeros on reads)
                  this can be done here, or beter still in _main.c, in data_copy */
        debug("Need to insert (%p, 0x%x) into node (used: 0x%x, leaf=%d).\n",
                key, version, node->used, node->is_leaf);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        BUG_ON(CVT_LEAF_PTR(new_cvt));
        castle_btree_slot_insert(c_bvec->btree_node,
                                 insert_idx,
                                 key,
                                 version,
                                 new_cvt);
        castle_btree_io_end(c_bvec, new_cvt, 0);
        return;
    }

    /* Final case: (k,v) found in the leaf node. */
    BUG_ON((btree->key_compare(lub_key, key) != 0) ||
           (lub_version != version));
    BUG_ON(lub_idx != insert_idx);
    BUG_ON(CVT_LEAF_PTR(lub_cvt));

    /* NOP for block devices */
    if ((ret = c_bvec->cvt_get(c_bvec, lub_cvt, &new_cvt)))
    {
       /* End the IO in failure */
       castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
       return;
    }
    BUG_ON(CVT_LEAF_PTR(new_cvt));
    btree->entry_replace(node, lub_idx, key, lub_version,
                         new_cvt);
    dirty_c2b(c_bvec->btree_node);
    debug("Key already exists, modifying in place.\n");
    castle_btree_io_end(c_bvec, new_cvt, 0);

}

/**
 * Perform read on btree specified by c_bvec.
 *
 * @also castle_btree_process()
 * @also castle_btree_write_process()
 */
static void castle_btree_read_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    version_t                    lub_version, version = c_bvec->version;
    int                          lub_idx;
    c_val_tup_t                  lub_cvt;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_RPROCESS);

    castle_btree_lub_find(node, key, version, &lub_idx, NULL);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((lub_idx < 0) && (!node->is_leaf));

    /* If we haven't found the LUB (in the leaf node), return early */
    if(lub_idx < 0)
    {
        debug(" Could not find the LUB for (k,v)=(%p, 0x%x)\n", key, version);
        castle_btree_io_end(c_bvec, INVAL_VAL_TUP, 0);
        return;
    }

    btree->entry_get(node, lub_idx, &lub_key, &lub_version,
                     &lub_cvt);
    /* If we found the LUB, either complete the ftree walk (if we are looking
       at a 'proper' leaf), or go to the next level (possibly following a leaf ptr) */
    if(node->is_leaf && !CVT_LEAF_PTR(lub_cvt))
    {
        BUG_ON(!CVT_LEAF_VAL(lub_cvt));
        if (CVT_ONDISK(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), cep="cep_fmt_str_nl,
                    lub_key, lub_version, lub_cvt.cep.ext_id,
                    cep2str(lub_cvt.cep));
        else if (CVT_INLINE(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), inline value\n",
                    lub_key, lub_version);
        else if (CVT_TOMB_STONE(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), tomb stone\n",
                    lub_key, lub_version);

        if(btree->key_compare(lub_key, key) == 0)
        {
            if (CVT_INLINE(lub_cvt))
            {
                char *loc_buf;
                loc_buf = castle_malloc(lub_cvt.length, GFP_NOIO);
                memcpy(loc_buf, lub_cvt.val, lub_cvt.length);
                lub_cvt.val = loc_buf;
            }
            castle_btree_io_end(c_bvec, lub_cvt, 0);
        }
        else
            castle_btree_io_end(c_bvec, INVAL_VAL_TUP, 0);
    }
    else
    {
        BUG_ON(CVT_LEAF_VAL(lub_cvt));
        if (CVT_LEAF_PTR(lub_cvt))
            debug("Leaf ptr. Read and search "cep_fmt_str_nl,
                   cep2str(lub_cvt.cep));
        else if (CVT_NODE(lub_cvt))
            debug("Child node. Read and search - inline value\n");
        else
            BUG();
        /* parent_key is not needed when reading (also, we might be looking at a leaf ptr)
           use INVAL key instead. */
        __castle_btree_submit(c_bvec, lub_cvt.cep, btree->inv_key);
    }
}

/**
 * Perform actual query on btree.
 *
 * @also __castle_btree_submit()
 * @also castle_btree_write_process()
 * @also castle_btree_read_process()
 */
void castle_btree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if (write)
        castle_btree_write_process(c_bvec);
    else
        castle_btree_read_process(c_bvec);
}

static void castle_btree_c2b_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE), write_unlock;
    c2_block_t *c2b_to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    c2b_to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    write_unlock = (write ? test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags) :
                            test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
    /* Release the buffer if one exists */
    if(c2b_to_forget)
    {
        if(write_unlock)
            write_unlock_c2b(c2b_to_forget);
        else
            read_unlock_c2b(c2b_to_forget);

        put_c2b(c2b_to_forget);
    }
    /* Also, release the component tree lock.
       On reads release as soon as possible. On writes make sure that we've got
       btree_node c2b locked. */
    if(test_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags) && (!write || c_bvec->btree_node))
        castle_btree_ct_unlock(c_bvec);
    /* Promote node to the parent on writes */
    if(write)
    {
        c_bvec->btree_parent_node = c_bvec->btree_node;
        if(test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags))
            set_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
        else
            clear_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
    }
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_btree_c2b_remember(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    /* Save the new node buffer, and the lock flags */
    c_bvec->btree_node = c2b;
    if(test_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags))
    {
        BUG_ON(!c2b_write_locked(c2b));
        set_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        BUG_ON(!c2b_read_locked(c2b));
        clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
}


static void castle_btree_c2b_lock(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

#ifdef CASTLE_DEBUG
    c_bvec->locking = c2b;
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_GOT_NODE);
    /* Lock the c2b in the write mode if:
       - c2b not up-to-date (doesn't matter if we are doing a read or a write,
       - on writes, if we reached leaf level (possibly following leaf pointers)
       - on writes, if we are doing splits
     */
    if(!c2b_uptodate(c2b) || write)
    {
        write_lock_c2b(c2b);
        set_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        read_lock_c2b(c2b);
        clear_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    }
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_LOCKED_NODE);
}

/**
 * Queues bvec on the right workqueue, on the right CPU (if one was specified).
 *
 * @param c_bvec    Castle bio vec to queue.
 */
static void castle_btree_bvec_queue(c_bvec_t *c_bvec)
{
    if(c_bvec->cpu >= 0)
        queue_work_on(c_bvec->cpu, castle_wqs[c_bvec->btree_depth], &c_bvec->work);
    else
        queue_work(castle_wqs[c_bvec->btree_depth], &c_bvec->work);
}

static void castle_btree_submit_io_end(c2_block_t *c2b)
{
#ifdef CASTLE_DEBUG
    struct castle_btree_node *node;
    struct castle_btree_type *btree;
#endif
    c_bvec_t *c_bvec = c2b->private;

    debug("Finished IO for: key %p, in version 0x%x\n",
            c_bvec->key, c_bvec->version);

    /* Callback on error */
    if(!c2b_uptodate(c2b))
    {
        castle_btree_io_end(c_bvec, INVAL_VAL_TUP, -EIO);
        return;
    }
    castle_btree_c2b_remember(c_bvec, c2b);
#ifdef CASTLE_DEBUG
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
    /* @TODO: This function runs in interrupt context and node_validate might
     * block due to kmalloc() */
    btree->node_validate(node);
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);

    BUG_ON(c_bvec->btree_depth > MAX_BTREE_DEPTH);
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree.
       A single queue cannot be used, because a request blocked on
       lock_c2b() would block the entire queue (=> deadlock). */
    CASTLE_INIT_WORK(&c_bvec->work, castle_btree_process);
    castle_btree_bvec_queue(c_bvec);
}

static void __castle_btree_submit(c_bvec_t *c_bvec,
                                  c_ext_pos_t node_cep,
                                  void *parent_key)
{
    struct castle_component_tree *ct;
    struct castle_btree_type *btree;
    c2_block_t *c2b;
    int ret;
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    debug("Asked for key: %p, in version 0x%x, reading ftree node" cep_fmt_str_nl,
            c_bvec->key, c_bvec->version, cep2str(node_cep));
    ret = -ENOMEM;

    ct = c_bvec->tree;
    btree = castle_btree_type_get(ct->btree_type);
    c_bvec->btree_depth++;

    if (write)
    {
        if (c_bvec->parent_key)
            btree->key_dealloc(c_bvec->parent_key);
        c_bvec->parent_key = btree->key_duplicate(parent_key);
    }

    castle_debug_bvec_btree_walk(c_bvec);

    /* Forget the parent node buffer first */
    castle_btree_c2b_forget(c_bvec);
    /* Get the cache block for the next node. */
    c2b = castle_cache_block_get(node_cep,
                                 btree->node_size(ct,
                                                  c_bvec->btree_levels - c_bvec->btree_depth));
    castle_btree_c2b_lock(c_bvec, c2b);
    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_OUTOFDATE);
        c2b->private = c_bvec;
        c2b->end_io = castle_btree_submit_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    }
    else
    {
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2b_remember should not return an error, because
           the Btree node had been normalized already. */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
        castle_btree_c2b_remember(c_bvec, c2b);
        castle_btree_process(&c_bvec->work);
    }
}

/**
 * Submit request to btree (workqueue function).
 *
 * - Queuer should have placed us such that we are running on the
 *   request_cpus.cpus[] cpu that matches c_bvec->tree (CPU-affinity for T0 CT)
 * - Except for some stateful ops and gets we expect to go largely uncontended
 *   for CT locks
 */
static void _castle_btree_submit(struct work_struct *work)
{
    struct castle_component_tree *ct;
    struct castle_btree_type *btree;
    c_ext_pos_t root_cep;
    c_bvec_t *c_bvec;

    /* Work out various request details. */
    c_bvec = container_of(work, c_bvec_t, work);
    ct = c_bvec->tree;
    btree = castle_btree_type_get(ct->btree_type);

    /* Prepare the state flags, etc. */
    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    clear_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
    clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    clear_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    /* This will lock the component tree. */
    root_cep = castle_btree_root_get(c_bvec);
    /* Number of levels in the tree can be read safely now */
    c_bvec->btree_levels = ct->tree_depth;
    BUG_ON(EXT_POS_INVAL(root_cep));
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_btree_submit(c_bvec, root_cep, btree->max_key);
}

/**
 * Submit request to the btree.
 *
 * - Queue the request to the c_bvec-specified CPU
 */
void castle_btree_submit(c_bvec_t *c_bvec)
{
    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    c_bvec->parent_key        = NULL;

    CASTLE_INIT_WORK(&c_bvec->work, _castle_btree_submit);
    castle_btree_bvec_queue(c_bvec);
}

/**********************************************************************************************/
/* Btree iterator */

static void castle_btree_iter_version_key_dealloc(c_iter_t *c_iter)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);

    if(c_iter->next_key.need_destroy)
        btree->key_dealloc(c_iter->next_key.key);
}

/* Put c2b's on the path from given depth. from = 0 means put entire path */
static void castle_btree_iter_path_put(c_iter_t *c_iter, int from)
{
    int i = 0;
    iter_debug("From=%d\n", from);

    for (i = from; i<MAX_BTREE_DEPTH; i++)
    {
        if(c_iter->path[i] == NULL)
            continue;

        put_c2b(c_iter->path[i]);
        c_iter->path[i] = NULL;
    }
}

static void castle_btree_iter_end(c_iter_t *c_iter, int err)
{
    iter_debug("Putting path, ending\n");


    castle_btree_iter_version_key_dealloc(c_iter);
    castle_btree_iter_path_put(c_iter, 0);

    /* @TODO: this will not work well for double frees/double ends, fix that */
    if(c_iter->indirect_nodes)
    {
        castle_vfree(c_iter->indirect_nodes);
        c_iter->indirect_nodes = NULL;
    }

    if (c_iter->end)
        c_iter->end(c_iter, err);

    atomic_dec(&castle_btree_iters_cnt);
    wake_up(&castle_btree_iters_wq);
}

#ifdef CASTLE_DEBUG
#define indirect_node(_i)      ({struct castle_indirect_node *_n;            \
                                 BUG_ON(!c_iter->indirect_nodes);            \
                                 BUG_ON(_i >= RW_TREES_MAX_ENTRIES);         \
                                 _n = &c_iter->indirect_nodes[(_i)];         \
                                 _n;})
#else
#define indirect_node(_i)      (&c_iter->indirect_nodes[(_i)])
#endif
#define cep_lt(_cep1, _cep2)   (EXT_POS_COMP(_cep1, _cep2) < 0)
#define c2b_follow_ptr(_i)     indirect_node(indirect_node(_i)->r_idx)->c2b

#define slot_follow_ptr(_i, _real_c2b, _real_slot_idx)                       \
({                                                                           \
    struct castle_btree_node *_n;                                            \
    struct castle_btree_type *_t;                                            \
    c_val_tup_t _cvt;                                                        \
                                                                             \
    (_real_c2b)      = c_iter->path[c_iter->depth];                          \
    _n               = c2b_bnode(_real_c2b);                                 \
    _t               = castle_btree_type_get(_n->type);                      \
    (_real_slot_idx) = (_i);                                                 \
    _t->entry_get(_n, _i, NULL, NULL, &_cvt);                                \
    if(CVT_LEAF_PTR(_cvt))                                                   \
    {                                                                        \
        BUG_ON(btree == &castle_ro_tree);                                    \
        (_real_c2b)  = c2b_follow_ptr(_i);                                   \
        (_real_slot_idx) = indirect_node(_i)->node_idx;                      \
    }                                                                        \
 })

void castle_btree_iter_replace(c_iter_t *c_iter, int index, c_val_tup_t cvt)
{
    struct castle_btree_node *real_node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *real_c2b;
    int real_entry_idx;
    void *prev_key;
    c_val_tup_t prev_cvt;
    version_t prev_version;
#ifdef CASTLE_DEBUG
    struct castle_btree_node *node;

    iter_debug("Version=0x%x, index=%d\n", c_iter->version, index);

    real_c2b = c_iter->path[c_iter->depth];
    BUG_ON(real_c2b == NULL);

    node = c2b_bnode(real_c2b);
    BUG_ON(!node->is_leaf);
    BUG_ON(index >= node->used);
#endif

    slot_follow_ptr(index, real_c2b, real_entry_idx);
    real_node = c2b_bnode(real_c2b);

    btree->entry_get(real_node,
                     real_entry_idx,
                    &prev_key,
                    &prev_version,
                    &prev_cvt);
    /* We should be looking at a concreate entry, not a leaf pointer now */
    BUG_ON(CVT_LEAF_PTR(prev_cvt));

#if 0
    if (CVT_ONDISK(prev_cvt) && CVT_ONDISK(cvt))
    iter_debug("Current=(0x%x, 0x%x), new=(0x%x, 0x%x), "
               "in btree node: (0x%x, 0x%x), index=%d\n",
                prev_cvt.cep.ext_id,
                prev_cvt.cep.offset,
                cvt.cep.ext_id,
                cvt.cep.offset,
                real_c2b->cep.ext_id,
                real_c2b->cep.offset,
                real_entry_idx);
#endif

    BUG_ON(CVT_LEAF_PTR(cvt));
    btree->entry_replace(real_node,
                         real_entry_idx,
                         prev_key,
                         prev_version,
                         cvt);
    dirty_c2b(real_c2b);
}

static void __castle_btree_iter_start(c_iter_t *c_iter);

static void __castle_btree_iter_release(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    c2_block_t *leaf;
    int i;

    iter_debug("Releasing leaf node.\n");
    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!node->is_leaf);

    if(c_iter->indirect_nodes != NULL)
    {
        /* Unlock all the indirect nodes. */
        for(i=node->used - 1; i>=0; i--)
        {
            iter_debug("===> Trying to unlock indirect node i=%d\n", i);
            if(indirect_node(i)->c2b)
            {
                write_unlock_c2b(indirect_node(i)->c2b);
                put_c2b(indirect_node(i)->c2b);
                indirect_node(i)->c2b = NULL;
            }
        }
        iter_debug("Unlocking cep=(0x%x, 0x%x)\n",
            leaf->cep.ext_id, leaf->cep.offset);
    }
    iter_debug("%p unlocks leaf (0x%x, 0x%x)\n",
        c_iter, leaf->cep.ext_id, leaf->cep.offset);
    write_unlock_c2b(leaf);
}

void castle_btree_iter_continue(c_iter_t *c_iter)
{
    __castle_btree_iter_release(c_iter);
    castle_btree_iter_start(c_iter);
}

static void castle_btree_iter_leaf_ptrs_sort(c_iter_t *c_iter, int nr_ptrs)
{
    int i, root, child, start, end, last_r_idx;
    c_ext_pos_t  last_cep;

    /* We use heapsort, using Wikipedia's pseudo-code as the reference */
#define heap_swap(_i, _j)                                                   \
           {c_ext_pos_t  tmp_cep;                                           \
            uint8_t      tmp_f_idx;                                         \
            tmp_cep   = indirect_node(_i)->cep;                             \
            tmp_f_idx = indirect_node(_i)->f_idx;                           \
            indirect_node(_i)->cep   = indirect_node(_j)->cep;              \
            indirect_node(_i)->f_idx = indirect_node(_j)->f_idx;            \
            indirect_node(_j)->cep   = tmp_cep;                             \
            indirect_node(_j)->f_idx = tmp_f_idx;}

#define sift_down(_start, _end)                                             \
   {root = (_start);                                                        \
    while((2*root + 1) <= (_end))                                           \
    {                                                                       \
        child = 2 * root + 1;                                               \
        if((child < (_end)) &&                                              \
            cep_lt(indirect_node(child)->cep, indirect_node(child+1)->cep)) \
                child = child+1;                                            \
        if(cep_lt(indirect_node(root)->cep, indirect_node(child)->cep))     \
        {                                                                   \
            heap_swap(root, child);                                         \
            root = child;                                                   \
        } else                                                              \
        {                                                                   \
            break;                                                          \
        }                                                                   \
    }}

    /* Arrange the array into a heap */
    for(start = (nr_ptrs - 2)/2; start >= 0; start--)
        sift_down(start, nr_ptrs-1);

    /* Sort */
    for(end=nr_ptrs-1; end > 0; end--)
    {
        heap_swap(end, 0);
        sift_down(0, end-1);
    }

    /* Create the reverse map. Also, remove duplicate ceps from the array */
    last_cep   = INVAL_EXT_POS;
    last_r_idx = -1;
    for(i=0; i < nr_ptrs; i++)
    {
        if(EXT_POS_EQUAL(indirect_node(i)->cep, last_cep))
        {
            BUG_ON(last_r_idx < 0);
            indirect_node(indirect_node(i)->f_idx)->r_idx = last_r_idx;
            indirect_node(i)->cep = INVAL_EXT_POS;
        } else
        {
            indirect_node(indirect_node(i)->f_idx)->r_idx = i;
            last_cep   = indirect_node(i)->cep;
            last_r_idx = i;
        }
    }
}

static void castle_btree_iter_leaf_ptrs_lock(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *c2b;
    int i, j, nr_ptrs;

    /* RO trees don't have leaf pointers. */
    if(btree == &castle_ro_tree)
    {
        BUG_ON(c_iter->indirect_nodes != NULL);
        return;
    }
    node = c2b_bnode(c_iter->path[c_iter->depth]);
    /* Make sure that node->used is smaller than what we can index in 1 byte f/r_idx */
    BUG_ON(node->used >= 1<<(8*sizeof(uint16_t)));

    /* Find all leaf pointers */
    j=0;
    for(i=0; i<node->used; i++)
    {
        version_t entry_version;
        c_val_tup_t entry_cvt;

        btree->entry_get(node, i, NULL, &entry_version,
                         &entry_cvt);
        if((c_iter->type == C_ITER_MATCHING_VERSIONS &&
            entry_version != c_iter->version) ||
           (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
            !castle_version_is_ancestor(entry_version, c_iter->version)))
            continue;
        if(CVT_LEAF_PTR(entry_cvt))
        {
            BUG_ON(indirect_node(j)->c2b);
            indirect_node(j)->cep   = entry_cvt.cep;
            indirect_node(j)->f_idx = i;
            j++;
        }
    }
    nr_ptrs = j;

    /* Sort the pointers on cep ordering */
    castle_btree_iter_leaf_ptrs_sort(c_iter, nr_ptrs);

    /* Now that leafs have been sorted, lock them all */
    for(i=0; i<nr_ptrs; i++)
    {
        c_ext_pos_t cep = indirect_node(i)->cep;
        /* Skip over the invalid (previously duplicated) blocks */
        if(EXT_POS_INVAL(cep))
        {
            indirect_node(i)->c2b = NULL;
            continue;
        }
        BUG_ON(c_iter->depth + 1 != c_iter->btree_levels);
        c2b = castle_cache_block_get(cep, btree->node_size(c_iter->tree, 0));
        write_lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
            submit_c2b_sync(READ, c2b);
        indirect_node(i)->c2b = c2b;
    }

    /* Finally, find out where in the indirect block the individual ptrs are */
    for(i=0; i<node->used; i++)
    {
        version_t entry_version;
        void *entry_key;
        c_val_tup_t entry_cvt;

        /* Set the idx to inval to catch bugs early */
        indirect_node(i)->node_idx = -1;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_cvt);
        if((c_iter->type == C_ITER_MATCHING_VERSIONS &&
            entry_version != c_iter->version) ||
           (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
            !castle_version_is_ancestor(entry_version, c_iter->version)))
            continue;
        if(CVT_LEAF_PTR(entry_cvt))
        {
            version_t real_entry_version;
            void *real_entry_key;
            int lub_idx;

            castle_btree_lub_find(c2b_bnode(c2b_follow_ptr(i)),
                                  entry_key,
                                  entry_version,
                                 &lub_idx,
                                  NULL);
            /* Check that we _really_ found the right entry in the indirect node */
            BUG_ON(lub_idx < 0);
            btree->entry_get(c2b_bnode(c2b_follow_ptr(i)),
                             lub_idx,
                            &real_entry_key,
                            &real_entry_version,
                             NULL);
            BUG_ON((btree->key_compare(entry_key, real_entry_key) != 0) ||
                   (entry_version != real_entry_version));
            indirect_node(i)->node_idx = lub_idx;
        }
    }
}

static void castle_btree_iter_parent_node_idx_increment(c_iter_t *c_iter)
{
#ifdef DEBUG
    int i;
#endif

    iter_debug("Called parent_node_idx_increment at depth=%d\n",
                c_iter->depth);
    /* Increment ONLY if we are doing C_ITER_ALL_ENTRIES */
    if(c_iter->type != C_ITER_ALL_ENTRIES)
        return;
    /* Otherwise, increment the index for our parent node, if one exists.
       Note that this may move the index beyond the capacity of the
       parent node. This will be picked up, and fixed up on the next
       path_traverse() */
    if(c_iter->depth > 0)
    {
        /* Increment the idx */
        iter_debug("Incrementing index at depth=%d, %d->%d\n",
                c_iter->depth-1,
                c_iter->node_idx[c_iter->depth - 1],
                c_iter->node_idx[c_iter->depth - 1] + 1);
        c_iter->node_idx[c_iter->depth - 1]++;
        /* Reset the current depth idx to -1 */
        iter_debug("Reseting index at depth: %d, from %d->-1\n",
                c_iter->depth,
                c_iter->node_idx[c_iter->depth]);
        c_iter->node_idx[c_iter->depth] = -1;
#ifdef DEBUG
        /* All indicies below should be zero, but check that anyway */
        for(i=c_iter->depth+1; i<MAX_BTREE_DEPTH; i++)
        {
            if(c_iter->node_idx[i] == -1)
                continue;
            castle_printk("ERROR: non -1 node_idx (%d) in idx_increment. "
                   "at c_iter->depth=%d, found non -1 at depth=%d\n",
                c_iter->node_idx[i], c_iter->depth, i);
            BUG();
        }
#endif
    }
    /* We don't have to do anything if we are at the root node.
       What will happen is that iter_start() will be called again, and
       this will terminate the iterator, as the ->depth == 0 */
}

static void castle_btree_iter_version_leaf_process(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *leaf;
    int i;

    BUG_ON(VERSION_INVAL(c_iter->version));

    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!node->is_leaf);

    iter_debug("Processing %d entries\n", node->used);

    /* We are in a leaf, then save the vblk number we followed to get here */
    castle_btree_iter_version_key_dealloc(c_iter);
    if(btree->key_compare(c_iter->parent_key, btree->inv_key) == 0)
    {
        c_iter->next_key.key          = btree->inv_key;
        c_iter->next_key.need_destroy = 0;
    } else
    {
        c_iter->next_key.key          = btree->key_next(c_iter->parent_key);
        c_iter->next_key.need_destroy = 1;
    }

    if (c_iter->node_start != NULL)
        c_iter->node_start(c_iter);

    castle_btree_iter_leaf_ptrs_lock(c_iter);

    for(i=0; i<node->used; i++)
    {
        int         real_slot_idx;
        version_t   entry_version;
        c_val_tup_t entry_cvt;
        void       *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_cvt);

        if (CVT_ONDISK(entry_cvt))
            iter_debug("Current slot: (b=%p, v=%x)->(cep=0x%x, 0x%x)\n",
                       entry_key, entry_version, entry_cvt.cep.ext_id,
                       entry_cvt.cep.offset);
        if (entry_version == c_iter->version ||
            (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
             castle_version_is_ancestor(entry_version, c_iter->version)))
        {
            c2_block_t *c2b;

            slot_follow_ptr(i, c2b, real_slot_idx);
            btree->entry_get(c2b_bnode(c2b), real_slot_idx, NULL, NULL,
                             &entry_cvt);
            c_iter->each(c_iter, i, entry_key, entry_version, entry_cvt);
        }
    }

    iter_debug("Done processing entries.\n");

    /*
     * Send end node callback if one not specified. Otherwise continue automatically.
     */
    if (c_iter->node_end != NULL)
       c_iter->node_end(c_iter);
    else
       castle_btree_iter_continue(c_iter);
}

static void castle_btree_iter_all_leaf_process(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *leaf;
    int i;

    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!node->is_leaf);

    iter_debug("All entries: processing %d entries\n", node->used);

    if (c_iter->node_start != NULL)
        c_iter->node_start(c_iter);

    for(i=0; i<node->used; i++)
    {
        version_t   entry_version;
        c_val_tup_t entry_cvt;
        void       *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_cvt);

        if (CVT_ONDISK(entry_cvt))
            iter_debug("All entries: current slot: (b=%p, v=%x)->(cep=0x%x, 0x%x)\n",
                       entry_key, entry_version, entry_cvt.cep.ext_id,
                       entry_cvt.cep.offset);
        if (!CVT_LEAF_PTR(entry_cvt))
            c_iter->each(c_iter, i, entry_key, entry_version, entry_cvt);
    }

    iter_debug("Done processing entries.\n");

    /*
     * Send end node callback if one not specified. Otherwise continue automatically.
     */
    if (c_iter->node_end != NULL)
       c_iter->node_end(c_iter);
    else
       castle_btree_iter_continue(c_iter);
}

static void   castle_btree_iter_path_traverse(c_iter_t *c_iter, c_ext_pos_t  node_cep);
static void __castle_btree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_ext_pos_t  entry_cep, node_cep;
    void *entry_key;
    int index, skip;
    c_val_tup_t cvt;

    /* Return early on error */
    if(c_iter->err)
    {
        /* Unlock the top of the stack, this is normally done by
           castle_btree_iter_continue. This will not happen now, because
           the iterator was cancelled between two btree nodes. */
        iter_debug("%p unlocking (0x%x, 0x%x)\n",
                c_iter,
                c_iter->path[c_iter->depth]->cep.ext_id,
                c_iter->path[c_iter->depth]->cep.offset);
        write_unlock_c2b(c_iter->path[c_iter->depth]);
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }

    /* Otherwise, we know that the node got read successfully. Its buffer is in the path. */
    node = c2b_bnode(c_iter->path[c_iter->depth]);

    switch(c_iter->type)
    {
        case C_ITER_ALL_ENTRIES:
            node_cep = c_iter->path[c_iter->depth]->cep;
            /* If we enumerating all entries in the tree, we use the index saved
               in node_idx table. */
            index = c_iter->node_idx[c_iter->depth];
            iter_debug("Processing node_cep=(0x%x, 0x%x), index=%d, node->used=%d\n",
                    node_cep.ext_id, node_cep.offset, index, node->used);
            BUG_ON((index >= 0) && (index > node->used)); /* Be careful about unsigned comparions */
            /* If index is in range [0 - (node->used-1)] (inclusive), we don't
               have to check need_visit() (this has already been done).
               If so, we can go straight to the next level of recursion */
            if((index >= 0) && (index < node->used))
            {
                iter_debug("Subsequent visit, processing.\n");
                break;
            }

            /* Skip processing the node if we already got to the end of the node.
               Or if we are visiting the node for the first time (index == -1),
               we may still want to skip it, if need_visit() call is false. */
            BUG_ON((index != node->used) && (index != -1));
            skip = (index == node->used) ||
                   (c_iter->need_visit && !c_iter->need_visit(c_iter, node_cep));

            if(skip)
            {
                iter_debug("Skipping.\n");
                castle_btree_iter_parent_node_idx_increment(c_iter);
                iter_debug("%p unlocking (0x%x, 0x%x)\n",
                        c_iter,
                        node_cep.ext_id,
                        node_cep.offset);
                write_unlock_c2b(c_iter->path[c_iter->depth]);
                castle_btree_iter_start(c_iter);
                return;
            }

            /* If we got here, it must be because we are visiting a node for the
               first time, and need_visit() was true */
            BUG_ON((index != -1) || skip);

            /* Deal with leafs first */
            if(node->is_leaf)
            {
                iter_debug("Visiting leaf node cep=(0x%x, 0x%x).\n",
                        node_cep.ext_id, node_cep.offset);
                castle_btree_iter_all_leaf_process(c_iter);
                castle_btree_iter_parent_node_idx_increment(c_iter);
                return;
            }

            /* Final case: intermediate node visited for the first time */
            iter_debug("Visiting node cep=(0x%x, 0x%x) for the first time.\n",
                       node_cep.ext_id, node_cep.offset);
            c_iter->node_idx[c_iter->depth] = index = 0;
            break;
        case C_ITER_MATCHING_VERSIONS:
        case C_ITER_ANCESTRAL_VERSIONS:
            /* Deal with leafs first */
            if(node->is_leaf)
            {
                castle_btree_iter_version_leaf_process(c_iter);
                return;
            }

             /* If we are enumerating all entries for a particular version,
               fin the occurance of the next key. */
            BUG_ON(VERSION_INVAL(c_iter->version));
            castle_btree_lub_find(node, c_iter->next_key.key, c_iter->version, &index, NULL);
            iter_debug("Node index=%d\n", index);
            break;
    }
    btree->entry_get(node, index, &entry_key, NULL, &cvt);
    entry_cep = cvt.cep;
    if (!CVT_NODE(cvt))
    {
        castle_printk("0x%x-%llu-"cep_fmt_str_nl,
                cvt.type,
                (uint64_t)cvt.length,
                cep2str(cvt.cep));
        BUG();
    }

    c_iter->depth++;
    c_iter->parent_key = entry_key;

    castle_btree_iter_path_traverse(c_iter, entry_cep);
}

static void _castle_btree_iter_path_traverse(c2_block_t *c2b)
{
    c_iter_t *c_iter = c2b->private;

    iter_debug("Finished reading btree node.\n");

    if(!c2b_uptodate(c2b))
    {
        iter_debug("Error reading the btree node. Cancelling iterator.\n");
        iter_debug("%p unlocking cep: (0x%x, 0x%x).\n", c_iter, c2b->cep.ext_id, c2b->cep.offset);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        /* Save the error. This will be handled properly by __path_traverse */
        c_iter->err = -EIO;
    } else
    {
        /* Push the node onto the path 'stack' */
        BUG_ON((c_iter->path[c_iter->depth] != NULL) && (c_iter->path[c_iter->depth] != c2b));
        c_iter->path[c_iter->depth] = c2b;
    }

    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree.
       A single queue cannot be used, because a request blocked on
       lock_c2b() would block the entire queue (=> deadlock).
       NOTE: The +1 is required to match the wqs we are using in normal btree walks. */
    CASTLE_INIT_WORK(&c_iter->work, __castle_btree_iter_path_traverse);
    queue_work(castle_wqs[c_iter->depth+MAX_BTREE_DEPTH], &c_iter->work);
}

static void castle_btree_iter_path_traverse(c_iter_t *c_iter, c_ext_pos_t node_cep)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *c2b = NULL;

    iter_debug("Starting the traversal: depth=%d, node_cep=(0x%x, 0x%x)\n",
                c_iter->depth, node_cep.ext_id, node_cep.offset);

    /* Try to use the c2b we've saved in the path, if it matches node_cep */
    if(c_iter->path[c_iter->depth] != NULL)
    {
        c2b = c_iter->path[c_iter->depth];

        if(!EXT_POS_EQUAL(c2b->cep, node_cep))
        {
            castle_btree_iter_path_put(c_iter, c_iter->depth);
            c2b = NULL;
        }
    }

    /* If we haven't found node_cep in path, get it from the cache instead */
    if(c2b == NULL)
        c2b = castle_cache_block_get(node_cep,
                                     btree->node_size(c_iter->tree,
                                                      c_iter->btree_levels - c_iter->depth - 1));

    iter_debug("%p locking cep=(0x%x, 0x%x)\n",
        c_iter, c2b->cep.ext_id, c2b->cep.offset);

    write_lock_c2b(c2b);

    /* Unlock the tree if we've just locked the root */
    if(c_iter->depth == 0)
    {
        /* We have just started the iteration - lets unlock the version tree */
        iter_debug("Unlocking component tree.\n");
        up_read(&c_iter->tree->lock);
    }
    /* Unlock previous c2b */
    if((c_iter->depth > 0) && (c_iter->path[c_iter->depth - 1] != NULL))
    {
        c2_block_t *prev_c2b = c_iter->path[c_iter->depth - 1];
        iter_debug("%p unlocking cep=(0x%x, 0x%x)\n",
            c_iter, prev_c2b->cep.ext_id, prev_c2b->cep.offset);
        write_unlock_c2b(prev_c2b);
        /* NOTE: not putting the c2b. Might be useful if we have to walk the tree again */
    }

    /* Read from disk where nessecary */
    c2b->private = c_iter;
    if(!c2b_uptodate(c2b))
    {
        iter_debug("Not uptodate, submitting\n");

        /* If the buffer doesn't contain up to date data, schedule the IO */
        c2b->end_io = _castle_btree_iter_path_traverse;
        BUG_ON(submit_c2b(READ, c2b));
    }
    else
    {
        iter_debug("Uptodate, carrying on\n");
        /* If the buffer is up to date */
        _castle_btree_iter_path_traverse(c2b);
    }
}

static void __castle_btree_iter_start(c_iter_t *c_iter)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_ext_pos_t  root_cep;

    iter_debug("-------------- STARTING THE ITERATOR -------------------\n");

    /*
     * End conditions: we must be done if:
     *    - we start again at depth 0 - ie the root is a leaf
     *    - we followed max key to a leaf
     *    - we were cancelled
     */
    if ((c_iter->depth == 0) ||
       ((c_iter->type == C_ITER_MATCHING_VERSIONS) &&
            (btree->key_compare(c_iter->next_key.key, btree->inv_key) == 0)) ||
       ((c_iter->type == C_ITER_ANCESTRAL_VERSIONS) &&
            (btree->key_compare(c_iter->next_key.key, btree->inv_key) == 0)) ||
        (c_iter->cancelled))
    {
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }

    /*
     * Let's start from the root again...
     */
    iter_debug("Locking version tree for version: %d\n", c_iter->version);

    down_read(&c_iter->tree->lock);

    c_iter->depth = 0;
    c_iter->btree_levels = c_iter->tree->tree_depth;
    root_cep = c_iter->tree->root_node;
    if(EXT_POS_INVAL(root_cep))
    {
        iter_debug("Warning: Invalid disk block for the root.\n");
        up_read(&c_iter->tree->lock);
        /* Complete the request early, end exit */
        castle_btree_iter_end(c_iter, -EINVAL);
        return;
    }

    c_iter->parent_key = btree->inv_key;
    castle_btree_iter_path_traverse(c_iter, root_cep);
}

static void _castle_btree_iter_start(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);

    __castle_btree_iter_start(c_iter);
}

void castle_btree_iter_start(c_iter_t* c_iter)
{
    CASTLE_INIT_WORK(&c_iter->work, _castle_btree_iter_start);
    queue_work(castle_wqs[19], &c_iter->work);
}

void castle_btree_iter_cancel(c_iter_t *c_iter, int err)
{
    iter_debug("Cancelling version=0x%x iterator, error=%d\n", c_iter->version, err);

    c_iter->err = err;
    wmb();
    c_iter->cancelled = 1;
}

void castle_btree_iter_init(c_iter_t *c_iter, version_t version, int type)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    int i;
;
    iter_debug("Initialising iterator for version=0x%x\n", version);

    atomic_inc(&castle_btree_iters_cnt);

    c_iter->type = type;
    c_iter->version = version;
    c_iter->parent_key = btree->min_key;
    c_iter->next_key.key = btree->min_key;
    c_iter->next_key.need_destroy = 0;
    c_iter->depth = -1;
    c_iter->err = 0;
    c_iter->cancelled = 0;
    c_iter->indirect_nodes = NULL;
    memset(c_iter->path, 0, sizeof(c_iter->path));
    switch(c_iter->type)
    {
        case C_ITER_ALL_ENTRIES:
            BUG_ON(!VERSION_INVAL(version));
            /* Set all node indices to -1, which implies most extreme LHS walk through
               the tree first */
            for(i=0; i<MAX_BTREE_DEPTH; i++)
                c_iter->node_idx[i] = -1;
            return;
        case C_ITER_MATCHING_VERSIONS:
        case C_ITER_ANCESTRAL_VERSIONS:
            /* RO trees don't have leaf pointers (and have much larger nodes). */
            if(btree == &castle_ro_tree)
                return;
            c_iter->indirect_nodes =
                castle_vmalloc(RW_TREES_MAX_ENTRIES * sizeof(struct castle_indirect_node));
            /* If memory allocation failed, cancel the iterator, and set the error condition.
               This will get picked up by _start() */
            if(!c_iter->indirect_nodes)
                castle_btree_iter_cancel(c_iter, -ENOMEM);
            memset(c_iter->indirect_nodes,
                   0,
                   RW_TREES_MAX_ENTRIES * sizeof(struct castle_indirect_node));
            return;
        default:
            BUG();
            return;
    }
}

/***** Init/fini functions *****/
/* We have a static array of btree types indexed by btree_t, don't let it grow too
   large. */
STATIC_BUG_ON(sizeof(btree_t) != 1);
int castle_btree_init(void)
{
    BUG_ON(RW_TREES_MAX_ENTRIES < MTREE_NODE_ENTRIES);
    BUG_ON(RW_TREES_MAX_ENTRIES < BATREE_NODE_ENTRIES);
    BUG_ON(RW_TREES_MAX_ENTRIES < VLBA_RW_TREE_MAX_ENTRIES);
    return 0;
}

void castle_btree_free(void)
{
    /* Wait until all iterators are completed */
    wait_event(castle_btree_iters_wq, (atomic_read(&castle_btree_iters_cnt) == 0));
}


/**********************************************************************************************/
/* Btree enumerator */
#define VISITED_HASH_LENGTH     (1000)
static int castle_enum_iter_need_visit(c_iter_t *c_iter, c_ext_pos_t  node_cep)
{
    struct castle_enumerator *c_enum = c_iter->private;
    struct castle_visited *visited;
    struct list_head *l;
    int i;

    enum_debug("Iterator is asking if to visit (0x%x, 0x%x)\n",
            node_cep.ext_id, node_cep.offset);
    /* All hash operations need to be protected with the lock */
    spin_lock(&c_enum->visited_lock);
    /* Simplistic hash function */
    i = (node_cep.ext_id + node_cep.offset) % VISITED_HASH_LENGTH;
    enum_debug("Hash bucket: %d\n", i);
    /* Check if the cep is in the hash */
    list_for_each(l, &c_enum->visited_hash[i])
    {
        visited = list_entry(l, struct castle_visited, list);
        if(EXT_POS_EQUAL(visited->cep, node_cep))
        {
            enum_debug("Found in the hash.\n");
            spin_unlock(&c_enum->visited_lock);
            return 0;
        }
    }
    enum_debug("Not found in the hash. Inserting\n");
    /* We haven't found the entry in the hash, insert it instead */
    visited = c_enum->visited + c_enum->next_visited++;
    BUG_ON(c_enum->next_visited >= c_enum->max_visited);
    visited->cep = node_cep;
    list_add(&visited->list, &c_enum->visited_hash[i]);
    /* Unlock and return 1 (please visit the node) */
    spin_unlock(&c_enum->visited_lock);

    return 1;
}

static void castle_enum_iter_each(c_iter_t *c_iter,
                                  int index,
                                  void *key,
                                  version_t version,
                                  c_val_tup_t cvt)
{
    struct castle_enumerator *c_enum = c_iter->private;
    struct castle_btree_type *btree;

    btree = castle_btree_type_get(c_enum->buffer->type);
    BUG_ON(c_enum->prod_idx != c_enum->buffer->used);
    enum_debug("Entry for iterator: idx=%d, key=%p, version=%d\n",
               index, key, version);
    BUG_ON(CVT_LEAF_PTR(cvt));
    btree->entry_add(c_enum->buffer, c_enum->prod_idx, key, version, cvt);
    c_enum->prod_idx++;
}

static void castle_enum_iter_node_end(c_iter_t *c_iter)
{
    struct castle_enumerator *c_enum = c_iter->private;

    BUG_ON(c_enum->cons_idx != 0);
    enum_debug("Ending node for iterator, nr_entries=%d.\n", c_enum->prod_idx);
    /* Special case, if nothing was read (it's possible if e.g. all entries are leaf ptrs)
       schedule the next node read, and exit early */
    if(c_enum->prod_idx == 0)
    {
        castle_printk("There were no useful entries in the node. How is that possible? Error?.\n");
        castle_btree_iter_continue(c_iter);
        return;
    }
    /* Release the leaf lock, otherwise other iterators will block, and we will never
       go past the enumaror initialisation */
    __castle_btree_iter_release(c_iter);

    c_enum->iterator_outs = 0;
    wmb();
    wake_up(&c_enum->iterator_wq);
}

static void castle_enum_iter_end(c_iter_t *c_iter, int err)
{
    struct castle_enumerator *c_enum = c_iter->private;

    if(err) c_enum->err = err;
    enum_debug("Iterator ending, err=%d\n", err);
    c_enum->iter_completed = 1;
    c_enum->iterator_outs = 0;
    wmb();
    wake_up(&c_enum->iterator_wq);
}

static void castle_btree_enum_fini(c_enum_t *c_enum)
{
    enum_debug("Freeing enumerator.\n");
#ifdef DEBUG
    if(c_enum->buffer)
    {
        enum_debug("Freeing buffer for the iterator.\n");
        BUG_ON((c_enum->err != -ENOMEM) && (!c_enum->iter_completed));
    }
#endif
    if(c_enum->buffer1)
        castle_vfree(c_enum->buffer1);
    if(c_enum->buffer2)
        castle_vfree(c_enum->buffer2);

    if(c_enum->visited_hash)
    {
        castle_free(c_enum->visited_hash);
        c_enum->visited_hash = NULL;
    }
    if(c_enum->visited)
    {
        castle_vfree(c_enum->visited);
        c_enum->visited = NULL;
    }
}

static inline void castle_btree_enum_iterator_wait(c_enum_t *c_enum)
{
    wait_event(c_enum->iterator_wq, ({int _ret;
                                      rmb();
                                      _ret = (c_enum->iterator_outs == 0);
                                      _ret;}));
}

void castle_btree_enum_cancel(c_enum_t *c_enum)
{
    enum_debug("Cancelling the enumerator\n");
    /* Make sure that there are no outstanding iterations going on */
    castle_btree_enum_iterator_wait(c_enum);
    /* Cancel the iterator */
    enum_debug("Canceling the iterator.\n");
    if(!c_enum->iter_completed)
    {
        castle_btree_iter_cancel(&c_enum->iterator, 0);
        /* Increment the counter, before restarting the iterator (this will terminate it) */
        c_enum->iterator_outs = 1;
        c_enum->cons_idx = c_enum->prod_idx = 0;
        castle_btree_iter_start(&c_enum->iterator);
    }
    /* Wait for the iterator to terminate */
    enum_debug("Waiting for the iterator to terminate, currently iterator_outs: %d\n",
        c_enum->iterator_outs);
    castle_btree_enum_iterator_wait(c_enum);

    /* Now free the buffers */
    castle_btree_enum_fini(c_enum);
}

int castle_btree_enum_has_next(c_enum_t *c_enum)
{
    int ret;

    /* Make sure that all buffers are up-to-date */
    castle_btree_enum_iterator_wait(c_enum);

    ret = !c_enum->iter_completed;
    if(!ret)
        castle_btree_enum_fini(c_enum);

    return ret;
}

static void castle_btree_node_buffer_init(struct castle_component_tree *tree,
                                          struct castle_btree_node *buffer,
                                          uint16_t node_size)
{
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
       Initialise the required bits of the node, so that the types don't complain. */
#ifdef CASTLE_DEBUG
    memset(buffer, 0x88, node_size * C_BLK_SIZE);
#endif
    buffer->magic   = BTREE_NODE_MAGIC;
    buffer->type    = tree->btree_type;
    buffer->version = 0;
    buffer->used    = 0;
    buffer->is_leaf = 1;
    buffer->size    = node_size;
}

void castle_btree_enum_next(c_enum_t *c_enum,
                            void **key_p,
                            version_t *version_p,
                            c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_enum->tree->btree_type);

    /* _has_next() waits for all buffers to be filled in, it's safe to assume this has
       been called just before */
    BUG_ON(c_enum->iterator_outs != 0);
    BUG_ON(c_enum->iter_completed);
    BUG_ON(c_enum->cons_idx >= c_enum->prod_idx);

    enum_debug("cons_idx %d, prod_idx %d\n", c_enum->cons_idx, c_enum->prod_idx);
    /* Read off the entry we want to return, and increment the consumer index */
    btree->entry_get(c_enum->buffer, c_enum->cons_idx, key_p, version_p, cvt_p);
    c_enum->cons_idx++;
    /* Check if next node should be read from the iterator */
    if(c_enum->cons_idx == c_enum->prod_idx)
    {
        enum_debug("Scheduling a read for iterator.\n");
        c_enum->prod_idx = c_enum->cons_idx = 0;
        /* Remember that the iterator is in flight, and schedule the read. */
        c_enum->iterator_outs = 1;
        /* Switch buffers and reset the buffer node */
        enum_debug("Switching buffer from %p ...\n", c_enum->buffer);
        c_enum->buffer = (c_enum->buffer == c_enum->buffer1 ? c_enum->buffer2 : c_enum->buffer1);
        enum_debug("                   to %p.\n", c_enum->buffer);
        castle_btree_node_buffer_init(c_enum->tree, c_enum->buffer, c_enum->buffer->size);
        /* Run the iterator again to get the next nodes worth of stuff */
        castle_btree_iter_start(&c_enum->iterator);
    }
}

void castle_btree_enum_init(c_enum_t *c_enum)
{
    struct castle_component_tree *ct;
    struct castle_iterator *iter;
    struct castle_btree_type *btype;
    uint16_t leaf_node_size;
    int i;

    ct = c_enum->tree;
    btype = castle_btree_type_get(ct->btree_type);
    leaf_node_size = btype->node_size(ct, 0);
    /* We no longer need to support multiple iterators, this should simplify a lot of
       this code.
        @TODO: go through it all and remove unneccessary code */
    c_enum->err            = 0;
    init_waitqueue_head(&c_enum->iterator_wq);
    c_enum->iterator_outs  = 0;
    /* Allocate memory for for buffers to store one node's worth of entries from the iterator */
    c_enum->buffer         = NULL;
    c_enum->buffer1        = NULL;
    c_enum->buffer2        = NULL;
    c_enum->visited_hash   = castle_malloc(VISITED_HASH_LENGTH * sizeof(struct list_head),
                                     GFP_KERNEL);
    c_enum->max_visited    = 8 * VISITED_HASH_LENGTH;
    c_enum->visited        = castle_vmalloc(c_enum->max_visited * sizeof(struct castle_visited));
    if(!c_enum->visited_hash || !c_enum->visited)
        goto no_mem;
    /* Init structures related to visited hash */
    spin_lock_init(&c_enum->visited_lock);
    c_enum->next_visited = 0;
    for(i=0; i<VISITED_HASH_LENGTH; i++)
        INIT_LIST_HEAD(c_enum->visited_hash + i);
    /* Initialise the iterator and the buffer */

    c_enum->prod_idx = 0;
    c_enum->cons_idx = 0;
    c_enum->iter_completed = 0;
    c_enum->buffer1 = castle_vmalloc(leaf_node_size * C_BLK_SIZE);
    c_enum->buffer2 = castle_vmalloc(leaf_node_size * C_BLK_SIZE);
    c_enum->buffer = c_enum->buffer1;
    if(!c_enum->buffer1 || !c_enum->buffer2)
        goto no_mem;
    castle_btree_node_buffer_init(ct, c_enum->buffer, leaf_node_size);

    iter = &c_enum->iterator;
    iter->tree       = ct;
    iter->need_visit = castle_enum_iter_need_visit;
    iter->node_start = NULL;
    iter->each       = castle_enum_iter_each;
    iter->node_end   = castle_enum_iter_node_end;
    iter->end        = castle_enum_iter_end;
    iter->private    = c_enum;
    castle_btree_iter_init(iter, INVAL_VERSION, C_ITER_ALL_ENTRIES);

    enum_debug("Allocated everything.\n");
    c_enum->iterator_outs = 1;
    /* Now, that the iterator has been created, and buffers allocated, start it */
    castle_btree_iter_start(&c_enum->iterator);

    return;
no_mem:
    c_enum->err = -ENOMEM;
    castle_btree_enum_fini(c_enum);
}

struct castle_iterator_type castle_btree_enum = {
    .register_cb = NULL,
    .prep_next   = NULL,
    .has_next = (castle_iterator_has_next_t)castle_btree_enum_has_next,
    .next     = (castle_iterator_next_t)    castle_btree_enum_next,
    .skip     = NULL,
};

static struct node_buf_t* node_buf_alloc(c_rq_enum_t *rq_enum)
{
    struct node_buf_t *node_buf;
    struct castle_btree_type *btype;
    struct castle_component_tree *ct;
    uint16_t leaf_node_size;

    ct = rq_enum->tree;
    btype = castle_btree_type_get(ct->btree_type);
    leaf_node_size = btype->node_size(ct, 0);
    node_buf = castle_malloc(sizeof(struct node_buf_t), GFP_KERNEL);
    BUG_ON(!node_buf);
    node_buf->node = castle_vmalloc(leaf_node_size * C_BLK_SIZE);
    BUG_ON(!node_buf->node);
    castle_btree_node_buffer_init(rq_enum->tree, node_buf->node, leaf_node_size);
    rq_enum->buf_count++;

    return node_buf;
}

static void castle_rq_enum_iter_each(c_iter_t *c_iter,
                                     int index,
                                     void *key,
                                     version_t version,
                                     c_val_tup_t cvt)
{
    struct castle_btree_type *btree;
    c_rq_enum_t *rq_enum = (c_rq_enum_t *)c_iter->private;
    struct node_buf_t *prod_buf = rq_enum->prod_buf;
    struct node_buf_t *cons_buf = rq_enum->cons_buf;
    struct castle_btree_node *node = prod_buf->node;

    btree = castle_btree_type_get(node->type);
    BUG_ON(rq_enum->prod_idx != node->used);

    /* Check if the node buffer is full */
    if (btree->need_split(node, 0))
    {
        debug("Need split - producer buffer :%p\n", prod_buf);
        /* Check to not overwrite last node of previous buffer */
        if (prod_buf->list.next == &cons_buf->list ||
            prod_buf->list.next->next == &cons_buf->list)
        {
            struct node_buf_t *new_buf;

            new_buf = node_buf_alloc(rq_enum);
            list_add(&new_buf->list, &prod_buf->list);
            rq_enum->prod_buf = new_buf;
            debug("Creating new node buffer: %p\n", rq_enum->prod_buf);
        }
        else
        {
            rq_enum->prod_buf = list_entry(prod_buf->list.next,
                                           struct node_buf_t, list);
            castle_btree_node_buffer_init(rq_enum->tree,
                                          rq_enum->prod_buf->node,
                                          rq_enum->prod_buf->node->size);
            debug("Moving prod_buf to next node_buf: %p\n", rq_enum->prod_buf);
        }
        rq_enum->prod_idx = 0;
    }

    if (!rq_enum->in_range)
    {
        if (btree->key_compare(rq_enum->start_key, key) <= 0)
            rq_enum->in_range = 1;
        else
            return;
    }

    if ((!rq_enum->cur_key || btree->key_compare(rq_enum->cur_key, key) != 0))
    {
        debug("Adding entry to node buffer: %p\n", rq_enum->prod_buf);
        BUG_ON(rq_enum->cur_key && btree->key_compare(rq_enum->cur_key, key) > 0);
        BUG_ON(CVT_LEAF_PTR(cvt));
        btree->entry_add(rq_enum->prod_buf->node, rq_enum->prod_idx, key, version, cvt);
        btree->entry_get(rq_enum->prod_buf->node, rq_enum->prod_idx, &rq_enum->cur_key, NULL,
                         NULL);
        rq_enum->prod_idx++;
    }
}

static int castle_btree_rq_enum_prep_next(c_rq_enum_t *rq_enum);

static void castle_rq_enum_iter_node_end(c_iter_t *c_iter)
{
    c_rq_enum_t *rq_enum = c_iter->private;

    rq_debug("%s:%p\n", __FUNCTION__, rq_enum);
    /* Check consumer idx for 0 */
    BUG_ON(rq_enum->cons_idx != 0);

    /* If producer idx also is 0, then schedule iterator again to get entries
     * and return */
    if (rq_enum->prod_idx == 0)
    {
        rq_debug("%p - reschedule\n", rq_enum);
        castle_btree_iter_continue(c_iter);
        return;
    }

    /* Release the iterator resources and mark node process completed */
    __castle_btree_iter_release(c_iter);
    rq_enum->iter_running = 0;
    wmb();
    wake_up(&rq_enum->iter_wq);

    /* prep_next() cancels the iterator, if end_key is found. Iterator
     * cancellation is executed on different thread. */
    if (!rq_enum->sync_call && castle_btree_rq_enum_prep_next(rq_enum))
    {
        /* Call callback of the higher level iterator */
        rq_debug("%p - Done\n", rq_enum);
        rq_enum->end_io(rq_enum, 0);
    }
}

static void castle_rq_enum_iter_end(c_iter_t *c_iter, int err)
{
    c_rq_enum_t *rq_enum = c_iter->private;

    if(err) rq_enum->err = err;
    rq_enum->iter_completed = 1;
    rq_enum->iter_running = 0;
    wmb();
    rq_debug("Nothing left in %p\n", rq_enum);
    wake_up(&rq_enum->iter_wq);
    if (!rq_enum->sync_call)
    {
        BUG_ON(!castle_btree_rq_enum_prep_next(rq_enum));
        rq_debug("%p - Done\n", rq_enum);
        /* Call callback of the higher level iterator */
        rq_enum->end_io(rq_enum, 0);
        return;
    }
}

static void castle_btree_rq_enum_fini(c_rq_enum_t *rq_enum)
{
    struct node_buf_t *buf = rq_enum->buf_head;
    struct node_buf_t *next;
    int count = 0;

    do {
        next = list_entry(buf->list.next,
                          struct node_buf_t, list);
        castle_vfree(buf->node);
        castle_free(buf);
        buf = next;
        count++;
        BUG_ON(count > rq_enum->buf_count);
    } while (buf != rq_enum->buf_head);
    BUG_ON(count != rq_enum->buf_count);
    debug("Free rq_enum: %p\n", rq_enum);
}

void castle_btree_rq_enum_init(c_rq_enum_t *rq_enum, version_t version,
                               struct castle_component_tree *tree,
                               void *start_key,
                               void *end_key)
{
    struct castle_btree_type *btype;
    struct castle_iterator *iter;

    btype = castle_btree_type_get(tree->btree_type);
    BUG_ON(btype->key_compare(start_key, btype->inv_key) == 0 ||
           btype->key_compare(end_key, btype->inv_key) == 0);

    rq_enum->tree           = tree;
    rq_enum->err            = 0;
    rq_enum->end_io         = NULL;
    rq_enum->version        = version;
    rq_enum->iter_completed = 0;
    init_waitqueue_head(&rq_enum->iter_wq);
    rq_enum->iter_running   = 0;
    rq_enum->prod_idx       = 0;
    rq_enum->cons_idx       = 0;
    rq_enum->buf_count      = 0;
    rq_enum->buf_head       = node_buf_alloc(rq_enum);
    INIT_LIST_HEAD(&rq_enum->buf_head->list);
    rq_enum->prod_buf       = rq_enum->buf_head;
    debug("0: Creating new node buffer: %p\n", rq_enum->prod_buf);
    rq_enum->cons_buf       = rq_enum->buf_head;
    rq_enum->cur_key        = NULL;
    rq_enum->last_key       = NULL;
    rq_enum->start_key      = start_key;
    rq_enum->end_key        = end_key;
    rq_enum->in_range       = 0;

    iter = &rq_enum->iterator;
    iter->tree       = rq_enum->tree;
    iter->need_visit = NULL;
    iter->node_start = NULL;
    iter->each       = castle_rq_enum_iter_each;
    iter->node_end   = castle_rq_enum_iter_node_end;
    iter->end        = castle_rq_enum_iter_end;
    iter->private    = rq_enum;

    castle_btree_iter_init(iter, version, C_ITER_ANCESTRAL_VERSIONS);
    iter->next_key.key          = start_key;
    iter->next_key.need_destroy = 0;
    rq_debug("New Iterator - %p\n", iter);

    return;
    /* @TODO: do we need to handle out of memory condidions better than with BUG_ON? */
#if 0
no_mem:
    rq_enum->err = -ENOMEM;
    castle_btree_rq_enum_fini(rq_enum);
#endif
}

static void castle_btree_rq_enum_buffer_switch(c_rq_enum_t *rq_enum)
{
    /* Only switch the buffer if the old buffer actually had anything in it,
       this prevents problems when the iterator below hasn't returned anything
       in the range we are interested in (double buffer swap will start invalidating
       the memory area used by the key pointer returned by previous _next()) */
    /* @TODO: check if enumerator also suffers from the same problem */
    if(rq_enum->prod_idx > 0)
    {
        if (rq_enum->prod_buf->list.next == &rq_enum->prod_buf->list)
        {
            struct node_buf_t *new_buf;

            new_buf = node_buf_alloc(rq_enum);
            list_add(&new_buf->list, &rq_enum->prod_buf->list);
            debug("1: Creating new node buffer: %p\n", rq_enum->prod_buf);
        }
        BUG_ON(rq_enum->prod_buf->list.next == &rq_enum->prod_buf->list);
        rq_enum->prod_buf = list_entry(rq_enum->prod_buf->list.next,
                                       struct node_buf_t, list);
        debug("1: Moving prod_buf to next node_buf: %p\n", rq_enum->prod_buf);
    } else
    {
        BUG_ON(rq_enum->cons_idx != 0 && rq_enum->cons_buf == rq_enum->prod_buf);
    }
    rq_enum->cons_buf = rq_enum->prod_buf;
    rq_enum->cons_idx = 0;
    rq_enum->prod_idx = 0;

    castle_btree_node_buffer_init(rq_enum->tree,
                                  rq_enum->prod_buf->node,
                                  rq_enum->prod_buf->node->size);
}

int cons_idx_prod_idx_compare(c_rq_enum_t *rq_enum)
{
    if (rq_enum->cons_buf != rq_enum->prod_buf ||
        rq_enum->cons_idx < rq_enum->prod_idx)
        return 1;

    /* If we are consuming and producing in different buffers, we should not get here */
    BUG_ON(rq_enum->cons_buf != rq_enum->prod_buf);
    /* In same buffer, consumer buffer must not overtake the producer index */
    BUG_ON(rq_enum->cons_idx > rq_enum->prod_idx);

    return 0;
}

static void castle_btree_rq_enum_register_cb(c_rq_enum_t *iter,
                                             castle_iterator_end_io_t cb,
                                             void *data)
{
    iter->end_io  = cb;
    iter->private = data;
}

/* Returns 1 - if ready to call has_next(); 0 - if waiting for some IO operation
 * to finish */
static int _castle_btree_rq_enum_prep_next(c_rq_enum_t *rq_enum, int sync_call)
{
    struct castle_iterator *iter = &rq_enum->iterator;
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_enum->prod_buf->node->type);
    void *key;

    while (1)
    {
        /* Wait for the iterator to complete */
        if (sync_call)
            wait_event(rq_enum->iter_wq, (rq_enum->iter_running == 0));

        /* Check if castle iterator is running */
        BUG_ON(rq_enum->iter_running);
        cons_idx_prod_idx_compare(rq_enum);
        BUG_ON(rq_enum->end_io == NULL);
        BUG_ON(rq_enum->iter_completed && cons_idx_prod_idx_compare(rq_enum));

        rq_debug("Checking for %p\n", rq_enum);
        /* Return if iterator is already completed */
        if (rq_enum->iter_completed)
            return 1;

        /* Check if the first entry in buffer is smaller than end key. */
        if (cons_idx_prod_idx_compare(rq_enum))
        {
            btree->entry_get(rq_enum->cons_buf->node, rq_enum->cons_idx, &key, NULL,
                             NULL);
            if (btree->key_compare(rq_enum->end_key, key) < 0)
            {
                rq_enum->cons_buf = rq_enum->prod_buf;
                rq_enum->cons_idx = rq_enum->prod_idx = 0;
                castle_btree_iter_cancel(iter, 0);
                rq_enum->iter_running = 1;
                rq_enum->sync_call = sync_call;
                wmb();
                castle_btree_iter_start(iter);

                if (rq_enum->sync_call)
                    wait_event(rq_enum->iter_wq, (rq_enum->iter_running == 0));
                else
                    return 0;
            }
            return 1;
        }

        /* Schedule iterator to get few more entries into buffer */
        castle_btree_rq_enum_buffer_switch(rq_enum);
        rq_enum->iter_running   = 1;
        rq_enum->sync_call = sync_call;
        wmb();
        castle_btree_iter_start(iter);
        rq_debug("%p - schedule\n", rq_enum);
        if (!sync_call) return 0;
    }
}

static int castle_btree_rq_enum_prep_next(c_rq_enum_t *rq_enum)
{
    rq_debug("%p\n", rq_enum);
    return _castle_btree_rq_enum_prep_next(rq_enum, 0);
}

int castle_btree_rq_enum_has_next(c_rq_enum_t *rq_enum)
{
    BUG_ON(!_castle_btree_rq_enum_prep_next(rq_enum, 1));
    BUG_ON(rq_enum->iter_running);

    /* Return 1, if buffer has entries. */
    if (cons_idx_prod_idx_compare(rq_enum))
        return 1;

    BUG_ON(!rq_enum->iter_completed);

    return 0;
}

void castle_btree_rq_enum_next(c_rq_enum_t *rq_enum,
                               void       **key_p,
                               version_t   *version_p,
                               c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_enum->tree->btree_type);

    rq_debug("%p\n", rq_enum);
    BUG_ON(rq_enum->iter_running);
    /* Make sure that consumer index is less than the producer (there is an assert in
       the comparator). */
    cons_idx_prod_idx_compare(rq_enum);
    btree->entry_get(rq_enum->cons_buf->node, rq_enum->cons_idx, key_p, version_p,
                     cvt_p);
    rq_enum->last_key = *key_p;
    rq_enum->cons_idx++;
    if (rq_enum->cons_buf != rq_enum->prod_buf &&
        rq_enum->cons_idx == rq_enum->cons_buf->node->used)
    {
        rq_enum->cons_buf = list_entry(rq_enum->cons_buf->list.next,
                                       struct node_buf_t, list);
        rq_enum->cons_idx = 0;
    }
}

void castle_btree_rq_enum_skip(c_rq_enum_t *rq_enum,
                               void        *key)
{
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_enum->tree->btree_type);
    int i;

    rq_debug("%p\n", rq_enum);
    BUG_ON(rq_enum->iter_running);
    cons_idx_prod_idx_compare(rq_enum);

    /* Should never try to skip to the key before last key returned. */
    if (rq_enum->last_key && (btree->key_compare(key, rq_enum->last_key) <= 0))
    {
        castle_printk("Trying to skip to a key[%p] smaller than last_key [%p], iter - %p\n", key,
                rq_enum->last_key, rq_enum);
        BUG();
    }

    /* Go through all buffers and skip keys smaller than the key to be skipped to. */
    while(1)
    {
        int last_idx;

        last_idx = (rq_enum->cons_buf == rq_enum->prod_buf)
                    ? rq_enum->prod_idx
                    : (rq_enum->cons_buf->node->used);
        /* Check if the seeking key is in buffer, if so skip to it and return */
        for (i=rq_enum->cons_idx; i < last_idx; i++)
        {
            void *buf_key;

            btree->entry_get(rq_enum->cons_buf->node, i, &buf_key, NULL, NULL);
            if (btree->key_compare(buf_key, key) >= 0)
            {
                rq_enum->cons_idx = i;
                return;
            }
        }
        if (rq_enum->cons_buf == rq_enum->prod_buf)
            break;

        /* Move consumer to next buffer. */
        rq_enum->cons_buf = list_entry(rq_enum->cons_buf->list.next,
                                       struct node_buf_t, list);
        rq_enum->cons_idx = 0;
    }

    /* Key that iterator is skipping to must be bigger than last key of the node
     * (which is stored in rq_enum->cur_key). */
    BUG_ON(btree->key_compare(rq_enum->cur_key, key) >= 0);

    castle_btree_rq_enum_buffer_switch(rq_enum);
    castle_btree_iter_version_key_dealloc(&rq_enum->iterator);
    rq_enum->iterator.next_key.key = key;
    rq_enum->iterator.next_key.need_destroy = 0;
    /* Reset range to handle next key in the middle of a node */
    rq_enum->in_range = 0;
    rq_enum->start_key = key;
}

void castle_btree_rq_enum_cancel(c_rq_enum_t *rq_enum)
{
    /* Wait for the iterator to complete */
    wait_event(rq_enum->iter_wq, (rq_enum->iter_running == 0));

    if (!rq_enum->iter_completed)
    {
        struct castle_iterator *iter = &rq_enum->iterator;

        castle_btree_iter_cancel(iter, 0);
        rq_enum->iter_running = 1;
        rq_enum->sync_call = 1;
        wmb();
        castle_btree_iter_start(iter);
        wait_event(rq_enum->iter_wq,
                   (rq_enum->iter_running == 0));
    }

    castle_btree_rq_enum_fini(rq_enum);
}

struct castle_iterator_type castle_btree_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_btree_rq_enum_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_btree_rq_enum_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_btree_rq_enum_has_next,
    .next       = (castle_iterator_next_t)       castle_btree_rq_enum_next,
    .skip       = (castle_iterator_skip_t)       castle_btree_rq_enum_skip,
    .cancel     = (castle_iterator_cancel_t)     castle_btree_rq_enum_cancel,
};
