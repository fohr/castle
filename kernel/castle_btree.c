#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_objects.h"
#include "castle_utils.h"
#include "castle_freespace.h"
#include "castle_versions.h"
#include "castle_block.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define iter_debug(_f, ...)     ((void)0)
#define enum_debug(_f, ...)     ((void)0)
#else
#define debug(_f, _a...)        (printk("%s:%.60s:%.4d: " _f, __FILE__, __func__, __LINE__ , ##_a))
#define iter_debug(_f, _a...)   (printk("Iterator  :%.60s:%.4d:  " _f, __func__, __LINE__ , ##_a))
#define enum_debug(_f, _a...)   (printk("Enumerator:%.60s:%.4d:  " _f, __func__, __LINE__ , ##_a))
#endif

static DECLARE_WAIT_QUEUE_HEAD(castle_btree_iters_wq); 
static atomic_t castle_btree_iters_cnt = ATOMIC_INIT(0);

struct castle_btree_node_save {
    struct castle_component_tree   *ct;
    c_disk_blk_t                    cdb;
    struct work_struct              work;
} PACKED;


/**********************************************************************************************/
/* Block mapper btree (mtree) definitions */

#define ENTRY_DATA_TYPE_MASK     0x38

#define MTREE_ENTRY_LEAF_VAL    0x01
#define MTREE_ENTRY_LEAF_PTR    0x02
#define MTREE_ENTRY_NODE        0x04
#define MTREE_ENTRY_TOMB_STONE  0x08
#define MTREE_ENTRY_INLINE      0x10
#define MTREE_ENTRY_ONDISK      0x20
#define MTREE_ENTRY_IS_NODE(_slot)        ((_slot)->type & MTREE_ENTRY_NODE)
#define MTREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type & MTREE_ENTRY_LEAF_VAL) 
#define MTREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type & MTREE_ENTRY_LEAF_PTR) 
#define MTREE_ENTRY_IS_ANY_LEAF(_slot)   (((_slot)->type & MTREE_ENTRY_LEAF_VAL) ||  \
                                          ((_slot)->type & MTREE_ENTRY_LEAF_PTR))

#define MTREE_ENTRY_DATA_TYPE(_slot)      ((_slot)->type & ENTRY_DATA_TYPE_MASK)
#define MTREE_ENTRY_IS_TOMB_STONE(_slot)  ((_slot)->type & MTREE_ENTRY_TOMB_STONE) 
#define MTREE_ENTRY_IS_INLINE(_slot)      ((_slot)->type & MTREE_ENTRY_INLINE) 
#define MTREE_ENTRY_IS_ONDISK(_slot)      ((_slot)->type & MTREE_ENTRY_ONDISK) 

#define MTREE_INVAL_BLK          ((block_t)-1)
#define MTREE_MAX_BLK            ((block_t)-2)
#define MTREE_BLK_INVAL(_blk)    ((_blk) == MTREE_INVAL_BLK)

struct castle_mtree_entry {
    uint8_t         type;
    block_t         block;
    version_t       version;
    uint32_t        val_len;
    c_disk_blk_t    cdb;
} PACKED;

#define MTREE_NODE_SIZE     (10) /* In blocks */
#define MTREE_NODE_ENTRIES  ((MTREE_NODE_SIZE * PAGE_SIZE - sizeof(struct castle_btree_node))/sizeof(struct castle_mtree_entry))

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
    
static void* castle_mtree_key_next(void *key)
{
    block_t blk = (block_t)(unsigned long)key;

    /* No successor to invalid block */
    if(MTREE_BLK_INVAL(blk))
        return (void *)(unsigned long)MTREE_INVAL_BLK;

    /* MTREE_INVAL_BLK is the successor of MTREE_MAX_BLK, conviniently */
    return (void *)(unsigned long)(blk+1);
}

static void castle_mtree_entry_get(struct castle_btree_node *node,
                                   int                       idx,
                                   void                    **key_p,            
                                   version_t                *version_p,
                                   int                      *is_leaf_ptr_p,
                                   c_val_tup_t              *cvt_p)
{
    struct castle_mtree_entry *entries = 
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)(unsigned long)entry->block;
    if(version_p)     *version_p     = entry->version;
    if(is_leaf_ptr_p) *is_leaf_ptr_p = MTREE_ENTRY_IS_LEAF_PTR(entry);
    if(cvt_p)
    {
        BUG_ON(!MTREE_ENTRY_IS_ONDISK(entry));
        CDB_TO_CVT(*cvt_p, entry->cdb, entry->val_len/C_BLK_SIZE);
    }
}

static void castle_mtree_entry_add(struct castle_btree_node *node,
                                   int                       idx,
                                   void                     *key,            
                                   version_t                 version,
                                   int                       is_leaf_ptr,
                                   c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries = 
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) > 
                                                MTREE_NODE_SIZE * C_BLK_SIZE); 
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    /* Make space for the new entry, noop if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? MTREE_ENTRY_LEAF_PTR : MTREE_ENTRY_LEAF_VAL) :
                        MTREE_ENTRY_NODE;
    BUG_ON(!CVT_ONDISK(cvt));
    entry->type    = entry->type | cvt.type;
    entry->cdb     = cvt.cdb;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}   

static void castle_mtree_entry_replace(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key,            
                                       version_t                 version,
                                       int                       is_leaf_ptr,
                                       c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries = 
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? MTREE_ENTRY_LEAF_PTR : MTREE_ENTRY_LEAF_VAL) :
                        MTREE_ENTRY_NODE;
    BUG_ON(!CVT_ONDISK(cvt));
    entry->type    = entry->type | cvt.type;
    entry->cdb     = cvt.cdb;
    entry->val_len = cvt.length;
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
        printk("Invalid mtree node used=%d and/or node version=%d\n",
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

    printk("Node: used=%d, version=%d, is_leaf=%d\n",
        node->used, node->version, node->is_leaf);
    for(i=0; i<node->used; i++)
        printk("[%d] (0x%x, 0x%x, %s) -> (0x%x, 0x%x)\n", 
            i,
            entries[i].block,
            entries[i].version,
            MTREE_ENTRY_IS_LEAF_PTR(entries + i) ? "leafptr" : "direct ",
            entries[i].cdb.disk,
            entries[i].cdb.block);
    printk("\n");
}


struct castle_btree_type castle_mtree = {
    .magic         = MTREE_TYPE,
    .node_size     = MTREE_NODE_SIZE,
    .min_key       = (void *)0,
    .max_key       = (void *)MTREE_MAX_BLK,
    .inv_key       = (void *)MTREE_INVAL_BLK,
    .need_split    = castle_mtree_need_split,
    .key_compare   = castle_mtree_key_compare,
    .key_next      = castle_mtree_key_next,
    .entry_get     = castle_mtree_entry_get,
    .entry_add     = castle_mtree_entry_add,
    .entry_replace = castle_mtree_entry_replace,
    .entries_drop  = castle_mtree_entries_drop,
    .node_print    = castle_mtree_node_print,
#ifdef CASTLE_DEBUG    
    .node_validate = castle_mtree_node_validate,
#endif
}; 

/**********************************************************************************************/
/* Fixed size byte array key btree (batree) definitions */

#define BATREE_ENTRY_LEAF_VAL   0x01
#define BATREE_ENTRY_LEAF_PTR   0x02
#define BATREE_ENTRY_NODE       0x04
#define BATREE_ENTRY_TOMB_STONE  0x08
#define BATREE_ENTRY_INLINE      0x10
#define BATREE_ENTRY_ONDISK      0x20
#define BATREE_ENTRY_IS_NODE(_slot)        ((_slot)->type & BATREE_ENTRY_NODE)
#define BATREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type & BATREE_ENTRY_LEAF_VAL) 
#define BATREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type & BATREE_ENTRY_LEAF_PTR) 
#define BATREE_ENTRY_IS_ANY_LEAF(_slot)   (((_slot)->type & BATREE_ENTRY_LEAF_VAL) ||  \
                                          ((_slot)->type & BATREE_ENTRY_LEAF_PTR))

#define BATREE_ENTRY_DATA_TYPE(_slot)      ((_slot)->type & ENTRY_DATA_TYPE_MASK)
#define BATREE_ENTRY_IS_TOMB_STONE(_slot)  ((_slot)->type & BATREE_ENTRY_TOMB_STONE) 
#define BATREE_ENTRY_IS_INLINE(_slot)      ((_slot)->type & BATREE_ENTRY_INLINE) 
#define BATREE_ENTRY_IS_ONDISK(_slot)      ((_slot)->type & BATREE_ENTRY_ONDISK) 

#define BATREE_KEY_SIZE         128      /* In bytes */
typedef struct bakey {
    uint8_t _key[BATREE_KEY_SIZE];
} PACKED bakey_t;

static const bakey_t BATREE_INVAL_KEY = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0xFF}};
static const bakey_t BATREE_MIN_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0x00}};
static const bakey_t BATREE_MAX_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-2)] = 0xFF,
                                                           [      (BATREE_KEY_SIZE-1)] = 0xFE}};
#define BATREE_KEY_INVAL(_key)          ((_key) == &BATREE_INVAL_KEY)

struct castle_batree_entry {
    uint8_t      type;
    bakey_t      key;
    version_t    version;
    uint32_t     val_len;
    c_disk_blk_t cdb;
} PACKED;

#define BATREE_NODE_SIZE     (20) /* In blocks */
#define BATREE_NODE_ENTRIES  ((BATREE_NODE_SIZE * PAGE_SIZE - sizeof(struct castle_btree_node))/sizeof(struct castle_batree_entry))

static void inline castle_batree_key_print(bakey_t *key)
{
    int i;

    for(i=0; i<BATREE_KEY_SIZE; i++)
        printk("%.2x", key->_key[i]);
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
    /* TODO: IMPORTANT THIS CREATES MEMORY LEAK, NEEDS TO BE FIXED */
    succ = kmalloc(sizeof(bakey_t), GFP_NOIO);
    /* TODO: Should this be handled properly? */
    BUG_ON(!succ);
    memcpy(succ, key, sizeof(bakey_t));
    for (i=sizeof(bakey_t)-1; i >= 0; i--)
        if((++succ->_key[i]) != 0)
            break;
    
    return succ;
}

static void castle_batree_entry_get(struct castle_btree_node *node,
                                    int                       idx,
                                    void                    **key_p,            
                                    version_t                *version_p,
                                    int                      *is_leaf_ptr_p,
                                    c_val_tup_t              *cvt_p)
{
    struct castle_batree_entry *entries = 
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(is_leaf_ptr_p) *is_leaf_ptr_p = BATREE_ENTRY_IS_LEAF_PTR(entry);
    if(cvt_p)
    {
        BUG_ON(!BATREE_ENTRY_IS_ONDISK(entry));
        CDB_TO_CVT(*cvt_p, entry->cdb, entry->val_len/C_BLK_SIZE);
    }
}

static void castle_batree_entry_add(struct castle_btree_node *node,
                                    int                       idx,
                                    void                     *key,            
                                    version_t                 version,
                                    int                       is_leaf_ptr,
                                    c_val_tup_t               cvt)
{
    struct castle_batree_entry *entries = 
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) > 
                                                BATREE_NODE_SIZE * C_BLK_SIZE); 
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    /* Make space for the new entry, noop if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? BATREE_ENTRY_LEAF_PTR : BATREE_ENTRY_LEAF_VAL) :
                        BATREE_ENTRY_NODE;
    BUG_ON(!CVT_ONDISK(cvt));
    entry->type    = entry->type | cvt.type;
    entry->cdb     = cvt.cdb;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}   

static void castle_batree_entry_replace(struct castle_btree_node *node,
                                        int                       idx,
                                        void                     *key,            
                                        version_t                 version,
                                        int                       is_leaf_ptr,
                                        c_val_tup_t                 cvt)
{
    struct castle_batree_entry *entries = 
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? BATREE_ENTRY_LEAF_PTR : BATREE_ENTRY_LEAF_VAL) :
                        BATREE_ENTRY_NODE;
    BUG_ON(!CVT_ONDISK(cvt));
    entry->type    = entry->type | cvt.type;
    entry->cdb     = cvt.cdb;
    entry->val_len = cvt.length;
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
        printk("Invalid batree node used=%d and/or node version=%d\n",
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

        printk("[%d] (", i); 
        for(j=0; j<BATREE_KEY_SIZE; j++)
            printk("%.2x", entry->key._key[j]);
        printk(", 0x%x) -> (0x%x, 0x%x)\n", 
            entries[i].version,
            entries[i].cdb.disk,
            entries[i].cdb.block);
    }
    printk("\n");
}


struct castle_btree_type castle_batree = {
    .magic         = BATREE_TYPE,
    .node_size     = BATREE_NODE_SIZE,
    .min_key       = (void *)&BATREE_MIN_KEY,
    .max_key       = (void *)&BATREE_MAX_KEY,
    .inv_key       = (void *)&BATREE_INVAL_KEY,
    .need_split    = castle_batree_need_split,
    .key_compare   = castle_batree_key_compare,
    .key_next      = castle_batree_key_next,
    .entry_get     = castle_batree_entry_get,
    .entry_add     = castle_batree_entry_add,
    .entry_replace = castle_batree_entry_replace,
    .entries_drop  = castle_batree_entries_drop,
    .node_print    = castle_batree_node_print,
#ifdef CASTLE_DEBUG    
    .node_validate = castle_batree_node_validate,
#endif
}; 


/**********************************************************************************************/
/* Variable length byte array key btree (vlbatree) definitions */

#define VLBA_TREE_ENTRY_LEAF_VAL     0x01
#define VLBA_TREE_ENTRY_LEAF_PTR     0x02
#define VLBA_TREE_ENTRY_NODE          0x04
#define VLBA_TREE_ENTRY_TOMB_STONE    0x08
#define VLBA_TREE_ENTRY_INLINE        0x10
#define VLBA_TREE_ENTRY_ONDISK        0x20
#define VLBA_TREE_ENTRY_IS_NODE(_slot)        ((_slot)->type & VLBA_TREE_ENTRY_NODE)
#define VLBA_TREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type & VLBA_TREE_ENTRY_LEAF_VAL) 
#define VLBA_TREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type & VLBA_TREE_ENTRY_LEAF_PTR) 
#define VLBA_TREE_ENTRY_IS_ANY_LEAF(_slot)   (((_slot)->type & VLBA_TREE_ENTRY_LEAF_VAL) ||  \
                                          ((_slot)->type & VLBA_TREE_ENTRY_LEAF_PTR))

#define VLBA_TREE_ENTRY_DATA_TYPE(_slot)      ((_slot)->type & ENTRY_DATA_TYPE_MASK)
#define VLBA_TREE_ENTRY_IS_TOMB_STONE(_slot)  ((_slot)->type & VLBA_TREE_ENTRY_TOMB_STONE) 
#define VLBA_TREE_ENTRY_IS_INLINE(_slot)      ((_slot)->type & VLBA_TREE_ENTRY_INLINE) 
#define VLBA_TREE_ENTRY_IS_ONDISK(_slot)      ((_slot)->type & VLBA_TREE_ENTRY_ONDISK) 

#define VLBA_TREE_MAX_KEY_SIZE         512      /* In bytes */
#define VLBA_TREE_NODE_ENTRIES      254

typedef struct vlba_key {
    uint32_t length;
    uint8_t _key[0];
} PACKED vlba_key_t;

static const vlba_key_t VLBA_TREE_INVAL_KEY = (vlba_key_t){.length = 0xFFFFFFFF};
static const vlba_key_t VLBA_TREE_MIN_KEY = (vlba_key_t){.length = 0x00};
static const vlba_key_t VLBA_TREE_MAX_KEY = (vlba_key_t){.length = 0xFFFFFFFE};

#define VLBA_TREE_KEY_INVAL(_key)          ((_key)->length == VLBA_TREE_INVAL_KEY.length) 
#define VLBA_TREE_KEY_MIN(_key)            ((_key)->length == VLBA_TREE_MIN_KEY.length) 
#define VLBA_TREE_KEY_MAX(_key)            ((_key)->length == VLBA_TREE_MAX_KEY.length) 

struct castle_vlba_tree_entry {
    uint8_t      type;
    version_t    version;
    uint32_t     val_len;
    c_disk_blk_t cdb;   
    vlba_key_t   key;
    /* Inline values are stored at the end of entry */
} PACKED;

struct castle_vlba_tree_node {
    uint32_t    dead_bytes;
    uint32_t    free_bytes;
    uint32_t    key_idx[0];
} PACKED;

#define VLBA_TREE_NODE_SIZE                 (2) 
#define VLBA_TREE_NODE_LENGTH               (VLBA_TREE_NODE_SIZE * C_BLK_SIZE)
#define EOF_VLBA_NODE(_node)                (((uint8_t *)_node) + VLBA_TREE_NODE_LENGTH)
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
    a = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
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
            vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH);

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

    kfree(a);
    kfree(idx);
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
                (VLBA_TREE_NODE_LENGTH - sizeof(struct castle_btree_node) - 
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

static void castle_vlba_tree_entry_get(struct castle_btree_node *node,
                                       int                       idx,
                                       void                    **key_p,            
                                       version_t                *version_p,
                                       int                      *is_leaf_ptr_p,
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
    if(is_leaf_ptr_p) *is_leaf_ptr_p = VLBA_TREE_ENTRY_IS_LEAF_PTR(entry);
    if(cvt_p)
    {
        cvt_p->type = VLBA_TREE_ENTRY_DATA_TYPE(entry);
        cvt_p->length = entry->val_len;
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        if (VLBA_TREE_ENTRY_IS_INLINE(entry))
        {
            BUG_ON(entry->val_len == 0 || entry->val_len > MAX_INLINE_VAL_SIZE);
#if 0
            cvt_p->val = kmalloc(entry->val_len, GFP_NOIO);
            memcpy(cvt_p->val, VLBA_ENTRY_VAL_PTR(entry), entry->val_len);
#endif
            cvt_p->val = VLBA_ENTRY_VAL_PTR(entry);
        }
        else 
            cvt_p->cdb = entry->cdb;
    }
}

static void castle_vlba_tree_entry_add(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key_v,            
                                       version_t                 version,
                                       int                       is_leaf_ptr,
                                       c_val_tup_t               cvt)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry; 
    vlba_key_t *key = (vlba_key_t *)key_v;
    uint32_t key_length = VLBA_KEY_LENGTH(key);
    /* entry header + key length + an entry in index table */
    uint32_t req_space = sizeof(struct castle_vlba_tree_entry) + key_length +
                         CVT_INLINE_VAL_LENGTH(cvt) + sizeof(uint32_t);

    BUG_ON(idx < 0 || idx > node->used);

    /* Initialization of node free space structures */
    if (node->used == 0) 
    {
        vlba_node->dead_bytes = 0;
        vlba_node->free_bytes = VLBA_TREE_NODE_LENGTH - sizeof(struct castle_btree_node) -
                                sizeof(struct castle_vlba_tree_node);
        BUG_ON( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
                vlba_node->free_bytes + vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH);
    }
        
    BUG_ON(key_length > VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(vlba_node->free_bytes + vlba_node->dead_bytes < req_space);
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    if(vlba_node->free_bytes < req_space) 
        castle_vlba_tree_node_compact(node);

    BUG_ON(vlba_node->free_bytes < req_space);

    vlba_node->free_bytes -= req_space;
    /* Free bytes count is already got updated. Adding free bytes count to the end of
     * index table gives us the pointer to new entry. */
    entry = (struct castle_vlba_tree_entry *)(((uint8_t *)&vlba_node->key_idx[node->used+1]) + 
                                              vlba_node->free_bytes);
    memmove(&vlba_node->key_idx[idx+1], &vlba_node->key_idx[idx],
            sizeof(uint32_t) * (node->used - idx));

    vlba_node->key_idx[idx] = EOF_VLBA_NODE(node) - ((uint8_t *)entry);
    memcpy(&entry->key, key, sizeof(vlba_key_t) + key_length);
    entry->version      = version;
    entry->type         = node->is_leaf ? 
                        (is_leaf_ptr ? VLBA_TREE_ENTRY_LEAF_PTR : VLBA_TREE_ENTRY_LEAF_VAL) :
                        VLBA_TREE_ENTRY_NODE;
    entry->type        |= cvt.type; 
    entry->val_len  = cvt.length;
    BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
    BUG_ON(!VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len == 0);
    if (VLBA_TREE_ENTRY_IS_INLINE(entry))
    {
        BUG_ON(entry->val_len == 0 || entry->val_len > MAX_INLINE_VAL_SIZE);
        memmove(VLBA_ENTRY_VAL_PTR(entry), cvt.val, cvt.length);
    }
    else 
        entry->cdb      = cvt.cdb;

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
                                           int                       is_leaf_ptr,
                                           c_val_tup_t               cvt)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry = 
        (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, idx);
    vlba_key_t *key = (vlba_key_t *)key_v;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && is_leaf_ptr);
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    if (VLBA_KEY_LENGTH(&entry->key) >= VLBA_KEY_LENGTH(key)) 
    {
        vlba_node->dead_bytes += VLBA_KEY_LENGTH(&entry->key) - VLBA_KEY_LENGTH(key);

        memcpy(&entry->key, key, sizeof(vlba_key_t) + VLBA_KEY_LENGTH(key));
        entry->version = version;
        entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? VLBA_TREE_ENTRY_LEAF_PTR : VLBA_TREE_ENTRY_LEAF_VAL) :
                        VLBA_TREE_ENTRY_NODE;
        entry->type        |= cvt.type; 
        entry->val_len  = cvt.length;
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        BUG_ON(!VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len == 0);
        if (VLBA_TREE_ENTRY_IS_INLINE(entry))
        {
            BUG_ON(entry->val_len == 0 || entry->val_len > MAX_INLINE_VAL_SIZE);
            memcpy(VLBA_ENTRY_VAL_PTR(entry), cvt.val, cvt.length);
        }
        else 
            entry->cdb      = cvt.cdb;
    } 
    else 
    {
        castle_vlba_tree_entries_drop(node, idx, idx);
        castle_vlba_tree_entry_add(node, idx, key, version, is_leaf_ptr, cvt);
    }
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

    /* TODO: node_validate called in interrupt context, cannot kmalloc GFP_NOIO here */
    if(0 == 0)
        return;
    a = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
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
            vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH) 
    {
        printk("sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +"
                "Index Table + Free Bytes + Sum of entries + Dead Bytes\n");
        printk("%u-%u-%u-%u-%u-%u\n", (uint32_t)sizeof(struct castle_btree_node)
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
            printk("Entry Overflow: Entry-%p; Length-%u; NodeEnd-%p\n",
                   entry, ent_len, EOF_VLBA_NODE(node));
            BUG();
        }
        if (entry_offset != a[count])
        {
            printk("Heap sort error\n");
            BUG();
        }
        if ((prev_offset != -1) && (prev_offset + ent_len > entry_offset))
        {
            printk("Entry overlap: offset:length -> %u:%u-%u:%u\n", prev_offset, prev_len,
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

            printk("Entry 1:\n");
            printk("[%d] (", i-1); 
            for(j=0; j<VLBA_KEY_LENGTH(&prev_entry->key); j++)
                printk("%.2x", prev_entry->key._key[j]);
            printk(", 0x%x) -> (0x%x, 0x%x)\n", 
                prev_entry->version,
                prev_entry->cdb.disk,
                prev_entry->cdb.block);

            printk("Entry 2:\n");
            printk("[%d] (", i); 
            for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
                printk("%.2x", entry->key._key[j]);
            printk(", 0x%x) -> (0x%x, 0x%x)\n", 
                entry->version,
                entry->cdb.disk,
                entry->cdb.block);
            BUG();
        }

        if (VLBA_TREE_ENTRY_IS_LEAF_PTR(entry) && !node->is_leaf) 
        {
            printk("Entry is leaf ptr but node is not a leaf\n");
            BUG();
        }
        
        BUG_ON(VLBA_TREE_ENTRY_IS_TOMB_STONE(entry) && entry->val_len != 0);
        BUG_ON(VLBA_TREE_ENTRY_IS_INLINE(entry) && entry->val_len == 0);
        BUG_ON(VLBA_INLINE_VAL_LENGTH(entry) > MAX_INLINE_VAL_SIZE);
    }

    kfree(a);
    kfree(idx);
}
#endif

static void castle_vlba_tree_node_print(struct castle_btree_node *node)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    int i, j;

    printk("node->used=%d, node=%p, vlba_node=%p, payload=%p\n", 
            node->used, 
            node, 
            vlba_node, 
            ((uint8_t*)vlba_node + sizeof(struct castle_vlba_tree_node)));
    for(i=0; i<node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(node, vlba_node, i);

        printk("[%d] key_idx[%d]=%d, key_length=%d, val_len=%d, entry_size=%ld (", 
                i, i, vlba_node->key_idx[i], VLBA_KEY_LENGTH(&entry->key),
                entry->val_len,
                VLBA_ENTRY_LENGTH(entry)); 
        for(j=0; j<VLBA_KEY_LENGTH(&entry->key); j++)
            printk("%.2x", entry->key._key[j]);
        printk(", 0x%x) -> (0x%x, 0x%x)\n", 
            entry->version,
            entry->cdb.disk,
            entry->cdb.block);
    }
    printk("\n");
}


struct castle_btree_type castle_vlba_tree = {
    .magic         = VLBA_TREE_TYPE,
    .node_size     = VLBA_TREE_NODE_SIZE,
    .min_key       = (void *)&VLBA_TREE_MIN_KEY,
    .max_key       = (void *)&VLBA_TREE_MAX_KEY, 
    .inv_key       = (void *)&VLBA_TREE_INVAL_KEY, 
    .need_split    = castle_vlba_tree_need_split,
    .key_compare   = castle_vlba_tree_key_compare,
    .key_next      = castle_vlba_tree_key_next,
    .entry_get     = castle_vlba_tree_entry_get,
    .entry_add     = castle_vlba_tree_entry_add,
    .entry_replace = castle_vlba_tree_entry_replace,
    .entries_drop  = castle_vlba_tree_entries_drop,
    .node_print    = castle_vlba_tree_node_print,
#ifdef CASTLE_DEBUG    
    .node_validate = castle_vlba_tree_node_validate,
#endif
}; 



/**********************************************************************************************/
/* Array of btree types */

static struct castle_btree_type *castle_btrees[1<<(8 * sizeof(btree_t))] = 
                                                       {[MTREE_TYPE]     = &castle_mtree,
                                                        [BATREE_TYPE]    = &castle_batree,
                                                        [VLBA_TREE_TYPE] = &castle_vlba_tree};


struct castle_btree_type *castle_btree_type_get(btree_t type)
{
#ifdef CASTLE_DEBUG
    BUG_ON((type != MTREE_TYPE) &&
           (type != BATREE_TYPE) &&
           (type != VLBA_TREE_TYPE));
#endif
    return castle_btrees[type];
}


/**********************************************************************************************/
/* Common modlist btree code */

static inline c_disk_blk_t castle_btree_root_get(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;
    c_disk_blk_t root_cdb;

    down_read(&att->lock);
    c_bvec->version = att->version;
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_btree_c2b_forget() */
    castle_version_lock(c_bvec->version);
    root_cdb = c_bvec->tree->root_node;
    up_read(&att->lock);

    return root_cdb;
}
  
static void castle_btree_c2b_forget(c_bvec_t *c_bvec);
static void __castle_btree_find(struct castle_btree_type *btree,
                                c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb,
                                void *parent_key);


static void castle_btree_io_end(c_bvec_t    *c_bvec,
                                c_val_tup_t    cvt,
                                int          err)
{
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
    /* Free the c2bs correctly. Call twice to release parent and child
       (if both exist) */
    castle_btree_c2b_forget(c_bvec);
    castle_btree_c2b_forget(c_bvec);
    /* Finish the IO */
    c_bvec->endfind(c_bvec, err, cvt);
}

static void USED castle_btree_node_print(struct castle_btree_type *t, struct castle_btree_node *node)
{
    printk("Printing node version=%d with used=%d, is_leaf=%d\n",
        node->version, node->used, node->is_leaf);

    t->node_print(node);
}

static void castle_btree_lub_find(struct castle_btree_node *node,
                                  void *key,
                                  version_t version,
                                  int *lub_idx_p,
                                  int *insert_idx_p)
{
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    version_t version_lub;
    void *key_lub;
    int lub_idx, insert_idx, low, high, mid;

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
        btree->entry_get(node, mid, &key_lub, NULL, NULL, NULL);
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
        oldest */
    for(lub_idx=high; lub_idx < node->used; lub_idx++)
    {
        btree->entry_get(node, lub_idx, &key_lub, &version_lub, NULL, NULL);

        debug(" (k,v) = (%p, 0x%x)\n", key_lub, version_lub); 

        /* First (k,v) that's an upper bound is guaranteed to be the correct lub,
           because versions are arranged from newest to oldest */ 
        if(btree->key_compare(key_lub, key) < 0)
            continue;
        if(castle_version_is_ancestor(version_lub, version))
            break;
    } 
    BUG_ON(lub_idx > node->used);
    /* insert_idx equals lub_idx because we are guaranteed to be inserting
       a newer entry (it should go to the left of lub) of a smaller or equal 
       key (which also should go to the left). 
       If there is no LUB, lub_idx will equal node->used, which also is the
       correct insertion point */
    insert_idx = lub_idx;
    if(lub_idx == node->used)
        lub_idx = -1;
    /* Return the indices */
    if(lub_idx_p) *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

static void castle_btree_node_save(struct work_struct *work)
{
    struct castle_btree_node_save *work_st = container_of(work, 
                                                       struct castle_btree_node_save, 
                                                       work);
    struct castle_component_tree *ct = work_st->ct;
    struct castle_btree_node *node;
    struct castle_btree_type *btree;
    c_disk_blk_t prev_cdb;
    c2_block_t *c2b;

    down(&ct->mutex);
    btree = castle_btree_type_get(ct->btree_type);

    if (unlikely(!atomic64_read(&ct->node_count))) 
    {
        BUG_ON(!DISK_BLK_INVAL(ct->first_node));
        ct->first_node = work_st->cdb;
    } 
    else
    {
        prev_cdb = ct->last_node;
        c2b = castle_cache_block_get(prev_cdb, btree->node_size);
        lock_c2b(c2b);
   
        /* If c2b is not up to date, issue a blocking READ to update */
        if(!c2b_uptodate(c2b))
            BUG_ON(submit_c2b_sync(READ, c2b));

        node = c2b_buffer(c2b);
        node->next_node = work_st->cdb;

        dirty_c2b(c2b);
        unlock_c2b(c2b);
        put_c2b(c2b);
    }
    ct->last_node = work_st->cdb;
    atomic64_inc(&ct->node_count);
    up(&ct->mutex);

    kfree(work_st);
}

c2_block_t* castle_btree_node_create(int version, int is_leaf, btree_t type,
                                     struct castle_component_tree *ct)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node;
    struct castle_btree_node_save *work_st; 
    c_disk_blk_t cdb;
    c2_block_t  *c2b;
    
    btree = castle_btree_type_get(type);
    cdb = castle_freespace_block_get(0, /* Used to denote nodes used by metadata */
                                     btree->node_size); 
    c2b = castle_cache_block_get(cdb, btree->node_size);
    
    lock_c2b(c2b);
    set_c2b_uptodate(c2b);

    node = c2b_buffer(c2b);
    /* memset the node, so that ftree nodes are easily recognisable in hexdump. */
    memset(node, 0x77, btree->node_size * C_BLK_SIZE);
    node->magic    = BTREE_NODE_MAGIC;
    node->type     = type;
    node->version  = version;
    node->used     = 0;
    node->is_leaf  = is_leaf;
    node->next_node = INVAL_DISK_BLK;

    dirty_c2b(c2b);

    /* Link the new node to last created node. But, schedule the task for later; as
     * locking the last node while holding lock for current node might lead to a
     * dead-lock */
    work_st = kmalloc(sizeof(struct castle_btree_node_save), GFP_NOIO);
    BUG_ON(!work_st);
    work_st->ct = ct;
    work_st->cdb = cdb;
    INIT_WORK(&work_st->work, castle_btree_node_save);
    queue_work(castle_wq, &work_st->work);

    return c2b;
}

static c2_block_t* castle_btree_effective_node_create(c_bvec_t *c_bvec, 
                                                      c2_block_t *orig_c2b,
                                                      version_t version)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node, *eff_node;
    c2_block_t *c2b;
    void *last_eff_key;
    version_t last_eff_version;
    int i, insert_idx;
    
    node = c2b_bnode(orig_c2b); 
    btree = castle_btree_type_get(node->type);
    c2b = castle_btree_node_create(version, node->is_leaf, node->type, c_bvec->tree);
    eff_node = c2b_buffer(c2b);

    last_eff_key = btree->inv_key;
    BUG_ON(eff_node->used != 0);
    insert_idx = 0;
    for(i=0; i<node->used; i++)
    {
        void        *entry_key;
        version_t    entry_version;
        int          entry_is_leaf_ptr;
        c_val_tup_t  entry_cvt;
 
        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_is_leaf_ptr, &entry_cvt);
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
        if(!node->is_leaf || entry_is_leaf_ptr)
        {
            /* If already a leaf pointer, or a non-leaf entry copy directly. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             entry_is_leaf_ptr,
                             entry_cvt);
        } else
        {
            c_val_tup_t cvt;
            CDB_TO_CVT(cvt, orig_c2b->cdb, orig_c2b->nr_pages);
            /* Otherwise construct a new leaf pointer. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             1,
                             cvt);
        }
        last_eff_key = entry_key;
        last_eff_version = entry_version;
        insert_idx++;
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL.
       Note that effective node is only identical to the original node if the
       entries match, AND also the version of the node itself also matches. 
     */ 
    if((node->version == version) && (eff_node->used == node->used))
    {
        /* TODO: should clean_c2b? */
        unlock_c2b(c2b);
        put_c2b(c2b);
        /* TODO: should also return the allocated disk block, but our allocator
                 is too simple to handle this ATM */
        return NULL;
    }

    return c2b;
}

static c2_block_t* castle_btree_node_key_split(c_bvec_t *c_bvec, c2_block_t *orig_c2b)
{
    c2_block_t *c2b;
    struct castle_btree_node *node, *sec_node;
    struct castle_btree_type *btree;
    int i;

    void        *entry_key;
    version_t    entry_version;
    int          entry_is_leaf_ptr;
    c_val_tup_t  entry_cvt;

    node     = c2b_bnode(orig_c2b);
    btree    = castle_btree_type_get(node->type);
    c2b      = castle_btree_node_create(node->version, node->is_leaf, 
                                        node->type, c_bvec->tree);
    sec_node = c2b_bnode(c2b);
    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    BUG_ON(sec_node->used != 0);
    for(i=0; i<node->used >> 1; i++)
    {
        /* Copy the entries */
        btree->entry_get(node,     i, &entry_key, &entry_version,
                         &entry_is_leaf_ptr, &entry_cvt);
        btree->entry_add(sec_node, i,  entry_key,  entry_version,
                         entry_is_leaf_ptr, entry_cvt);
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
                                     int          is_leaf_ptr,
                                     c_val_tup_t  cvt)
{
    struct castle_btree_node *node = c2b_buffer(c2b);
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void      *lub_key      = btree->inv_key;
    version_t  lub_version  = INVAL_VERSION;
    int        lub_is_leaf_ptr;

    BUG_ON(index > node->used);
   
    if (CVT_ONDISK(cvt)) 
        debug("Inserting (0x%x, 0x%x) under index=%d\n", cvt.cdb.disk,
              cvt.cdb.block, index);
    else 
        debug("Inserting a inline value under index=%d\n", index);

    if(index < node->used)
        btree->entry_get(node, index, &lub_key, &lub_version, &lub_is_leaf_ptr, NULL);

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
        BUG_ON(!lub_is_leaf_ptr && node->is_leaf);
        /* Replace the slot */
        btree->entry_replace(node, index, key, version, 0, cvt);
        dirty_c2b(c2b);
        return;
    }
    /* Insert the new entry */ 
    btree->entry_add(node, index, key, version, is_leaf_ptr, cvt);
    BUG_ON(node->used >= MAX_BTREE_ENTRIES);
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
    btree->entry_get(child, child->used-1, &key, NULL, NULL, NULL);

    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    CDB_TO_CVT(cvt, child_c2b->cdb, btree->node_size);
    castle_btree_slot_insert(parent_c2b, 
                             insert_idx, 
                             key,
                             version,
                             0,
                             cvt);
}

static void castle_btree_node_under_key_insert(c2_block_t *parent_c2b,
                                               c2_block_t *child_c2b,
                                               void *key,
                                               version_t version)
{
    struct castle_btree_node    *parent = c2b_buffer(parent_c2b);
    struct castle_btree_type    *btree = castle_btree_type_get(parent->type);
    int                          insert_idx;
    c_val_tup_t                  cvt;

    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), "
          "will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx); 
    CDB_TO_CVT(cvt, child_c2b->cdb, btree->node_size);
    castle_btree_slot_insert(parent_c2b, 
                             insert_idx, 
                             key,
                             version,
                             0,
                             cvt);
}

static void castle_btree_new_root_create(c_bvec_t *c_bvec, btree_t type)
{
    c2_block_t *c2b;
    struct castle_btree_node *node;
    
    debug("Creating a new root node, while handling write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Create the node */
    c2b = castle_btree_node_create(0, 0, type, c_bvec->tree);
    node = c2b_buffer(c2b);
    /* TODO: locking for root_node */
    c_bvec->tree->root_node = c2b->cdb;
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
    /* Release the version lock (c2b_forget will no longer do that, 
       because there will be a parent node). */
    castle_version_unlock(c_bvec->version);
    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
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

    /* Create the effective node */
    eff_c2b = castle_btree_effective_node_create(c_bvec, retain_c2b, version);
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
                                                eff_c2b ? eff_c2b : c_bvec->btree_node);
        split_node = c2b_buffer(split_c2b);
        BUG_ON(split_node->version != c_bvec->version);
        /* Work out whether to take the split node for the further btree walk.
           Since in the effective & split node there is at most one version
           for each key, and this version is ancestoral to what we are
           looking for, it's enough to check if the last entry in the 
           split node (that's the node that contains left hand side elements
           from the original effective node) is greater-or-equal to the block
           we are looking for */
        btree->entry_get(split_node, split_node->used-1, &max_split_key, NULL, NULL, NULL);
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
        unlock_c2b(c_bvec->btree_node);
        put_c2b(c_bvec->btree_node);
    }
    if(eff_c2b && (retain_c2b != eff_c2b))
    {
        debug("Unlocking the effective node.\n");
        unlock_c2b(eff_c2b);
        put_c2b(eff_c2b);
    }
    if(split_c2b && (retain_c2b != split_c2b))
    {
        debug("Unlocking the split node.\n");
        unlock_c2b(split_c2b);
        put_c2b(split_c2b);
    }

    /* Save the retained_c2b */
    c_bvec->btree_node = retain_c2b;

    return 0;
}

static void castle_btree_write_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    version_t                    lub_version, version = c_bvec->version;
    int                          lub_idx, lub_is_leaf_ptr, insert_idx, ret;
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
                        &lub_is_leaf_ptr, &lub_cvt);

    /* Deal with non-leaf nodes first */
    if(!node->is_leaf)
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        debug("Following write down the tree.\n");
        if (!CVT_BTREE_NODE(lub_cvt, btree)) 
        {
            printk("0x%x-%d-0x%x-0x%x\n", lub_cvt.type, lub_cvt.length,
                   lub_cvt.cdb.disk, lub_cvt.cdb.block);
            BUG();
        }
        __castle_btree_find(btree, c_bvec, lub_cvt.cdb, lub_key);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!node->is_leaf);

    /* Insert an entry if LUB doesn't match our (k,v) precisely. */
    if((lub_idx < 0) || 
       (btree->key_compare(lub_key, key) != 0) || 
       (lub_version != version))
    {
        c_bvec->cvt_get(c_bvec, INVAL_VAL_TUP, &new_cvt);

        atomic64_inc(&c_bvec->tree->item_count);
        /* TODO: should memset the page to zero (because we return zeros on reads)
                 this can be done here, or beter still in _main.c, in data_copy */
        debug("Need to insert (%p, 0x%x) into node (used: 0x%x, leaf=%d).\n",
                key, version, node->used, node->is_leaf);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        castle_btree_slot_insert(c_bvec->btree_node,
                                 insert_idx,
                                 key,
                                 version,
                                 0,
                                 new_cvt);
        castle_btree_io_end(c_bvec, new_cvt, 0);
        return;
    } 
    
    /* Final case: (k,v) found in the leaf node. */
    BUG_ON((btree->key_compare(lub_key, key) != 0) || 
           (lub_version != version));
    BUG_ON(lub_idx != insert_idx);

    /* If we are looking at the leaf pointer, follow it */
    if(lub_is_leaf_ptr)
    {
        BUG_ON(!CVT_ONDISK(lub_cvt));
        debug("Following a leaf pointer to (0x%x, 0x%x).\n", 
                lub_cvt.cdb.disk, lub_cvt.cdb.block);
        __castle_btree_find(btree, c_bvec, lub_cvt.cdb, btree->inv_key);
        return;
    }

    /* NOP for block devices */
    c_bvec->cvt_get(c_bvec, lub_cvt, &new_cvt);
    /* Temporary check - remove */
    {
        void *tmp_key;
        version_t tmp_version;

        btree->entry_get(node, lub_idx, &tmp_key, &tmp_version, NULL, NULL);
        BUG_ON((btree->key_compare(lub_key, tmp_key) != 0) || 
               (lub_version != tmp_version));
    }
    btree->entry_replace(node, lub_idx, lub_key, lub_version, 0,
                         new_cvt);
    debug("Key already exists, modifying in place.\n");
    castle_btree_io_end(c_bvec, new_cvt, 0);

}

static void castle_btree_read_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    version_t                    lub_version, version = c_bvec->version;
    int                          lub_idx, lub_is_leaf_ptr;
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

    btree->entry_get(node, lub_idx, &lub_key, &lub_version, &lub_is_leaf_ptr,
                     &lub_cvt);
    /* If we found the LUB, either complete the ftree walk (if we are looking 
       at a 'proper' leaf), or go to the next level (possibly following a leaf ptr) */
    if(node->is_leaf && !lub_is_leaf_ptr)
    {
        BUG_ON(CVT_INVALID(lub_cvt));
        if (CVT_ONDISK(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), cdb=(0x%x, 0x%x)\n", 
                    lub_key, lub_version, lub_cvt.cdb.disk, 
                    lub_cvt.cdb.block);
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
                loc_buf = kmalloc(lub_cvt.length, GFP_NOIO);
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
        if (CVT_ONDISK(lub_cvt))
            debug("Leaf ptr or not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                   lub_cvt.cdb.disk, lub_cvt.cdb.block);
        else if (CVT_INLINE(lub_cvt))
            debug("Leaf ptr or not a leaf. Read and search - inline value\n");
        else if (CVT_TOMB_STONE(lub_cvt))
            debug("Leaf ptr or not a leaf. Read and search - tomb stone\n");
        /* parent_key is not needed when reading (also, we might be looking at a leaf ptr)
           use INVAL key instead. */
        __castle_btree_find(btree, c_bvec, lub_cvt.cdb, btree->inv_key);
    }
}

void castle_btree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
        castle_btree_write_process(c_bvec);
    else
        castle_btree_read_process(c_bvec);
}


/* TODO move locking of c2bs here?. Possibly rename the function */
static int castle_btree_c2b_remember(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    int ret = 0;

    /* Forget the parent node buffer first */
    castle_btree_c2b_forget(c_bvec);

    /* Save the new node buffer */
    BUG_ON(!c2b_locked(c2b));
    c_bvec->btree_node = c2b;

    return ret; 
}

/* TODO check that the root node lock will be released correctly, even on 
   node splits! */
static void castle_btree_c2b_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    c2_block_t *c2b_to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    c2b_to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    /* Release the buffer if one exists */
    if(c2b_to_forget)
    {
        unlock_c2b(c2b_to_forget);
        put_c2b(c2b_to_forget);
    }
    /* Also, release the version lock.
       On reads release as soon as possible. On writes make sure that we've got
       btree_node c2b locked. */
    if(test_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags) && (!write || c_bvec->btree_node))
    {
        castle_version_unlock(c_bvec->version); 
        clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    }
    /* Promote node to the parent on writes */
    if(write) c_bvec->btree_parent_node = c_bvec->btree_node;
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_btree_find_io_end(c2_block_t *c2b, int uptodate)
{
#ifdef CASTLE_DEBUG    
    struct castle_btree_node *node;
    struct castle_btree_type *btree;
#endif    
    c_bvec_t *c_bvec = c2b->private;

    debug("Finished IO for: key %p, in version 0x%x\n", 
            c_bvec->key, c_bvec->version);
    
    /* Callback on error */
    if(!uptodate || castle_btree_c2b_remember(c_bvec, c2b))
    {
        castle_btree_io_end(c_bvec, INVAL_VAL_TUP, -EIO);
        return;
    }

#ifdef CASTLE_DEBUG    
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
    /* TODO: This function runs in interrupt context and node_validate might
     * block due to kmalloc() */
    btree->node_validate(node);
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
    set_c2b_uptodate(c2b);

    BUG_ON(c_bvec->btree_depth > MAX_BTREE_DEPTH);
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree. 
       A single queue cannot be used, because a request blocked on 
       lock_c2b() would block the entire queue (=> deadlock). */
    INIT_WORK(&c_bvec->work, castle_btree_process);
    queue_work(castle_wqs[c_bvec->btree_depth], &c_bvec->work); 
}

static void __castle_btree_find(struct castle_btree_type *btree,
                                c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb,
                                void *parent_key)
{
    c2_block_t *c2b;
    int ret;
    
    debug("Asked for key: %p, in version 0x%x, reading ftree node (0x%x, 0x%x)\n", 
            c_bvec->key, c_bvec->version, node_cdb.disk, node_cdb.block);
    ret = -ENOMEM;

    c_bvec->btree_depth++;
    c_bvec->parent_key = parent_key;
    castle_debug_bvec_btree_walk(c_bvec);

    c2b = castle_cache_block_get(node_cdb, btree->node_size);
#ifdef CASTLE_DEBUG
    c_bvec->locking = c2b;
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_GOT_NODE);
    lock_c2b(c2b);
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_LOCKED_NODE);

    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_OUTOFDATE);
        c2b->private = c_bvec;
        c2b->end_io = castle_btree_find_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    } else
    {
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2b_remember should not return an error, because
           the Btree node had been normalized already. */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
        BUG_ON(castle_btree_c2b_remember(c_bvec, c2b) != 0);
        castle_btree_process(&c_bvec->work);
    }
}

static void _castle_btree_find(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_btree_type *btree = castle_btree_type_get(c_bvec->tree->btree_type);
    c_disk_blk_t root_cdb;

    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    /* This will lock the version. */
    root_cdb = castle_btree_root_get(c_bvec);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        c_bvec->endfind(c_bvec, -EINVAL, INVAL_VAL_TUP);
        return;
    }
    set_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_btree_find(btree, c_bvec, root_cdb, btree->max_key);
}

void castle_btree_find(c_bvec_t *c_bvec)
{
    INIT_WORK(&c_bvec->work, _castle_btree_find);
    queue_work(castle_wqs[19], &c_bvec->work); 
}


/**********************************************************************************************/
/* Btree iterator */

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
 
    castle_btree_iter_path_put(c_iter, 0);

    /* TODO: this will not work well for double frees/double ends, fix that */
    if(c_iter->indirect_nodes)
    {
        kfree(c_iter->indirect_nodes);
        c_iter->indirect_nodes = NULL;
    }
    
    if (c_iter->end) 
        c_iter->end(c_iter, err);
    
    atomic_dec(&castle_btree_iters_cnt);
    wake_up(&castle_btree_iters_wq);
}

#define indirect_node(_i)      (c_iter->indirect_nodes[(_i)]) 
#define cdb_lt(_cdb1, _cdb2) ( ((_cdb1).disk  < (_cdb2).disk ) ||            \
                              (((_cdb1).disk == (_cdb2).disk ) &&            \
                               ((_cdb1).block < (_cdb2).block)) )           
#define c2b_follow_ptr(_i)     indirect_node(indirect_node(_i).r_idx).c2b

#define slot_follow_ptr(_i, _real_c2b, _real_slot_idx)                       \
({                                                                           \
    struct castle_btree_node *_n;                                            \
    struct castle_btree_type *_t;                                            \
    int _is_leaf_ptr;                                                        \
                                                                             \
    (_real_c2b)      = c_iter->path[c_iter->depth];                          \
    _n               = c2b_bnode(_real_c2b);                                 \
    _t               = castle_btree_type_get(_n->type);                      \
    (_real_slot_idx) = (_i);                                                 \
    _t->entry_get(_n, _i, NULL, NULL, &_is_leaf_ptr, NULL);                  \
    if(_is_leaf_ptr)                                                         \
    {                                                                        \
        (_real_c2b)  = c2b_follow_ptr(_i);                                   \
        (_real_slot_idx) = indirect_node(_i).node_idx;                       \
    }                                                                        \
 })

void castle_btree_iter_replace(c_iter_t *c_iter, int index, c_val_tup_t cvt)
{
    struct castle_btree_node *real_node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *real_c2b;
    int real_entry_idx, prev_is_leaf_ptr;
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
                    &prev_is_leaf_ptr, 
                    &prev_cvt);
    /* We should be looking at a concreate entry, not a leaf pointer now */
    BUG_ON(prev_is_leaf_ptr);
    
    if (CVT_ONDISK(prev_cvt) && CVT_ONDISK(cvt))
    iter_debug("Current=(0x%x, 0x%x), new=(0x%x, 0x%x), "
               "in btree node: (0x%x, 0x%x), index=%d\n", 
                prev_cvt.cdb.disk,
                prev_cvt.cdb.block,
                cvt.cdb.disk, 
                cvt.cdb.block, 
                real_c2b->cdb.disk, 
                real_c2b->cdb.block, 
                real_entry_idx);
    
    btree->entry_replace(real_node,
                         real_entry_idx,
                         prev_key,
                         prev_version,
                         0,
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
    
    if(c_iter->type == C_ITER_MATCHING_VERSIONS || 
        c_iter->type == C_ITER_ANCESTRAL_VERSIONS)
    { 
        /* Unlock all the indirect nodes. */
        for(i=node->used - 1; i>=0; i--)
        {
            iter_debug("===> Trying to unlock indirect node i=%d\n", i);
            if(indirect_node(i).c2b)
            {
                unlock_c2b(indirect_node(i).c2b);
                put_c2b(indirect_node(i).c2b);
                indirect_node(i).c2b = NULL;
            }
        }
        iter_debug("Unlocking cdb=(0x%x, 0x%x)\n", 
            leaf->cdb.disk, leaf->cdb.block);
    }
    iter_debug("%p unlocks leaf (0x%x, 0x%x)\n",
        c_iter, leaf->cdb.disk, leaf->cdb.block);
    unlock_c2b(leaf);
}

void castle_btree_iter_continue(c_iter_t *c_iter)
{
    __castle_btree_iter_release(c_iter);
    castle_btree_iter_start(c_iter);
}

static void castle_btree_iter_leaf_ptrs_sort(c_iter_t *c_iter, int nr_ptrs)
{
    int i, root, child, start, end, last_r_idx;
    c_disk_blk_t last_cdb;

    /* We use heapsort, using Wikipedia's pseudo-code as the reference */
#define heap_swap(_i, _j)                                                 \
           {c_disk_blk_t tmp_cdb;                                         \
            uint8_t      tmp_f_idx;                                       \
            tmp_cdb   = indirect_node(_i).cdb;                            \
            tmp_f_idx = indirect_node(_i).f_idx;                          \
            indirect_node(_i).cdb   = indirect_node(_j).cdb;              \
            indirect_node(_i).f_idx = indirect_node(_j).f_idx;            \
            indirect_node(_j).cdb   = tmp_cdb;                            \
            indirect_node(_j).f_idx = tmp_f_idx;}
    
#define sift_down(_start, _end)                                           \
   {root = (_start);                                                      \
    while((2*root + 1) <= (_end))                                         \
    {                                                                     \
        child = 2 * root + 1;                                             \
        if((child < (_end)) &&                                            \
            cdb_lt(indirect_node(child).cdb, indirect_node(child+1).cdb)) \
                child = child+1;                                          \
        if(cdb_lt(indirect_node(root).cdb, indirect_node(child).cdb))     \
        {                                                                 \
            heap_swap(root, child);                                       \
            root = child;                                                 \
        } else                                                            \
        {                                                                 \
            break;                                                        \
        }                                                                 \
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

    /* Create the reverse map. Also, remove duplicate cdbs from the array */
    last_cdb   = INVAL_DISK_BLK;
    last_r_idx = -1;
    for(i=0; i < nr_ptrs; i++)
    {
        if(DISK_BLK_EQUAL(indirect_node(i).cdb, last_cdb))
        {
            BUG_ON(last_r_idx < 0);
            indirect_node(indirect_node(i).f_idx).r_idx = last_r_idx;
            indirect_node(i).cdb = INVAL_DISK_BLK;
        } else
        {
            indirect_node(indirect_node(i).f_idx).r_idx = i;
            last_cdb   = indirect_node(i).cdb;
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

    node = c2b_bnode(c_iter->path[c_iter->depth]);
    /* Make sure that node->used is smaller than what we can index in 1 byte f/r_idx */
    BUG_ON(node->used >= 1<<(8*sizeof(uint16_t)));
    
    /* Find all leaf pointers */
    j=0;
    for(i=0; i<node->used; i++)
    {
        version_t entry_version;
        c_val_tup_t entry_cvt;
        int entry_is_leaf_ptr; 

        btree->entry_get(node, i, NULL, &entry_version, &entry_is_leaf_ptr,
                         &entry_cvt);
        if((c_iter->type == C_ITER_MATCHING_VERSIONS && 
            entry_version != c_iter->version) || 
           (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
            !castle_version_is_ancestor(entry_version, c_iter->version)))
            continue;
        if(entry_is_leaf_ptr)
        {
            BUG_ON(indirect_node(j).c2b);
            indirect_node(j).cdb   = entry_cvt.cdb;
            indirect_node(j).f_idx = i;
            j++;
        }
    }
    nr_ptrs = j;

    /* Sort the pointers on cdb ordering */
    castle_btree_iter_leaf_ptrs_sort(c_iter, nr_ptrs);

    /* Now that leafs have been sorted, lock them all */
    for(i=0; i<nr_ptrs; i++)
    {
        c_disk_blk_t cdb = indirect_node(i).cdb;
        /* Skip over the invalid (previously duplicated) blocks */
        if(DISK_BLK_INVAL(cdb))
        {
            indirect_node(i).c2b = NULL; 
            continue;
        }
        c2b = castle_cache_block_get(cdb, btree->node_size);
        lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
            submit_c2b_sync(READ, c2b);
        indirect_node(i).c2b = c2b; 
    }
    /* Finally, find out where in the indirect block the individual ptrs are */
    for(i=0; i<node->used; i++)
    {
        version_t entry_version;
        int entry_is_leaf_ptr; 
        void *entry_key;

        /* Set the idx to inval to catch bugs early */
        indirect_node(i).node_idx = -1;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_is_leaf_ptr, NULL);
        if((c_iter->type == C_ITER_MATCHING_VERSIONS && 
            entry_version != c_iter->version) || 
           (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
            !castle_version_is_ancestor(entry_version, c_iter->version)))
            continue;
        if(entry_is_leaf_ptr)
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
            btree->entry_get(c2b_bnode(c2b),
                             lub_idx,
                            &real_entry_key,
                            &real_entry_version,
                             NULL,
                             NULL);
            BUG_ON((btree->key_compare(entry_key, real_entry_key) != 0) ||
                   (entry_version != real_entry_version));
            indirect_node(i).node_idx = lub_idx;
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
            printk("ERROR: non -1 node_idx (%d) in idx_increment. "
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
    c_iter->next_key = (btree->key_compare(c_iter->parent_key, btree->inv_key) == 0) ? 
                            btree->inv_key :
                            btree->key_next(c_iter->parent_key); 

    if (c_iter->node_start != NULL) 
        c_iter->node_start(c_iter);
    
    castle_btree_iter_leaf_ptrs_lock(c_iter);

    for(i=0; i<node->used; i++)
    {
        int         entry_is_leaf_ptr, real_slot_idx; 
        version_t   entry_version;
        c_val_tup_t entry_cvt;
        void       *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_is_leaf_ptr, &entry_cvt);

        if (CVT_ONDISK(entry_cvt))
            iter_debug("Current slot: (b=%p, v=%x)->(cdb=0x%x, 0x%x)\n",
                       entry_key, entry_version, entry_cvt.cdb.disk, 
                       entry_cvt.cdb.block);
        if (entry_version == c_iter->version || 
            (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
             castle_version_is_ancestor(entry_version, c_iter->version)))
        {
            c2_block_t *c2b;

            slot_follow_ptr(i, c2b, real_slot_idx);
            btree->entry_get(c2b_bnode(c2b), real_slot_idx, NULL, NULL, NULL,
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
        int         entry_is_leaf_ptr; 
        version_t   entry_version;
        c_val_tup_t entry_cvt; 
        void       *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version,
                         &entry_is_leaf_ptr, &entry_cvt);

        if (CVT_ONDISK(entry_cvt))
            iter_debug("All entries: current slot: (b=%p, v=%x)->(cdb=0x%x, 0x%x)\n",
                       entry_key, entry_version, entry_cvt.cdb.disk, 
                       entry_cvt.cdb.block);
        if (!entry_is_leaf_ptr)
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

static void   castle_btree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb);
static void __castle_btree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_disk_blk_t entry_cdb, node_cdb;
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
                c_iter->path[c_iter->depth]->cdb.disk,
                c_iter->path[c_iter->depth]->cdb.block);
        unlock_c2b(c_iter->path[c_iter->depth]);
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /* Otherwise, we know that the node got read successfully. Its buffer is in the path. */
    node = c2b_bnode(c_iter->path[c_iter->depth]);

    switch(c_iter->type)
    { 
        case C_ITER_ALL_ENTRIES:
            node_cdb = c_iter->path[c_iter->depth]->cdb;
            /* If we enumerating all entries in the tree, we use the index saved
               in node_idx table. */
            index = c_iter->node_idx[c_iter->depth];
            iter_debug("Processing node_cdb=(0x%x, 0x%x), index=%d, node->used=%d\n",
                    node_cdb.disk, node_cdb.block, index, node->used);
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
                   (c_iter->need_visit && !c_iter->need_visit(c_iter, node_cdb));

            if(skip)
            {
                iter_debug("Skipping.\n");
                castle_btree_iter_parent_node_idx_increment(c_iter);
                iter_debug("%p unlocking (0x%x, 0x%x)\n",
                        c_iter, 
                        node_cdb.disk,
                        node_cdb.block);
                unlock_c2b(c_iter->path[c_iter->depth]);
                castle_btree_iter_start(c_iter);
                return;
            }

            /* If we got here, it must be because we are visiting a node for the
               first time, and need_visit() was true */
            BUG_ON((index != -1) || skip);

            /* Deal with leafs first */
            if(node->is_leaf)
            {
                iter_debug("Visiting leaf node cdb=(0x%x, 0x%x).\n",
                        node_cdb.disk, node_cdb.block);
                castle_btree_iter_all_leaf_process(c_iter);
                castle_btree_iter_parent_node_idx_increment(c_iter);
                return;        
            }

            /* Final case: intermediate node visited for the first time */
            iter_debug("Visiting node cdb=(0x%x, 0x%x) for the first time.\n",
                       node_cdb.disk, node_cdb.block);
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
            castle_btree_lub_find(node, c_iter->next_key, c_iter->version, &index, NULL);
            iter_debug("Node index=%d\n", index);
            break;
    }
    btree->entry_get(node, index, &entry_key, NULL, NULL, &cvt);
    entry_cdb = cvt.cdb;
    if (!CVT_BTREE_NODE(cvt, btree))
    {
        printk("0x%x-%d-0x%x-0x%x\n", cvt.type, cvt.length,
                cvt.cdb.disk, cvt.cdb.block);
        BUG();
    }

    c_iter->depth++;
    c_iter->parent_key = entry_key;

    castle_btree_iter_path_traverse(c_iter, entry_cdb);
}

static void _castle_btree_iter_path_traverse(c2_block_t *c2b, int uptodate)
{
    c_iter_t *c_iter = c2b->private;

    iter_debug("Finished reading btree node.\n");
   
    if(!uptodate)
    {
        iter_debug("Error reading the btree node. Cancelling iterator.\n");
        iter_debug("%p unlocking cdb: (0x%x, 0x%x).\n", c_iter, c2b->cdb.disk, c2b->cdb.block);
        unlock_c2b(c2b);
        put_c2b(c2b);
        /* Save the error. This will be handled properly by __path_traverse */
        c_iter->err = -EIO;
    } else
    {
        /* Push the node onto the path 'stack' */
        set_c2b_uptodate(c2b);
        BUG_ON((c_iter->path[c_iter->depth] != NULL) && (c_iter->path[c_iter->depth] != c2b));
        c_iter->path[c_iter->depth] = c2b;
    }
    
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree. 
       A single queue cannot be used, because a request blocked on 
       lock_c2b() would block the entire queue (=> deadlock). 
       NOTE: The +1 is required to match the wqs we are using in normal btree walks. */
    INIT_WORK(&c_iter->work, __castle_btree_iter_path_traverse);
    queue_work(castle_wqs[c_iter->depth+MAX_BTREE_DEPTH], &c_iter->work);
}

static void castle_btree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *c2b = NULL;
    
    iter_debug("Starting the traversal: depth=%d, node_cdb=(0x%x, 0x%x)\n", 
                c_iter->depth, node_cdb.disk, node_cdb.block);
    
    /* Try to use the c2b we've saved in the path, if it matches node_cdb */
    if(c_iter->path[c_iter->depth] != NULL)
    {
        c2b = c_iter->path[c_iter->depth];
        
        if(!DISK_BLK_EQUAL(c2b->cdb, node_cdb))
        {
            castle_btree_iter_path_put(c_iter, c_iter->depth);
            c2b = NULL;
        }
    }
    
    /* If we haven't found node_cdb in path, get it from the cache instead */
    if(c2b == NULL)
        c2b = castle_cache_block_get(node_cdb, btree->node_size);
  
    iter_debug("%p locking cdb=(0x%x, 0x%x)\n", 
        c_iter, c2b->cdb.disk, c2b->cdb.block);
    
    lock_c2b(c2b);
    
    /* Unlock the ftree if we've just locked the root */
    if(c_iter->depth == 0)
    {
        /* We have just started the iteration - lets unlock the version tree */
        iter_debug("Unlocking version tree.\n");
        if(!VERSION_INVAL(c_iter->version))
            castle_version_unlock(c_iter->version);
    }
    /* Unlock previous c2b */
    if((c_iter->depth > 0) && (c_iter->path[c_iter->depth - 1] != NULL))
    {
        c2_block_t *prev_c2b = c_iter->path[c_iter->depth - 1];
        iter_debug("%p unlocking cdb=(0x%x, 0x%x)\n", 
            c_iter, prev_c2b->cdb.disk, prev_c2b->cdb.block);
        unlock_c2b(prev_c2b);
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
        _castle_btree_iter_path_traverse(c2b, 1);
    }
}

static void __castle_btree_iter_start(c_iter_t *c_iter)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_disk_blk_t root_cdb;

    iter_debug("-------------- STARTING THE ITERATOR -------------------\n");

    /* 
     * End conditions: we must be done if:
     *    - we start again at depth 0 - ie the root is a leaf
     *    - we followed max key to a leaf
     *    - we were cancelled
     */
    if ((c_iter->depth == 0) || 
       ((c_iter->type == C_ITER_MATCHING_VERSIONS) && 
            (btree->key_compare(c_iter->next_key, btree->inv_key) == 0)) ||
        (c_iter->cancelled))
    {
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /*
     * Let's start from the root again...
     */
    c_iter->depth = 0;
    
    iter_debug("Locking version tree for version: %d\n", c_iter->version);
    
    if(!VERSION_INVAL(c_iter->version))
        castle_version_lock(c_iter->version);
    root_cdb = c_iter->tree->root_node;
    if(DISK_BLK_INVAL(root_cdb))
    {
        iter_debug("Warning: Invalid disk block for the root.\n");
        if(!VERSION_INVAL(c_iter->version))
            castle_version_unlock(c_iter->version);
        /* Complete the request early, end exit */
        castle_btree_iter_end(c_iter, -EINVAL);
        return;
    }

    c_iter->parent_key = btree->inv_key;
    castle_btree_iter_path_traverse(c_iter, root_cdb);
}

static void _castle_btree_iter_start(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    
    __castle_btree_iter_start(c_iter);
}

void castle_btree_iter_start(c_iter_t* c_iter)
{
    INIT_WORK(&c_iter->work, _castle_btree_iter_start);
    queue_work(castle_wq, &c_iter->work);
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
    c_iter->next_key = btree->min_key;
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
            c_iter->indirect_nodes = kzalloc(MAX_BTREE_ENTRIES * sizeof(struct castle_indirect_node), GFP_KERNEL);
            /* If memory allocation failed, cancel the iterator, and set the error condition. 
               This will get picked up by _start() */
            if(!c_iter->indirect_nodes)
                castle_btree_iter_cancel(c_iter, -ENOMEM);
            return;
        default:
            BUG();
            return;
    }
}

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    /* We have a static array of btree types indexed by btree_t, don't let it grow too
       large. */
    BUG_ON(sizeof(btree_t) != 1);
    BUG_ON(MAX_BTREE_ENTRIES < MTREE_NODE_ENTRIES);
    BUG_ON(MAX_BTREE_ENTRIES < BATREE_NODE_ENTRIES);

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
static int castle_enum_iter_need_visit(c_iter_t *c_iter, c_disk_blk_t node_cdb)
{
    struct castle_enumerator *c_enum = c_iter->private;
    struct castle_visited *visited; 
    struct list_head *l;
    int i; 

    enum_debug("Iterator is asking if to visit (0x%x, 0x%x)\n", 
            node_cdb.disk, node_cdb.block);
    /* All hash operations need to be protected with the lock */
    spin_lock(&c_enum->visited_lock);
    /* Simplistic hash function */ 
    i = (node_cdb.disk + node_cdb.block) % VISITED_HASH_LENGTH;
    enum_debug("Hash bucket: %d\n", i);
    /* Check if the cdb is in the hash */
    list_for_each(l, &c_enum->visited_hash[i])
    {
        visited = list_entry(l, struct castle_visited, list);
        if(DISK_BLK_EQUAL(visited->cdb, node_cdb))
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
    visited->cdb = node_cdb;
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
    if (CVT_ONDISK(cvt))
        enum_debug("Entry for iterator idx=%d: idx=%d, key=%p, version=%d, cdb=(0x%x, 0x%x)\n", 
                    idx, index, key, version, cvt.cdb.disk, cvt.cdb.block);
    btree->entry_add(c_enum->buffer, c_enum->prod_idx, key, version, 0, cvt);
    c_enum->prod_idx++;
}

static void castle_enum_iter_node_end(c_iter_t *c_iter)
{
    struct castle_enumerator *c_enum = c_iter->private;

    BUG_ON(c_enum->cons_idx != 0);
    enum_debug("Ending node for iterator idx=%d, nr_entries=%d.\n", idx, c_enum->prod_idx);
    /* Special case, if nothing was read (it's possible if e.g. all entries are leaf ptrs)
       schedule the next node read, and exit early */
    if(c_enum->prod_idx == 0)
    {
        printk("There were no useful entries in the node. How is that possible?? Error?.\n");
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
        vfree(c_enum->buffer1);
    if(c_enum->buffer2)
        vfree(c_enum->buffer2);
    
    if(c_enum->visited_hash)
    {
        kfree(c_enum->visited_hash);
        c_enum->visited_hash = NULL;
    }
    if(c_enum->visited)
    {
        vfree(c_enum->visited);
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
    enum_debug("Cancelling the enumerator, currently live iters: %d\n", 
            atomic_read(&c_enum->live_iterators));
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
                                          struct castle_btree_node *buffer)
{
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
       Initialise the required bits of the node, so that the types don't complain. */
    buffer->magic   = BTREE_NODE_MAGIC;
    buffer->type    = tree->btree_type;
    buffer->version = 0;
    buffer->used    = 0;
    buffer->is_leaf = 1;
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
    btree->entry_get(c_enum->buffer, c_enum->cons_idx, key_p, version_p, NULL, cvt_p); 
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
        castle_btree_node_buffer_init(c_enum->tree, c_enum->buffer);
        /* Run the iterator again to get the next nodes worth of stuff */
        castle_btree_iter_start(&c_enum->iterator);
    }
}
       
void castle_btree_enum_init(c_enum_t *c_enum)
{
    struct castle_iterator *iter;
    struct castle_btree_type *btype;
    int i;

    btype = castle_btree_type_get(c_enum->tree->btree_type);
    /* We no longer need to support multiple iterators, this should simplify a lot of
       this code.
        TODO: go through it all and remove unneccessary code */
    c_enum->err            = 0;
    init_waitqueue_head(&c_enum->iterator_wq);
    c_enum->iterator_outs  = 0;
    /* Allocate memory for for buffers to store one node's worth of entries from the iterator */
    c_enum->buffer         = NULL;
    c_enum->buffer1        = NULL;
    c_enum->buffer2        = NULL;
    c_enum->visited_hash   = kmalloc(VISITED_HASH_LENGTH * sizeof(struct list_head),
                                     GFP_KERNEL);
    c_enum->max_visited    = 8 * VISITED_HASH_LENGTH;
    c_enum->visited        = vmalloc(c_enum->max_visited * sizeof(struct castle_visited));
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
    c_enum->buffer1 = vmalloc(btype->node_size * C_BLK_SIZE);
    c_enum->buffer2 = vmalloc(btype->node_size * C_BLK_SIZE);
    c_enum->buffer = c_enum->buffer1;
    if(!c_enum->buffer1 || !c_enum->buffer2)
        goto no_mem;
    castle_btree_node_buffer_init(c_enum->tree, c_enum->buffer);

    iter = &c_enum->iterator; 
    iter->tree       = c_enum->tree;
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
    .has_next = (castle_iterator_has_next_t)castle_btree_enum_has_next,
    .next     = (castle_iterator_next_t)    castle_btree_enum_next,
    .skip     = NULL, 
};

static void castle_rq_enum_iter_each(c_iter_t *c_iter, 
                                     int index, 
                                     void *key, 
                                     version_t version, 
                                     c_val_tup_t cvt)
{
    struct castle_btree_type *btree;
    c_rq_enum_t *rq_enum;

    rq_enum = (c_rq_enum_t *) c_iter->private;
    btree = castle_btree_type_get(rq_enum->buffer->type);
    BUG_ON(rq_enum->prod_idx != rq_enum->buffer->used);
    
    if (!rq_enum->in_range) 
    {
        if (btree->key_compare(rq_enum->start_key, key) <= 0)
            rq_enum->in_range = 1;
        else
            return;
    }
    
    if ((!rq_enum->cur_key || btree->key_compare(rq_enum->cur_key, key) != 0))
    {
        BUG_ON(rq_enum->cur_key && btree->key_compare(rq_enum->cur_key, key) > 0);
        btree->entry_add(rq_enum->buffer, rq_enum->prod_idx, key, version, 0, cvt);
        btree->entry_get(rq_enum->buffer, rq_enum->prod_idx, &rq_enum->cur_key, NULL, 
                         NULL, NULL);
        rq_enum->prod_idx++;
    } 
}

static void castle_rq_enum_iter_node_end(c_iter_t *c_iter)
{
    c_rq_enum_t *rq_enum = c_iter->private;

    __castle_btree_iter_release(c_iter);
    rq_enum->iter_running = 0;
    wmb();
    wake_up(&rq_enum->iter_wq);
}

static void castle_rq_enum_iter_end(c_iter_t *c_iter, int err)
{
    c_rq_enum_t *rq_enum = c_iter->private;

    if(err) rq_enum->err = err;
    rq_enum->iter_completed = 1;
    rq_enum->iter_running = 0;
    wmb();
    wake_up(&rq_enum->iter_wq);
}

static void castle_btree_rq_enum_fini(c_rq_enum_t *rq_enum)
{
    if (rq_enum->buffer1)
        vfree(rq_enum->buffer1);
    if (rq_enum->buffer2)
        vfree(rq_enum->buffer2);
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
    rq_enum->version        = version;
    rq_enum->iter_completed = 0;
    init_waitqueue_head(&rq_enum->iter_wq);
    rq_enum->iter_running   = 0;
    rq_enum->prod_idx       = 0;
    rq_enum->cons_idx       = 0;
    rq_enum->buffer1        = vmalloc(btype->node_size * C_BLK_SIZE);
    rq_enum->buffer2        = vmalloc(btype->node_size * C_BLK_SIZE);
    rq_enum->buffer         = rq_enum->buffer1;
    rq_enum->cur_key        = NULL;
    rq_enum->start_key      = start_key;
    rq_enum->end_key        = end_key;
    rq_enum->in_range       = 0;

    if(!rq_enum->buffer1 || !rq_enum->buffer2)
        goto no_mem;
    castle_btree_node_buffer_init(rq_enum->tree, rq_enum->buffer);

    iter = &rq_enum->iterator;
    iter->tree       = rq_enum->tree;
    iter->need_visit = NULL;
    iter->node_start = NULL;
    iter->each       = castle_rq_enum_iter_each;
    iter->node_end   = castle_rq_enum_iter_node_end;
    iter->end        = castle_rq_enum_iter_end;
    iter->private    = rq_enum;
    
    castle_btree_iter_init(iter, version, C_ITER_ANCESTRAL_VERSIONS);
    iter->next_key   = start_key;
    rq_enum->iter_running = 1;
    castle_btree_iter_start(iter);
    
    return;
no_mem:
    rq_enum->err = -ENOMEM;
    castle_btree_rq_enum_fini(rq_enum);
}

static void castle_btree_rq_enum_buffer_switch(c_rq_enum_t *rq_enum)
{
    /* Only switch the buffer if the old buffer actually had anything in it,
       this prevents problems when the iterator below hasn't returned anything 
       in the range we are interested in (double buffer swap will start invalidating
       the memory area used by the key pointer returned by previous _next()) */
    /* TODO: check if enumerator also suffers from the same problem */
    if(rq_enum->prod_idx > 0)
    {
        rq_enum->buffer  = (rq_enum->buffer == rq_enum->buffer1) ?
                            rq_enum->buffer2 : rq_enum->buffer1;
    } else
    {
        BUG_ON(rq_enum->cons_idx != 0);
    }
    rq_enum->cons_idx = 0;
    rq_enum->prod_idx = 0;

    castle_btree_node_buffer_init(rq_enum->tree, rq_enum->buffer);
}

int castle_btree_rq_enum_has_next(c_rq_enum_t *rq_enum)
{
    struct castle_iterator *iter = &rq_enum->iterator;
    struct castle_btree_type *btree = castle_btree_type_get(rq_enum->buffer->type);
    void *key;

__has_next_again:
  
    /* Wait for the iterator to complete */
    wait_event(rq_enum->iter_wq, ({int _ret; rmb(); _ret = (rq_enum->iter_running == 0); _ret;}));
    
    BUG_ON(rq_enum->cons_idx > rq_enum->prod_idx);
   
    if (rq_enum->cons_idx < rq_enum->prod_idx)
    {
        btree->entry_get(rq_enum->buffer, rq_enum->cons_idx, &key, NULL,
                             NULL, NULL);
        /* Move this check to rq_enum_each() */
        if (btree->key_compare(rq_enum->end_key, key) < 0)
        {
            /* The iterator has noting more of interest, reset the idxs to zero.
               This will make has_next() reentrant even for completed iterator. */
            rq_enum->cons_idx = rq_enum->prod_idx = 0;
            castle_btree_iter_cancel(iter, 0);
            rq_enum->iter_running = 1;
            castle_btree_iter_start(iter);
            return 0;
        }
        return 1;
    }

    /* TODO: iter_completed is set in end(). Make sure this wouldn't lead to a
     * race condition */
    if (rq_enum->iter_completed)
        return 0;

    castle_btree_rq_enum_buffer_switch(rq_enum);
    rq_enum->iter_running = 1;
    castle_btree_iter_start(iter);

goto __has_next_again;
}

void castle_btree_rq_enum_next(c_rq_enum_t *rq_enum, 
                               void       **key_p, 
                               version_t   *version_p,
                               c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_enum->tree->btree_type);

    wait_event(rq_enum->iter_wq, (rq_enum->iter_running == 0));

    BUG_ON(rq_enum->cons_idx >= rq_enum->prod_idx);
    btree->entry_get(rq_enum->buffer, rq_enum->cons_idx, key_p, version_p, NULL, 
                     cvt_p);
    rq_enum->cons_idx++;
}

void castle_btree_rq_enum_skip(c_rq_enum_t *rq_enum, 
                               void        *key) 
{
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_enum->tree->btree_type);
    int i;

    /* Wait for the iterator to complete */
    wait_event(rq_enum->iter_wq, (rq_enum->iter_running == 0));

    /* Check if the seeking key is in buffer, if so skip to it and return */
    for (i=rq_enum->cons_idx; i < rq_enum->prod_idx; i++)
    {
        void *buf_key;

        btree->entry_get(rq_enum->buffer, i, &buf_key, NULL, NULL, NULL);
        if (btree->key_compare(buf_key, key) >= 0)
        {
            rq_enum->cons_idx = i;
            return;
        }
    }

    castle_btree_rq_enum_buffer_switch(rq_enum);
    rq_enum->iterator.next_key = key;
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
        castle_btree_iter_start(iter);
        wait_event(rq_enum->iter_wq, 
                   (rq_enum->iter_running == 0));
    }

    castle_btree_rq_enum_fini(rq_enum);
}

struct castle_iterator_type castle_btree_rq_iter = {
    .has_next = (castle_iterator_has_next_t)castle_btree_rq_enum_has_next,
    .next     = (castle_iterator_next_t)    castle_btree_rq_enum_next,
    .skip     = (castle_iterator_skip_t)    castle_btree_rq_enum_skip, 
};
