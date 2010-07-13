#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
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


/**********************************************************************************************/
/* Block mapper btree (mtree) definitions */

#define MTREE_ENTRY_LEAF_VAL   0x1
#define MTREE_ENTRY_LEAF_PTR   0x2
#define MTREE_ENTRY_NODE       0x3
#define MTREE_ENTRY_IS_NODE(_slot)        ((_slot)->type == MTREE_ENTRY_NODE)
#define MTREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type == MTREE_ENTRY_LEAF_VAL) 
#define MTREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type == MTREE_ENTRY_LEAF_PTR) 
#define MTREE_ENTRY_IS_ANY_LEAF(_slot)   (((_slot)->type == MTREE_ENTRY_LEAF_VAL) ||  \
                                          ((_slot)->type == MTREE_ENTRY_LEAF_PTR))

#define MTREE_INVAL_BLK          ((block_t)-1)
#define MTREE_MAX_BLK            ((block_t)-2)
#define MTREE_BLK_INVAL(_blk)    ((_blk) == MTREE_INVAL_BLK)

struct castle_mtree_entry {
    uint8_t      type;
    block_t      block;
    version_t    version;
    c_disk_blk_t cdb;
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
                                   c_disk_blk_t             *cdb_p)
{
    struct castle_mtree_entry *entries = 
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)(unsigned long)entry->block;
    if(version_p)     *version_p     = entry->version;
    if(is_leaf_ptr_p) *is_leaf_ptr_p = MTREE_ENTRY_IS_LEAF_PTR(entry);
    if(cdb_p)         *cdb_p         = entry->cdb;
}

static void castle_mtree_entry_add(struct castle_btree_node *node,
                                   int                       idx,
                                   void                     *key,            
                                   version_t                 version,
                                   int                       is_leaf_ptr,
                                   c_disk_blk_t              cdb)
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
    entry->cdb     = cdb;

    /* Increment the node used count */
    node->used++;
}   

static void castle_mtree_entry_replace(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key,            
                                       version_t                 version,
                                       int                       is_leaf_ptr,
                                       c_disk_blk_t              cdb)
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
    entry->cdb     = cdb;
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

#define BATREE_ENTRY_LEAF_VAL   0x1
#define BATREE_ENTRY_LEAF_PTR   0x2
#define BATREE_ENTRY_NODE       0x3
#define BATREE_ENTRY_IS_NODE(_slot)        ((_slot)->type == BATREE_ENTRY_NODE)
#define BATREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type == BATREE_ENTRY_LEAF_VAL) 
#define BATREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type == BATREE_ENTRY_LEAF_PTR) 
#define BATREE_ENTRY_IS_ANY_LEAF(_slot)   (((_slot)->type == BATREE_ENTRY_LEAF_VAL) ||  \
                                           ((_slot)->type == BATREE_ENTRY_LEAF_PTR))

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
    for(i=0; i<sizeof(bakey_t); i++)
        if((++succ->_key[i]) != 0)
            break;
      
    return succ;
}

static void castle_batree_entry_get(struct castle_btree_node *node,
                                    int                       idx,
                                    void                    **key_p,            
                                    version_t                *version_p,
                                    int                      *is_leaf_ptr_p,
                                    c_disk_blk_t             *cdb_p)
{
    struct castle_batree_entry *entries = 
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(is_leaf_ptr_p) *is_leaf_ptr_p = BATREE_ENTRY_IS_LEAF_PTR(entry);
    if(cdb_p)         *cdb_p         = entry->cdb;
}

static void castle_batree_entry_add(struct castle_btree_node *node,
                                    int                       idx,
                                    void                     *key,            
                                    version_t                 version,
                                    int                       is_leaf_ptr,
                                    c_disk_blk_t              cdb)
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
    entry->cdb     = cdb;

    /* Increment the node used count */
    node->used++;
}   

static void castle_batree_entry_replace(struct castle_btree_node *node,
                                        int                       idx,
                                        void                     *key,            
                                        version_t                 version,
                                        int                       is_leaf_ptr,
                                        c_disk_blk_t              cdb)
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
    entry->cdb     = cdb;
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

#define VLBA_TREE_ENTRY_LEAF_VAL   0x1
#define VLBA_TREE_ENTRY_LEAF_PTR   0x2
#define VLBA_TREE_ENTRY_NODE       0x3
#define VLBA_TREE_ENTRY_IS_NODE(_slot)        ((_slot)->type == VLBA_TREE_ENTRY_NODE)
#define VLBA_TREE_ENTRY_IS_LEAF_VAL(_slot)    ((_slot)->type == VLBA_TREE_ENTRY_LEAF_VAL) 
#define VLBA_TREE_ENTRY_IS_LEAF_PTR(_slot)    ((_slot)->type == VLBA_TREE_ENTRY_LEAF_PTR) 
#define VLBA_TREE_ENTRY_IS_ANY_LEAF(_slot)    \
                      (((_slot)->type == VLBA_TREE_ENTRY_LEAF_VAL) ||  \
                      ((_slot)->type == VLBA_TREE_ENTRY_LEAF_PTR))

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
#define VLBA_TREE_KEY_MAX(_key)            ((_key)->length == VLBA_TREE_MAX_KEY.length) 

struct castle_vlba_tree_entry {
    uint8_t      type;
    version_t    version;
    c_disk_blk_t cdb;
    vlba_key_t   key;
} PACKED;

struct castle_vlba_tree_node {
    uint32_t    dead_bytes;
    uint32_t    free_bytes;
    uint32_t    key_idx[VLBA_TREE_NODE_ENTRIES];
    struct castle_vlba_tree_entry entries[0];
} PACKED;

#define VLBA_TREE_NODE_SIZE                 10
#define VLBA_TREE_NODE_LENGTH               (VLBA_TREE_NODE_SIZE * C_BLK_SIZE)
#define EOF_VLBA_NODE(_node)                (((uint8_t *)_node) + VLBA_TREE_NODE_LENGTH)
#define VLBA_NODE_FIRST_ENTRY(_vlba_node)   ((uint8_t *)&_vlba_node->entries[0])
#define VLBA_KEY_LENGTH(_key)               (VLBA_TREE_KEY_MAX(_key) ? 0 : (_key)->length)
#define VLBA_ENTRY_LENGTH(_entry)           \
                (sizeof(struct castle_vlba_tree_entry) + VLBA_KEY_LENGTH(&(_entry)->key))
#define MAX_VLBA_ENTRY_LENGTH               \
                (sizeof(struct castle_vlba_tree_entry) + VLBA_TREE_MAX_KEY_SIZE)
#define VLBA_ENTRY_PTR(_vlba_node, _i)      (VLBA_NODE_FIRST_ENTRY(_vlba_node) + \
                                                           _vlba_node->key_idx[_i])

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

    a = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    BUG_ON(!a || !idx);
    
    memcpy(a, &vlba_node->key_idx[0], (sizeof(uint32_t) * node->used));
    for (i=0, count=0; i < node->used; i++) 
    {
        struct castle_vlba_tree_entry *entry;

        idx[i] = i;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(vlba_node, i);
        count += VLBA_ENTRY_LENGTH(entry);
    }

    BUG_ON( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
                                           count + vlba_node->free_bytes +
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
        entry = (struct castle_vlba_tree_entry *)(VLBA_NODE_FIRST_ENTRY(vlba_node) +
                 entry_offset);
        ent_len = (uint32_t)VLBA_ENTRY_LENGTH(entry);
        
        BUG_ON(entry_offset != a[count]);
        BUG_ON(cur_loc > entry_offset);
       
        /* If there is no hole before the entry, just leave the entry as it was */
        if (entry_offset == cur_loc) 
        {   
            cur_loc += ent_len;
            continue;
        }
        
        memmove(VLBA_NODE_FIRST_ENTRY(vlba_node) + cur_loc, entry, ent_len);
        vlba_node->key_idx[idx[count]] = cur_loc;
        cur_loc += ent_len;
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

    switch(ver_or_key_split)
    {
        case 0:
            if(node->is_leaf)
            {
                if(node->used >= VLBA_TREE_NODE_ENTRIES) 
                    return 1;
                if(vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH) 
                    return 1;
                return 0;
            } else
            {
                if(node->used >= VLBA_TREE_NODE_ENTRIES - 1)
                    return 1;
                if(vlba_node->free_bytes + vlba_node->dead_bytes < MAX_VLBA_ENTRY_LENGTH*2)
                    return 1;
                return 0;
            }
            BUG();
            break;
        case 1:
            if(node->used >= 2*VLBA_TREE_NODE_ENTRIES/3)
                return 1;
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
    uint32_t key1_length = VLBA_KEY_LENGTH(key1);

    BUG_ON(!key1 || !key2);

    if(unlikely(VLBA_TREE_KEY_INVAL(key1) && VLBA_TREE_KEY_INVAL(key2)))
        return 0;

    if(unlikely(VLBA_TREE_KEY_INVAL(key1)))
        return -1;
    
    if(unlikely(VLBA_TREE_KEY_INVAL(key2)))
        return 1;

    if(key1->length < key2->length)
        return -1;

    if(key1->length > key2->length)
        return 1;

    BUG_ON(key1_length >= VLBA_TREE_MAX_KEY_SIZE);
    
    return memcmp(key1->_key, key2->_key, key1_length);
}
    
static void* castle_vlba_tree_key_next(void *keyv)
{
    debug("Enter - castle_vlba_tree_key_next() is not yet implemented\n");

    BUG();
    return NULL;
}

static void castle_vlba_tree_entry_get(struct castle_btree_node *node,
                                       int                       idx,
                                       void                    **key_p,            
                                       version_t                *version_p,
                                       int                      *is_leaf_ptr_p,
                                       c_disk_blk_t             *cdb_p)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry = 
               (struct castle_vlba_tree_entry *) VLBA_ENTRY_PTR(vlba_node, idx);

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(((uint8_t *)entry) >= EOF_VLBA_NODE(node));

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(is_leaf_ptr_p) *is_leaf_ptr_p = VLBA_TREE_ENTRY_IS_LEAF_PTR(entry);
    if(cdb_p)         *cdb_p         = entry->cdb;
}

static void castle_vlba_tree_entry_add(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key_v,            
                                       version_t                 version,
                                       int                       is_leaf_ptr,
                                       c_disk_blk_t              cdb)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry; 
    vlba_key_t *key = (vlba_key_t *)key_v;
    uint32_t key_length = VLBA_KEY_LENGTH(key);
    uint32_t req_space = sizeof(struct castle_vlba_tree_entry) + key_length;

    BUG_ON(idx < 0 || idx > node->used);

    /* Initialization of node free space structures */
    if (node->used == 0) 
    {
        vlba_node->dead_bytes = 0;
        vlba_node->free_bytes = VLBA_TREE_NODE_LENGTH - sizeof(struct castle_btree_node) -
                                sizeof(struct castle_vlba_tree_node);
    }
        
    BUG_ON(key_length > VLBA_TREE_MAX_KEY_SIZE);
    BUG_ON(vlba_node->free_bytes + vlba_node->dead_bytes < req_space);
    BUG_ON(node->used >= VLBA_TREE_NODE_ENTRIES);
    BUG_ON(!node->is_leaf && is_leaf_ptr);

    if(vlba_node->free_bytes < req_space) 
        castle_vlba_tree_node_compact(node);

    BUG_ON(vlba_node->free_bytes < req_space);

    entry = (struct castle_vlba_tree_entry *)(EOF_VLBA_NODE(node) - vlba_node->free_bytes);
    vlba_node->free_bytes -= req_space;
    memmove(&vlba_node->key_idx[idx+1], &vlba_node->key_idx[idx],
            sizeof(uint32_t) * (node->used - idx));

    vlba_node->key_idx[idx] = ((uint8_t *)entry) - VLBA_NODE_FIRST_ENTRY(vlba_node);
    memcpy(&entry->key, key, sizeof(vlba_key_t) + key_length);
    entry->version = version;
    entry->type    = node->is_leaf ? 
                        (is_leaf_ptr ? VLBA_TREE_ENTRY_LEAF_PTR : VLBA_TREE_ENTRY_LEAF_VAL) :
                        VLBA_TREE_ENTRY_NODE;
    entry->cdb     = cdb;

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
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(vlba_node, i);
        vlba_node->dead_bytes += VLBA_ENTRY_LENGTH(entry);
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
                                           c_disk_blk_t              cdb)
{
    struct castle_vlba_tree_node *vlba_node = 
        (struct castle_vlba_tree_node*) BTREE_NODE_PAYLOAD(node);
    struct castle_vlba_tree_entry *entry = 
        (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(vlba_node, idx);
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
        entry->cdb     = cdb;
    } 
    else 
    {
        castle_vlba_tree_entries_drop(node, idx, idx);
        castle_vlba_tree_entry_add(node, idx, key, version, is_leaf_ptr, cdb);
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

    a = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    idx = kmalloc(sizeof(uint32_t) * node->used, GFP_NOIO);
    BUG_ON(!a || !idx);
    
    memcpy(a, &vlba_node->key_idx[0], (sizeof(uint32_t) * node->used));
    for (i=0, count=0; i < node->used; i++) 
    {
        struct castle_vlba_tree_entry *entry;

        idx[i] = i;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(vlba_node, i);
        count += VLBA_ENTRY_LENGTH(entry);
    }

    BUG_ON( sizeof(struct castle_btree_node) + sizeof(struct castle_vlba_tree_node) +
                                           count + vlba_node->free_bytes +
                                           vlba_node->dead_bytes != VLBA_TREE_NODE_LENGTH);

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
        entry = (struct castle_vlba_tree_entry *)(VLBA_NODE_FIRST_ENTRY(vlba_node) +
                 entry_offset);
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
        if ((prev_offset != -1) && (prev_offset + prev_len > entry_offset))
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
        entry = (struct castle_vlba_tree_entry *)(VLBA_NODE_FIRST_ENTRY(vlba_node) +
                 entry_offset);
        ent_len = (uint32_t)VLBA_ENTRY_LENGTH(entry);

        ret = (prev_offset == -1)?0:castle_vlba_tree_key_compare(&prev_entry->key, &entry->key);
        if ((prev_offset != -1) && (ret == 1 || 
                                    (!ret && prev_entry->version > entry->version)))
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

    for(i=0; i<node->used; i++)
    {
        struct castle_vlba_tree_entry *entry;
        entry = (struct castle_vlba_tree_entry *)VLBA_ENTRY_PTR(vlba_node, i);

        printk("[%d] (", i); 
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


static inline struct castle_btree_type *castle_btree_type_get(btree_t type)
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

static void castle_btree_c2b_forget(c_bvec_t *c_bvec);
static void __castle_btree_find(struct castle_btree_type *btree,
                                c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb,
                                void *parent_key);


static void castle_btree_io_end(c_bvec_t *c_bvec,
                                c_disk_blk_t cdb,
                                int err)
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
    BUG_ON((!DISK_BLK_INVAL(cdb)) && (err));
    BUG_ON((c_bvec_data_dir(c_bvec) == WRITE) && (DISK_BLK_INVAL(cdb)) && (!err));
    /* Free the c2bs correctly. Call twice to release parent and child
       (if both exist) */
    castle_btree_c2b_forget(c_bvec);
    castle_btree_c2b_forget(c_bvec);
    /* Finish the IO */
    c_bvec->endfind(c_bvec, err, cdb);
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
    int lub_idx, insert_idx, i, key_cmp;

    debug("Looking for (k,v) = (%p, 0x%x), node->used=%d\n",
            key, version, node->used);
    /* We should not search for an invalid key */
    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
        
    lub_idx   = -1;
    key_lub = btree->inv_key; 
    for(i=node->used-1; i >= 0; i--)
    {
        void *entry_key;
        version_t entry_version;

        btree->entry_get(node, i, &entry_key, &entry_version, NULL, NULL);

        debug(" (k,v) = (%p, 0x%x)\n", entry_key, entry_version); 

        /* If the key is already too small, we must have gone past the least
           upper bound */
        if(btree->key_compare(entry_key, key) < 0)
            break;

        /* Do not consider versions which are not ancestral to the version we 
           are looking for.
           Also, don't update the LUB index if the key doesn't change.
           This is because the most recent ancestor will be found first when
           scanning from right to left */
        if((btree->key_compare(key_lub, entry_key) != 0) &&
            castle_version_is_ancestor(entry_version, version))
        {
            key_lub     = entry_key;
            version_lub = entry_version;
            lub_idx = i;
            debug("  set key_lub=%p, lub_idx=%d\n", key_lub, lub_idx);
        }
    } 

    /* If we are insterting something into the node, work out where should it go */
    /* Case 1: (key_lub == key) && (version_lub == version)
               no need to insert, we have exactly the (k,v) we wanted
       Case 2: (key_lub == key) && (version_lub != version)
               but we know that is_ancestor(version_lub, version) == 1
               this means that 'version' is more recent than version_lub, and
               it needs to go (just) to the right of the LUB
               => insert_idx = lub_idx + 1
       Case 3: (key_lub > key)
               there is no (k_x, v_x) such that 
               (key <= k_x < key_lub) && (is_ancestor(v_x, version)) because then 
               (k_x, v_x) would be the LUB.
               Therefore, in the inclusive range [i+1, lub_idx-1] there are no 
               ancestors of 'version'. It follows that we should insert on the basis
               of the key only. Therefore i+1 will point to the correct place.
       Case 4: There is no LUB.
               This case is similar to Case 3, in that there is no (k_x, v_x) such
               that (key <= k_x) && (is_ancestor(v_x, version)).
               Insert at i+1.
       Cases are exhaustive, because either LUB doesn't exist (Case 4), or it does,
       in which case, key_lub > key (Case 3) or key_lub == key (Case 2 and Case 1).
    */
    key_cmp = btree->key_compare(key_lub, key);
    if((lub_idx < 0) || (key_cmp > 0))
    /* Case 4 and Case 3 */
    {
        insert_idx = i+1;    
    }
    else
    if (version_lub != version)
    /* Case 2 */
    {
        /* key_lub should equal key */
        BUG_ON(key_cmp != 0);
        insert_idx = lub_idx + 1;
    } else
    /* Case 1 */
    {
        /* key_lub should equal key */
        BUG_ON(key_cmp != 0);
        /* version_lub should equal version */
        BUG_ON(version_lub != version);
        insert_idx = lub_idx;
    }

    if(lub_idx_p)    *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

c2_block_t* castle_btree_node_create(int version, int is_leaf, btree_t type)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node;
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

    dirty_c2b(c2b);

    return c2b;
}

static c2_block_t* castle_btree_effective_node_create(c2_block_t *orig_c2b,
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
    c2b = castle_btree_node_create(version, node->is_leaf, node->type);
    eff_node = c2b_buffer(c2b);

    last_eff_key = btree->inv_key;
    BUG_ON(eff_node->used != 0);
    insert_idx = -1;
    for(i=0; i<node->used; i++)
    {
        void        *entry_key;
        version_t    entry_version;
        int          entry_is_leaf_ptr;
        c_disk_blk_t entry_cdb;
        void       (*consume_entry_fn) (struct castle_btree_node *node,
                                        int                       idx,
                                        void                     *key,            
                                        version_t                 version,
                                        int                       is_leaf_ptr,
                                        c_disk_blk_t              cdb);
 
        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        /* Check if slot->version is ancestoral to version. If not,
           reject straigt away. */
        if(!castle_version_is_ancestor(entry_version, version))
            continue;

        /* Advance to the next entry if last_eff_key (last effective entry key) is different
           to the key we are looking at */ 
        if(btree->key_compare(last_eff_key, entry_key) != 0)
        {
            insert_idx++;
            consume_entry_fn = btree->entry_add;
        } else
        {
            /* last_eff_key == entry_key (&& last_eff_key != inv_key) 
               => do not allocate a new slot, replace it instead.
               Since we are scanning from left to right, we should be
               looking on a more recent versions now. Check for that.
             */
            /* TODO: these asserts should really be turned into
                     'corrupt btree' exception. */
            BUG_ON(!castle_version_is_ancestor(last_eff_version, entry_version));
            consume_entry_fn = btree->entry_replace;
        }
        
        if(!node->is_leaf || entry_is_leaf_ptr)
        {
            /* If already a leaf pointer, or a non-leaf entry copy directly. */
            consume_entry_fn(eff_node,
                            insert_idx,
                            entry_key,
                            entry_version,
                            entry_is_leaf_ptr,
                            entry_cdb);
        } else
        {
            /* Otherwise construct a new leaf pointer. */
            consume_entry_fn(eff_node,
                            insert_idx,
                            entry_key,
                            entry_version,
                            1,
                            orig_c2b->cdb);
        }
        last_eff_key = entry_key;
        last_eff_version = entry_version;
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

static c2_block_t* castle_btree_node_key_split(c2_block_t *orig_c2b)
{
    c2_block_t *c2b;
    struct castle_btree_node *node, *sec_node;
    struct castle_btree_type *btree;
    int i;

    void        *entry_key;
    version_t    entry_version;
    int          entry_is_leaf_ptr;
    c_disk_blk_t entry_cdb;

    node     = c2b_bnode(orig_c2b);
    btree    = castle_btree_type_get(node->type);
    c2b      = castle_btree_node_create(node->version, node->is_leaf, node->type);
    sec_node = c2b_bnode(c2b);
    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    BUG_ON(sec_node->used != 0);
    for(i=0; i<node->used >> 1; i++)
    {
        /* Copy the entries */
        btree->entry_get(node,     i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        btree->entry_add(sec_node, i,  entry_key,  entry_version,  entry_is_leaf_ptr,  entry_cdb);
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
                                     c_disk_blk_t cdb)
{
    struct castle_btree_node *node = c2b_buffer(c2b);
    /* TODO: Check that that 'index-1' is really always correct! */
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void      *left_key      = btree->inv_key;
    version_t  left_version  = INVAL_VERSION;
    int        left_is_leaf_ptr;

    BUG_ON(index > node->used);
    
    debug("Inserting (0x%x, 0x%x) under index=%d\n", cdb.disk, cdb.block, index);
    if(index > 0)
        btree->entry_get(node, index-1, &left_key, &left_version, &left_is_leaf_ptr, NULL);

    /* Special case. Newly inserted block may make another entry unreachable.
       This would cause problems with future splits. And therefore unreachable
       entry has to be replaced by the new one.
       The potentially unreachable entry is neccessarily just to the left. 
       It will stop being reachable if:
       - keys match
       - version to insert descendant from the left_version (and different)
       - version to insert the same as the node version
      If all of the above true, replace rather than insert */ 
    if((btree->key_compare(left_key, key) == 0) &&
       (left_version != version) &&
        castle_version_is_ancestor(left_version, version) &&
       (version == node->version))
    {
        /* In leaf nodes the element we are replacing MUST be a leaf pointer, 
           because left_version is strictly ancestoral to the node version.
           It implies that the key hasn't been insterted here, because 
           keys are only inserted to weakly ancestoral nodes */
        BUG_ON(!left_is_leaf_ptr && node->is_leaf);
        /* Replace the slot */
        btree->entry_replace(node, index-1, key, version, 0, cdb);
        dirty_c2b(c2b);
        return;
    }
    /* Insert the new entry */ 
    btree->entry_add(node, index, key, version, is_leaf_ptr, cdb);
    BUG_ON(node->used >= MAX_BTREE_ENTRIES);
    dirty_c2b(c2b);
}

static void castle_btree_node_insert(c2_block_t *parent_c2b,
                                     c2_block_t *child_c2b)
{
    struct castle_btree_node *parent = c2b_buffer(parent_c2b);
    struct castle_btree_node *child  = c2b_buffer(child_c2b);
    struct castle_btree_type *btree  = castle_btree_type_get(parent->type);
    version_t version = child->version;
    void *key;
    int insert_idx;
    
    BUG_ON(castle_btree_type_get(child->type) != btree);
    btree->entry_get(child, child->used-1, &key, NULL, NULL, NULL);

    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    castle_btree_slot_insert(parent_c2b, 
                             insert_idx, 
                             key,
                             version,
                             0,
                             child_c2b->cdb);
}

static void castle_btree_node_under_key_insert(c2_block_t *parent_c2b,
                                               c2_block_t *child_c2b,
                                               void *key,
                                               version_t version)
{
    struct castle_btree_node *parent = c2b_buffer(parent_c2b);
    struct castle_btree_type *btree = castle_btree_type_get(parent->type);
    int insert_idx;

    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), "
          "will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx); 
    castle_btree_slot_insert(parent_c2b, 
                             insert_idx, 
                             key,
                             version,
                             0,
                             child_c2b->cdb);
}

static void castle_btree_new_root_create(c_bvec_t *c_bvec, btree_t type)
{
    c2_block_t *c2b;
    struct castle_btree_node *node;
    
    debug("Creating a new root node, while handling write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Create the node */
    c2b = castle_btree_node_create(c_bvec->version, 0, type);
    node = c2b_buffer(c2b);
    /* Update the version tree, and release the version lock (c2b_forget will 
       no longer do that, because there will be a parent node). */
    debug("About to update version tree.\n");
    /* TODO: Check if we hold the version lock */
    /* Should not fail, because the root already exists */
    BUG_ON(castle_version_root_update(c_bvec->version, 
                                      c_bvec->tree->seq,
                                      c2b->cdb));
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
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
    eff_c2b = castle_btree_effective_node_create(retain_c2b, version);
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
    if(btree->need_split(eff_node, 1))
    {
        void *max_split_key;

        debug("Effective node too full, splitting.\n");
        split_c2b = castle_btree_node_key_split(eff_c2b ? eff_c2b : c_bvec->btree_node);
        split_node = c2b_buffer(split_c2b);
        BUG_ON(split_node->version != c_bvec->version);
        /* Work out whether to take the split node for the further btree walk.
           Since in the effective & split node there is at most one version
           for each block, and this version is ancestoral to what we are
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

    /* If we don't have a parent, we may may need to create a new root node.
       If not, the effective node will act as the new root node. In either 
       case (version -> root cdb) mapping has to be updated. */
    new_root = 0;
    if(!c_bvec->btree_parent_node)
    {
        if(split_c2b)
        {
            debug("Creating new root node.\n");
            castle_btree_new_root_create(c_bvec, node->type);
            new_root = 1;
        } else
        {
            debug("Effective node will be the new root node\n");
            BUG_ON(!eff_c2b);
            /* Should not fail, because the root already exists */
            BUG_ON(castle_version_root_update(version,
                                              c_bvec->tree->seq,
                                              eff_c2b->cdb));
        }
    }

    /* Work out if we have a parent */
    parent_c2b  = c_bvec->btree_parent_node;
    parent_node = parent_c2b ? c2b_buffer(parent_c2b) : NULL;
    /* Insert!
       This is a bit complex, due to number of different cases. Each is described below
       in some detail.
     
       If split node got created then it should be inserted with the
       usual (b,v) in the parent. Parent must have existed, or has just been 
       created
     */
    if(split_c2b)
    {
        debug("Inserting split node.\n");
        BUG_ON(!parent_c2b);
        castle_btree_node_insert(parent_c2b, split_c2b);
    }

    /* If effective node got created (rather than using the original node) then
       it either needs to be inserted in the usual way, or under MAX key if we are 
       inserting into the new root.
       Also, note that if effective node is our new root, and we don't have to
       insert it anywhere. In this case parent_c2b will be NULL. */
    if(eff_c2b && parent_c2b)
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

    /* Finally, if new root got created, and the effective node was identical
       to the original node. Insert the original node under MAX block key */
    if(new_root && !eff_c2b)
    {
        debug("Inserting original root node under MAX block key.\n");
        castle_btree_node_under_key_insert(parent_c2b,
                                           c_bvec->btree_node,
                                           btree->max_key,
                                           c_bvec->version);
    }

    /* All nodes inserted. Now, unlock all children nodes, except of the
       one with which we'll continue the walk with (saved in retained_c2b) */
    if(retain_c2b != c_bvec->btree_node)
    {
        debug("Unlocking the original node.\n");
        unlock_c2b(c_bvec->btree_node);
        put_c2b(c_bvec->btree_node);
    }
    if((retain_c2b != eff_c2b) && (eff_c2b))
    {
        debug("Unlocking the effective node.\n");
        unlock_c2b(eff_c2b);
        put_c2b(eff_c2b);
    }
    if((retain_c2b != split_c2b) && (split_c2b))
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
    struct castle_btree_node *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void *lub_key, *key = c_bvec->key;
    version_t lub_version, version = c_bvec->version;
    int lub_idx, lub_is_leaf_ptr, insert_idx, ret;
    c_disk_blk_t lub_cdb;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_WPROCESS);

    /* Check if the node needs to be split first. 
       A leaf node only needs to be split if there are _no_ empty slots in it.
       Internal nodes, if there are less than 2 free slots in them. 
       The exception is, if we got here following a leaf pointer. If that's the
       case, we know that we'll be updating in place.
     */ 
    if((btree->key_compare(c_bvec->parent_key, btree->inv_key) != 0) &&
       (btree->need_split(node, 0)))
    {
        debug("===> Splitting node: leaf=%d, used=%d\n",
                node->is_leaf, node->used);
        ret = castle_btree_node_split(c_bvec);
        if(ret)
        {
            /* End the IO in failure */
            castle_btree_io_end(c_bvec, INVAL_DISK_BLK, ret);
            return;
        }
        /* Make sure that node now points to the correct node after split */
        node = c_bvec_bnode(c_bvec);
    }
 
    /* Find out what to follow, and where to insert */
    castle_btree_lub_find(node, key, version, &lub_idx, &insert_idx);
    if(lub_idx >= 0)
        btree->entry_get(node, lub_idx, &lub_key, &lub_version, &lub_is_leaf_ptr, &lub_cdb);

    /* Deal with non-leaf nodes first */
    if(!node->is_leaf)
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        debug("Following write down the tree.\n");
        __castle_btree_find(btree, c_bvec, lub_cdb, lub_key);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!node->is_leaf);

    /* Insert an entry if LUB doesn't match our (k,v) precisely. */
    if((lub_idx < 0) || 
       (btree->key_compare(lub_key, key) != 0) || 
       (lub_version != version))
    {
        c_disk_blk_t cdb = castle_freespace_block_get(version, 1); 
        
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
                                 cdb);
        dirty_c2b(c_bvec->btree_node);
        castle_btree_io_end(c_bvec, cdb, 0);
        return;
    } 
    
    /* Final case: (k,v) found in the leaf node. */
    BUG_ON((btree->key_compare(lub_key, key) != 0) || 
           (lub_version != version));
    BUG_ON(lub_idx != insert_idx);

    /* If we are looking at the leaf pointer, follow it */
    if(lub_is_leaf_ptr)
    {
        debug("Following a leaf pointer to (0x%x, 0x%x).\n", 
                lub_cdb.disk, lub_cdb.block);
        __castle_btree_find(btree, c_bvec, lub_cdb, btree->inv_key);
        return;
    }

    debug("Block already exists, modifying in place.\n");
    castle_btree_io_end(c_bvec, lub_cdb, 0);
}

static void castle_btree_read_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void *lub_key, *key = c_bvec->key;
    version_t lub_version, version = c_bvec->version;
    int lub_idx, lub_is_leaf_ptr;
    c_disk_blk_t lub_cdb;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_RPROCESS);

    castle_btree_lub_find(node, key, version, &lub_idx, NULL);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((lub_idx < 0) && (!node->is_leaf));
    
    /* If we haven't found the LUB (in the leaf node), return early */
    if(lub_idx < 0)
    {
        debug(" Could not find the LUB for (k,v)=(%p, 0x%x)\n", key, version);
        castle_btree_io_end(c_bvec, INVAL_DISK_BLK, 0);
        return;
    }

    btree->entry_get(node, lub_idx, &lub_key, &lub_version, &lub_is_leaf_ptr, &lub_cdb);
    /* If we found the LUB, either complete the ftree walk (if we are looking 
       at a 'proper' leaf), or go to the next level (possibly following a leaf ptr) */
    if(node->is_leaf && !lub_is_leaf_ptr)
    {
        debug(" Is a leaf, found (k,v)=(%p, 0x%x), cdb=(0x%x, 0x%x)\n", 
                lub_key, lub_version, lub_cdb.disk, lub_cdb.block);
        if(btree->key_compare(lub_key, key) == 0)
            castle_btree_io_end(c_bvec, lub_cdb, 0);
        else
            castle_btree_io_end(c_bvec, INVAL_DISK_BLK, 0);
    }
    else
    {
        debug("Leaf ptr or not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                lub_cdb.disk, lub_cdb.block);
        /* parent_key is not needed when reading (also, we might be looking at a leaf ptr)
           use INVAL key instead. */
        __castle_btree_find(btree, c_bvec, lub_cdb, btree->inv_key);
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
        castle_btree_io_end(c_bvec, INVAL_DISK_BLK, -EIO);
        return;
    }

#ifdef CASTLE_DEBUG    
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
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
    struct castle_attachment *att = c_bvec->c_bio->attachment;
    struct castle_btree_type *btree = castle_btree_type_get(c_bvec->tree->btree_type);
    c_disk_blk_t root_cdb;

    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_btree_c2b_forget() */
    down_read(&att->lock);
    c_bvec->version = att->version;
    castle_version_lock(c_bvec->version);
    root_cdb = castle_version_root_get(c_bvec->version, 
                                       c_bvec->tree->seq);
    up_read(&att->lock);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        c_bvec->endfind(c_bvec, -EINVAL, INVAL_DISK_BLK);
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

    if(c_iter->indirect_nodes)
        kfree(c_iter->indirect_nodes);
    
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

void castle_btree_iter_replace(c_iter_t *c_iter, int index, c_disk_blk_t cdb)
{
    struct castle_btree_node *real_node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *real_c2b;
    int real_entry_idx, prev_is_leaf_ptr;
    void *prev_key;
    c_disk_blk_t prev_cdb;
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
                    &prev_cdb);
    /* We should be looking at a concreate entry, not a leaf pointer now */
    BUG_ON(prev_is_leaf_ptr);
    
    iter_debug("Current=(0x%x, 0x%x), new=(0x%x, 0x%x), "
               "in btree node: (0x%x, 0x%x), index=%d\n", 
                prev_cdb.disk,
                prev_cdb.block,
                cdb.disk, 
                cdb.block, 
                real_c2b->cdb.disk, 
                real_c2b->cdb.block, 
                real_entry_idx);
    
    btree->entry_replace(real_node,
                         real_entry_idx,
                         prev_key,
                         prev_version,
                         0,
                         cdb);
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
    
    if(c_iter->type == C_ITER_MATCHING_VERSIONS)
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
#define swap(_i, _j)                                                      \
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
            swap(root, child)                                             \
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
        swap(end, 0);
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
        c_disk_blk_t entry_cdb;
        int entry_is_leaf_ptr; 

        btree->entry_get(node, i, NULL, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        if(entry_version != c_iter->version)
            continue;
        if(entry_is_leaf_ptr)
        {
            BUG_ON(indirect_node(j).c2b);
            indirect_node(j).cdb   = entry_cdb;
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
        c_disk_blk_t entry_cdb;
        int entry_is_leaf_ptr; 
        void *entry_key;

        /* Set the idx to inval to catch bugs early */
        indirect_node(i).node_idx = -1;

        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        if(entry_version != c_iter->version)
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
        /* Reset the current depth idx to 0 */
        iter_debug("Reseting index at depth: %d, from %d->0\n",
                c_iter->depth,
                c_iter->node_idx[c_iter->depth]);
        c_iter->node_idx[c_iter->depth] = 0;
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

    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);
    
    node = c2b_bnode(leaf);
    BUG_ON(!node->is_leaf);
    
    iter_debug("Processing %d entries\n", node->used);
    
    /* We are in a leaf, then save the vblk number we followed to get here */
    c_iter->next_key = btree->key_compare(c_iter->parent_key, btree->inv_key) == 0 ?
                            btree->inv_key :
                            btree->key_next(c_iter->parent_key); 

    if (c_iter->node_start != NULL) 
        c_iter->node_start(c_iter);
    
    castle_btree_iter_leaf_ptrs_lock(c_iter);

    for(i=0; i<node->used; i++)
    {
        int entry_is_leaf_ptr, real_slot_idx; 
        version_t entry_version;
        c_disk_blk_t entry_cdb;
        void *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);

        iter_debug("Current slot: (b=%p, v=%x)->(cdb=0x%x, 0x%x)\n",
                entry_key, entry_version, entry_cdb.disk, entry_cdb.block);
        if (entry_version == c_iter->version)
        {
            c2_block_t *c2b;

            slot_follow_ptr(i, c2b, real_slot_idx);
            btree->entry_get(c2b_bnode(c2b), real_slot_idx, NULL, NULL, NULL, &entry_cdb);
            c_iter->each(c_iter, i, entry_cdb);
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
        int entry_is_leaf_ptr; 
        version_t entry_version;
        c_disk_blk_t entry_cdb;
        void *entry_key;

        if (c_iter->cancelled)
            break;

        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);

        iter_debug("All entries: current slot: (b=%p, v=%x)->(cdb=0x%x, 0x%x)\n",
                entry_key, entry_version, entry_cdb.disk, entry_cdb.block);
        if (!entry_is_leaf_ptr)
            c_iter->each(c_iter, i, entry_cdb);
    }

    iter_debug("Done processing entries.\n");

    /* 
     * Send end node callback if one not specified. Otherwise continue automatically.
     */   
    if (c_iter->node_end != NULL)
       c_iter->node_end(c_iter);
    else
       castle_btree_iter_continue(c_iter);
        
    castle_btree_iter_parent_node_idx_increment(c_iter);
}

static void   castle_btree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb);
static void __castle_btree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_disk_blk_t entry_cdb;
    void *entry_key;
    int index; 

    /* Return early on error */
    if(c_iter->err)
    {
        /* Unlock the top of the stack, this is normally done by 
           castle_btree_iter_continue. This will not happen now, because 
           the iterator was cancelled between two btree nodes. */
        unlock_c2b(c_iter->path[c_iter->depth]);
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /* Otherwise, we know that the node got read successfully. Its buffer is in the path. */
    node = c2b_bnode(c_iter->path[c_iter->depth]);

    switch(c_iter->type)
    { 
        case C_ITER_ALL_ENTRIES:
            /* Deal with leafs first */
            if(node->is_leaf)
            {
                castle_btree_iter_all_leaf_process(c_iter);
                return;        
            }

            /* If we enumerating all entries in the tree, we use the index saved
               in node_idx table. */
            index = c_iter->node_idx[c_iter->depth];
            /* Check if that index goes past the last entry in the node,
               if so, increment the index in the parent and restart the 
               traverse with the new node_idx array */
            if(index == node->used)
            {
                iter_debug("Got to the end of the node at depth=%d. "
                           "Incrementing the parent idx.\n",
                        c_iter->depth);
                castle_btree_iter_parent_node_idx_increment(c_iter);
                unlock_c2b(c_iter->path[c_iter->depth]);
                castle_btree_iter_start(c_iter);
                return;
            }
            BUG_ON(index > node->used);
            break;
        case C_ITER_MATCHING_VERSIONS:
            /* Deal with leafs first */
            if(node->is_leaf)
            {
                castle_btree_iter_version_leaf_process(c_iter);
                return;        
            }

             /* If we are enumerating all entries for a particular version,
               fin the occurance of the next key. */
            castle_btree_lub_find(node, c_iter->next_key, c_iter->version, &index, NULL);
            iter_debug("Node index=%d\n", index);
            break;
    }
    btree->entry_get(node, index, &entry_key, NULL, NULL, &entry_cdb);

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
        iter_debug("Unlocking cdb: (0x%x, 0x%x).\n", c2b->cdb.disk, c2b->cdb.block);
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
  
    iter_debug("Locking cdb=(0x%x, 0x%x)\n", 
        c2b->cdb.disk, c2b->cdb.block);
    lock_c2b(c2b);
    
    /* Unlock the ftree if we've just locked the root */
    if(c_iter->depth == 0)
    {
        /* We have just started the iteration - lets unlock the version tree */
        iter_debug("Unlocking version tree.\n");
        castle_version_unlock(c_iter->version);
    }
    /* Unlock previous c2b */
    if((c_iter->depth > 0) && (c_iter->path[c_iter->depth - 1] != NULL))
    {
        c2_block_t *prev_c2b = c_iter->path[c_iter->depth - 1];
        iter_debug("Unlocking cdb=(0x%x, 0x%x)\n", 
            prev_c2b->cdb.disk, prev_c2b->cdb.block);
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
        (btree->key_compare(c_iter->next_key, btree->inv_key) == 0) ||
        (c_iter->cancelled))
    {
        castle_btree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /*
     * Let's start from the root again...
     */
    c_iter->depth = 0;
    
    iter_debug("Locking version tree\n");
    
    castle_version_lock(c_iter->version);
    root_cdb = castle_version_root_get(c_iter->version, c_iter->tree->seq);
    if(DISK_BLK_INVAL(root_cdb))
    {
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
            /* Set all node indices to 0, which implies most extreme LHS walk through
               the tree first, which is precisely what we want */ 
            memset(c_iter->node_idx, 0, sizeof(c_iter->node_idx));
            return;
        case C_ITER_MATCHING_VERSIONS:
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
static inline void castle_iter_enum_idx_get(c_iter_t *c_iter,
                                            c_enum_t **c_enum_p,
                                            version_t *idx_p)
{
    struct castle_enumerator *c_enum = c_iter->private;

    if(c_enum_p) *c_enum_p = c_enum;
    if(idx_p)    *idx_p    = (c_iter - c_enum->iterators);
}

static void castle_enum_iter_each(c_iter_t *c_iter, int index, c_disk_blk_t cdb)
{
    struct castle_enumerator *c_enum;
    struct castle_iterator_buffer *buff;
    version_t idx; 

    castle_iter_enum_idx_get(c_iter, &c_enum, &idx);
    buff = c_enum->buffers + idx;
    buff->prod_idx++;
    enum_debug("Entry for iterator idx=%d: idx=%d, cdb=(0x%x, 0x%x)\n", 
                    idx, index, cdb.disk, cdb.block);
}

static void castle_enum_iter_node_end(c_iter_t *c_iter)
{
    struct castle_enumerator *c_enum;
    struct castle_iterator_buffer *buff;
    version_t idx; 

    castle_iter_enum_idx_get(c_iter, &c_enum, &idx);
    buff = c_enum->buffers + idx;
    BUG_ON(buff->cons_idx != 0);
    enum_debug("Ending node for iterator idx=%d, nr_entries=%d.\n", idx, buff->prod_idx);
    /* Special case, if nothing was read (it's possible if e.g. all entries are leaf ptrs)
       schedule the next node read, and exit early */
    if(buff->prod_idx == 0)
    {
        castle_btree_iter_continue(c_iter);
        return;
    }
    /* Release the leaf lock, otherwise other iterators will block, and we will never
       go past the enumaror initialisation */
    __castle_btree_iter_release(c_iter);

    atomic_dec(&c_enum->outs_iterators);
    wake_up(&c_enum->iterators_wq);
}

static void castle_enum_iter_end(c_iter_t *c_iter, int err)
{
    struct castle_enumerator *c_enum;
    struct castle_iterator_buffer *buff;
    version_t idx; 

    castle_iter_enum_idx_get(c_iter, &c_enum, &idx);
    if(err) c_enum->err = err;
    buff = c_enum->buffers + idx;
    enum_debug("Iterator %d ending, err=%d\n", idx, err);
    buff->iter_completed = 1;
    atomic_dec(&c_enum->outs_iterators);
    atomic_dec(&c_enum->live_iterators);
    wake_up(&c_enum->iterators_wq);
}

int castle_btree_enum_has_next(c_enum_t *c_enum)
{
    enum_debug("outs_iterators: %d\n", atomic_read(&c_enum->outs_iterators));
    /* Make sure that all buffers are up-to-date */
    wait_event(c_enum->iterators_wq, (atomic_read(&c_enum->outs_iterators) == 0));
    enum_debug("live_iterators: %d\n", atomic_read(&c_enum->live_iterators));

    return (atomic_read(&c_enum->live_iterators) != 0);
}

void castle_btree_enum_next(c_enum_t *c_enum)
{
    struct castle_iterator_buffer *buff;
    int first_iter;

    /* _has_next() waits for all buffers to be filled in, it's safe to assume this has
       been called just before */
    BUG_ON(atomic_read(&c_enum->outs_iterators) != 0);
    BUG_ON(atomic_read(&c_enum->live_iterators) == 0);
    
    /* First, find the iterator to use, all non-completed iterators are guaranteed to have
       something in the buffer */
    first_iter = c_enum->tmp_iter;
    enum_debug("first_iter %d\n", first_iter);
    do {
        buff = c_enum->buffers + c_enum->tmp_iter;
        enum_debug("iter_completed %d\n", buff->iter_completed);
        if(!buff->iter_completed)
            break;
        /* Move to the next iterator */
        c_enum->tmp_iter = (c_enum->tmp_iter + 1) % c_enum->nr_iters;
        enum_debug("moving to iter %d\n", c_enum->tmp_iter);
    } while(c_enum->tmp_iter != first_iter);

    BUG_ON(buff->iter_completed);
    BUG_ON((buff - c_enum->buffers) != c_enum->tmp_iter);
    BUG_ON(buff->cons_idx >= buff->prod_idx);

    enum_debug("cons_idx %d, prod_idx %d\n", buff->cons_idx, buff->prod_idx);
    /* TODO: Read off the entry we want to return here */
    buff->cons_idx++;
    
    /* Check if next node should be read for this iterator */
    if(buff->cons_idx == buff->prod_idx)
    {
        enum_debug("Scheduling a read for iterator %d.\n", c_enum->tmp_iter);
        buff->prod_idx = buff->cons_idx = 0;
        /* Remember that there will one more iterator in flight, and schedule the read. */
        atomic_inc(&c_enum->outs_iterators);
        castle_btree_iter_start(c_enum->iterators + c_enum->tmp_iter);
        /* TODO: this should be cleverer, at the moment, just move to the next iterator */
        c_enum->tmp_iter = (c_enum->tmp_iter + 1) % c_enum->nr_iters;
    }
}

void castle_btree_enum_init(c_enum_t *c_enum)
{
    version_t first_version, curr_version, ver_idx, nr_versions;
    struct castle_btree_type *btype;
    c_disk_blk_t cdb;

    btype = castle_btree_type_get(c_enum->tree->btree_type);
    nr_versions = list_length(&c_enum->tree->roots_list);
    enum_debug("Nr versions: %d\n", nr_versions);
    c_enum->nr_iters       = nr_versions;
    c_enum->err            = 0;
    c_enum->tmp_iter = 0;
    init_waitqueue_head(&c_enum->iterators_wq);
    c_enum->outs_iterators = ATOMIC(0);
    c_enum->live_iterators = ATOMIC(0); 
    /* Allocate memory for iterators, and for buffers to store one node's worth of entries
       for each iterator */
    c_enum->iterators      = NULL;
    c_enum->iterators      = vmalloc(nr_versions * sizeof(struct castle_iterator)); 
    c_enum->buffers        = NULL;
    c_enum->buffers        = vmalloc(nr_versions * sizeof(*c_enum->buffers));
    if(!c_enum->iterators || !c_enum->buffers)
        goto no_mem;
    memset(c_enum->buffers, 0, sizeof(c_enum->buffers)); 
    /* Go through versions, one at the time, and initialise the iterators, as well as the
       buffers */
    ver_idx = 0;
    castle_version_root_next(c_enum->tree->seq, &first_version, &cdb);
    curr_version = first_version;
    do {
        struct castle_iterator *iter;

        BUG_ON(ver_idx >= c_enum->nr_iters);
        /* Work out the next version, the root node cdb is ignored */
        castle_version_root_next(c_enum->tree->seq, &curr_version, &cdb);
        if(VERSION_INVAL(curr_version))
           break; 
        enum_debug("Version: %d, cdb=(0x%x, 0x%x)\n", curr_version, cdb.disk, cdb.block);

        /* Allocate buffer for a node */
        c_enum->buffers[ver_idx].prod_idx = 0;
        c_enum->buffers[ver_idx].cons_idx = 0;
        c_enum->buffers[ver_idx].iter_completed = 0;
        c_enum->buffers[ver_idx].buffer = vmalloc(btype->node_size * C_BLK_SIZE);
        if(!c_enum->buffers[ver_idx].buffer)
        goto no_mem;

        iter = c_enum->iterators + ver_idx; 
        iter->tree       = c_enum->tree;
        iter->node_start = NULL;
        iter->each       = castle_enum_iter_each;
        iter->node_end   = castle_enum_iter_node_end;
        iter->end        = castle_enum_iter_end;
        iter->private    = c_enum;
        castle_btree_iter_init(iter, curr_version, C_ITER_ALL_ENTRIES);
        ver_idx++;
    } while(curr_version != first_version);
    /* We should go through precisely nr_iters versions */
    BUG_ON(ver_idx != c_enum->nr_iters);

    enum_debug("Allocated all buffers & iterators.\n"); 
    c_enum->live_iterators = ATOMIC(c_enum->nr_iters); 
    /* Now, that all iterators have been created, and buffers allocated, start them all */
    for(ver_idx = 0; ver_idx < c_enum->nr_iters; ver_idx++)
    {
        atomic_inc(&c_enum->outs_iterators);
        castle_btree_iter_start(c_enum->iterators + ver_idx); 
    }

    return;
no_mem:
    if(c_enum->buffers)
    {
        for(ver_idx = 0; ver_idx < c_enum->nr_iters; ver_idx++)
            if(c_enum->buffers[ver_idx].buffer)
                vfree(c_enum->buffers[ver_idx].buffer);
        vfree(c_enum->buffers);
    }
    if(c_enum->iterators)
        vfree(c_enum->iterators);
    c_enum->err = -ENOMEM;
}

