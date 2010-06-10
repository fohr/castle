#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_freespace.h"
#include "castle_versions.h"
#include "castle_block.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define iter_debug(_f, ...)     ((void)0)
#else
#define debug(_f, _a...)        (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define iter_debug(_f, _a...)   (printk("Iterator:%.60s:%.4d:  " _f, __func__, __LINE__ , ##_a))
#endif


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

static void castle_mtree_entry_set(struct castle_btree_node *node,
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

#ifdef CASTLE_DEBUG
static void castle_mtree_node_validate(struct castle_btree_node *node)
{
    struct castle_mtree_entry *entries = 
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->capacity > MTREE_NODE_ENTRIES) ||
       (node->used     > node->capacity) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        printk("Invalid mtree node capacity or/and used: (%d, %d), node version=%d\n",
               node->capacity, node->used, node->version);
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

    for(i=0; i<node->used; i++)
        printk("[%d] (0x%x, 0x%x) -> (0x%x, 0x%x)\n", 
            i,
            entries[i].block,
            entries[i].version,
            entries[i].cdb.disk,
            entries[i].cdb.block);
    printk("\n");
}


struct castle_btree_type castle_mtree = {
    .magic         = MTREE_TYPE,
    .node_size     = MTREE_NODE_SIZE,
    .node_capacity = MTREE_NODE_ENTRIES,
    .min_key       = (void *)0,
    .max_key       = (void *)MTREE_MAX_BLK,
    .inv_key       = (void *)MTREE_INVAL_BLK,
    .key_compare   = castle_mtree_key_compare,
    .key_next      = castle_mtree_key_next,
    .entry_get     = castle_mtree_entry_get,
    .entry_set     = castle_mtree_entry_set,
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

static void castle_batree_entry_set(struct castle_btree_node *node,
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

#ifdef CASTLE_DEBUG
static void castle_batree_node_validate(struct castle_btree_node *node)
{
    struct castle_batree_entry *entries = 
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->capacity > BATREE_NODE_ENTRIES) ||
       (node->used     > node->capacity) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        printk("Invalid batree node capacity or/and used: (%d, %d), node version=%d\n",
               node->capacity, node->used, node->version);
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
    .node_capacity = BATREE_NODE_ENTRIES,
    .min_key       = (void *)&BATREE_MIN_KEY,
    .max_key       = (void *)&BATREE_MAX_KEY,
    .inv_key       = (void *)&BATREE_INVAL_KEY,
    .key_compare   = castle_batree_key_compare,
    .key_next      = castle_batree_key_next,
    .entry_get     = castle_batree_entry_get,
    .entry_set     = castle_batree_entry_set,
    .node_print    = castle_batree_node_print,
#ifdef CASTLE_DEBUG    
    .node_validate = castle_batree_node_validate,
#endif
}; 


/**********************************************************************************************/
/* Array of btree types */

static struct castle_btree_type *castle_btrees[1<<(8 * sizeof(btree_t))] = 
                                                       {[MTREE_TYPE]  = &castle_mtree,
                                                        [BATREE_TYPE] = &castle_batree};


static inline struct castle_btree_type *castle_btree_type_get(btree_t type)
{
#ifdef CASTLE_DEBUG
    BUG_ON((type != MTREE_TYPE) &&
           (type != BATREE_TYPE));
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
    /* Once buffers have been freed, save the cdb */
    c_bvec->cdb = cdb;
    /* Finish the IO (call _io_end directly on an error */
    if(err)
        castle_bio_data_io_end(c_bvec, err);
    else
        castle_bio_data_io(c_bvec);
}

static void USED castle_btree_node_print(struct castle_btree_type *t, struct castle_btree_node *node)
{
    printk("Printing node version=%d with (cap, use) = (%d, %d), is_leaf=%d\n",
        node->version, node->capacity, node->used, node->is_leaf);

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

    debug("Looking for (k,v) = (%p, 0x%x), node->used=%d, capacity=%d\n",
            key, version, node->used, node->capacity);
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
    node->capacity = btree->node_capacity;
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
    int i, first;
    
    node = c2b_bnode(orig_c2b); 
    btree = castle_btree_type_get(node->type);
    c2b = castle_btree_node_create(version, node->is_leaf, node->type);
    eff_node = c2b_buffer(c2b);

    first = 1;
    last_eff_key = btree->inv_key;
    for(i=0; i<node->used; i++)
    {
        void        *entry_key;
        version_t    entry_version;
        int          entry_is_leaf_ptr;
        c_disk_blk_t entry_cdb;

        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);

        BUG_ON(eff_node->used >= eff_node->capacity);
        /* Check if slot->version is ancestoral to version. If not,
           reject straigt away. */
        if(!castle_version_is_ancestor(entry_version, version))
            continue;

        /* Advance to the next entry if last_eff_key (last effective entry key) is different
           to the key we are looking at */ 
        if(btree->key_compare(last_eff_key, entry_key) != 0)
        {
            eff_node->used++;
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
        }
        
        if(!node->is_leaf || entry_is_leaf_ptr)
        {
            /* If already a leaf pointer, or a non-leaf entry copy directly. */
            btree->entry_set(eff_node,
                             eff_node->used-1,
                             entry_key,
                             entry_version,
                             entry_is_leaf_ptr,
                             entry_cdb);
        } else
        {
            /* Otherwise construct a new leaf pointer. */
            btree->entry_set(eff_node,
                             eff_node->used-1,
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
    int i, j;

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
    sec_node->used = node->used >> 1;
    for(i=0; i<sec_node->used; i++)
    {
        /* Copy the entries */
        btree->entry_get(node,     i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        btree->entry_set(sec_node, i,  entry_key,  entry_version,  entry_is_leaf_ptr,  entry_cdb);
    }

    /* Move the entries in node to the beginning of the node */
    for(i=sec_node->used, j=0; i<node->used; i++, j++)
    {
        btree->entry_get(node, i, &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        btree->entry_set(node, j,  entry_key,  entry_version,  entry_is_leaf_ptr,  entry_cdb);
    }
    node->used -= sec_node->used;
    BUG_ON(node->used != j);
    
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
    int        left_is_leaf_ptr, i;

    BUG_ON(index      >  node->used);
    BUG_ON(node->used >= node->capacity);
    
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
        /* The element we are replacing MUST be a leaf pointer, 
           because left_version is strictly ancestoral to the node version.
           It implies that the key hasn't been insterted here, because 
           keys are only inserted to weakly ancestoral nodes */
        BUG_ON(!left_is_leaf_ptr);
        /* Replace the slot */
        btree->entry_set(node, index-1, key, version, 0, cdb);
        dirty_c2b(c2b);
        return;
    }
    /* Make space for the extra slot. */
    node->used++;
    for(i=node->used-2; i>=index; i--) 
    {
        void        *entry_key;
        version_t    entry_version;
        int          entry_is_leaf_ptr;
        c_disk_blk_t entry_cdb;

        btree->entry_get(node, i,  &entry_key, &entry_version, &entry_is_leaf_ptr, &entry_cdb);
        btree->entry_set(node, i+1, entry_key,  entry_version,  entry_is_leaf_ptr,  entry_cdb);
    }
    /* Finally, set the entry */ 
    btree->entry_set(node, index, key, version, is_leaf_ptr, cdb);
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
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, key, version, insert_idx);
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
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), "
          "will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, key, version, insert_idx);
    castle_btree_slot_insert(parent_c2b, 
                             insert_idx, 
                             key,
                             version,
                             0,
                             child_c2b->cdb);
}

static int castle_btree_new_root_create(c_bvec_t *c_bvec, btree_t type)
{
    c2_block_t *c2b;
    struct castle_btree_node *node;
    int ret;
    
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
    ret = castle_version_ftree_update(c_bvec->version, c2b->cdb);
    /* If we failed to update the version tree, dealloc the root */
    if(ret)
    {
        debug("Failed.\n");
        /* TODO: dealloc the block, possibly clean c2b */
        unlock_c2b(c2b);
        put_c2b(c2b);
        return ret;
    }
    debug("Succeeded.\n");
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
    castle_version_ftree_unlock(c_bvec->version);
    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);

    return 0;
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

    /* Split the effective node if it's more than 75% full */
    if(eff_node->used > (eff_node->capacity >> 1) + (eff_node->capacity >> 2))
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
        int ret;
        
        if(split_c2b)
        {
            debug("Creating new root node.\n");
            ret = castle_btree_new_root_create(c_bvec, node->type);
            new_root = 1;
        } else
        {
            debug("Effective node will be the new root node\n");
            BUG_ON(!eff_c2b);
            ret = castle_version_ftree_update(version, eff_c2b->cdb);
        }
        /* If ret != 0, we failed to update (version -> root) mapping */ 
        if(ret)
        {
            debug("Failed to update version->root mapping.\n");
            /* Free the newly created nodes */
            /* TODO: we should also free the blocks */
            if(split_c2b)
            {
                unlock_c2b(split_c2b);
                put_c2b(split_c2b);
            }
            if(eff_c2b)
            {
                unlock_c2b(eff_c2b);
                put_c2b(eff_c2b);
            }
            return ret;
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
       ((node->is_leaf && (node->capacity == node->used)) ||
       (!node->is_leaf && (node->capacity - node->used < 2))))
    {
        debug("===> Splitting node: leaf=%d, cap,use=(%d,%d)\n",
                node->is_leaf, node->capacity, node->used);
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
        
        /* TODO: should memset the page to zero (because we return zeros on reads)
                 this can be done here, or beter still in _main.c, in data_copy */
        debug("Need to insert (%p, 0x%x) into node (used: 0x%x, capacity: 0x%x, leaf=%d).\n",
                key, version, node->used, node->capacity, node->is_leaf);
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
        castle_version_ftree_unlock(c_bvec->version); 
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
    struct castle_device *c_dev = c_bvec->c_bio->c_dev;
    struct castle_btree_type *btree = c_bvec->btree; /* This is in an union, get it out ASAP */
    c_disk_blk_t root_cdb;

    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_btree_c2b_forget() */
    down_read(&c_dev->lock);
    c_bvec->version = c_dev->version;
    root_cdb = castle_version_ftree_lock(c_bvec->version);
    up_read(&c_dev->lock);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    }
    set_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_btree_find(btree, c_bvec, root_cdb, btree->max_key);
}

void castle_btree_find(struct castle_btree_type *btree, c_bvec_t *c_bvec)
{
    c_bvec->btree = btree;
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
    
    if (c_iter->end) 
        c_iter->end(c_iter, err);
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
    struct castle_btree_type *btree = c_iter->btree;
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
    
    btree->entry_set(real_node,
                     real_entry_idx,
                     prev_key,
                     prev_version,
                     0,
                     cdb);
    dirty_c2b(real_c2b);
}

static void __castle_btree_iter_start(c_iter_t *c_iter);

void castle_btree_iter_continue(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = c_iter->btree;
    c2_block_t *leaf; 
    int i;

    iter_debug("Continuing.\n");
    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);
    
    node = c2b_bnode(leaf);
    BUG_ON(!node->is_leaf);
    
    /* Unlock all the indirect nodes. */
    for(i=btree->node_capacity-1; i>=0; i--)
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
    unlock_c2b(leaf);
    
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
    struct castle_btree_type *btree = c_iter->btree;
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
        c2b = castle_cache_block_get(cdb, btree->node_capacity);
        lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
            submit_c2b_sync(READ, c2b);
        indirect_node(i).c2b = c2b; 
    }
    /* Finally, find out where in the indirect block the individual ptrs are */
    for(i=0; i<btree->node_capacity; i++)
        indirect_node(i).node_idx = -1;
    for(i=0; i<node->used; i++)
    {
        version_t entry_version;
        c_disk_blk_t entry_cdb;
        int entry_is_leaf_ptr; 
        void *entry_key;

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

static void castle_btree_iter_leaf_process(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = c_iter->btree;
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

static void castle_btree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb);

static void __castle_btree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    struct castle_btree_node *node;
    struct castle_btree_type *btree = c_iter->btree;
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

    /* Are we at a leaf? */
    if(node->is_leaf)
    {
        castle_btree_iter_leaf_process(c_iter);
        return;        
    }

    /* Otherwise, 'recurse' - find the occurance of the next key */
    castle_btree_lub_find(node, c_iter->next_key, c_iter->version, &index, NULL);
    iter_debug("Node index=%d\n", index);
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
    struct castle_btree_type *btree = c_iter->btree;
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
        castle_version_ftree_unlock(c_iter->version);
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
    struct castle_btree_type *btree = c_iter->btree;
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
    
    root_cdb = castle_version_ftree_lock(c_iter->version);
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

void castle_btree_iter_init(c_iter_t *c_iter, version_t version)
{
    iter_debug("Initialising iterator for version=0x%x\n", version);
    
    /* TODO: This needs to be moved! */
    c_iter->btree = &castle_mtree;
    c_iter->version = version;
    c_iter->parent_key = c_iter->btree->min_key;
    c_iter->next_key = c_iter->btree->min_key;
    c_iter->depth = -1;
    c_iter->err = 0;
    c_iter->cancelled = 0;
    memset(c_iter->indirect_nodes, 0, sizeof(c_iter->indirect_nodes));
    memset(c_iter->path, 0, sizeof(c_iter->path));
}

void castle_btree_iter_cancel(c_iter_t *c_iter, int err)
{
    iter_debug("Cancelling version=0x%x iterator, error=%d\n", c_iter->version, err);
    
    c_iter->err = err;
    wmb();
    c_iter->cancelled = 1;
}

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    /* We have a static array of btree types indexed by btree_t, don't let it grow too
       large. */
    BUG_ON(sizeof(btree_t) != 1);
    BUG_ON(MAX_BTREE_ENTRIES < MTREE_NODE_ENTRIES);

    return 0;
}

void castle_btree_free(void)
{
}
