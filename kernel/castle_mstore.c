#include "castle.h"
#include "castle_cache.h"
#include "castle_utils.h"
#include "castle_ctrl.h"
#include "castle_da.h"
#include "castle_versions.h"

#ifndef DEBUG
#define debug(_f, _a...)  ((void)0)
#else
#define PREF_DEBUG  /* ensure pref_debug* messages are printed too. */
#define debug(_f, _a...)  (castle_printk(LOG_USERINFO, "%s:%.4d:%s " _f,                    \
                                                 __FILE__, __LINE__ , __func__, ##_a))
#endif

static c_ext_free_t            mstore_ext_free;
static atomic_t                mstores_ref_cnt = ATOMIC_INIT(0);

/* TO BE DELETED. */
typedef struct castle_mstore_key {
    c_ext_pos_t  cep;
    int          idx;
} c_mstore_key_t;

#define INVAL_MSTORE_KEY           ((c_mstore_key_t){.cep = __INVAL_EXT_POS, .idx = 0})
#define MSTORE_KEY_INVAL(_k)       (EXT_POS_INVAL(_k.cep) && ((_k).idx == 0))
#define MSTORE_KEY_EQUAL(_k1, _k2) (EXT_POS_EQUAL(_k1.cep, _k2.cep)  &&         \
                                    ((_k1).idx == (_k2).idx))
#define MSTORE_NODE_BLOCKS         (256)    /* MStores use 1MB nodes. */
/**********************************************************************************************
 * Generic storage functionality for (usually small) persistent data (e.g. versions in
 * version tree, double arrays).
 */
#define CASTLE_MSTORE_ENTRY_LAST     (1<<0)

struct castle_mstore_entry {
    /* align:   1 */
    /* offset:  0 */ uint8_t  flags;
    /*          1 */ uint8_t  _unused[3];
    /*          4 */ uint32_t size;
    /*          8 */ char payload[0];
    /*          8 */
} PACKED;

/**
 * Works out where a given entry is in an mstore.
 */
static inline struct castle_mstore_entry* castle_mstore_entry_get(struct castle_mstore *mstore,
                                                                  struct castle_mlist_node *node,
                                                                  int last_or_next /* 0 - last */)
{
    c_byte_off_t node_offset;

    node_offset = (last_or_next == 0) ? mstore->last_node_last_entry_offset :
                                        mstore->last_node_next_entry_offset;
    /* Byte offset must be valid. */
    BUG_ON(BYTE_OFF_INVAL(node_offset));
    BUG_ON(node_offset + sizeof(struct castle_mstore_entry) >= (MSTORE_NODE_BLOCKS * C_BLK_SIZE));

    return (struct castle_mstore_entry *)((char *)node + node_offset);
}

static void _castle_mstore_init(c_mstore_id_t store_id, struct castle_mstore *store, int rw)
{
    store->store_id                    = store_id;
    store->rw                          = rw;
    init_MUTEX(&store->mutex);
    store->last_node_cep               = INVAL_EXT_POS;
    store->last_node_last_entry_offset = INVAL_BYTE_OFF;
    store->last_node_next_entry_offset = INVAL_BYTE_OFF;
}

static void castle_mstore_iterator_validate(struct castle_mstore_iter *iter)
{
    struct castle_mlist_node *node = c2b_buffer(iter->node_c2b);

    BUG_ON(node->magic != MLIST_NODE_MAGIC);
    debug("Succeeded at validating the iterator.\n");
}

static void castle_mstore_iterator_advance(struct castle_mstore_iter *iter)
{
    struct castle_mlist_node *node;
    c2_block_t *c2b;

again:
    c2b = NULL;
    debug("Advancing the iterator.\n");

    /* Ignore attempts to advance completed iterator */
    if(!iter->node_c2b)
        return;

    /* Advance the indexes. */
    iter->next_entry_idx++;
    iter->store.last_node_last_entry_offset = iter->store.last_node_next_entry_offset;

    node = c2b_buffer(iter->node_c2b);
    debug("node_idx=%d, node->used=%d.\n", iter->next_entry_idx, node->used);
    /* Check if we need to advance to the next node */
    BUG_ON(iter->next_entry_idx > node->used);
    if(iter->next_entry_idx == node->used)
    {
        debug("Advancing to the next node.\n");
        /* Update the node_c2b field appropriately */
        if(!EXT_POS_INVAL(node->next))
        {
            debug("Node exists.\n");
            c2b = castle_cache_block_get(node->next, MSTORE_NODE_BLOCKS);
            write_lock_c2b(c2b);
            if(!c2b_uptodate(c2b))
            {
                debug("Scheduling a read.\n");
                BUG_ON(submit_c2b_sync(READ, c2b));
            }
        }
        debug("Unlocking prev node.\n");
        write_unlock_c2b(iter->node_c2b);
        put_c2b(iter->node_c2b);
        iter->node_c2b = c2b;
        iter->next_entry_idx = -1;
        iter->store.last_node_next_entry_offset = sizeof(struct castle_mlist_node);
        debug("Advancing again.\n");
        goto again;
    }
}

int castle_mstore_iterator_has_next(struct castle_mstore_iter *iter)
{
    debug("Iterator %s.\n", iter->node_c2b ? "has next" : "doesn't have next");
    return iter->node_c2b ? 1 : 0;
}

void castle_mstore_iterator_next(struct castle_mstore_iter *iter,
                                 void *entry_p,
                                 size_t *size_p)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *entry;

    debug("Iterator next.\n");
    BUG_ON(!castle_mstore_iterator_has_next(iter));
    node = c2b_buffer(iter->node_c2b);
    entry = castle_mstore_entry_get(&iter->store, node, 0);

    /* Copy the entry out. */
    BUG_ON(!entry_p || !size_p);
    debug("Copying entry, entry=%p, first 32bits=%x, size=%d.\n",
            entry, *((uint32_t *)entry->payload), entry->size);
    memcpy(entry_p,
           entry->payload,
           entry->size);
    *size_p = entry->size;

    debug("Advancing the iterator last=%lld, next=%lld.\n",
            iter->store.last_node_last_entry_offset,
            iter->store.last_node_next_entry_offset);
    /* The offset to next entry has to be advanced manually, _advance() takes care of the rest. */
    iter->store.last_node_next_entry_offset += entry->size + sizeof(struct castle_mstore_entry);
    debug("Before advance next offset=%lld.\n",
            iter->store.last_node_next_entry_offset);
    castle_mstore_iterator_advance(iter);
    debug("After advance last offset=%lld.\n",
            iter->store.last_node_last_entry_offset);
}

void castle_mstore_iterator_destroy(struct castle_mstore_iter *iter)
{
    debug("Destroying the iterator.\n");
    if(iter->node_c2b)
    {
        debug("Unlocking the node.\n");
        write_unlock_c2b(iter->node_c2b);
        put_c2b(iter->node_c2b);
    }
    debug("Freeing.\n");
    castle_free(iter);
    atomic_dec(&mstores_ref_cnt);
}

struct castle_mstore_iter* castle_mstore_iterate(c_mstore_id_t store_id)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore_iter *iter;
    c_ext_pos_t list_cep;

    /* Sanity check, to see if store_id isn't too large. */
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t ))
    {
        castle_printk(LOG_ERROR, "Asked to iterate mstore id=%d, this is too large.\n", store_id);
        return NULL;
    }

    /* Find out where the first block for this store is. */
    fs_sb = castle_fs_superblocks_get();
    list_cep = fs_sb->mstore[store_id];
    castle_fs_superblocks_put(fs_sb, 0);
    debug("Read first list node for mstore %d, got "cep_fmt_str_nl,
                    store_id, cep2str(list_cep));
    if(EXT_POS_INVAL(list_cep))
        return NULL;

    /* Allocate the iterator structure. */
    debug("Creating the iterator.\n");
    iter = castle_zalloc(sizeof(struct castle_mstore_iter));
    if(!iter)
        return NULL;

    /* Initialise the store structure for reading. */
    _castle_mstore_init(store_id, &iter->store, READ);

    /* Init the iterator structure correctly. */
    iter->store.last_node_cep = list_cep;
    BUG_ON(!BYTE_OFF_INVAL(iter->store.last_node_last_entry_offset));
    iter->store.last_node_next_entry_offset = sizeof(struct castle_mlist_node);
    iter->node_c2b = castle_cache_block_get(list_cep, MSTORE_NODE_BLOCKS);
    iter->next_entry_idx = -1;  /* This is going to be advanced to 0 later in the function. */

    /* Read in the first node (leave it locked). */
    debug("Locking the first node "cep_fmt_str_nl, cep2str(iter->node_c2b->cep));
    write_lock_c2b(iter->node_c2b);
    if(!c2b_uptodate(iter->node_c2b))
        BUG_ON(submit_c2b_sync(READ, iter->node_c2b));
    debug("Node uptodate\n");

    /* Validate the first node, and advance once, to set all the iterator fields correctly. */
    castle_mstore_iterator_validate(iter);
    castle_mstore_iterator_advance(iter);
    debug("Iterator ready.\n");

    atomic_inc(&mstores_ref_cnt);

    return iter;
}

/**
 * Place node on mstore list.
 *
 * NOTE: Needs to be called with store mutex locked. Otherwise two/more racing
 * node_adds may be generated due to the lock-free period between
 * last_node_unused check, and node_add.
 */
static void castle_mstore_node_add(struct castle_mstore *store)
{
    struct castle_mlist_node *node, *prev_node;
    struct castle_fs_superblock *fs_sb;
    c2_block_t *c2b, *prev_c2b;
    c_ext_pos_t cep;

    debug("Adding a node.\n");
    /* Check that store is writable. */
    BUG_ON(store->rw != WRITE);

    /* Check if mutex is locked */
    BUG_ON(down_trylock(&store->mutex) == 0);

    /* Prepare the node first */
    BUG_ON(castle_ext_freespace_get(&mstore_ext_free,
                                     MSTORE_NODE_BLOCKS * C_BLK_SIZE,
                                     0,
                                     &cep) < 0);
    c2b = castle_cache_block_get(cep, MSTORE_NODE_BLOCKS);
    debug("Allocated "cep_fmt_str_nl, cep2str(cep));
    write_lock_c2b(c2b);
    update_c2b(c2b);
    debug("Locked.\n");

    /* Init the node correctly */
    node = c2b_buffer(c2b);
    node->magic     = MLIST_NODE_MAGIC;
    node->used      = 0;
    node->next      = INVAL_EXT_POS;
    /* Memset the _unused bytes, so that we can make it easier to upgrade. */
    memset(node->_unused, 0, sizeof(node->_unused));
    dirty_c2b(c2b);
    debug("Inited the node.\n");
    /* Update relevant pointers to point to us (either FS superblock, or prev node) */
    if(EXT_POS_INVAL(store->last_node_cep))
    {
        debug("Linking into the superblock.\n");
        fs_sb = castle_fs_superblocks_get();
        BUG_ON(!EXT_POS_INVAL(fs_sb->mstore[store->store_id]));
        fs_sb->mstore[store->store_id] = cep;
        castle_fs_superblocks_put(fs_sb, 1);
    } else
    {
        struct castle_mstore_entry *last_entry;

        prev_c2b = castle_cache_block_get(store->last_node_cep, MSTORE_NODE_BLOCKS);
        debug("Linking into the prev node "cep_fmt_str_nl,
                cep2str(prev_c2b->cep));
        write_lock_c2b(prev_c2b);
        if(!c2b_uptodate(prev_c2b))
            BUG_ON(submit_c2b_sync(READ, prev_c2b));
        debug("Read prev node.\n");
        /* Link the new node in. */
        prev_node = c2b_buffer(prev_c2b);
        prev_node->next = cep;
        /* Set the last entry bit for the last entry in that node. */
        last_entry = castle_mstore_entry_get(store, prev_node, 0);
        last_entry->flags |= CASTLE_MSTORE_ENTRY_LAST;
        dirty_c2b(prev_c2b);
        write_unlock_c2b(prev_c2b);
        put_c2b(prev_c2b);
    }
    debug("Updating the saved last node.\n");
    /* Finally, save this node as the last node */
    store->last_node_cep               = cep;
    store->last_node_last_entry_offset = INVAL_BYTE_OFF;
    /* First entry is just after the header. */
    store->last_node_next_entry_offset = sizeof(struct castle_mlist_node);
    write_unlock_c2b(c2b);
    put_c2b(c2b);
}

int castle_mstore_entry_insert(struct castle_mstore *store,
                               void *entry,
                               size_t entry_size)
{
    struct castle_mlist_node *node;
    struct castle_mstore_entry *mentry;
    c2_block_t *c2b;

    debug("Inserting a new entry.\n");
    down(&store->mutex);

    /* We cannot store entries bigger than node size - overheads. */
    BUG_ON(entry_size + sizeof(struct castle_mstore_entry) + sizeof(struct castle_mlist_node)
           >
           MSTORE_NODE_BLOCKS * C_BLK_SIZE);

    /* Work out whether a new node must be added to store this entry. */
    if(store->last_node_next_entry_offset + sizeof(struct castle_mstore_entry) + entry_size
       >
       MSTORE_NODE_BLOCKS * C_BLK_SIZE)
    {
        debug("Adding a new node to the list, when adding entry size: %lld.\n", entry_size);
        castle_mstore_node_add(store);
    }

    /* Write the entry to the last node */
    debug("Reading last node "cep_fmt_str_nl,
            cep2str(store->last_node_cep));
    c2b = castle_cache_block_get(store->last_node_cep, MSTORE_NODE_BLOCKS);
    write_lock_c2b(c2b);
    if(!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    node = c2b_buffer(c2b);
    mentry = castle_mstore_entry_get(store, node, 1 /* next entry */);
    debug("Writing out under off=%lld (%p), first 32bits are: %x, size=%ld.\n",
            store->last_node_next_entry_offset, mentry, *((uint32_t *)entry), entry_size);
    mentry->flags = 0;
    mentry->size = entry_size;
    memcpy(mentry->payload,
           entry,
           entry_size);
    node->used++;
    store->last_node_last_entry_offset = store->last_node_next_entry_offset;
    store->last_node_next_entry_offset += sizeof(struct castle_mstore_entry) + entry_size;
    dirty_c2b(c2b);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    up(&store->mutex);

    return 0;
}

struct castle_mstore* castle_mstore_init(c_mstore_id_t store_id)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_mstore *store;

    debug("Opening mstore id=%d.\n", store_id);
    /* Sanity check, to see if store_id isn't too large. */
    if(store_id >= sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t))
    {
        castle_printk(LOG_WARN, "Asked for mstore id=%d, this is too large.\n", store_id);
        return NULL;
    }

    /* Allocate memory for the store structure. */
    debug("Allocating mstore id=%d.\n", store_id);
    store = castle_zalloc(sizeof(struct castle_mstore));
    if(!store)
        return NULL;

    /* Initialise the structure. */
    _castle_mstore_init(store_id, store, WRITE);

    /* Initialise the first node. */
    debug("Initialising first list node.\n");
    /* Lock (even though no-one knows about this store yet), since node_add() checks. */
    down(&store->mutex);
    castle_mstore_node_add(store);
    up(&store->mutex);

    atomic_inc(&mstores_ref_cnt);

    return store;
}

void castle_mstore_fini(struct castle_mstore *store)
{
    debug("Closing mstore id=%d.\n", store->store_id);
    castle_free(store);

    atomic_dec(&mstores_ref_cnt);
}

/**
 * High level handler for writing out stats mstore. It prepares the store, and calls sub-handlers
 * to collect all the stats.
 */
static int castle_stats_writeback(void)
{
    c_mstore_t *stats_store;

    /* Initialise the store. */
    stats_store = castle_mstore_init(MSTORE_STATS);
    if(!stats_store)
        return -ENOMEM;

    /* Writeback extent stats. */
    castle_extents_stats_writeback(stats_store);

    /* Close mstore. */
    castle_mstore_fini(stats_store);

    return 0;
}

/**
 * Reads all stats from stats mstore, and, depending on stat type calls appropriate consumer.
 * At the moment only used for rebuild progress counter.
 */
int castle_stats_read(void)
{
    struct castle_mstore_iter *iterator;

    castle_printk(LOG_INFO, "Opening mstore for stats\n");

    /* Create the iterator for the mstore. */
    iterator = castle_mstore_iterate(MSTORE_STATS);
    if(!iterator)
        return -EINVAL;

    /* Iterate through all entries. */
    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_slist_entry mstore_entry;
        size_t mstore_entry_size;

        castle_mstore_iterator_next(iterator, &mstore_entry, &mstore_entry_size);
        BUG_ON(mstore_entry_size != sizeof(struct castle_slist_entry));

        /* Handle each entry appropriately. */
        switch(mstore_entry.stat_type)
        {
            case STATS_MSTORE_REBUILD_PROGRESS:
                castle_extents_stat_read(&mstore_entry);
                break;
            default:
                castle_printk(LOG_ERROR, "Unknown mstore stat (%p), type=0x%x\n",
                        &mstore_entry, mstore_entry.stat_type);
                BUG();
                break;
        }
    }

    /* Cleanup. */
    castle_mstore_iterator_destroy(iterator);

    return 0;
}

int castle_mstores_writeback(uint32_t version, int is_fini)
{
    struct castle_fs_superblock *fs_sb;
    int    i;
    int    slot = version % 2;

    if (!castle_fs_inited)
        return 0;

    BUG_ON(atomic_read(&mstores_ref_cnt));

    /* Setup mstore for writeback. */
    fs_sb = castle_fs_superblocks_get();
    for(i=0; i<sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t ); i++)
        fs_sb->mstore[i] = INVAL_EXT_POS;
    castle_fs_superblocks_put(fs_sb, 1);

    castle_ext_freespace_init(&mstore_ext_free, MSTORE_EXT_ID + slot);

    /* Call writebacks of components. */
    castle_attachments_writeback();
    castle_double_arrays_writeback();

    FAULT(CHECKPOINT_FAULT);

    castle_versions_writeback(is_fini);
    castle_extents_writeback();
    castle_stats_writeback();

    BUG_ON(!castle_ext_freespace_consistent(&mstore_ext_free));
    castle_cache_extent_flush_schedule(MSTORE_EXT_ID + slot, 0,
                                       atomic64_read(&mstore_ext_free.used));

    return 0;
}
