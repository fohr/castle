#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/random.h>
#include <linux/delay.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_rda.h"
#include "castle_freespace.h"
#include "castle_extent.h"
#include "castle_cache.h"
#include "castle_da.h"
#include "castle_rebuild.h"
#include "castle_events.h"

/* Extent manager - Every disk reserves few chunks in the begining of the disk to
 * store meta data. Meta data for freespace management (for each disk) would be
 * stored only on specific disk. Meta data for extent management is stored
 * across multiple disks. This meta data is stored in terms of special extents.
 *
 * Super Extent - One for each disk. Located on initial chunks [SUP_EXT_SIZE] for
 * each disk. First chunk contains super block. Next subsequent chunks contain the
 * freespace data structures.
 *
 * Micro Extent - Contains mappings for meta extent. Replicated on all disks.
 *
 * Meta Extent - One extent for the complete system to store extent manager's
 * structures i.e. extent strcuture and chunk mappings. This extent is spread
 * and replicated across all disks to reduce the riscue of failure. Meta data of
 * this extent is stored on all disks (in Super extent).
 */

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

#define MAP_IDX(_ext, _i, _j)       (((_ext)->k_factor * _i) + _j)
#define CASTLE_EXTENTS_HASH_SIZE    100

#define CONVERT_MENTRY_TO_EXTENT(_ext, _me)                                 \
        (_ext)->ext_id      = (_me)->ext_id;                                \
        (_ext)->size        = (_me)->size;                                  \
        (_ext)->type        = (_me)->type;                                  \
        (_ext)->k_factor    = (_me)->k_factor;                              \
        (_ext)->maps_cep    = (_me)->maps_cep;                              \
        (_ext)->curr_rebuild_seqno = (_me)->curr_rebuild_seqno;             \
        (_ext)->ext_type    = (_me)->ext_type;                              \
        (_ext)->da_id       = (_me)->da_id;

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->curr_rebuild_seqno = (_ext)->curr_rebuild_seqno;             \
        (_me)->ext_type     = (_ext)->ext_type;                             \
        (_me)->da_id        = (_ext)->da_id;

#define FAULT_CODE EXTENT_FAULT

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_superblock castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

static int castle_extents_exiting = 0;

typedef struct castle_extent {
    c_ext_id_t          ext_id;         /* Unique extent ID                             */
    c_chk_cnt_t         size;           /* Number of chunks                             */
    c_rda_type_t        type;           /* RDA type                                     */
    uint32_t            k_factor;       /* K factor in K-RDA                            */
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent    */
    struct list_head    hash_list;
    struct list_head    rebuild_list;
    struct list_head    verify_list;    /* Used for testing.                            */
    uint32_t            curr_rebuild_seqno;
    spinlock_t          shadow_map_lock;
    c_disk_chk_t        *shadow_map;
    int                 use_shadow_map; /* Extent is currently being remapped           */
    atomic_t            ref_cnt;
    uint8_t             alive;
    c_ext_dirtytree_t  *dirtytree;      /**< RB-tree of dirty c2bs.                     */
    struct work_struct *work;           /**< work structure to schedule extent free.    */
    uint8_t             deleted;        /**< Marked when an extent is not refrenced by
                                             anybody anymore. Safe to free it now.      */
    c_ext_type_t        ext_type;       /**< Type of extent.                            */
    c_da_t              da_id;          /**< DA that extent corresponds to.             */
} c_ext_t;

static struct list_head *castle_extents_hash = NULL;
static c_ext_free_t meta_ext_free;

/**
 * Low freespace victim handling structure.
 */
typedef struct c_ext_event {
    c_ext_event_callback_t  callback;              /**< Callback to be called when more
                                                     *< disk space is available.          */
    void                   *data;
    struct list_head        list;
} c_ext_event_t;

static c_ext_id_t _castle_extent_alloc(c_rda_type_t   rda_type,
                                       c_da_t         da_id,
                                       c_ext_type_t   ext_type,
                                       c_chk_cnt_t    count,
                                       c_ext_id_t     ext_id,
                                       c_ext_event_t *hdl);
void __castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree, int check_hash);

DEFINE_HASH_TBL(castle_extents, castle_extents_hash, CASTLE_EXTENTS_HASH_SIZE,
                c_ext_t, hash_list, c_ext_id_t, ext_id);


c_ext_t sup_ext = {
    .ext_id         = SUP_EXT_ID,
    .size           = SUP_EXT_SIZE,
    .type           = SUPER_EXT,
    .k_factor       = 2,
    .maps_cep       = INVAL_EXT_POS,
};

uint8_t extent_init_done = 0;

static struct list_head     rebuild_list;
static struct list_head     verify_list; /* Used for testing. */
static wait_queue_head_t    rebuild_wq;
struct task_struct   *rebuild_thread;
static LIST_HEAD(castle_lfs_victim_list);

/*
 * A difference between current_rebuild_seqno and rebuild_to_seqno indicates that
 * current_rebuild_seqno has changed doing a rebuild. This can be due to a slave going
 * out-of-service or being evacuated. If a difference is discovered the rebuild is
 * restarted when it finishes it's current run to pick up and remap any extents that
 * have already been remapped to the (old) current_rebuild_seqno.
 */
atomic_t                    current_rebuild_seqno;/* The latest rebuild sequence number */
static int                  rebuild_to_seqno;     /* The sequence number being rebuilt to */

static int                  castle_extents_rescan_required = 0;

long                        castle_extents_chunks_remapped = 0;

static atomic_t             castle_extents_dead_count = ATOMIC(0);

uint32_t castle_rebuild_fs_version = 0;

/**
 * Allocate and initialise extent and per-extent dirtytree structures.
 */
static c_ext_t * castle_ext_alloc(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext)
        return NULL;
    ext->dirtytree = castle_zalloc(sizeof(c_ext_dirtytree_t), GFP_KERNEL);
    if (!ext->dirtytree)
    {
        castle_free(ext);
        return NULL;
    }

    /* Extent structure. */
    ext->ext_id             = ext_id;
    ext->alive              = 1;
    ext->deleted            = 0;
    ext->maps_cep           = INVAL_EXT_POS;
    ext->ext_type           = EXT_T_INVALID;
    ext->da_id              = INVAL_DA;
    ext->work               = NULL;
    atomic_set(&ext->ref_cnt, 1);
    spin_lock_init(&ext->shadow_map_lock);

    /* Per-extent RB dirtytree structure. */
    ext->dirtytree->ext_id  = ext_id;
    ext->dirtytree->ref_cnt = ATOMIC(1);
    ext->dirtytree->rb_root = RB_ROOT;
    INIT_LIST_HEAD(&ext->dirtytree->list);
    spin_lock_init(&ext->dirtytree->lock);

    debug("Allocated extent ext_id=%lld.\n", ext->ext_id);

    return ext;
}

static int castle_extent_print(c_ext_t *ext, void *unused)
{
    debug("Print   Extent   %llu\n", ext->ext_id);
    debug("        Size     %u chunks\n", ext->size);
    debug("        Maps at  "cep_fmt_str_nl, cep2str(ext->maps_cep));

    return 0;
}

void castle_extent_mark_live(c_ext_id_t ext_id, c_da_t da_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
    {
        /* Extent should belong to the same DA. */
        BUG_ON(ext->da_id != da_id);
        ext->alive = 1;
    }
}

int castle_extents_init(void)
{
    debug("Initing castle extents\n");

    /* Initialise hash table for extents. */
    castle_extents_hash = castle_extents_hash_alloc();
    if (!castle_extents_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        goto err_out;
    }
    castle_extents_hash_init();

    return EXIT_SUCCESS;

err_out:
    return -ENOMEM;
}

/* Cleanup all extents from hash table. Called at finish. */
static int castle_extent_hash_remove(c_ext_t *ext, void *unused)
{
    debug("Freeing extent #%llu\n", ext->ext_id);

    BUG_ON(atomic_read(&ext->ref_cnt) != 1);
    /* There shouldn't be any outstanding extents for deletion on exit. */
    BUG_ON(ext->deleted);
    __castle_extents_hash_remove(ext);

    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs =
                castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));

        castle_free(cs->sup_ext_maps);
    }
    __castle_extent_dirtytree_put(ext->dirtytree, 0 /*check_hash*/);
    if(ext->work)
        castle_free(ext->work);
    castle_free(ext);

    return 0;
}

static void castle_extents_super_block_init(void)
{
    castle_extents_global_sb.ext_id_seq           = EXT_SEQ_START;
    castle_extents_global_sb.nr_exts              = 0;
    castle_extents_global_sb.micro_ext.ext_id     = INVAL_EXT_ID;
    castle_extents_global_sb.meta_ext.ext_id      = INVAL_EXT_ID;
    castle_extents_global_sb.mstore_ext[0].ext_id = INVAL_EXT_ID;
    castle_extents_global_sb.mstore_ext[1].ext_id = INVAL_EXT_ID;
}

static void castle_extents_super_block_read(void)
{
    struct castle_fs_superblock *sblk;

    BUG_ON(!castle_extent_in_transaction());

    sblk = castle_fs_superblocks_get();
    memcpy(&castle_extents_global_sb, &sblk->extents_sb,
           sizeof(struct castle_extents_superblock));
    castle_fs_superblocks_put(sblk, 0);
}

static void castle_extents_super_block_writeback(void)
{ /* Should be called with castle_extents_mutex held. */
    struct castle_fs_superblock *sblk;

    sblk = castle_fs_superblocks_get();

    memcpy(&sblk->extents_sb, &castle_extents_global_sb,
           sizeof(struct castle_extents_superblock));

    castle_fs_superblocks_put(sblk, 1);

    INJECT_FAULT;
}

/**
 * Start an extent transaction. An extent transaction makes sure that all extent operations in
 * transaction are atomic.
 */
void castle_extent_transaction_start(void)
{
    mutex_lock(&castle_extents_mutex);
}

/**
 * End the extent transaction.
 */
void castle_extent_transaction_end(void)
{
    mutex_unlock(&castle_extents_mutex);
}

int castle_extent_in_transaction(void)
{
    return mutex_is_locked(&castle_extents_mutex);
}

/**
 * Get global extent superblock. Dont try to get mutex. Function is called with mutex.
 */
struct castle_extents_superblock* _castle_extents_super_block_get(void)
{
    return &castle_extents_global_sb;
}

struct castle_extents_superblock* castle_extents_super_block_get(void)
{
    /* Doesn't make sense to get superblock without being in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    return &castle_extents_global_sb;
}

/**
 * Adds a new slave into the micro_maps. Used during claims after fs init.
 *
 * @param cs    The slave to add to the micro extent maps
 */
void castle_extent_micro_ext_update(struct castle_slave * cs)
{
    c_ext_t * micro_ext;
    struct castle_extents_superblock *castle_extents_sb;
    c_disk_chk_t *micro_maps;
    c2_block_t *c2b;
    c_ext_pos_t cep;

    micro_ext = castle_extent_get(MICRO_EXT_ID);
    BUG_ON(!micro_ext || (micro_ext->size > 1));

    /* Read in the micro extent using the old micro map. */
    cep.ext_id = MICRO_EXT_ID;
    cep.offset = 0;

    c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
    write_lock_c2b(c2b);
    if(!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));

    /* Update the micro map to include the new slave. */
    castle_extent_transaction_start();

    castle_extents_sb = castle_extents_super_block_get();
    micro_maps = castle_extents_sb->micro_maps;

    micro_maps[micro_ext->k_factor].slave_id = cs->uuid;
    micro_maps[micro_ext->k_factor].offset   = MICRO_EXT_START;
    micro_ext->k_factor++;

    castle_extent_transaction_end();

    /* Write out the micro extent using the updated micro map. */
    dirty_c2b(c2b);
    BUG_ON(submit_c2b_sync(WRITE, c2b));
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    castle_extent_put(MICRO_EXT_ID);
}

static int castle_extent_micro_ext_create(void)
{
    struct castle_extents_superblock *castle_extents_sb = castle_extents_super_block_get();
    c_disk_chk_t *micro_maps = castle_extents_sb->micro_maps;
    c_ext_t *micro_ext;
    struct list_head *l;
    int i = 0;

    BUG_ON(!castle_extent_in_transaction());

    micro_ext = castle_ext_alloc(MICRO_EXT_ID);
    if (!micro_ext)
        return -ENOMEM;

    micro_ext->size     = MICRO_EXT_SIZE;
    micro_ext->type     = MICRO_EXT;
    micro_ext->ext_type = EXT_T_META_DATA;
    micro_ext->da_id    = 0;
    micro_ext->maps_cep = INVAL_EXT_POS;

    memset(micro_maps, 0, sizeof(castle_extents_sb->micro_maps));
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        /* Don't add maps for ghost slaves. */
        if (test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags))
            continue;

        BUG_ON(MICRO_EXT_SIZE != 1);

        micro_maps[i].slave_id = cs->uuid;
        micro_maps[i].offset   = MICRO_EXT_START;
        i++;
    }
    rcu_read_unlock();
    BUG_ON(i > MAX_NR_SLAVES);
    micro_ext->k_factor = i;
    CONVERT_EXTENT_TO_MENTRY(micro_ext, &castle_extents_sb->micro_ext);
    castle_extents_hash_add(micro_ext);

    return 0;
}

static int castle_extent_meta_ext_create(void)
{
    int k_factor = (castle_rda_spec_get(META_EXT))->k_factor, i = 0;
    struct castle_extents_superblock *castle_extents_sb;
    struct list_head *l;
    c_ext_t *meta_ext;
    c_ext_id_t ext_id;

    BUG_ON(!castle_extent_in_transaction());

    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
        i++;
    rcu_read_unlock();

    /* Allocate meta extent size to be however much we allocated in all the
       slaves, divided by the k-factor (2) */
    meta_ext_size = META_SPACE_SIZE * MAX_NR_SLAVES / k_factor;

    ext_id = _castle_extent_alloc(META_EXT, 0,
                                  EXT_T_META_DATA,
                                  meta_ext_size,
                                  META_EXT_ID,
                                  NULL);
    if (ext_id != META_EXT_ID)
    {
        castle_printk(LOG_WARN, "Meta Extent Allocation Failed\n");
        return -ENOSPC;
    }

    castle_extents_sb = castle_extents_super_block_get();
    meta_ext = castle_extents_hash_get(META_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(meta_ext, &castle_extents_sb->meta_ext);

    debug("Done with intialization of meta extent mappings\n");

    return 0;
}

static int castle_extent_mstore_ext_create(void)
{
    struct   list_head *l;
    int      i = 0;
    c_ext_t *mstore_ext;
    struct   castle_extents_superblock *castle_extents_sb;
    c_ext_id_t ext_id;
    int      k_factor = (castle_rda_spec_get(DEFAULT_RDA))->k_factor;

    BUG_ON(!castle_extent_in_transaction());

    i = 0;
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
        i++;
    rcu_read_unlock();

    ext_id = _castle_extent_alloc(DEFAULT_RDA, 0,
                                  EXT_T_META_DATA,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID,
                                  NULL);
    if (ext_id != MSTORE_EXT_ID)
        return -ENOSPC;

    ext_id = _castle_extent_alloc(DEFAULT_RDA, 0,
                                  EXT_T_META_DATA,
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID+1,
                                  NULL);
    if (ext_id != MSTORE_EXT_ID+1)
        return -ENOSPC;

    castle_extents_sb = castle_extents_super_block_get();

    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[0]);
    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID+1);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[1]);

    return 0;
}

int castle_extents_create(void)
{
    int ret = 0;

    BUG_ON(extent_init_done);

    castle_extent_transaction_start();

    castle_extents_super_block_init();

    if ((ret = castle_extent_micro_ext_create()))
        goto out;

    if ((ret = castle_extent_meta_ext_create()))
        goto out;

    castle_ext_freespace_init(&meta_ext_free, META_EXT_ID);

    INJECT_FAULT;

    if ((ret = castle_extent_mstore_ext_create()))
        goto out;

    extent_init_done = 1;

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Inserts all extent stats into the stats mstore. At the moment just the rebulid progress counter.
 */
void castle_extents_stats_writeback(c_mstore_t *stats_mstore)
{
    struct castle_slist_entry mstore_entry;

    mstore_entry.stat_type = STATS_MSTORE_REBUILD_PROGRESS;
    mstore_entry.key = -1;
    mstore_entry.val = castle_extents_chunks_remapped;

    castle_mstore_entry_insert(stats_mstore, &mstore_entry);
}

/**
 * Reads extent stats. At the moment just a single entry of STATS_MSTORE_REBUILD_PROGRESS expected.
 */
void castle_extents_stat_read(struct castle_slist_entry *mstore_entry)
{
    BUG_ON(mstore_entry->stat_type != STATS_MSTORE_REBUILD_PROGRESS);
    BUG_ON(mstore_entry->key != (uint64_t)-1);

    /* Temporarily high logging level. */
    castle_printk(LOG_INFO,
                  "Read %lld chunks remapped from mstore.\n",
                  mstore_entry->val);
    castle_extents_chunks_remapped += mstore_entry->val;
}

int nr_exts = 0;

/* @TODO who should handle errors in writeback? */
static int castle_extent_writeback(c_ext_t *ext, void *store)
{
    struct castle_elist_entry mstore_entry;
    c_mstore_t *castle_extents_mstore = store;

    /* Shouldnt be any outstanding deletions before last checkpoint. */
    BUG_ON(castle_extents_exiting && ext->deleted);

    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    debug("Writing back extent %llu\n", ext->ext_id);

    CONVERT_EXTENT_TO_MENTRY(ext, &mstore_entry);

    read_unlock_irq(&castle_extents_hash_lock);
    castle_mstore_entry_insert(castle_extents_mstore, &mstore_entry);
    read_lock_irq(&castle_extents_hash_lock);

    nr_exts++;

    INJECT_FAULT;
    return 0;
}

int castle_extents_writeback(void)
{
    struct castle_extents_superblock *ext_sblk;
    c_mstore_t *castle_extents_mstore = NULL;

    if (!extent_init_done)
        return 0;

    /* Don't exit with out-standing dead extents. They are scheduled to get freed on
     * system work queue. */
    if (castle_extents_exiting)
        while (atomic_read(&castle_extents_dead_count))
            msleep_interruptible(1000);

    castle_extents_mstore =
        castle_mstore_init(MSTORE_EXTENTS, sizeof(struct castle_elist_entry));
    if(!castle_extents_mstore)
        return -ENOMEM;

    castle_extent_transaction_start();

    /* Note: This is important to make sure, nothing changes in extents. And
     * writeback() relinquishes hash spin_lock() while doing writeback. */
    ext_sblk = castle_extents_super_block_get();
    /* Writeback new copy. */
    nr_exts = 0;
    castle_extents_hash_iterate(castle_extent_writeback, castle_extents_mstore);

    if (ext_sblk->nr_exts != nr_exts)
    {
        castle_printk(LOG_ERROR, "%llx:%x\n", ext_sblk->nr_exts, nr_exts);
        BUG();
    }

    castle_mstore_fini(castle_extents_mstore);

    /* Writeback maps freespace structure into extent superblock. */
    castle_ext_freespace_marshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    /* Flush micro extent. */
    castle_cache_extent_flush_schedule(MICRO_EXT_ID, 0, 0);

    /* Flush the complete meta extent onto disk, before completing writeback. */
    BUG_ON(!castle_ext_freespace_consistent(&meta_ext_free));
    castle_cache_extent_flush_schedule(META_EXT_ID, 0,
                                       atomic64_read(&meta_ext_free.used));

    INJECT_FAULT;

    /* It is important to complete freespace_writeback() under extent lock, to
     * make sure freesapce and extents are in sync. */
    castle_freespace_writeback();

    castle_extents_super_block_writeback();

    castle_extent_transaction_end();

    return 0;
}

static int load_extent_from_mentry(struct castle_elist_entry *mstore_entry)
{
    c_ext_t *ext = NULL;
    int ret;

    /* Load micro extent. */
    ext = castle_ext_alloc(mstore_entry->ext_id);
    if (!ext)
    {
        ret = -ENOMEM;
        goto err1;
    }

    CONVERT_MENTRY_TO_EXTENT(ext, mstore_entry);
    if (EXT_ID_INVAL(ext->ext_id))
    {
        ret = -EINVAL;
        goto err2;
    }

    castle_extents_hash_add(ext);
    castle_extent_print(ext, NULL);

    return 0;

err2:
    castle_free(ext->dirtytree);
    castle_free(ext);
err1:
    return ret;
}

int castle_extents_read(void)
{
    int ret = EXIT_SUCCESS;

    struct castle_extents_superblock *ext_sblk = NULL;

    BUG_ON(extent_init_done);

    castle_extent_transaction_start();

    castle_extents_super_block_read();

    castle_extent_micro_ext_create();

    ext_sblk = castle_extents_super_block_get();

    /* Read maps freespace structure from extents superblock. */
    castle_ext_freespace_unmarshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    if ((ret = load_extent_from_mentry(&ext_sblk->meta_ext)))
        goto out;

    if ((ret = load_extent_from_mentry(&ext_sblk->mstore_ext[0])))
        goto out;

    if ((ret = load_extent_from_mentry(&ext_sblk->mstore_ext[1])))
        goto out;

    atomic_set(&current_rebuild_seqno, ext_sblk->current_rebuild_seqno);

    /* Mark Logical extents as alive. */
    castle_extent_mark_live(MICRO_EXT_ID, 0);
    castle_extent_mark_live(META_EXT_ID, 0);
    castle_extent_mark_live(MSTORE_EXT_ID, 0);
    castle_extent_mark_live(MSTORE_EXT_ID+1, 0);
    meta_ext_size = castle_extent_size_get(META_EXT_ID);
    extent_init_done = 1;

out:
    castle_extent_transaction_end();
    return ret;
}

int castle_extents_read_complete(void)
{
    struct castle_elist_entry mstore_entry;
    struct castle_extents_superblock *ext_sblk = NULL;
    struct castle_mstore_iter *iterator = NULL;
    c_mstore_t *castle_extents_mstore = NULL;
    c_mstore_key_t key;

    castle_extents_mstore =
        castle_mstore_open(MSTORE_EXTENTS, sizeof(struct castle_elist_entry));
    if(!castle_extents_mstore)
        return -ENOMEM;

    castle_extent_transaction_start();

    nr_exts = 0;
    iterator = castle_mstore_iterate(castle_extents_mstore);
    if (!iterator)
        goto error_out;

    while (castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_entry, &key);

        BUG_ON(LOGICAL_EXTENT(mstore_entry.ext_id));
        if (load_extent_from_mentry(&mstore_entry))
            goto error_out;

        nr_exts++;
    }
    castle_mstore_iterator_destroy(iterator);
    castle_mstore_fini(castle_extents_mstore);

    ext_sblk = castle_extents_super_block_get();
    BUG_ON(ext_sblk->nr_exts != nr_exts);

    INJECT_FAULT;

    castle_extent_transaction_end();

    return 0;

error_out:
    if (iterator)               castle_mstore_iterator_destroy(iterator);
    if (castle_extents_mstore)  castle_mstore_fini(castle_extents_mstore);

    castle_extent_transaction_end();

    return -1;
}

void castle_extents_fini(void)
{
    /* Make sure cache flushed all dirty pages */
    /* Iterate over extents hash with exclusive access. Indeed, we don't need a
     * lock here as this happenes in the module end. */
    castle_extents_hash_iterate_exclusive(castle_extent_hash_remove, NULL);
    castle_free(castle_extents_hash);
}

#define MAX_K_FACTOR   4
struct castle_extent_state {
    c_ext_t *ext;
    c_chk_t  chunks[MAX_NR_SLAVES][MAX_K_FACTOR];
};

#define map_chks_per_page(_k_factor)    (PAGE_SIZE / (_k_factor * sizeof(c_disk_chk_t)))
#define map_size(_ext_chks, _k_factor)  (1 + (_ext_chks-1) / map_chks_per_page(_k_factor))

/**
 * Allocates structure used during the extent allocation/destruction in order to
 * maintain the active set of superchunks. Initialises this structure appropriately.
 *
 * @param ext   Extent to allocate/destroy.
 */
static struct castle_extent_state *castle_extent_state_alloc(c_ext_t *ext)
{
    struct castle_extent_state *ext_state;
    int i, j;

    ext_state = castle_malloc(sizeof(struct castle_extent_state), GFP_KERNEL);
    if(!ext_state)
        return NULL;

    ext_state->ext = ext;
    for(i=0; i<MAX_NR_SLAVES; i++)
        for(j=0; j<MAX_K_FACTOR; j++)
            ext_state->chunks[i][j] = INVAL_CHK;

    return ext_state;
}

/**
 * Frees specified number of disk chunks allocated to the specified extent. Called when destroying
 * extents, or during failed allocations, to return already allocated disk space.
 *
 * @param ext   Extent to free the disk space for.
 * @param count Number of chunks to free.
 *
 * @FIXME Cannot handle kmalloc failure. We should retry freeing extent freespace,
 * once memory becomes available.
 */
static void castle_extent_space_free(c_ext_t *ext, c_chk_cnt_t count)
{
    c_chk_cnt_t                 chks_per_page;
    c_ext_pos_t                 map_cep;
    c2_block_t                  *map_c2b;
    c_disk_chk_t                *map_buf;
    struct castle_slave         *cs;

    debug("Freeing %d disk chunks from extent %lld\n", count, ext->ext_id);
    chks_per_page = map_chks_per_page(ext->k_factor);

    map_cep = ext->maps_cep;
    debug("Map at cep: "cep_fmt_str_nl, cep2str(map_cep));
    while(count>0)
    {
        c_chk_cnt_t logical_chunks, logical_chunk;

        /* Get page-worth of extent map. */
        debug("Processing map page at cep: "cep_fmt_str_nl, cep2str(map_cep));
        map_c2b = castle_cache_page_block_get(map_cep);
        write_lock_c2b(map_c2b);
        if(!c2b_uptodate(map_c2b))
            BUG_ON(submit_c2b_sync(READ, map_c2b));
        map_buf = c2b_buffer(map_c2b);

        /* Work out how many logical chunks (in the extent space) to free. */
        logical_chunks = (count > chks_per_page * ext->k_factor) ?
                            chks_per_page :
                            (count - 1) / ext->k_factor + 1;
        /* For each logical chunk, look through each copy. */
        for( logical_chunk=0; (logical_chunk<chks_per_page) && (count > 0); logical_chunk++)
        {
            int copy;
            for(copy=0; (copy<ext->k_factor) && (count > 0); copy++)
            {
#define SUPER_CHUNK_STRUCT(chk_idx)  ((c_chk_seq_t){chk_idx, CHKS_PER_SLOT})
                cs = castle_slave_find_by_uuid(
                    map_buf[logical_chunk*ext->k_factor + copy].slave_id);
                if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                {
                    if (map_buf[logical_chunk * ext->k_factor + copy].offset % CHKS_PER_SLOT == 0)
                    {
                        /* If chunk is super chunk aligned, free that superchunk. */
                        debug("Freeing superchunk: "disk_chk_fmt", from ext_id: %lld\n",
                            disk_chk2str(map_buf[logical_chunk * ext->k_factor + copy]),
                                         ext->ext_id);
                        castle_freespace_slave_superchunk_free(cs,
                            SUPER_CHUNK_STRUCT(map_buf[logical_chunk * ext->k_factor + copy].offset));
                    }
                }
                count--;
            }
        }

        /* We are done with maps. No need of flushing maps onto disk anymore. Mark them clean. */
        if (c2b_dirty(map_c2b))
            clean_c2b(map_c2b);

        write_unlock_c2b(map_c2b);

        /* Destroy maps c2b. dont need this anymore. */
        /* Ignore we if we fail to destroy - perhaps flush thread or checkpointing thread is
         * accessing it. */
        if (castle_cache_block_destroy(map_c2b))
            castle_printk(LOG_WARN, "Failed to destroy c2b for cep "cep_fmt_str_nl,
                    cep2str(map_cep));

        map_cep.offset += C_BLK_SIZE;
    }
}

/**
 * Allocates disk chunks for particular extent (specified by the extent state struct).
 * Allocates chunks from the specified slave, takes the copy id into account, to make sure
 * continous reads perform well. Gets superchunks from the freespace periodically, and
 * chops them up into individual chunks.
 *
 * @param da_id     Doubling array id for which the extent is to be allocated.
 * @param slave     Disk slave to allocate disk chunk from.
 * @param copy_id   Which copy in the k-RDA set we are trying to allocate.
 * @param token     Reservation token, required to allocate freespace.
 */
static c_disk_chk_t castle_extent_disk_chk_alloc(c_da_t da_id,
                                                 struct castle_extent_state *ext_state,
                                                 struct castle_slave *slave,
                                                 int copy_id,
                                                 struct castle_freespace_reservation *token)
{
    c_disk_chk_t disk_chk;
    c_chk_seq_t chk_seq;
    c_chk_t *chk;

    disk_chk = INVAL_DISK_CHK;
    disk_chk.slave_id = slave->uuid;
    /* Work out which chunk sequence we are using. */
    chk = &ext_state->chunks[slave->id][copy_id];
    debug("*chk: %d/0x%x\n", *chk, *chk);
    /* If we've got some chunks left in our cache, return one from there. */
    if(!CHK_INVAL(*chk))
    {
        disk_chk.offset = *chk;
        *chk = *chk + 1;
        /* If we've run out of the superchunk, set the chunk to invalid. */
        if(SUPER_CHUNK(*chk) != SUPER_CHUNK(disk_chk.offset))
            *chk = INVAL_CHK;

        return disk_chk;
    }
    /* If we got here, we need to allocate a new superchunk. */
    chk_seq = castle_freespace_slave_superchunk_alloc(slave, da_id, token);
    if (CHK_SEQ_INVAL(chk_seq))
    {
        /*
         * We get here if the slave is either out-or-service, or out of space. If the slave is
         * out-of-service then just return INVAL_DISK_CHK so calling stack can retry.
         */
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags)) && (!(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)))
        {
            /* Slave is not out-of-service so we are out of space.  */
            castle_printk(LOG_WARN, "Failed to get freespace from slave: 0x%x\n", slave->uuid);
            castle_freespace_stats_print();
        }
        return INVAL_DISK_CHK;
    }
    /* Chunk sequence must represent a single superchunk. */
    BUG_ON(chk_seq.count != CHKS_PER_SLOT);

    debug("Allocated disk superchunk: %d, for extent: %lld\n",
            chk_seq.first_chk, ext_state->ext->ext_id);
    disk_chk.offset = chk_seq.first_chk;
    *chk = chk_seq.first_chk + 1;

    return disk_chk;
}

/**
 * Gets location of the map for given chunk, given the start of the map, and k_factor.
 *
 * @param map_start     Location of the start of the map (usually in the meta extent).
 * @param chk_idx       Which chunk is the map location requested for.
 * @param k_factor      K-factor of the RDA scheme used by the particular extent.
 */
static inline c_ext_pos_t castle_extent_map_cep_get(c_ext_pos_t map_start,
                                                    c_chk_t chk_idx,
                                                    uint32_t k_factor)
{
    c_chk_t chks_per_page;

    /* Work out how many chunks fit in one page. */
    chks_per_page = map_chks_per_page(k_factor);
    map_start.offset += PAGE_SIZE * (chk_idx / chks_per_page);
    map_start.offset += k_factor * sizeof(c_disk_chk_t) * (chk_idx % chks_per_page);

    return map_start;
}

/**
 * Allocates disk space for given extent.
 *
 * @param ext   Extent to allocate the space for.
 * @param da_id Doubling array ID.
 *
 * @return -ENOMEM: Could not allocate memory for state structure.
 * @return -EINVAL: RDA spec failed to initialise.
 * @return -ENOSPC: Not enough disk space left to create this extent (for the particular set of
 *                  slaves chosen by the RDA spec).
 * @return  0:      Success.
 */
int castle_extent_space_alloc(c_ext_t *ext, c_da_t da_id)
{
    struct castle_extent_state *ext_state;
    struct castle_freespace_reservation *reservation_token;
    struct castle_slave *slaves[ext->k_factor];
    int schk_ids[ext->k_factor];
    c_rda_spec_t *rda_spec;
    c_chk_cnt_t chunk;
    void *rda_state;
    c_ext_pos_t map_cep;
    c2_block_t *map_c2b;
    c_disk_chk_t disk_chk, *map_page;
    int map_page_idx, max_map_page_idx, err, j;

    BUG_ON(LOGICAL_EXTENT(ext->ext_id) && (ext->ext_id < META_EXT_ID));

    /* Initialise all the variables checked in the out: block. */
    map_c2b = NULL;
    rda_state = NULL;
    ext_state = NULL;

    /* Get the RDA spec structure. */
    rda_spec = castle_rda_spec_get(ext->type);
    BUG_ON(rda_spec->k_factor != ext->k_factor);
    /* Initialise our own state first. */
    ext_state = castle_extent_state_alloc(ext);
    if(!ext_state)
    {
        castle_printk(LOG_WARN, "Couldn't malloc extent allocation structure.\n");
        err = -ENOMEM;
        goto out;
    }
    /* Initialise the RDA spec state. */
    rda_state = rda_spec->extent_init(ext->ext_id, ext->size, ext->type);
    if (!rda_state)
    {
        debug("Couldn't initialise RDA state.\n");
        /* FIXME: It is also possible that the error is -ENOMEM. */
        err = -ENOSPC;
        goto out;
    }

    debug("Allocating physical space for extent: %lld, k_factor: %d\n", ext->ext_id, ext->k_factor);
    /* Get k_factor disk chunks for each logical chunk, and save them in the meta extent. */
    max_map_page_idx = map_chks_per_page(ext->k_factor);

retry:
    map_cep = ext->maps_cep;
    map_page_idx = max_map_page_idx;
    map_page = NULL;
    map_c2b = NULL;
    for(chunk=0; chunk<ext->size; chunk++)
    {
        debug("Map_page_idx: %d/%d\n", map_page_idx, max_map_page_idx);
        /* Move to the next map page, once the index overflows the max. */
        if(map_page_idx >= max_map_page_idx)
        {
            /* Release the previous map_c2b, if one exists. */
            if(map_c2b)
            {
                debug("Putting old map_c2b for cep: "cep_fmt_str_nl, cep2str(map_c2b->cep));
                dirty_c2b(map_c2b);
                write_unlock_c2b(map_c2b);
                put_c2b(map_c2b);
            }
            /* Get the next map_c2b. */
            debug("Getting map c2b, for cep: "cep_fmt_str_nl, cep2str(map_cep));
            map_c2b = castle_cache_page_block_get(map_cep);
            write_lock_c2b(map_c2b);
            update_c2b(map_c2b);
            /* Reset the index, and the map pointer. */
            map_page_idx = 0;
            map_page = c2b_buffer(map_c2b);
            /* Advance the map cep. */
            map_cep.offset += C_BLK_SIZE;
        }

        /* Ask the RDA spec which slaves to use. */
        if (rda_spec->next_slave_get( slaves,
                                      schk_ids,
                                     &reservation_token,
                                      rda_state,
                                      chunk) < 0)
        {
            castle_printk(LOG_WARN, "Failed to get next slave for extent: %llu\n", ext->ext_id);
            err = -ENOSPC;
            goto out;
        }

        /* Allocate disk chunks from each slave designated by the rda spec. */
        for (j=0; j<ext->k_factor; j++)
        {
            disk_chk = castle_extent_disk_chk_alloc(da_id,
                                                    ext_state,
                                                    slaves[j],
                                                    schk_ids[j],
                                                    reservation_token);
            debug("Allocation for (logical_chunk=%d, copy=%d) -> (slave=0x%x, "disk_chk_fmt")\n",
                chunk, j, slaves[j]->uuid, disk_chk2str(disk_chk));
            if(DISK_CHK_INVAL(disk_chk))
            {
                debug("Invalid disk chunk, freeing the extent.\n");
                /* Release map c2b, so that castle_extent_space_free() can use it. */
                dirty_c2b(map_c2b);
                write_unlock_c2b(map_c2b);
                put_c2b(map_c2b);
                map_c2b = NULL;
                castle_extent_space_free(ext, ext->k_factor * chunk + j);
                if (test_bit(CASTLE_SLAVE_OOS_BIT, &slaves[j]->flags))
                    /*
                     * The slave went out-of-service since the 'next_slave_get'. Retry, and the
                     * next time around the slave should be excluded from the map.
                     */
                    goto retry;
                err = -ENOSPC;
                goto out;
            }
            /* Save the disk chunk in the map. */
            map_page[ext->k_factor * map_page_idx + j] = disk_chk;
        }
        map_page_idx++;
    }
    /* Succeeded alocating everything. */
    err = 0;

out:
    if(map_c2b)
    {
        dirty_c2b(map_c2b);
        write_unlock_c2b(map_c2b);
        put_c2b(map_c2b);
    }
    if(rda_state)
        rda_spec->extent_fini(ext->ext_id, rda_state);
    if(ext_state)
        castle_free(ext_state);

    return err;
}

/**
 * Allocate an extent.
 *
 * @param rda_type      [in]    RDA algorithm to be used.
 * @param da_id         [in]    Double-Array that this extent belongs to.
 * @param ext_type      [in]    Type of data, that will be stored in extent.
 * @param count         [in]    Size of extent (in chunks). Extent could occupy more space
 *                              than this, depends on RDA algorithm and freespace algos.
 * @param in_tran       [in]    Already in the extent transaction.
 * @param data          [in]    Data to be used in event handler.
 * @param callback      [in]    Extent Event handler. Current events are just low space events.
 *
 * @return Extent ID.
 *
 * @also _castle_extent_alloc
 */
c_ext_id_t castle_extent_alloc(c_rda_type_t             rda_type,
                               c_da_t                   da_id,
                               c_ext_type_t             ext_type,
                               c_chk_cnt_t              count,
                               int                      in_tran,
                               void                    *data,
                               c_ext_event_callback_t   callback)
{
    int ret = 0;
    c_ext_event_t *event_hdl = NULL;

    /* Either get both parameters or none. */
    BUG_ON((callback && !data) || (!callback && data));

    /* Allocate event handler structure and call low level extent alloc(). */
    if (callback)
    {
        event_hdl = castle_zalloc(sizeof(c_ext_event_t), GFP_KERNEL);

        if (!event_hdl)
            return INVAL_EXT_ID;

        event_hdl->callback = callback;
        event_hdl->data     = data;
    }

    /* If the caller is not already in transaction. start a transaction. */
    if (!in_tran)   castle_extent_transaction_start();

    ret = _castle_extent_alloc(rda_type, da_id, ext_type, count, INVAL_EXT_ID, event_hdl);

    /* End the transaction. */
    if (!in_tran)   castle_extent_transaction_end();

    return ret;
}

/**
 * Add the low freespace callback to the victim list.
 */
static void castle_extent_lfs_callback_add(c_ext_event_t *event_hdl)
{
    BUG_ON(!castle_extent_in_transaction());

    /* Add the victim handler to the list of handlers of specific type. This handler gets
     * called, when more space is available. */
    if (event_hdl)
    {
        /* Add to the end, to maintain FIFO. */
        list_add_tail(&event_hdl->list, &castle_lfs_victim_list);
    }
}

/**
 * Allocate a new extent.
 *
 * @param rda_type      [in]    RDA algorithm to be used.
 * @param da_id         [in]    Double-Array that this extent belongs to.
 * @param ext_type      [in]    Type of data, that will be stored in extent.
 * @param count         [in]    Size of extent (in chunks). Extent could occupy more space
 *                              than this, depends on RDA algorithm and freespace algos.
 * @param ext_id        [in]    Specify an extent ID, for logical extents. INVAL_EXT_ID for
 *                              normal extents.
 * @param event_hdl     [in]    Low space event handler structure.
 *
 * @return  Extent ID of the newly created extent.
 *
 * @also castle_extent_alloc
 * @also CONVERT_MENTRY_TO_EXTENT()
 * @also castle_extent_micro_ext_create()
 * @also castle_extent_sup_ext_init()
 */
static c_ext_id_t _castle_extent_alloc(c_rda_type_t     rda_type,
                                       c_da_t           da_id,
                                       c_ext_type_t     ext_type,
                                       c_chk_cnt_t      count,
                                       c_ext_id_t       ext_id,
                                       c_ext_event_t   *event_hdl)
{
    c_ext_t *ext = NULL;
    int ret = 0;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_extents_superblock *castle_extents_sb;

    BUG_ON(!castle_extent_in_transaction());
    BUG_ON(!extent_init_done && !LOGICAL_EXTENT(ext_id));

    /* ext_id would be passed only for logical extents and they musn't be in the hash. */
    BUG_ON(castle_extents_hash_get(ext_id));

    debug("Creating extent of size: %u\n", count);
    ext = castle_ext_alloc(0);
    if (!ext)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent\n");
        goto __hell;
    }
    castle_extents_sb       = castle_extents_super_block_get();

    ext->ext_id             = EXT_ID_INVAL(ext_id) ? castle_extents_sb->ext_id_seq : ext_id;
    ext->dirtytree->ext_id  = ext->ext_id;
    ext->size               = count;
    ext->type               = rda_type;
    ext->k_factor           = rda_spec->k_factor;
    ext->ext_type           = ext_type;
    ext->da_id              = da_id;
    ext->use_shadow_map     = 0;

    /* The rebuild sequence number that this extent starts off at */
    ext->curr_rebuild_seqno = atomic_read(&current_rebuild_seqno);

    /* Block aligned chunk maps for each extent. */
    if (ext->ext_id == META_EXT_ID)
    {
        ext->maps_cep.ext_id = MICRO_EXT_ID;
        ext->maps_cep.offset = 0;
    }
    else
    {
        uint32_t nr_blocks = map_size(count, rda_spec->k_factor);

        if (castle_ext_freespace_get(&meta_ext_free, (nr_blocks * C_BLK_SIZE), 0, &ext->maps_cep))
        {
            castle_printk(LOG_WARN, "Too big of an extent/crossing the boundry.\n");
            goto __hell;
        }
        debug("Allocated extent map at: "cep_fmt_str_nl, cep2str(ext->maps_cep));
    }

    if ((ret = castle_extent_space_alloc(ext, da_id)) == -ENOSPC)
    {
        debug("Extent alloc failed to allocate space for %u chunks\n", count);
        goto __low_space;
    }
    else if (ret < 0)
    {
        debug("Extent alloc failed for %u chunks\n", count);
        goto __hell;
    }

    /* Add extent and extent dirtylist to hash tables. */
    castle_extents_hash_add(ext);

    /*
     * If current_rebuild_seqno has changed, then the mappings for this extent may contain
     * out-of-service slaves. Set the rescan flag and kick the rebuild thread so that the extent
     * list is rescanned by the rebuild thread. This extent will then be remapped if required.
     */
    if (ext->curr_rebuild_seqno != atomic_read(&current_rebuild_seqno))
    {
        castle_extents_rescan_required = 1;
        wake_up(&rebuild_wq);
    }

    castle_extent_print(ext, NULL);

    if (EXT_ID_INVAL(ext_id))
    {
        castle_extents_sb->nr_exts++;
        castle_extents_sb->ext_id_seq++;
    }

    /* Extent allocation is SUCCESS. No need of event handler. Free it. */
    if (event_hdl)
        castle_free(event_hdl);

    return ext->ext_id;

__low_space:
    castle_printk(LOG_INFO, "Failed to create extent for DA: %u of type %s for %u chunks\n",
                  da_id,
                  castle_ext_type_str[ext_type],
                  count);
    /* Add the victim handler to the list of handlers of specific type. This handler gets
     * called, when more space is available. */
    castle_extent_lfs_callback_add(event_hdl);

__hell:
    if (ext)
    {
        castle_free(ext->dirtytree);
        castle_free(ext);
    }

    return INVAL_EXT_ID;
}


/**
 * Low freespace handling
 * === ========= ========
 *
 * Lewis notes from meeting:
 * ----- ----- ---- -------
 *
 * When a thread calls castle_extent_alloc() that fails it passes a work_struct to
 * the extent layer.  This work_struct might be a CB handler (which wakes another
 * thread up, etc.) or a full-blown function.
 *
 * When the extent layer has more freespace available for allocation it schedules
 * the work_structs which will retry their various allocations, potentially calling
 * back into the extent layer to requeue themselves if allocations still fail.
 *
 * By keeping the list of work items sensibly sorted we could fairly share access
 * to freespace as it becomes available.  Big non-atomic consumers (e.g.
 * castle_da_all_rwcts_create() which makes multiple small allocations) could be
 * scheduled in an atomic fashion and eventually bubble to the top of the CB list.
 * Atomic allocations would also bubble up but are less likely to fail as a result
 * of races from other threads.
 *
 * e.g.
 * a merge thread that failed to allocate an output extent would call into the
 * extent layer to be notified when more freespace is available.
 *
 * e.g.
 * a castle_da_rwct_create() that failed to allocate a T0 extent would call into
 * the extent layer to be notified when more freespace is available.  It would also
 * set the DA's frozen bit, preventing any further inserts until a new T0 could be
 * created.  [ could this frozen bit be per T0 RWCT? ]
 *
 * e.g.
 * castle_da_all_rwcts_create() fails to allocate an extent and calls into the
 * extent layer to be notified when more freespace is available.  It would set the
 * DA frozen bit, preventing further inserts.
 *
 * Design:
 * ------
 *
 * Every consumer of freespace that has failed to allocate would add itself to a list of
 * victims. And also registers a callback. All operations on this victim list are atomic.
 *
 * LIST_HEAD(castle_freespace_victim_list)
 *
 * When more freespace is available (checkpoints potentially release space), go through
 * victim list and runs callback function for each victim in sequence. Each victim can
 * also mark the priority.
 */

/**
 * Call low free space handlers of all victims. Stop if any of the handler fails.
 */
void castle_extent_lfs_victims_wakeup(void)
{
    struct list_head head;

    castle_extent_transaction_start();

    /* Take the snapshot of the list and clean it. */
    list_replace_init(&castle_lfs_victim_list, &head);

    castle_extent_transaction_end();

    /* Call each handler for each victim in sequence. */
    /* Note: Don't use list_for_each_safe as it is possible that someone else could be changing
     * the list. */
    while (!list_empty(&head))
    {
        c_ext_event_t *hdl = list_first_entry(&head, c_ext_event_t, list);
        int ret = 0;

        /* No need to call handlers in case module is exiting. No point of creating more extents
         * for components just before they die. */
        if (!castle_extents_exiting)
            ret = hdl->callback(hdl->data);

         /* Handled low free space successfully. Get rid of event handler. */
         list_del(&hdl->list);
         castle_free(hdl);

         /* Callback failed, add remaining callbacks back to the list and break. */
         if (ret)
         {
             if (!list_empty(&head))
             {
                castle_extent_transaction_start();
                list_append(&castle_lfs_victim_list, &head);
                castle_extent_transaction_end();
             }

             break;
         }
    }
}

void castle_extent_free(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    struct work_struct *work;
    if(!ext)
    {
        castle_printk(LOG_ERROR, "%s::cannot find ext with id %d.\n", __FUNCTION__, ext_id);
        BUG();
    }

    /* Allocate space for work structure, to be used to schedule castle_extent_free
     * onto work queue.
     * Only do it once (this function is often called just to put the reference,
     * and is therefore reentrant. For example from castle_ct_put() large object
     * scan).
     */
    if(!ext->work)
    {
        work = castle_malloc(sizeof(struct work_struct), GFP_KERNEL);
        /* Assign ext->work pointer atomically. */
        if(cmpxchg(&ext->work, NULL, work) != NULL)
        {
            castle_printk(LOG_WARN, "WARNING: Race in assigning ext->work ptr, ext=%p.\n", ext);
            castle_free(work);
            BUG_ON(!ext->work);
        }
    }

    if (!ext->work)
    {
        castle_printk(LOG_ERROR, "Failed to allocate memory for extent deletion structures -"
                                 " Not deleting extent\n");
        return;
    }
    castle_extent_put(ext_id);
}

/* Free the resources taken by extent. This function gets executed on system work queue.
 *
 * @param data void pointer to extent structure that to be freed.
 *
 * @also castle_extent_put
 * @also castle_extent_free
 */
static void _castle_extent_free(void *data)
{
    c_ext_t *ext = data;
    struct castle_extents_superblock *castle_extents_sb = NULL;
    c_ext_id_t ext_id = ext->ext_id;

    castle_extent_transaction_start();

    /* Reference count should be zero. */
    if (atomic_read(&ext->ref_cnt))
    {
        castle_printk(LOG_ERROR, "Couldn't delete the referenced extent %llu, %d\n",
                ext_id,
                atomic_read(&ext->ref_cnt));
        BUG();
    }

    /* Get the extent lock, to prevent checkpoint happening parallely. */
    castle_extents_sb = castle_extents_super_block_get();

    /* Remove extent from hash and free the space. Both should happen in atomic with respect
     * to checkpoint. */
    castle_extents_hash_remove(ext);
    castle_extent_space_free(ext, ext->k_factor * ext->size);

    /* Drop 'extent exists' reference on c2b dirtytree. */
    castle_extent_dirtytree_put(ext->dirtytree);

    debug("Completed deleting ext: %lld\n", ext_id);

    castle_extents_sb->nr_exts--;

    castle_free(ext->work);
    castle_free(ext);

    /* Decrement the dead count. Module can't exit with outstanding dead extents.  */
    atomic_dec(&castle_extents_dead_count);

    castle_extent_transaction_end();
}

uint32_t castle_extent_kfactor_get(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_t *ext;
    uint32_t ret = 0;

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    if (ext)
        ret = ext->k_factor;

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return ret;
}

/**
 * Return the size of extent ext_id in chunks.
 */
c_chk_cnt_t castle_extent_size_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
        return ext->size;
    return 0;
}

/**
 * Return the number of (optionally active) slaves for ext_id.
 *
 * @param ext_id        Extent ID to return slave count for
 * @param only_active   Return only active slaves if set
 */
static int _castle_extent_slave_count_get(c_ext_id_t ext_id, int only_active)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
    {
        /* @TODO currently we return the total number of slaves, this needs to
         * be updated to return the number of slaves for a given extent. */
        struct list_head *lh;
        int slaves = 0;

        rcu_read_lock();
        list_for_each_rcu(lh, &castle_slaves.slaves)
        {
            slaves++;
        }
        rcu_read_unlock();

        return slaves;
    }
    else
        return 0;
}

/**
 * Return the total number of slaves for ext_id.
 */
int castle_extent_slave_count_get(c_ext_id_t ext_id)
{
    return _castle_extent_slave_count_get(ext_id, 0);
}

/**
 * Return the number of active slaves for ext_id.
 */
int castle_extent_active_slave_count_get(c_ext_id_t ext_id)
{
    return _castle_extent_slave_count_get(ext_id, 1);
}

/**
 * Determines whether an extent ID exists.
 *
 * @param   ext_id  Extent ID to check
 *
 * @return  1   Extent exists
 * @return  0   No such extent
 */
int castle_extent_exists(c_ext_id_t ext_id)
{
    if (castle_extents_hash_get(ext_id))
        return 1;

    return 0;
}

static void __castle_extent_map_get(c_ext_t *ext, c_chk_t chk_idx, c_disk_chk_t *chk_map)
{
    c_ext_pos_t map_page_cep, map_cep;
    c2_block_t *map_c2b;
    uint64_t offset;

    debug("Seeking map for ext: %llu, chunk: %u\n", ext->ext_id, chk_idx);
    offset = (chk_idx * ext->k_factor * sizeof(c_disk_chk_t));
    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs;

        cs = castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));
        BUG_ON((cs->sup_ext_maps == NULL) || (ext->k_factor != sup_ext.k_factor));
        memcpy(chk_map,
               (((uint8_t *)cs->sup_ext_maps) + offset),
               ext->k_factor * sizeof(c_disk_chk_t));
    }
    else if (ext->ext_id == MICRO_EXT_ID)
    {
        /* Accessing castle_extents_global_sb without lock. extent_space_alloc()
         * calls this function with lock held, which could lead to deadlock. */
        BUG_ON(chk_idx != 0);
        memcpy(chk_map, castle_extents_global_sb.micro_maps, ext->k_factor * sizeof(c_disk_chk_t));
    }
    else
    {
        debug("Maps cep="cep_fmt_str_nl, cep2str(ext->maps_cep));
        map_cep = castle_extent_map_cep_get(ext->maps_cep, chk_idx, ext->k_factor);
        /* Make the map_page_cep offset block aligned. */
        memcpy(&map_page_cep, &map_cep, sizeof(c_ext_pos_t));
        map_page_cep.offset = MASK_BLK_OFFSET(map_page_cep.offset);
        /* Get the c2b coresponding to map_page_cep. */
        map_c2b = castle_cache_page_block_get(map_page_cep);
        if (!c2b_uptodate(map_c2b))
        {
            debug("Scheduling read to get chunk mappings for ext: %llu\n",
                        ext->ext_id);
            write_lock_c2b(map_c2b);
            /* Need to recheck whether it's uptodate after getting the lock. */
            if(!c2b_uptodate(map_c2b))
            {
                set_c2b_no_resubmit(map_c2b);
                submit_c2b_sync(READ, map_c2b);
                if (!c2b_uptodate(map_c2b))
                {
                    /*
                     * The I/O has failed. This may be because we had a slave die on us. That I/O
                     * fail should have resulted in future I/O submissions by-passing that dead
                     * slave. So, try again, just once, and we should be able to read successfully
                     * from the other slave for this c2b. Assumes no_resubmit still set on c2b.
                     */
                    BUG_ON(submit_c2b_sync(READ, map_c2b));
                }
                clear_c2b_no_resubmit(map_c2b);
            }
            write_unlock_c2b(map_c2b);
        }
        read_lock_c2b(map_c2b);
        /* Check that the mapping for the chunk fits in the page. */
        BUG_ON(BLOCK_OFFSET(map_cep.offset) + (ext->k_factor * sizeof(c_disk_chk_t)) > C_BLK_SIZE);
        /* Copy. */
        memcpy(chk_map,
               c2b_buffer(map_c2b) + BLOCK_OFFSET(map_cep.offset),
               ext->k_factor * sizeof(c_disk_chk_t));
#ifdef DEBUG
        /* Print the mapping. */
        {
            int i;
            for(i=0; i<ext->k_factor; i++)
                debug("Mapping read: ext_id=%lld, logical_chunk=%d, copy=%d -> "disk_chk_fmt_nl,
                    ext->ext_id, chk_idx, i, disk_chk2str(chk_map[i]));
        }
#endif
        /* Release the cache block. */
        read_unlock_c2b(map_c2b);
        put_c2b(map_c2b);

        INJECT_FAULT;
    }
}

uint32_t castle_extent_map_get(void          *ext_p,
                               c_chk_t        offset,
                               c_disk_chk_t  *chk_map,
                               int            rw)
{
    c_ext_t *ext = ext_p;
    uint32_t ret;

    if(ext == NULL)
        return 0;

    if (offset >= ext->size)
    {
        castle_printk(LOG_ERROR, "BUG in %s\n", __FUNCTION__);
        castle_printk(LOG_ERROR, "    Extent: %llu\n", ext->ext_id);
        castle_printk(LOG_ERROR, "    Offset: %u\n", offset);
        castle_printk(LOG_ERROR, "    Extent Size: %u\n", ext->size);
        BUG();
    }

    /*
     * This extent may be being remapped, in which case writes need to be redirected via its shadow
     * map. This needs to be checked under the shadow map lock, but that lock and the
     * 'use_shadow_map' flag are only initialised for 'normal' extents, hence the extent id checks.
     */
    if ((rw == WRITE) && (!SUPER_EXTENT(ext->ext_id)) && !(ext->ext_id == MICRO_EXT_ID))
    {
        spin_lock(&ext->shadow_map_lock);
        if (ext->use_shadow_map)
        {
            memcpy(chk_map, &ext->shadow_map[offset*ext->k_factor], ext->k_factor * sizeof(c_disk_chk_t));
            spin_unlock(&ext->shadow_map_lock);
            goto map_done;
        }
        spin_unlock(&ext->shadow_map_lock);
    }
    __castle_extent_map_get(ext, offset, chk_map);

map_done:
    ret = ext->k_factor;

    return ret;
}

c_ext_id_t castle_extent_sup_ext_init(struct castle_slave *cs)
{
    c_ext_t      *ext;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(SUPER_EXT);
    int           i, j;

    ext = castle_ext_alloc(slave_id_to_sup_ext(cs->id));
    if (!ext)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent\n");
        goto err1;
    }
    ext->size       = sup_ext.size;
    ext->type       = sup_ext.type;
    ext->k_factor   = sup_ext.k_factor;
    ext->maps_cep   = sup_ext.maps_cep;
    ext->ext_type   = EXT_T_META_DATA;
    ext->da_id      = 0;

    cs->sup_ext_maps = castle_malloc(sizeof(c_disk_chk_t) * ext->size *
                                                    rda_spec->k_factor, GFP_KERNEL);
    BUG_ON(rda_spec->k_factor != ext->k_factor);
    if (!cs->sup_ext_maps)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent chunk "
                "maps of size %u:%u chunks\n",
        ext->size, rda_spec->k_factor);
        goto err2;
    }

    for (i=0; i<ext->size; i++)
    {
        for (j=0; j<rda_spec->k_factor; j++)
        {
            cs->sup_ext_maps[MAP_IDX(ext, i, j)].slave_id   = cs->uuid;
            cs->sup_ext_maps[MAP_IDX(ext, i, j)].offset     = i + (j * ext->size);
        }
    }
    ext->maps_cep = INVAL_EXT_POS;
    castle_extents_hash_add(ext);
    cs->sup_ext = ext->ext_id;

    debug("Created super extent %llu for slave 0x%x\n", ext->ext_id, cs->uuid);

    return ext->ext_id;

err2:
    castle_free(ext->dirtytree);
    castle_free(ext);
err1:
    return INVAL_EXT_ID;
}

void castle_extent_sup_ext_close(struct castle_slave *cs)
{
    c_ext_id_t ext_id;
    c_ext_t *ext;

    ext_id = slave_id_to_sup_ext(cs->id);
    ext = castle_extents_hash_get(ext_id);
    if (ext)
    {
        BUG_ON(atomic_read(&ext->ref_cnt) != 1);
        castle_extents_hash_remove(ext);
        castle_free(ext);
    }
    castle_free(cs->sup_ext_maps);

    return;
}

#define LIVE_EXTENT(_ext) ((_ext) && !(_ext)->deleted)
/**
 * Gets a 'light' reference to the extent. This is one that won't stop the extent from
 * being scheduled for removal, but it'll preserve the extent structure in the hashtable
 * and stop the freespace from being released.
 */
void* castle_extent_get(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_t *ext;

    /* Read lock is good enough as ref count is atomic. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);

    /* Don't give reference if extent is marked for deletion. */
    if (LIVE_EXTENT(ext))
        atomic_inc(&ext->ref_cnt);
    else
        ext = NULL;

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return ext;
}

/**
 * Puts the light reference. (Interrupt Context)
 *
 * Trigger _castle_extent_free() if the reference count is 0. But, dont call it from here as
 * free() is sleeping function and we are in interrupt context now. Instead, schedule
 * the _castle_extent_free() on system WQ. This fucntion just marks an extent for deletion,
 * but doesnt remove it from hash. As removing from hash table and freeing freespace on disk
 * should happen atomically under extents global mutex (as a transaction for the sake of
 * checkpoiting).
 *
 * @also: _castle_extent_free
 */
void castle_extent_put(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_t *ext;

    /* Write lock is required to mark the deleted bit to 1. We dont want to anybody to get
     * references, while marking it for deletion.  */
    write_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);

    /* Dont do put on deleted extents. */
    if (LIVE_EXTENT(ext) &&  atomic_dec_return(&ext->ref_cnt) == 0)
    {
        /* Increment the count of scheduled extents for deletion. Last checkpoint, conseqeuntly,
         * castle_exit waits for all outstanding dead extents to get destroyed. */
        atomic_inc(&castle_extents_dead_count);

        /* Extent shouldn't be already marked for deletion. */
        BUG_ON(ext->deleted);

        /* Mark for deletion. But, dont remove it from hash.
         *
         * Notes: Removing it from hash and freeing space should happen together under extent
         * lock. If we remove it from hash wihtout freeing sapce, then checkpoint would skip the
         * extent but counts freespace occupied by extent. In case of crash, this would leak
         * the freespace. */
        ext->deleted = 1;

        /* Work structure should have been malloced in castle_extent_free(). */
        BUG_ON(ext->work == NULL);

        /* Schedule extent deletion on system WQ. */
        INIT_WORK(ext->work, _castle_extent_free, ext);
        schedule_work(ext->work);
    }

    write_unlock_irqrestore(&castle_extents_hash_lock, flags);
}

/**
 * Get and hold a reference to RB-tree dirtytree for extent ext_id.
 *
 * All dirtytree gets by extent ID must occur while the extent exists
 * within the hash (e.g. checkpoint extent flush and dirty_c2b()).
 *
 * @also castle_cache_extent_flush()
 * @also dirty_c2b()
 *
 * @also castle_extent_dirtytree_get()
 * @also castle_extent_dirtytree_put()
 */
c_ext_dirtytree_t* castle_extent_dirtytree_by_id_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_dirtytree_t *dirtytree;
    unsigned long flags;

    read_lock_irqsave(&castle_extents_hash_lock, flags);
    ext = __castle_extents_hash_get(ext_id);
    BUG_ON(!ext);
    BUG_ON(atomic_inc_return(&ext->dirtytree->ref_cnt) < 2);
    dirtytree = ext->dirtytree;
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return dirtytree;
}

/**
 * Take an additional reference to per-extent dirtytree.
 *
 * Extent structure specified by dirtytree->ext_id does not need to exist
 * within the extents hash.
 *
 * @also castle_cache_flush()
 *
 * @also castle_extent_dirtytree_by_id_get()
 * @also castle_extent_dirtytree_put()
 */
void castle_extent_dirtytree_get(c_ext_dirtytree_t *dirtytree)
{
    /* Per-extent dirtytrees are freed when the ref_cnt reaches 0. */
    BUG_ON(atomic_inc_return(&dirtytree->ref_cnt) <= 1);
}

/**
 * Drop a reference to per-extent dirtytree.
 *
 * @param   dirtytree   Dirtytree to drop reference on
 * @param   check_hash  Whether to verify the dirtytree's extent is not in hash
 *
 * Extent structure specified by dirtytree->ext_id does not need to exist
 * within the extents hash.
 *
 * Frees the per-extent dirtytree if the reference count reaches 0.
 *
 * @also castle_extent_dirtytree_get()
 */
void __castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree, int check_hash)
{
    if (unlikely(atomic_dec_return(&dirtytree->ref_cnt) == 0))
    {
        if (check_hash)
            BUG_ON(castle_extent_get(dirtytree->ext_id));   /* cannot be in hash now */
        BUG_ON(!RB_EMPTY_ROOT(&dirtytree->rb_root));    /* must be empty */
        castle_free(dirtytree);
    }
}

/**
 * Drop a reference to per-extent dirtytree.
 *
 * @also __castle_extent_dirtytree_put()
 */
void castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree)
{
    __castle_extent_dirtytree_put(dirtytree, 1 /*check_hash*/);
}

/* Check if the extent is alive or not.
 * Extent is alive if it referenced by one of
 *  - Component Trees in a DA
 *      - Tree Extent
 *      - Medium Object Extent
 *      - Large Object Extent
 *  - Logical Extents
 *
 *  Other wise free it.
 */
static int castle_extent_check_alive(c_ext_t *ext, void *unused)
{
    if (ext->alive == 0)
    {
        castle_printk(LOG_WARN, "Found a dead extent: %llu - Cleaning it\n", ext->ext_id);
        read_unlock_irq(&castle_extents_hash_lock);
        /* Extent is dead and not referenced any of the structures. Free it. */
        castle_extent_free(ext->ext_id);
        read_lock_irq(&castle_extents_hash_lock);
    }
    return 0;
}

int castle_extents_restore(void)
{
    castle_extents_hash_iterate(castle_extent_check_alive, NULL);
    return 0;
}

/*
 * Add an extent to the rebuild list if it is potentially remappable.
 *
 * @param ext       The extent to check and add to the rebuild list.
 *
 * @return 0:       Always return 0 so that castle_extents_hash_iterate continues.
 */
static int castle_extent_rebuild_list_add(c_ext_t *ext, void *unused)
{
    c_ext_t *ref_ext;
    /*
     * We are not handling logical extents. The extent is not already at current_rebuild_seqno. The extent
     * is not marked for deletion (it is a live extent)
     */
    if ((!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID)) &&
        (ext->curr_rebuild_seqno < atomic_read(&current_rebuild_seqno)) &&
        LIVE_EXTENT(ext))
    {
        debug("Adding extent %llu to rebuild list for extent seqno %u, global seqno %u\n",
               ext->ext_id, ext->curr_rebuild_seqno, atomic_read(&current_rebuild_seqno));
        list_add_tail(&ext->rebuild_list, &rebuild_list);
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        ref_ext = castle_extent_get(ext->ext_id);
        BUG_ON(!ref_ext);
    }
    return 0;
}

/*
 * This structure keeps track of the current 'remapping state' - which slaves can be used for
 * remapping, and for each of those slaves a set of chunks to use for remapping, and an indication
 * of which chunk to use next.
 */
typedef struct live_slave {
    c_disk_chk_t    chunks[CHKS_PER_SLOT];  /* Chunk mappings (slave, offset) for slave. */
    int             next_chk;               /* The next chunk to use. */
    uint32_t        uuid;                   /* Uuid for slave. */
    uint32_t        flags;                  /* State flags for slave. */
} live_slave_t;

static struct remap_state {
    int             nr_live_slaves;              /* Number of slaves available for remapping. */
    live_slave_t    *live_slaves[MAX_NR_SLAVES];
} remap_state;

/*
 * (Re-)populate the list of 'live' slaves. This is the list that can currently be used as a
 * source of replacement slaves for remapping.
 */
static void castle_extents_remap_state_init(void)
{
    struct list_head        *lh;
    struct castle_slave     *cs;
    int                     i;

    if (remap_state.nr_live_slaves)
    {
        /* This is a re-population - a slave has become unavailable as a source for remapping. */
        for (i=0; i<remap_state.nr_live_slaves; i++)
        {
            /* Previous re-population may have left 'holes' in remap_state.live_slaves. */
            if (remap_state.live_slaves[i])
            {
                cs = castle_slave_find_by_uuid(remap_state.live_slaves[i]->uuid);
                if ((test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) ||
                    (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
                {
                    /*
                     * A previously-live slave is now no longer available for remapping.
                     * Leave the slave as a 'hole' in remap_state.live_slaves.
                     */
                    BUG_ON(!remap_state.live_slaves[i]);
                    castle_free(remap_state.live_slaves[i]);
                    remap_state.live_slaves[i] = NULL;
                }
                /* Still alive - leave it as it is. */
            }
        }
    } else
    {
        /* Initial population at startup. */
        rcu_read_lock();
        list_for_each_rcu(lh, &castle_slaves.slaves)
        {
            cs = list_entry(lh, struct castle_slave, list);
            if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
                (!test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
            {
                remap_state.live_slaves[remap_state.nr_live_slaves] =
                    castle_zalloc(sizeof(live_slave_t), GFP_KERNEL);
                BUG_ON(!remap_state.live_slaves[remap_state.nr_live_slaves]);
                remap_state.live_slaves[remap_state.nr_live_slaves]->uuid = cs->uuid;
                if (cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                    remap_state.live_slaves[remap_state.nr_live_slaves]->flags |= CASTLE_SLAVE_SSD;
                remap_state.nr_live_slaves++;
            }
        }
        rcu_read_unlock();
        for (i=remap_state.nr_live_slaves; i<MAX_NR_SLAVES; i++)
            remap_state.live_slaves[i++] = NULL;
    }
}

/*
 * Frees any data associated with the remap_state structure.
 */
static void castle_extents_remap_state_fini(void)
{
    int i;

    for (i=0; i<MAX_NR_SLAVES; i++)
    {
        if (remap_state.live_slaves[i])
            castle_free(remap_state.live_slaves[i]);
    }
}

/*
 * Populates the remap_state.chunks array for the passed slave with a superchunk's
 * worth of of disk chunks.
 *
 * @param slave_idx The index into the remap_state chunks / live_slaves array.
 *
 * @return EXIT_SUCCESS:       Success.
 * @return -ENOSPC:            Slave is out of space.
 */
static int castle_extent_remap_superchunks_alloc(int slave_idx)
{
    c_disk_chk_t        *chunkp = remap_state.live_slaves[slave_idx]->chunks;
    int                 chunk;
    c_chk_seq_t         chk_seq;
    c_chk_t             offset;
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(remap_state.live_slaves[slave_idx]->uuid);
    BUG_ON(!cs);
    BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));

    /*
     * Allocate a superchunk. We do not want to pre-reserve space, so use a NULL token.
     */
    chk_seq = castle_freespace_slave_superchunk_alloc(cs, 0, NULL);
    if (CHK_SEQ_INVAL(chk_seq))
    {
        /*
         * We get here if the slave is either out-or-service, or out of space. If the slave is
         * out-of-service then just return ENOSPC so calling stack can retry.
         */
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
            (!(cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)))
        {
            /* Slave is not out-of-service so we are out of space */
            castle_printk(LOG_WARN, "Error: failed to get freespace from slave: 0x%x [%s].\n",
                    cs->uuid, cs->bdev_name);

            castle_freespace_stats_print();
            return -ENOSPC;
        } else
        {
            castle_printk(LOG_WARN, "Warning - Failed allocating superchunk from "
                    "out-of-service slave: 0x%x [%s].", cs->uuid, cs->bdev_name);
            /*
             * Slave is now out-of-service. Re-initialise remap state and retry.
             */
            return -EAGAIN;
        }
    }

    /* Chunk sequence must represent a single superchunk. */
    BUG_ON(chk_seq.count != CHKS_PER_SLOT);

    /* Fill in the chunks for this slave. */
    for (chunk=0, offset=chk_seq.first_chk; chunk<chk_seq.count; chunk++, offset++)
    {
        (chunkp+chunk)->slave_id = remap_state.live_slaves[slave_idx]->uuid;
        (chunkp+chunk)->offset = offset;
    }
    return EXIT_SUCCESS;
}

/*
 * Return the slave index to use for remapping a chunk. Scans the remap_state.live_slaves
 * array for a slave which is not already used in the disk chunk.
 *
 * @param ext           The extent for which the remapping is being done.
 * @param chunkno       The logical chunk being remapped.
 * @param want_ssd      Flag set if we want to remap onto an SSD (if possible).
 * @param ssds_tried    The number of SSDs we have tried, but failed to allocate space from.
 *
 * @return          The index into the remap_state arrays to use for allocation
 */
static int castle_extent_replacement_slave_get(c_ext_t *ext,
                                               int chunkno,
                                               int *want_ssd,
                                               int ssds_tried)
{
    int         chunk_idx, slave_idx, nr_slaves_to_use, already_used;
    int         slaves_to_use[MAX_NR_SLAVES];
    uint16_t    r;
    int         is_ssd=0;

    /* For each slave in remap_state.live_slaves (the list of potential remap slaves). */
retry:
    nr_slaves_to_use = 0;
    for (slave_idx=0; slave_idx<remap_state.nr_live_slaves; slave_idx++)
    {
        if (remap_state.live_slaves[slave_idx] == NULL)
            /* This slave is no longer available - skip it. */
            continue;

        is_ssd = remap_state.live_slaves[slave_idx]->flags & CASTLE_SLAVE_SSD;

        if ((is_ssd && !*want_ssd) || (!is_ssd && *want_ssd))
            /*
             * Slave is an SSD, but we want to allocate from non-SSD slaves, or slave is not an
             * SSD, but we want to allocate from SSD slaves. Do not use this slave.
             */
            continue;

        if (is_ssd && ssds_tried)
        {
            /* Skip SSDs that caller has already tried, but failed to allocate space from. */
            ssds_tried--;
            continue;
        }

        already_used = 0;
        /* Scan through all the slaves in this logical chunk. */
        for (chunk_idx=0; chunk_idx<ext->k_factor; chunk_idx++)
        {
            if (ext->shadow_map[(chunkno*ext->k_factor)+chunk_idx].slave_id ==
                remap_state.live_slaves[slave_idx]->uuid)
            {
                /* This slave is already used in this logical chunk - ignore it. */
                already_used = 1;
                break;
            }
        }
        if (!already_used)
            /*
             * This slave is not already used in this logical chunk - add it to set of potential
             * target slaves for remapping this chunk.
             */
            slaves_to_use[nr_slaves_to_use++] = slave_idx;
    }

    if (!nr_slaves_to_use && *want_ssd)
    {
        /* We want an SSD, but we could not find one - retry for a non-SSD. */
        debug("Wanted to remap to SSD, but failed to find one. Retrying from non-SSD\n");
        *want_ssd = 0;
        goto retry;
    }

    BUG_ON(!nr_slaves_to_use);

    /*
     * Now slaves_to_use is an array of indexes into remap_state.live_slaves that reflect
     * potential target slaves for remapping for this logical chunk. Pick one at random.
     */
    get_random_bytes(&r, 2);
    r = r % nr_slaves_to_use;
    return slaves_to_use[r];
}

/*
 * Find a replacement disk chunk for an out-of-service or evacuating slave.
 *
 * @param ext       The extent for which the remapping is being done.
 * @param chunkno   The logical chunk being remapped.
 *
 * @return          The disk chunk to use.
 */
static c_disk_chk_t *castle_extent_remap_disk_chunk_alloc(c_ext_t *ext, int chunkno, int want_ssd)
{
    c_disk_chk_t        *disk_chk;
    int                 slave_idx;
    struct castle_slave *target_slave;
    int                 ret;
    int                 ssds_tried=0;

retry:
    /* Get the replacement slave */
    slave_idx = castle_extent_replacement_slave_get(ext, chunkno, &want_ssd, ssds_tried);
    BUG_ON(slave_idx == -1);

    target_slave = castle_slave_find_by_uuid(remap_state.live_slaves[slave_idx]->uuid);
    BUG_ON(!target_slave);

    if ((test_bit(CASTLE_SLAVE_OOS_BIT, &target_slave->flags)) ||
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &target_slave->flags)))
    {
        /* Tried to use a now-dead slave for remapping. Repopulate the remap_state and retry. */
        debug("Rebuild tried using a now-dead slave - repopulating remap state\n");
        castle_extents_remap_state_init();
        goto retry;
    }

    if (!remap_state.live_slaves[slave_idx]->next_chk)
    {
        /* We've run out of chunks on this slave, allocate another set. */
        ret = castle_extent_remap_superchunks_alloc(slave_idx);
        if (ret == -EAGAIN)
        {
            /*
             * Tried to use a now-dead slave for superchunk allocation.
             * Repopulate the remap_state and retry.
             */
            debug("Rebuild tried using a now-dead slave - repopulating remap state\n");
            castle_extents_remap_state_init();
            goto retry;
        }
        else
        if ((ret == -ENOSPC) && want_ssd)
        {
            /*
             * ssds_tried keeps count of the number of SSDs we have tried, and failed, to allocate
             * from. We'll keep retrying other SSDs until castle_extent_replacement_slave_get
             * determines that we have tried all SSDs.
             */
            ssds_tried++;
            goto retry;
        }

        if(ret)
            return NULL;
    }

    disk_chk =
        &remap_state.live_slaves[slave_idx]->chunks[remap_state.live_slaves[slave_idx]->next_chk];

    BUG_ON(DISK_CHK_INVAL(*disk_chk));

    /*
     * Calculate the next disk chunk to use in the remap_state chunks array. When this wraps to 0
     * this is a trigger to allocate another set of superchunks and repopulate the array (see above)
     * if a new disk chunk request is made.
     */
    remap_state.live_slaves[slave_idx]->next_chk =
                        ++remap_state.live_slaves[slave_idx]->next_chk % CHKS_PER_SLOT;

    return disk_chk;
}

/*
 * Check if a slave needs remapping.
 *
 * @param slave_id  The slave uuid.
 *
 * @return:         A pointer to the castle_slave if it needs remapping, else NULL.
 */
static struct castle_slave *slave_needs_remapping(uint32_t slave_id)
{
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(slave_id);
    BUG_ON(!cs);

    if ((test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) ||
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
        return cs;
    else
        return NULL;
}

/*
 * Scan an extent, remapping disk chunks where necessary.
 *
 * @param ext       The extent to remap.
 *
 * @return 1:       We got kthread_should_stop() while remapping an extent.
 * @return -ENOSPC: We got an allocation failure (out of disk space).
 * @return 0:       We successfully processed the extent.
 */
static int castle_extent_remap(c_ext_t *ext)
{
    uint32_t            k_factor = castle_extent_kfactor_get(ext->ext_id);
    int                 chunkno, idx, remap_idx, no_remap_idx, i;
    struct castle_slave *cs;
    int ret=0;

    debug("\nRemapping extent %llu size: %u, from seqno: %u to seqno: %u\n",
            ext->ext_id, ext->size, ext->curr_rebuild_seqno, rebuild_to_seqno);

    ext->shadow_map = castle_vmalloc(ext->size*k_factor*sizeof(c_disk_chk_t));
    if (!ext->shadow_map)
    {
        castle_printk(LOG_ERROR, "ERROR: could not allocate rebuild shadow map of size %lu\n",
                ext->size*k_factor*sizeof(c_disk_chk_t));
        BUG();
    }

    /* Populate the shadow map - a copy of the existing mapping. */
    for (chunkno = 0; chunkno<ext->size; chunkno++)
        __castle_extent_map_get(ext, chunkno, &ext->shadow_map[chunkno*k_factor]);

    /*
     * As we are remapping a new extent, we need to stop using any pre-existing superchunks.
     * Setting next_chk to 0 will force new superchunk(s) to be allocated for this extent.
     */
    for (i=0; i<remap_state.nr_live_slaves; i++)
        if (remap_state.live_slaves[i])
            remap_state.live_slaves[i]->next_chk = 0;

    /*
     * From this point, we will start using the shadow map to remap the extent. All write I/O must
     * now be submitted via the shadow map because it will be more up-to-date (or at least no less
     * up-to-date) than the original extent map.
     */
    ext->use_shadow_map = 1;

    /* Scan the shadow map, chunk by chunk, remapping slaves as necessary. */
    for (chunkno = 0; chunkno<ext->size; chunkno++)
    {
        /*
         * Populate the remap chunks array that will be used to write out remapped data.
         * Disk chunks for remapped slaves go at the start. Disk chunks for non-remapped slaves
         * go at the end. This split allows lower level code to submit I/O only for remapped
         * slaves, or for all slaves, as required. Remap_idx will define the boundary between
         * the two sets in the remap chunks array.
         */
        c_disk_chk_t remap_chunks[k_factor];

retry:
        for (idx=0, remap_idx=0, no_remap_idx=k_factor-1; idx<k_factor; idx++)
        {
            c_disk_chk_t *disk_chk;

            /* Chunks that don't need remapping go to the end of the remap_chunks array. */
            if (!(cs = slave_needs_remapping(ext->shadow_map[(chunkno*k_factor)+idx].slave_id)))
            {
                remap_chunks[no_remap_idx].slave_id =
                                        ext->shadow_map[(chunkno*k_factor)+idx].slave_id;
                remap_chunks[no_remap_idx--].offset =
                                        ext->shadow_map[(chunkno*k_factor)+idx].offset;
                continue;
            }

            /* This slave needs remapping. Get a replacement disk chunk. */
            disk_chk = castle_extent_remap_disk_chunk_alloc(ext, chunkno,
                                            cs->cs_superblock.pub.flags & CASTLE_SLAVE_SSD);
            if (!disk_chk)
            {
                /* Failed to allocate a disk chunk (slave out of space is most likely cause). */
                castle_printk(LOG_WARN, "Rebuild could not allocate a disk chunk.\n");
                spin_lock(&ext->shadow_map_lock);
                ext->use_shadow_map = 0;
                spin_unlock(&ext->shadow_map_lock);
                castle_vfree(ext->shadow_map);
                return -ENOSPC;
            }
            /*
             * Lock the shadow map here because we don't want the read/write path to access
             * a chunk in mid-remap.
             */
            spin_lock(&ext->shadow_map_lock);
            ext->shadow_map[(chunkno*k_factor)+idx].slave_id = disk_chk->slave_id;
            ext->shadow_map[(chunkno*k_factor)+idx].offset = disk_chk->offset;
            spin_unlock(&ext->shadow_map_lock);

            /* Chunks that need remapping go to the start of the remap_chunks array. */
            remap_chunks[remap_idx].slave_id = disk_chk->slave_id;
            remap_chunks[remap_idx++].offset = disk_chk->offset;
        }

        FAULT(REBUILD_FAULT2);

        /*
         * The remap_chunks array now contains all the disk chunks for this chunkno.
         */
        if (remap_idx)
        {
            c_ext_pos_t cep, map_cep, map_page_cep;
            c2_block_t *c2b, *map_c2b, *reserve_c2b;

            /*
             * If a chunk has been remapped, read it in (via the old map) and write it out (using
             * the remap_chunks array as the map).
             */
            cep.ext_id = ext->ext_id;
            cep.offset = chunkno*C_CHK_SIZE;

            c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
            write_lock_c2b(c2b);

            /*
             * Remap c2bs are handled slightly differently in the cache, as we can
             * have clean c2bs with dirty pages.
            */
            set_c2b_remap(c2b);

            /*
             * If c2b is not up to date, issue a blocking READ to update.
             * READ uses the existing map.
             */
            if(!c2b_uptodate(c2b))
                BUG_ON(submit_c2b_sync(READ, c2b));

            /* Submit the write. */
            ret = submit_c2b_remap_rda(c2b, remap_chunks, remap_idx);

            write_unlock_c2b(c2b);

            /* This c2b is not needed any more, and it pollutes the cache, so destroy it. */
            /* Note: c2b still contains valid data. Destroy could fail due to other potential consumers
             * of the c2b. Except in the case logical extents, rebuild is the only consumer accesses in
             * chunks. So, there shouldnt be any other references to this c2b. */
            BUG_ON(castle_cache_block_destroy(c2b) && LOGICAL_EXTENT(ext->ext_id));

            /*
             * Check that the submit_c2b_remap_rda succeeded. If it got EAGAIN, then the
             * remap_chunks contained a now-oos slave (a slave that went oos between the disk chunk
             * alloc and the submit. In this case, we can retry, which should rebuild remap_chunks
             * with (hopefully) now valid slave(s).
             */
            if (ret == -EAGAIN)
                goto retry;
            BUG_ON(ret);

            /*
             * Now write out the shadow map entry for this chunk.
             * First, get the cep for the map for this chunk.
             */
            map_cep = castle_extent_map_cep_get(ext->maps_cep, chunkno, ext->k_factor);
            /* Make the map_page_cep offset block aligned. */
            memcpy(&map_page_cep, &map_cep, sizeof(c_ext_pos_t));
            map_page_cep.offset = MASK_BLK_OFFSET(map_page_cep.offset);

            /* Get the c2b for the page containing the map cep.
             *
             * In order to prevent a situation where we have no reserve c2b/c2ps
             * for the flush thread, make a single page c2b reservation and
             * release it once we've finished dirtying the map_c2b. */
            reserve_c2b = castle_cache_page_block_reserve();
            map_c2b = castle_cache_page_block_get(map_page_cep);

            write_lock_c2b(map_c2b);

            /* Shadow map must be page aligned. */
            BUG_ON((unsigned long)ext->shadow_map % PAGE_SIZE);

            /* Update the entire buffer with the page containing the shadow map for the chunk */
            memcpy(c2b_buffer(map_c2b),
                   (char *)(MASK_BLK_OFFSET((unsigned long)&ext->shadow_map[chunkno*k_factor])),
                   C_BLK_SIZE);

            dirty_c2b(map_c2b);
            update_c2b(map_c2b);

            write_unlock_c2b(map_c2b);
            put_c2b(map_c2b);
            castle_cache_page_block_unreserve(reserve_c2b);
        }

        /* Keep count of the chunks that have actually been remapped. */
        castle_extents_chunks_remapped += remap_idx;

        /*
         * Allow for shutdown in mid-extent (between chunks), because extents may be large and
         * take too long to remap.
         */
        if (kthread_should_stop())
        {
            spin_lock(&ext->shadow_map_lock);
            ext->use_shadow_map = 0;
            spin_unlock(&ext->shadow_map_lock);
            castle_vfree(ext->shadow_map);
            return 1;
        }
    }

    /* This is the rebuild sequence number we have rebuilt the extent to. */
    debug("Setting extent %llu to rebuild seqno %d\n", ext->ext_id, rebuild_to_seqno);
    ext->curr_rebuild_seqno = rebuild_to_seqno;

    /*
     * For superblock meta extents, update the superblock too, because that's what will get
     * written out to disk.
     */
    if ((ext->ext_id == META_EXT_ID) ||
        (ext->ext_id == MSTORE_EXT_ID) ||
        (ext->ext_id == MSTORE_EXT_ID+1))
    {
        struct castle_extents_superblock* castle_extents_sb;

        castle_extent_transaction_start();
        castle_extents_sb = castle_extents_super_block_get();
        switch (ext->ext_id) {
            case META_EXT_ID:
                castle_extents_sb->meta_ext.curr_rebuild_seqno = rebuild_to_seqno;
                break;
            case MSTORE_EXT_ID:
                castle_extents_sb->mstore_ext[0].curr_rebuild_seqno = rebuild_to_seqno;
                break;
            case MSTORE_EXT_ID+1:
                castle_extents_sb->mstore_ext[1].curr_rebuild_seqno = rebuild_to_seqno;
                break;
        }
        castle_extent_transaction_end();
    }

    /* Now the shadow map has become the default map, we can stop redirecting write I/O. */
    spin_lock(&ext->shadow_map_lock);
    ext->use_shadow_map = 0;
    spin_unlock(&ext->shadow_map_lock);
    castle_vfree(ext->shadow_map);

    return EXIT_SUCCESS;
}

/*
 * The main rebuild kthread function.
 *
 * @return 0:       Kthread should stop.
 */

static int  freespace_added = 0;

int castle_extents_rebuild_callback(void *data)
{
    freespace_added = 1;
    wake_up(&rebuild_wq);
    return 0;
}

static int castle_extents_rebuild_run(void *unused)
{
    struct list_head            *entry, *tmp;
    c_ext_t                     *ext;
    struct castle_slave         *cs, *evacuated_slaves[MAX_NR_SLAVES], *oos_slaves[MAX_NR_SLAVES];
    int                         i, ret=0, nr_evacuated_slaves=0, nr_oos_slaves=0, exit_early=0;
    struct castle_fs_superblock *fs_sb;

    /* Initialise the rebuild list. */
    INIT_LIST_HEAD(&rebuild_list);

    debug("Starting rebuild thread ...\n");
    do {
        wait_event_interruptible(rebuild_wq,
                                 ((atomic_read(&current_rebuild_seqno) > rebuild_to_seqno) ||
                                  freespace_added ||
                                  kthread_should_stop()));

        if (kthread_should_stop())
        {
            debug("Rebuild thread terminated.\n");
            goto out;
        }

restart:
        castle_printk(LOG_USERINFO, "Rebuild run starting.\n");

        fs_sb = castle_fs_superblocks_get();
        fs_sb->fs_in_rebuild = 1;
        castle_fs_superblocks_put(fs_sb, 1);

        castle_extents_rescan_required = exit_early = freespace_added = 0;

        rebuild_to_seqno = atomic_read(&current_rebuild_seqno);

        castle_extents_remap_state_init();

        /* Build the list of extents to remap. */
        castle_extents_hash_iterate(castle_extent_rebuild_list_add, NULL);

        if (list_empty(&rebuild_list))
        {
            castle_printk(LOG_WARN, "Rebuild: no extents found.\n");
            continue;
        }

        /*
         * Iterate over the list, remapping as necessary. If exit_early gets set, we'll just
         * 'put' the remaining extents in the list.
         */
        list_for_each_safe(entry, tmp, &rebuild_list)
        {
            ext = list_entry(entry, c_ext_t, rebuild_list);
            list_del(entry);
            BUG_ON(ext->curr_rebuild_seqno >= rebuild_to_seqno);

            if (!exit_early)
            {
                /*
                 * Allow rebuild to be stopped or restarted in-between extent remappings.
                 */
                if ((ret = castle_extent_remap(ext)) ||
                        kthread_should_stop() ||
                        castle_extents_rescan_required ||
                        rebuild_to_seqno != atomic_read(&current_rebuild_seqno))
                    exit_early = 1;
            }

            FAULT(REBUILD_FAULT1);

            /* Drop ref to extent. */
            castle_extent_put(ext->ext_id);
        }

        if (exit_early)
        {
            if (kthread_should_stop())
            {
                castle_printk(LOG_WARN, "Rebuild run terminating early.\n");
                goto out;
            }
            else if (rebuild_to_seqno != atomic_read(&current_rebuild_seqno) ||
                     castle_extents_rescan_required)
            {
                castle_printk(LOG_WARN, "Rebuild run restarting.\n");
                goto restart;
            } else if (ret == -ENOSPC)
            {
                c_ext_event_t *event_hdl = NULL;
                /* Currently we can't do anything other than go back to the wait_event. */
                castle_printk(LOG_WARN, "Rebuild run pausing.\n");

                event_hdl = castle_zalloc(sizeof(c_ext_event_t), GFP_KERNEL);
                if (!event_hdl)
                    BUG();

                event_hdl->callback = castle_extents_rebuild_callback;
                event_hdl->data     = NULL;

                castle_extent_transaction_start();
                castle_extent_lfs_callback_add(event_hdl);
                castle_extent_transaction_end();
                continue;
            } else
                BUG();
        }

        if ((rebuild_to_seqno == atomic_read(&current_rebuild_seqno)) &&
            !castle_extents_rescan_required)
        {
            /*
             * No further remapping required. We can now convert any evacuating or out-of-service
             * slaves to remapped state. First, create the list of evacuated / oos slaves.
             */
            for (i=0; i<MAX_NR_SLAVES; i++)
                oos_slaves[i] = evacuated_slaves[i] = 0;
            nr_oos_slaves = nr_evacuated_slaves = 0;

            rcu_read_lock();
            list_for_each_rcu(entry, &castle_slaves.slaves)
            {
                cs = list_entry(entry, struct castle_slave, list);
                if (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags) &&
                   !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags) &&
                   !test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                    evacuated_slaves[nr_evacuated_slaves++] = cs;
                if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
                   !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags))
                    oos_slaves[nr_oos_slaves++] = cs;
            }
            rcu_read_unlock();
        }

        /*
         * If current_rebuild_seqno has changed during the run then start again to pick up any
         * extents which have not been remapped to the new sequence number.
         */
        if ((rebuild_to_seqno != atomic_read(&current_rebuild_seqno)) ||
            castle_extents_rescan_required)
        {
            castle_printk(LOG_WARN, "Rebuild run restarting.\n");
            goto restart;
        }

        /*
         * Nothing more to do. Now we can be sure that the set of evacuated_slaves and oos_slaves
         * built earlier is correct. Use them to convert to oos / remapped.
         */
        for (i=0; i<nr_oos_slaves; i++)
        {
            if (oos_slaves[i])
            {
                castle_printk(LOG_USERINFO, "Finished remapping out-of-service slave 0x%x.\n",
                              oos_slaves[i]->uuid);
                set_bit(CASTLE_SLAVE_REMAPPED_BIT, &oos_slaves[i]->flags);
                if (atomic_read(&oos_slaves[i]->io_in_flight) == 0 &&
                    test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &oos_slaves[i]->flags))
                    castle_release_device(oos_slaves[i]);
            }
        }
        for (i=0; i<nr_evacuated_slaves; i++)
        {
            if (evacuated_slaves[i])
            {
                BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &evacuated_slaves[i]->flags));
                castle_printk(LOG_USERINFO, "Finished remapping evacuated slave 0x%x.\n",
                              evacuated_slaves[i]->uuid);
                set_bit(CASTLE_SLAVE_OOS_BIT, &evacuated_slaves[i]->flags);
                set_bit(CASTLE_SLAVE_REMAPPED_BIT, &evacuated_slaves[i]->flags);
                clear_bit(CASTLE_SLAVE_EVACUATE_BIT, &evacuated_slaves[i]->flags);
                if (atomic_read(&evacuated_slaves[i]->io_in_flight) == 0 &&
                    test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &evacuated_slaves[i]->flags))
                    castle_release_device(evacuated_slaves[i]);
            }
        }

        /* Rebuild has finished. Mark it so in the superblock. */
        fs_sb = castle_fs_superblocks_get();
        fs_sb->fs_in_rebuild = 0;
        castle_rebuild_fs_version = fs_sb->fs_version;
        castle_fs_superblocks_put(fs_sb, 1);
        castle_extents_chunks_remapped = 0;

        castle_printk(LOG_USERINFO, "Rebuild completed.\n");

    } while (1);

    /* NOTREACHED */
    BUG();

out:
    castle_extents_remap_state_fini();
    return EXIT_SUCCESS;
}

/*
 * Kick the rebuild thread to start the rebuild process (e.g. when a slave dies or is evacuated).
 */
void castle_extents_rebuild_wake(void)
{
    atomic_inc(&current_rebuild_seqno);
    castle_events_slave_rebuild_notify();
    wake_up(&rebuild_wq);
}

/*
 * Main initialisation function for rebuild.
 *
 * @return 0:       Success.
 */
int castle_extents_rebuild_init(void)
{
    atomic_set(&current_rebuild_seqno, 0);

    init_waitqueue_head(&rebuild_wq);

    rebuild_thread = kthread_run(castle_extents_rebuild_run, NULL, "castle-rebuild");
    if(!rebuild_thread)
        return -ENOMEM;

    return 0;
}

/*
 * Main fini function for rebuild.
 */
void castle_extents_rebuild_fini(void)
{
    kthread_stop(rebuild_thread);
    castle_extents_exiting = 1;
}

/*
 * Check if rebuild needs to be started on fs startup.
 */
void castle_extents_rebuild_startup_check(int need_rebuild)
{
    struct castle_fs_superblock *fs_sb;

    /*
     * If fs init decided that we need a rebuild, then bumping current_rebuild_seqno will force all
     * extents to be checked.
     */
    if (need_rebuild)
        atomic_inc(&current_rebuild_seqno);

    fs_sb = castle_fs_superblocks_get();
    /*
     * If fs_in_rebuild is non-zero or need_rebuild is set we need to (re)start rebuild. Setting
     * rebuild_to_seqno to current_rebuild_seqno-1 will force the rebuild thread to start the rebuild.
     */
    if (fs_sb->fs_in_rebuild || need_rebuild)
    {
        rebuild_to_seqno = atomic_read(&current_rebuild_seqno) - 1;
        castle_printk(LOG_USERINFO, "Rebuild startup check: Restarting rebuild.\n");

        /* Wake the rebuild thread */
        wake_up(&rebuild_wq);
    }
    castle_fs_superblocks_put(fs_sb, 1);
}

/*
 * Add an extent to the verify list if it is potentially remappable.
 *
 * @param ext       The extent to check and add to the verify list.
 *
 * @return 0:       Always return 0 so that castle_extents_hash_iterate continues.
 */
static int castle_extent_verify_list_add(c_ext_t *ext, void *unused)
{
    c_ext_t *ref_ext;

    /* We are not handling logical extents or extents scheduled for deletion. */
    if (!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID) && LIVE_EXTENT(ext))
    {
        list_add_tail(&ext->verify_list, &verify_list);
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        ref_ext = castle_extent_get(ext->ext_id);
        BUG_ON(!ref_ext);
    }
    return 0;
}

/*
 * Scanb the map for an extent, looking for references to a slave.
 *
 * @param ext       The extent to check.
 * @param uuid      The slave to scan for.
 *
 * @return nr_refs: The number of references to the uuid in this extent
 */
static int castle_extent_scan_uuid(c_ext_t *ext, uint32_t uuid)
{
    int chunkno, nr_refs=0, idx=0;
    c_disk_chk_t chunks[ext->k_factor];

    for (chunkno = 0; chunkno<ext->size; chunkno++)
    {
        __castle_extent_map_get(ext, chunkno, chunks);
        for (idx=0; idx<ext->k_factor; idx++)
        {
            if (chunks[idx].slave_id == uuid)
            {
                castle_printk(LOG_DEVEL, "castle_extent_scan_uuid found uuid 0x%x in extent %llu\n", uuid, ext->ext_id);
                nr_refs++;
            }
        }
    }
    return nr_refs;
}

/**
 * Scan all extents in the hash, looking for disk chunks using that slave.
 *
 * @param uuid      The slave to check for
 * return           Returns EBUSY if a rebuild is in progress, so a scan may be invalid.
 *                  Returns EEXIST if at least one chunk is found for the slave.
 *                  Returns ENOENT if extents found to check.
 *                  Returns EXIT_SUCCESS if no chunk is found for the slave.
 */
int castle_extents_slave_scan(uint32_t uuid)
{
    struct castle_fs_superblock *fs_sb;
    struct list_head            *entry, *tmp;
    c_ext_t *ext;
    int     nr_refs=0;

    fs_sb = castle_fs_superblocks_get();
    /*
     * If fs_in_rebuild is non-zero a rebuild is still in progress, so a scan may be invalid.
     */
    if (fs_sb->fs_in_rebuild)
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY returning EBUSY\n");
        castle_fs_superblocks_put(fs_sb, 1);
        return -EBUSY;
    }
    castle_fs_superblocks_put(fs_sb, 1);

    /* Initialise the verify list. */
    INIT_LIST_HEAD(&verify_list);

    debug("castle_extents_slave_scan started on slave 0x%x\n", uuid);
    castle_extents_hash_iterate(castle_extent_verify_list_add, NULL);

    if (list_empty(&verify_list))
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY: list is empty.\n");
        return -ENOENT;
    }

    list_for_each_safe(entry, tmp, &verify_list)
    {
        ext = list_entry(entry, c_ext_t, verify_list);
        list_del(entry);

        nr_refs += castle_extent_scan_uuid(ext, uuid);
        castle_extent_put(ext->ext_id);
    }

    if (nr_refs)
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY: %d references found to uuid 0x%xd\n", nr_refs, uuid);
        return -EEXIST;
    }
    else
        return 0;
}

signed int castle_extent_ref_cnt_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return -1;
    return ((signed int)atomic_read(&ext->ref_cnt));
}

c_ext_type_t castle_extent_type_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return EXT_T_INVALID;
    return ext->ext_type;
}

