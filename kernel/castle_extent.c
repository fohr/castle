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
#define debug_mask(_f, _a...)   (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_resize(_f, _a...) (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_schks(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#define debug_mask(_f, ...)     ((void)0)
#define debug_resize(_f, ...)   ((void)0)
#define debug_schks(_f, ...)    ((void)0)
#endif

#define MAP_IDX(_ext, _i, _j)       (((_ext)->k_factor * _i) + _j)
#define CASTLE_EXTENTS_HASH_SIZE    100

#define GET_LATEST_MASK(_ext)   ((!list_empty(&(_ext)->mask_list))?                          \
                                 (list_entry((_ext)->mask_list.next, c_ext_mask_t, list)):   \
                                 NULL)
#define GET_OLDEST_MASK(_ext)   ((!list_empty(&(_ext)->mask_list))?                          \
                                 (list_entry((_ext)->mask_list.prev, c_ext_mask_t, list)):   \
                                 NULL)

#define IS_OLDEST_MASK(_ext, _mask)     list_is_last(&((_mask)->list), &((_ext)->mask_list))

#define SUPER_CHUNK_STRUCT(chk_idx)  ((c_chk_seq_t){chk_idx, CHKS_PER_SLOT})

/* Note: load_extent_from_mentry() deals with complete extent deserialization. This
 * is just a helper function. */
#ifdef CASTLE_PERF_DEBUG
#define CONVERT_MENTRY_TO_EXTENT(_ext, _me)                                 \
        (_ext)->ext_id      = (_me)->ext_id;                                \
        (_ext)->size        = (_me)->size;                                  \
        (_ext)->type        = (_me)->type;                                  \
        (_ext)->k_factor    = (_me)->k_factor;                              \
        (_ext)->maps_cep    = (_me)->maps_cep;                              \
        (_ext)->curr_rebuild_seqno = (_me)->curr_rebuild_seqno;             \
        (_ext)->ext_type    = (_me)->ext_type;                              \
        (_ext)->da_id       = (_me)->da_id;                                 \
        (_ext)->dirtytree->ext_size = (_me)->size;                          \
        (_ext)->dirtytree->ext_type = (_me)->ext_type;
#else
#define CONVERT_MENTRY_TO_EXTENT(_ext, _me)                                 \
        (_ext)->ext_id      = (_me)->ext_id;                                \
        (_ext)->size        = (_me)->size;                                  \
        (_ext)->type        = (_me)->type;                                  \
        (_ext)->k_factor    = (_me)->k_factor;                              \
        (_ext)->maps_cep    = (_me)->maps_cep;                              \
        (_ext)->curr_rebuild_seqno = (_me)->curr_rebuild_seqno;             \
        (_ext)->ext_type    = (_me)->ext_type;                              \
        (_ext)->da_id       = (_me)->da_id;
#endif

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->curr_rebuild_seqno = (_ext)->curr_rebuild_seqno;             \
        (_me)->ext_type     = (_ext)->ext_type;                             \
        (_me)->cur_mask     = GET_LATEST_MASK(_ext)->range;                 \
        (_me)->prev_mask    = (_ext)->chkpt_global_mask;                    \
        (_me)->da_id        = (_ext)->da_id;

#define FAULT_CODE EXTENT_FAULT

#define cemr_cstr           "[%u:%u)"
#define cemr2str(_r)        (_r).start, (_r).end

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_superblock castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

struct castle_extent;

/**
 * Structure to keep the partial superchunks that extent owns.
 *
 * Rebuild makes extent space mapping un-predictable. We can't assume any layout for a
 * given superchunk. With extent resize operations, it is possible to delete parts of
 * extents seperately. So, we maintain outstadning partial superchunks in the extent.
 */
typedef struct castle_partial_schk {
    uint32_t            slave_id;       /**< Slave ID, this superchunk belongs to.      */
    c_chk_cnt_t         first_chk;      /**< First chunk's offset.                      */
    uint8_t             count;          /**< Number of chunks left in this super chunk. */
    struct list_head    list;           /**< Link to extent.                            */
} c_part_schk_t;

/**
 * Extent mask represents a range of logical chunks in extent space. It gives a view
 * of the valid chunks in extent. When the reference count of mask becomes zero, it is
 * safe to delete mask and also chunks that are invalid after this mask.
 */
typedef struct castle_extent_mask {
    c_ext_mask_id_t         mask_id;        /**< Unique mask ID.                        */
    c_ext_mask_range_t      range;
    atomic_t                ref_count;      /**< Number of references on this mask.     */
    struct list_head        list;           /**< Link to extent mask list.              */
    struct list_head        hash_list;      /**< Link to hash list.                     */
    struct castle_extent   *ext;            /**< Extent that this mask belongs to.      */
} c_ext_mask_t;

static int castle_extent_mask_create(c_ext_t          *ext,
                                     c_ext_mask_range_t range,
                                     c_ext_mask_id_t   prev_mask_id);

static inline c_ext_pos_t castle_extent_map_cep_get(c_ext_pos_t     map_start,
                                                    c_chk_t         chk_idx,
                                                    uint32_t        k_factor);

static c_ext_mask_id_t castle_extent_get_ptr(c_ext_id_t ext_id, c_ext_t **ext);

#define CASTLE_EXTENT_MASK_HASH_SIZE 100

static struct list_head *castle_extent_mask_hash = NULL;

static DECLARE_WAIT_QUEUE_HEAD (castle_ext_mask_gc_wq);

DEFINE_HASH_TBL(castle_extent_mask, castle_extent_mask_hash, CASTLE_EXTENT_MASK_HASH_SIZE,
                c_ext_mask_t, hash_list, c_ext_mask_id_t, mask_id);

static struct list_head *castle_extents_hash = NULL;
static c_ext_free_t meta_ext_free;

atomic_t castle_extents_gc_q_size = ATOMIC(0);

static LIST_HEAD(castle_ext_mask_free_list);

static atomic_t castle_extent_max_mask_id = ATOMIC(0);
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
                                       c_chk_cnt_t    ext_size,
                                       c_chk_cnt_t    alloc_size,
                                       c_ext_id_t     ext_id,
                                       c_ext_event_t *hdl);
void __castle_extent_dirtytree_put(c_ext_dirtytree_t *dirtytree, int check_hash);

static void castle_extent_mask_reduce(c_ext_t             *ext,
                                      c_ext_mask_range_t   base,
                                      c_ext_mask_range_t   range1,
                                      c_ext_mask_range_t  *global_mask,
                                      int                  do_free);

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
static struct list_head     rebuild_done_list;
struct mutex                rebuild_done_list_lock;
static struct list_head     verify_list; /* Used for testing. */
static wait_queue_head_t    rebuild_wq;
static wait_queue_head_t    rebuild_done_wq;
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

struct task_struct         *extents_gc_thread;

static struct kmem_cache   *castle_partial_schks_cache = NULL;

/**
 * Partial Superchunks handling.
 */

c_chk_cnt_t castle_extent_free_chunks_count(c_ext_t *ext, uint32_t slave_id)
{
    struct list_head *pos;
    c_chk_cnt_t count = 0;

    BUG_ON(!ext);

    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);

        if (part_schk->slave_id == slave_id)
            count += part_schk->count;
    }

    return count;
}

static c_part_schk_t *castle_extent_part_schk_get(c_ext_t *ext, struct castle_slave *slave)
{
    struct list_head *pos;

    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);

        if (part_schk->slave_id == slave->id)
            return part_schk;
    }

    return NULL;
}

static void castle_extent_part_schk_save(c_ext_t       *ext,
                                         uint32_t       slave_id,
                                         c_chk_t        first_chk,
                                         c_chk_cnt_t    count)
{
    struct list_head *pos;
    c_part_schk_t *part_schk = NULL;

    BUG_ON(count == 0);

    /* Don't try to save more than one super chunk at a time. */
    BUG_ON(SUPER_CHUNK(first_chk) != SUPER_CHUNK(first_chk + count - 1));

    /* Go over all existing super chunks and try to append to them. */
    list_for_each(pos, &ext->schks_list)
    {
        part_schk = list_entry(pos, c_part_schk_t, list);

        /* Shouldn't have any empty partial super chunks in the list. */
        BUG_ON(part_schk->count == 0);

        /* If the super chuink belongs to different slave, skip. */
        if (slave_id != part_schk->slave_id)
            continue;

        /* If its a different superchunk, skip. */
        if (SUPER_CHUNK(first_chk) != SUPER_CHUNK(part_schk->first_chk))
            continue;

        /* Check if it is appendable at end. */
        if (first_chk == (part_schk->first_chk + part_schk->count))
        {
            part_schk->count += count;
            break;
        }

        /* Check if it is appendable at start. */
        if (part_schk->first_chk == (first_chk + count))
        {
            part_schk->first_chk = first_chk;
            part_schk->count += count;
            break;
        }
    }

    /* Check if we stopped in between. */
    if (pos != &ext->schks_list)
    {
        /* If we stopped in between, there should be a matching superchunk. And Superchunk
         * size should be sane. */
        BUG_ON(part_schk == NULL || part_schk->count > CHKS_PER_SLOT);

        /* If the superchunk is full, free it. */
        if (part_schk->count == CHKS_PER_SLOT)
        {
            /* First chunk should be aligned to superchunk. */
            BUG_ON(part_schk->first_chk % CHKS_PER_SLOT);

            debug_schks("Freeing superchunk %u\n", part_schk->first_chk);

            /* Free super chunk. */
            castle_freespace_slave_superchunk_free(castle_slave_find_by_id(slave_id),
                                                   SUPER_CHUNK_STRUCT(part_schk->first_chk));

            /* Delete from list. */
            list_del(&part_schk->list);

            /* Free space. */
            kmem_cache_free(castle_partial_schks_cache, part_schk);
        }

        return;
    }

    /* If we are here, we couldn't find any appropriate superchunk in the list. */
    /* Allocate memory. */
    part_schk = kmem_cache_alloc(castle_partial_schks_cache, GFP_KERNEL);
    BUG_ON(!part_schk);

    /* Init and add to the list. */
    part_schk->slave_id     = slave_id;
    part_schk->first_chk    = first_chk;
    part_schk->count        = count;
    list_add(&part_schk->list, &ext->schks_list);
}

/* TODO: Works not efficent. Re-check. */
static void castle_extent_part_schks_converge(c_ext_t *ext)
{
    struct list_head *pos, *tmp, *pos1;
    c_part_schk_t *part_schk, *part_schk1;
    LIST_HEAD(free_list);

    list_for_each(pos, &ext->schks_list)
    {
        part_schk = list_entry(pos, c_part_schk_t, list);

        list_for_each_safe(pos1, tmp, &ext->schks_list)
        {
            part_schk1 = list_entry(pos1, c_part_schk_t, list);

            if (part_schk->first_chk == (part_schk1->first_chk + part_schk1->count) ||
                part_schk1->first_chk == (part_schk->first_chk + part_schk->count))
            {
                list_del(pos1);
                list_add(pos1, &free_list);

                continue;
            }
        }
    }

    list_for_each_safe(pos, tmp, &free_list)
    {
        part_schk = list_entry(pos, c_part_schk_t, list);

        castle_extent_part_schk_save(ext, part_schk->slave_id, part_schk->first_chk, part_schk->count);
        list_del(pos);

        /* Free space. */
        kmem_cache_free(castle_partial_schks_cache, part_schk);
    }
}

static int castle_extent_part_schks_writeback(c_ext_t *ext, void *store)
{
    struct list_head *pos;
    struct castle_plist_entry mstore_entry;
    c_mstore_t *castle_part_schks_mstore = store;

    /* Go over all existing super chunks and write them to mstore. */
    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *part_schk = list_entry(pos, c_part_schk_t, list);
        struct castle_slave *cs = castle_slave_find_by_id(part_schk->slave_id);

        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            continue;

        mstore_entry.ext_id     = ext->ext_id;
        mstore_entry.slave_uuid = cs->uuid;
        mstore_entry.first_chk  = part_schk->first_chk;
        mstore_entry.count      = part_schk->count;

        castle_mstore_entry_insert(castle_part_schks_mstore, &mstore_entry);
    }

    return 0;
}

static int castle_extents_part_schks_writeback(void)
{
    c_mstore_t *castle_part_schks_mstore;

    castle_part_schks_mstore =
                castle_mstore_init(MSTORE_PART_SCHKS, sizeof(struct castle_plist_entry));
    if (!castle_part_schks_mstore)
        return -ENOMEM;

    __castle_extents_hash_iterate(castle_extent_part_schks_writeback, castle_part_schks_mstore);

    castle_mstore_fini(castle_part_schks_mstore);

    return 0;
}

static int castle_extents_part_schks_read(void)
{
    struct castle_plist_entry entry;
    struct castle_mstore_iter *iterator = NULL;
    c_mstore_t *castle_part_schks_mstore = NULL;
    c_mstore_key_t key;

    castle_part_schks_mstore =
        castle_mstore_open(MSTORE_PART_SCHKS, sizeof(struct castle_plist_entry));
    if(!castle_part_schks_mstore)
        return -ENOMEM;

    iterator = castle_mstore_iterate(castle_part_schks_mstore);
    if (!iterator)
        goto error_out;

    while (castle_mstore_iterator_has_next(iterator))
    {
        c_ext_t *ext;
        struct castle_slave *cs;

        castle_mstore_iterator_next(iterator, &entry, &key);

        ext = castle_extents_hash_get(entry.ext_id);
        cs = castle_slave_find_by_uuid(entry.slave_uuid);

        /* TODO: Handle gracefully. */
        BUG_ON(!ext || !cs);

        castle_extent_part_schk_save(ext, cs->id,
                                     entry.first_chk,
                                     entry.count);
    }

    castle_mstore_iterator_destroy(iterator);
    castle_mstore_fini(castle_part_schks_mstore);

    return 0;

error_out:
    if (iterator)                   castle_mstore_iterator_destroy(iterator);
    if (castle_part_schks_mstore)   castle_mstore_fini(castle_part_schks_mstore);

    return -1;
}

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
        castle_kfree(ext);
        return NULL;
    }

    /* Extent structure. */
    ext->ext_id             = ext_id;
#ifdef CASTLE_DEBUG
    ext->alive              = 1;
#endif
    ext->maps_cep           = INVAL_EXT_POS;
    ext->ext_type           = EXT_T_INVALID;
    ext->da_id              = INVAL_DA;
    atomic_set(&ext->link_cnt, 1);
    spin_lock_init(&ext->shadow_map_lock);

    INIT_LIST_HEAD(&ext->mask_list);
    INIT_LIST_HEAD(&ext->schks_list);
    ext->rebuild_mask_id    = INVAL_MASK_ID;

    /* Per-extent RB dirtytree structure. */
    ext->dirtytree->ext_id  = ext_id;
    ext->dirtytree->ref_cnt = ATOMIC(1);
    ext->dirtytree->rb_root = RB_ROOT;
    INIT_LIST_HEAD(&ext->dirtytree->list);
    spin_lock_init(&ext->dirtytree->lock);
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size= 0;
    ext->dirtytree->ext_type= ext->ext_type;
#endif
    ext->chkpt_global_mask = EMPTY_MASK_RANGE;

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
    printk("%s::ext_id %lld\n", __FUNCTION__, ext_id);

    if (ext)
    {
        /* Extent should belong to the same DA. */
        BUG_ON(ext->da_id != da_id);

        /* Create a link. This is the extra link other than the one in castle_ext_alloc().
         * This preserves the extent. */
        BUG_ON(castle_extent_link(ext_id));
    }
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
    /* Logical extents are always alive. */
    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    /* Remove the link, we have created in castle_ext_alloc(). If no module called
     * castle_extent_mark_live() on the extent. It would have only one link and would
     * get freed. */
    BUG_ON(castle_extent_unlink(ext->ext_id));

    return 0;
}

int castle_extents_restore(void)
{
    __castle_extents_hash_iterate(castle_extent_check_alive, NULL);
    return 0;
}

static int castle_extents_garbage_collector(void *unused);

int castle_extents_init(void)
{
    debug("Initing castle extents\n");

    /* Initialise extents garbage collector. */
    extents_gc_thread = kthread_run(castle_extents_garbage_collector, NULL,
                                    "castle-extents-gc");
    if (IS_ERR(extents_gc_thread))
    {
        castle_printk(LOG_INIT, "Could not start garbage collector thread for extents\n");
        goto err_out;
    }

    /* Initialise hash table for extents. */
    castle_extents_hash = castle_extents_hash_alloc();
    if (!castle_extents_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        kthread_stop(extents_gc_thread);

        goto err_out;
    }
    castle_extents_hash_init();

    /* Initialise hash table for extent masks. */
    castle_extent_mask_hash = castle_extent_mask_hash_alloc();
    if (!castle_extent_mask_hash)
    {
        castle_printk(LOG_INIT, "Could not allocate extents hash.\n");
        kthread_stop(extents_gc_thread);

        goto err_out;
    }
    castle_extent_mask_hash_init();

    /* Init kmem_cache for in_flight counters for extent_flush. */
    castle_partial_schks_cache = kmem_cache_create("castle_partial_schks_cache",
                                            sizeof(c_part_schk_t),
                                            0,   /* align */
                                            0,   /* flags */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                            NULL, NULL); /* ctor, dtor */
#else
                                            NULL); /* ctor */
#endif
    if (!castle_partial_schks_cache)
    {
        castle_printk(LOG_INIT,
                      "Could not allocate kmem cache for castle_partial_schks_cache.\n");
        goto err_out;
    }

    return EXIT_SUCCESS;

err_out:
    castle_extents_fini();
    return -ENOMEM;
}

/* Cleanup all extents from hash table. Called at finish. */
static int castle_extent_hash_remove(c_ext_t *ext, void *unused)
{
    c_ext_mask_t *mask = GET_LATEST_MASK(ext);
    struct list_head *pos, *tmp;

    castle_printk(LOG_DEBUG, "%s::Freeing extent #%llu\n", __FUNCTION__, ext->ext_id);

    /* Should have only one valid mask. */
    BUG_ON(!list_is_last(&mask->list, &ext->mask_list));

    /* And its reference count should be equal to number of links. */
    BUG_ON(atomic_read(&mask->ref_count) != 1);

    /* There shouldn't be any outstanding extents for deletion on exit. */
    __castle_extents_hash_remove(ext);

    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs =
                castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));

        castle_kfree(cs->sup_ext_maps);
    }
    __castle_extent_dirtytree_put(ext->dirtytree, 0 /*check_hash*/);

    /* Free memory occupied by superchunk strcutures. */
    list_for_each_safe(pos, tmp, &ext->schks_list)
    {
        c_part_schk_t *schk = list_entry(pos, c_part_schk_t, list);

        kmem_cache_free(castle_partial_schks_cache, schk);
    }

    castle_kfree(mask);
    castle_kfree(ext);

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
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(MICRO_EXT_ID, &micro_ext);
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

    castle_extent_put(mask_id);
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
#ifdef CASTLE_PERF_DEBUG
    micro_ext->dirtytree->ext_size  = micro_ext->size;
    micro_ext->dirtytree->ext_type  = micro_ext->ext_type;
#endif

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

    /* Create a mask for it. */
    BUG_ON(castle_extent_mask_create(micro_ext,
                                     MASK_RANGE(0, micro_ext->size),
                                     INVAL_MASK_ID) < 0);

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
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID,
                                  NULL);
    if (ext_id != MSTORE_EXT_ID)
        return -ENOSPC;

    ext_id = _castle_extent_alloc(DEFAULT_RDA, 0,
                                  EXT_T_META_DATA,
                                  MSTORE_SPACE_SIZE * i / k_factor,
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
    if(castle_last_checkpoint_ongoing && (atomic_read(&ext->link_cnt) == 0))
        castle_printk(LOG_DEBUG, "%s::ext %p ext_id %d\n", __FUNCTION__, ext, ext->ext_id);
    BUG_ON(castle_last_checkpoint_ongoing && (atomic_read(&ext->link_cnt) == 0));

    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    debug("Writing back extent %llu\n", ext->ext_id);

    CONVERT_EXTENT_TO_MENTRY(ext, &mstore_entry);

    castle_mstore_entry_insert(castle_extents_mstore, &mstore_entry);

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
    if (castle_last_checkpoint_ongoing)
        while (atomic_read(&castle_extents_gc_q_size) || atomic_read(&castle_extents_dead_count))
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
    __castle_extents_hash_iterate(castle_extent_writeback, castle_extents_mstore);

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

    /* Write list of partial superchunks for all extents into mstore. */
    castle_extents_part_schks_writeback();

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

    /* ext_alloc() would set the alive bit to 1. Shouldn't do that during module reload.
     * Instead, extent owner would mark it alive. */
#ifdef CASTLE_DEBUG
    ext->alive = 0;
#endif

    CONVERT_MENTRY_TO_EXTENT(ext, mstore_entry);
    if (EXT_ID_INVAL(ext->ext_id))
    {
        ret = -EINVAL;
        goto err2;
    }

    /* Create the initial masks. */
    BUG_ON(castle_extent_mask_create(ext,
                                     mstore_entry->prev_mask,
                                     INVAL_MASK_ID) < 0);

    castle_extents_hash_add(ext);

    /* This would delete the previous mask, as it doesnt have any references. */
    BUG_ON(castle_extent_mask_create(ext,
                                     mstore_entry->cur_mask,
                                     GET_LATEST_MASK(ext)->mask_id) < 0);

    castle_extent_print(ext, NULL);

    return 0;

err2:
    castle_kfree(ext->dirtytree);
    castle_kfree(ext);
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

    /* Read partial superchunks for extents. */
    if (castle_extents_part_schks_read())
        goto error_out;

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
    /* Stop the Garbage collector thread. */
    kthread_stop(extents_gc_thread);

    /* Make sure cache flushed all dirty pages */
    /* Iterate over extents hash with exclusive access. Indeed, we don't need a
     * lock here as this happenes in the module end. */
    if (castle_extents_hash)
    {
        castle_extents_hash_iterate_exclusive(castle_extent_hash_remove, NULL);
        castle_kfree(castle_extents_hash);
    }

    if (castle_extent_mask_hash)
        castle_kfree(castle_extent_mask_hash);

    if (castle_partial_schks_cache)
        kmem_cache_destroy(castle_partial_schks_cache);
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

static void castle_extent_state_dealloc(c_ext_t *ext, struct castle_extent_state *ext_state)
{
    int i, j;

    for(i=0; i<MAX_NR_SLAVES; i++)
        for(j=0; j<MAX_K_FACTOR; j++)
            if (!CHK_INVAL(ext_state->chunks[i][j]))
            {
                debug_schks("Left with part_schk after exntent alloc: %u, (%u, %u)\n",
                            ext->ext_id, ext_state->chunks[i][j],
                            CHKS_PER_SLOT - (ext_state->chunks[i][j] % CHKS_PER_SLOT));
                castle_extent_part_schk_save(ext,
                                             i,
                                             ext_state->chunks[i][j],
                                             CHKS_PER_SLOT -
                                                (ext_state->chunks[i][j] % CHKS_PER_SLOT));
            }

    castle_kfree(ext_state);
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
static void castle_extent_space_free(c_ext_t *ext, c_chk_cnt_t start, c_chk_cnt_t count)
{
    c_chk_cnt_t                 chks_per_page;
    c_ext_pos_t                 map_cep;
    c2_block_t                  *map_c2b;
    c_disk_chk_t                *map_buf;
    struct castle_slave         *cs;

    debug("Freeing %d disk chunks from extent %lld\n", count, ext->ext_id);
    chks_per_page = map_chks_per_page(ext->k_factor);

    /* Find map cep for the start chunk. */
    map_cep = castle_extent_map_cep_get(ext->maps_cep, start, ext->k_factor);
    map_c2b = NULL;
    debug("Map at cep: "cep_fmt_str_nl, cep2str(map_cep));
    while(count>0)
    {
        c_chk_cnt_t logical_chunk;

        /* If this is the first page, set first logical_chunk accordingly.*/
        logical_chunk = (map_c2b)? 0: (start % chks_per_page);

        /* Get page-worth of extent map. */
        debug("Processing map page at cep: "cep_fmt_str_nl, cep2str(map_cep));
        map_cep = PG_ALIGN_CEP(map_cep);
        map_c2b = castle_cache_page_block_get(map_cep);
        write_lock_c2b(map_c2b);
        if(!c2b_uptodate(map_c2b))
            BUG_ON(submit_c2b_sync(READ, map_c2b));
        map_buf = c2b_buffer(map_c2b);

        /* For each logical chunk, look through each copy. */
        for (; (logical_chunk < chks_per_page) && (count > 0); logical_chunk++)
        {
            int copy;
            for(copy=0; (copy<ext->k_factor) && (count > 0); copy++)
            {
                cs = castle_slave_find_by_uuid(
                    map_buf[logical_chunk*ext->k_factor + copy].slave_id);
                BUG_ON(!cs);

                if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                    castle_extent_part_schk_save(ext,
                                                 cs->id,
                                                 map_buf[logical_chunk * ext->k_factor + copy].offset,
                                                 1);
                count--;
            }
        }

        write_unlock_c2b(map_c2b);
        put_c2b(map_c2b);

        map_cep.offset += C_BLK_SIZE;
    }

    castle_extent_part_schks_converge(ext);
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
    c_part_schk_t *part_schk;
    c_chk_t *chk;

    disk_chk = INVAL_DISK_CHK;
    disk_chk.slave_id = slave->uuid;
    /* Work out which chunk sequence we are using. */
    chk = &ext_state->chunks[slave->id][copy_id];
    debug("*chk: %d/0x%x\n", *chk, *chk);

    /* If there are no chunks in the buffer, get them from partial superchunk buffer for the
     * extent. */
    if (CHK_INVAL(*chk) && (part_schk = castle_extent_part_schk_get(ext_state->ext, slave)))
    {
        /* Check if the partial superchunk is preoperly aligned. */
        BUG_ON((part_schk->first_chk + part_schk->count) % CHKS_PER_SLOT);

        /* Partial superchunks can't be bigger than a superchunk. If it is this code ignores
         * the part bigger than superchunk. */
        BUG_ON(part_schk->count > CHKS_PER_SLOT);

        /* Update the chunk buffer in extent state. */
        *chk = part_schk->first_chk;

        /* No need to keep this in list anymore. Get rid of it. */
        list_del(&part_schk->list);
        kmem_cache_free(castle_partial_schks_cache, part_schk);
    }

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
int castle_extent_space_alloc(c_ext_t *ext, c_da_t da_id, c_chk_cnt_t alloc_size)
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
    c_chk_cnt_t start;

    /* Nothing to allocate. */
    if (!alloc_size)
        return 0;

    BUG_ON(LOGICAL_EXTENT(ext->ext_id) && (ext->ext_id < META_EXT_ID));

    /* Should be in transaction. */
    BUG_ON(!castle_extent_in_transaction());

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
    rda_state = rda_spec->extent_init(ext, ext->size, alloc_size, ext->type);
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
    start = ext->chkpt_global_mask.end;
    map_cep = castle_extent_map_cep_get(ext->maps_cep, start, ext->k_factor);
    map_cep.offset = MASK_BLK_OFFSET(map_cep.offset);
    map_page_idx = start % max_map_page_idx;
    map_page = NULL;
    map_c2b = NULL;
    for(chunk=0; chunk<alloc_size; chunk++)
    {
        debug("Map_page_idx: %d/%d\n", map_page_idx, max_map_page_idx);
        /* Move to the next map page, once the index overflows the max. */
        if(!map_c2b || (map_page_idx >= max_map_page_idx))
        {
            /* Release the previous map_c2b, if one exists. */
            if(map_c2b)
            {
                debug("Putting old map_c2b for cep: "cep_fmt_str_nl, cep2str(map_c2b->cep));
                dirty_c2b(map_c2b);
                write_unlock_c2b(map_c2b);
                put_c2b(map_c2b);

                /* Reset the index. */
                map_page_idx = 0;
            }
            /* Get the next map_c2b. */
            debug("Getting map c2b, for cep: "cep_fmt_str_nl, cep2str(map_cep));
            map_c2b = castle_cache_page_block_get(map_cep);
            write_lock_c2b(map_c2b);

            /* Read old maps, if we are allocating from in-between. */
            if (map_page_idx && !c2b_uptodate(map_c2b))
                BUG_ON(submit_c2b_sync(READ, map_c2b));
            else
                update_c2b(map_c2b);

            /* Reset the map pointer. */
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
                castle_extent_space_free(ext, 0, ext->k_factor * chunk + j);
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
        rda_spec->extent_fini(rda_state);
    if(ext_state)
        castle_extent_state_dealloc(ext, ext_state);

    return err;
}

c_ext_id_t castle_extent_alloc_sparse(c_rda_type_t             rda_type,
                                      c_da_t                   da_id,
                                      c_ext_type_t             ext_type,
                                      c_chk_cnt_t              ext_size,
                                      c_chk_cnt_t              alloc_size,
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

    ret = _castle_extent_alloc(rda_type, da_id, ext_type, ext_size, alloc_size, INVAL_EXT_ID, event_hdl);

    /* End the transaction. */
    if (!in_tran)   castle_extent_transaction_end();

    return ret;
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
                               c_chk_cnt_t              ext_size,
                               int                      in_tran,
                               void                    *data,
                               c_ext_event_callback_t   callback)
{
    return castle_extent_alloc_sparse(rda_type, da_id, ext_type, ext_size, ext_size,
                                      in_tran, data, callback);
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
                                       c_chk_cnt_t      ext_size,
                                       c_chk_cnt_t      alloc_size,
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

    debug("Creating extent of size: %u/%u\n", ext_size, alloc_size);
    ext = castle_ext_alloc(0);
    if (!ext)
    {
        castle_printk(LOG_WARN, "Failed to allocate memory for extent\n");
        goto __hell;
    }
    castle_extents_sb       = castle_extents_super_block_get();

    ext->ext_id             = EXT_ID_INVAL(ext_id) ? castle_extents_sb->ext_id_seq : ext_id;
    ext->dirtytree->ext_id  = ext->ext_id;
    ext->size               = ext_size;
    ext->type               = rda_type;
    ext->k_factor           = rda_spec->k_factor;
    ext->ext_type           = ext_type;
    ext->da_id              = da_id;
    ext->use_shadow_map     = 0;
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size= ext->size;
    ext->dirtytree->ext_type= ext->ext_type;
#endif

    /* The rebuild sequence number that this extent starts off at */
    ext->curr_rebuild_seqno = atomic_read(&current_rebuild_seqno);
    ext->rebuild_done_list.next = NULL;
    ext->remap_seqno = 0;

    /* Block aligned chunk maps for each extent. */
    if (ext->ext_id == META_EXT_ID)
    {
        ext->maps_cep.ext_id = MICRO_EXT_ID;
        ext->maps_cep.offset = 0;
    }
    else
    {
        uint32_t nr_blocks = map_size(ext_size, rda_spec->k_factor);

        if (castle_ext_freespace_get(&meta_ext_free, (nr_blocks * C_BLK_SIZE), 0, &ext->maps_cep))
        {
            castle_printk(LOG_WARN, "Too big of an extent/crossing the boundry.\n");
            goto __hell;
        }
        debug("Allocated extent map at: "cep_fmt_str_nl, cep2str(ext->maps_cep));
    }

    BUG_ON(BLOCK_OFFSET(ext->maps_cep.offset));

    if (alloc_size == 0)
        goto alloc_done;

    if ((ret = castle_extent_space_alloc(ext, da_id, alloc_size)) == -ENOSPC)
    {
        debug("Extent alloc failed to allocate space for %u chunks\n", alloc_size);
        goto __low_space;
    }
    else if (ret < 0)
    {
        debug("Extent alloc failed for %u chunks\n", alloc_size);
        goto __hell;
    }

alloc_done:
    /* Successfully allocated space for extent. Create a mask for it. */
    BUG_ON(castle_extent_mask_create(ext,
                                     MASK_RANGE(0, alloc_size),
                                     INVAL_MASK_ID) < 0);

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
        castle_kfree(event_hdl);

    return ext->ext_id;

__low_space:
    castle_printk(LOG_INFO, "Failed to create extent for DA: %u of type %s for %u chunks\n",
                  da_id,
                  castle_ext_type_str[ext_type],
                  alloc_size);
    /* Add the victim handler to the list of handlers of specific type. This handler gets
     * called, when more space is available. */
    castle_extent_lfs_callback_add(event_hdl);

__hell:
    if (ext)
    {
        castle_kfree(ext->dirtytree);
        castle_kfree(ext);
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
        if (!castle_last_checkpoint_ongoing)
            ret = hdl->callback(hdl->data);

         /* Handled low free space successfully. Get rid of event handler. */
         list_del(&hdl->list);
         castle_kfree(hdl);

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

/* Free the resources taken by extent. This function gets executed on system work queue.
 *
 * @param data void pointer to extent structure that to be freed.
 *
 * @also castle_extent_put
 * @also castle_extent_unlink
 */
static void castle_extent_resource_release(void *data)
{
    c_ext_t *ext = data;
    struct castle_extents_superblock *castle_extents_sb = NULL;
    c_ext_id_t ext_id = ext->ext_id;
    struct list_head *pos;

    /* Should be in transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /* Shouldn't have partial superchunks left. */
    list_for_each(pos, &ext->schks_list)
    {
        c_part_schk_t *schk = list_entry(pos, c_part_schk_t, list);

        printk("%llu: Superchunk: (%u:%u)\n", ext_id, schk->first_chk, schk->count);
    }

    BUG_ON(!list_empty(&ext->schks_list));

    /* Shouldn't have any live masks left. */
    BUG_ON(!list_empty(&ext->mask_list));

    /* Reference count should be zero. */
    if (atomic_read(&ext->link_cnt))
    {
        castle_printk(LOG_ERROR, "Couldn't delete the referenced extent %llu, %d\n",
                                 ext_id,
                                 atomic_read(&ext->link_cnt));
        BUG();
    }

    /* Get the extent lock, to prevent checkpoint happening parallely. */
    castle_extents_sb = castle_extents_super_block_get();

    /* Remove extent from hash. */
    castle_extents_hash_remove(ext);

    /* Drop 'extent exists' reference on c2b dirtytree. */
    castle_extent_dirtytree_put(ext->dirtytree);

    debug("Completed deleting ext: %lld\n", ext_id);

    castle_extents_sb->nr_exts--;

    /* Decrement the dead count. Module can't exit with outstanding dead extents.  */
    atomic_dec(&castle_extents_dead_count);
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

/**
 * Get the mapping of disk chunk layout for a given logical chunk in extent.
 *
 * Note: Caller should be holding a reference on the extent.
 */
uint32_t castle_extent_map_get(c_ext_id_t     ext_id,
                               c_chk_t        offset,
                               c_disk_chk_t  *chk_map,
                               int            rw)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
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

    if ((offset < ext->chkpt_global_mask.start) || (offset >= ext->chkpt_global_mask.end))
        return 0;

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
#ifdef CASTLE_PERF_DEBUG
    ext->dirtytree->ext_size    = ext->size;
    ext->dirtytree->ext_type    = ext->ext_type;
#endif

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

    castle_extent_transaction_start();

    /* Create a mask for it. */
    BUG_ON(castle_extent_mask_create(ext,
                                     MASK_RANGE(0, ext->size),
                                     INVAL_MASK_ID) < 0);

    castle_extents_hash_add(ext);
    cs->sup_ext = ext->ext_id;

    castle_extent_transaction_end();

    debug("Created super extent %llu for slave 0x%x\n", ext->ext_id, cs->uuid);

    return ext->ext_id;

err2:
    castle_kfree(ext->dirtytree);
    castle_kfree(ext);
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
        c_ext_mask_t *mask = GET_LATEST_MASK(ext);

        BUG_ON(atomic_read(&mask->ref_count) != 1);
        castle_extents_hash_remove(ext);
        castle_kfree(ext);
    }
    castle_kfree(cs->sup_ext_maps);

    return;
}

/**
 * Extents Reference Counting:
 *
 * Extent structures can be referenced two ways..
 *      - links
 *      - transient references
 *
 * Links are used to link extents to multiple sources. For ex, large objects could be linked and
 * unlinked between component trees during merges. Links also take a transient reference on the
 * extent. Removing the last link to an extent, would mark the extent for deletion. Other than
 * that, it wouldn't do anything else. Also leaves the extent in the hash, to make sure no
 * outstanding operations would fail. It is not possible to get any references or links after
 * releasing the last link.
 *
 * Transient references are taken on extents to preserve them while doing some task(mostly io).
 * It is not possible to get a reference on an extent with no active links. After deleting last
 * reference, schedule the free function and also add the extent to a deleted extents list.
 * Last checkpoint of extent code should wait on this list to get exmpty to make sure there are
 * no outstanding deletes.
 *
 * Synchronization for Reference Counting:
 *
 * Both counts ref_cnt and link_count would be atomic variables to make sure multiple writes to
 * these variables won't race. Four operations we need for this are get(), put(), link() and
 * unlink(). It is okay to run get() and link() to run together. They just get references. Only
 * races that are possible are when the last link and last reference are released, link() and get()
 * should see it in consistent way. So, run unulink() and put() under write lock and get() and
 * link() under read lock.
 */

#define LIVE_EXTENT(_ext) ((_ext) && atomic_read(&(_ext)->link_cnt))

/**
 * Get a reference on the latest mask. Don't give a reference, if the extent doesn't have
 * any active links.
 *
 * @param ext_id    [in]    Extent that the reference is seeking for.
 *
 * @return mask_id  ID of the mask that reference is given for.
 */
c_ext_mask_id_t castle_extent_mask_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = __castle_extents_hash_get(ext_id);
    uint32_t val;

    /* Expected to hold atleast read_lock. */
    BUG_ON(write_can_lock(&castle_extents_hash_lock));

    /* Don't give reference if extent is not alive. */
    if (LIVE_EXTENT(ext))
    {
        /* Get the latest mask for this extent. */
        c_ext_mask_t *mask = GET_LATEST_MASK(ext);

        /* Get a reference on latest mask. Count shouldn't be zero, before increment. */
        BUG_ON((val = atomic_inc_return(&mask->ref_count)) == 1);

        //castle_printk(LOG_DEVEL, "GET: %u "cemr_cstr"%u\n", mask->mask_id, cemr2str(mask->range), val);

        BUG_ON(castle_extent_mask_hash_get(mask->mask_id) == NULL);

        /* Return the mask ID. put() needs to be called with the same ID. */
        return mask->mask_id;
    }

    /* Extent is not alive. Return error. */
    return INVAL_MASK_ID;
}

/**
 * Release reference on the extent mask. Locks are already taken. If releasing last
 * reference, add the mask to the free list. It get's deleted by the extent garbage
 * collector thread.
 *
 * Can't free the resources from this function as that would be sleeping function and
 * the function could be in interrupt context. Instead, offload the task.
 *
 * @param mask_id [inout]   Extent mask that reference has to be released.
 */
void castle_extent_mask_put(c_ext_mask_id_t mask_id)
{
    /* Get the mask structure. */
    c_ext_mask_t *mask = castle_extent_mask_hash_get(mask_id);
    uint32_t val;

    /* Expected to hold atleast read_lock. */
    BUG_ON(write_can_lock(&castle_extents_hash_lock));

    /* Mask should be alive. */
    BUG_ON(mask == NULL);

    /* Reference count shouldn't be zero. */
    if (atomic_read(&mask->ref_count) == 0)
    {
        printk("mask: %p\n", mask);
        BUG();
    }

    val = atomic_dec_return(&mask->ref_count);
    //castle_printk(LOG_DEVEL, "PUT: %u "cemr_cstr"%u\n", mask->mask_id, cemr2str(mask->range), val);
    /* Release reference and also check if this is the last referece; if so, schedule mask
     * for deletion. */
    if (val == 0)
    {
        static DEFINE_SPINLOCK(mask_ref_release_lock);
        unsigned long flags;
        int release_mask = 0;

        /* Take lock to make sure, no other last reference release for other in this
         * extent is racgin. */
        spin_lock_irqsave(&mask_ref_release_lock, flags);

        if (IS_OLDEST_MASK(mask->ext, mask))
            release_mask = 1;
        else
        {
            c_ext_mask_t *next_mask = list_entry(mask->list.next, c_ext_mask_t, list);

            /* If the next mask is not in hash, then it is already marked for deletion. And
             * this mask can be deleted. */
            if (!castle_extent_mask_hash_get(next_mask->mask_id))
                release_mask = 1;
        }

        if (release_mask)
        {
            c_ext_t *ext = mask->ext;
            struct list_head *pos;

            /* Update global mask. */
            list_for_each_prev(pos, &ext->mask_list)
            {
                c_ext_mask_t *pos_mask = list_entry(pos, c_ext_mask_t, list);

                /* Already scheduled for release. */
                if (castle_extent_mask_hash_get(pos_mask->mask_id) == NULL)
                    continue;

                /* Not yet ready for release. */
                if (atomic_read(&pos_mask->ref_count))
                    break;

#if 0
                castle_printk(LOG_DEVEL, "Scheduling mask %u "cemr_cstr" for free\n",
                                         pos_mask->mask_id, cemr2str(pos_mask->range));
#endif
                /* If this is the last mask, there should be no active links. */
                BUG_ON(list_is_singular(&ext->mask_list) && atomic_read(&ext->link_cnt));

                castle_extent_mask_hash_remove(pos_mask);

                /* Add to the free list, it would get destroyed later by the GC thread. */
                list_add_tail(&pos_mask->hash_list, &castle_ext_mask_free_list);

                atomic_inc_return(&castle_extents_gc_q_size);
            }

            /* Wakeup the garbage collector. */
            wake_up(&castle_ext_mask_gc_wq);
        }

        spin_unlock_irqrestore(&mask_ref_release_lock, flags);
    }
}

/**
 * Take a reference on extent to preserve extent from being deleted.
 *
 * @param   ext_id  [in]    Extent id that reference to be taken.
 *
 * @return  Pointer of extent, if SUCCESS
 *          NULL, if FAILURE
 */
c_ext_mask_id_t castle_extent_get(c_ext_id_t ext_id)
{
    static int count=0;
    unsigned long flags;
    c_ext_mask_id_t mask_id;

    /* Read lock is good enough as ref count is atomic. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Call low level get function. */
    mask_id = castle_extent_mask_get(ext_id);

    castle_printk(LOG_DEBUG, "%s::count = %d\n", __FUNCTION__, count++);
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return mask_id;
}

/**
 * Take a reference on all extent views by taking reference on latest and oldest masks.
 *
 * @param   ext_id  [in]    Extent id that reference to be taken.
 *
 * @return  Pointer of extent, if SUCCESS
 *          NULL, if FAILURE
 */
c_ext_mask_id_t castle_extent_get_all(c_ext_id_t ext_id)
{
    unsigned long flags;
    c_ext_mask_id_t mask_id;

    /* Call low level get function. */
    mask_id = castle_extent_get(ext_id);

    /* Take reference on oldest mask. */
    if (!MASK_ID_INVAL(mask_id))
    {
        c_ext_mask_t *mask, *oldest_mask;
        struct list_head *pos;

        /* Take writelock to make sure last valid mask is not getting released. */
        write_lock_irqsave(&castle_extents_hash_lock, flags);

        mask = castle_extent_mask_hash_get(mask_id);
        if (!mask)
        {
            printk("%llu %u\n", ext_id, mask_id);
            BUG();
        }

        list_for_each_prev(pos, &mask->ext->mask_list)
        {
            oldest_mask = list_entry(pos, c_ext_mask_t, list);

            if (atomic_read(&oldest_mask->ref_count))
            {
                uint32_t val;
                BUG_ON((val = atomic_inc_return(&oldest_mask->ref_count)) == 1);
                //castle_printk(LOG_DEVEL, "get: %u "cemr_cstr"%u\n", oldest_mask->mask_id, cemr2str(oldest_mask->range), val);
                BUG_ON(castle_extent_mask_hash_get(oldest_mask->mask_id) == NULL);
                break;
            }
        }

        write_unlock_irqrestore(&castle_extents_hash_lock, flags);
    }

    return mask_id;
}

/**
 * Puts the reference. (Interrupt Context)
 *
 * @also: castle_extent_resource_release
 */
void castle_extent_put(c_ext_mask_id_t mask_id)
{
    static int count = 0;
    unsigned long flags;

    /* Write lock is required to not race with reference gets. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Call low level put function. */
    castle_extent_mask_put(mask_id);
    castle_printk(LOG_DEBUG, "%s::count = %d\n", __FUNCTION__, count++);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);
}

/**
 * Puts the reference on oldest mask and latest mask. (Interrupt Context)
 *
 * @also: castle_extent_resource_release
 */
void castle_extent_put_all(c_ext_mask_id_t mask_id)
{
    unsigned long flags;
    c_ext_mask_t *mask, *oldest_mask;
    struct list_head *pos;

    /* Write lock is required to not race with reference gets. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    mask = castle_extent_mask_hash_get(mask_id);

    /* Release reference on oldest mask. */
    list_for_each_prev(pos, &mask->ext->mask_list)
    {
        oldest_mask = list_entry(pos, c_ext_mask_t, list);

        if (atomic_read(&oldest_mask->ref_count))
        {
            castle_extent_mask_put(oldest_mask->mask_id);
            break;
        }
    }

    /* Call low level put function on latest mask. */
    castle_extent_mask_put(mask_id);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);
}

static c_ext_mask_id_t castle_extent_get_ptr(c_ext_id_t ext_id, c_ext_t **ext)
{
    c_ext_mask_id_t mask_id = castle_extent_get(ext_id);

    if (MASK_ID_INVAL(mask_id))
    {
        *ext = NULL;
        return mask_id;
    }

    *ext = castle_extents_hash_get(ext_id);
    BUG_ON(*ext == NULL);

    return mask_id;
}

/**
 * Create a new link to the extent. New links can't be created if extent has no active links
 * (extent is dead).
 *
 * Link to an extent also takes a reference to the extent.
 *
 * @param   ext_id  [in]    Extent ID, link to be created.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_link(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;
    unsigned long flags;

    /* Read lock is good enough as link count is atomic and unlink works under write lock. */
    read_lock_irqsave(&castle_extents_hash_lock, flags);

    /* Try to get a reference on the extent. Would fail, if the extent is already dead. */
    mask_id = castle_extent_mask_get(ext_id);
    if (MASK_ID_INVAL(mask_id))
    {
        /* Shouldn't have tried to create links on a dead extent. BUG. */
        castle_printk(LOG_ERROR, "%s::cannot do get on ext with id %d.\n", __FUNCTION__, ext_id);
        BUG();
    }

    ext = __castle_extents_hash_get(ext_id);

    /* Shouldn't be a dead extent. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* Increment link count. */
    atomic_inc(&ext->link_cnt);

    /* Unlock hash lock. */
    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return 0;
}

/**
 * Remove a link for extent. Removing the last link would mark extent for deletion. No more
 * references or links can be created after that.
 *
 * @param   ext_id  [in]    Extent ID, to be unlinked.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_unlink(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;
    unsigned long flags;

    /* Get a write lock, to make sure there are no parallel get() or link(). */
    write_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    /* Can't unlink an extent not in hash. BUG. */
    if(!ext)
    {
        castle_printk(LOG_ERROR, "%s::cannot do unlink on ext with id %d.\n", __FUNCTION__, ext_id);
        BUG();
    }

    /* Shouldn't try to unlink a deleted extent. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* Reduce the link count and check if this is the last link. */
    if (atomic_dec_return(&ext->link_cnt) == 0)
    {
        printk("%s::extent %lld\n", __FUNCTION__, ext_id);
        /* All merges and request would have completed before setting castle_last_checkpoint_ongoing.
         * There shouldn't be any free()/unlink() after that. */
        BUG_ON(castle_last_checkpoint_ongoing);

        /* Increment the count of scheduled extents for deletion. Last checkpoint, conseqeuntly,
         * castle_exit waits for all outstanding dead extents to get destroyed. */
        atomic_inc(&castle_extents_dead_count);
    }

    /* There should be atleast one mask. */
    BUG_ON(list_empty(&ext->mask_list));

    /* This link has a reference on current latest mask. */
    mask_id = GET_LATEST_MASK(ext)->mask_id;

    write_unlock_irqrestore(&castle_extents_hash_lock, flags);

    /* Release the reference on latest mask. */
    castle_extent_put(mask_id);

    return 0;
}

/**
 * It's exactly same as castle_extent_unlink(). Unlink function would be used with extents with
 * multiple links. Just to be clear with terminology adding one more function castle_extent_free()
 * to remove the only link normal(non-large object) extents have.
 *
 * @param   ext_id  [in]    Extent ID, to be unlinked.
 *
 * @return  0   SUCCESS
 *          -1  FAILURE
 */
int castle_extent_free(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    /* Free should be called to remove the the last/only link extent has. */
    BUG_ON(atomic_read(&ext->link_cnt) != 1);

    return castle_extent_unlink(ext_id);
}

#ifdef CASTLE_PERF_DEBUG
/**
 * Increment the number of up2date/not up2date chunks prefetched (or not).
 *
 * @param   up2date If set, increment the number of chunks that did not need
 *                  to be prefetched
 *                  If unset, increment the number of chunks that needed to
 *                  be prefetched
 */
void _castle_extent_efficiency_inc(c_ext_id_t ext_id, int up2date)
{
    c_ext_t *ext;
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(ext_id, &ext);
    BUG_ON(!ext);

    if (up2date)
        atomic_inc(&ext->pref_chunks_up2date);
    else
        atomic_inc(&ext->pref_chunks_not_up2date);

    castle_extent_put(mask_id);
}

/**
 * Increment the number of prefetched chunks for extent.
 */
void castle_extent_not_up2date_inc(c_ext_id_t ext_id)
{
    _castle_extent_efficiency_inc(ext_id, 0 /*up2date*/);
}

/**
 * Increment the number of chunks that did not need to be prefetched for extent.
 */
void castle_extent_up2date_inc(c_ext_id_t ext_id)
{
    _castle_extent_efficiency_inc(ext_id, 1 /*up2date*/);
}

/**
 * Return and reset the number of up2date/not up2date chunks prefetched (or not).
 *
 * @param   up2date If set, get/reset the number of chunks that did not need
 *                  to be prefetched
 *                  If unset, get/reset the number of chunks that needed to
 *                  be prefetched
 */
int _castle_extent_efficiency_get_reset(c_ext_id_t ext_id, int up2date)
{
    c_ext_t *ext;
    int amount;
    c_ext_mask_id_t mask_id;

    mask_id = castle_extent_get_ptr(ext_id, &ext);
    BUG_ON(!ext);

    if (up2date)
    {
        amount = atomic_read(&ext->pref_chunks_up2date);
        atomic_sub(amount, &ext->pref_chunks_up2date);
    }
    else
    {
        amount = atomic_read(&ext->pref_chunks_not_up2date);
        atomic_sub(amount, &ext->pref_chunks_not_up2date);
    }

    castle_extent_put(mask_id);

    return amount;
}

/**
 * Get/reset the number of chunks that needed to be prefetched.
 */
int castle_extent_not_up2date_get_reset(c_ext_id_t ext_id)
{
    return _castle_extent_efficiency_get_reset(ext_id, 0 /*up2date*/);
}

/**
 * Get/reset the number of chunks that did not need to be prefetched.
 */
int castle_extent_up2date_get_reset(c_ext_id_t ext_id)
{
    return _castle_extent_efficiency_get_reset(ext_id, 1 /*up2date*/);
}
#endif

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
    if(!ext)
    {
        printk("%s::no extent %lld\n", __FUNCTION__, ext_id);\
        read_unlock_irqrestore(&castle_extents_hash_lock, flags);
        BUG();
    }
    BUG_ON(!ext);
    if(atomic_inc_return(&ext->dirtytree->ref_cnt) < 2)
        printk("%s::extent ref_cnt < 2; %lld\n", __FUNCTION__, ext_id);
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
            /* cannot be in hash now */
            BUG_ON(!MASK_ID_INVAL(castle_extent_get(dirtytree->ext_id)));
        BUG_ON(!RB_EMPTY_ROOT(&dirtytree->rb_root));    /* must be empty */
        castle_kfree(dirtytree);
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

int castle_extent_rebuild_ext_get(c_ext_t *ext, int is_locked)
{
    /* There shouldn't be an outstanding reference. */
    BUG_ON(!MASK_ID_INVAL(ext->rebuild_mask_id));

    if (is_locked)
        ext->rebuild_mask_id = castle_extent_mask_get(ext->ext_id);
    else
        ext->rebuild_mask_id = castle_extent_get(ext->ext_id);

    if (MASK_ID_INVAL(ext->rebuild_mask_id))
        return -1;

    return 0;
}

void castle_extent_rebuild_ext_put(c_ext_t *ext, int is_locked)
{
    /* There should be an outstanding reference. */
    BUG_ON(MASK_ID_INVAL(ext->rebuild_mask_id));

    if (is_locked)
        castle_extent_mask_put(ext->rebuild_mask_id);
    else
        castle_extent_put(ext->rebuild_mask_id);

    ext->rebuild_mask_id = INVAL_MASK_ID;
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
    /*
     * We are not handling logical extents. The extent is not already at current_rebuild_seqno. The extent
     * is not marked for deletion (it is a live extent).
     */

    if ((!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID)) &&
        (ext->curr_rebuild_seqno < atomic_read(&current_rebuild_seqno)))
    {
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        if (castle_extent_rebuild_ext_get(ext, 1) < 0)
            /* Extent is already dead. */
            return 0;

        debug("Adding extent %llu to rebuild list for extent seqno %u, global seqno %u\n",
               ext->ext_id, ext->curr_rebuild_seqno, atomic_read(&current_rebuild_seqno));
        list_add_tail(&ext->rebuild_list, &rebuild_list);
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
                    castle_kfree(remap_state.live_slaves[i]);
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

    /* There may be outstanding extent maps that need to be written out. */
    debug("Rebuild writeback flushing out final extent maps.\n");
    castle_extents_remap_writeback_setstate();
    castle_extents_remap_writeback();
    mutex_lock(&rebuild_done_list_lock);
    if(!list_empty(&rebuild_done_list))
        castle_printk(LOG_ERROR, "Finishing remap thread while there are still extents "
                                 "on the rebuild_done_list.\n");
    mutex_unlock(&rebuild_done_list_lock);

    for (i=0; i<MAX_NR_SLAVES; i++)
    {
        if (remap_state.live_slaves[i])
            castle_kfree(remap_state.live_slaves[i]);
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

static c_ext_id_t current_rebuild_extent = 0, rebuild_extent_last = 0;
static int rebuild_extent_chunk = 0;
static atomic_t current_rebuild_chunk = ATOMIC(0);

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

    mutex_lock(&rebuild_done_list_lock);
    current_rebuild_extent = ext->ext_id;
    atomic_set(&current_rebuild_chunk, 0);
    /* Add this extent to the rebuild_done_list. Move it to the end of the list
       if its already on it. */
    if(ext->rebuild_done_list.next != NULL)
        list_move_tail(&ext->rebuild_done_list, &rebuild_done_list);
    else
        list_add_tail(&ext->rebuild_done_list, &rebuild_done_list);
    mutex_unlock(&rebuild_done_list_lock);

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

    /* Keeps track of which chunk we are remapping. */
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
            c_ext_pos_t cep;
            c2_block_t *c2b;

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
                if(submit_c2b_sync(READ, c2b))
                {
                    if (!LIVE_EXTENT(ext))
                    {
                        /*
                         * We failed to get a ref on the extent, which means that the extent is no
                         * longer live, and therefore does not need remapping.
                         */
                        ret = -EINVAL;
                        goto skip_extent;
                    }
                    BUG();
                }

            /* Submit the write. */
            ret = submit_c2b_remap_rda(c2b, remap_chunks, remap_idx);

skip_extent:
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
             * with (hopefully) now valid slave(s). If it got -EINVAL then it failed to get a ref
             * on the extent, which means that the extent is no longer live, and therefore does not
             * need remapping.
             */
            if (ret == -EAGAIN)
                goto retry;
            if (ret == -EINVAL)
                return -EINVAL;
            BUG_ON(ret);
        }

        /* Keep count of the chunks that have actually been remapped. */
        castle_extents_chunks_remapped += remap_idx;

        atomic_inc(&current_rebuild_chunk);

        /*
         * Allow for shutdown in mid-extent (between chunks), because extents may be large and
         * take too long to remap.
         */
        if (kthread_should_stop() && ext->size != atomic_read(&current_rebuild_chunk))
            return -EINTR;
    }

    /*
     * Save the rebuild sequence number we have rebuilt the extent to.
     * This can't be saved in the extent until the remap writeback because if a checkpoint
     * and crash occurs before the writeback, the extent will have the wrong sequence number.
     */
    debug("Setting extent %llu to rebuild seqno %d\n", ext->ext_id, rebuild_to_seqno);
    ext->remap_seqno = rebuild_to_seqno;

    return EXIT_SUCCESS;
}

/*
 * Writeback a remapped extent.
 *
 * @param ext       The extent to writeback.
 */
void castle_extent_remap_writeback(c_ext_t *ext)
{
    c_ext_pos_t map_cep, map_page_cep;
    c2_block_t *map_c2b, *reserve_c2b;
    int chunkno;
    uint32_t            k_factor = castle_extent_kfactor_get(ext->ext_id);

    for (chunkno = 0; chunkno<ext->size; chunkno++)
    {
        /*
        * Write back the shadow map entry for this chunk.
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

    castle_cache_extent_flush(ext->ext_id, 0, 0, 0);

    /* Now the shadow map has become the default map, we can stop redirecting write I/O. */
    spin_lock(&ext->shadow_map_lock);
    ext->use_shadow_map = 0;
    spin_unlock(&ext->shadow_map_lock);
    castle_vfree(ext->shadow_map);

    /* It is now safe to update the extent with the rebuild sequence number. */
    ext->curr_rebuild_seqno = ext->remap_seqno;

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
                castle_extents_sb->meta_ext.curr_rebuild_seqno = ext->remap_seqno;
                break;
            case MSTORE_EXT_ID:
                castle_extents_sb->mstore_ext[0].curr_rebuild_seqno = ext->remap_seqno;
                break;
            case MSTORE_EXT_ID+1:
                castle_extents_sb->mstore_ext[1].curr_rebuild_seqno = ext->remap_seqno;
                break;
        }
        castle_extent_transaction_end();
    }

    castle_extent_rebuild_ext_put(ext, 0);
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
    struct castle_slave         *cs;
    int                         ret=0, exit_early=0;
    struct castle_fs_superblock *fs_sb;

    /* Initialise the rebuild list. */
    INIT_LIST_HEAD(&rebuild_list);
    INIT_LIST_HEAD(&rebuild_done_list);
    mutex_init(&rebuild_done_list_lock);

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
            goto finished;
        }

        /*
         * Iterate over the list, remapping as necessary. If exit_early gets set, we'll just
         * 'put' the remaining extents in the list.
         */
        list_for_each_safe(entry, tmp, &rebuild_list)
        {
            ret = 0;
            ext = list_entry(entry, c_ext_t, rebuild_list);
            list_del(entry);
            BUG_ON(ext->curr_rebuild_seqno >= rebuild_to_seqno);

            /*
             * If exit_early is set, then we are abandoning the rest of this rebuild run.
             * castle_extent_remap will not be called, and all we will do is drop the ref
             * on the extents remaining inthe rebuild list, before we stop.
             */
            if (!exit_early)
            {
                ret = castle_extent_remap(ext);

                if (ret == -EINTR || ret == -ENOSPC || kthread_should_stop())
                    /* We will not be remapping any more extents in this rebuild run. */
                    exit_early = 1;

                if (ret == -EINTR || ret == -ENOSPC || ret == -EINVAL)
                {
                    /*
                     * If A: The remap has been interrupted by a kthread_stop() and it has not yet
                     *       remapped all the chunks (EINTR).
                     * or B: An allocation has failed (which implicitly means that it has not yet
                     *       remapped all the chunks (ENOSPC).
                     * or C: The extent is no longer live, and therefore we don't care if it has
                     *       remapped all the chunks (EINVAL).
                     * then this extent should no longer be scheduled for map writeback. Take it off
                     * the rebuild_done_list and clean up the shadow map.
                     */
                    mutex_lock(&rebuild_done_list_lock);
                    if (ext->ext_id == rebuild_extent_last)
                    {
                        /*
                         * This extent is the marker used by castle_extents_remap_writeback to
                         * determine the point in the rebuild_done_list where it should stop. If we
                         * simply remove this extent from the rebuild_done_list that logic would
                         * break. Since we know that the previous extent in rebuild_done_list (if
                         * there is one) will be fully remapped, we can replace the marker with that
                         * and then we are free to remove this extent from the list.
                         */
                        if (ext->rebuild_done_list.prev != NULL)
                        {
                            c_ext_t *prev_ext;
                            prev_ext = list_entry(ext->rebuild_done_list.prev,
                                                  c_ext_t,
                                                  rebuild_done_list);
                            rebuild_extent_last = prev_ext->ext_id;
                            rebuild_extent_chunk = prev_ext->size;
                        } else
                            /* No previous extent (rebuild_done_list will become empty). */
                            rebuild_extent_last = rebuild_extent_chunk = 0;
                    }
                    list_del(&ext->rebuild_done_list);
                    ext->rebuild_done_list.next = ext->rebuild_done_list.prev = NULL;
                    mutex_unlock(&rebuild_done_list_lock);
                    spin_lock(&ext->shadow_map_lock);
                    ext->use_shadow_map = 0;
                    spin_unlock(&ext->shadow_map_lock);
                    castle_vfree(ext->shadow_map);
                }
            }

            FAULT(REBUILD_FAULT1);

            /*
             * If we are exiting early or the last extent is no longer live, and the extent is not
             * on the rebuild_done list, then drop the ref here. Otherwise writeback will drop it
             * when it has finished with it.
             */
            if ((exit_early || (ret == -EINVAL)) && (ext->rebuild_done_list.next == NULL))
                castle_extent_rebuild_ext_put(ext, 0);
        }

        if (exit_early)
        {
            if (kthread_should_stop())
            {
                castle_printk(LOG_WARN, "Rebuild run terminating early.\n");
                goto out;
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

        /* Now wait until all the extent maps have been written out (via the callback from
           castle_periodic_checkpoint). */
        wait_event_interruptible(rebuild_done_wq,
                    ({int _ret;
                     mutex_lock(&rebuild_done_list_lock);
                     _ret = list_empty(&rebuild_done_list);
                     mutex_unlock(&rebuild_done_list_lock);
                     _ret;}) ||
                    kthread_should_stop());

        if (kthread_should_stop())
        {
            castle_printk(LOG_WARN, "Rebuild terminating before writeback.\n");
            goto out;
        }

        if (castle_extents_rescan_required)
        {
            castle_printk(LOG_WARN, "Rebuild run restarting - rescan required.\n");
            goto restart;
        }

finished:
        /*
         * No further remapping required. We can now convert any evacuating or out-of-service
         * slaves to remapped state.
         */
        rcu_read_lock();
        list_for_each_rcu(entry, &castle_slaves.slaves)
        {
            cs = list_entry(entry, struct castle_slave, list);
            if (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags) &&
               !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags) &&
               !test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            {
                BUG_ON(test_bit(CASTLE_SLAVE_GHOST_BIT, &cs->flags));
                castle_printk(LOG_USERINFO, "Finished remapping evacuated slave 0x%x.\n",
                            cs->uuid);
                set_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags);
                set_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags);
                clear_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags);
                if (atomic_read(&cs->io_in_flight) == 0 &&
                    test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &cs->flags))
                    castle_release_device(cs);
            }
            if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags) &&
               !test_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags))
            {
                castle_printk(LOG_USERINFO, "Finished remapping out-of-service slave 0x%x.\n",
                              cs->uuid);
                set_bit(CASTLE_SLAVE_REMAPPED_BIT, &cs->flags);
                if (atomic_read(&cs->io_in_flight) == 0 &&
                    test_bit(CASTLE_SLAVE_BDCLAIMED_BIT, &cs->flags))
                    castle_release_device(cs);
            }
        }
        rcu_read_unlock();

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
    init_waitqueue_head(&rebuild_done_wq);

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
    /* We are not handling logical extents or extents scheduled for deletion. */
    if (!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID))
    {
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        if (castle_extent_rebuild_ext_get(ext, 1) < 0)
            /* Extent is already dead. */
            return 0;

        list_add_tail(&ext->verify_list, &verify_list);
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
                castle_printk(LOG_DEVEL, "castle_extent_scan_uuid found uuid 0x%x in extent %llu\n",
                    uuid, ext->ext_id);
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
        castle_extent_rebuild_ext_put(ext, 0);
    }

    if (nr_refs)
    {
        castle_printk(LOG_DEVEL, "REBUILD_VERIFY: %d references found to uuid 0x%xd\n", nr_refs, uuid);
        return -EEXIST;
    }
    else
        return 0;
}

/**
 * Saves current rebuild state before checkpoint
 * (this is the point up to which we will commit remap state.
 */
void castle_extents_remap_writeback_setstate(void)
{
    mutex_lock(&rebuild_done_list_lock);
    if (list_empty(&rebuild_done_list))
        rebuild_extent_last = rebuild_extent_chunk = 0;
    else
    {
        rebuild_extent_last = current_rebuild_extent;
        rebuild_extent_chunk = atomic_read(&current_rebuild_chunk);
    }
    mutex_unlock(&rebuild_done_list_lock);
}

/**
 * 'Commits' current rebuild remap state so that extent maps match the remap allocations.
 */
void castle_extents_remap_writeback(void)
{
    struct list_head    *entry, *tmp;
    c_ext_t             *ext;

    /* Lock, because rebuild want to add extents to the tail while we commiting. */
    mutex_lock(&rebuild_done_list_lock);
    list_for_each_safe(entry, tmp, &rebuild_done_list)
    {
        ext = list_entry(entry, c_ext_t, rebuild_done_list);

        /*
         * We want all the extents in the list up to but not including the one we saved in the
         * precheckpoint callback, but that one too - only if we finished remapping it.
         */
        if (rebuild_extent_last &&
           ((ext->ext_id != rebuild_extent_last) ||
           ((ext->ext_id == rebuild_extent_last) && (ext->size == rebuild_extent_chunk))))
        {
            list_del(entry);
            ext->rebuild_done_list.next = NULL;
            castle_extent_remap_writeback(ext);
        }
        if ((!rebuild_extent_last) || (ext->ext_id == rebuild_extent_last))
            /* We're done for this pass. */
            break;
    }
    /*
     * If we're done, then kick the rebuild thread to update the slave state bitmaps,
     * and go back to it's normal wait-for-a-rebuild-event state.
     */
    if (list_empty(&rebuild_done_list))
        wake_up(&rebuild_done_wq);
    mutex_unlock(&rebuild_done_list_lock);

}

signed int castle_extent_link_count_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return -1;
    return ((signed int)atomic_read(&ext->link_cnt));
}

c_ext_type_t castle_extent_type_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    ext = castle_extents_hash_get(ext_id);
    if(!ext) return EXT_T_INVALID;
    return ext->ext_type;
}


/**
 * Extents Resize
 */

/**
 * Create new extent mask and add it to the extent as latest mask.
 *
 * @param   ext         [inout]     Create a new mask for this extent.
 * @param   start       [in]        First chunk offset of mask.
 * #param   end         [in]        Last chunk offset of mask.
 * @param   prev_mask_id[in]        ID of the mask that the new mask is relative to. If that
 *                                  doesn't match, then racing with other mask_create. Just,
 *                                  return error. Caller will try again.
 *
 * @return  mask_id     ID of the new mask that is created.
 */
static int castle_extent_mask_create(c_ext_t            *ext,
                                     c_ext_mask_range_t  range,
                                     c_ext_mask_id_t     prev_mask_id)
{
    c_ext_mask_t *mask = castle_malloc(sizeof(c_ext_mask_t), GFP_KERNEL);
    c_ext_mask_t *prev_mask = NULL;

    /* Should be in of the extent transaction. */
    BUG_ON(!castle_extent_in_transaction());

    debug_mask("Creating mask " cemr_cstr "for extent %llu\n",
               cemr2str(range), ext->ext_id);

    /* Sanity checks. */
    CHECK_MASK_RANGE(range);

    /* Shouldn't cross extent boundary. */
    BUG_ON(range.end > ext->size);

    /* No memory available return error. */
    if (!mask)
        return -ENOMEM;

    /* Init mask structure. */
    mask->mask_id   = atomic_inc_return(&castle_extent_max_mask_id);
    mask->range     = range;
    mask->ext       = ext;

    /* Get hold of extents hash lock, to make sure no one else is accessing the extents
     * mask_list and no references are being acquired parallely. */
    write_lock_irq(&castle_extents_hash_lock);

    /* Extent link count should not be 0. Should be alive. */
    BUG_ON(atomic_read(&ext->link_cnt) == 0);

    /* This is the latest mask. Should represent number links in reference count. */
    atomic_set(&mask->ref_count, atomic_read(&ext->link_cnt));

    /* If there is no previous mask, list should be empty. Same the other way. */
    BUG_ON(!!MASK_ID_INVAL(prev_mask_id) ^ !!list_empty(&ext->mask_list));

    /* If there is a previous mask. */
    if (!MASK_ID_INVAL(prev_mask_id))
    {
        /* Get the previous mask structure. */
        prev_mask = GET_LATEST_MASK(ext);

        /* If it doesn't match the ID passed by the caller, then racing with some other
         * mask_create on the same extent, return error and caller would try again. */
        BUG_ON((prev_mask->mask_id != prev_mask_id));
    }
    else
        /* Extent just got created link count should be 1. */
        BUG_ON(atomic_read(&ext->link_cnt) != 1);

    /* Add the mask as latest mask to the extent. */
    list_add(&mask->list, &ext->mask_list);

    /* Add mask to hash. */
    castle_extent_mask_hash_add(mask);

    /* Update global mask.
     *
     * Note:  Global mask gets updated by mask_create() and mask_destroy(). mask_create()
     * changes the global mask only in case of grow().
     */
    if (ext->chkpt_global_mask.start > mask->range.start)
        ext->chkpt_global_mask.start = mask->range.start;

    if (ext->chkpt_global_mask.end < mask->range.end)
        ext->chkpt_global_mask.end = mask->range.end;

    debug_mask("Updated global mask to " cemr_cstr "\n", cemr2str(ext->chkpt_global_mask));

    /* Release link references from previous mask. */
    if (!MASK_ID_INVAL(prev_mask_id))
    {
        BUG_ON(castle_extent_mask_hash_get(prev_mask->mask_id) == NULL);

        BUG_ON(atomic_read(&prev_mask->ref_count) < atomic_read(&ext->link_cnt));

        /* This is not latest any more. Doesn't represent the reference count. Leave one
         * extra reference, to release by mask_put() as it could be the last reference on
         * mask. */
        atomic_sub(atomic_read(&ext->link_cnt) - 1, &prev_mask->ref_count);

        /* Release last link reference also. */
        castle_extent_mask_put(prev_mask_id);
    }

    /* Done with create, release the lock. */
    write_unlock_irq(&castle_extents_hash_lock);

    return 0;
}

/**
 * Delete extent mask from mask list and free the resources that would become invalid after
 * the deletion.
 *
 * 1. If the extent has older masks than this mask, then just delete this mask from list,
 * nothing more to do.
 * 2. If this is the oldest mask, commit the mask operation
 *      a. Shrink - Free the space in shrinked range.
 *      b. Grow - Nothing to do, space is already allocated and being used.
 *      c. Truncate - Free the space in truncated range.
 *
 * @param   mask    [in]    Destroy the mask.
 */
static int castle_extent_mask_destroy(c_ext_mask_t *mask)
{
    struct list_head *head;
    c_ext_t *ext;
    int ext_free = 0;

    debug_mask("Destroying mask " cemr_cstr " on extent: %llu\n",
                             cemr2str(mask->range), mask->ext->ext_id);

    /* Should be in extent transaction. */
    BUG_ON(!castle_extent_in_transaction());

    /* Get hold of extent mask lock, to make sure no one else accessing the extents mask_list. */
    write_lock_irq(&castle_extents_hash_lock);

    /* Should be the oldest mask. */
    BUG_ON(!IS_OLDEST_MASK(mask->ext, mask));

    /* Shouldn't be any references left. */
    BUG_ON(atomic_read(&mask->ref_count));

    ext = mask->ext;
    head = &ext->mask_list;

    /* Remove the mask from the list. */
    list_del(&mask->list);

    if (list_empty(head))
        ext_free = 1;

    write_unlock_irq(&castle_extents_hash_lock);

    if (ext_free)
        /* Last mask to be freed. */
        castle_extent_mask_reduce(ext, mask->range, EMPTY_MASK_RANGE,
                                  &ext->chkpt_global_mask, 1);
    else
        castle_extent_mask_reduce(ext, mask->range, GET_OLDEST_MASK(ext)->range,
                                  &ext->chkpt_global_mask, 1);

    castle_kfree(mask);

    if (ext_free)
        /* Free the extent resources. */
        castle_extent_resource_release(mask->ext);

    return 0;
}

static int castle_extents_garbage_collector(void *unused)
{
    LIST_HEAD(gc_list);

    castle_printk(LOG_INIT, "Starting Extents garbage collector thread: %p\n", &gc_list);

    do {
        int ignore;
        struct list_head *tmp, *pos;

        /* Wait for some one to schedule a mask to free or thread to stop. */
        __wait_event_interruptible(castle_ext_mask_gc_wq,
                                   (kthread_should_stop() ||
                                            atomic_read(&castle_extents_gc_q_size)),
                                   ignore);

        /* If the file sytem is exiting break the loop. */
        if (kthread_should_stop())
        {
            /* By this time, it shouldn't have any more extents to free. Should have
             * completed last checkpoint by now. */
            BUG_ON(atomic_read(&castle_extents_gc_q_size));

            /* Break the loop, and exit the thread. */
            break;
        }

        /* Start an extent transaction, to make sure no checkpoint happening in parellel. */
        castle_extent_transaction_start();

        /* Don't want any parallel additions to the list. */
        write_lock_irq(&castle_extents_hash_lock);

        BUG_ON(list_empty(&castle_ext_mask_free_list));

        /* Make a duplicate copy of the list. */
        list_splice_init(&castle_ext_mask_free_list, &gc_list);

        write_unlock_irq(&castle_extents_hash_lock);

        /* Go over the list of masks, and call destroy on them. */
        list_for_each_safe(pos, tmp, &gc_list)
        {
            c_ext_mask_t *mask = list_entry(pos, c_ext_mask_t, hash_list);

            /* Remove from GC list. */
            list_del(pos);

            /* Removes mask from extent and also free-up any resources occupied by it. */
            BUG_ON(castle_extent_mask_destroy(mask) < 0);

            atomic_dec_return(&castle_extents_gc_q_size);
        }

        castle_extent_transaction_end();
    } while(1);

    return 0;
}

/**
 * Get the extents global view.
 */
void castle_extent_mask_read_all(c_ext_id_t     ext_id,
                                 c_chk_cnt_t   *start,
                                 c_chk_cnt_t   *end)
{
    c_ext_t *ext;
    struct list_head *pos;

    *start = *end = 0;

    write_lock_irq(&castle_extents_hash_lock);

    ext = __castle_extents_hash_get(ext_id);

    list_for_each_prev(pos, &ext->mask_list)
    {
        c_ext_mask_t *mask = list_entry(pos, c_ext_mask_t, list);

        if (atomic_read(&mask->ref_count) == 0)
            continue;

        if (*start > mask->range.start)
            *start = mask->range.start;

        if (*end < mask->range.end)
            *end = mask->range.end;
    }

    *end = *end - 1;

    write_unlock_irq(&castle_extents_hash_lock);
}

static void castle_extent_reduce_global_mask(c_ext_mask_range_t *global_mask,
                                             c_ext_mask_range_t  free_range)
{
    int set = 0;

    if (MASK_RANGE_EMPTY(free_range))
        return;

    /* Check the borders. */
    BUG_ON(free_range.start < global_mask->start);
    BUG_ON(free_range.end > global_mask->end);

    /* Update global mask. */
    if (free_range.start == global_mask->start)
    {
        global_mask->start = free_range.end;
        set++;
    }

    if (free_range.end == global_mask->end)
    {
        global_mask->end = free_range.start;
        set++;
    }

    /* If both ranges are same, deleting everything. */
    if (set == 2)
        *global_mask = EMPTY_MASK_RANGE;

    debug_mask("Updated global mask to " cemr_cstr "\n", cemr2str(*global_mask));

    BUG_ON(!set);
}

/* Resize functions. */

/**
 * Grow the extent by given number of chunks.
 *
 * @param   ext_id  [inout]     ID of the extent that has to grow.
 * @param   count   [in]        Number of chunks to be grown.
 *
 * @return  0   SUCCESS - Extent is successfully grown.
 *          <0  FAILURE
 */
int castle_extent_grow(c_ext_id_t ext_id, c_chk_cnt_t count)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    castle_printk(LOG_DEVEL, "%s::ext %d, %d chunks\n", __FUNCTION__, ext_id, count);

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    debug_resize("Grow the extent by %u chunks\n", count);

    castle_extent_transaction_start();

    /* Allocate space to the extent. */
    ret = castle_extent_space_alloc(ext, INVAL_DA, count);
    if (ret < 0)
    {
        castle_printk(LOG_WARN, "Failed to allocate space for extent %u\n", ext_id);
        goto out;
    }

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    if(!mask)
    {
        castle_printk(LOG_ERROR, "%s::failed to recover a mask for extent %d\n", ext->ext_id);
        BUG();
    }

    /* Grow shouldn't try to cross extent boundary. */
    BUG_ON(mask->range.end + count > ext->size);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(mask->range.start, mask->range.end + count),
                                    mask->mask_id);
    if (ret < 0)
    {
        castle_extent_space_free(ext, mask->range.start, mask->range.end + count);
        goto out;
    }

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Shrink the extent to the given chunk offset.
 *
 * @param   ext_id      [inout]     ID of the extent to be shrunk.
 * @param   chunk       [in]        Chunk to be shrunk to. Everything upto (chunk-1)
 *                                  becomes invalid.
 *
 * @return      0 SUCCESS
 *            < 0 FAILURE
 */
int castle_extent_shrink(c_ext_id_t ext_id, c_chk_cnt_t chunk)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    debug_resize("Shrink the extent upto %u chunk (%u is valid)\n", chunk, chunk);

    castle_extent_transaction_start();

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    /* Can't shrink if the latest mask doesnt cover that range. */
    BUG_ON(mask->range.start > chunk);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(chunk, mask->range.end),
                                    mask->mask_id);
    if (ret < 0)
    {
        debug_resize("Fail to shrink the extent: %llu\n", ext_id);
        goto out;
    }

out:
    castle_extent_transaction_end();

    return ret;
}

/**
 * Truncate the extent to the given chunk offset.
 *
 * @param   ext_id      [inout]     ID of the extent to be shrunk.
 * @param   chunk       [in]        Chunk to be truncate to. Everything from (chunk+1)
 *                                  becomes invalid.
 *
 * @return      0 SUCCESS
 *            < 0 FAILURE
 */
int castle_extent_truncate(c_ext_id_t ext_id, c_chk_cnt_t chunk)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    c_ext_mask_t *mask;
    int ret = 0;

    debug_resize("Truncate extent upto %u chunk(%u is valid)\n", chunk, chunk);

    /* Extent should be alive, something is wrong with client. */
    BUG_ON(!ext);

    castle_printk(LOG_DEVEL, "%s::ext_id %d, chunk %d\n", __FUNCTION__, ext_id, chunk);

    castle_extent_transaction_start();

    /* Get the current latest mask. */
    mask = GET_LATEST_MASK(ext);

    /* Can't shrink if the latest mask doesnt cover that range. */
    BUG_ON(mask->range.end <= chunk);

    /* Create new mask for the extent and set as latest. */
    ret = castle_extent_mask_create(ext,
                                    MASK_RANGE(mask->range.start, chunk + 1),
                                    mask->mask_id);
    if (ret < 0)
    {
        castle_printk(LOG_WARN, "Fail to shrink the extent: %u\n", ext_id);
        goto out;
    }

out:
    castle_extent_transaction_end();

    return ret;
}

static void castle_extent_mask_split(c_ext_mask_range_t   range,
                                     c_ext_mask_range_t   seperator,
                                     c_ext_mask_range_t  *split1,
                                     c_ext_mask_range_t  *split2)
{
    *split1 = *split2 = EMPTY_MASK_RANGE;

    /* If the base range is empty just return. Do nothing. */
    if (MASK_RANGE_EMPTY(range))
        return;

    /* Get the first half before serperator, if any. */
    if (range.start < seperator.start)
    {
        split1->start   = range.start;
        split1->end     = (range.end < seperator.start)? range.end: seperator.start;
    }

    /* Get the second half after serperator, if any. */
    if (range.end > seperator.end)
    {
        split2->start   = (range.start > seperator.end)? range.start: seperator.end;
        split2->end     = range.end;
    }

    debug_mask("Splitting " cemr_cstr " by " cemr_cstr " into " cemr_cstr " and " cemr_cstr "\n",
                  cemr2str(range), cemr2str(seperator), cemr2str(*split1), cemr2str(*split2));

}

static void castle_extent_free_range(c_ext_t               *ext,
                                     c_ext_mask_range_t     range)
{
    if (MASK_RANGE_EMPTY(range))
        return;

    debug_mask("Freeing space " cemr_cstr " from extent: %llu\n",
                             cemr2str(range), ext->ext_id);

    castle_cache_extent_evict(ext->dirtytree,
                              range.start,
                              (range.end - range.start));

    castle_extent_space_free(ext, range.start, (range.end - range.start) * ext->k_factor);
}

static void castle_extent_mask_reduce(c_ext_t             *ext,
                                      c_ext_mask_range_t   base,
                                      c_ext_mask_range_t   range1,
                                      c_ext_mask_range_t  *global_mask,
                                      int                  do_free)
{
    c_ext_mask_range_t split1, split2;

    debug_mask("Reducing mask " cemr_cstr " from extent %llu\n",
                             cemr2str(base), ext->ext_id);

    /* If the base range is empty just return. Do nothing. */
    if (MASK_RANGE_EMPTY(base))
        return;

    /* Find the parts of base range that are not overlapped by range1. */
    castle_extent_mask_split(base, range1, &split1, &split2);

    castle_extent_reduce_global_mask(global_mask, split1);
    if (do_free)    castle_extent_free_range(ext, split1);

    castle_extent_reduce_global_mask(global_mask, split2);
    if (do_free)    castle_extent_free_range(ext, split2);
}
