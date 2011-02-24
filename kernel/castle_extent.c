#include <linux/mm.h>
#include <linux/kthread.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>
#include <linux/random.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_rda.h"
#include "castle_freespace.h"
#include "castle_extent.h"
#include "castle_cache.h"
#include "castle_da.h"
#include "castle_rebuild.h"

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
#define debug(_f, _a...)        (printk(_f, ##_a))
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
        atomic_set(&(_ext)->obj_refs, (_me)->obj_refs);                     \
        (_ext)->dirtylist.rb_root = RB_ROOT;                                \
        spin_lock_init(&ext->dirtylist.lock);

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->obj_refs     = atomic_read(&(_ext)->obj_refs);                              
 
#define FAULT_CODE EXTENT_FAULT

int low_disk_space = 0;

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_superblock castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

typedef struct castle_extent {
    c_ext_id_t          ext_id;         /* Unique extent ID */
    c_chk_cnt_t         size;           /* Number of chunks */
    c_rda_type_t        type;           /* RDA type */
    uint32_t            k_factor;       /* K factor in K-RDA */
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent */
    struct list_head    hash_list;
    struct list_head    rebuild_list;
    uint32_t            curr_rebuild_seqno;
    spinlock_t          shadow_map_lock;
    c_disk_chk_t        *shadow_map;
    int                 use_shadow_map; /* Extent is currently being remapped */
    atomic_t            ref_cnt;
    atomic_t            obj_refs;       /**< Number of references to extent. Gets
                                             updated with extents hash read lock. 
                                             Need to be atomic_t. */
    uint8_t             alive;
    c_ext_dirtylist_t   dirtylist;      /**< Extent c2b dirtylist */
} c_ext_t;

static struct list_head *castle_extents_hash = NULL;
static c_ext_free_t meta_ext_free;

static c_ext_id_t _castle_extent_alloc(c_rda_type_t rda_type,
                                       da_id_t      da_id,
                                       c_chk_cnt_t  count,
                                       c_ext_id_t   ext_id);

DEFINE_RHASH_TBL(castle_extents, castle_extents_hash, CASTLE_EXTENTS_HASH_SIZE,
                c_ext_t, hash_list, c_ext_id_t, ext_id, ref_cnt);


c_ext_t sup_ext = { 
    .ext_id         = SUP_EXT_ID,
    .size           = SUP_EXT_SIZE,
    .type           = SUPER_EXT,
    .k_factor       = 2,
    .maps_cep       = INVAL_EXT_POS,
};

uint8_t extent_init_done = 0;

static struct list_head     rebuild_list;
static wait_queue_head_t    rebuild_wq;
static struct task_struct   *rebuild_thread;

/*
 * A difference between current_rebuild_seqo and rebuild_to_seqno indicates that
 * current_rebuild_seqo has changed doing a rebuild. This can be due to a slave going
 * out-of-service or being evacuated. If a difference is discovered the rebuild is
 * restarted when it finishes it's current run to pick up and remap any extents that
 * have already been remapped to the (old) current_rebuild_seqo.
 */
static atomic_t             current_rebuild_seqo; /* The latest rebuild sequence number */
static int                  rebuild_to_seqno;     /* The sequence number being rebuilt to */

static int                  castle_extents_rescan_required = 0;

static int castle_extent_print(c_ext_t *ext, void *unused) 
{
    debug("Print   Extent   %llu\n", ext->ext_id);
    debug("        Size     %u chunks\n", ext->size);
    debug("        Maps at  "cep_fmt_str_nl, cep2str(ext->maps_cep));
   
    return 0;
}

void castle_extent_mark_live(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
        ext->alive = 1;
}

int castle_extents_init(void)
{
    int ret = 0;

    debug("Initing castle extents\n");

    /* Initialise hash table for extents */
    castle_extents_hash = castle_extents_hash_alloc();
    if(!castle_extents_hash)
    {
        printk("Could not allocate extents hash\n");
        ret = -ENOMEM;
        goto __hell;
    }
    castle_extents_hash_init();

    return 0;
__hell:
    return ret;
}

static int castle_extent_hash_remove(c_ext_t *ext, void *unused) 
{
    debug("Freeing extent #%llu\n", ext->ext_id);

    __castle_extents_hash_remove(ext);
    
    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs =
                castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));

        castle_free(cs->sup_ext_maps);
    }
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

    mutex_lock(&castle_extents_mutex);

    sblk = castle_fs_superblocks_get();
    memcpy(&castle_extents_global_sb, &sblk->extents_sb,
           sizeof(struct castle_extents_superblock));
    castle_fs_superblocks_put(sblk, 0);

    mutex_unlock(&castle_extents_mutex);
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

struct castle_extents_superblock* castle_extents_super_block_get(void)
{
    mutex_lock(&castle_extents_mutex);
    return &castle_extents_global_sb;
}
 
void castle_extents_super_block_put(int dirty)
{
    mutex_unlock(&castle_extents_mutex);
}

static int castle_extent_micro_ext_create(void)
{
    struct castle_extents_superblock *castle_extents_sb = castle_extents_super_block_get();
    c_disk_chk_t *micro_maps = castle_extents_sb->micro_maps;
    c_ext_t *micro_ext;
    struct list_head *l;
    int i = 0;

    micro_ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!micro_ext)
    {
        castle_extents_super_block_put(0);
        return -ENOMEM;
    }

    micro_ext->ext_id   = MICRO_EXT_ID;
    micro_ext->size     = MICRO_EXT_SIZE;
    micro_ext->type     = MICRO_EXT;
    micro_ext->maps_cep = INVAL_EXT_POS;
    atomic_set(&micro_ext->obj_refs, 1);
    micro_ext->alive    = 1;
    micro_ext->dirtylist.rb_root = RB_ROOT;
    spin_lock_init(&micro_ext->dirtylist.lock);

    memset(micro_maps, 0, sizeof(castle_extents_sb->micro_maps));
    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        BUG_ON(MICRO_EXT_SIZE != 1);
        
        micro_maps[i].slave_id = cs->uuid;
        micro_maps[i].offset   = MICRO_EXT_START;
        i++;
    }
    BUG_ON(i > MAX_NR_SLAVES);
    micro_ext->k_factor = i;
    CONVERT_EXTENT_TO_MENTRY(micro_ext, &castle_extents_sb->micro_ext);
    castle_extents_rhash_add(micro_ext);

    castle_extents_super_block_put(1);

    return 0;
}

static int castle_extent_meta_ext_create(void)
{
    int k_factor = (castle_rda_spec_get(META_EXT))->k_factor, i = 0;
    struct castle_extents_superblock *castle_extents_sb;
    struct list_head *l;
    c_ext_t *meta_ext;
    c_ext_id_t ext_id;

    list_for_each(l, &castle_slaves.slaves)
        i++;

    /* Allocate meta extent size to be however much we allocated in all the
       slaves, divided by the k-factor (2) */
    meta_ext_size = META_SPACE_SIZE * i / k_factor;

    ext_id = _castle_extent_alloc(META_EXT, 0, 
                                  meta_ext_size,
                                  META_EXT_ID);
    if (ext_id != META_EXT_ID)
    {
        printk("Meta Extent Allocation Failed\n");
        return -ENOSPC;
    }

    castle_extents_sb = castle_extents_super_block_get();
    meta_ext = castle_extents_hash_get(META_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(meta_ext, &castle_extents_sb->meta_ext);
    castle_extents_super_block_put(1);

    /* Make sure that micro extent is persistent. */
    castle_cache_extent_flush_schedule(MICRO_EXT_ID, 0, 0);
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

    i = 0;
    list_for_each(l, &castle_slaves.slaves)
        i++;

    ext_id = _castle_extent_alloc(DEFAULT_RDA, 0, 
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID);
    if (ext_id != MSTORE_EXT_ID)
        return -ENOSPC;

    ext_id = _castle_extent_alloc(DEFAULT_RDA, 0, 
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID+1);
    if (ext_id != MSTORE_EXT_ID+1)
        return -ENOSPC;

    castle_extents_sb = castle_extents_super_block_get();

    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[0]);
    mstore_ext = castle_extents_hash_get(MSTORE_EXT_ID+1);
    CONVERT_EXTENT_TO_MENTRY(mstore_ext, &castle_extents_sb->mstore_ext[1]);

    castle_extents_super_block_put(1);

    return 0;
}

int castle_extents_create(void)
{
    BUG_ON(extent_init_done);
    
    castle_extents_super_block_init();

    if (castle_extent_micro_ext_create())
        return -EINVAL;

    if (castle_extent_meta_ext_create())
        return -EINVAL;

    _castle_ext_freespace_init(&meta_ext_free, 0, 0, C_BLK_SIZE, META_EXT_ID);

    INJECT_FAULT;

    if (castle_extent_mstore_ext_create())
        return -EINVAL;

    extent_init_done = 1;
    return 0;
}

int nr_exts = 0;

/* TODO who should handle errors in writeback? */
static int castle_extent_writeback(c_ext_t *ext, void *store)
{
    struct castle_elist_entry mstore_entry;
    c_mstore_t *castle_extents_mstore = store;
   
    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    if (atomic_read(&ext->obj_refs) != 1)
        printk("Unexpected extents ref count: (%llu, %u)\n", ext->ext_id,
                atomic_read(&ext->obj_refs));

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

    castle_extents_mstore = 
        castle_mstore_init(MSTORE_EXTENTS, sizeof(struct castle_elist_entry));
    if(!castle_extents_mstore)
        return -ENOMEM;
  
    /* Note: This is important to make sure, nothing changes in extents. And
     * writeback() relinquishes hash spin_lock() while doing writeback. */
    ext_sblk = castle_extents_super_block_get();
    /* Writeback new copy. */
    nr_exts = 0;
    castle_extents_hash_iterate(castle_extent_writeback, castle_extents_mstore);

    if (ext_sblk->nr_exts != nr_exts)
    {
        printk("%llx:%x\n", ext_sblk->nr_exts, nr_exts);
        BUG();
    }

    castle_mstore_fini(castle_extents_mstore);

    /* Writeback maps freespace structure into extent superblock. */
    castle_ext_freespace_marshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    /* Flush the complete meta extent onto disk, before completing writeback. */
    BUG_ON(!castle_ext_freespace_consistent(&meta_ext_free));
    castle_cache_extent_flush_schedule(META_EXT_ID, 0,
                                       atomic64_read(&meta_ext_free.used));

    INJECT_FAULT;

    /* It is important to complete freespace_writeback() under extent lock, to
     * make sure freesapce and extents are in sync. */ 
    castle_freespace_writeback();

    castle_extents_super_block_writeback();
    castle_extents_super_block_put(0);

    return 0;
}

static int load_extent_from_mentry(struct castle_elist_entry *mstore_entry)
{
    c_ext_t *ext = NULL;

    /* Load micro extent. */
    ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext) return -ENOMEM;

    CONVERT_MENTRY_TO_EXTENT(ext, mstore_entry);
    if (EXT_ID_INVAL(ext->ext_id))
        return -EINVAL;

    castle_extents_rhash_add(ext);
    castle_extent_print(ext, NULL);

    return 0;
}

int castle_extents_read(void)
{
    struct castle_extents_superblock *ext_sblk = NULL;

    BUG_ON(extent_init_done);

    castle_extents_super_block_read();

    ext_sblk = castle_extents_super_block_get();

    /* Read maps freespace structure from extents superblock. */
    castle_ext_freespace_unmarshall(&meta_ext_free, &ext_sblk->meta_ext_free_bs);

    if (load_extent_from_mentry(&ext_sblk->micro_ext))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->meta_ext))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->mstore_ext[0]))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->mstore_ext[1]))
        goto error_out;

    /* Mark Logical extents as alive. */
    castle_extent_mark_live(MICRO_EXT_ID);
    castle_extent_mark_live(META_EXT_ID);
    castle_extent_mark_live(MSTORE_EXT_ID);
    castle_extent_mark_live(MSTORE_EXT_ID+1);
    meta_ext_size = castle_extent_size_get(META_EXT_ID);
    castle_extents_super_block_put(0);
    extent_init_done = 1;

    return 0;

error_out:
    return -1;
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
    castle_extents_super_block_put(0);

    INJECT_FAULT;

    return 0;

error_out:
    if (iterator)               castle_mstore_iterator_destroy(iterator);
    if (castle_extents_mstore)  castle_mstore_fini(castle_extents_mstore);

    return -1;
}

void castle_extents_fini(void)
{
    /* Make sure cache flushed all dirty pages */
    /* Iterate over extents hash with exclusive access. Indeed, we dont need a
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
 * Collects disk chunks to be freed from an extent into superchunks, and frees the superchunks
 * to the freespace layer.
 *
 * @param ext_state     State structure passed to every call to this function for a given 
 *                      extent.
 * @param disk_chk      Disk chunk to be freed.
 * @param copy          Which k-RDA copy did this chunk belong to.
 */
static void castle_extent_disk_chk_free(struct castle_extent_state *ext_state,
                                        c_disk_chk_t disk_chk,
                                        int copy)
{
    struct castle_slave *cs;
    c_chk_t *chk;
#define SUPER_CHUNK_STRUCT(chk_idx)  ((c_chk_seq_t){chk_idx, CHKS_PER_SLOT})

    cs = castle_slave_find_by_uuid(disk_chk.slave_id);
    if(!cs)
    {
        printk("When freeing extent=%lld, couldn't free disk chk="disk_chk_fmt", disk not found.\n",
                ext_state->ext->ext_id, disk_chk2str(disk_chk));
        return;
    }
    chk = &ext_state->chunks[cs->id][copy];
    /* Check whether we are moving to a different superchunk. */
    BUG_ON(CHK_INVAL(*chk) && (SUPER_CHUNK(*chk) == SUPER_CHUNK(disk_chk.offset)));
    if(SUPER_CHUNK(*chk) != SUPER_CHUNK(disk_chk.offset))
    {
        debug("Freeing superchunk: "disk_chk_fmt", from ext_id: %lld\n", 
                disk_chk2str(disk_chk), ext_state->ext->ext_id);
        /* Chunk should be super chunk aligned. */
        BUG_ON(disk_chk.offset % CHKS_PER_SLOT != 0);
        /* Previous chunk freed for that (slave, copy_id), should have been last
           superchunk chunk. */
        BUG_ON(!CHK_INVAL(*chk) && (((*chk+1) % CHKS_PER_SLOT) != 0));
        /* Free the superchunk. */
        castle_freespace_slave_superchunk_free(cs, SUPER_CHUNK_STRUCT(disk_chk.offset));
        /* Invalidate the chunk stored in state structure, so that it get reset
           correctly below. */
        *chk = INVAL_CHK;
    }
    /* We expect disk chunk to follow previous chunk. */
    BUG_ON(!CHK_INVAL(*chk) && (*chk+1 != disk_chk.offset));
    *chk = disk_chk.offset;
}

/**
 * Frees specified number of disk chunks allocated to the specified extent. Called when destroying
 * extents, or during failed allocations, to return already allocated disk space.
 *
 * @param ext   Extent to free the disk space for.
 * @param count Number of chunks to free.
 * 
 * @FIXME Cannot handle kmallac failure. We should retry freeing extent freespace, 
 * once memory becomes available. 
 */
static void castle_extent_space_free(c_ext_t *ext, c_chk_cnt_t count)
{
    struct castle_extent_state *ext_state; 
    c_chk_cnt_t chks_per_page;
    c_ext_pos_t map_cep;
    c2_block_t *map_c2b;
    c_disk_chk_t *map_buf;

    debug("Freeing %d disk chunks from extent %lld\n", count, ext->ext_id);
    ext_state = castle_extent_state_alloc(ext);
    BUG_ON(!ext_state);
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
        for( logical_chunk=0; 
            (logical_chunk<chks_per_page) && (count > 0); 
             logical_chunk++)
        {
            int copy;
            for( copy=0; 
                (copy<ext->k_factor) && (count > 0); 
                 copy++)
            {
                debug("Freeing logical_chunk=%d, copy=%d, disk_chk="disk_chk_fmt_nl,
                        logical_chunk, 
                        copy, 
                        disk_chk2str(map_buf[logical_chunk * ext->k_factor + copy]));
                castle_extent_disk_chk_free(ext_state, 
                                            map_buf[logical_chunk * ext->k_factor + copy],
                                            copy);
                count--;
            }
        }
                         
        write_unlock_c2b(map_c2b);
        put_c2b(map_c2b);
        map_cep.offset += C_BLK_SIZE;
    }
    kfree(ext_state);
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
static c_disk_chk_t castle_extent_disk_chk_alloc(da_id_t da_id,
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
        * We get an here if the slave is either out-or-service, or out of space. If the slave is
        * out-of-service then just return INVAL_DISK_CHK so calling stack can retry.
        */
        if (!test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags))
        {
            /* Slave is not out-of-service so we are out of space */
            printk("Failed to get freespace from slave: 0x%x\n", slave->uuid);
            castle_freespace_stats_print();
            low_disk_space = 1;
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
int castle_extent_space_alloc(c_ext_t *ext, da_id_t da_id)
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
        printk("Couldn't malloc extent allocation structure.\n");
        err = -ENOMEM;
        goto out;
    }
    /* Initialise the RDA spec state. */
    rda_state = rda_spec->extent_init(ext->ext_id, ext->size, ext->type);
    if (!rda_state)
    {
        printk("Couldn't initialise RDA state.\n");
        err = -EINVAL;
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
            printk("Failed to get next slave for extent: %llu\n", ext->ext_id);
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
  
c_ext_id_t castle_extent_alloc(c_rda_type_t rda_type,
                               da_id_t      da_id,
                               c_chk_cnt_t  count)
{
    return _castle_extent_alloc(rda_type, da_id, count, INVAL_EXT_ID);
}

/**
 * Allocate a new extent.
 *
 * @return  Extent ID of the newly created extent.
 *
 * Extents are also allocated in:
 *
 * @also CONVERT_MENTRY_TO_EXTENT()
 * @also castle_extent_micro_ext_create()
 * @also castle_extent_sup_ext_init()
 */
static c_ext_id_t _castle_extent_alloc(c_rda_type_t rda_type,
                                       da_id_t      da_id,
                                       c_chk_cnt_t  count,
                                       c_ext_id_t   ext_id)
{
    c_ext_t *ext = NULL;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_extents_superblock *castle_extents_sb = NULL;

    BUG_ON(!extent_init_done && !LOGICAL_EXTENT(ext_id));

    if (low_disk_space)
        goto __hell;

    if (castle_extents_hash_get(ext_id))
        goto __hell;

    debug("Creating extent of size: %u\n", count);
    ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext)
    {
        printk("Failed to allocate memory for extent\n");
        goto __hell;
    }
    castle_extents_sb   = castle_extents_super_block_get();

    ext->ext_id         = (EXT_ID_INVAL(ext_id))? castle_extents_sb->ext_id_seq: 
                                                  ext_id;
    ext->size           = count;
    ext->type           = rda_type;
    ext->k_factor       = rda_spec->k_factor;
    atomic_set(&ext->obj_refs, 1);
    ext->alive          = 1;
    ext->dirtylist.rb_root = RB_ROOT;
    spin_lock_init(&ext->dirtylist.lock);
    ext->use_shadow_map = 0;
    spin_lock_init(&ext->shadow_map_lock);

    /* The rebuild sequence number that this extent starts off at */
    ext->curr_rebuild_seqno = atomic_read(&current_rebuild_seqo);
    
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
            printk("Too big of an extent/crossing the boundry.\n");
            goto __hell;
        }
        debug("Allocated extent map at: "cep_fmt_str_nl, cep2str(ext->maps_cep));
    }
  
    if (castle_extent_space_alloc(ext, da_id) < 0)
    {
        printk("Extent alloc failed for %u chunks\n", count);
        goto __hell;
    }
  
    /* Add extent to hash table */
    castle_extents_rhash_add(ext);

    /*
     * If current_rebuild_seqo has changed, then the mappings for this extent may contain
     * out-of-service slaves. Set the rescan flag and kick the rebuild thread so that the  extent
     * list is rescanned by the rebuild thread. This extent will then be remapped if required.
     */
    if (ext->curr_rebuild_seqno != atomic_read(&current_rebuild_seqo))
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
    castle_extents_super_block_put(1);

    return ext->ext_id;

__hell:
    if (ext)
        castle_free(ext);
    if (castle_extents_sb)
        castle_extents_super_block_put(1);

    return INVAL_EXT_ID;
}

void castle_extent_free(c_ext_id_t ext_id)
{
    castle_extent_put(ext_id);
}

void _castle_extent_free(c_ext_t *ext)
{
    struct castle_extents_superblock *castle_extents_sb = NULL;
    c_ext_id_t ext_id = ext->ext_id;

    if (atomic_read(&ext->obj_refs))
    {
        printk("Couldnt delete the referenced extent %llu\n", ext_id);
        return;
    }

    castle_extents_sb = castle_extents_super_block_get();
    castle_extents_rhash_remove(ext);
    printk("Removed extent %llu from hash\n", ext_id);

    castle_extent_space_free(ext, ext->k_factor * ext->size);
    debug("Completed deleting ext: %lld\n", ext_id);

    castle_extents_sb->nr_exts--;
    castle_extents_super_block_put(1);

    castle_free(ext);
}

uint32_t castle_extent_kfactor_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_rhash_get(ext_id);
    uint32_t ret;

    if (!ext)
        return 0;
        
    ret = ext->k_factor;
    castle_extents_rhash_put(ext);

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
 *
 * @FIXME this function is incomplete and needs to be updated to return
 * the actual number of active slaves and not a constant
 */
static int _castle_extent_slave_count_get(c_ext_id_t ext_id, int only_active)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
    {
        /* @FIXME currently we return the total number of slaves, this needs to
         * be updated to return the number of slaves for a given extent. */
        struct list_head *lh;
        int slaves = 0;

        list_for_each(lh, &castle_slaves.slaves)
        {
            slaves++;
        }

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

uint32_t castle_extent_map_get(c_ext_id_t             ext_id,
                               c_chk_t                offset,
                               c_disk_chk_t          *chk_map,
                               int                   rw)
{
    c_ext_t      *ext;
    uint32_t      ret;

    BUG_ON(ext_id == INVAL_EXT_ID);
    
    if ((ext = castle_extents_rhash_get(ext_id)) == NULL)
        return 0;

    if (offset >= ext->size)
    {
        printk("BUG in %s\n", __FUNCTION__);
        printk("    Extent: %llu\n", ext_id);
        printk("    Offset: %u\n", offset);
        printk("    Extent Size: %u\n", ext->size);
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
            memcpy(chk_map, &ext->shadow_map[offset], ext->k_factor * sizeof(c_disk_chk_t));
            spin_unlock(&ext->shadow_map_lock);
            goto map_done;
        }
        spin_unlock(&ext->shadow_map_lock);
    }
    __castle_extent_map_get(ext, offset, chk_map);

map_done:
    ret = ext->k_factor;
    castle_extents_rhash_put(ext);

    return ret;
}

c_ext_id_t castle_extent_sup_ext_init(struct castle_slave *cs)
{
    c_ext_t      *ext;
    c_rda_spec_t *rda_spec = castle_rda_spec_get(SUPER_EXT);
    int           i, j;

    ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext)
    {
        printk("Failed to allocate memory for extent\n");
        goto __hell;
    }
    memcpy(ext, &sup_ext, sizeof(c_ext_t));
    
    ext->ext_id      = slave_id_to_sup_ext(cs->id);
    atomic_set(&ext->obj_refs, 1);
    ext->alive       = 1;
    ext->dirtylist.rb_root = RB_ROOT;
    spin_lock_init(&ext->dirtylist.lock);
    cs->sup_ext_maps = castle_malloc(sizeof(c_disk_chk_t) * ext->size *
                                                    rda_spec->k_factor, GFP_KERNEL);
    BUG_ON(rda_spec->k_factor != ext->k_factor);
    if (!cs->sup_ext_maps)
    {
        printk("Failed to allocate memory for extent chunk maps of size %u:%u chunks\n", 
        ext->size, rda_spec->k_factor);
        goto __hell;
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
    castle_extents_rhash_add(ext);
    cs->sup_ext = ext->ext_id;

    debug("Created super extent %llu for slave 0x%x\n", ext->ext_id, cs->uuid);

    return ext->ext_id;

__hell:
    if (cs->sup_ext_maps)
        castle_free(cs->sup_ext_maps);
    if (ext)
        castle_free(ext);

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
        castle_extents_rhash_remove(ext);
        castle_free(ext);
    }
    castle_free(cs->sup_ext_maps);

    return;
}

int castle_extent_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;
    unsigned long flags;

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    if (!ext)
    {
        read_unlock_irqrestore(&castle_extents_hash_lock, flags);
        return -EINVAL;
    }
    atomic_inc(&ext->obj_refs);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    return 0;
}

int castle_extent_put(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    unsigned long flags;
    int free_ext = 0;

    if (EXT_ID_INVAL(ext_id))
        return -EINVAL;

    BUG_ON(ext == NULL);

    read_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    BUG_ON(!ext);

    if (atomic_dec_return(&ext->obj_refs) == 0)
        free_ext = 1;
    debug("Object Refrence for %llu: %u\n", ext_id, ext->obj_refs);

    read_unlock_irqrestore(&castle_extents_hash_lock, flags);

    if (free_ext)
        _castle_extent_free(ext);

    return 0;
}

/**
 * Hold a reference on the extent and return the dirtylist RB-tree.
 *
 * castle_extents_rhash_get() holds a reference to the extent for us.
 *
 * @also castle_extents_rhash_get()
 * @also castle_extent_dirtylist_put()
 */
c_ext_dirtylist_t* castle_extent_dirtylist_get(c_ext_id_t ext_id)
{
    c_ext_t *ext;

    if ((ext = castle_extents_rhash_get(ext_id)) == NULL)
        return NULL;

    return &ext->dirtylist;
}

/**
 * Release reference on the extent.
 *
 * @also castle_extents_rhash_put()
 * @also castle_extent_dirtylist_get()
 */
void castle_extent_dirtylist_put(c_ext_id_t ext_id)
{
    c_ext_t *ext;

    if ((ext = castle_extents_hash_get(ext_id)) == NULL)
        return;

    castle_extents_rhash_put(ext);
}

static int castle_extent_check_alive(c_ext_t *ext, void *unused)
{
    if (ext->alive == 0)
    {
        printk("Found a dead extent: %llu - Cleaning it\n", ext->ext_id);
        BUG_ON(atomic_read(&ext->obj_refs) != 1);
        read_unlock_irq(&castle_extents_hash_lock);
        castle_extent_put(ext->ext_id);
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
    /* We are not handling logical extents. */
    if ((!SUPER_EXTENT(ext->ext_id) && !(ext->ext_id == MICRO_EXT_ID)) &&
        (ext->curr_rebuild_seqno < atomic_read(&current_rebuild_seqo)))
    {
        debug("Adding extent %llu to rebuild list for seqno %u\n",
               ext->ext_id, atomic_read(&current_rebuild_seqo));
        list_add_tail(&ext->rebuild_list, &rebuild_list);
        /*
         * Take a reference to the extent. We will drop this when we have finished remapping
         * the extent.
         */
        atomic_inc(&ext->obj_refs);
    }
    return 0;
}

/*
 * This structure keeps track of the current 'remapping state' - which slaves can be used for
 * remapping, and for each of those slaves a set of chunks to use for remapping, and an indication
 * of which chunk to use next.
 */
static struct remap_state {
    c_disk_chk_t    *chunks[MAX_NR_SLAVES];      /* chunk mappings (slave, offset) for all slaves. */
    int             next_chk[MAX_NR_SLAVES];     /* For each 'live' slave, the next chunk to use. */
    int             nr_live_slaves;              /* Number of slaves available for remapping. */
    uint32_t        live_slaves[MAX_NR_SLAVES];  /* uuids for all 'live' slaves. */
} remap_state;

/*
 * (Re-)populate the list of 'live' slaves. This is the list that can currently be used as a
 * source of replacement slaves for remapping.
 */
static void populate_live_slaves(void)
{
    struct list_head        *lh;
    struct castle_slave     *cs;
    int                     i;

    remap_state.nr_live_slaves = 0;
    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        if ((!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags)) &&
            (!test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags)))
            remap_state.live_slaves[remap_state.nr_live_slaves++] = cs->uuid;
    }
    for (i=remap_state.nr_live_slaves; i<MAX_NR_SLAVES; i++)
        remap_state.live_slaves[i++] = 0;
}

/*
 * Initialises the remap_state structure
 */
static void castle_extents_remap_state_init(void)
{
    int i;
    
    /* Initialise the remap_state structure. */
    for (i=0; i<MAX_NR_SLAVES; i++)
        remap_state.next_chk[i] = 0;    /* 0 means that no chunks are allocated yet. */

    /* Create the array and counter of live slaves that can be used for remapping. */
    populate_live_slaves();

    /*
     * Allocate space for disk chunks for each 'live' slave. This doesn't need to change even if
     * nr_live_slaves does, because nr_live_slaves can only decrease.
     */
    for (i=0; i<remap_state.nr_live_slaves; i++)
    {
        remap_state.chunks[i] = castle_malloc(sizeof(c_disk_chk_t)*CHKS_PER_SLOT, GFP_KERNEL);
        BUG_ON(!remap_state.chunks[i]);
    }

    /* Note: we don't actually allocate any disk chunks until they are needed. */
}

/*
 * Frees any data associated withthe remap_state structure.
 */
static void castle_extents_remap_state_fini(void)
{
    int i;

    for (i=0; i<MAX_NR_SLAVES; i++)
        if (remap_state.chunks[i])
            castle_free(remap_state.chunks[i]);
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
    c_disk_chk_t        *chunkp = remap_state.chunks[slave_idx];
    int                 chunk;
    c_chk_seq_t         chk_seq;
    c_chk_t             offset;
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(remap_state.live_slaves[slave_idx]);
    BUG_ON(!cs);

    /*
     * Allocate a superchunk. We do not want to pre-reserve space, so use a NULL token.
     */
    chk_seq = castle_freespace_slave_superchunk_alloc(cs, 0, NULL);
    if (CHK_SEQ_INVAL(chk_seq))
    {
        char b[BDEVNAME_SIZE];
        /*
         * We get here if the slave is either out-or-service, or out of space.
         */
        if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
        {

            /* Slave is not out-of-service so we are out of space */
            printk("Error: failed to get freespace from slave: 0x%x (%s).",
                    cs->uuid, bdevname(cs->bdev, b));

            castle_freespace_stats_print();
            low_disk_space = 1;
            return -ENOSPC;
        } else
        {
            printk("Warning - Failed allocating superchunk from out-of-service slave: 0x%x (%s).",
                    cs->uuid, bdevname(cs->bdev, b));
            /*
             * Slave is now out-of-service.
             */
            /* TBD - handle this properly - stop / restart rebuild (of this extent)?  */
            BUG();
        }
    }
 
    /* Chunk sequence must represent a single superchunk. */
    BUG_ON(chk_seq.count != CHKS_PER_SLOT);

    /* Fill in the chunks for this slave. */
    for (chunk=0, offset=chk_seq.first_chk; chunk<chk_seq.count; chunk++, offset++)
    {
        (chunkp+chunk)->slave_id = remap_state.live_slaves[slave_idx];
        (chunkp+chunk)->offset = offset;
    }
    return EXIT_SUCCESS;
}

/*
 * Return the slave index to use for remapping a chunk. Scans the remap_state.live_slaves
 * array for a slave which is not already used in the disk chunk.
 *
 * @param ext       The extent for which the remapping is being done.
 * @param chunkno   The logical chunk being remapped.
 *
 * @return          The index into the remap_state arrays to use for allocation
 */
static int castle_extent_replacement_slave_get(c_ext_t *ext, int chunkno)
{
    int         chunk_idx, slave_idx, nr_slaves_to_use, already_used;
    int         slaves_to_use[MAX_NR_SLAVES];
    uint16_t    r;

    /* For each slave in remap_state.live_slaves (the list of potential slave. */
    nr_slaves_to_use = 0;
    for (slave_idx=0; slave_idx<remap_state.nr_live_slaves; slave_idx++)
    {
        already_used = 0;
        /* Scan through all the slaves in this logical chunk. */
        for (chunk_idx=0; chunk_idx<ext->k_factor; chunk_idx++)
        {
            if (ext->shadow_map[(chunkno*ext->k_factor)+chunk_idx].slave_id ==
                remap_state.live_slaves[slave_idx])
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
static c_disk_chk_t *castle_extent_remap_disk_chunk_alloc(c_ext_t *ext, int chunkno)
{
    c_disk_chk_t    *disk_chk;
    int             slave_idx;

    /* Get the replacement slave */
    slave_idx = castle_extent_replacement_slave_get(ext, chunkno);
    BUG_ON(slave_idx == -1);

    if (!remap_state.next_chk[slave_idx])
        /* We've run out of chunks on this slave, allocate another set. */
        castle_extent_remap_superchunks_alloc(slave_idx);

    disk_chk = &remap_state.chunks[slave_idx][remap_state.next_chk[slave_idx]];

    BUG_ON(DISK_CHK_INVAL(*disk_chk));

    /*
     * Calculate the next disk chunk to use in the remap_state chunks array. When this wraps to 0
     * this is a trigger to allocate another set of superchunks and repopulate the array (see above)
     * if a new disk chunk request is made.
     */
    remap_state.next_chk[slave_idx] =
                        ++remap_state.next_chk[slave_idx] % CHKS_PER_SLOT;

    return disk_chk; 
}

/*
 * Check if a slave needs remapping.
 *
 * @param slave_id  The slave uuid.
 *
 * @return 0:       Slave does not need remapping.
 * @return 1:       Slave needs remapping.
 */
static int slave_needs_remapping(uint32_t slave_id)
{
    int i;

    /* If it's not a live slave, it needs remapping */
    for (i=0; i<remap_state.nr_live_slaves; i++)
        if (remap_state.live_slaves[i] == slave_id)
            return 0;
    return 1;
}

/*
 * Scan an extent, remapping disk chunks where necessary.
 *
 * @param ext       The extent to remap.
 *
 * @return 1:       We got kthread_should_stop() while remapping an extent.
 * @return 0:       We successfully processed the extent.
 */
static int castle_extent_remap(c_ext_t *ext)
{
    uint32_t            k_factor = castle_extent_kfactor_get(ext->ext_id);
    int                 chunkno, idx, chunk_remapped;

    debug("\nRemapping extent %llu size: %u, from seqno: %u to seqno: %u\n",
            ext->ext_id, ext->size, ext->curr_rebuild_seqno, rebuild_to_seqno);

    ext->shadow_map = castle_malloc(ext->size*k_factor*sizeof(c_disk_chk_t), GFP_KERNEL);
    if (!ext->shadow_map)
    {
        printk("ERROR: could not allocate rebuild shadow map of size %lu\n",
                ext->size*k_factor*sizeof(c_disk_chk_t));
        BUG();
    }

    /* Populate the shadow map - a copy of the existing mapping. */
    for (chunkno = 0; chunkno<ext->size; chunkno++)
        __castle_extent_map_get(ext, chunkno, &ext->shadow_map[chunkno*k_factor]);

    if (rebuild_to_seqno != atomic_read(&current_rebuild_seqo))
    {
        /*
         * Sequence number has changed. Set rebuild_to_seqno, which is the sequence number we will
         * be remapping to. Populate the live slaves array with its matching set of slaves and set
         * the flag to indicate thet rebuild will need to restart to remap extents that we have
         * already scanned, because these may now be out of date.
         */
        castle_extents_rescan_required = 1;

        rebuild_to_seqno = atomic_read(&current_rebuild_seqo);

        /*
         * Refresh the live slaves array to reflect the change, and use that from now on.
         */
        populate_live_slaves();
    }

    /*
     * From this point, we will start using the shadow map to remap the extent. All write I/O must
     * now be submitted via the shadow map because it will be more up-to-date (or at least no less
     * up-to-date) than the original extent map.
     */
    ext->use_shadow_map = 1;

    /* Scan the shadow map, chunk by chunk, remapping slaves as necessary. */
    for (chunkno = 0; chunkno<ext->size; chunkno++)
    {
        chunk_remapped = 0;
        for (idx=0; idx<k_factor; idx++)
        {
            c_disk_chk_t *disk_chk;

            if (!slave_needs_remapping(ext->shadow_map[(chunkno*k_factor)+idx].slave_id))
                continue;

            /* This slave needs remapping. Get a replacement disk chunk. */
            disk_chk = castle_extent_remap_disk_chunk_alloc(ext, chunkno);
            /*
             * Lock the shadow map here because we don't want the read/write path to access
             * a chunk in mid-remap.
             */
            spin_lock(&ext->shadow_map_lock);
            ext->shadow_map[(chunkno*k_factor)+idx].slave_id = disk_chk->slave_id;
            ext->shadow_map[(chunkno*k_factor)+idx].offset = disk_chk->offset;
            spin_unlock(&ext->shadow_map_lock);

            chunk_remapped = 1; /* So we know we have to write out the new chunk mapping */
        }

        if (chunk_remapped)
        {
            c_ext_pos_t cep;
            c2_block_t  *c2b;
            c_ext_pos_t map_cep, map_page_cep;
            c2_block_t * map_c2b;

            /*
             * If a chunk has been remapped, read it in (via the old map) and write it out (via the
             * shadow map).
             */
            cep.ext_id = ext->ext_id;
            cep.offset = chunkno*C_CHK_SIZE;

            c2b = castle_cache_block_get(cep, BLKS_PER_CHK);
            write_lock_c2b(c2b);

            /*
             * If c2b is not up to date, issue a blocking READ to update.
             * READ uses the existing map.
             */
            if(!c2b_uptodate(c2b))
                BUG_ON(submit_c2b_sync(READ, c2b));

            /*
             * Force the write to push out to disk. The cache may think that the block is not
             * dirty, but we know better.
             */
            dirty_c2b(c2b);

            /* Write will use the shadow map */
            BUG_ON(submit_c2b_sync(WRITE, c2b));

            write_unlock_c2b(c2b);

            /* This c2b is not needed any more, and it pollutes the cache, so destroy it. */
            BUG_ON(castle_cache_block_destroy(c2b) && LOGICAL_EXTENT(ext->ext_id));

            /* Now write out the shadow map entry for this chunk. */

            /* First, get the cep for the map for this chunk */
            map_cep = castle_extent_map_cep_get(ext->maps_cep, chunkno, ext->k_factor);
            /* Make the map_page_cep offset block aligned. */
            memcpy(&map_page_cep, &map_cep, sizeof(c_ext_pos_t));
            map_page_cep.offset = MASK_BLK_OFFSET(map_page_cep.offset);

            /* Get the c2b for the page containing the map cep */
            map_c2b = castle_cache_page_block_get(map_page_cep);

            write_lock_c2b(map_c2b);

            /* Update the buffer so it contains the shadow map for the chunk */
            memcpy(c2b_buffer(map_c2b) + BLOCK_OFFSET(map_cep.offset),
                &ext->shadow_map[chunkno*k_factor],
                ext->k_factor * sizeof(c_disk_chk_t));

            dirty_c2b(map_c2b);
            update_c2b(map_c2b);

            write_unlock_c2b(map_c2b);
            put_c2b(map_c2b);
        }

        /*
         * Allow for shutdown in mid-extent (between chunks), because extents may be large and
         * take too long to remap.
         */
        if (kthread_should_stop())
        {
            spin_lock(&ext->shadow_map_lock);
            ext->use_shadow_map = 0;
            spin_unlock(&ext->shadow_map_lock);
            castle_free(ext->shadow_map);
            /* Release the hold we took in castle_rebuild_extent_add */
            castle_extent_put(ext->ext_id);
            return 1;
        }
    }

    /* This is the rebuild sequence number we have rebuilt the extent to. */
    ext->curr_rebuild_seqno = rebuild_to_seqno;

    /* Now the shadow map has become the default map, we can stop redirecting write I/O. */
    spin_lock(&ext->shadow_map_lock);
    ext->use_shadow_map = 0;
    spin_unlock(&ext->shadow_map_lock);
    castle_free(ext->shadow_map);

    /* Release the hold we took in castle_rebuild_extent_add */
    castle_extent_put(ext->ext_id);
    return EXIT_SUCCESS;
}

/*
 * Remove all entries from the rebuild list.
 */
static void castle_extent_rebuild_deletelist(void)
{
    struct list_head *entry, *tmp;
    list_for_each_safe(entry, tmp, &rebuild_list)
        list_del(entry);
}

/*
 * The main rebuild kthread function.
 *
 * @return 0:       Kthread should stop.
 */

static int castle_extents_rebuild_run(void *unused)
{
    struct list_head    *l;
    c_ext_t             *ext;
    struct castle_slave *cs, *evacuated_slaves[MAX_NR_SLAVES];
    int                 i, nr_evacuated_slaves=0;

    // TBD - load this from superblock
    atomic_set(&current_rebuild_seqo, 0);

    /* Initialise the rebuild list. */
    INIT_LIST_HEAD(&rebuild_list);

    debug("Starting rebuild thread ...\n");
    do {
        wait_event_interruptible(rebuild_wq,
                                 ((atomic_read(&current_rebuild_seqo) > rebuild_to_seqno) ||
                                  kthread_should_stop()));

        if (kthread_should_stop())
        {
            debug("Rebuild thread terminated.\n");
            goto out;
        }

restart:
        castle_extents_rescan_required = 0;

        rebuild_to_seqno = atomic_read(&current_rebuild_seqo);

        castle_extents_remap_state_init();

        /* Build the list of extents to remap. */
        castle_extents_hash_iterate(castle_extent_rebuild_list_add, NULL);

        /* Iterate over the list, remapping as necessary. */
        list_for_each(l, &rebuild_list)
        {
            ext = list_entry(l, c_ext_t, rebuild_list);
            BUG_ON(ext->curr_rebuild_seqno >= rebuild_to_seqno);

            /*
             * Allow rebuild to be suspended in-between extent remappings.
             * The only 'error' castle_extent_remap should return is when it discovers that
             * kthread_should_stop().
             */
            if (castle_extent_remap(ext) || kthread_should_stop())
            {
                // TBD Write restart info to superblock
                printk("Warning: rebuild terminating early ...\n");

                /* We don't need the extent list any more - delete it */
                castle_extent_rebuild_deletelist();
                goto out;
            }
        }

        /* Finished with the extent list - delete it */
        castle_extent_rebuild_deletelist();

        if ((rebuild_to_seqno == atomic_read(&current_rebuild_seqo)) &&
            !castle_extents_rescan_required)
        {
            /*
             * No further remapping required. We can now convert any evacuating slaves to
             * out-of-service state. First, create the list of evacuated slaves.
             */
            for (i=0; i<MAX_NR_SLAVES; i++)
                evacuated_slaves[i] = 0;    
            nr_evacuated_slaves = 0;
    
            list_for_each(l, &castle_slaves.slaves)
            {
                cs = list_entry(l, struct castle_slave, list);
                if (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &cs->flags))
                    evacuated_slaves[nr_evacuated_slaves++] = cs;
            }
        }

        /*
         * If current_rebuild_seqo has changed during the run then start again to pick up any
         * extents which have not been remapped to the new sequence number.
         */
        if ((rebuild_to_seqno != atomic_read(&current_rebuild_seqo)) ||
            castle_extents_rescan_required)
        {
            debug("Rebuild extent rescan required (seqno has changed)\n");
            goto restart;
        } else
        {
            /*
             * Nothing more to do. Now we can be sure that the set of evacuated_slaves built
             * earlier is correct. Use it to convert evacualted slave to out-of-service.
             */
            for (i=0; i<nr_evacuated_slaves; i++)
                if (evacuated_slaves[i])
                {
                    char b[BDEVNAME_SIZE];
                    printk("Finished remapping evacuated slave 0x%x (%s)."
                            " Converting to out-of-service.\n",
                            evacuated_slaves[i]->uuid, bdevname(evacuated_slaves[i]->bdev, b));
                    set_bit(CASTLE_SLAVE_OOS_BIT, &evacuated_slaves[i]->flags);
                    clear_bit(CASTLE_SLAVE_EVACUATE_BIT, &evacuated_slaves[i]->flags);
                }
        }

    } while (1);

    // NOTREACHED
    BUG();

out:
    castle_extents_remap_state_fini();
    return 0;
}

/*
 * Kick the rebuild thread to start the rebuild process (e.g. when a slave dies or is evacuated).
 */
void castle_extents_rebuild_start(void)
{
    atomic_inc(&current_rebuild_seqo);
    wake_up(&rebuild_wq);
}

/*
 * Main initialisation function for rebuild.
 *
 * @return 0:       Success.
 */
int castle_extents_rebuild_init(void)
{
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
}
