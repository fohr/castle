#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/rbtree.h>
#include <linux/spinlock.h>

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
        (_ext)->obj_refs    = (_me)->obj_refs;                              \
        (_ext)->dirtylist.rb_root = RB_ROOT;                                \
        spin_lock_init(&ext->dirtylist.lock);

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->obj_refs     = (_ext)->obj_refs;                              
 
#define FAULT_CODE EXTENT_FAULT

int low_disk_space = 0;

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_superblock castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

typedef struct {
    c_ext_id_t          ext_id;         /* Unique extent ID */
    c_chk_cnt_t         size;           /* Number of chunks */
    c_rda_type_t        type;           /* RDA type */
    uint32_t            k_factor;       /* K factor in K-RDA */
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent */
    struct list_head    hash_list;      /* Only Dynamic variable */
    uint32_t            ref_cnt;
    uint32_t            obj_refs;
    uint8_t             alive;
    c_ext_dirtylist_t   dirtylist;      /**< Extent c2b dirtylist */
} c_ext_t;

static struct list_head *castle_extents_hash = NULL;
static c_ext_fs_t meta_ext_fs;

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
    micro_ext->obj_refs = 1;
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

    _castle_ext_fs_init(&meta_ext_fs, 0, 0, C_BLK_SIZE, META_EXT_ID);

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

    if (ext->obj_refs != 1)
        printk("Unexpected extents ref count: (%llu, %u)\n", ext->ext_id,
                ext->obj_refs);

    debug("Writing back extent %llu\n", ext->ext_id);

    CONVERT_EXTENT_TO_MENTRY(ext, &mstore_entry);

    spin_unlock_irq(&castle_extents_hash_lock);
    castle_mstore_entry_insert(castle_extents_mstore, &mstore_entry);
    spin_lock_irq(&castle_extents_hash_lock);

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
    castle_ext_fs_marshall(&meta_ext_fs, &ext_sblk->meta_ext_fs_bs);

    /* Flush the complete meta extent onto disk, before completing writeback. */
    BUG_ON(!castle_ext_fs_consistent(&meta_ext_fs));
    castle_cache_extent_flush_schedule(META_EXT_ID, 0,
                                       atomic64_read(&meta_ext_fs.used));

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
    castle_ext_fs_unmarshall(&meta_ext_fs, &ext_sblk->meta_ext_fs_bs);

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
    castle_extents_hash_iterate(castle_extent_hash_remove, NULL);
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
 */
static c_disk_chk_t castle_extent_disk_chk_alloc(da_id_t da_id,
                                                 struct castle_extent_state *ext_state,
                                                 struct castle_slave *slave,
                                                 int copy_id)
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
    chk_seq = castle_freespace_slave_superchunk_alloc(slave, da_id);
    if (CHK_SEQ_INVAL(chk_seq))
    {
        printk("Failed to get freespace from slave: 0x%x\n", slave->uuid);
        castle_freespace_stats_print();
        low_disk_space = 1;
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
            /* The block shouldn't be dirty, yet. */
            BUG_ON(c2b_dirty(map_c2b));
            /* Reset the index, and the map pointer. */
            map_page_idx = 0; 
            map_page = c2b_buffer(map_c2b);
            /* Advance the map cep. */
            map_cep.offset += C_BLK_SIZE;
        }

        /* Ask the RDA spec which slaves to use. */
        if (rda_spec->next_slave_get(slaves, schk_ids, rda_state, chunk) < 0)
        {
            printk("Failed to get next slave for extent: %llu\n", ext->ext_id);
            err = -ENOSPC;
            goto out;
        }

        /* Allocate disk chunks from each slave designated by the rda spec. */
        for (j=0; j<ext->k_factor; j++)
        {
            disk_chk = castle_extent_disk_chk_alloc(da_id, ext_state, slaves[j], schk_ids[j]);
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
    ext->obj_refs       = 1;
    ext->alive          = 1;
    ext->dirtylist.rb_root = RB_ROOT;
    spin_lock_init(&ext->dirtylist.lock);
    
    /* Block aligned chunk maps for each extent. */
    if (ext->ext_id == META_EXT_ID)
    {
        ext->maps_cep.ext_id = MICRO_EXT_ID;
        ext->maps_cep.offset = 0;
    }
    else
    {
        uint32_t nr_blocks = map_size(count, rda_spec->k_factor);

        if (castle_ext_fs_get(&meta_ext_fs, (nr_blocks * C_BLK_SIZE), 0, &ext->maps_cep))
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

    if (ext->obj_refs)
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
                               c_disk_chk_t          *chk_map)
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

    __castle_extent_map_get(ext, offset, chk_map);
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
    ext->obj_refs    = 1;
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

    spin_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    if (!ext)
    {
        spin_unlock_irqrestore(&castle_extents_hash_lock, flags);
        return -EINVAL;
    }
    ext->obj_refs++;

    spin_unlock_irqrestore(&castle_extents_hash_lock, flags);

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

    spin_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    BUG_ON(!ext);
    ext->obj_refs--;

    debug("Object Refrence for %llu: %u\n", ext_id, ext->obj_refs);
    if (ext->obj_refs == 0)
        free_ext = 1;

    spin_unlock_irqrestore(&castle_extents_hash_lock, flags);

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
        BUG_ON(ext->obj_refs != 1);
        spin_unlock_irq(&castle_extents_hash_lock);
        castle_extent_put(ext->ext_id);
        spin_lock_irq(&castle_extents_hash_lock);
    }
    return 0;
}

int castle_extents_restore(void)
{
    castle_extents_hash_iterate(castle_extent_check_alive, NULL);
    return 0;
}
