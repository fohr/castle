#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_freespace.h"
#include "castle_extent.h"
#include "castle_cache.h"

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
        (_ext)->obj_refs    = (_me)->obj_refs;                              

#define CONVERT_EXTENT_TO_MENTRY(_ext, _me)                                 \
        (_me)->ext_id       = (_ext)->ext_id;                               \
        (_me)->size         = (_ext)->size;                                 \
        (_me)->type         = (_ext)->type;                                 \
        (_me)->k_factor     = (_ext)->k_factor;                             \
        (_me)->maps_cep     = (_ext)->maps_cep;                             \
        (_me)->obj_refs     = (_ext)->obj_refs;                              
 
int low_disk_space = 0;

c_chk_cnt_t meta_ext_size = 0;

struct castle_extents_sb_t castle_extents_global_sb;
static DEFINE_MUTEX(castle_extents_mutex);

typedef struct {
    c_ext_id_t          ext_id;         /* Unique extent ID */
    c_chk_cnt_t         size;           /* Number of chunks */
    c_rda_type_t        type;           /* RDA type */
    uint32_t            k_factor;       /* K factor in K-RDA */ 
    c_chk_seq_t         chk_buf[MAX_NR_SLAVES];     
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent */
    struct list_head    hash_list;      /* Only Dynamic variable */
    uint32_t            ref_cnt;
    uint32_t            obj_refs;
    uint8_t             alive;
} c_ext_t;

static struct list_head *castle_extents_hash = NULL;

DEFINE_RHASH_TBL(castle_extents, castle_extents_hash, CASTLE_EXTENTS_HASH_SIZE,
                c_ext_t, hash_list, c_ext_id_t, ext_id, ref_cnt);

void * castle_rda_extent_init(c_ext_id_t             ext_id, 
                              c_chk_cnt_t            size, 
                              c_rda_type_t           rda_type);

int castle_rda_next_slave_get(struct castle_slave  *cs[],
                              void                 *_state,
                              c_chk_t               chk_num,
                              c_rda_type_t          rda_type);

void castle_rda_extent_fini(c_ext_id_t    ext_id,
                            void         *_state);

int castle_extent_space_alloc(c_ext_t *ext, da_id_t da_id);

static c_ext_id_t _castle_extent_alloc(c_rda_type_t            rda_type,
                                       da_id_t                 da_id,
                                       c_chk_cnt_t             count,
                                       c_ext_id_t              ext_id);

static c_rda_spec_t castle_default_rda = {
    .type               = DEFAULT,
    .k_factor           = 2,
    .next_slave_get     = castle_rda_next_slave_get,
    .extent_init        = castle_rda_extent_init,
    .extent_fini        = castle_rda_extent_fini,
};

static c_rda_spec_t castle_journal_rda = {
    .type               = JOURNAL,
    .k_factor           = 2,
    .next_slave_get     = NULL,
    .extent_init        = NULL,
    .extent_fini        = NULL,
};

static c_rda_spec_t castle_fs_meta_rda = {
    .type               = FS_META,
    .k_factor           = 2,
    .next_slave_get     = NULL,
    .extent_init        = NULL,
    .extent_fini        = NULL,
};

static c_rda_spec_t castle_log_freezer_rda = {
    .type               = LOG_FREEZER,
    .k_factor           = 2,
    .next_slave_get     = NULL,
    .extent_init        = NULL,
    .extent_fini        = NULL,
};

static c_rda_spec_t castle_meta_ext_rda = {
    .type               = META_EXT,
    .k_factor           = 2,
    .next_slave_get     = castle_rda_next_slave_get,
    .extent_init        = castle_rda_extent_init,
    .extent_fini        = castle_rda_extent_fini,
};

c_rda_spec_t *castle_rda_specs[] =  {
    [DEFAULT]           = &castle_default_rda,
    [JOURNAL]           = &castle_journal_rda,
    [FS_META]           = &castle_fs_meta_rda,
    [LOG_FREEZER]       = &castle_log_freezer_rda,
    [META_EXT]          = &castle_meta_ext_rda,
    [MICRO_EXT]         = NULL,
    [SUPER_EXT]         = NULL,
};

c_ext_t sup_ext = { 
    .ext_id         = SUP_EXT_ID,
    .size           = SUP_EXT_SIZE,
    .type           = FS_META,
    .k_factor       = 2,
    .maps_cep       = INVAL_EXT_POS,
};

uint8_t extent_init_done = 0;

c_rda_spec_t * castle_rda_spec_get(c_rda_type_t rda_type)
{
    return castle_rda_specs[rda_type];
}

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

int castle_extents_init()
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
    castle_extents_global_sb.next_free_byte       = 0;
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
           sizeof(struct castle_extents_sb_t));
    castle_fs_superblocks_put(sblk, 0);

    mutex_unlock(&castle_extents_mutex);
}

static void castle_extents_super_block_writeback(void)
{ /* Should be called with castle_extents_mutex held. */
    struct castle_fs_superblock *sblk;

    sblk = castle_fs_superblocks_get();

    memcpy(&sblk->extents_sb, &castle_extents_global_sb,
           sizeof(struct castle_extents_sb_t));

    castle_fs_superblocks_put(sblk, 1);
}

static struct castle_extents_sb_t * castle_extents_super_block_get(void)
{
    mutex_lock(&castle_extents_mutex);
    return &castle_extents_global_sb;
}
 
static void castle_extents_super_block_put(int dirty)
{
    mutex_unlock(&castle_extents_mutex);
}

static int castle_extent_micro_ext_create(void)
{
    struct list_head *l;
    struct castle_extents_sb_t *castle_extents_sb = castle_extents_super_block_get();
    int    i = 0;
    c_disk_chk_t *micro_maps = castle_extents_sb->micro_maps;
    c_ext_t      *micro_ext;

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
    struct   list_head *l;
    int      i = 0;
    c_ext_t *meta_ext;
    int      ret;
    struct castle_extents_sb_t *castle_extents_sb;

    meta_ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!meta_ext)
        return -ENOMEM;

    meta_ext->ext_id   = META_EXT_ID;
    meta_ext->size     = 0;
    meta_ext->type     = META_EXT;
    meta_ext->k_factor = 2;
    meta_ext->maps_cep = (c_ext_pos_t){MICRO_EXT_ID, 0};
    meta_ext->obj_refs = 1;
    meta_ext->alive    = 1;

    i = 0;
    list_for_each(l, &castle_slaves.slaves)
        i++;

    /* Allocate meta extent size to be however much we allocated in all the
       slaves, divided by the k-factor (2) */
    meta_ext->size = META_SPACE_SIZE * i / meta_ext->k_factor;
    meta_ext_size = meta_ext->size;

    /* Create meta extent and embed it's chunk mappings into Super extents 
     * on each slave */
    printk("Initialising meta extent mappings for the first time\n");
    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        meta_ext->chk_buf[cs->id].first_chk = META_SPACE_START;
        meta_ext->chk_buf[cs->id].count     = META_SPACE_SIZE;
    }

    /* Allocate freespace for meta extent with K-RDA just like usual
     * extents. Except that, the space for meta extent is taken from
     * META_SPACE_START of each disk. */
    if ((ret = castle_extent_space_alloc(meta_ext, 0)))
    {
        printk("Meta Extent Allocation Failed\n");
        castle_free(meta_ext);

        return ret;
    }

    castle_extents_sb = castle_extents_super_block_get();
    CONVERT_EXTENT_TO_MENTRY(meta_ext, &castle_extents_sb->meta_ext);
    castle_extents_super_block_put(1);

    castle_extents_rhash_add(meta_ext);

    /* Make sure that micro extent is persistent. */
    castle_cache_extent_flush(MICRO_EXT_ID, 0, 0);
    debug("Done with intialization of meta extent mappings\n");

    return 0;
}

static int castle_extent_mstore_ext_create(void)
{
    struct   list_head *l;
    int      i = 0;
    c_ext_t *mstore_ext;
    struct   castle_extents_sb_t *castle_extents_sb;
    c_ext_id_t ext_id;
    int      k_factor = (castle_rda_spec_get(DEFAULT))->k_factor; 

    i = 0;
    list_for_each(l, &castle_slaves.slaves)
        i++;

    ext_id = _castle_extent_alloc(DEFAULT, 0, 
                                  MSTORE_SPACE_SIZE * i / k_factor,
                                  MSTORE_EXT_ID);
    if (ext_id != MSTORE_EXT_ID)
        return -ENOSPC;

    ext_id = _castle_extent_alloc(DEFAULT, 0, 
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

    extent_init_done = 1;

    if (castle_extent_mstore_ext_create())
        return -EINVAL;

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

    return 0;
}

int castle_extents_writeback(void)
{
    struct castle_extents_sb_t *ext_sblk;
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

    /* Flush the complete meta extent onto disk, before completing writeback. */
    castle_cache_extent_flush(META_EXT_ID, 0, 0);

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
    struct castle_extents_sb_t *ext_sblk = NULL;

    BUG_ON(extent_init_done);

    castle_extents_super_block_read();

    ext_sblk = castle_extents_super_block_get();

    if (load_extent_from_mentry(&ext_sblk->micro_ext))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->meta_ext))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->mstore_ext[0]))
        goto error_out;

    if (load_extent_from_mentry(&ext_sblk->mstore_ext[1]))
        goto error_out;

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
    struct castle_extents_sb_t *ext_sblk = NULL;
    struct castle_mstore_iter  *iterator = NULL;
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

int castle_extent_space_alloc(c_ext_t *ext, da_id_t da_id)
{
    c_chk_cnt_t             count = ext->size;
    c_rda_spec_t           *rda_spec = castle_rda_spec_get(ext->type);
    struct castle_slave    *slaves[MAX_NR_SLAVES];
    int                     i, j, k;
    void                   *state;
    c_chk_seq_t            *chk_buf;
    c_disk_chk_t           *maps_buf = NULL;
    c2_block_t             *c2b = NULL;
    uint32_t                req_space ;
    c_ext_pos_t             cep;

    BUG_ON(!POWOF2(ext->k_factor * sizeof(c_disk_chk_t)));
    BUG_ON(LOGICAL_EXTENT(ext->ext_id) && (ext->ext_id < META_EXT_ID));
    
    chk_buf= &ext->chk_buf[0];
    state  = rda_spec->extent_init(ext->ext_id, count, ext->type);
    if (!state)
    {
        debug("RDA returned error for extent_alloc()\n");
        return -EINVAL;
    }

    req_space = (sizeof(c_disk_chk_t) * count * rda_spec->k_factor);
    maps_buf = castle_vmalloc(req_space);
    BUG_ON(!maps_buf);

    for (i=0; i<count; i++)
    { /* For each logical chunk */
        /* Get k num of slaves for each logical chunk */
        if (rda_spec->next_slave_get(slaves, state, i, ext->type) < 0)
        {
            printk("Failed to get next slave for extent: %llu\n", ext->ext_id);
            castle_vfree(maps_buf);
            return -1;
        }

        /* Allocate physical chunks from slaves */
        for (j=0; j<rda_spec->k_factor; j++)
        { /* For each replica */
            struct castle_slave *cs = slaves[j];
            uint32_t id = cs->id;
            uint32_t idx = MAP_IDX(ext, i, j);

            BUG_ON(idx >= (req_space / sizeof(c_disk_chk_t)));
            BUG_ON(id >= MAX_NR_SLAVES);

            maps_buf[idx].slave_id = cs->uuid;
            /* If free chunks are available in the buffer, use them. Otherwise,
             * allocate more */
            if (chk_buf[id].count)
            {
                maps_buf[idx].offset = chk_buf[id].first_chk;
                if (--chk_buf[id].count)
                    chk_buf[id].first_chk++;
            }
            else 
            {
                BUG_ON(ext->ext_id == META_EXT_ID);
                chk_buf[id] = castle_freespace_slave_chunks_alloc(cs, da_id, 1);
                if (CHK_SEQ_INVAL(chk_buf[id]))
                {
                    debug("Failed to allocate chunks from slave: %u\n",
                            cs->uuid);
                    /* Rollback allocations from other slaves for this chunk*/
                    for (k=0; k<j; k++)
                    {
                        BUG_ON(chk_buf[id].count == 0);
                        maps_buf[MAP_IDX(ext, i, k)] = INVAL_DISK_CHK;
                        chk_buf[id].first_chk--;
                        chk_buf[id].count++;
                    }
                    i--;
                    /* TODO: Free the space allocated back to disks. */
                    rda_spec->extent_fini(ext->ext_id, state);
                    castle_vfree(maps_buf);
                    low_disk_space = 1;
                    return -1;
                }
                maps_buf[idx].offset = chk_buf[id].first_chk;
                if (--chk_buf[id].count)
                    chk_buf[id].first_chk++;
            }
        }
    }
    rda_spec->extent_fini(ext->ext_id, state);

    castle_extent_print(ext, NULL);
    for (i=0; i<ext->size; i++)
    {
        for (j=0; j<ext->k_factor; j++)
            debug("%u - %u |", maps_buf[MAP_IDX(ext, i, j)].slave_id,
                                    maps_buf[MAP_IDX(ext, i, j)].offset);
        debug("\n ");
    }

    cep = ext->maps_cep;
    for (i=0; i < req_space; i += C_BLK_SIZE)
    {
        BUG_ON(cep.offset >= (meta_ext_size * C_CHK_SIZE));
        c2b = castle_cache_block_get(cep, 1);
        write_lock_c2b(c2b);
        update_c2b(c2b);
        BUG_ON(c2b_dirty(c2b));
        memcpy(c2b_buffer(c2b), 
               ((uint8_t *)maps_buf) + i, 
               ((req_space - i) > C_BLK_SIZE)?C_BLK_SIZE:(req_space - i));
        dirty_c2b(c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        cep.offset += C_BLK_SIZE;
    }
    castle_vfree(maps_buf);

    return 0;
}
  
c_ext_id_t castle_extent_alloc(c_rda_type_t            rda_type,
                               da_id_t                 da_id,
                               c_chk_cnt_t             count)
{
    return _castle_extent_alloc(rda_type, da_id, count, INVAL_EXT_ID);
}

static c_ext_id_t _castle_extent_alloc(c_rda_type_t            rda_type,
                                       da_id_t                 da_id,
                                       c_chk_cnt_t             count,
                                       c_ext_id_t              ext_id)
{
    c_ext_t                     *ext = NULL;
    c_rda_spec_t                *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_extents_sb_t  *castle_extents_sb = NULL;

    BUG_ON(!extent_init_done);

    if (low_disk_space)
        goto __hell;

#ifdef DEBUG
    castle_freespace_stats_print();
#endif
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
    
    /* Block aligned chunk maps for each extent. */
    BUG_ON(BLOCK_OFFSET(castle_extents_sb->next_free_byte));
    ext->maps_cep.ext_id= META_EXT_ID;
    ext->maps_cep.offset= castle_extents_sb->next_free_byte;
  
    if(castle_extents_sb->next_free_byte + 
       (sizeof(c_disk_chk_t) * count * rda_spec->k_factor) > (meta_ext_size * C_CHK_SIZE))
    {
        printk("Too big of an extent/crossing the boundry.\n");
        goto __hell;
    }
    /* TODO: Use castle_ext_fs_X functions. */
    castle_extents_sb->next_free_byte += (sizeof(c_disk_chk_t) * count * 
                                                            rda_spec->k_factor);
    if (BLOCK_OFFSET(castle_extents_sb->next_free_byte))
        castle_extents_sb->next_free_byte =
                    MASK_BLK_OFFSET(castle_extents_sb->next_free_byte + C_BLK_SIZE);
    BUG_ON(castle_extents_sb->next_free_byte > (meta_ext_size * C_CHK_SIZE));

    if (castle_extent_space_alloc(ext, da_id) < 0)
    {
        printk("Extent alloc failed\n");
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
    struct castle_extents_sb_t  *castle_extents_sb = NULL;
    int                          i, j;
    uint32_t                     req_space;
    c_disk_chk_t                *maps_buf = NULL;
    c_ext_pos_t                  cep;
    c2_block_t                  *c2b = NULL;
    c_chk_t                      super_chk[MAX_NR_SLAVES];
    c_ext_id_t                   ext_id = ext->ext_id;

    if (ext->obj_refs)
    {
        printk("Couldnt delete the referenced extent %llu\n", ext_id);
        return;
    }

    castle_extents_sb = castle_extents_super_block_get();
    castle_extents_rhash_remove(ext);
    printk("Removed extent %llu from hash\n", ext_id);
    req_space = (sizeof(c_disk_chk_t) * ext->size * ext->k_factor);
    maps_buf = castle_vmalloc(req_space);
    BUG_ON(!maps_buf);
    cep = ext->maps_cep;
    for (i=0; i < req_space; i += C_BLK_SIZE)
    {
        BUG_ON(cep.offset >= (meta_ext_size * C_CHK_SIZE));
        c2b = castle_cache_block_get(cep, 1);
        write_lock_c2b(c2b);
        if (!c2b_uptodate(c2b)) BUG_ON(submit_c2b_sync(READ, c2b));
        memcpy(((uint8_t *)maps_buf) + i,
               c2b_buffer(c2b),
               ((req_space - i) > C_BLK_SIZE)?C_BLK_SIZE:(req_space - i));
        memset(c2b_buffer(c2b), 0, C_BLK_SIZE);
        dirty_c2b(c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        cep.offset += C_BLK_SIZE;
    }

    /* Note: Super Chunk 0 is pre-allocated for super extent. No extent contains
     * mappings for Super Chunk 0. */
    memset(super_chk, 0, sizeof(c_chk_t) * MAX_NR_SLAVES);
    /* Free all the physical chunks. Do it in the reverse order, to free chunks in
     * batches */
    for (i=ext->size-1; i>=0; i--) 
    { /* For each logical chunk */
        for (j=0; j<ext->k_factor; j++) 
        { /* For each replica */
            struct      castle_slave *cs;
            uint32_t    id;
            uint32_t    uuid = maps_buf[MAP_IDX(ext, i, j)].slave_id;
            c_chk_t     chk = maps_buf[MAP_IDX(ext, i, j)].offset;

            cs = castle_slave_find_by_uuid(uuid);
            if (!cs)
            {
                printk("FATAL: Extent is corrupted pointing to uuid: %u\n",
                        uuid);
                BUG();
            }
            id = cs->id;
            debug("Freeing chunk %u from %u - %u\n", chk, uuid, super_chk[id]);
            if (super_chk[id] != SUPER_CHUNK(chk))
            {
                if (super_chk[id]) 
                    castle_freespace_slave_super_chunk_free(cs, super_chk[id]); 
                super_chk[id] = SUPER_CHUNK(chk);
            }
        }
    }

    for (i=0; i<MAX_NR_SLAVES; i++)
    {
        if (super_chk[i])
        {
            struct castle_slave *cs = castle_slave_find_by_id(i);
            
            debug("Freeing super chunk %u from %u\n", super_chk[i], cs->uuid);
            castle_freespace_slave_super_chunk_free(cs, super_chk[i]);
        }
    }

    castle_extents_sb->nr_exts--;
    castle_extents_super_block_put(1);

    castle_free(ext);
    castle_vfree(maps_buf);
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

c_chk_cnt_t castle_extent_size_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (ext)
        return ext->size;
    return 0;
}

static void __castle_extent_map_get(c_ext_t             *ext,
                                    c_chk_t              chk_idx,
                                    c_disk_chk_t        *chk_map)
{
    c_ext_pos_t     cep;
    uint64_t        offset;
    c2_block_t     *c2b = NULL;

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
        cep.ext_id  = ext->maps_cep.ext_id;
        BUG_ON(BLOCK_OFFSET(ext->maps_cep.offset));
        cep.offset  = MASK_BLK_OFFSET(ext->maps_cep.offset + offset);
        c2b         = castle_cache_block_get(cep, 1);
        if (!c2b_uptodate(c2b))
        {
            debug("Scheduling read to get chunk mappings for ext: %llu\n",
                        ext->ext_id);
            write_lock_c2b(c2b);
            /* Need to recheck whether it's uptodate after getting the lock. */
            if(!c2b_uptodate(c2b))
                BUG_ON(submit_c2b_sync(READ, c2b));
            write_unlock_c2b(c2b);
        }
        read_lock_c2b(c2b);
        BUG_ON((C_BLK_SIZE - BLOCK_OFFSET(offset)) < (ext->k_factor * sizeof(c_disk_chk_t)));
        memcpy(chk_map, 
               (((uint8_t *)c2b_buffer(c2b)) + BLOCK_OFFSET(offset)),
               ext->k_factor * sizeof(c_disk_chk_t));

        read_unlock_c2b(c2b);
        put_c2b(c2b);
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
    c_ext_t        *ext;
    c_rda_spec_t   *rda_spec = castle_rda_spec_get(FS_META);
    int             i, j;

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

    debug("Created super extent %llu for slave %u\n", ext->ext_id, cs->uuid);

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

    if (EXT_ID_INVAL(ext_id))
        return -EINVAL;

    spin_lock_irqsave(&castle_extents_hash_lock, flags);

    ext = __castle_extents_hash_get(ext_id);
    BUG_ON(!ext);
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
