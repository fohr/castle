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

#define EXTENTS_MAGIC1  0xABABABAB
#define EXTENTS_MAGIC2  0xCDCDCDCD

struct castle_extents_t {
    uint32_t        magic1;
    uint32_t        magic2;
    c_ext_id_t      ext_id_seq;
    uint64_t        nr_exts;
    c_byte_off_t    next_free_byte;
};

c2_block_t *castle_extents_sb_c2b = NULL;

typedef struct {
    c_ext_id_t          ext_id;         /* Unique extent ID */
    c_chk_cnt_t         size;           /* Number of chunks */
    c_rda_type_t        type;           /* RDA type */
    uint32_t            k_factor;       /* K factor in K-RDA */ 
    c_chk_seq_t         chk_buf[MAX_NR_SLAVES]; /* FIXME: Give space to client and
                                                   get-rid off this */
    /* FIXME: Just offset is enough. cep not requried. */
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent */
    struct list_head    hash_list;      /* Only Dynamic variable */
} c_ext_t;

static struct list_head *castle_extents_hash = NULL;

DEFINE_HASH_TBL(castle_extents, castle_extents_hash, CASTLE_EXTENTS_HASH_SIZE,
                c_ext_t, hash_list, c_ext_id_t, ext_id);

void * castle_rda_extent_init(c_ext_id_t             ext_id, 
                              c_chk_cnt_t            size, 
                              c_rda_type_t           rda_type);

int castle_rda_next_slave_get(struct castle_slave  *cs[],
                              void                 *_state,
                              c_chk_t               chk_num,
                              c_rda_type_t          rda_type);

void castle_rda_extent_fini(c_ext_id_t    ext_id,
                            void         *_state);

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

c_ext_t meta_ext = { 
    .ext_id         = META_EXT_ID,
    .size           = -1,           /* The size of meta extent is worked out on the first fs init. */ 
    .type           = META_EXT,
    .k_factor       = 2,
    .maps_cep       = INVAL_EXT_POS,
};

c_ext_t micro_ext = { 
    .ext_id         = MICRO_EXT_ID,
    .size           = MICRO_EXT_SIZE,
    .type           = MICRO_EXT,
    .k_factor       = -1,           /* Set to # of slaves by init() */
    .maps_cep       = INVAL_EXT_POS,
};

uint8_t extent_init_done = 0;

c_disk_chk_t *micro_maps = NULL;

c_rda_spec_t * castle_rda_spec_get(c_rda_type_t rda_type)
{
    return castle_rda_specs[rda_type];
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

    list_del(&ext->hash_list);
    
    if (ext->ext_id == MICRO_EXT_ID || ext->ext_id == META_EXT_ID)
        return 0;

    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs =
                castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));

        castle_free(cs->sup_ext_maps);
    }
    castle_free(ext);

    return 0;
}

static struct castle_extents_t * castle_extents_get_sb(void)
{
    BUG_ON(castle_extents_sb_c2b == NULL);
    write_lock_c2b(castle_extents_sb_c2b);
    BUG_ON(!c2b_uptodate(castle_extents_sb_c2b));

    return ((struct castle_extents_t *) c2b_buffer(castle_extents_sb_c2b));
}

static void castle_extents_put_sb(int dirty)
{
    BUG_ON(castle_extents_sb_c2b == NULL);
    if (dirty)
        dirty_c2b(castle_extents_sb_c2b);
    write_unlock_c2b(castle_extents_sb_c2b);
}

static void castle_extent_micro_maps_set(void)
{
    struct list_head *l;
    int i = 0;

    micro_maps = castle_malloc(sizeof(c_disk_chk_t) * MAX_NR_SLAVES * MICRO_EXT_SIZE, GFP_KERNEL);
    BUG_ON(!micro_maps);

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        BUG_ON(MICRO_EXT_SIZE != 1);
        
        micro_maps[i].slave_id = cs->uuid;
        micro_maps[i].offset   = MICRO_EXT_START;
        i++;
    }

    BUG_ON(i > MAX_NR_SLAVES);
    micro_ext.k_factor = i;
}

static void castle_extent_micro_maps_destroy(void)
{
    castle_free(micro_maps);
}

static int castle_extent_hash_flush2disk(c_ext_t *ext, void *unused) 
{
    static int                      i = 0;
    static int                      pg = 1; /* First page is for extents header */
    static int                      nr_exts = 0;
    static c2_block_t              *c2b = NULL;
    static c_ext_pos_t              cep = {META_EXT_ID, 0};
    static c_ext_t                 *extents = NULL;
    int                             exts_per_pg = C_BLK_SIZE / sizeof(c_ext_t);

    /* Finish extent flush operation. */
    if (ext == NULL)
    {
        struct castle_extents_t *castle_extents_sb = castle_extents_get_sb();

        if (c2b)
        {
            dirty_c2b(c2b);
            write_unlock_c2b(c2b);
            put_c2b(c2b);
            c2b = NULL;
            extents = NULL;
            i = 0;
        }
        if (nr_exts != castle_extents_sb->nr_exts)
        {
            printk("FATAL: Nr of extents doesn't match :%u/%llu\n", nr_exts,
                            castle_extents_sb->nr_exts);
            BUG();
        }
        castle_extents_put_sb(0);
        return 0;
    }

    if (LOGICAL_EXTENT(ext->ext_id))
        return 0;

    debug("Flushing extent #%llu\n", ext->ext_id);

    if (!i)
    {
        cep.offset = pg * C_BLK_SIZE;
        BUG_ON(cep.offset >= (EXT_ST_SIZE * C_CHK_SIZE));
        c2b = castle_cache_block_get(cep, 1);
        write_lock_c2b(c2b);
        update_c2b(c2b);
        extents = c2b_buffer(c2b);
    }
    BUG_ON(!extents);
    memcpy(&extents[i], ext, sizeof(c_ext_t));
    i = (i + 1) % exts_per_pg;
    nr_exts++;
    if (!i)
    {
        dirty_c2b(c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        c2b = NULL;
        extents = NULL;
        pg++;
    }

    return 0;
}

static int castle_extent_print(c_ext_t *ext, void *unused) 
{
    debug("Print   Extent   %llu\n", ext->ext_id);
    debug("        Size     %u chunks\n", ext->size);
    debug("        Maps at  "cep_fmt_str_nl, cep2str(ext->maps_cep));
   
    return 0;
}

void __castle_extents_fini(void)
{
    debug("Finishing castle extents\n");
    castle_extents_hash_iterate(castle_extent_print, NULL);
    /* FIXME: Not safe to do this. Should be fine at end of the module. */
    castle_extents_hash_iterate_unsafe(castle_extent_hash_flush2disk, NULL);
    castle_extent_hash_flush2disk(NULL, NULL);
    put_c2b(castle_extents_sb_c2b);
    castle_extents_sb_c2b = NULL;
}

void castle_extents_fini(void)
{
    /* Make sure cache flushed all dirty pages */
    castle_extents_hash_iterate(castle_extent_hash_remove, NULL);
    castle_extent_micro_maps_destroy();
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
    BUG_ON(LOGICAL_EXTENT(ext->ext_id) && (ext->ext_id != META_EXT_ID));
    
    chk_buf= &ext->chk_buf[0];
    state  = rda_spec->extent_init(ext->ext_id, count, ext->type);
    if (!state)
    {
        printk("Failed to allocate memory in %s\n", __FUNCTION__);
        return -ENOMEM;
    }

    req_space = (sizeof(c_disk_chk_t) * count * rda_spec->k_factor);
    maps_buf = vmalloc(req_space);
    BUG_ON(!maps_buf);

    for (i=0; i<count; i++)
    { /* For each logical chunk */
        /* Get k num of slaves for each logical chunk */
        if (rda_spec->next_slave_get(slaves, state, i, ext->type) < 0)
        {
            printk("Failed to get next slave for extent: %llu\n", ext->ext_id);
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
                /* FIXME: might need to allocate more than one slot */
                chk_buf[id] = castle_freespace_slave_chunks_alloc(cs, 
                                            da_id, 1);
                if (!chk_buf[id].count)
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
                    break;
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
        BUG_ON(cep.offset >= (meta_ext.size * C_CHK_SIZE));
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
    vfree(maps_buf);

    return 0;
}
  
c_ext_id_t castle_extent_alloc(c_rda_type_t            rda_type,
                               da_id_t                 da_id,
                               c_chk_cnt_t             count)
{
    c_ext_t                 *ext;
    c_rda_spec_t            *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_extents_t *castle_extents_sb = NULL;

    BUG_ON(!extent_init_done);
    BUG_ON(count >= MAX_EXT_SIZE);
    ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext)
    {
        printk("Failed to allocate memory for extent\n");
        goto __hell;
    }
    castle_extents_sb   = castle_extents_get_sb();

    ext->ext_id         = castle_extents_sb->ext_id_seq++;
    ext->size           = count;
    ext->type           = rda_type;
    ext->k_factor       = rda_spec->k_factor;
    
    /* Block aligned chunk maps for each extent. */
    BUG_ON(BLOCK_OFFSET(castle_extents_sb->next_free_byte));
    ext->maps_cep.ext_id= META_EXT_ID;
    ext->maps_cep.offset= castle_extents_sb->next_free_byte;
   
    castle_extents_sb->next_free_byte += (sizeof(c_disk_chk_t) * count * 
                                                            rda_spec->k_factor);
    if (BLOCK_OFFSET(castle_extents_sb->next_free_byte))
        castle_extents_sb->next_free_byte =
                    MASK_BLK_OFFSET(castle_extents_sb->next_free_byte + C_BLK_SIZE);
    BUG_ON(castle_extents_sb->next_free_byte > (meta_ext.size * C_CHK_SIZE));
    castle_extents_sb->nr_exts++;
    castle_extents_put_sb(1);

    if (castle_extent_space_alloc(ext, da_id) < 0)
    {
        printk("Extent alloc failed\n");
        goto __hell;
    }
  
    /* Add extent to hash table */
    castle_extents_hash_add(ext);
    castle_extent_print(ext, NULL);

    return ext->ext_id;

__hell:
    if (ext)
        castle_free(ext);

    return INVAL_EXT_ID;
}

void castle_extent_free(c_rda_type_t            rda_type,
                        da_id_t                 da_id,
                        c_ext_id_t              ext_id)
{
    BUG();
#if 0
    c_ext_t *ext = castle_extents_hash_get(ext_id);
    struct castle_extents_t *castle_extents_sb = NULL;
    int i,j;

    if (!ext)
        return;

    /* Remove extent from hash table */
    castle_extents_hash_remove(ext);

    /* Free all the physical chunks. Do it in the reverse order, to free chunks in
     * batches */
    for (i=ext->size-1; i>=0; i--) 
    { /* For each logical chunk */
        for (j=0; j<ext->k_factor; j++) 
        { /* For each replica */
            struct castle_slave *cs;
            uint32_t id;

            cs = castle_slave_find_by_uuid(maps_buf[MAP_IDX(ext, i, j)].slave_id);
            if (!cs)
            {
                printk("FATAL: Extent is corrupted pointing to uuid: %u\n", 
                        maps_buf[MAP_IDX(ext, i, j)].slave_id);
                BUG();
            }
            id = cs->id;
            debug("Freeing chunk %llu from %u - %llu\%llu\n",
            maps_buf[MAP_IDX(ext, i, j)].offset,
            maps_buf[MAP_IDX(ext, i, j)].slave_id, ext->chk_buf[id].first_chk,
            ext->chk_buf[id].count);
            if (ext->chk_buf[id].count)
            {
                if (ext->chk_buf[id].first_chk - 1 == maps_buf[MAP_IDX(ext, i, j)].offset)
                {
                    ext->chk_buf[id].first_chk--;
                    ext->chk_buf[id].count++;
                }
                else
                {
                    castle_freespace_slave_chunk_free(cs, ext->chk_buf[id], da_id);
                    ext->chk_buf[id].first_chk = maps_buf[MAP_IDX(ext, i, j)].offset;
                    ext->chk_buf[id].count = 1;
                }
            } 
            else 
            {
                ext->chk_buf[id].first_chk = maps_buf[MAP_IDX(ext, i, j)].offset;
                ext->chk_buf[id].count++;
            }
        }
    }

    for (i=0; i<MAX_NR_SLAVES; i++)
    {
        if (ext->chk_buf[i].count)
        {
            struct castle_slave *cs = castle_slave_find_by_id(i);
            
            debug("Freeing %llu chunks from %u\n",
                                ext->chk_buf[i].count, cs->uuid);
            castle_freespace_slave_chunk_free(cs, ext->chk_buf[i], da_id);
        }
    }

    castle_extents_sb   = castle_extents_get_sb();
    castle_extents_sb->nr_exts--;
    castle_extents_put_sb(1);

    castle_free(ext->chk_map);
    castle_free(ext);
#endif
}

uint32_t castle_extent_kfactor_get(c_ext_id_t ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    return ext->k_factor;
}

static c_disk_chk_t * castle_extent_map_buf_get(c_ext_t             *ext,
                                                c_chk_t              chk_idx,
                                                c_chk_cnt_t          nr_chunks,
                                                c2_block_t         **_c2b)
{
    c_ext_pos_t     cep;
    uint64_t        start, end;
    c_disk_chk_t   *buf;
    c2_block_t     *c2b = NULL;

    debug("Seeking maps for ext: %llu, %u chunks from %u\n", ext->ext_id,
                    nr_chunks, chk_idx);
    BUG_ON(nr_chunks != 1);
    start = (chk_idx * ext->k_factor * sizeof(c_disk_chk_t));
    end   = ((chk_idx + nr_chunks) * ext->k_factor * sizeof(c_disk_chk_t)) - 1;
    if (SUPER_EXTENT(ext->ext_id))
    {
        struct castle_slave *cs;

        cs = castle_slave_find_by_id(sup_ext_to_slave_id(ext->ext_id));
        BUG_ON(cs->sup_ext_maps == NULL);
        buf = cs->sup_ext_maps + (chk_idx * (sup_ext.k_factor));
    }
    else if (ext->ext_id == MICRO_EXT_ID)
    {
        BUG_ON(nr_chunks != 1);
        BUG_ON(chk_idx != 0);
        BUG_ON(!micro_maps);
        buf = micro_maps;
    }
    else
    {
        /* FIXME: Can't handle chunk mappings spanning across multiple blocks.
         * Cache logic can't handle multiple block access conurrency properly. */
        BUG_ON(BLOCK(start) != BLOCK(end));
        cep.ext_id  = ext->maps_cep.ext_id;
        BUG_ON(BLOCK_OFFSET(ext->maps_cep.offset));
        cep.offset  = MASK_BLK_OFFSET(ext->maps_cep.offset + start);
        c2b         = castle_cache_block_get(cep, 1);
        buf         = (c_disk_chk_t *)(((uint8_t *)c2b_buffer(c2b)) + BLOCK_OFFSET(start));
        if (!c2b_uptodate(c2b))
        {
            debug("Scheduling read to get chunk mappings for ext: %llu\n",
                        ext->ext_id);
            write_lock_c2b(c2b);
            BUG_ON(submit_c2b_sync(READ, c2b));
            write_unlock_c2b(c2b);
        }
        read_lock_c2b(c2b);
    }

    *_c2b = c2b;
    return buf;
}

static void castle_extent_map_buf_put(c_ext_t *ext, c2_block_t *c2b)
{
    if (SUPER_EXTENT(ext->ext_id) || ext->ext_id == MICRO_EXT_ID)
        return;

    BUG_ON(c2b == NULL);
    read_unlock_c2b(c2b);
    put_c2b(c2b);
}

uint32_t castle_extent_map_get(c_ext_id_t             ext_id,
                               c_chk_t                offset,
                               c_chk_cnt_t            nr_chunks, 
                               c_disk_chk_t          *chk_maps)
{
    c_ext_t      *ext;
    c2_block_t   *c2b = NULL;
    c_disk_chk_t *buf;

    BUG_ON(ext_id == INVAL_EXT_ID);
    BUG_ON((ext = castle_extents_hash_get(ext_id)) == NULL);
    if ((offset >= ext->size) || ((offset + nr_chunks - 1) >= ext->size))
    {
        printk("BUG in %s\n", __FUNCTION__);
        printk("    Extent: %llu\n", ext_id);
        printk("    Offset: %u\n", offset);
        printk("    Count: %u\n", nr_chunks);
        printk("    Extent Size: %u\n", ext->size);
        BUG();
    }

    buf = castle_extent_map_buf_get(ext, offset, nr_chunks, &c2b);
    memcpy(chk_maps, buf, sizeof(c_disk_chk_t) * nr_chunks * ext->k_factor);
    castle_extent_map_buf_put(ext, c2b);

    return ext->k_factor;
}


static int castle_extents_super_block_validate(struct castle_extents_t *castle_extents_sb)
{
    if (castle_extents_sb->magic1 != EXTENTS_MAGIC1 ||
        castle_extents_sb->magic2 != EXTENTS_MAGIC2)
    {
        printk("Invalid Extent Super Block\n");
        return 0;
    }

    return 1;
}

static void castle_extents_super_block_init(struct castle_extents_t *castle_extents_sb)
{
    castle_extents_sb->magic1         =   EXTENTS_MAGIC1;
    castle_extents_sb->magic2         =   EXTENTS_MAGIC2;
    castle_extents_sb->ext_id_seq     =   EXT_SEQ_START;
    castle_extents_sb->nr_exts        =   0;
    castle_extents_sb->next_free_byte = EXT_ST_SIZE * C_CHK_SIZE;
}

void castle_extents_load(int first)
{
    struct list_head *l;
    c2_block_t *c2b;
    int i, j, pg;
    c_ext_pos_t cep;
    struct castle_extents_t *castle_extents_sb = NULL;
    uint32_t exts_per_pg;
    c_ext_t *extents = NULL;

    BUG_ON(extent_init_done);
    
    castle_extent_micro_maps_set();
    micro_ext.maps_cep = INVAL_EXT_POS;
    castle_extents_hash_add(&micro_ext);
    
    meta_ext.maps_cep = (c_ext_pos_t){MICRO_EXT_ID, 0};
    castle_extents_hash_add(&meta_ext);

    i = 0;
    list_for_each(l, &castle_slaves.slaves)
        i++;
    /* Allocate meta extent size to be however much we allocated in all the
       slaves, divided by the k-factor (2) */
    meta_ext.size = META_SPACE_SIZE * i / meta_ext.k_factor;

    /* If it is the first invocation of FS, create meta extent and embed it's
     * chunk mappings into Super extents on each slave */
    if (first)
    {
        printk("Initialising meta extent mappings for the first time\n");

        /* FIXME: Doesn't work for dynamic disk claim and rebuild. Dont use id
         * for idx */
        /* Set mappings */
        list_for_each(l, &castle_slaves.slaves)
        {
            struct castle_slave *cs = list_entry(l, struct castle_slave, list);

            meta_ext.chk_buf[cs->id].first_chk = META_SPACE_START;
            meta_ext.chk_buf[cs->id].count     = META_SPACE_SIZE;
        }
        /* Allocate freespace for meta extent with K-RDA just like usual
         * extents. Except that, the space for meta extent is taken from
         * META_SPACE_START of each disk. */
        castle_extent_space_alloc(&meta_ext, 0);
    }
    debug("Done with intialization of meta extent mappings\n");

    /* Read extents super block from first block of meta extent. */
    cep.ext_id = META_EXT_ID;
    cep.offset = 0;
    castle_extents_sb_c2b = castle_cache_block_get(cep, 1);
    write_lock_c2b(castle_extents_sb_c2b);
    if (first)
        update_c2b(castle_extents_sb_c2b);
    if (!c2b_uptodate(castle_extents_sb_c2b))
        BUG_ON(submit_c2b_sync(READ, castle_extents_sb_c2b));
    write_unlock_c2b(castle_extents_sb_c2b);

    castle_extents_sb = castle_extents_get_sb();
    /* Initialize extent super block incase of fresh FS or invalid block. */
    if (first || !castle_extents_super_block_validate(castle_extents_sb))
        castle_extents_super_block_init(castle_extents_sb);

    /* Read extents meta data page by page from meta extent's page 2. */
    j  = 0;
    pg = 1;
    c2b = NULL;
    exts_per_pg = C_BLK_SIZE / sizeof(c_ext_t);
    cep.ext_id  = META_EXT_ID;
    for (i=0; i<castle_extents_sb->nr_exts; i++)
    {
        c_ext_t *ext;

        if (!j)
        {
            cep.offset = pg * C_BLK_SIZE;
            BUG_ON(cep.offset >= (EXT_ST_SIZE * C_CHK_SIZE));
            c2b = castle_cache_block_get(cep, 1);
            write_lock_c2b(c2b);
            BUG_ON(c2b_uptodate(c2b));
            BUG_ON(submit_c2b_sync(READ, c2b));
            extents = c2b_buffer(c2b);
        }
        ext = castle_malloc(sizeof(c_ext_t), GFP_KERNEL);
        BUG_ON(!ext);
        memcpy(ext, &extents[j], sizeof(c_ext_t));
        castle_extents_hash_add(ext);
        castle_extent_print(ext, NULL);
        j = (j + 1) % exts_per_pg;
        if (!j)
        {
            write_unlock_c2b(c2b);
            put_c2b(c2b);
            c2b = NULL;
            extents = NULL;
            pg++;
        }
    }
    if (c2b)
    {
        write_unlock_c2b(c2b);
        put_c2b(c2b);
    }
    castle_extents_put_sb(1);
    extent_init_done = 1;
    debug("Loaded %llu extents from disk\n", castle_extents_sb->nr_exts);
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
    castle_extents_hash_add(ext);
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
    printk("Not yet implemented %s\n", __FUNCTION__);
    BUG();

    return;
}
