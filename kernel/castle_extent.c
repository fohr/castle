#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_freespace.h"
#include "castle_extent.h"

#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

#define MAP_IDX(_ext, _i, _j)       ((_ext)->k_factor * _i + _j)
#define CASTLE_EXTENTS_HASH_SIZE    100
#define META_EXT_ID                 333

typedef struct {
    c_ext_id_t          ext_id;         /* Unique extent ID */
    c_chk_cnt_t         size;           /* Number of chunks */
    c_rda_type_t        type;           /* RDA type */
    uint32_t            k_factor;       /* K factor in K-RDA */ 
    struct list_head    hash_list; 
    c_chk_seq_t         chk_buf[MAX_NR_SLAVES]; /* FIXME: Give space to client and
                                                   get-rid off this */
    uint32_t            chk_map_off;    /* Offset of chunk mapping in logical extent */
    c_disk_chk_t       *chk_map;        /* Logical-to-Physical chunk mappings */
} c_ext_t;

atomic_t ext_id_seq = ATOMIC(1000);

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

c_rda_spec_t *castle_rda_specs[] =  {
    [DEFAULT]           = &castle_default_rda,
    [JOURNAL]           = &castle_journal_rda,
    [FS_META]           = &castle_fs_meta_rda,
    [LOG_FREEZER]       = &castle_log_freezer_rda,
};

c_ext_t sup_ext = { 
    .ext_id         = 10,
    .size           = SUP_EXT_SIZE,
    .type           = FS_META,
    .k_factor       = 2,
    .chk_map_off    = -1,
    .chk_map        = NULL,
};

c_rda_spec_t * castle_rda_spec_get(c_rda_type_t rda_type)
{
    return castle_rda_specs[rda_type];
}

int castle_extents_init()
{
    int ret = 0;

    debug("Initing castle extents\n");
    /* Set ext_id_seq */

    /* Initialise hash table for extents */
    castle_extents_hash = castle_extents_hash_alloc();
    if(!castle_extents_hash)
    {
        printk("Could not allocate extents hash\n");
        ret = -ENOMEM;
        goto __hell;
    }
    castle_extents_hash_init();

    /* Generate hash table from extent store and chunk map store on logical
     * extents */
    return 0;

__hell:
    return ret;
}

static int castle_extent_hash_remove(c_ext_t *ext, void *unused) 
{
    debug("Freeing extent #%u\n", ext->ext_id);

    list_del(&ext->hash_list);
    castle_free(ext);

    return 0;
}

void castle_extents_fini()
{
    /* Sync in-memory extent hash table with extent store and chunk map store */

    // free castle_extent_free();
    debug("Finishing castle extents\n");
    /* Free the resources */
    castle_extents_hash_iterate(castle_extent_hash_remove, NULL);
    castle_free(castle_extents_hash);
}

c_ext_id_t castle_extent_alloc(c_rda_type_t            rda_type,
                               da_id_t                 da_id,
                               c_chk_cnt_t             count)
{
    int                     i, j, k;
    c_ext_t                *ext;
    void                   *state;
    struct castle_slave   **slaves = NULL;
    c_rda_spec_t           *rda_spec = castle_rda_spec_get(rda_type);
    c_chk_seq_t            *chk_buf;

    /* FIXME: can use better allocation (batch allocation) */
    ext = castle_zalloc(sizeof(c_ext_t), GFP_KERNEL);
    if (!ext)
    {
        printk("Failed to allocate memory for extent\n");
        goto __hell;
    }
    ext->ext_id         = atomic_inc_return(&ext_id_seq);
    ext->size           = count;
    ext->type           = rda_type;
    ext->k_factor       = rda_spec->k_factor;
    ext->chk_map_off    = -1; /* Set to correct value while serializing */
    ext->chk_map        = castle_malloc((sizeof(c_disk_chk_t) * count * rda_spec->k_factor), GFP_KERNEL);
    state               = rda_spec->extent_init(ext->ext_id, count, rda_type);
    slaves              = castle_zalloc(sizeof(struct castle_slave *) * ext->k_factor, GFP_KERNEL);
    chk_buf             = &ext->chk_buf[0];
    if (!ext->chk_map)
    {
        printk("Failed to allocate memory for extent chunk maps of size %llu:%u chunks\n", 
        count, rda_spec->k_factor);
        goto __hell;
    }
    if (!slaves || !state)
    {
        printk("Failed to allocate memory in %s\n", __FUNCTION__);
        goto __hell;
    }

    for (i=0; i<count; i++)
    { /* For each logical chunk */
        /* Get k num of slaves for each logical chunk */
        if (rda_spec->next_slave_get(slaves, state, i, rda_type) < 0)
        {
            printk("Failed to get next slave for extent: %u\n", ext->ext_id);
            goto __hell;
        }

        /* Allocate physical chunks from slaves */
        for (j=0; j<rda_spec->k_factor; j++)
        { /* For each replica */
            struct castle_slave *cs = slaves[j];
            uint32_t id = cs->id;

            /* FIXME: Try better design */
            BUG_ON(id >= MAX_NR_SLAVES);

            ext->chk_map[MAP_IDX(ext,i,j)].slave_id = cs->uuid;
            /* If free chunks are available in the buffer, use them. Otherwise,
             * allocate more */
            if (chk_buf[id].count)
            {
                //debug("Using chunks from buffer\n");
                ext->chk_map[MAP_IDX(ext,i,j)].offset   = chk_buf[id].first_chk;
                if (--chk_buf[id].count)
                    chk_buf[id].first_chk++;
            }
            else 
            {
                /* FIXME: might need to allocate more than one slot */
                chk_buf[id] = castle_freespace_slave_chunks_alloc(cs, 
                                            da_id, 1);
                //debug("Allocating more into buffer\n");
                if (!chk_buf[id].count)
                {
                    debug("Failed to allocate chunks from slave: %u\n",
                            cs->uuid);
                    /* Rollback allocations from other slaves for this chunk*/
                    for (k=0; k<j; k++)
                    {
                        BUG_ON(chk_buf[id].count == 0);
                        ext->chk_map[MAP_IDX(ext,i,k)] = INVAL_DISK_CHK;
                        chk_buf[id].first_chk--;
                        chk_buf[id].count++;
                    }
                    i--;
                    break;
                }
                ext->chk_map[MAP_IDX(ext,i,j)].offset   = chk_buf[id].first_chk;
                if (--chk_buf[id].count)
                    chk_buf[id].first_chk++;
            }
        }
    }
  
    debug("Extent #%u; size: %llu\n ", ext->ext_id, ext->size);
    for (i=0; i<ext->size; i++)
    {
        for (j=0; j<ext->k_factor; j++)
            printk("%u - %llu |", ext->chk_map[MAP_IDX(ext,i,j)].slave_id,
                                    ext->chk_map[MAP_IDX(ext,i,j)].offset);
        debug("\n ");
    }
    /* Add extent to hash table */
    castle_extents_hash_add(ext);
    
    castle_free(slaves);
    rda_spec->extent_fini(ext->ext_id, state);
    return ext->ext_id;

__hell:
    if (state)
        rda_spec->extent_fini(ext->ext_id, state);
    if (ext->chk_map)
        castle_free(ext->chk_map);
    if (ext)
        castle_free(ext);
    if (slaves)
        castle_free(slaves);
    return INVAL_EXT_ID;
}

void castle_extent_free(c_rda_type_t            rda_type,
                        da_id_t                 da_id,
                        c_ext_id_t              ext_id)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);
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

            cs = castle_slave_find_by_uuid(ext->chk_map[MAP_IDX(ext,i,j)].slave_id);
            if (!cs)
            {
                printk("FATAL: Extent is corrupted pointing to uuid: %u\n", 
                        ext->chk_map[MAP_IDX(ext,i,j)].slave_id);
                BUG();
            }
            id = cs->id;
            debug("Freeing chunk %llu from %u - %llu\%llu\n",
            ext->chk_map[MAP_IDX(ext,i,j)].offset,
            ext->chk_map[MAP_IDX(ext,i,j)].slave_id, ext->chk_buf[id].first_chk,
            ext->chk_buf[id].count);
            if (ext->chk_buf[id].count)
            {
                if (ext->chk_buf[id].first_chk - 1 == ext->chk_map[MAP_IDX(ext,i,j)].offset)
                {
                    ext->chk_buf[id].first_chk--;
                    ext->chk_buf[id].count++;
                }
                else
                {
                    castle_freespace_slave_chunk_free(cs, ext->chk_buf[id], da_id);
                    ext->chk_buf[id].first_chk = ext->chk_map[MAP_IDX(ext,i,j)].offset;
                    ext->chk_buf[id].count = 1;
                }
            } 
            else 
            {
                ext->chk_buf[id].first_chk = ext->chk_map[MAP_IDX(ext,i,j)].offset;
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

    castle_free(ext->chk_map);
    castle_free(ext);
}

c_disk_chk_t * castle_extent_map_get(c_ext_id_t             ext_id,
                                     c_chk_t                offset,
                                     uint32_t              *k_factor)
{
    c_ext_t *ext = castle_extents_hash_get(ext_id);

    if (k_factor)
        *k_factor = ext->k_factor;
    return &ext->chk_map[MAP_IDX(ext,offset,0)];
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
    
    ext->ext_id     += cs->id;
    ext->chk_map     = castle_malloc(sizeof(c_disk_chk_t) * ext->size *
                                                    rda_spec->k_factor, GFP_KERNEL);
    if (!ext->chk_map)
    {
        printk("Failed to allocate memory for extent chunk maps of size %llu:%u chunks\n", 
        ext->size, rda_spec->k_factor);
        goto __hell;
    }

    for (i=0; i<ext->size; i++)
    {
        for (j=0; j<rda_spec->k_factor; j++)
        {
            ext->chk_map[MAP_IDX(ext, i, j)].slave_id   = cs->uuid;
            ext->chk_map[MAP_IDX(ext, i, j)].offset     = i + (j * ext->size);
        }
    }
    castle_extents_hash_add(ext);

    return ext->ext_id;

__hell:
    if (ext->chk_map)
        castle_free(ext->chk_map);
    if (ext)
        castle_free(ext);

    return INVAL_EXT_ID;
}

void castle_extent_sup_ext_close(struct castle_slave *cs)
{
    printk("Not yet implemented %s\n", __FUNCTION__);

    return;
}
