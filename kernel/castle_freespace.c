#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"
#include "castle_freespace.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

#define DISK_NO_SPACE(_fs) (((_fs)->prod == (_fs)->cons) &&            \
                            ((_fs)->nr_entries == 0))
#define DISK_NOT_USED(_fs) (((_fs)->prod == (_fs)->cons) &&            \
                            ((_fs)->nr_entries == (_fs)->max_entries))

castle_freespace_t * freespace_sblk_get(struct castle_slave *cs)
{
    mutex_lock(&cs->freespace_lock);
    return &cs->freespace; 
}

void freespace_sblk_put(struct castle_slave *cs, int dirty)
{
    mutex_unlock(&cs->freespace_lock);
}

c_chk_seq_t castle_freespace_slave_chunks_alloc(struct castle_slave    *cs,
                                                da_id_t                 da_id, 
                                                c_chk_cnt_t             count)
{
    castle_freespace_t  *freespace;
    c_chk_seq_t          chk_seq;
    c_ext_pos_t          cep;
    c_byte_off_t         cons_off;
    c2_block_t          *c2b;
    c_chk_t             *cons_chk;

    if (!count)
        return INVAL_CHK_SEQ;

    freespace = freespace_sblk_get(cs);

    /* Check if any freespace left. Don't allocate from freespace freed after
     * last checkpoint. */
    if (freespace->cons == cs->prev_prod)
    {
#if 0
        if (freespace->free_chk_cnt || freespace->nr_entries)
        {
            printk("Inconsistant Freespace structures - %u:%u - %u\n", 
                    freespace->cons, freespace->prod, freespace->free_chk_cnt);
            BUG();
        }
#endif

        freespace_sblk_put(cs, 0);
        return INVAL_CHK_SEQ;
    }
    BUG_ON(!freespace->free_chk_cnt || !freespace->nr_entries);

    cons_off   = FREESPACE_OFFSET + freespace->cons * sizeof(c_chk_t);
    cep.ext_id = cs->sup_ext;
    cep.offset = MASK_BLK_OFFSET(cons_off);
    c2b = castle_cache_page_block_get(cep);
    write_lock_c2b(c2b);
    
    if (!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    
    cons_chk = (c_chk_t *)(((uint8_t *)c2b_buffer(c2b)) + BLOCK_OFFSET(cons_off));
    BUG_ON((*cons_chk == -1) || (*cons_chk % CHKS_PER_SLOT));

    chk_seq.first_chk        = *cons_chk;
    chk_seq.count            = CHKS_PER_SLOT;
    freespace->free_chk_cnt -= CHKS_PER_SLOT;
    freespace->cons          = (freespace->cons + 1) % freespace->max_entries;
    freespace->nr_entries--;
    
    BUG_ON(freespace->nr_entries < 0 || freespace->free_chk_cnt < 0);

    dirty_c2b(c2b);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    BUG_ON((chk_seq.first_chk + chk_seq.count - 1) >= (freespace->disk_size + FREE_SPACE_START));
    freespace_sblk_put(cs, 1);

    debug("Allocating %u chunks from slave %u at %u chunk\n", chk_seq.count, 
          cs->uuid,
          chk_seq.first_chk);
    
    return chk_seq;
}

void castle_freespace_slave_chunk_free(struct castle_slave      *cs, 
                                       c_chk_seq_t               chk_seq)
{
    castle_freespace_t  *freespace;
    c2_block_t          *c2b;
    c_byte_off_t         prod_off;
    c_ext_pos_t          cep = INVAL_EXT_POS;
    c_chk_cnt_t          nr_sup_chunks = (chk_seq.count/CHKS_PER_SLOT);
    int                  i, j;
    c_chk_t             *chunks = NULL;

    if (!chk_seq.count)
        return;

    freespace = freespace_sblk_get(cs);

    debug("Freeing blocks %u\n", chk_seq.count);
    BUG_ON((chk_seq.first_chk + chk_seq.count - 1) >= (freespace->disk_size + FREE_SPACE_START));
    BUG_ON(chk_seq.count % CHKS_PER_SLOT);

    prod_off = FREESPACE_OFFSET + (freespace->prod * sizeof(c_chk_t));
    i = j = 0;
    c2b = NULL;
    while (i < nr_sup_chunks)
    {
        if(!j)
        {
            if (!c2b)
            { /* Initialise for the first iteration. */
                cep.ext_id = cs->sup_ext;
                cep.offset = MASK_BLK_OFFSET(prod_off);
                j = BLOCK_OFFSET(prod_off) / sizeof(c_chk_t);
            }
            else
            { /* Goto next block. */
                dirty_c2b(c2b);
                write_unlock_c2b(c2b);
                put_c2b(c2b);
                if (freespace->prod == 0)
                    cep.offset = 0;
                else
                    cep.offset += C_BLK_SIZE;
            }
            c2b = castle_cache_page_block_get(cep);
            write_lock_c2b(c2b);
            if (!c2b_uptodate(c2b))
                BUG_ON(submit_c2b_sync(READ, c2b));
            chunks = (c_chk_t *)c2b->buffer;
        }

        chunks[j] = chk_seq.first_chk + (i * CHKS_PER_SLOT);
        j = (j + 1) % (C_BLK_SIZE / sizeof(c_chk_t));
        i++;
        freespace->prod = (freespace->prod + 1) % freespace->max_entries;
        BUG_ON(freespace->prod == freespace->cons);
    }

    if (c2b)
    {
        dirty_c2b(c2b);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
    }

    freespace->free_chk_cnt += chk_seq.count;
    freespace->nr_entries += nr_sup_chunks;

    if ((freespace->cons == ((freespace->prod + 1) % freespace->max_entries)) && 
        (freespace->nr_entries != freespace->max_entries - 1))
    {
        printk("    Free Chunks: %u from slave %u\n", freespace->free_chk_cnt,
                cs->uuid);
        freespace_sblk_put(cs, 1);
        castle_freespace_stats_print();
        BUG(); 
    }
    BUG_ON(freespace->nr_entries > freespace->max_entries ||
                freespace->free_chk_cnt > freespace->disk_size);

    freespace_sblk_put(cs, 1);
}

sector_t get_bd_capacity(struct block_device *bd);

/* Load on-disk structures into memory */
int castle_freespace_slave_init(struct castle_slave *cs, int fresh)
{
    castle_freespace_t      *freespace;
    uint64_t                 disk_sz = (get_bd_capacity(cs->bdev) << 9);
    c_chk_cnt_t              nr_chunks;

    BUG_ON(!POWOF2(sizeof(c_chk_t)));
    BUG_ON(cs->sup_ext == INVAL_EXT_ID);

    freespace = &cs->freespace;
    if (!fresh)
    {
        struct castle_slave_superblock *sblk;

        sblk = castle_slave_superblock_get(cs);
        memcpy(freespace, &sblk->freespace, sizeof(castle_freespace_t));
        castle_slave_superblock_put(cs, 0);
    }
    else 
    {
        debug("Initialising new device\n");
        memset(freespace, 0, sizeof(castle_freespace_t));
        freespace->disk_size   = disk_sz / C_CHK_SIZE - FREE_SPACE_START;
        freespace->disk_size  -= (freespace->disk_size % CHKS_PER_SLOT);
        freespace->max_entries = (freespace->disk_size / CHKS_PER_SLOT) + 1;
    }
    mutex_init(&cs->freespace_lock);

    printk("Init Disk %d\n\tsize %u chunks\n\tlist size: %u\n", 
          cs->id, 
          freespace->disk_size,
          freespace->max_entries);
    debug("     Free chunks: %u\n", freespace->free_chk_cnt);
    debug("     nr_entries: %u\n", freespace->nr_entries);

    nr_chunks = freespace->disk_size;
  
    if (fresh)
        castle_freespace_slave_chunk_free(cs, 
                         (c_chk_seq_t){FREE_SPACE_START, nr_chunks});

    cs->frozen_prod = cs->prev_prod = freespace->prod;
#ifdef CASTLE_DEBUG
    cs->disk_size = nr_chunks + FREE_SPACE_START;
#endif

    return 0;
}

void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size)
{
    castle_freespace_t *freespace = freespace_sblk_get(cs);

    if (free_cnt)
        *free_cnt = freespace->free_chk_cnt;
    
    if (size)
        *size = freespace->disk_size;

    freespace_sblk_put(cs, 0);
}

static int castle_freespace_slave_writeback(struct castle_slave *cs, void *unused)
{/* Should be called with extent lock held. Keeps freespace and extents in sync. */
    struct castle_slave_superblock *sblk;

    sblk = castle_slave_superblock_get(cs);

    memcpy(&sblk->freespace, &cs->freespace, sizeof(castle_freespace_t));
    cs->frozen_prod = cs->freespace.prod;

    castle_slave_superblock_put(cs, 1);

    castle_cache_extent_flush_schedule(cs->sup_ext, FREESPACE_OFFSET, 
                                       cs->freespace.nr_entries * sizeof(c_chk_t));
    
    return 0;
}

int castle_freespace_writeback(void)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        castle_freespace_slave_writeback(slave, NULL);
    }

    return 0;
}

void castle_freespace_slave_close(struct castle_slave *cs)
{
    debug("Closed the module\n");
}

void castle_freespace_stats_print(void)
{
    struct list_head *lh;
    struct castle_slave *slave;
    castle_freespace_t  *freespace;

    printk("Freespace stats: \n");
    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        freespace = freespace_sblk_get(slave);
        printk("\tDisk (0x%x) -> %u\n", slave->uuid, freespace->free_chk_cnt);
        printk("\t\tprod: %d\n", freespace->prod);
        printk("\t\tcons: %d\n", freespace->cons);
        printk("\t\tnr_entries: %d\n", freespace->nr_entries);
        printk("\t\tmax_entries: %d\n", freespace->max_entries);
        freespace_sblk_put(slave, 0);
    }
}
