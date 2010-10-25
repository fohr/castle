#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

#define CHKS_PER_SLOT  10
#define C_FLOOR_OF(a) (((a) / CHKS_PER_SLOT) * CHKS_PER_SLOT)
#define C_CEIL_OF(a)  (C_FLOOR_OF(a) + CHKS_PER_SLOT) 

#define ENTRIES_PER_CHK                (C_CHK_SIZE / sizeof(c_chk_seq_t))

castle_freespace_t * freespace_sblk_get(struct castle_slave *cs)
{
    c2_block_t *c2b = cs->freespace_sblk; 
    
    BUG_ON(c2b == NULL);
    BUG_ON(!c2b_uptodate(c2b));
    write_lock_c2b(c2b);
    
    return c2b_buffer(c2b);
}

void freespace_sblk_put(struct castle_slave *cs, int dirty)
{
    c2_block_t *c2b = cs->freespace_sblk;

    BUG_ON(c2b == NULL);
    if (dirty)
        dirty_c2b(c2b);
    write_unlock_c2b(c2b);
}

c_chk_seq_t castle_freespace_slave_chunks_alloc(struct castle_slave    *cs,
                                                da_id_t                 da_id, 
                                                c_chk_cnt_t             count)
{
    castle_freespace_t  *freespace;
    c_chk_seq_t          chk_seq;
    c_chk_seq_t         *cons_chk_seq;
    c_ext_pos_t          cep;
    c_byte_off_t         cons_off;
    c2_block_t          *c2b;

    if (!count)
        return INVAL_CHK_SEQ;
    
    if (count % CHKS_PER_SLOT)
        count = C_CEIL_OF(count);

    freespace = freespace_sblk_get(cs);

    BUG_ON(freespace->cons == freespace->prod);

    cons_off   = FREESPACE_OFFSET + C_BLK_SIZE + freespace->cons * sizeof(c_chk_seq_t);
    cep.ext_id = cs->sup_ext;
    cep.offset = MASK_BLK_OFFSET(cons_off);
    c2b = castle_cache_block_get(cep, 1);
    write_lock_c2b(c2b);
    
    if (!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    
    cons_chk_seq = (c_chk_seq_t *)(((uint8_t *)c2b_buffer(c2b)) + (cons_off - cep.offset));
    BUG_ON(!cons_chk_seq->count);
    BUG_ON(cons_chk_seq->count % CHKS_PER_SLOT);

    chk_seq.first_chk            = cons_chk_seq->first_chk;
    if (cons_chk_seq->count > count)
    {
        cons_chk_seq->first_chk += count;
        cons_chk_seq->count     -= count;
        chk_seq.count            = count;
    }
    else 
    {
        chk_seq.count   = cons_chk_seq->count;
        freespace->cons = (freespace->cons + 1) % freespace->max_entries;
        freespace->nr_entries--;
    }
    freespace->free_chk_cnt -= chk_seq.count;
    
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
                                       c_chk_seq_t               chk_seq, 
                                       da_id_t                   da_id)
{
    castle_freespace_t  *freespace;
    c2_block_t          *c2b;
    c_chk_seq_t         *prod_chk_seq;
    c_byte_off_t         prod_off;
    c_ext_pos_t          cep;

    if (!chk_seq.count)
        return;

    freespace = freespace_sblk_get(cs);

    debug("Freeing blocks %u\n", chk_seq.count);
    BUG_ON((chk_seq.first_chk + chk_seq.count - 1) >= (freespace->disk_size + FREE_SPACE_START));
    BUG_ON(chk_seq.count % CHKS_PER_SLOT);

    prod_off   = FREESPACE_OFFSET + C_BLK_SIZE + freespace->prod * sizeof(c_chk_seq_t);
    cep.ext_id = cs->sup_ext;
    cep.offset = MASK_BLK_OFFSET(prod_off);
    c2b = castle_cache_block_get(cep, 1);
    write_lock_c2b(c2b);
    
    if (!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    
    prod_chk_seq = (c_chk_seq_t *)(((uint8_t *)c2b_buffer(c2b)) + (prod_off - cep.offset));
    prod_chk_seq->first_chk  = chk_seq.first_chk;
    prod_chk_seq->count      = chk_seq.count;

    dirty_c2b(c2b);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    freespace->free_chk_cnt += chk_seq.count;
    freespace->nr_entries++;

    freespace->prod = (freespace->prod + 1) % freespace->max_entries;

    if (freespace->prod == freespace->cons)
    {
        printk("    Free Chunks: %u from slave %u\n", freespace->free_chk_cnt,
                cs->uuid);
        BUG(); /* FIXME: shouldn't come here */
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
    size_t                   disk_sz = get_bd_capacity(cs->bdev);
    c2_block_t              *c2b;
    c_chk_cnt_t              nr_chunks;
    c_ext_pos_t              cep;

    BUG_ON(!POWOF2(sizeof(c_chk_seq_t)));
    BUG_ON(cs->sup_ext == INVAL_EXT_ID);

    cep.ext_id = cs->sup_ext;
    cep.offset = FREESPACE_OFFSET;
    c2b = castle_cache_block_get(cep, 1);
    BUG_ON(!c2b);
    write_lock_c2b(c2b);
    if (fresh)
        update_c2b(c2b);
    /* If c2b is not up to date, issue a blocking READ to update */
    if (!c2b_uptodate(c2b))
        BUG_ON(submit_c2b_sync(READ, c2b));
    cs->freespace_sblk = c2b;
    freespace = c2b_buffer(c2b);
    
    if (fresh)
    {
        debug("Initialising new device\n");
        memset(freespace, 0, sizeof(castle_freespace_t));
        freespace->disk_size        = C_FLOOR_OF((disk_sz << 9)/ C_CHK_SIZE) -
                                                FREE_SPACE_START;
        freespace->max_entries      = freespace->disk_size / CHKS_PER_SLOT;
    }

    debug("Init Disk %d\n\tsize %u chunks\n\tlist size: %u\n", 
          cs->id, 
          freespace->disk_size,
          freespace->max_entries);
    debug("     Free chunks: %u\n", freespace->free_chk_cnt);
    debug("     nr_entries: %u\n", freespace->nr_entries);

    nr_chunks = freespace->disk_size;
    write_unlock_c2b(c2b);
  
    if (fresh)
        castle_freespace_slave_chunk_free(cs, 
                         (c_chk_seq_t){FREE_SPACE_START, nr_chunks},
                         0);
    cs->disk_size = nr_chunks + FREE_SPACE_START;

    return 0;
}

void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size)
{
    BUG_ON(free_cnt);
    if (size)
        *size = cs->disk_size;
}

void castle_freespace_slave_close(struct castle_slave *cs)
{
    debug("Closed the module\n");
}
