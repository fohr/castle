#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/spinlock.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"

#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

#define CHKS_PER_SLOT  10
#define C_FLOOR_OF(a) (((a) / CHKS_PER_SLOT) * CHKS_PER_SLOT)
#define C_CEIL_OF(a)  (C_FLOOR_OF(a) + CHKS_PER_SLOT) 

c_chk_seq_t castle_freespace_slave_chunks_alloc(struct castle_slave    *cs,
                                                da_id_t                 da_id, 
                                                c_chk_cnt_t             count)
{
    castle_freespace_t *freespace = cs->freespace;
    c_chk_seq_t  chk_seq;
    c_chk_seq_t *cons_chk_seq;

    if (!count)
        return INVAL_CHK_SEQ;
    
    if (count % CHKS_PER_SLOT)
        count = C_CEIL_OF(count);

    spin_lock(&freespace->lock);

    BUG_ON(freespace->cons == freespace->prod);

    cons_chk_seq = &freespace->chk_seqs[freespace->cons];
    BUG_ON(!cons_chk_seq->count);
    BUG_ON(cons_chk_seq->count % CHKS_PER_SLOT);

    chk_seq.first_chk        = cons_chk_seq->first_chk;
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

    spin_unlock(&freespace->lock);

    debug("Allocating %llu chunks from slave %u at %llu chunk\n", chk_seq.count, 
          cs->uuid,
          chk_seq.first_chk);
    
    return chk_seq;
}

void castle_freespace_slave_chunk_free(struct castle_slave      *cs, 
                                       c_chk_seq_t               chk_seq, 
                                       da_id_t                   da_id)
{
    castle_freespace_t *freespace = cs->freespace;
    unsigned long flags;

    if (!chk_seq.count)
        return;

    spin_lock(&freespace->lock);

    printk("Freeing blocks %llu\n", chk_seq.count);
    BUG_ON(chk_seq.count % CHKS_PER_SLOT);
    BUG_ON(freespace->chk_seqs[freespace->prod].count);

    freespace->chk_seqs[freespace->prod].first_chk  = chk_seq.first_chk;
    freespace->chk_seqs[freespace->prod].count      = chk_seq.count;
    freespace->free_chk_cnt                        += chk_seq.count;
    freespace->nr_entries++;

    freespace->prod = (freespace->prod + 1) % freespace->max_entries;

    if (freespace->prod == freespace->cons)
    {
        spin_unlock_irqrestore(&freespace->lock, flags);
        printk("    Free Chunks: %llu from slave %u\n", freespace->free_chk_cnt,
                cs->uuid);
        BUG(); /* FIXME: shouldn't come here */
    }

    spin_unlock(&freespace->lock);
}

sector_t get_bd_capacity(struct block_device *bd);

/* Load on-disk structures into memory */
int castle_freespace_slave_init(struct castle_slave *cs)
{
    castle_freespace_t *freespace;
    size_t disk_sz = get_bd_capacity(cs->bdev);
    int ret = 0;

    /* Allocate free-space structure for each slave */
    freespace = castle_zalloc(sizeof(castle_freespace_t), GFP_KERNEL);
    if (!freespace)
    {
        ret = -ENOMEM;
        printk("FATAL: Failed to allocate memory for freespace\n");
        goto __hell;
    }
    freespace->disk_id          = cs->id;
    freespace->prod             = 0;
    freespace->cons             = 0;
    freespace->disk_size        = C_FLOOR_OF((disk_sz << 9)/ C_CHK_SIZE);
    freespace->free_chk_cnt     = freespace->disk_size;
    spin_lock_init(&freespace->lock);
    freespace->max_entries      = freespace->free_chk_cnt / CHKS_PER_SLOT;
    freespace->chk_seqs         = vmalloc(freespace->max_entries *
                                                    sizeof(c_chk_seq_t));
    if (!freespace->chk_seqs)
    {
        ret = -ENOMEM;
        printk("FATAL: Failed to allocate memory for freespace list: %u:%llu\n",
               freespace->max_entries, freespace->disk_size);
        goto __hell;
    }
    /* FIXME: This is in-efficient. Need this for sake of correctness */
    memset(freespace->chk_seqs, 0, freespace->max_entries * sizeof(c_chk_seq_t));
    
    debug("Init Disk %d of size %llu chunks with list size: %u\n", 
          cs->id, 
          freespace->disk_size,
          freespace->max_entries);
   
    freespace->free_chk_cnt -= FREE_SPACE_START;
    cs->freespace = freespace;
    
    castle_freespace_slave_chunk_free(cs, 
                         (c_chk_seq_t){FREE_SPACE_START, freespace->free_chk_cnt},
                         0);

    return 0;

__hell:
    if (freespace)
    {
        if (freespace->chk_seqs)
            castle_free(freespace->chk_seqs);
        castle_free(freespace);
    }
    cs->freespace = NULL;

    return ret;
}

void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size)
{
    castle_freespace_t *freespace = cs->freespace;

    *free_cnt   = freespace->free_chk_cnt;
    *size       = freespace->disk_size;
}

void castle_freespace_slave_close(struct castle_slave *cs)
{
    castle_freespace_t *freespace = cs->freespace;

    debug("De-Init Disk %u with free chunks: %llu\n", 
          cs->id, 
          freespace->free_chk_cnt);

    vfree(freespace->chk_seqs);
    castle_free(freespace);
    cs->freespace = NULL;

    debug("Closed the module\n");
}

void castle_freespace_print(struct castle_slave *cs)
{
    castle_freespace_t *freespace = cs->freespace;
    int i;

    printk("*************************************************************");
    printk("Freespace for slave: %u\n", cs->uuid);
    for (i=freespace->cons; i<freespace->prod; i++)
    {
        printk("    %15llu-%15llu\n", freespace->chk_seqs[i].first_chk,
                            freespace->chk_seqs[i].count);
    }
    printk("*************************************************************");
}
