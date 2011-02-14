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

#define FAULT_CODE FREESPACE_FAULT

castle_freespace_t * freespace_sblk_get(struct castle_slave *cs)
{
    mutex_lock(&cs->freespace_lock);
    return &cs->freespace; 
}

void freespace_sblk_put(struct castle_slave *cs, int dirty)
{
    mutex_unlock(&cs->freespace_lock);
}

/**
 * Reserves specified amount of freespace from a slave. Reservation is stored in
 * an appropriate reservation structure, which must be provided to subsequent allocation
 * requests. Reservation can be cancelled. This function cannot be called mulitple times for
 * the same slave, using the same token.
 *
 * @param cs        Slave from which to reserve freespace. 
 * @param nr_schks  Number of superchunks to reserve. 
 * @param token     Reservation structure, updated by this function. Must be zeroed before first
 *                  call to this function.
 *
 * @return 0:       Success.
 * @return -ENOSPC: Not enough freespace. 
 */
int castle_freespace_slave_superchunks_reserve(struct castle_slave *cs, 
                                               c_chk_cnt_t nr_schks,
                                               struct castle_freespace_reservation *token)
{
    castle_freespace_t *freespace;
    c_chk_cnt_t free_schks;
    int ret;
    
    /* Freespace token must be zeroed. */
    if(!token->inited)
    {
        int i;
        for(i=0; i<sizeof(struct castle_freespace_reservation); i++)
            BUG_ON(((char *)token)[i]);
        token->inited = 1;
    }
    BUG_ON(token->reserved_schks[cs->id]);
    /* Get the superblock lock. */
    freespace = freespace_sblk_get(cs);
    /* Work out how many free superchunks there are ATM. */
    if(freespace->cons <= cs->prev_prod)
        free_schks = cs->prev_prod - freespace->cons; 
    else
        free_schks = freespace->max_entries - freespace->cons + cs->prev_prod;
    /* Subtract reserved superchunks. */ 
    BUG_ON(free_schks < cs->reserved_schks);
    free_schks -= cs->reserved_schks;
    
    /* Allocate freespace, if enough freespace is available. */
    ret = -ENOSPC;
    if(free_schks >= nr_schks)
    {
        cs->reserved_schks += nr_schks;
        token->reserved_schks[cs->id] = nr_schks;
        ret = 0;
    }
    /* Release the lock. */ 
    freespace_sblk_put(cs, 0);

    return ret;
}

/**
 * Cleans up the reservation structure, unreserves any remaining superchunks for the
 * specified slave.
 *
 * @param cs    Slave to unreserve the superchunks for.
 * @param token Reservation structure to free from.
 */
void castle_freespace_slave_superchunks_unreserve(struct castle_slave *cs,
                                                  struct castle_freespace_reservation *token)
{
    castle_freespace_t *freespace;
    c_chk_cnt_t schks_to_free;

    /* Reservation token must be initialised. */
    BUG_ON(!token->inited);
    /* Exit early if no superchunks are reserved. */
    schks_to_free = token->reserved_schks[cs->id];
    token->reserved_schks[cs->id] = 0;
    if(schks_to_free == 0)
        return;
    
    /* Get the superblock lock. */
    freespace = freespace_sblk_get(cs);
    BUG_ON(schks_to_free > cs->reserved_schks); 
    cs->reserved_schks -= schks_to_free;
    /* Release the lock. */ 
    freespace_sblk_put(cs, 0);
}
                                      
c_chk_seq_t castle_freespace_slave_superchunk_alloc(struct castle_slave *cs,
                                                    da_id_t da_id,
                                                    struct castle_freespace_reservation *token) 
{
    castle_freespace_t  *freespace;
    c_chk_seq_t          chk_seq;
    c_ext_pos_t          cep;
    c_byte_off_t         cons_off;
    c2_block_t          *c2b;
    c_chk_t             *cons_chk;

    /* Superchunks must be pre-reserved. */
    BUG_ON(!token->inited);
    BUG_ON(token->reserved_schks[cs->id] == 0);
    /* Check for underflows. */ 
    BUG_ON(token->reserved_schks[cs->id] > ((c_chk_cnt_t)-1)/3);

    /* Lock the slave. */
    freespace = freespace_sblk_get(cs);

    /* There should be freespace, because we've reserved it. */
    BUG_ON(freespace->cons == cs->prev_prod);
    BUG_ON(!freespace->free_chk_cnt || !freespace->nr_entries);

    cons_off   = FREESPACE_OFFSET + freespace->cons * sizeof(c_chk_t);
    cep.ext_id = cs->sup_ext;
    cep.offset = MASK_BLK_OFFSET(cons_off);
    c2b = castle_cache_page_block_get(cep);
    write_lock_c2b(c2b);
    
    if ((!c2b_uptodate(c2b)) && (submit_c2b_sync(READ, c2b)))
    {
        debug("Failed to read superblock from slave %x\n", cs->uuid);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        freespace_sblk_put(cs, 0);
        return INVAL_CHK_SEQ;
    }

    cons_chk = (c_chk_t *)(((uint8_t *)c2b_buffer(c2b)) + BLOCK_OFFSET(cons_off));
    BUG_ON((*cons_chk == -1) || (*cons_chk % CHKS_PER_SLOT));

    /* Make the superchunk to return (respresented as chk_seq. */
    chk_seq.first_chk        = *cons_chk;
    chk_seq.count            = CHKS_PER_SLOT;
    /* Update bookkeeping information in various structures. */
    freespace->free_chk_cnt -= CHKS_PER_SLOT;
    atomic_sub(CHKS_PER_SLOT, &cs->free_chk_cnt);
    freespace->cons          = (freespace->cons + 1) % freespace->max_entries;
    freespace->nr_entries--;
    token->reserved_schks[cs->id]--;
    cs->reserved_schks--;
    
    BUG_ON(freespace->nr_entries < 0 || freespace->free_chk_cnt < 0);

    dirty_c2b(c2b);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    BUG_ON((chk_seq.first_chk + chk_seq.count - 1) >= (freespace->disk_size + FREE_SPACE_START));
    freespace_sblk_put(cs, 1);

    INJECT_FAULT;

    debug("Allocating %u chunks from slave %u at %u chunk\n", chk_seq.count, 
          cs->uuid,
          chk_seq.first_chk);
    
    return chk_seq;
}

void castle_freespace_slave_superchunk_free(struct castle_slave *cs, 
                                            c_chk_seq_t          chk_seq)
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
    atomic_add(chk_seq.count, &cs->free_chk_cnt);
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

    INJECT_FAULT;

    freespace_sblk_put(cs, 1);
}

sector_t get_bd_capacity(struct block_device *bd);
static int castle_freespace_print(struct castle_slave *cs, void *unused);

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

    cs->reserved_schks = 0;
    cs->disk_size = freespace->disk_size;
    atomic_set(&cs->free_chk_cnt, freespace->free_chk_cnt);
    castle_freespace_print(cs, NULL);

    nr_chunks = freespace->disk_size;
  
    INJECT_FAULT;

    if (fresh)
        castle_freespace_slave_superchunk_free(cs, (c_chk_seq_t){FREE_SPACE_START, nr_chunks});

    cs->frozen_prod = cs->prev_prod = freespace->prod;

    return 0;
}

void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size)
{
    if (free_cnt)
        *free_cnt = atomic_read(&cs->free_chk_cnt);
    
    if (size)
        *size = (cs->disk_size + FREE_SPACE_START);
}

static void castle_freespace_foreach_slave(int (*fn)(struct castle_slave *cs, void *data), 
                                    void *data)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        fn(slave, data);
    }
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
    INJECT_FAULT;

    return 0;
}

int castle_freespace_writeback(void)
{
    castle_freespace_foreach_slave(castle_freespace_slave_writeback, NULL);

    return 0;
}

void castle_freespace_slave_close(struct castle_slave *cs)
{
    debug("Closed the module\n");
}

static int castle_freespace_print(struct castle_slave *cs, void *unused)
{
    castle_freespace_t  *freespace;

    freespace = freespace_sblk_get(cs);
    printk("\tFreespace (0x%x) -> %u\n", cs->uuid, freespace->free_chk_cnt);
    printk("\t\tprod: %d\n", freespace->prod);
    printk("\t\tcons: %d\n", freespace->cons);
    printk("\t\tprev_prod: %d\n", cs->prev_prod);
    printk("\t\tnr_entries: %d\n", freespace->nr_entries);
    printk("\t\tmax_entries: %d\n", freespace->max_entries);
    freespace_sblk_put(cs, 0);

    return 0;
}

void castle_freespace_stats_print(void)
{
    printk("Freespace stats: \n");
    castle_freespace_foreach_slave(castle_freespace_print, NULL);
}

static int castle_freespace_get(struct castle_slave *cs, void *_space)
{
    c_chk_cnt_t *space = (c_chk_cnt_t *)_space;
    castle_freespace_t *freespace;

    freespace = freespace_sblk_get(cs);
    (*space) += freespace->free_chk_cnt;
    freespace_sblk_put(cs,0);

    return 0;
}

c_chk_cnt_t castle_freespace_space_get(void)
{
    c_chk_cnt_t space;

    castle_freespace_foreach_slave(castle_freespace_get, &space);

    return space;
}
