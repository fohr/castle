#include <linux/mm.h>
#include <linux/vmalloc.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"
#include "castle_utils.h"
#include "castle_freespace.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_res_pools(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#define debug_res_pools(_f, _a...)  ((void)0)
#endif

#if 0
#undef debug_res_pools
#define debug_res_pools(_f, _a...)  (printk(_f, ##_a))
#endif

#define DISK_NO_SPACE(_fs) (((_fs)->prod == (_fs)->cons) &&            \
                            ((_fs)->nr_entries == 0))

#define FAULT_CODE FREESPACE_FAULT

static int castle_slaves_size = 0;      /**< Size to allocate to new slaves in chunks.
                                             0 => Maximum available space.                  */
module_param(castle_slaves_size, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_slaves_size, "Size to allocate to new slaves (chunks)");

castle_freespace_t * freespace_sblk_get(struct castle_slave *cs)
{
    mutex_lock(&cs->freespace_lock);
    return &cs->freespace;
}

void freespace_sblk_put(struct castle_slave *cs)
{
    mutex_unlock(&cs->freespace_lock);
}

inline c_chk_cnt_t castle_freespace_free_superchunks(struct castle_slave *cs)
{
    /* Should be part of a extent transaction, to make sure counters are consistent. */
    BUG_ON(!castle_extent_in_transaction());

    if (cs->freespace.cons <= cs->prev_prod)
        return (cs->prev_prod - cs->freespace.cons);

    return (cs->freespace.max_entries - cs->freespace.cons + cs->prev_prod);
}

/**
 * Reserves specified amount of freespace from a slave. Reservation is stored in
 * an appropriate reservation structure, which must be provided to subsequent allocation
 * requests. Reservation can be cancelled.
 *
 * @param cs        Slave from which to reserve freespace.
 * @param nr_schks  Number of superchunks to reserve.
 * @param pool      Reservation pool that the reservations should be bound to.
 *
 * @return 0:       Success.
 * @return -ENOSPC: Not enough freespace.
 */
int castle_freespace_slave_superchunks_reserve(struct castle_slave  *cs,
                                               c_chk_cnt_t           nr_schks,
                                               c_res_pool_t         *pool)
{
    c_chk_cnt_t free_schks;
    int ret = 0;

    /* Should be part of a extent transaction, to avoid race with checkpoints. */
    BUG_ON(!castle_extent_in_transaction());

    /* Get the superblock lock. */
    freespace_sblk_get(cs);

    /* Work out how many free superchunks there are ATM. */
    free_schks = castle_freespace_free_superchunks(cs);

    /* Subtract reserved superchunks. */
    BUG_ON(free_schks < cs->reserved_schks);
    free_schks -= cs->reserved_schks;

    /* Allocate freespace, if enough freespace is available. */
    if (free_schks >= nr_schks)
    {
        debug_res_pools("Reservation count for slave: 0x%x updated: %u -> %u\n",
                         cs->uuid, cs->reserved_schks, cs->reserved_schks + nr_schks);
        cs->reserved_schks += nr_schks;

        /* Update reservation counters in pool structure. */
        if (pool)
        {
            pool->reserved_schks[cs->id] += ((c_signed_chk_cnt_t)nr_schks);
            castle_res_pool_counter_check(pool, cs->id);
        }
    }
    else
        ret = -ENOSPC;

    /* Release the lock. */
    freespace_sblk_put(cs);

    return ret;
}

/**
 * Returns reserved superchunks back to the pool.
 *
 * @param cs            Slave to unreserve the superchunks for.
 * @param schks_to_free How many superchunks to free.
 */
static void _castle_freespace_slave_superchunks_unreserve(struct castle_slave  *cs,
                                                          c_chk_cnt_t           schks_to_free,
                                                          c_res_pool_t         *pool)
{
    /* Should be part of a extent transaction, to avoid race with checkpoints. */
    BUG_ON(!castle_extent_in_transaction());

    BUG_ON(schks_to_free > cs->reserved_schks);

    debug_res_pools("Reservation count for slave: 0x%x updated: %u -> %u\n",
                     cs->uuid, cs->reserved_schks, cs->reserved_schks - schks_to_free);

    cs->reserved_schks -= schks_to_free;

    /* Unreserve superchunks from reservation pool. */
    if (pool)
    {
        c_signed_chk_cnt_t nr_schks = pool->reserved_schks[cs->id];

        /* Unreserve shouldn't be called when we are overallocated. */
        BUG_ON(nr_schks < 0);

        /* We dont use this function to reduce count on over used reservations. */
        BUG_ON(((c_signed_chk_cnt_t)schks_to_free) > nr_schks);

        pool->reserved_schks[cs->id] -= ((c_signed_chk_cnt_t)schks_to_free);

        castle_res_pool_counter_check(pool, cs->id);
    }
}

/**
 * Cleans up the reservation structure, unreserves any remaining superchunks for the
 * specified slave.
 *
 * @param cs    Slave to unreserve the superchunks for.
 * @param token Reservation structure to free from.
 */
void castle_freespace_slave_superchunks_unreserve(struct castle_slave *cs,
                                                  c_chk_cnt_t schks_to_free,
                                                  c_res_pool_t *pool)
{
    c_signed_chk_cnt_t nr_schks = pool->reserved_schks[cs->id];

    /* If asked to unreserve 0 chunks, free all of them. */
    if (schks_to_free == 0)
    {
        /* Exit early if no superchunks are reserved. */
        if (nr_schks <= 0)
        {
            pool->reserved_schks[cs->id] = 0;
            return;
        }
        else
            schks_to_free = (c_chk_cnt_t)nr_schks;
    }

    /* Do the actual work. */
    _castle_freespace_slave_superchunks_unreserve(cs, schks_to_free, pool);
}

static void castle_freespace_slave_superchunk_over_usage(struct castle_slave  *cs,
                                                         c_res_pool_t         *pool)
{
    BUG_ON(!pool);

    /* Should be part of a extent transaction, to avoid race with checkpoints. */
    BUG_ON(!castle_extent_in_transaction());

    /* There shouldnt be any reserved supechunks. */
    BUG_ON(pool->reserved_schks[cs->id] > 0);

    castle_res_pool_counter_check(pool, cs->id);

    /* Never include overallocated chunks shouldn't be added to freed_schks. If we got
     * any free_schks, first use them instead of incrementing overallocated count. */
    if (pool->freed_schks[cs->id])
        pool->freed_schks[cs->id]--;
    else
        pool->reserved_schks[cs->id]--;
}

static void castle_freespace_slave_superchunk_freed(struct castle_slave  *cs,
                                                    c_res_pool_t         *pool)
{
    /* Should be part of a extent transaction, to avoid race with checkpoints. */
    BUG_ON(!castle_extent_in_transaction());

    /* Unreserve superchunks from reservation pool. */
    if (pool)
    {
        castle_res_pool_counter_check(pool, cs->id);

        /* If we still got few overallocated chunks, first free them. */
        if (pool->reserved_schks[cs->id] < 0)
            pool->reserved_schks[cs->id]++;
        else
            pool->freed_schks[cs->id]++;
    }
}

/*
 * Allocate a superchunk from the slave with reservation from reservation pool. It is
 * possible to pass invalid pool id.
 *
 * @param   cs      [in]    Slave that the superchunk has to be reserved from.
 * @param   da_id   [in]    Doubling Array that the space is accounted for.
 * @param   pool    [in]    Reservation pool, that space has to be taken from.
 */
c_chk_seq_t castle_freespace_slave_superchunk_alloc(struct castle_slave *cs,
                                                    c_da_t da_id,
                                                    c_res_pool_t *pool)
{
    castle_freespace_t  *freespace;
    c_chk_seq_t          chk_seq;
    c_ext_pos_t          cep;
    c_byte_off_t         cons_off;
    c2_block_t          *c2b;
    c_chk_t             *cons_chk;
    int                  ret;
    int                  reserved_here = 0;

    /* Check if the reservations are already available. */
    if (pool && (pool->reserved_schks[cs->id] > 0))
        goto get_super_chunk;

    /* Reservations are not available try to reserve some space from unreserved freespace. */
    ret = castle_freespace_slave_superchunks_reserve(cs, 1, NULL);
    if (ret)
    {
        /* If reservation failed, we are expecting -ENOSPC error. */
        BUG_ON(ret != -ENOSPC);

        return INVAL_CHK_SEQ;
    }

    /* Reservations succeeded. */
    reserved_here = 1;

get_super_chunk:

    /* Lock the slave. */
    freespace = freespace_sblk_get(cs);

    /* There should be freespace, because we've reserved it. */
    BUG_ON(freespace->cons == cs->prev_prod);
    BUG_ON(!freespace->free_chk_cnt || !freespace->nr_entries);

    /* Calculate consumer offset within super extent and cep to be used to fetch c2b. */
    cons_off   = FREESPACE_OFFSET + freespace->cons * sizeof(c_chk_t);
    cep.ext_id = cs->sup_ext;
    cep.offset = MASK_BLK_OFFSET(cons_off);
    c2b = castle_cache_page_block_get(cep);
    write_lock_c2b(c2b);

    /* Get the uptodate buffer, If failed it should be due to disk failure. */
    if ((!c2b_uptodate(c2b)) && (submit_c2b_sync(READ, c2b)))
    {
        debug("Failed to read superblock from slave %x\n", cs->uuid);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        freespace_sblk_put(cs);
        /* If we reserved superchunks at the top of this function, we should return them.
           This is unlikely to matter, as the above error will only happen when the
           slave goes out of service, but still. */
        if (reserved_here)
            _castle_freespace_slave_superchunks_unreserve(cs, 1, NULL);

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

    /* Is the space is grabbed from freespace wihtout any reservation for a pool, then update
     * over usage count. */
    if (pool && reserved_here)
    {
        /* Update over usage count. */
        castle_freespace_slave_superchunk_over_usage(cs, pool);

        /* Remove reservation from freespace. */
        _castle_freespace_slave_superchunks_unreserve(cs, 1, NULL);
    }
    else
    {
        BUG_ON(!pool && !reserved_here);

        /* Remove reservation from freespace and pool. */
        _castle_freespace_slave_superchunks_unreserve(cs, 1, pool);
    }

    BUG_ON(freespace->nr_entries < 0 || freespace->free_chk_cnt < 0);

    dirty_c2b(c2b);
    write_unlock_c2b(c2b);
    put_c2b(c2b);

    BUG_ON((chk_seq.first_chk + chk_seq.count - 1) >= (freespace->disk_size + FREE_SPACE_START));
    freespace_sblk_put(cs);

    INJECT_FAULT;

    debug("Allocating %u chunks from slave %u at %u chunk\n", chk_seq.count,
          cs->uuid,
          chk_seq.first_chk);

    return chk_seq;
}

void castle_freespace_slave_superchunk_free(struct castle_slave *cs,
                                            c_chk_seq_t          chk_seq,
                                            c_res_pool_t        *pool)
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
            if (!c2b_uptodate(c2b) && submit_c2b_sync(READ, c2b))
            {
                /*
                 * If the submit failed for a slave superblock extent that has gone OOS,
                 * then we can safely ignore it as we no longer care about it's freespace.
                 * All other failures are fatal.
                 */
                if (SUPER_EXTENT(c2b->cep.ext_id) && test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
                {
                    write_unlock_c2b(c2b);
                    put_c2b(c2b);
                    freespace_sblk_put(cs);
                    return;
                }
                BUG();
            }
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

    if (pool)
    {
        BUG_ON(chk_seq.count != CHKS_PER_SLOT);
        castle_freespace_slave_superchunk_freed(cs, pool);
    }

    BUG_ON(freespace->nr_entries > freespace->max_entries ||
                freespace->free_chk_cnt > freespace->disk_size);

    INJECT_FAULT;

    freespace_sblk_put(cs);
}

sector_t get_bd_capacity(struct block_device *bd);
static int castle_freespace_print(struct castle_slave *cs, void *unused);

/*
 * Initialise freespace for a slave. If it's fresh then calculate initial values. If it's an
 * already existing slave, then copy it from the cs_superblock. If it's an OOS slave
 * then default-initialise it for safety.
 */
int castle_freespace_slave_init(struct castle_slave *cs, int fresh)
{
    castle_freespace_t      *freespace;
    c_chk_cnt_t              nr_chunks;
    int                      slave_oos = test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags);

    BUG_ON(!POWOF2(sizeof(c_chk_t)));
    BUG_ON((cs->sup_ext == INVAL_EXT_ID) && (!slave_oos));

    freespace = &cs->freespace;
    memset(freespace, 0, sizeof(castle_freespace_t));
    if (fresh)
    {
        uint64_t disk_sz = (get_bd_capacity(cs->bdev) << 9);

        debug("Initialising new device\n");
        freespace->disk_size   = disk_sz / C_CHK_SIZE - FREE_SPACE_START;
        if (castle_slaves_size && castle_slaves_size < freespace->disk_size)
            freespace->disk_size = castle_slaves_size;
        freespace->disk_size  -= (freespace->disk_size % CHKS_PER_SLOT);
        freespace->max_entries = (freespace->disk_size / CHKS_PER_SLOT) + 1;
        /* Now, double the max_entries, which guarantees that freespace
           has enough space to produce entries, even if checkpoint is taking
           ages. */
        freespace->max_entries *= 2;
    }
    else if (!slave_oos)
    {
        struct castle_slave_superblock *sblk;

        sblk = castle_slave_superblock_get(cs);
        memcpy(freespace, &sblk->freespace, sizeof(castle_freespace_t));
        castle_slave_superblock_put(cs, 0);
    }

    mutex_init(&cs->freespace_lock);

    cs->reserved_schks = 0;
    cs->disk_size = freespace->disk_size;
    atomic_set(&cs->free_chk_cnt, freespace->free_chk_cnt);

    nr_chunks = freespace->disk_size;

    INJECT_FAULT;

    if (fresh)
    {
        castle_extent_transaction_start();

        castle_freespace_slave_superchunk_free(cs,
                                               (c_chk_seq_t){FREE_SPACE_START, nr_chunks},
                                               NULL);

        castle_extent_transaction_end();
    }

    cs->frozen_prod = cs->prev_prod = freespace->prod;

    if (!slave_oos)
        castle_freespace_print(cs, NULL);

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

    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        fn(slave, data);
    }
    rcu_read_unlock();
}

static int castle_freespace_slave_writeback(struct castle_slave *cs, void *unused)
{/* Should be called with extent lock held. Keeps freespace and extents in sync. */
    struct castle_slave_superblock *sblk;

    sblk = castle_slave_superblock_get(cs);

    memcpy(&sblk->freespace, &cs->freespace, sizeof(castle_freespace_t));
    cs->frozen_prod = cs->freespace.prod;

    castle_slave_superblock_put(cs, 1);

    if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
        castle_cache_extent_flush_schedule(cs->sup_ext, FREESPACE_OFFSET,
                                           cs->freespace.max_entries * sizeof(c_chk_t));
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

int castle_freespace_print(struct castle_slave *cs, void *unused)
{
    castle_freespace_t  *freespace;

    if (!test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
    {
        freespace = freespace_sblk_get(cs);
        castle_printk(LOG_INIT, "\tFreespace (0x%x) -> %u\n", cs->uuid, freespace->free_chk_cnt);
        castle_printk(LOG_INIT, "\t\tprod: %d\n", freespace->prod);
        castle_printk(LOG_INIT, "\t\tcons: %d\n", freespace->cons);
        castle_printk(LOG_INIT, "\t\tprev_prod: %d\n", cs->prev_prod);
        castle_printk(LOG_INIT, "\t\tnr_entries: %d\n", freespace->nr_entries);
        castle_printk(LOG_INIT, "\t\tmax_entries: %d\n", freespace->max_entries);
        freespace_sblk_put(cs);
    }

    return 0;
}

void castle_freespace_stats_print(void)
{
    castle_printk(LOG_INIT, "Freespace stats: \n");
    castle_freespace_foreach_slave(castle_freespace_print, NULL);
}

static int castle_freespace_get(struct castle_slave *cs, void *_space)
{
    c_chk_cnt_t *space = (c_chk_cnt_t *)_space;
    castle_freespace_t *freespace;

    freespace = freespace_sblk_get(cs);
    (*space) += freespace->free_chk_cnt;
    freespace_sblk_put(cs);

    return 0;
}

c_chk_cnt_t castle_freespace_space_get(void)
{
    c_chk_cnt_t space;

    castle_freespace_foreach_slave(castle_freespace_get, &space);

    return space;
}

/* Make the freespace, released since last checkpoint, available for usage.
   As the flushed version is consistent now on disk, It is okay to overwrite
   the previous version now. Change freespace producer accordingly. */
void castle_freespace_post_checkpoint(void)
{
    struct list_head *lh;

    /* Makes sure no parallel freespace operations happening. */
    castle_extent_transaction_start();

    /* Update counters for all slaves. */
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(lh, struct castle_slave, list);

        /* Do not worry about out-of-service slaves. */
        if (test_bit(CASTLE_SLAVE_OOS_BIT, &cs->flags))
            continue;

        cs->prev_prod = cs->frozen_prod;
    }
    rcu_read_unlock();

    /* Update reservation pool counters. */
    castle_res_pools_post_checkpoint();

    castle_extent_transaction_end();

    /* Created more freespace, wakeup all low freespace victims. */
    castle_extent_lfs_victims_wakeup();
}
