#ifndef __CASTLE_FREESPACE_H__
#define __CASTLE_FREESPACE_H__

#include "castle.h"

/**
 * Freespace: Maintains free space for every disk separately. On-disk structure
 *            for every disk contains log of events happened since last
 * reboot(init) and list of free chunks at last reboot. Allocator uses
 * buddy-list allocation.
 */

#define CHKS_PER_SLOT  10
#define SUPER_CHUNK(chk)           ((chk) / CHKS_PER_SLOT)
#define FIRST_CHUNK(sup_chk)       ((sup_chk) * CHKS_PER_SLOT)

/* Load on-disk structures into memory */
int         castle_freespace_slave_init             (struct castle_slave *cs, int fresh);

/* Writeback Freespace meta data back onto disk. */
int         castle_freespace_writeback              (void);

void        castle_freespace_summary_get            (struct castle_slave *cs,
                                                     c_chk_cnt_t         *free_cnt,
                                                     c_chk_cnt_t         *size);

/* Superchunk allocation. */

/**
 * Structure representing freespace reservation from the slaves.
 */
struct castle_freespace_reservation {
    int inited;
    c_chk_cnt_t reserved_schks[MAX_NR_SLAVES];
};

int         castle_freespace_slave_superchunks_reserve
                                                    (struct castle_slave *cs,
                                                     c_chk_cnt_t nr_schks,
                                                     c_res_pool_t *pool);
void        castle_freespace_slave_superchunks_unreserve
                                                    (struct castle_slave *cs,
                                                     c_chk_cnt_t nr_schks,
                                                     c_res_pool_t *pool);
c_chk_seq_t castle_freespace_slave_superchunk_alloc (struct castle_slave *cs,
                                                     c_da_t da_id,
                                                     c_res_pool_t *pool);

void        castle_freespace_slave_superchunk_free  (struct castle_slave  *cs,
                                                     c_chk_seq_t           chk_seq,
                                                     c_res_pool_t         *pool);

void        castle_freespace_stats_print            (void);

c_chk_cnt_t castle_freespace_space_get              (void);

void        castle_freespace_post_checkpoint        (void);

c_chk_cnt_t castle_freespace_free_superchunks             (struct castle_slave *cs);
#endif /* __CASTLE_FREESPACE_H__ */
