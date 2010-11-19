#ifndef __DEV_FREESPACE_H__
#define __DEV_FREESPACE_H__

#include "castle.h"

/**
 * Freespace: Maintains free space for every disk seperatly. On-disk structure
 *            for every disk contains log of events happened since last
 * reboot(init) and list of free chunks at last reboot. Allocator uses 
 * buddy-list allocation.
 */

#define CHKS_PER_SLOT  10
#define SUPER_CHUNK(chk) ((chk) / CHKS_PER_SLOT)

#define castle_freespace_slave_super_chunk_free(_cs, _super_chk)        \
    castle_freespace_slave_chunk_free(_cs,                              \
    (c_chk_seq_t){((_super_chk)*CHKS_PER_SLOT), CHKS_PER_SLOT})

//void castle_freespace_slaves_init(int fresh_fs);

/* Load on-disk structures into memory */
int castle_freespace_slave_init(struct castle_slave *cs, int fresh);

/* Writeback Freespace meta data back onto disk. */
int castle_freespace_writeback(void);

void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size);

/* Allocate chunks */
c_chk_seq_t castle_freespace_slave_chunks_alloc(struct castle_slave *cs,
                                                da_id_t              da_id, 
                                                c_chk_cnt_t          count);

void castle_freespace_slave_chunk_free(struct castle_slave  *cs, 
                                       c_chk_seq_t           chk_seq);

void castle_freespace_print(struct castle_slave *cs);

void castle_freespace_stats_print(void);
#endif // __DEV_FREESPACE_H__
