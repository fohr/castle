#ifndef __DEV_FREESPACE_H__
#define __DEV_FREESPACE_H__

#include "castle.h"

/**
 * Freespace: Maintains free space for every disk seperatly. On-disk structure
 *            for every disk contains log of events happened since last
 * reboot(init) and list of free chunks at last reboot. Allocator uses 
 * buddy-list allocation.
 */

void castle_freespace_slaves_init(int fresh_fs);

/* Load on-disk structures into memory */
int castle_freespace_slave_init(struct castle_slave *cs);

/* Free in-memory structures */
void castle_freespace_slave_close(struct castle_slave *cs);

#if 0                                                       
int          castle_freespace_version_add              (version_t version);
int          castle_freespace_summary_get              (struct castle_slave *cs, uint32_t *buf, size_t max, size_t *count);
ssize_t      castle_freespace_version_slave_blocks_get (struct castle_slave *cs, version_t version);
ssize_t      castle_freespace_version_blocks_get       (version_t version);
#endif

#if 0
void castle_freespace_summary_get(struct castle_slave *cs,
                                  c_chk_cnt_t         *free_cnt,
                                  c_chk_cnt_t         *size);
#endif

/* Allocate chunks */
c_chk_seq_t castle_freespace_slave_chunks_alloc(struct castle_slave *cs,
                                                da_id_t              da_id, 
                                                c_chk_cnt_t          count);

void castle_freespace_slave_chunk_free(struct castle_slave  *cs, 
                                       c_chk_seq_t           chk_seq, 
                                       da_id_t               da_id);

void castle_freespace_print(struct castle_slave *cs);
#endif // __DEV_FREESPACE_H__
