#ifndef __CASTLE_BLOOM_H__
#define __CASTLE_BLOOM_H__

#include "castle.h"

int castle_bloom_create(castle_bloom_t *bf, da_id_t da_id, uint64_t num_elements);
void castle_bloom_complete(castle_bloom_t *bf);
void castle_bloom_destroy(castle_bloom_t *bf);
void castle_bloom_add(castle_bloom_t *bf, struct castle_btree_type *btree, void *key);
void castle_bloom_submit(c_bvec_t *c_bvec);
void castle_bloom_marshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);
void castle_bloom_unmarshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);

#endif /* __CASTLE_BLOOM_H__ */
