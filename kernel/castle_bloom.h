#ifndef __CASTLE_BLOOM_H__
#define __CASTLE_BLOOM_H__

#include "castle.h"

/**** Bloom filter builds ****/

struct castle_bloom_build_params
{
    uint64_t expected_num_elements;
    uint64_t elements_inserted;
    uint32_t chunks_complete;
    uint32_t cur_node_cur_chunk_id;
    struct castle_btree_node *cur_node;
    c2_block_t *node_c2b;
    c_ext_pos_t node_cep;
    void *cur_chunk_buffer;
    c2_block_t *chunk_c2b;
    c_ext_pos_t chunk_cep;
    uint32_t cur_chunk_num_blocks;
    uint32_t nodes_complete;
#ifdef DEBUG
    uint32_t *elements_inserted_per_block;
#endif
};

int castle_bloom_create(castle_bloom_t *bf, da_id_t da_id, uint64_t num_elements);
void castle_bloom_complete(castle_bloom_t *bf);
void castle_bloom_abort(castle_bloom_t *bf);
void castle_bloom_destroy(castle_bloom_t *bf);
void castle_bloom_add(castle_bloom_t *bf, struct castle_btree_type *btree, void *key);
void castle_bloom_submit(c_bvec_t *c_bvec);
void castle_bloom_marshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);
void castle_bloom_unmarshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);
void castle_bloom_build_param_marshall(struct castle_bbp_entry *bbpm,
                                       struct castle_bloom_build_params *bbp);
void castle_bloom_build_param_unmarshall(castle_bloom_t *bf,
                                         struct castle_bbp_entry *bbpm);
#endif /* __CASTLE_BLOOM_H__ */
