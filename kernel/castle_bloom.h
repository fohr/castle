#ifndef __CASTLE_BLOOM_H__
#define __CASTLE_BLOOM_H__

#include "castle.h"

extern int castle_bloom_debug;

/**** Bloom filter builds ****/

/**
 * State structure used during construction of bloom filter.
 */
struct castle_bloom_build_params
{
    uint64_t                    max_num_elements;
    uint64_t                    elements_inserted;
    uint32_t                    chunks_complete;
    uint32_t                    cur_node_cur_chunk_id;
    struct castle_btree_node   *cur_node;
    c2_block_t                 *node_c2b;
    c_ext_pos_t                 node_cep;
    void                       *cur_chunk_buffer;
    c2_block_t                 *chunk_c2b;
    c_ext_pos_t                 chunk_cep;
    uint32_t                    nodes_complete;

    uint8_t                     force_stripped_insert;  /**< Should we insert the stripped key
                                                             hash, even if it matches
                                                             last_stripped_hash?                */
    uint32_t                    last_stripped_hash;     /**< Hash of last stripped key, see
                                                             @also castle_bloom_add().          */
#ifdef DEBUG
    uint32_t                   *elems_in_block;         /**< Key hashes per block in the
                                                             current chunk.                     */
#endif
};

/**
 * Structure to store bloom filter index btree node c2bs.
 */
#define CASTLE_BLOOM_INDEX_NODES_MAX    20      /**< Maximum number of btree nodes for index.   */
struct castle_bloom_index
{
    int         nr_c2bs;                        /**< Number of index c2bs handled by structure. */
    c2_block_t *c2bs[CASTLE_BLOOM_INDEX_NODES_MAX]; /**< Array of index node c2bs.              */
};

int castle_bloom_create(castle_bloom_t *bf, c_da_t da_id, btree_t btree_type, uint64_t num_elements);
void castle_bloom_complete(castle_bloom_t *bf);
void castle_bloom_abort(castle_bloom_t *bf);
void castle_bloom_destroy(castle_bloom_t *bf);
void castle_bloom_add(castle_bloom_t *bf, struct castle_btree_type *btree, void *key);

int castle_bloom_key_exists(c_bloom_lookup_t *bl,
                            castle_bloom_t *bf,
                            void *key,
                            c_btree_hash_enum_t hash_type,
                            castle_bloom_lookup_async_cb_t async_cb,
                            void *private);

void castle_bloom_marshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);
void castle_bloom_unmarshall(castle_bloom_t *bf, struct castle_clist_entry *ctm);
void castle_bloom_build_param_marshall(struct castle_bbp_entry *bbpm,
                                       struct castle_bloom_build_params *bbp);
void castle_bloom_build_param_unmarshall(castle_bloom_t *bf,
                                         struct castle_bbp_entry *bbpm);
#endif /* __CASTLE_BLOOM_H__ */
