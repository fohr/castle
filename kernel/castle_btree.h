#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

#include "castle_cache.h"

/* When initialising a new btree node, a node size larger then this should be cause for concern. */
#define NODE_SIZE_WARN (256 * C_BLK_SIZE)

struct castle_btree_type*
            castle_btree_type_get     (btree_t type);
size_t      castle_btree_node_size_get(btree_t type);
c2_block_t* castle_btree_node_create  (struct castle_component_tree *ct,
                                       int version,
                                       uint16_t level,
                                       int was_preallocated);
void        castle_btree_submit       (c_bvec_t *c_bvec, int go_async);

void        castle_btree_iter_init    (c_iter_t *c_iter, c_ver_t version, int type);
void        castle_btree_iter_start   (c_iter_t *c_iter);
void        castle_btree_iter_continue(c_iter_t *c_iter);
void        castle_btree_iter_cancel  (c_iter_t *c_iter, int err);

void        castle_btree_lub_find     (struct castle_btree_node *node,
                                       void *key,
                                       c_ver_t version,
                                       int *lub_idx_p,
                                       int *insert_idx_p);

/* Iterator to enumerate latest ancestral entries */
void        castle_rq_iter_init       (c_rq_iter_t *c_rq_iter,
                                       c_ver_t      version,
                                       struct castle_component_tree
                                                   *tree,
                                       void        *start_key,
                                       void        *end_key,
                                       int          seq_id);
void        castle_rq_iter_cancel     (c_rq_iter_t *c_rq_iter);
extern struct castle_iterator_type castle_rq_iter;

int         castle_btree_init         (void);
void        castle_btree_free         (void);
void castle_btree_node_init(struct castle_component_tree *ct,
                            struct castle_btree_node *node,
                            int version,
                            uint16_t node_size,
                            uint8_t rev_level);
void castle_btree_node_buffer_init(btree_t type,
                                   struct castle_btree_node *buffer,
                                   uint16_t node_size,
                                   uint8_t flags,
                                   int version);



#endif /* __CASTLE_BTREE_H__ */
