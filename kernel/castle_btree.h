#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

#include "castle_cache.h"

struct castle_btree_type* 
            castle_btree_type_get     (btree_t type);
uint32_t    castle_btree_vlba_max_nr_entries_get
                                      (uint16_t node_size);
c2_block_t* castle_btree_node_create  (struct castle_component_tree *ct,
                                       int version,
                                       uint16_t level,
                                       int was_preallocated);
void        castle_btree_node_save_prepare
                                      (struct castle_component_tree *ct, 
                                       c_ext_pos_t node_cep,
                                       uint16_t node_size);
void        castle_btree_submit       (c_bvec_t *c_bvec);
         
void        castle_btree_iter_init    (c_iter_t *c_iter, version_t version, int type);
void        castle_btree_iter_start   (c_iter_t *c_iter);
void        castle_btree_iter_replace (c_iter_t *c_iter, int index, 
                                       c_val_tup_t cvt);
void        castle_btree_iter_continue(c_iter_t *c_iter);
void        castle_btree_iter_cancel  (c_iter_t *c_iter, int err);

void        castle_btree_lub_find     (struct castle_btree_node *node,
                                       void *key,
                                       version_t version,
                                       int *lub_idx_p,
                                       int *insert_idx_p);

/* Iterator to enumerate latest ancestral entries */
void        castle_btree_rq_enum_init (c_rq_enum_t *c_rq_enum, 
                                       version_t    version, 
                                       struct castle_component_tree *tree,
                                       void        *start_key,
                                       void        *end_key);
void        castle_btree_rq_enum_cancel  (c_rq_enum_t *c_rq_enum);
extern struct castle_iterator_type castle_btree_rq_iter;
         
/* Iterator to enumerate all entries in a dynamic modlist tree */
void        castle_btree_enum_init    (c_enum_t *c_enum); 
void        castle_btree_enum_cancel  (c_enum_t *c_enum); 
extern struct castle_iterator_type castle_btree_enum; 

int         castle_btree_init         (void);
void        castle_btree_free         (void);

#endif /* __CASTLE_BTREE_H__ */
