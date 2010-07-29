#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

#include "castle_cache.h"

struct castle_btree_type* 
            castle_btree_type_get     (btree_t type);
c2_block_t* castle_btree_node_create  (int version, int is_leaf, uint8_t type,
                                       struct castle_component_tree *ct);
void        castle_btree_find         (c_bvec_t *c_bvec);
         
void        castle_btree_iter_init    (c_iter_t *c_iter, version_t version, int type);
void        castle_btree_iter_start   (c_iter_t *c_iter);
void        castle_btree_iter_replace (c_iter_t *c_iter, int index, 
                                       c_val_tup_t cvt);
void        castle_btree_iter_continue(c_iter_t *c_iter);
void        castle_btree_iter_cancel  (c_iter_t *c_iter, int err);

/* Iterator to enumerate Latest Ancestar(LA) entries */
void        castle_btree_rq_enum_init (c_rq_enum_t *c_rq_enum, 
                                       version_t    version, 
                                       struct castle_component_tree *tree,
                                       void        *start_key,
                                       void        *end_key);
int         castle_btree_rq_enum_has_next(c_rq_enum_t *c_rq_enum);
void        castle_btree_rq_enum_next    (c_rq_enum_t *c_rq_enum,
                                          void       **key_p,
                                          version_t   *version_p,
                                          c_val_tup_t *cvt_p);
void        castle_btree_rq_enum_skip    (c_rq_enum_t *c_rq_enum,
                                          void        *key);
void        castle_btree_rq_enum_cancel  (c_rq_enum_t *c_rq_enum);
         
void        castle_btree_enum_init    (c_enum_t *c_enum); 
int         castle_btree_enum_has_next(c_enum_t *c_enum); 
void        castle_btree_enum_next    (c_enum_t *c_enum, 
                                       void **key_p, 
                                       version_t *version_p, 
                                       c_val_tup_t *cvt_p); 
void        castle_btree_enum_cancel  (c_enum_t *c_enum); 

int         castle_btree_init         (void);
void        castle_btree_free         (void);

#endif /* __CASTLE_BTREE_H__ */
