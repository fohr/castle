#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

#include "castle_cache.h"

c2_block_t* castle_btree_node_create  (int version, int is_leaf, uint8_t type);
void        castle_btree_find         (c_bvec_t *c_bvec);
         
void        castle_btree_iter_init    (c_iter_t *c_iter, version_t version, int type);
void        castle_btree_iter_start   (c_iter_t *c_iter);
void        castle_btree_iter_replace (c_iter_t *c_iter, int index, c_disk_blk_t cdb);
void        castle_btree_iter_continue(c_iter_t *c_iter);
void        castle_btree_iter_cancel  (c_iter_t *c_iter, int err);
         
void        castle_btree_enum_init    (c_enum_t *c_enum); 
int         castle_btree_enum_has_next(c_enum_t *c_enum); 
void        castle_btree_enum_next    (c_enum_t *c_enum); 
void        castle_btree_enum_cancel  (c_enum_t *c_enum); 

int         castle_btree_init         (void);
void        castle_btree_free         (void);

#endif /* __CASTLE_BTREE_H__ */
