#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

c2_block_t* castle_ftree_node_create  (int version, int is_leaf);
void        castle_ftree_find         (c_bvec_t *c_bvec);
         
void        castle_ftree_iter_init    (c_iter_t *c_iter, version_t version);
void        castle_ftree_iter_start   (c_iter_t *c_iter);
void        castle_ftree_iter_replace (c_iter_t *c_iter, int index, c_disk_blk_t cdb);
void        castle_ftree_iter_continue(c_iter_t *c_iter);
void        castle_ftree_iter_cancel  (c_iter_t *c_iter, int err);
         
int         castle_btree_init         (void);
void        castle_btree_free         (void);

#endif /* __CASTLE_BTREE_H__ */
