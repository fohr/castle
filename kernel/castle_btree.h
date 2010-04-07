#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

c2_page_t* castle_ftree_node_create  (int version, int is_leaf);
void       castle_ftree_find         (c_bvec_t *c_bvec);
void       castle_ftree_iter         (c_iter_t *c_iter);
void       castle_ftree_iter_continue(c_iter_t *c_iter);
void       castle_ftree_iter_cancel  (c_iter_t *c_iter, int err);
int        castle_btree_init         (void);
void       castle_btree_free         (void);

#endif /* __CASTLE_BTREE_H__ */
