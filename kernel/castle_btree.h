#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

int castle_version_tree_read(c_disk_blk_t cdb, struct castle_vtree_node **v_node);
struct castle_vtree_leaf_slot* castle_version_find(struct castle_vtree_node *node, uint32_t version);
int  castle_btree_init(void);
void castle_btree_free(void);

#if 0
struct castle_btree_type {
    int on_disk_node_size; /* Size of btree node in bytes */

};

typedef struct castle_btree_node_handle {
    c_disk_blk_t              block;
    struct castle_btree_type *tree_type;
} c_bnode_hnd_t;
#endif

#endif /* __CASTLE_BTREE_H__ */
