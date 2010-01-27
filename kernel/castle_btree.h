#ifndef __CASTLE_BTREE_H__
#define __CASTLE_BTREE_H__

struct castle_btree_type {
    int on_disk_node_size; /* Size of btree node in bytes */

};

typedef struct castle_btree_node_handle {
    c_disk_blk_t              block;
    struct castle_btree_type *tree_type;
} c_bnode_hnd_t;


int  castle_btree_init(void);
void castle_btree_free(void);

#endif /* __CASTLE_BTREE_H__ */
