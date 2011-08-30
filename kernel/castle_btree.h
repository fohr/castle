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
void        castle_btree_submit       (c_bvec_t *c_bvec);

void        castle_btree_iter_init    (c_iter_t *c_iter, c_ver_t version, int type);
void        castle_btree_iter_start   (c_iter_t *c_iter);
void        castle_btree_iter_replace (c_iter_t *c_iter, int index, c_val_tup_t cvt);
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
                                       void        *end_key);
void        castle_rq_iter_cancel     (c_rq_iter_t *c_rq_iter);
extern struct castle_iterator_type castle_rq_iter;

/* Iterator to enumerate all entries in a dynamic modlist tree */
void        castle_btree_enum_init    (c_enum_t *c_enum);
void        castle_btree_enum_cancel  (c_enum_t *c_enum);
extern struct castle_iterator_type castle_btree_enum;

int         castle_btree_init         (void);
void        castle_btree_free         (void);

typedef struct vlba_key {
    /* align:   4 */
    /* offset:  0 */ uint32_t length;
    /*          4 */ uint8_t _key[0];
    /*          4 */
} PACKED vlba_key_t;

/*
 * The special values used for the length field of struct vlba_key / struct
 * castle_var_length_btree_key. These are exported here because this type of keys is used
 * well beyond the VLBA tree code, and therefore these values are needed for code which
 * needs to dissect such keys.
 *
 * The straightforward way to name these would be VLBA_TREE_*_KEY_LENGTH, but this could
 * potentially cause confusion between VLBA_TREE_MAX_KEY_LENGTH and
 * VLBA_TREE_MAX_KEY_SIZE, which is a completely unrelated constant.
 */
enum {
    VLBA_TREE_LENGTH_OF_MIN_KEY   = 0x00000000,
    VLBA_TREE_LENGTH_OF_MAX_KEY   = 0xFFFFFFFE,
    VLBA_TREE_LENGTH_OF_INVAL_KEY = 0xFFFFFFFF
};

#endif /* __CASTLE_BTREE_H__ */
