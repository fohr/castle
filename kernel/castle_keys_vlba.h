#ifndef __CASTLE_KEYS_VLBA_H__
#define __CASTLE_KEYS_VLBA_H__

#include <linux/types.h>
#include "castle_public.h"

int          castle_object_btree_key_compare     (const c_vl_bkey_t *key1,
                                                  const c_vl_bkey_t *key2);
int          castle_object_btree_key_copy        (const c_vl_bkey_t *old_key,
                                                  c_vl_bkey_t       *new_key,
                                                  uint32_t           buf_len);
void *       castle_object_btree_key_duplicate   (const c_vl_bkey_t *key);
void *       castle_object_btree_key_next        (const c_vl_bkey_t *key);
int          castle_object_btree_key_bounds_check(const c_vl_bkey_t *key,
                                                  const c_vl_bkey_t *start,
                                                  const c_vl_bkey_t *end,
                                                  int               *offending_dim_p);
c_vl_bkey_t *castle_object_btree_key_skip        (const c_vl_bkey_t *old_key,
                                                  const c_vl_bkey_t *start,
                                                  int                offending_dim,
                                                  int                out_of_range);
void         castle_object_bkey_free             (c_vl_bkey_t       *bkey);

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

#endif  /* !defined(__CASTLE_KEYS_VLBA_H__) */
