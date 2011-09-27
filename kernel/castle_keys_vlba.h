#ifndef __CASTLE_KEYS_VLBA_H__
#define __CASTLE_KEYS_VLBA_H__

#include <linux/types.h>
#include "castle_public.h"

int          castle_object_btree_key_compare       (const c_vl_bkey_t *key1,
                                                    const c_vl_bkey_t *key2);
c_vl_bkey_t *castle_object_btree_key_copy          (const c_vl_bkey_t *src,
                                                    c_vl_bkey_t       *dst,
                                                    size_t            *dst_len);
c_vl_bkey_t *castle_object_btree_key_next          (const c_vl_bkey_t *key,
                                                    c_vl_bkey_t       *dst,
                                                    size_t            *dst_len);
c_vl_bkey_t* castle_object_btree_key_hypercube_next(const c_vl_bkey_t *key,
                                                    const c_vl_bkey_t *start,
                                                    const c_vl_bkey_t *end);
void         castle_object_btree_key_free          (c_vl_bkey_t       *bkey);

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
