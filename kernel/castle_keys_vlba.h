#ifndef __CASTLE_KEYS_VLBA_H__
#define __CASTLE_KEYS_VLBA_H__

#include <linux/types.h>
#include "castle_public.h"

int          castle_object_btree_key_compare     (c_vl_bkey_t *key1,
                                                  c_vl_bkey_t *key2);
int          castle_object_btree_key_copy        (c_vl_bkey_t *old_key,
                                                  c_vl_bkey_t *new_key,
                                                  uint32_t     buf_len);
void *       castle_object_btree_key_duplicate   (c_vl_bkey_t *key);
void *       castle_object_btree_key_next        (c_vl_bkey_t *key);
int          castle_object_btree_key_bounds_check(c_vl_bkey_t *key,
                                                  c_vl_bkey_t *start,
                                                  c_vl_bkey_t *end,
                                                  int         *offending_dim_p);
c_vl_bkey_t *castle_object_btree_key_skip        (c_vl_bkey_t *old_key,
                                                  c_vl_bkey_t *start,
                                                  int          offending_dim,
                                                  int          out_of_range);
void         castle_object_bkey_free             (c_vl_bkey_t *bkey);

#endif  /* !defined(__CASTLE_KEYS_VLBA_H__) */
