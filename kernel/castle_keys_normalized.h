#ifndef __CASTLE_KEYS_NORMALIZED_H__
#define __CASTLE_KEYS_NORMALIZED_H__

#include "castle_public.h"

struct castle_norm_key;

struct castle_norm_key *castle_norm_key_pack(const struct castle_var_length_btree_key *);
struct castle_norm_key *castle_norm_key_duplicate(const struct castle_norm_key *);
int castle_norm_key_compare(const struct castle_norm_key *, const struct castle_norm_key *);
int castle_norm_key_bounds_check(const struct castle_norm_key *, const struct castle_norm_key *,
                                 const struct castle_norm_key *, int *);
struct castle_var_length_btree_key *castle_norm_key_unpack(const struct castle_norm_key *);

#endif  /* !defined(__CASTLE_KEYS_NORMALIZED_H__) */
