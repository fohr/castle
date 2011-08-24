#ifndef __CASTLE_KEYS_NORMALIZED_H__
#define __CASTLE_KEYS_NORMALIZED_H__

#include "castle_public.h"

struct castle_norm_key;

size_t castle_norm_key_size_predict(const struct castle_var_length_btree_key *);
struct castle_norm_key *castle_norm_key_construct(const struct castle_var_length_btree_key *);
struct castle_norm_key *castle_norm_key_duplicate(const struct castle_norm_key *);
int castle_norm_key_compare(const struct castle_norm_key *, const struct castle_norm_key *);

#endif  /* !defined(__CASTLE_KEYS_NORMALIZED_H__) */
