/*
 * System header file inclusions.
 */
#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/kernel.h>
#include <linux/slab.h>         /* kmalloc() and friends */
#include <linux/string.h>       /* memcmp() etc */
#else
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>             /* malloc() etc */
#include <stdio.h>              /* fprintf() etc */
#include <string.h>             /* memcmp() etc */
#include <assert.h>
#include <errno.h>

#define BUG()                   assert(0)
#define BUG_ON(x)               assert(!(x))
#define castle_alloc(x)         malloc(x)
#define castle_free(x)          free(x)
#endif

/*
 * Local header file inclusions.
 */
#include "castle_public.h"
#include "castle_defines.h"
#ifdef __KERNEL__
#include "castle_debug.h"
#include "castle_utils.h"       /* castle_printk() and friends */
#else
void *castle_dup_or_copy(const void *src, size_t src_len, void *dst, size_t *dst_len);
#define LOG_ERROR               stderr
#define castle_printk           fprintf
#endif
#include "castle_keys_vlba.h"

#define PLUS_INFINITY_DIM_LENGTH 0xFFFFFFFF

/**
 * Constructs btree key, from two source keys k1 and k2. Take first n dimensions from k1 and
 * remaining from k2. It is possible that all dimensions are coming from k2 (n = 0). But, we
 * never take all dimensions from k1 (n should less than k1->nr_dims).
 *
 * @param k1                [in]    B-Tree key to copy first dimensions.
 * @param k2                [in]    B-Tree key to copy remianing dimensions from.
 * @param nr_dims_from_k1   [in]    Copy these many number of dimensions from k1 and remaining
 *                                  from k2. Could be zero.
 *
 * @return  out_key SUCCESS
 *          NULL    FAILURE
 */
static c_vl_bkey_t* castle_object_btree_key_construct(const c_vl_bkey_t *k1,
                                                      const c_vl_bkey_t *k2,
                                                      uint32_t nr_dims_from_k1)
{
    uint32_t key_len, nr_dims;
    uint32_t k2_payload_len, offset, i;
    uint32_t payload_split_offset = 0;
    c_vl_bkey_t *out_key;

    /* Sanity checks */
    /* Check if source is NULL. */
    BUG_ON(!k2 || !k2->nr_dims);

    /* k1 should exist if we want to copy few dimensions. */
    BUG_ON(nr_dims_from_k1 > 0 && !k1);

    /* k1 shouldn't exist if we are not copying any thing from k1. */
    BUG_ON(nr_dims_from_k1 == 0 && k1);

    /* If k1 exists, k1 & k2 should contain same number of dimensions. */
    BUG_ON(k1 && (k1->nr_dims != k2->nr_dims));

    /* Number of dimensions to copy shouldn't exceed the nr_dims(k1)-1. We expect atleast one
     * dimension to go from k2. */
    BUG_ON(nr_dims_from_k1 && (nr_dims_from_k1 > (k1->nr_dims - 1)));

    nr_dims = k2->nr_dims;

    /* Workout the length of the key. */

    /* Workout the offset in payload, that k2 dimensions has to be copied to. */
    if (nr_dims_from_k1 > 0)
    {
        /* The length of the header + dimensions from k1 can be easily worked out by looking at
         * the offset for the next dimension in k1. */
        payload_split_offset = KEY_DIMENSION_OFFSET(k1->dim_head[nr_dims_from_k1]);
        key_len = payload_split_offset;
    }
    else
    {
        /* Work out the header size (including the dim_head array) */
        key_len = sizeof(c_vl_bkey_t) + 4 * nr_dims;
        payload_split_offset = KEY_DIMENSION_OFFSET(k2->dim_head[0]);
    }

    BUG_ON(key_len != payload_split_offset);

    /* Find the length of payload to be copied from k2. */
    k2_payload_len = castle_object_btree_key_length(k2) -
                            KEY_DIMENSION_OFFSET(k2->dim_head[nr_dims_from_k1]);
    key_len += k2_payload_len;

    /* Length doesn't include length field */
    if (key_len - 4 > VLBA_TREE_MAX_KEY_SIZE)
        return NULL;

    /* Allocate the single-dimensional key */
    out_key = castle_zalloc(key_len);
    if (!out_key)
        return NULL;

    /* Copy the part from k1. Both header and payload together. */
    if (nr_dims_from_k1 > 0)
        memcpy(out_key, k1, payload_split_offset);
    else
        out_key->nr_dims = k2->nr_dims;

    /* Calculate and set offsets for K2 dimensions. */
    offset = payload_split_offset;
    for (i=nr_dims_from_k1; i<nr_dims; i++)
    {
        out_key->dim_head[i] =
                    KEY_DIMENSION_HEADER(offset, castle_object_btree_key_dim_flags_get(k2, i));
        offset += castle_object_btree_key_dim_length(k2, i);
    }
    BUG_ON(offset != key_len);

    /* Copy payload for k2 dimensions. */
    memcpy((char *)out_key + payload_split_offset,
           castle_object_btree_key_dim_get(k2, nr_dims_from_k1),
           k2_payload_len);

    /* Set key length. */
    out_key->length = key_len - 4;

    return out_key;
}

static inline int castle_object_key_dim_compare(const char *dim_a, uint32_t dim_a_len, uint32_t dim_a_flags,
                                                const char *dim_b, uint32_t dim_b_len, uint32_t dim_b_flags)
{
    int cmp, dim_a_next_flag, dim_b_next_flag;

     /* Lexicographic comparison of the two dims (min length) */
    cmp = memcmp(dim_a, dim_b, ((dim_a_len > dim_b_len) ? dim_b_len : dim_a_len));
    if(cmp)
        return cmp;

    BUG_ON(dim_a_len == PLUS_INFINITY_DIM_LENGTH || dim_b_len == PLUS_INFINITY_DIM_LENGTH);

    if ((dim_a_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG) &&
        (dim_b_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG))
        return 0;

    if (dim_a_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG)
        return -1;

    if (dim_b_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG)
        return 1;

    /* If the common part of the keys the same, check which one is shorter */
    dim_a_len = (dim_a_flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)?
                 PLUS_INFINITY_DIM_LENGTH:
                 dim_a_len;
    dim_b_len = (dim_b_flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)?
                 PLUS_INFINITY_DIM_LENGTH:
                 dim_b_len;
    if(dim_a_len != dim_b_len)
        return (dim_a_len > dim_b_len) ? 1 : -1;

    /* Identical dimension, check if either of the keys has NEXT_FLAG set */
    dim_a_next_flag = dim_a_flags & KEY_DIMENSION_NEXT_FLAG;
    dim_b_next_flag = dim_b_flags & KEY_DIMENSION_NEXT_FLAG;
    /* We should never compare two non-btree keys */
    BUG_ON(dim_a_next_flag && dim_b_next_flag);
    if(dim_a_next_flag)
        return 1;
    if(dim_b_next_flag)
        return -1;

    return 0;
}

int castle_object_btree_key_compare(const c_vl_bkey_t *key1, const c_vl_bkey_t *key2)
{
    int dim;

    /* Compare dimensions first */
    if(key1->nr_dims != key2->nr_dims)
        return key1->nr_dims > key2->nr_dims ? 1 : -1;

    /* Number of dimensions is the same, go through them one by one */
    for(dim=0; dim<key1->nr_dims; dim++)
    {
        int cmp;

        /* Lexicographic comparison of the two dims (min length) */
        cmp = castle_object_key_dim_compare(castle_object_btree_key_dim_get(key1, dim),
                                            castle_object_btree_key_dim_length(key1, dim),
                                            castle_object_btree_key_dim_flags_get(key1, dim),
                                            castle_object_btree_key_dim_get(key2, dim),
                                            castle_object_btree_key_dim_length(key2, dim),
                                            castle_object_btree_key_dim_flags_get(key2, dim));
        if(cmp)
            return cmp;
        /* This dimension is identical in every way for the two keys. Move on to the next one */
    }

    /* All dimensions identical in every way for the two keys => keys identical */
    return 0;
}

static void castle_object_btree_key_dim_inc(c_vl_bkey_t *key, int dim)
{
    uint32_t flags = KEY_DIMENSION_FLAGS(key->dim_head[dim]);
    uint32_t offset = KEY_DIMENSION_OFFSET(key->dim_head[dim]);

    key->dim_head[dim] = KEY_DIMENSION_HEADER(offset, flags | KEY_DIMENSION_NEXT_FLAG);
}

c_vl_bkey_t *castle_object_btree_key_copy(const c_vl_bkey_t *src,
                                          c_vl_bkey_t *dst, size_t *dst_len)
{
    return castle_dup_or_copy(src, src->length + sizeof src->length, dst, dst_len);
}

c_vl_bkey_t *castle_object_btree_key_next(const c_vl_bkey_t *src,
                                          c_vl_bkey_t *dst, size_t *dst_len)
{
    c_vl_bkey_t *new_key;

    /* Duplicate the key first */
    if (!(new_key = castle_object_btree_key_copy(src, dst, dst_len)))
        return NULL;

    /* Increment the least significant dimension */
    castle_object_btree_key_dim_inc(new_key, new_key->nr_dims-1);
    return new_key;
}

/* Checks if the btree key is within the bounds imposed by start/end object keys.
   Returns 1 if the most significant dimension is greater than the end, -1 if it is
   less then start, or 0 if the key is within bounds. Optionally, the function can
   be queried about which dimension offeneded */
static int castle_object_btree_key_bounds_check(const c_vl_bkey_t *key,
                                                const c_vl_bkey_t *start,
                                                const c_vl_bkey_t *end,
                                                int *offending_dim_p)
{
    int dim;

    if((key->nr_dims != start->nr_dims) || (key->nr_dims != end->nr_dims))
    {
        castle_printk(LOG_ERROR, "Nonmatching # of dimensions: key=%d, start_key=%d, end_key=%d\n",
                key->nr_dims, start->nr_dims, end->nr_dims);
        BUG();
    }
    /* Go through each dimension checking if they are within bounds */
    for(dim=0; dim<key->nr_dims; dim++)
    {
        uint32_t key_dim_len, key_dim_flags, start_dim_len, start_dim_flags;
        uint32_t end_dim_len, end_dim_flags;
        const char *key_dim, *start_dim, *end_dim;
        int cmp;

        key_dim_len     = castle_object_btree_key_dim_length(key, dim);
        key_dim         = castle_object_btree_key_dim_get(key, dim);
        key_dim_flags   = castle_object_btree_key_dim_flags_get(key, dim);

        start_dim_len   = castle_object_btree_key_dim_length(start, dim);
        start_dim       = castle_object_btree_key_dim_get(start, dim);
        start_dim_flags = castle_object_btree_key_dim_flags_get(start, dim);

        end_dim_len     = castle_object_btree_key_dim_length(end, dim);
        end_dim         = castle_object_btree_key_dim_get(end, dim);
        end_dim_flags   = castle_object_btree_key_dim_flags_get(end, dim);

        cmp = castle_object_key_dim_compare(key_dim,
                                            key_dim_len,
                                            key_dim_flags,
                                            start_dim,
                                            start_dim_len,
                                            start_dim_flags);
        /* We expect the key to be >= than the start key. Therefore, exit when it is not. */
        if(cmp < 0)
        {
            if(offending_dim_p) *offending_dim_p = dim;
            return -1;
        }

        cmp = castle_object_key_dim_compare(key_dim,
                                            key_dim_len,
                                            key_dim_flags,
                                            end_dim,
                                            end_dim_len,
                                            end_dim_flags);
        /* We expect the key to be <= than the end key. */
        if(cmp > 0)
        {
            if(offending_dim_p) *offending_dim_p = dim;
            return 1;
        }
    }

    return 0;
}

static c_vl_bkey_t* castle_object_btree_key_skip(const c_vl_bkey_t *old_key,
                                                 const c_vl_bkey_t *start,
                                                 int offending_dim,
                                                 int out_of_range)
{
    c_vl_bkey_t *new_key;

    new_key = castle_object_btree_key_construct(old_key,
                                                start,
                                                offending_dim);
    if(!new_key)
        return NULL;

    /* If the offending dimension was out_of_range than the bounds, we need to set
       the NEXT_FLAG for it */
    if(out_of_range > 0)
        castle_object_btree_key_dim_inc(new_key, offending_dim - 1);

    return new_key;
}

c_vl_bkey_t* castle_object_btree_key_hypercube_next(const c_vl_bkey_t *key,
                                                    const c_vl_bkey_t *start,
                                                    const c_vl_bkey_t *end)
{
    int offending_dim, out_of_range;
    out_of_range = castle_object_btree_key_bounds_check(key, start, end, &offending_dim);
    if (out_of_range)
    {
        if (offending_dim > 0)
            return castle_object_btree_key_skip(key, start, offending_dim, out_of_range);
        else
        {
            BUG_ON(out_of_range < 0);
            return (c_vl_bkey_t *) end;
        }
    }
    else return (c_vl_bkey_t *) key;
}

void castle_object_btree_key_free(c_vl_bkey_t *bkey)
{
    castle_free(bkey);
}
