#include <linux/delay.h>

#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_versions.h"
#include "castle_objects.h"
#include "castle_extent.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define debug_rq(_f, ...)       ((void)0)
#define debug_obj(_f, ...)      ((void)0)
#else
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_rq(_f, _a...)     (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_obj(_f, _a...)    (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static const uint32_t OBJ_TOMBSTONE = ((uint32_t)-1);

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
static c_vl_bkey_t* castle_object_btree_key_construct(c_vl_bkey_t  *k1,
                                                      c_vl_bkey_t  *k2,
                                                      uint32_t      nr_dims_from_k1)
{
    uint32_t key_len, nr_dims;
    uint32_t nr_dims_from_k2;
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
    nr_dims_from_k2 = nr_dims - nr_dims_from_k1;

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
    out_key = castle_zalloc(key_len, GFP_KERNEL);
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

static inline int castle_object_key_dim_compare(char *dim_a, uint32_t dim_a_len, uint32_t dim_a_flags,
                                                char *dim_b, uint32_t dim_b_len, uint32_t dim_b_flags)
{
    int cmp, dim_a_next_flag, dim_b_next_flag;

     /* Lexicographic comparison of the two dims (min length) */
    cmp = memcmp(dim_a, dim_b, ((dim_a_len > dim_b_len) ? dim_b_len : dim_a_len));
    if(cmp)
        return cmp;

    BUG_ON(dim_a_len == PLUS_INFINITY_DIM_LENGTH ||
           dim_b_len == PLUS_INFINITY_DIM_LENGTH);
    BUG_ON((dim_a_len == 0) &&
           !(dim_a_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG) &&
           !(dim_a_flags & KEY_DIMENSION_PLUS_INFINITY_FLAG));
    BUG_ON((dim_b_len == 0) &&
           !(dim_b_flags & KEY_DIMENSION_MINUS_INFINITY_FLAG) &&
           !(dim_b_flags & KEY_DIMENSION_PLUS_INFINITY_FLAG));
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

int castle_object_btree_key_compare(c_vl_bkey_t *key1, c_vl_bkey_t *key2)
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

int castle_object_btree_key_copy(c_vl_bkey_t *old_key,
                                 c_vl_bkey_t *new_key,
                                 uint32_t     buf_len)
{
    int key_length;

    if(!new_key || !old_key)
        return -ENOMEM;

    key_length = old_key->length + 4;

    if (buf_len < key_length)
        return -ENOMEM;

    memcpy(new_key, old_key, key_length);

    return 0;
}

void *castle_object_btree_key_duplicate(c_vl_bkey_t *key)
{
    c_vl_bkey_t *new_key;

    new_key = castle_malloc(key->length + 4, GFP_KERNEL);
    if(!new_key)
        return NULL;

    BUG_ON(castle_object_btree_key_copy(key, new_key, key->length + 4));

    return new_key;
}

void *castle_object_btree_key_next(c_vl_bkey_t *key)
{
    c_vl_bkey_t *new_key;

    /* Duplicate the key first */
    new_key = castle_object_btree_key_duplicate(key);

    /* Increment the least significant dimension */
    castle_object_btree_key_dim_inc(new_key, new_key->nr_dims-1);

    return new_key;
}

/* Checks if the btree key is within the bounds imposed by start/end object keys.
   Returns 1 if the most significant dimension is greater than the end, -1 if it is
   less then start, or 0 if the key is within bounds. Optionally, the function can
   be queried about which dimension offeneded */
static int castle_object_btree_key_bounds_check(c_vl_bkey_t *key,
                                                c_vl_bkey_t *start,
                                                c_vl_bkey_t *end,
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
        char *key_dim, *start_dim, *end_dim;
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

static c_vl_bkey_t* castle_object_btree_key_skip(c_vl_bkey_t *old_key,
                                                 c_vl_bkey_t *start,
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

void castle_object_bkey_free(c_vl_bkey_t *bkey)
{
    castle_free(bkey);
}

/**********************************************************************************************/
/* Iterator(s) */

static void castle_objects_rq_iter_register_cb(castle_object_iterator_t *iter,
                                               castle_iterator_end_io_t cb,
                                               void *data)
{
    iter->data = data;
    iter->end_io = cb;
}

static void castle_objects_rq_iter_next(castle_object_iterator_t *iter,
                                        void **k,
                                        c_ver_t *v,
                                        c_val_tup_t *cvt)
{
    BUG_ON(!iter->cached);
    if(k)   *k   = iter->cached_k;
    if(v)   *v   = iter->cached_v;
    if(cvt) *cvt = iter->cached_cvt;
    iter->cached = 0;
}

static void castle_objects_rq_iter_next_key_free(castle_object_iterator_t *iter)
{
    if(iter->last_next_key)
        castle_object_bkey_free(iter->last_next_key);
    iter->last_next_key = NULL;
}

static int _castle_objects_rq_iter_prep_next(castle_object_iterator_t *iter,
                                             int sync_call)
{
    void *k;
    c_ver_t v;
    c_val_tup_t cvt;
    int offending_dim=0, out_of_range;

    while(1)
    {
        if(iter->cached || iter->completed)
            return 1;
        if(!sync_call && !castle_da_rq_iter.prep_next(&iter->da_rq_iter))
            return 0;
        /* Nothing cached, check if da_rq_iter has anything */
        if(!castle_da_rq_iter.has_next(&iter->da_rq_iter))
            return 1;

        /* Nothing cached, but there is something in the da_rq_iter.
           Check if that's within the rq hypercube */
        castle_da_rq_iter.next(&iter->da_rq_iter, &k, &v, &cvt);
        out_of_range = castle_object_btree_key_bounds_check(k,
                                                            iter->start_key,
                                                            iter->end_key,
                                                            &offending_dim);
#ifdef DEBUG
        debug("Got the following key from da_rq iterator. Is in range: %d, offending_dim=%d\n",
                out_of_range, offending_dim);
        vl_bkey_print(k);
#endif
        if(out_of_range)
        {
            c_vl_bkey_t *next_key;

            if (offending_dim == 0)
            {
                iter->completed = 1;
                return 1;
            }

            /* We are outside of the rq hypercube, find next intersection point
               and skip to that */
            next_key = castle_object_btree_key_skip(k,
                                                    iter->start_key,
                                                    offending_dim,
                                                    out_of_range);
            /* Save the key, to be freed the next time around the loop/on cancel */
            castle_objects_rq_iter_next_key_free(iter);
            iter->last_next_key = next_key;

#ifdef DEBUG
            debug("Skipping to:\n");
            vl_bkey_print(next_key);
#endif
            castle_da_rq_iter.skip(&iter->da_rq_iter, next_key);
        }
        else
        {
            /* Found something to cache, save */
            iter->cached_k = k;
            iter->cached_v = v;
            iter->cached_cvt = cvt;
            iter->cached = 1;
        }
    }

    /* We should never get here */
    BUG();
}

static int castle_objects_rq_iter_prep_next(castle_object_iterator_t *iter)
{
    return _castle_objects_rq_iter_prep_next(iter, 0);
}

static void castle_objects_rq_iter_end_io(void *da_iter,
                                          int err)
{
    castle_object_iterator_t *iter = ((c_da_rq_iter_t *)da_iter)->private;

    if (castle_objects_rq_iter_prep_next(iter))
        iter->end_io(iter, 0);
}

static int castle_objects_rq_iter_has_next(castle_object_iterator_t *iter)
{
    BUG_ON(!_castle_objects_rq_iter_prep_next(iter, 1));

    debug_obj("%s:%p\n", __FUNCTION__, iter);
    if(iter->cached)
        return 1;

    /* End of iterator. */
    if(iter->completed)
        return 0;

    /* Nothing cached, check if da_rq_iter has anything */
    BUG_ON(castle_da_rq_iter.has_next(&iter->da_rq_iter));
    debug_obj("%s:%p - reschedule\n", __FUNCTION__, iter);

    return 0;
}

static void castle_objects_rq_iter_cancel(castle_object_iterator_t *iter)
{
    /* Cancel da_rq_iter if it's error free */
    if(!iter->da_rq_iter.err)
        castle_da_rq_iter.cancel(&iter->da_rq_iter);
    castle_objects_rq_iter_next_key_free(iter);
}

static void castle_objects_rq_iter_init(castle_object_iterator_t *iter)
{
    BUG_ON(!iter->start_key || !iter->end_key);

    iter->err = 0;
    iter->end_io = NULL;
    iter->cached = 0;
    /* Set the error on da_rq_iter, which will get cleared by the init,
       but will prevent castle_object_rq_iter_cancel from cancelling the
       da_rq_iter unnecessarily */
    iter->da_rq_iter.err = -EINVAL;
    iter->last_next_key = NULL;
    iter->completed     = 0;
#ifdef DEBUG
    castle_printk(LOG_DEBUG, "====================== RQ start keys =======================\n");
    vl_okey_print(iter->start_okey);
    vl_bkey_print(iter->start_bkey);
    castle_printk(LOG_DEBUG, "======================= RQ end keys ========================\n");
    vl_okey_print(iter->end_okey);
    vl_bkey_print(iter->end_bkey);
    castle_printk(LOG_DEBUG, "============================================================\n");
#endif

    castle_da_rq_iter_init(&iter->da_rq_iter,
                            iter->version,
                            iter->da_id,
                            iter->start_key,
                            iter->end_key);
    castle_da_rq_iter.register_cb(&iter->da_rq_iter,
                                  castle_objects_rq_iter_end_io,
                                  (void *)iter);
    if(iter->da_rq_iter.err)
    {
        iter->err = iter->da_rq_iter.err;
        return;
    }
}

struct castle_iterator_type castle_objects_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_objects_rq_iter_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_objects_rq_iter_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_objects_rq_iter_has_next,
    .next       = (castle_iterator_next_t)       castle_objects_rq_iter_next,
    .skip       = NULL,
    .cancel     = (castle_iterator_cancel_t)     castle_objects_rq_iter_cancel,
};

/**********************************************************************************************/
/* High level interface functions */
/**********************************************************************************************/

#define OBJ_IO_MAX_BUFFER_SIZE      (10)    /* In C_BLK_SIZE blocks */

static c_ext_pos_t  castle_object_write_next_cep(c_ext_pos_t  old_cep,
                                                 uint32_t data_length)
{
    uint32_t data_c2b_length;
    c_ext_pos_t new_data_cep;
    int nr_blocks;

    /* Work out how large buffer to allocate */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1;
    debug("Allocating new buffer of size %d blocks, for data_length=%d\n",
        nr_blocks, data_length);
    new_data_cep.ext_id  = old_cep.ext_id;
    new_data_cep.offset = old_cep.offset + (nr_blocks * C_BLK_SIZE);

    return new_data_cep;
}

static c2_block_t* castle_object_write_buffer_alloc(c_ext_pos_t new_data_cep,
                                                    uint64_t data_length)
{
    uint64_t data_c2b_length;
    c2_block_t *new_data_c2b;
    int nr_blocks;

    /* Work out how large the buffer is */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1;
    new_data_c2b = castle_cache_block_get(new_data_cep, nr_blocks);
#ifdef CASTLE_DEBUG
    write_lock_c2b(new_data_c2b);
    update_c2b(new_data_c2b);
    /* Poison the data block */
    memset(c2b_buffer(new_data_c2b), 0xf4, nr_blocks * C_BLK_SIZE);
    dirty_c2b(new_data_c2b);
    write_unlock_c2b(new_data_c2b);
#endif

    return new_data_c2b;
}

static int castle_object_data_write(struct castle_object_replace *replace)
{
    c2_block_t *data_c2b;
    uint64_t data_c2b_offset, data_c2b_length, data_length, packet_length;
    int c2b_locked = 0;

    /* Work out how much data we've got, and how far we've got so far */
    data_c2b = replace->data_c2b;
    data_c2b_offset = replace->data_c2b_offset;
    data_length = replace->data_length;

    debug("Data write. replace=%p, data_c2b=%p, data_c2b_offset=%d, data_length=%d\n",
        replace, data_c2b, data_c2b_offset, data_length);
    data_c2b_length = data_c2b->nr_pages * C_BLK_SIZE;
    packet_length = replace->data_length_get(replace);

    debug("Packet length=%d, data_length=%d\n", packet_length, data_length);

    if (((int64_t)packet_length < 0) || (packet_length > replace->value_len))
    {
        castle_printk(LOG_ERROR, "Unexpected Packet length=%llu, data_length=%llu\n",
                packet_length, data_length);
        BUG();
    }

    do {
        char *data_c2b_buffer;
        int copy_length;
        int last_copy;

        BUG_ON(data_c2b_offset >= data_c2b_length);
        data_c2b_buffer = (char *)c2b_buffer(data_c2b) + data_c2b_offset;
        copy_length = data_c2b_length - data_c2b_offset >= packet_length ?
                                           packet_length :
                                           data_c2b_length - data_c2b_offset;
        debug("Could copy %d bytes.\n", copy_length);
        last_copy = 0;
        if(copy_length >= data_length)
        {
            debug("data_length=%d is smaller than copy_length=%d, resetting copy_length.\n",
                    data_length, copy_length);
            last_copy = 1;
            copy_length = data_length;
        }
        if (copy_length < 0 || copy_length > (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE))
        {
            castle_printk(LOG_ERROR, "Unexpected copy_length %d\n", copy_length);
            BUG();
        }

        write_lock_c2b(data_c2b);
        update_c2b(data_c2b);
        c2b_locked = 1;

        replace->data_copy(replace,
                          data_c2b_buffer,
                          copy_length,
                          last_copy ? 0 : 1);

        data_length     -= copy_length;
        data_c2b_offset += copy_length;
        packet_length   -= copy_length;
        debug("Read %d bytes from the packet.\n", copy_length);


        /* Allocate a new buffer if there will be more data (either in the current
           packet, or in future packets). */
        if((data_c2b_offset == data_c2b_length) && (data_length > 0))
        {
            c2_block_t *new_data_c2b;
            c_ext_pos_t new_data_cep;
            debug("Run out of buffer space, allocating a new one.\n");
            new_data_cep = castle_object_write_next_cep(data_c2b->cep, data_c2b_length);
            if (EXT_POS_COMP(new_data_cep, data_c2b->cep) <= 0)
            {
                castle_printk(LOG_ERROR, "Unexpected change in CEP while copy"cep_fmt_str
                        cep_fmt_str_nl, cep2str(data_c2b->cep), cep2str(new_data_cep));
                BUG();
            }
            new_data_c2b = castle_object_write_buffer_alloc(new_data_cep, data_length);
            data_c2b_length = new_data_c2b->nr_pages * C_BLK_SIZE;
            data_c2b_offset = 0;
            /* Release the (old) buffer */
            dirty_c2b(data_c2b);
            write_unlock_c2b(data_c2b);
            put_c2b(data_c2b);
            c2b_locked = 0;
            /* Swap the new buffer in, if one was initialised. */
            data_c2b = new_data_c2b;
        }
    }
    while((packet_length > 0) && (data_length > 0));

    debug("Exiting data_write with data_c2b_offset=%d, data_length=%d, data_c2b=%p\n",
            data_c2b_offset, data_length, data_c2b);

    /* Release the locks on c2b. */
    if (c2b_locked)
    {
        dirty_c2b(data_c2b);
        write_unlock_c2b(data_c2b);
    }

    replace->data_c2b = data_c2b;
    replace->data_c2b_offset = data_c2b_offset;
    replace->data_length = data_length;

    return (data_length == 0);
}

/**
 * Frees up the large object specified by the CVT provided to this function.
 * It deals with accounting, large object refcounting and extent freeing (the last two
 * indirectly through the DA code).
 */
static void castle_object_replace_large_object_free(struct castle_component_tree *ct,
                                                    c_val_tup_t cvt)
{
    uint64_t chk_cnt;

    BUG_ON(!CVT_LARGE_OBJECT(cvt));
    /* Update the large object chunk count on the tree */
    chk_cnt = castle_extent_size_get(cvt.cep.ext_id);
    atomic64_sub(chk_cnt, &ct->large_ext_chk_cnt);
    debug("Freeing Large Object of size - %u\n", chk_cnt);
    castle_ct_large_obj_remove(cvt.cep.ext_id,
                               &ct->large_objs,
                               &ct->lo_mutex);
}

/**
 * Wraps up object replace operation after either:
 * - btree insertion was completed
 * - there was an error allocating space for the value/btree
 * - the replace was cancelled
 *
 * Specifically this function is responsible for storing the last key (if that was requested),
 * freeing the btree key structure, freeing up large object extents on errors, freeing up the
 * BIO structure and releasing the reference on CT.
 *
 * It calls back to the user, unless the replace operation was cancelled by the user (in which
 * case it already knows).
 */
static void castle_object_replace_complete(struct castle_bio_vec *c_bvec,
                                           int err,
                                           c_val_tup_t cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    c_bio_t *c_bio = c_bvec->c_bio;
    struct castle_component_tree *ct = c_bvec->tree;
    int cancelled;

    /* This function is used to cleanup when cancelling a request, with err set to -EPIPE. */
    cancelled = (err == -EPIPE);

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);
    BUG_ON(replace->data_c2b);
    BUG_ON(memcmp(&replace->cvt, &cvt, sizeof(c_val_tup_t)));
    BUG_ON((c_bvec->cvt_get == NULL) && err);

    debug("castle_object_replace_complete\n");

    if(err && !cancelled)
        castle_printk(LOG_WARN, "Failed to insert into btree.\n");

    /* If there was an error inserting on large objects, free the extent.
       Since there was an error, the object hasn't been threaded onto large object list yet.
       There is no need to remove it from there, or to change any accounting. */
    if(err && CVT_LARGE_OBJECT(cvt))
        castle_extent_free(cvt.cep.ext_id);

    /* Reserve kmalloced memory for inline objects. */
    if(CVT_INLINE(cvt))
        castle_free(cvt.val);

    /* Unreserve any space we may still hold in the CT. Drop the CT ref. */
    if (ct)
    {
        castle_double_array_unreserve(c_bvec);
        castle_ct_put(ct, 1);
    }
    BUG_ON(atomic_read(&c_bvec->reserv_nodes) != 0);

    /* Free the bio. */
    castle_utils_bio_free(c_bio);

    /* Tell the client everything is finished. */
    if(!cancelled)
        replace->complete(replace, err);
}

/**
 * Wrapper for @see castle_object_replace_complete(), called after
 * @see castle_double_array_submit(), responsible for deregistering BIOs from the
 * internal debugger.
 */
static void castle_object_da_replace_complete(struct castle_bio_vec *c_bvec,
                                              int err,
                                              c_val_tup_t cvt)
{
    /* Deregister the BIO. */
    castle_debug_bio_deregister(c_bvec->c_bio);
    /* Call the actual complete function. */
    castle_object_replace_complete(c_bvec, err, cvt);
}

/**
 * Schedules the DA key insertion.
 */
static void castle_object_replace_key_insert(struct castle_object_replace *replace)
{
    c_bvec_t *c_bvec = replace->c_bvec;

    FAULT(REPLACE_FAULT);

    /* Register with the debugger. */
    castle_debug_bio_register(c_bvec->c_bio, c_bvec->c_bio->attachment->version, 1);
    /* Set the callback. */
    c_bvec->submit_complete = castle_object_da_replace_complete;
    /* Submit to the DA. */
    BUG_ON(replace->data_c2b);
    castle_double_array_submit(c_bvec);
}

int castle_object_replace_continue(struct castle_object_replace *replace)
{
    int copy_end;

    FAULT(REPLACE_FAULT);

    debug("Replace continue.\n");
    copy_end = castle_object_data_write(replace);
    if(copy_end)
    {
        c2_block_t *data_c2b = replace->data_c2b;
        uint32_t data_length = replace->data_length;

        BUG_ON(data_length != 0);
        put_c2b(data_c2b);
        replace->data_c2b = NULL;

        /* Finished writing the data out, insert the key into the btree. */
        castle_object_replace_key_insert(replace);
        return 0;
    }

    /* If the data writeout isn't finished, notify the client. */
    replace->replace_continue(replace);

    return 0;
}

int castle_object_replace_cancel(struct castle_object_replace *replace)
{
    debug("Replace cancel.\n");

    /* Release the data c2b. */
    put_c2b(replace->data_c2b);
    replace->data_c2b = NULL;

    /* Btree reservation is going to be released by replace_complete().
       No need to release medium object extent, because we allocated space from it
      (haven't used it, but its too late to free it). */

    /* The rest of the cleanup will be done by: */
    castle_object_replace_complete(replace->c_bvec, -EPIPE, replace->cvt);

    return 0;
}

/**
 * Start up an on disk (medium/large) object replace.
 *
 * It initialises the c_bvec->data_c2b, and calls the functions handling data write.
 * If all the data is already available, it will clean up the data_c2b too (release the c2b
 * reference, and set the field to NULL).
 */
static void castle_object_replace_on_disk_start(struct castle_object_replace *replace)
{
    c2_block_t *c2b;
    c_val_tup_t cvt;

    cvt = replace->cvt;
    BUG_ON(!CVT_ONDISK(cvt));
    BUG_ON(replace->value_len != cvt.length);

    /* Init the c2b for data writeout. */
    c2b = castle_object_write_buffer_alloc(cvt.cep, cvt.length);
    replace->data_c2b = c2b;
    replace->data_c2b_offset = 0;
    replace->data_length = cvt.length;

    if (replace->data_length_get(replace) > 0)
    {
        int complete_write;

        complete_write = castle_object_data_write(replace);
        BUG_ON(complete_write && (replace->data_length != 0));
        if(complete_write)
        {
            put_c2b(replace->data_c2b);
            replace->data_c2b = NULL;
        }
    }
}

/**
 * Returns the CVT for the object being inserted and does the appropriate bookkeeping
 * (by registering large objects with the DA code, and updating the chunk counter on
 * the component tree). Also, it frees up and cleans up after large objects that used
 * to be stored under the same key.
 */
static int castle_object_replace_cvt_get(c_bvec_t    *c_bvec,
                                         c_val_tup_t prev_cvt,
                                         c_val_tup_t *cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    uint64_t nr_chunks;

    /* We should be handling a write (possibly a tombstone write). */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);
    /* Some sanity checks on the prev_cvt. */
    BUG_ON(!CVT_INVALID(prev_cvt) && !CVT_LEAF_VAL(prev_cvt));
    BUG_ON(CVT_TOMB_STONE(prev_cvt) && (prev_cvt.length != 0));

    /* Bookkeeping for large objects (about to be inserted into the tree). */
    if(CVT_LARGE_OBJECT(replace->cvt))
    {
        if (castle_ct_large_obj_add(replace->cvt.cep.ext_id,
                                    replace->value_len,
                                    &c_bvec->tree->large_objs,
                                    &c_bvec->tree->lo_mutex))
        {
            castle_printk(LOG_WARN, "Failed to intialize large object\n");
            return -ENOMEM;
        }

        /* Update the large object chunk count on the tree */
        nr_chunks = (replace->value_len - 1) / C_CHK_SIZE + 1;
        atomic64_add(nr_chunks, &c_bvec->tree->large_ext_chk_cnt);
    }

    if(CVT_COUNTER_ADD(replace->cvt))
    {
        if ( (CVT_COUNTER_ADD(prev_cvt)) || (CVT_COUNTER_SET(prev_cvt)) )
        {
            int64_t prev_x, new_x, accum_x;
            castle_printk(LOG_DEVEL, "%s::reducing COUNTER_ADD.\n", __FUNCTION__);

            //TODO@tr this is horrible, fix it! (and allow 512b counter values)
            memcpy(&prev_x, prev_cvt.val, sizeof(prev_x));
            memcpy(&new_x, replace->cvt.val, sizeof(new_x));

            castle_printk(LOG_DEVEL, "%s::old x = %llx, new x = %llx.\n", __FUNCTION__, prev_x, new_x);
            accum_x = prev_x + new_x;
            memcpy(replace->cvt.val, &accum_x, sizeof(accum_x));
            castle_printk(LOG_DEVEL, "%s::resulting x = %llx.\n", __FUNCTION__, (uint64_t)*(replace->cvt.val));

            if (CVT_COUNTER_SET(prev_cvt))
            {
                castle_printk(LOG_DEVEL, "%s::converting to COUNTER_SET.\n", __FUNCTION__);
                CVT_COUNTER_SET_SET(replace->cvt);
            }
        }
    }

    /* Free the space occupied by large object, if prev_cvt points to a large object. */
    if(CVT_LARGE_OBJECT(prev_cvt))
        castle_object_replace_large_object_free(c_bvec->tree, prev_cvt);

    /* Set cvt_get to NULL, to tell the replace_complete function that cvt_get was done
       successfully */
    c_bvec->cvt_get = NULL;
    /* Finally set the cvt. */
    *cvt = replace->cvt;

    FAULT(REPLACE_FAULT);

    return 0;
}

/**
 * Reserves memory for inline objects, extent space in medium object extent, or a brand new
 * extent for large objects. It sets the CVT.
 *
 * For inline objects, the data is copied into memory allocated too.
 *
 * This function may fail in variety of ways in which case an appropriate code will be
 * returned, replace->cvt will be set to INVAL_VAL_TUP in such case.
 */
static int castle_object_replace_space_reserve(struct castle_object_replace *replace)
{
    c_bvec_t *c_bvec = replace->c_bvec;
    int tombstone = c_bvec_data_del(c_bvec);
    uint64_t value_len, nr_blocks, nr_chunks;
    c_ext_pos_t cep;
    int counter_type = 0;

    /* save counter flags because replace->cvt is reinitialised here */
    if(CVT_COUNTER_ADD(replace->cvt))
        counter_type=1;
    if(CVT_COUNTER_SET(replace->cvt))
        counter_type=2;

    replace->cvt = INVAL_VAL_TUP;
    /* Deal with tombstones first. */
    if(tombstone)
    {
        CVT_TOMB_STONE_SET(replace->cvt);
        /* No need to allocate any memory/extent space for tombstones. */
        return 0;
    }

    value_len = replace->value_len;
    /* Reserve memory for inline values. */
    if(value_len <= MAX_INLINE_VAL_SIZE)
    {
        void *value;

        /* Allocate memory. */
        value = castle_malloc(value_len, GFP_KERNEL);
        if(!value)
            return -ENOMEM;

        /* Construct the cvt. */
        CVT_INLINE_SET(replace->cvt, value_len, value);
        /* Get the data copied into the cvt. It should all be available in one shot. */
        if(counter_type==1)
            CVT_COUNTER_ADD_SET(replace->cvt);
        if(counter_type==2)
            CVT_COUNTER_SET_SET(replace->cvt);
        BUG_ON(replace->data_length_get(replace) < value_len);
        replace->data_copy(replace, value, value_len, 0 /* not partial */);

        return 0;
    }

    /* Out of line objects. */
    nr_blocks = (value_len - 1) / C_BLK_SIZE + 1;
    nr_chunks = (value_len - 1) / C_CHK_SIZE + 1;
    /* Medium objects. */
    if(value_len <= MEDIUM_OBJECT_LIMIT)
    {
        /* Allocate space in the medium object extent. This has already been preallocated
           therefore the allocation should always succeed. */
        BUG_ON(castle_ext_freespace_get(&c_bvec->tree->data_ext_free,
                                         nr_blocks * C_BLK_SIZE,
                                         1,
                                        &cep) < 0);
        CVT_MEDIUM_OBJECT_SET(replace->cvt, value_len, cep);
        debug("Medium Object in %p, cep: "cep_fmt_str_nl, c_bvec->tree, __cep2str(cvt->cep));

        return 0;
    }

    /* Large objects. */
    memset(&cep, 0, sizeof(c_ext_pos_t));
    cep.ext_id = castle_extent_alloc(DEFAULT_RDA,
                                     c_bvec->tree->da,
                                     EXT_T_LARGE_OBJECT,
                                     nr_chunks, 0,  /* Not in transaction. */
                                     NULL, NULL);

    if(EXT_ID_INVAL(cep.ext_id))
    {
        castle_printk(LOG_WARN, "Failed to allocate space for Large Object.\n");
        return -ENOSPC;
    }
    CVT_LARGE_OBJECT_SET(replace->cvt, value_len, cep);

    return 0;
}

/**
 * Callback used after the request went through the DA throttling, and btree/medium
 * object extent space has been reserved.
 *
 * This function allocates memory/extent space, and starts the write.
 *
 * If the write is completed in one shot it schedules the key insert. If not, it notifies
 * the client and exits.
 */
static void castle_object_replace_queue_complete(struct castle_bio_vec *c_bvec, int err)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    int write_complete;

    /* Handle the error case first. Notify the client, and exit. */
    if(err)
    {
        /* If we failed to queue, there should be no CT set, and no CVT. */
        BUG_ON(c_bvec->tree);
        BUG_ON(!CVT_INVALID(replace->cvt));
        goto err_out;
    }
    /* Otherwise the CT should be set. */
    BUG_ON(!c_bvec->tree);

    /* Reserve space (memory or extent space) to store the value. */
    err = castle_object_replace_space_reserve(replace);
    if(err)
    {
        BUG_ON(!CVT_INVALID(replace->cvt));
        goto err_out;
    }

    /*
     * For on disk objects, kick off the write-out (inline objects/tombstones have already been
     * dealt with by now).
     * If the entire value gets written out (which is trivially true for inline values/tombstones)
     * insert the key into the btree.
     */
    write_complete = 1;
    if(CVT_ONDISK(replace->cvt))
    {
        castle_object_replace_on_disk_start(replace);
        write_complete = (replace->data_length == 0);
    }

    if(write_complete)
        castle_object_replace_key_insert(replace);
    else
        /* If the data writeout isn't finished, notify the client. */
        replace->replace_continue(replace);

    return;

err_out:
    BUG_ON(err == 0);
    /* This cleans everything up, including the CT ref. */
    castle_object_replace_complete(c_bvec, err, replace->cvt);
}

/**
 * Starts object replace.
 * It allocates memory for the BIO and btree key, sets up the requsets, and submits the
 * request to the queue. The request may go straight through and be handled on the
 * current thread, but otherwise will be queued up in the DA, and handled asynchronously later.
 */
int castle_object_replace(struct castle_object_replace *replace,
                          struct castle_attachment *attachment,
                          c_vl_bkey_t *key,
                          int cpu_index,
                          int tombstone)
{
    c_bvec_t *c_bvec = NULL;
    c_bio_t *c_bio = NULL;
    int i, ret;
    int counter_type = 0;

    /* Sanity checks. */
    BUG_ON(!attachment);

    /* save counter flags because replace->cvt is reinitialised here */
    if(CVT_COUNTER_ADD(replace->cvt))
        counter_type=1;
    if(CVT_COUNTER_SET(replace->cvt))
        counter_type=2;

    /*
     * Make sure that the filesystem has been fully initialised before accepting any requsets.
     * @TODO consider moving this check to castle_back_open().
     */
    if(!castle_fs_inited)
        return -ENODEV;

    /* Checks on the key. */
    for (i=0; i<key->nr_dims; i++)
        if(castle_object_btree_key_dim_length(key, i) == 0)
            return -EINVAL;

    /* Create btree key out of the object key. */
    ret = -EINVAL;
    if (!key)
        goto err_out;

    /* Allocate castle bio with a single bvec. */
    ret = -ENOMEM;
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        goto err_out;

    /* Initialise the bio. */
    c_bio->attachment    = attachment;
    c_bio->replace       = replace;
    c_bio->data_dir      = WRITE;
    if(tombstone)
        c_bio->data_dir |= REMOVE;

    /* Initialise the bvec. */
    c_bvec = c_bio->c_bvecs;
    c_bvec->key            = key;
    c_bvec->tree           = NULL;
    c_bvec->cpu_index      = cpu_index;
    c_bvec->cpu            = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->flags          = 0;
    c_bvec->cvt_get        = castle_object_replace_cvt_get;
    c_bvec->queue_complete = castle_object_replace_queue_complete;
    c_bvec->orig_complete  = NULL;
    atomic_set(&c_bvec->reserv_nodes, 0);

    /* Save c_bvec in the replace. */
    replace->c_bvec = c_bvec;
    CVT_INVALID_SET(replace->cvt);
    if(counter_type==1)
        CVT_COUNTER_ADD_SET(replace->cvt);
    if(counter_type==2)
        CVT_COUNTER_SET_SET(replace->cvt);
    replace->data_c2b = NULL;

    /* Queue up in the DA. */
    castle_double_array_queue(c_bvec);

    return 0;

err_out:
    /* Free up allocated memory on errors. */
    if(ret)
    {
        if(c_bio)
            castle_utils_bio_free(c_bio);
    }

    return ret;
}
EXPORT_SYMBOL(castle_object_replace);

void castle_object_slice_get_end_io(void *obj_iter, int err);

int castle_object_iter_start(struct castle_attachment *attachment,
                            c_vl_bkey_t *start_key,
                            c_vl_bkey_t *end_key,
                            castle_object_iterator_t **iter)
{
    castle_object_iterator_t *iterator;
    int i;

    /* Checks on keys. */
    if(start_key->nr_dims != end_key->nr_dims)
    {
        castle_printk(LOG_WARN, "Range query with different # of dimensions.\n");
        return -EINVAL;
    }

    /* Empty dimensions on start_key are allowed only if it is -ve infinity. */
    for (i=0; i<start_key->nr_dims; i++)
        if (castle_object_btree_key_dim_length(start_key, i) == 0 &&
            !(castle_object_btree_key_dim_flags_get(start_key, i) & KEY_DIMENSION_MINUS_INFINITY_FLAG))
            return -EINVAL;

    /* Empty dimensions on end_key are allowed only if it is +ve infinity. */
    for (i=0; i<end_key->nr_dims; i++)
        if (castle_object_btree_key_dim_length(end_key, i) == 0 &&
            !(castle_object_btree_key_dim_flags_get(end_key, i) & KEY_DIMENSION_PLUS_INFINITY_FLAG))
            return -EINVAL;

    iterator = castle_malloc(sizeof(castle_object_iterator_t), GFP_KERNEL);
    if(!iterator)
        return -ENOMEM;

    *iter = iterator;

    /* Initialise the iterator */
    iterator->start_key = start_key;
    iterator->end_key   = end_key;
    iterator->version   = attachment->version;
    iterator->da_id     = castle_version_da_id_get(iterator->version);

    debug_rq("rq_iter_init.\n");
    castle_objects_rq_iter_init(iterator);
    if(iterator->err)
    {
        castle_free(iterator);
        return iterator->err;
    }

    castle_objects_rq_iter_register_cb(iterator, castle_object_slice_get_end_io, NULL);

    debug_rq("rq_iter_init done.\n");

    return 0;
}

int castle_object_iter_next(castle_object_iterator_t *iterator,
                            castle_object_iter_next_available_t callback,
                            void *data)
{
    c_vl_bkey_t *k, *key = NULL;
    c_val_tup_t val;
    c_ver_t v;
    int has_response;
    int continue_iterator = 1;

    iterator->next_available = callback;
    iterator->next_available_data = data;

    while (continue_iterator)
    {
        has_response = 0;
        while (!has_response && castle_objects_rq_iter.prep_next(iterator))
        {
            if (!castle_objects_rq_iter.has_next(iterator))
            {
                debug_rq("Iterator at end.\n");
                key = NULL;
                has_response = 1;
            }
            else
            {
                debug_rq("Getting an entry for the range query.\n");
                castle_objects_rq_iter.next(iterator,
                                            (void **)&k,
                                            &v,
                                            &val);
                debug_rq("Got an entry for the range query.\n");
                if (!CVT_TOMB_STONE(val))
                {
                    has_response = 1;

                    key = k;
                    if (!key)
                    {
                        callback(iterator, NULL, NULL, -ENOMEM, iterator->next_available_data);
                        return 0;
                    }
                }
            }
        }

        if (!has_response)
        {
            /* we're waiting for the iterator */
            debug_rq("Waiting for next available.\n");
            return 0;
        }

        if (!key)
        {
            debug_rq("Calling next available callback with NULL key.\n");
            continue_iterator = callback(iterator, NULL, NULL, 0, iterator->next_available_data);
        }
        else
        {
            debug_rq("Calling next available callback with key=%p.\n", key);
            continue_iterator = callback(iterator, key, &val, 0, iterator->next_available_data);
        }
        debug_rq("Next available callback gave response %d.\n", continue_iterator);
    }

    return 0;
}

int castle_object_iter_finish(castle_object_iterator_t *iterator)
{
    castle_objects_rq_iter_cancel(iterator);
    debug_rq("Freeing iterators & buffers.\n");
    castle_free(iterator);

    return 0;
}

static void castle_object_next_available(struct work_struct *work)
{
    castle_object_iterator_t *iter = container_of(work, castle_object_iterator_t, work);

    castle_object_iter_next(iter, iter->next_available, iter->next_available_data);
}

void castle_object_slice_get_end_io(void *obj_iter, int err)
{
    castle_object_iterator_t *iter = obj_iter;

    BUG_ON(!castle_objects_rq_iter_prep_next(iter));
    debug_rq("Done async key read: Re-scheduling slice_get()- iterator: %p\n", iter);
    CASTLE_INIT_WORK(&iter->work, castle_object_next_available);
    queue_work(castle_wq, &iter->work);
}

static int castle_object_reference_get(c_bvec_t    *c_bvec,
                                       c_val_tup_t  cvt)
{
    BUG_ON(c_bvec_data_dir(c_bvec) != READ);

    if (CVT_LARGE_OBJECT(cvt))
        BUG_ON(!castle_extent_get(cvt.cep.ext_id));

    return 0;
}

static void castle_object_reference_release(c_val_tup_t cvt)
{
    if (CVT_LARGE_OBJECT(cvt))
        castle_extent_put(cvt.cep.ext_id);
}

void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_object_get *get,
                                c_ext_pos_t  data_cep,
                                uint64_t data_length);
void __castle_object_get_complete(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_object_get *get = c_bvec->c_bio->get;
    c2_block_t *c2b = get->data_c2b;
    c_ext_pos_t cep;
    uint64_t data_c2b_length = get->data_c2b_length;
    uint64_t data_length = get->data_length;
    int first = get->first;
    struct castle_component_tree *ct = get->ct;
    int last, dont_want_more;
    c_val_tup_t cvt = get->cvt;

    /* Deal with error case first */
    if(!c2b_uptodate(c2b))
    {
        debug("Not up to date.\n");
        if(first)
            get->reply_start(get, -EIO, 0, NULL, 0);
        else
            get->reply_continue(get, -EIO, NULL, 0, 1 /* last */);
        goto out;
    }

    /* If data_length is zero, it means we are supposed to finish this get call */
    last = (data_length == 0);
    debug("Last=%d\n", last);
    read_lock_c2b(c2b);
    if(first)
        dont_want_more = get->reply_start(get,
                                          0,
                                          data_c2b_length + data_length,
                                          c2b_buffer(c2b),
                                          data_c2b_length);
    else
        dont_want_more = get->reply_continue(get,
                                             0,
                                             c2b_buffer(c2b),
                                             data_c2b_length,
                                             last);
    read_unlock_c2b(c2b);

    if(last || dont_want_more)
        goto out;

    BUG_ON(data_c2b_length != OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE);
    cep.ext_id = c2b->cep.ext_id;
    cep.offset = c2b->cep.offset + (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE);
    debug("Continuing for cep="cep_fmt_str_nl, cep2str(cep));

    /* @TODO: how much of this is a no-op from above? */
    get->data_c2b        = c2b;
    get->data_c2b_length = data_c2b_length;
    get->data_length     = data_length;
    get->first           = 0; /* not first any more */

    castle_object_get_continue(c_bvec,
                               get,
                               cep,
                               data_length);
    return;

out:
    debug("Finishing with get %p, putting c2b->cep="cep_fmt_str_nl,
        get, cep2str(c2b->cep));
    put_c2b(c2b);

    castle_ct_put(ct, 0);
    castle_object_reference_release(cvt);
    castle_utils_bio_free(c_bvec->c_bio);
}

void castle_object_get_io_end(c2_block_t *c2b)
{
    c_bvec_t *c_bvec = c2b->private;

#ifdef CASTLE_DEBUG
    struct castle_object_get *get = c_bvec->c_bio->get;
    c2_block_t *data_c2b = get->data_c2b;
    BUG_ON(c2b != data_c2b);
#endif
    write_unlock_c2b(c2b);
    /* @TODO: io error handling. */
    debug("IO end for cep "cep_fmt_str_nl, cep2str(c2b->cep));
    CASTLE_INIT_WORK(&c_bvec->work, __castle_object_get_complete);
    queue_work(castle_wq, &c_bvec->work);
}

void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_object_get *get,
                                c_ext_pos_t  data_cep,
                                uint64_t data_length)
{
    c2_block_t *c2b;
    int nr_blocks;

    c2_block_t *old_c2b = get->data_c2b;
    uint64_t data_c2b_length = get->data_c2b_length;
    uint64_t old_data_length = get->data_length;

    BUG_ON(c_bvec->c_bio->get != get);

    debug("get_continue for get=%p, data_c2b_length=%d, "
           "old_data_length=%d, data_length=%d, first=%d\n",
        get, data_c2b_length, old_data_length, data_length, get->first);
    BUG_ON(data_length != old_data_length);
    /* If old_c2b exists, we must have completed a MAX chunk */
    BUG_ON( old_c2b &&
           (old_c2b->cep.ext_id != data_cep.ext_id) &&
           (old_c2b->cep.offset + (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE) != data_cep.offset));

    /* Work out if we can read the (remaining part of the) object in full,
       or if we are going to be reading just a part of it */
    if(data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE)
    {
        nr_blocks = OBJ_IO_MAX_BUFFER_SIZE;
        data_c2b_length = nr_blocks * C_BLK_SIZE;
        debug("Too many blocks required, reducing to %d\n", nr_blocks);
    } else
    {
        nr_blocks = (data_length - 1) / C_BLK_SIZE + 1;
        data_c2b_length = data_length;
    }
    debug("Nr blocks this time around: %d\n", nr_blocks);
    debug("data_c2b_length=%d, data_length=%d\n", data_c2b_length, data_length);
    data_length -= data_c2b_length;

    debug("Locking cep "cep_fmt_str_nl, cep2str(data_cep));
    c2b = castle_cache_block_get(data_cep, nr_blocks);
    write_lock_c2b(c2b);

    get->data_c2b        = c2b;
    get->data_c2b_length = data_c2b_length;
    get->data_length     = data_length;

    /* Unlock the old c2b if we had one */
    if(old_c2b)
    {
        debug("Putting old_cep "cep_fmt_str_nl, cep2str(old_c2b->cep));
        put_c2b(old_c2b);
    }

    debug("c2b uptodate: %d\n", c2b_uptodate(c2b));
    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        c2b->private = c_bvec;
        c2b->end_io = castle_object_get_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    } else
    {
        write_unlock_c2b(c2b);
        CASTLE_INIT_WORK(&c_bvec->work, __castle_object_get_complete);
        queue_work(castle_wq, &c_bvec->work);
    }
}

void castle_object_get_complete(struct castle_bio_vec *c_bvec,
                                int err,
                                c_val_tup_t cvt)
{
    //struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    struct castle_object_get *get = c_bvec->c_bio->get;
    c_bio_t *c_bio = c_bvec->c_bio;

    debug("Returned from btree walk with value of type 0x%x and length %llu\n",
          cvt.type, cvt.length);
    get->ct = c_bvec->tree;
    get->cvt = cvt;
    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != READ);
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Deal with error case, or non-existant value. */
    if(err || CVT_INVALID(cvt) || CVT_TOMB_STONE(cvt))
    {
        debug("Error, invalid or tombstone.\n");
        /* Dont have any object returned, no need to release reference of object. */
        /* Release reference of Component Tree. */
        if(get->ct)
            castle_ct_put(get->ct, 0);
        CVT_INVALID_SET(get->cvt);
        get->reply_start(get, err, 0, NULL, 0);
        castle_utils_bio_free(c_bvec->c_bio);
        return;
    }
    BUG_ON(!get->ct);

    /* Next, handle inline values, since we already have them in memory */
    if(CVT_INLINE(cvt))
    {
        debug("Inline.\n");
        /* Release reference of Component Tree. */
        castle_ct_put(get->ct, 0);
        get->reply_start(get, 0, cvt.length, cvt.val, cvt.length);
        castle_free(cvt.val);
        castle_utils_bio_free(c_bvec->c_bio);

        FAULT(GET_FAULT);
        return;
    }

    BUG_ON(CVT_MEDIUM_OBJECT(cvt) &&
            cvt.cep.ext_id != c_bvec->tree->data_ext_free.ext_id);

    debug("Out of line.\n");
    /* Finally, out of line values */
    BUG_ON(!CVT_ONDISK(cvt));
    /* Init the variables stored in the call correctly, so that _continue() doesn't
       get confused */

    get->data_c2b        = NULL;
    get->data_c2b_length = 0;
    get->data_length     = cvt.length;
    get->first           = 1; /* first */

    castle_object_get_continue(c_bvec, get, cvt.cep, cvt.length);

    FAULT(GET_FAULT);
}

/**
 * Lookup and return an object from btree.
 *
 * @param cpu_index CPU index (to determine correct T0 CT)
 *
 * @also castle_back_get()
 */
int castle_object_get(struct castle_object_get *get,
                      struct castle_attachment *attachment,
                      c_vl_bkey_t *key,
                      int cpu_index)
{
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    int i;

    debug("castle_object_get get=%p\n", get);

    if(!castle_fs_inited)
        return -ENODEV;

    if (!key)
        return -EINVAL;

    /* Checks on the key. */
    for (i=0; i<key->nr_dims; i++)
        if(castle_object_btree_key_dim_length(key, i) == 0)
            return -EINVAL;

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM; // @TODO leaking btree_key?
    BUG_ON(!attachment);
    c_bio->attachment    = attachment;
    c_bio->get           = get;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs;
    c_bvec->key             = key;
    c_bvec->cpu_index       = cpu_index;
    c_bvec->cpu             = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->ref_get         = castle_object_reference_get;
    c_bvec->submit_complete = castle_object_get_complete;
    c_bvec->orig_complete   = NULL;
    atomic_set(&c_bvec->reserv_nodes, 0);

    /* @TODO: add bios to the debugger! */
    castle_double_array_submit(c_bvec);

    return 0;
}
EXPORT_SYMBOL(castle_object_get);

void castle_object_pull_finish(struct castle_object_pull *pull)
{
    castle_ct_put(pull->ct, 0);
    castle_object_reference_release(pull->cvt);
}


void __castle_object_chunk_pull_complete(struct work_struct *work)
{
    struct castle_object_pull *pull = container_of(work, struct castle_object_pull, work);
    uint32_t to_copy = pull->to_copy;

    BUG_ON(!pull->buf);

    read_lock_c2b(pull->curr_c2b);
    memcpy(pull->buf, c2b_buffer(pull->curr_c2b), to_copy);

    pull->offset += to_copy;
    pull->remaining -= to_copy;

    debug("Unlocking old_cdb (0x%x, 0x%x)\n", pull->curr_c2b->cdb.disk, pull->curr_c2b->cdb.block);
    read_unlock_c2b(pull->curr_c2b);
    put_c2b(pull->curr_c2b);

    pull->curr_c2b = NULL;
    pull->buf = NULL;
    pull->to_copy = 0;

    pull->pull_continue(pull, 0, to_copy, pull->remaining == 0);
}

void castle_object_chunk_pull_io_end(c2_block_t *c2b)
{
    struct castle_object_pull *pull = c2b->private;

    debug("IO end for cdb, c2b->nr_pages=%d, cep" cep_fmt_str_nl, c2b->nr_pages, cep2str(c2b->cep));
    write_unlock_c2b(pull->curr_c2b);


    /* @TODO deal with not up to date - get error and pass it on? */

    CASTLE_INIT_WORK(&pull->work, __castle_object_chunk_pull_complete);
    queue_work(castle_wq, &pull->work);
}

void castle_object_chunk_pull(struct castle_object_pull *pull, void *buf, size_t buf_len)
{
    /* @TODO currently relies on objects being page aligned. */
    c_ext_pos_t cep;

    if(!castle_fs_inited)
        return;

    BUG_ON(buf_len % PAGE_SIZE);
    BUG_ON(pull->curr_c2b != NULL);
    BUG_ON(pull->buf != NULL);

    pull->to_copy = min(pull->remaining, (uint64_t)buf_len);

    BUG_ON(pull->to_copy == 0);

    if(pull->is_inline)
    {
        /* this is assured since buf_len >= PAGE_SIZE > MAX_INLINE_VAL_SIZE */
        BUG_ON(buf_len < pull->remaining);
        memcpy(buf, pull->inline_val, pull->remaining);
        castle_free(pull->inline_val);
        pull->pull_continue(pull, 0, pull->remaining, 1 /* done */);
        return;
    }

    cep.ext_id = pull->cep.ext_id;
    cep.offset = pull->cep.offset + pull->offset; /* @TODO in bytes or blocks? */

    debug("Locking cdb (0x%x, 0x%x)\n", cep.ext_id, cep.offset);
    pull->curr_c2b = castle_cache_block_get(cep, (pull->to_copy - 1) / PAGE_SIZE + 1);
    castle_cache_advise(pull->curr_c2b->cep, C2_ADV_PREFETCH|C2_ADV_FRWD, -1, -1, 0);
    write_lock_c2b(pull->curr_c2b);

    pull->buf = buf;

    debug("c2b uptodate: %d\n", c2b_uptodate(pull->curr_c2b));
    if(!c2b_uptodate(pull->curr_c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        pull->curr_c2b->private = pull;
        pull->curr_c2b->end_io = castle_object_chunk_pull_io_end;
        BUG_ON(submit_c2b(READ, pull->curr_c2b));
    } else
    {
        write_unlock_c2b(pull->curr_c2b);
        __castle_object_chunk_pull_complete(&pull->work);
    }
}
EXPORT_SYMBOL(castle_object_chunk_pull);

static void castle_object_pull_continue(struct castle_bio_vec *c_bvec, int err, c_val_tup_t cvt)
{
    struct castle_object_pull *pull = c_bvec->c_bio->pull;

    pull->ct = c_bvec->tree;
    pull->cvt = cvt;
    castle_utils_bio_free(c_bvec->c_bio);

    if(err || CVT_INVALID(cvt) || CVT_TOMB_STONE(cvt))
    {
        debug("Error, invalid or tombstone.\n");

        if (err)
            castle_ct_put(pull->ct, 0);
        CVT_INVALID_SET(pull->cvt);
        pull->pull_continue(pull, err, 0, 1 /* done */);
        return;
    }

    if(CVT_INLINE(cvt))
    {
        pull->is_inline = 1;
        pull->inline_val = cvt.val;
    }
    else
    {
        pull->is_inline = 0;
        pull->cep = cvt.cep;
    }

    pull->offset = 0;
    pull->curr_c2b = NULL;
    pull->buf = NULL;
    pull->remaining = cvt.length;
    pull->pull_continue(pull, err, cvt.length, 0 /* not done yet */);
}

int castle_object_pull(struct castle_object_pull *pull,
                       struct castle_attachment *attachment,
                       c_vl_bkey_t *key,
                       int cpu_index)
{
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    int i;

    debug("castle_object_pull pull=%p\n", pull);

    if(!castle_fs_inited)
        return -ENODEV;

    if (!key)
        return -EINVAL;

    /* Checks on the key. */
    for (i=0; i<key->nr_dims; i++)
        if(castle_object_btree_key_dim_length(key, i) == 0)
            return -EINVAL;

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM; /* @TODO leaking btree_key? */
    BUG_ON(!attachment);
    c_bio->attachment    = attachment;
    c_bio->pull          = pull;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs;
    c_bvec->key             = key;
    c_bvec->cpu_index       = cpu_index;
    c_bvec->cpu             = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->ref_get         = castle_object_reference_get;
    c_bvec->submit_complete = castle_object_pull_continue;
    c_bvec->orig_complete   = NULL;
    atomic_set(&c_bvec->reserv_nodes, 0);

    /* @TODO: add bios to the debugger! */
    castle_double_array_submit(c_bvec);

    return 0;
}
EXPORT_SYMBOL(castle_object_pull);
