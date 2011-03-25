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
#define debug(_f, _a...)        (castle_printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_rq(_f, _a...)     (castle_printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_obj(_f, _a...)    (castle_printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

   
static const uint32_t OBJ_TOMBSTONE = ((uint32_t)-1);

#define KEY_DIMENSION_NEXT_FLAG             (1 << 0)
#define KEY_DIMENSION_MINUS_INFINITY_FLAG   (1 << 1)
#define KEY_DIMENSION_PLUS_INFINITY_FLAG    (1 << 2)
#define KEY_DIMENSION_UNUSED3_FLAG          (1 << 3)
#define KEY_DIMENSION_UNUSED4_FLAG          (1 << 4)
#define KEY_DIMENSION_UNUSED5_FLAG          (1 << 5)
#define KEY_DIMENSION_UNUSED6_FLAG          (1 << 6)
#define KEY_DIMENSION_UNUSED7_FLAG          (1 << 7)
#define KEY_DIMENSION_FLAGS_SHIFT           (8)
#define KEY_DIMENSION_FLAGS_MASK           ((1 << KEY_DIMENSION_FLAGS_SHIFT) - 1) 
#define KEY_DIMENSION_FLAGS(_dim_head)      ((_dim_head) &  KEY_DIMENSION_FLAGS_MASK)
#define KEY_DIMENSION_OFFSET(_dim_head)     ((_dim_head) >> KEY_DIMENSION_FLAGS_SHIFT)
#define KEY_DIMENSION_HEADER(_off, _flags)  (((_off)  << KEY_DIMENSION_FLAGS_SHIFT) |     \
                                             ((_flags) & KEY_DIMENSION_FLAGS_MASK))



static inline uint32_t castle_object_btree_key_dim_length(c_vl_bkey_t *key, int dim)
{
    uint32_t end_offset;

    end_offset = (dim+1 < key->nr_dims) ? KEY_DIMENSION_OFFSET(key->dim_head[dim+1]) :
                                          key->length + 4;

    return end_offset - KEY_DIMENSION_OFFSET(key->dim_head[dim]);
}

static inline char* castle_object_btree_key_dim_get(c_vl_bkey_t *key, int dim)
{
    return (char *)key + KEY_DIMENSION_OFFSET(key->dim_head[dim]);
}

static inline uint32_t castle_object_btree_key_dim_flags_get(c_vl_bkey_t *key, int dim)
{
    return KEY_DIMENSION_FLAGS(key->dim_head[dim]);
}

/* Constructs btree key, taking dimensions < okey_first_dim from the src_bkey, and
   dimensions >= okey_first_dim from src_okey. */
static c_vl_bkey_t* castle_object_btree_key_construct(c_vl_bkey_t *src_bkey,
                                                      c_vl_okey_t *src_okey,
                                                      int okey_first_dim)
{
    uint32_t key_len, first_okey_offset = 0, payload_offset;
    int i, nr_dims;
    c_vl_bkey_t *btree_key;
    int plus_infinity = 0;

    /* Sanity checks */
    BUG_ON(!src_okey);
    BUG_ON(okey_first_dim > 0 && !src_bkey);
    BUG_ON(okey_first_dim == 0 && src_bkey);
    BUG_ON(src_bkey && src_okey && (src_bkey->nr_dims != src_okey->nr_dims));
    BUG_ON(okey_first_dim >= src_okey->nr_dims);

    nr_dims = src_okey->nr_dims;

    for (i=okey_first_dim; i<nr_dims; i++)
    {
        if (src_okey->dims[i]->length == PLUS_INFINITY_DIM_LENGTH)
        {
            plus_infinity = 1;
            src_okey->dims[i]->length = 0;
            break;
        }
    }
    /* Work the length of the btree key. okey_first_dim > 0, work out how much space the
       dimensions < okey_first_dim take up first. */ 
    if(okey_first_dim > 0)
    {
        /* The length of the header + dimensions < okey_first_dim can be easily worked
           out by looking at the offset for the okey_first_dim in the src_bkey */ 
        first_okey_offset = castle_object_btree_key_dim_get(src_bkey, okey_first_dim) - 
                                (char *)src_bkey;
        key_len = first_okey_offset;
    }
    else
    {
        /* Work out the header size (including the dim_head array) */
        key_len = sizeof(c_vl_bkey_t) + 4 * nr_dims;
    }

    /* Add the size of dimensions >= okey_first_dim */
    for(i=okey_first_dim; i<nr_dims; i++)
        key_len += src_okey->dims[i]->length;

    if (key_len - 4 > VLBA_TREE_MAX_KEY_SIZE) /* Length doesn't include length field */
        return NULL;
    
    /* Allocate the single-dimensional key */
    btree_key = castle_zalloc(key_len, GFP_KERNEL);
    if(!btree_key)
        return NULL;

    /* Work out where should the first_okey_dim be put. Copy the relevant bits from src_bkey. */
    if(okey_first_dim > 0)
    {
        payload_offset = first_okey_offset;
        memcpy(btree_key, src_bkey, payload_offset);
    }
    else
        payload_offset = sizeof(c_vl_bkey_t) + 4 * nr_dims;

    /* Construct the key. */
    btree_key->length  = key_len - 4; /* Length doesn't include length field */
    btree_key->nr_dims = nr_dims;
    /* Go through all okey dimensions and write them in. */ 
    for(i=okey_first_dim; i<nr_dims; i++)
    {
        BUG_ON(src_okey->dims[i]->length == PLUS_INFINITY_DIM_LENGTH);
        if (src_okey->dims[i]->length == 0)
        {
            if (!plus_infinity)
            {
                btree_key->dim_head[i] = KEY_DIMENSION_HEADER(payload_offset,
                                           KEY_DIMENSION_MINUS_INFINITY_FLAG);
                BUG_ON(!(castle_object_btree_key_dim_flags_get(btree_key, i) & 
                        KEY_DIMENSION_MINUS_INFINITY_FLAG));
            }
            else
            {
                btree_key->dim_head[i] = KEY_DIMENSION_HEADER(payload_offset,
                                           KEY_DIMENSION_PLUS_INFINITY_FLAG);
                BUG_ON(!(castle_object_btree_key_dim_flags_get(btree_key, i) & 
                        KEY_DIMENSION_PLUS_INFINITY_FLAG));
            }
        }
        else
            btree_key->dim_head[i] = KEY_DIMENSION_HEADER(payload_offset, 0);
        memcpy((char *)btree_key + payload_offset, src_okey->dims[i]->key, src_okey->dims[i]->length);
        payload_offset += src_okey->dims[i]->length;
    }
    BUG_ON(payload_offset != key_len);

    return btree_key;
}

/* Converts 'object key' (i.e. multidimensional key) to btree key (single dimensional) */
c_vl_bkey_t* castle_object_key_convert(c_vl_okey_t *obj_key)
{
    if (obj_key->nr_dims == 0)
        return NULL;

    return castle_object_btree_key_construct(NULL, obj_key, 0);
}

c_vl_okey_t* castle_object_btree_key_convert(c_vl_bkey_t *btree_key)
{
    c_vl_okey_t *obj_key;
    c_vl_key_t *dim;
    uint32_t dim_len;
    int i;

    obj_key = castle_zalloc(sizeof(c_vl_okey_t) + sizeof(c_vl_key_t *) * btree_key->nr_dims, GFP_KERNEL);
    if(!obj_key)
        return NULL;

    obj_key->nr_dims = btree_key->nr_dims;
    for(i=0; i<btree_key->nr_dims; i++)
    {
        dim_len = castle_object_btree_key_dim_length(btree_key, i);
        BUG_ON((dim_len == 0) &&
               !(castle_object_btree_key_dim_flags_get(btree_key, i) &
                KEY_DIMENSION_MINUS_INFINITY_FLAG) &&
               !(castle_object_btree_key_dim_flags_get(btree_key, i) &
                KEY_DIMENSION_PLUS_INFINITY_FLAG));
        dim = castle_malloc(dim_len + 4, GFP_KERNEL);
        if(!dim)
        {
        castle_printk("Couldn't malloc dim_len=%d, dim=%p\n", dim_len, dim);
            goto err_out;
        }
        dim->length = dim_len;
        memcpy(dim->key, castle_object_btree_key_dim_get(btree_key, i), dim_len);
        obj_key->dims[i] = dim; 
    }

    return obj_key;

err_out:
castle_printk("Error!\n");
    for(i--; i>0; i--)
        castle_free(obj_key->dims[i]);
    castle_free(obj_key);

    return NULL;
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

void *castle_object_btree_key_duplicate(c_vl_bkey_t *key)
{
    c_vl_bkey_t *new_key;
    uint32_t key_length;

    key_length = key->length + 4;
    new_key = castle_malloc(key_length, GFP_KERNEL);
    if(!new_key)
        return NULL;
    memcpy(new_key, key, key_length);

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
                                                c_vl_okey_t *start,
                                                c_vl_okey_t *end,
                                                int *offending_dim_p)
{
    int dim;

    if((key->nr_dims != start->nr_dims) || (key->nr_dims != end->nr_dims))
    {
        castle_printk("Nonmatching # of dimensions: key=%d, start_key=%d, end_key=%d\n",
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

        key_dim_len   = castle_object_btree_key_dim_length(key, dim);
        key_dim       = castle_object_btree_key_dim_get(key, dim);
        key_dim_flags = castle_object_btree_key_dim_flags_get(key, dim);

        start_dim_len = start->dims[dim]->length;
        start_dim     = start->dims[dim]->key;
        start_dim_flags = ((start_dim_len == 0)?
                           KEY_DIMENSION_MINUS_INFINITY_FLAG:0);

        end_dim_len   = end->dims[dim]->length;
        end_dim       = end->dims[dim]->key;
        end_dim_flags = ((end_dim_len == 0)?
                         KEY_DIMENSION_PLUS_INFINITY_FLAG:0);

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
                                                 c_vl_okey_t *start, 
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

void castle_object_okey_free(c_vl_okey_t *obj_key)
{
    int i;

    for(i=0; i < obj_key->nr_dims; i++)
        castle_free(obj_key->dims[i]);
    castle_free(obj_key);
}

c_vl_okey_t *castle_object_okey_copy(c_vl_okey_t *obj_key)
{
    c_vl_okey_t *copy;
    int i, j;

    copy = castle_malloc(sizeof(c_vl_okey_t) + sizeof(c_vl_key_t *) * obj_key->nr_dims, GFP_KERNEL);
    if (copy == NULL)
        return NULL;

    copy->nr_dims = obj_key->nr_dims;
    for(i=0; i < obj_key->nr_dims; i++)
    {
        copy->dims[i] = castle_malloc(sizeof(c_vl_key_t) + obj_key->dims[i]->length, GFP_KERNEL);
        if (copy->dims[i] == NULL)
            goto err0;
        memcpy(copy->dims[i], obj_key->dims[i], sizeof(c_vl_key_t) + obj_key->dims[i]->length);
    }

    return copy;

err0:
    for (j = 0; j < i; j++)
        castle_free(copy->dims[j]);
    castle_free(copy);
    return NULL;
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
                                        version_t *v, 
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
    version_t v;
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
                                                            iter->start_okey, 
                                                            iter->end_okey,
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
                                                    iter->start_okey, 
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
    if(iter->start_bkey);
        castle_object_bkey_free(iter->start_bkey);
    if(iter->end_bkey);
        castle_object_bkey_free(iter->end_bkey);
    castle_objects_rq_iter_next_key_free(iter);
}

static void castle_objects_rq_iter_init(castle_object_iterator_t *iter)
{
    BUG_ON(!iter->start_okey || !iter->end_okey);

    iter->err = 0;
    iter->end_io = NULL;
    iter->cached = 0;
    /* Set the error on da_rq_iter, which will get cleared by the init,
       but will prevent castle_object_rq_iter_cancel from cancelling the
       da_rq_iter unnecessarily */
    iter->da_rq_iter.err = -EINVAL;
    /* Construct the btree keys for range-query */
    iter->start_bkey    = castle_object_key_convert(iter->start_okey);
    iter->end_bkey      = castle_object_key_convert(iter->end_okey);
    iter->last_next_key = NULL;
    iter->completed     = 0;
#ifdef DEBUG
    castle_printk("====================== RQ start keys =======================\n");
    vl_okey_print(iter->start_okey);
    vl_bkey_print(iter->start_bkey);
    castle_printk("======================= RQ end keys ========================\n");
    vl_okey_print(iter->end_okey);
    vl_bkey_print(iter->end_bkey);
    castle_printk("============================================================\n");
#endif

    /* Check if we managed to initialise the btree keys correctly */
    if(!iter->start_bkey || !iter->end_bkey)
    {
        castle_objects_rq_iter_cancel(iter);
        iter->err = -ENOMEM;
        return;
    }

    castle_da_rq_iter_init(&iter->da_rq_iter, 
                            iter->version, 
                            iter->da_id, 
                            iter->start_bkey, 
                            iter->end_bkey);
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
static int castle_object_replace_cvt_get(c_bvec_t    *c_bvec,
                                         c_val_tup_t  prev_cvt,
                                         c_val_tup_t *cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    int tombstone = c_bvec_data_del(c_bvec); 
    int nr_blocks;
    int prev_large_ext_chk_cnt;

    /* We should be handling a write (possibly a tombstone write). */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 
    /* Some sanity checks */
    BUG_ON(!CVT_LEAF_VAL(prev_cvt) && !CVT_INVALID(prev_cvt));
    BUG_ON(CVT_TOMB_STONE(prev_cvt) && (prev_cvt.length != 0));

    /* Allocate space for new value, in or out of line */ 
    if(!tombstone)
    {
        cvt->length = replace->value_len;

        /* Decide whether to use inline, or out-of-line value on the 
           basis of this length. */
        if (replace->value_len <= MAX_INLINE_VAL_SIZE)
        {
            CVT_INLINE_SET(*cvt, replace->value_len, NULL);
            cvt->val  = castle_malloc(cvt->length, GFP_NOIO);
            /* @TODO: Work out how to handle this */
            BUG_ON(!cvt->val);
            /* We should not inline values which do not fit in a packet */
            BUG_ON(replace->data_length_get(replace) < cvt->length);
            replace->data_copy(replace, cvt->val, cvt->length, 0 /* not partial */); 
        }
        else /* On-disk objects. (Medium or Large Objects) */
        {
            uint32_t nr_chunks;
            c_ext_pos_t cep;
            uint32_t prev_nr_blocks;

            nr_blocks = (cvt->length - 1) / C_BLK_SIZE + 1; 
            nr_chunks = (cvt->length - 1) / C_CHK_SIZE + 1; 
            prev_nr_blocks = (prev_cvt.length - 1) / C_BLK_SIZE + 1;

            if (replace->value_len <= MEDIUM_OBJECT_LIMIT)
            { /* Medium Objects. */
                if (CVT_MEDIUM_OBJECT(prev_cvt) && (prev_nr_blocks >= nr_blocks))
                {
                    castle_ext_freespace_free(&c_bvec->tree->data_ext_free,
                                               nr_blocks * C_BLK_SIZE);
                    debug("Freeing %u blks from %p|%p\n", nr_blocks, c_bvec,
                                                             c_bvec->tree);
                    CVT_MEDIUM_OBJECT_SET(*cvt, replace->value_len, prev_cvt.cep);
                }
                else
                {
                    BUG_ON(castle_ext_freespace_get(&c_bvec->tree->data_ext_free,
                                                     nr_blocks * C_BLK_SIZE,
                                                     1,
                                                    &cep) < 0);
                    CVT_MEDIUM_OBJECT_SET(*cvt, replace->value_len, cep);
                }
                debug("Medium Object in %p, cep: "cep_fmt_str_nl, c_bvec->tree,
                                                   __cep2str(cvt->cep));
            }
            else 
            { /* Large Objects. */
                cep.ext_id = castle_extent_alloc(DEFAULT_RDA, c_bvec->tree->da, 
                                                 nr_chunks);
                cep.offset = 0;

                if (EXT_ID_INVAL(cep.ext_id))
                {
                    castle_printk("Failed to allocate space for Large Object.\n");
                    return -ENOSPC;
                }

                if (castle_ct_large_obj_add(cep.ext_id, replace->value_len,
                                            &c_bvec->tree->large_objs,
                                            &c_bvec->tree->lo_mutex))
                {
                    castle_printk("Failed to intialize large object\n");
                    return -ENOMEM;
                }

                /* Update the large object chunk count on the tree */
                atomic64_add(nr_chunks, &c_bvec->tree->large_ext_chk_cnt);

                CVT_LARGE_OBJECT_SET(*cvt, replace->value_len, cep);


                debug("Creating Large Object of size - %u\n", nr_chunks);
                /* @TODO: Again, work out how to handle failed allocations */ 
                BUG_ON(EXT_POS_INVAL(cvt->cep));
            }
        }
    } else
    /* For tombstones, construct the cvt and exit. */
    {
        CVT_TOMB_STONE_SET(*cvt);
    }

    /* If there was an out-of-line object stored under this key, release it. */
    /* Note: Not handling Medium objects. They may create holes. But, its fine
     * as it is just in T0. */
    BUG_ON(CVT_MEDIUM_OBJECT(prev_cvt) &&
           (prev_cvt.cep.ext_id != c_bvec->tree->data_ext_free.ext_id));

    /* Free Old Large Object */
    if (CVT_LARGE_OBJECT(prev_cvt))
    {
        /* Update the large object chunk count on the tree */
        prev_large_ext_chk_cnt = castle_extent_size_get(prev_cvt.cep.ext_id);
        atomic64_sub(prev_large_ext_chk_cnt, &c_bvec->tree->large_ext_chk_cnt);
        debug("Freeing Large Object of size - %u\n", prev_large_ext_chk_cnt);
        castle_ct_large_obj_remove(prev_cvt.cep.ext_id, 
                                  &c_bvec->tree->large_objs, 
                                  &c_bvec->tree->lo_mutex);
    }
    BUG_ON(CVT_INVALID(*cvt));
    FAULT(REPLACE_FAULT);

    return 0;
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
        castle_printk("Unexpected Packet length=%llu, data_length=%llu\n", 
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
            castle_printk("Unexpected copy_length %d\n", copy_length);
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
                castle_printk("Unexpected change in CEP while copy"cep_fmt_str
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
                                     

void castle_object_replace_complete(struct castle_bio_vec *c_bvec,
                                    int err,
                                    c_val_tup_t cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b = NULL;
    int complete_write = 0;

    replace->ct = c_bvec->tree;
    castle_debug_bio_deregister(c_bio);

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    debug("castle_object_replace_complete\n");

    if (castle_latest_key && !err)
    {
        mutex_lock(&c_bvec->tree->last_key_mutex);

        if (c_bvec->tree->last_key)
            castle_object_okey_free(c_bvec->tree->last_key);
        c_bvec->tree->last_key = castle_object_btree_key_convert(c_bvec->key);

        mutex_unlock(&c_bvec->tree->last_key_mutex);
    }

    /* Free the key */
    castle_object_bkey_free(c_bvec->key);

    /* Deal with error case first */
    if(err)
    {
        if (replace->ct)
            castle_ct_put(replace->ct, 1);
        replace->complete(replace, err);
        castle_utils_bio_free(c_bio);
        return;
    }

    /* Otherwise, write the entry out. */
    BUG_ON(!CVT_LEAF_VAL(cvt));
    if(CVT_ONDISK(cvt))
    {
        BUG_ON(c_bvec_data_del(c_bvec));
        c2b = castle_object_write_buffer_alloc(cvt.cep, cvt.length); 
        
        replace->data_c2b = c2b;
        replace->data_c2b_offset = 0;
        replace->data_length = cvt.length;
        
        if (replace->data_length_get(replace) > 0)
            complete_write = castle_object_data_write(replace);
    
        c2b = replace->data_c2b;
    }
    else 
    if(CVT_INLINE(cvt))
    {
        complete_write = 1;
        castle_free(cvt.val);
    }
    else /* tombstone */
        complete_write = 1;
        
    /* Unlock buffers, and complete the call if we are done already */
    if(complete_write)
    {
        debug("Completing the write. c2b=%p\n", c2b);
        if(c2b)
            put_c2b(c2b);
 
        castle_ct_put(replace->ct, 1);
        replace->complete(replace, 0);
    } else
    /* Complete the packet, so that the client sends us more. */
    {
        debug("Completing the packet, continuing the rest of the write.\n");
        replace->replace_continue(replace);
    }

    castle_utils_bio_free(c_bio);
}

int castle_object_replace_continue(struct castle_object_replace *replace)
{
    int copy_end;

    debug("Replace continue.\n");
    copy_end = castle_object_data_write(replace);
    if(copy_end)
    {
        c2_block_t *data_c2b = replace->data_c2b;
        uint32_t data_length = replace->data_length;
        
        BUG_ON(data_length != 0);
        put_c2b(data_c2b);
        castle_ct_put(replace->ct, 1);
        replace->complete(replace, 0);
    } else
    {
        replace->replace_continue(replace);
    }

    return 0;
}

int castle_object_replace_cancel(struct castle_object_replace *replace)
{
    struct castle_component_tree *ct = replace->ct;
    c2_block_t *data_c2b = replace->data_c2b;

    debug("Replace cancel.\n");

    castle_ct_put(ct, 1);
    put_c2b(data_c2b);

    /* @TODO: delete the partially written object */
    /* castle_utils_bio_free(c_bio); ??? */

    return 0;
}

/**
 * Insert new or replace existing object.
 *
 * @param cpu_index     CPU index (to determine correct T0 CT)
 *
 * @also castle_back_replace()
 * @also castle_back_remove()
 * @also castle_back_big_put()
 */
int castle_object_replace(struct castle_object_replace *replace, 
                          struct castle_attachment *attachment,
                          c_vl_okey_t *key, 
                          int cpu_index,
                          int tombstone)
{
    c_vl_bkey_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    int i;

    if(!castle_fs_inited)
        return -ENODEV;

    for (i=0; i<key->nr_dims; i++)
        if(key->dims[i]->length == 0)
            return -EINVAL;
    
    btree_key = castle_object_key_convert(key);
    if (!btree_key)
        return -EINVAL;
   
    //castle_printk(" value          : %s\n", tombstone ? "tombstone" : "object");
    //castle_printk("Btree key is:");
    //vl_key_print(btree_key);

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM;
    BUG_ON(!attachment);
    c_bio->attachment    = attachment;
    c_bio->replace       = replace;
    c_bio->data_dir      = WRITE;
    /* Tombstone & object replace both require a write */
    if(tombstone) 
        c_bio->data_dir |= REMOVE;
    
    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = btree_key; 
    c_bvec->cpu_index  = cpu_index;
    c_bvec->cpu        = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->flags      = 0;
    c_bvec->cvt_get    = castle_object_replace_cvt_get;
    c_bvec->endfind    = castle_object_replace_complete;
    c_bvec->da_endfind = NULL; 
    atomic_set(&c_bvec->reserv_nodes, 0);

    castle_debug_bio_register(c_bio, attachment->version, 1);
    castle_double_array_submit(c_bvec);

    return 0;
}
EXPORT_SYMBOL(castle_object_replace);

void castle_object_slice_get_end_io(void *obj_iter, int err);

int castle_object_iter_start(struct castle_attachment *attachment,
                            c_vl_okey_t *start_key,
                            c_vl_okey_t *end_key,
                            castle_object_iterator_t **iter)
{
    castle_object_iterator_t *iterator;
    int i;

    if(start_key->nr_dims != end_key->nr_dims)
    {
        castle_printk("Range query with different # of dimensions.\n");
        return -EINVAL;
    }
    /* Mark the key that this is end key. To notify this is infinity and +ve.
     * Assuming that end_key will not used anywhere before converting into
     * btree_key. */
    for (i=0; i<end_key->nr_dims; i++)
    {
        if (end_key->dims[i]->length == 0)
        {
            end_key->dims[i]->length = PLUS_INFINITY_DIM_LENGTH;
            break;
        }
    }

    iterator = castle_malloc(sizeof(castle_object_iterator_t), GFP_KERNEL);
    if(!iterator)
        return -ENOMEM;

    *iter = iterator;

    /* Initialise the iterator */
    iterator->start_okey = start_key;
    iterator->end_okey   = end_key;
    iterator->version    = attachment->version;
    iterator->da_id      = castle_version_da_id_get(iterator->version);

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
    c_vl_bkey_t *k;
    c_vl_okey_t *key = NULL;
    c_val_tup_t val;
    version_t v;
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

                    key = castle_object_btree_key_convert(k);
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
            castle_object_okey_free(key);
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
    int last;
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
        get->reply_start(get, 
                         0,
                         data_c2b_length + data_length,
                         c2b_buffer(c2b), 
                         data_c2b_length);
    else
        get->reply_continue(get, 
                            0, 
                            c2b_buffer(c2b), 
                            data_c2b_length,
                            last);
    read_unlock_c2b(c2b);

    if(last)
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

    /* Free the key */
    castle_object_bkey_free(c_bvec->key);

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
                      c_vl_okey_t *key,
                      int cpu_index)
{
    c_vl_bkey_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;

    debug("castle_object_get get=%p\n", get);
    
    if(!castle_fs_inited)
        return -ENODEV;

    btree_key = castle_object_key_convert(key);
    if (!btree_key)
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
    c_bvec->key        = btree_key; 
    c_bvec->cpu_index  = cpu_index;
    c_bvec->cpu        = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->ref_get    = castle_object_reference_get;
    c_bvec->endfind    = castle_object_get_complete;
    c_bvec->da_endfind = NULL; 
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
    castle_object_bkey_free(c_bvec->key);
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
                       c_vl_okey_t *key,
                       int cpu_index)
{
    c_vl_bkey_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;

    debug("castle_object_pull pull=%p\n", pull);

    if(!castle_fs_inited)
        return -ENODEV;

    btree_key = castle_object_key_convert(key);
    if (!btree_key)
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
    c_bvec->key        = btree_key; 
    c_bvec->cpu_index  = cpu_index;
    c_bvec->cpu        = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->ref_get    = castle_object_reference_get;
    c_bvec->endfind    = castle_object_pull_continue;
    c_bvec->da_endfind = NULL; 
    atomic_set(&c_bvec->reserv_nodes, 0);
    
    /* @TODO: add bios to the debugger! */ 
    castle_double_array_submit(c_bvec);

    return 0;
}
EXPORT_SYMBOL(castle_object_pull);
