/*
 * Current issues:
 * - switch from magic numbers like 2 and 4 to sizeof(uint32_t) and the like
 * - then also make those sizes typedefs to have a single definition
 */

/*
 * System header file inclusions.
 */

#ifdef __KERNEL__
#include <linux/types.h>
#include <linux/compiler.h>     /* likely() */
#include <linux/kernel.h>
#include <linux/slab.h>         /* kmalloc() and friends */
#include <linux/string.h>       /* memcmp() etc */
#include <asm/byteorder.h>      /* htons() etc */
#else
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>             /* malloc() */
#include <string.h>             /* memcmp() etc */
#include <assert.h>
#include <arpa/inet.h>          /* htons() etc */

#define BUG_ON(x)               assert(!(x))
#define castle_alloc(x)         malloc(x)
#define castle_free(x)          free(x)

/* lifted from linux/kernel.h */
#define likely(x)               __builtin_expect(!!(x), 1)
#define roundup(x, y)           ((((x) + ((y) - 1)) / (y)) * (y))
#define min(x, y) ({				\
	typeof(x) _min1 = (x);			\
	typeof(y) _min2 = (y);			\
	(void) (&_min1 == &_min2);		\
	_min1 < _min2 ? _min1 : _min2; })
#endif

/*
 * Local header file inclusions.
 */

#include "castle_public.h"
#include "castle_keys_vlba.h"   /* VLBA_TREE_LENGTH_OF_*_KEY */
#include "castle_utils.h"
#include "castle_keys_normalized.h"

/*
 * Data structure definitions (see also castle_keys_normalized.h).
 */

/* special values for the number of dimensions field */
enum {
    NORM_DIM_NUMBER_LARGE = NORM_KEY_LENGTH_LARGE
};

/* insert a marker byte after this number of content bytes */
#define MARKER_STRIDE 8

/* special values for the marker bytes */
enum {
    KEY_MARKER_RESERVED0      = 0x00,
    KEY_MARKER_MINUS_INFINITY = 0x01,
    KEY_MARKER_END_BASE       = 0x02,
    KEY_MARKER_CONTINUES      = 0xfe,
    KEY_MARKER_PLUS_INFINITY  = 0xff
};

/* the number of special values in the above enum */
#define KEY_MARKER_NUM_SPECIAL 4
#if (MARKER_STRIDE + 1) * 2 + KEY_MARKER_NUM_SPECIAL > 256
#error Normalized key marker values do not fit inside a byte.
#endif

/*
 * Helper macros.
 */

#define NORM_KEY_LENGTH_TO_SIZE(len)  ({                                \
            typeof(len) _len = (len);                                   \
            _len + (_len >= NORM_KEY_LENGTH_LARGE ? 6 : 2); })
#define NORM_KEY_SIZE_TO_LENGTH(size) ({                                \
            typeof(size) _size = (size);                                \
            _size - (_size >= NORM_KEY_LENGTH_LARGE + 6 ? 6 : 2); })

#define NORM_KEY_DIM_SIZE(dim) ((dim) >= NORM_DIM_NUMBER_LARGE ? 6 : 2)

/*
 * Functions which query/set various properties of normalized keys.
 */

/**
 * Compute the length of a normalized key.
 * @param key       the key whose length we need to compute
 * @param data      used to store a pointer to the actual key data
 *
 * While @see castle_norm_key has a length field, that field is only two bytes long, and
 * for large keys it is allowed to overflow and also take up the first four bytes of the
 * data field. This function computes the actual value of key's length based on the length
 * field (and potentially the start of the data field), and also stores in data the
 * pointer to the actual start of the key's data.
 */
static size_t castle_norm_key_len_get(const struct castle_norm_key *key, const unsigned char **data)
{
    size_t len = key->length;
    BUG_ON(NORM_KEY_SPECIAL(key));
    *data = key->data;

    if (len == NORM_KEY_LENGTH_LARGE)
    {
        len = *((const uint32_t *) *data);
        *data += sizeof(uint32_t);
    }

    return len;
}

/**
 * Write out the length of a normalized key.
 * @param key       the key in which to store the length
 * @param data      used to store a pointer to just after the stored length
 * @param len       the length to be written
 *
 * The length is stored in the two-byte length field, if it fits; otherwise a special
 * value is stored in those two bytes, and the length is stored in the subsequent four
 * bytes.
 *
 * When the function returns, the data pointer points just past the stored length.
 */
static void castle_norm_key_len_put(struct castle_norm_key *key, unsigned char **data, size_t len)
{
    *data = key->data;
    if (len >= NORM_KEY_LENGTH_LARGE)
    {
        key->length = NORM_KEY_LENGTH_LARGE;
        *((uint32_t *) *data) = len;
        *data += sizeof(uint32_t);
    }
    else key->length = len;
    BUG_ON(NORM_KEY_SPECIAL(key));
}

/**
 * Locate the end of a normalized key.
 * @param key       the key whose end we need to locate
 * @param data      used to store a pointer to the start of the key
 *
 * This function is similar to @see castle_norm_key_len_get(), except that, instead of
 * returning an integer with the length of the key, it returns a pointer to its end.
 */
inline static const unsigned char *castle_norm_key_end(const struct castle_norm_key *key,
                                                       const unsigned char **data)
{
    size_t length = castle_norm_key_len_get(key, data);
    return *data + length;
}

/**
 * Return the number of dimensions of a normalized key.
 * @param data      pointer to the key's contents
 *
 * After the length of the key, the next thing stored in it is the number of dimensions,
 * in a similar format (first two bytes, then four more bytes if necessary). Unlike the
 * length field though, the number of dimensions is always stored in big-endian, in order
 * to be memcmp()-comparable. This function extracts the number of dimensions and advances
 * the data pointer to point just after it.
 */
static size_t castle_norm_key_dim_get(const unsigned char **data)
{
    size_t dim = ntohs(*((uint16_t *) *data));
    *data += sizeof(uint16_t);

    if (dim == NORM_DIM_NUMBER_LARGE)
    {
        dim = ntohl(*((uint32_t *) *data));
        *data += sizeof(uint32_t);
    }

    return dim;
}

/**
 * Write out the number of dimensions of a normalized key.
 * @param data      pointer to the key's content array
 * @param dim       the number of dimensions to be written
 *
 * The number of dimensions is stored in two bytes, if it fits; otherwise a special value
 * is stored in those two bytes, and the number of dimensions is stored in the subsequent
 * four bytes. All these values are stored in big-endian.
 *
 * When the function returns, the data pointer has advanced to point past the stored
 * dimensions field.
 */
static void castle_norm_key_dim_put(unsigned char **data, size_t dim)
{
    if (dim < NORM_DIM_NUMBER_LARGE)
    {
        *((uint16_t *) *data) = htons(dim);
        *data += sizeof(uint16_t);
    }
    else
    {
        *((uint16_t *) *data) = htons(NORM_DIM_NUMBER_LARGE);
        *data += sizeof(uint16_t);
        *((uint32_t *) *data) = htonl(dim);
        *data += sizeof(uint32_t);
    }
}

/*
 * Functions which create (or help create) normalized keys.
 */

/**
 * Predict the size of a normalized key.
 * @param src       the source key that needs to be normalized
 *
 * Since normalized keys are variable-length, it's hard to predict how much space to
 * allocate for them in advance. This function performs a normalization "dummy run" in
 * order to count the number of bytes needed.
 *
 * The value returned is the number of bytes which need to be allocated, so it includes
 * the (variable-length) length field -- hence "size" and not "length".
 */
static size_t castle_norm_key_packed_size_predict(const struct castle_var_length_btree_key *src)
{
    size_t len = 0;
    unsigned int dim;

    if (src->length == VLBA_TREE_LENGTH_OF_MIN_KEY ||
        src->length == VLBA_TREE_LENGTH_OF_MAX_KEY ||
        src->length == VLBA_TREE_LENGTH_OF_INVAL_KEY)
        return 2;

    for (dim = 0; dim < src->nr_dims; ++dim)
    {
        unsigned int flags = castle_object_btree_key_dim_flags_get(src, dim);
        if (!(flags & KEY_DIMENSION_INFINITY_FLAGS_MASK))
        {
            size_t dim_len = castle_object_btree_key_dim_length(src, dim);
            if (dim_len != 0)
            {
                dim_len = roundup(dim_len, MARKER_STRIDE);
                dim_len += dim_len / MARKER_STRIDE;
            }
            else dim_len = MARKER_STRIDE + 1;
            len += dim_len;
        }
        else len += MARKER_STRIDE + 1;
    }

    len += NORM_KEY_DIM_SIZE(dim);
    return NORM_KEY_LENGTH_TO_SIZE(len);
}

/**
 * Copy a bytestream and lace it with marker bytes.
 * @param dst       the destination buffer of the copy
 * @param src       the source buffer of the copy
 * @param len       number of src bytes to be copied
 *
 * This is a helper function which copies len bytes of a standard key from src into a
 * series of segments of a normalized key in dst, by lacing the source bytestream with the
 * KEY_MARKER_CONTINUES marker every MARKER_STRIDE bytes. It returns the position in dst
 * immediately after the copied bytes.
 */
static unsigned char *castle_norm_key_lace(unsigned char *dst, const char *src, size_t len)
{
    while (len > MARKER_STRIDE)
    {
        memcpy(dst, src, MARKER_STRIDE);
        dst += MARKER_STRIDE;
        *dst++ = KEY_MARKER_CONTINUES;
        src += MARKER_STRIDE;
        len -= MARKER_STRIDE;
    }
    memcpy(dst, src, len);
    return dst + len;
}

/**
 * Pad a segment of a normalized key and insert an end marker.
 * @param dst       the destination buffer for padding
 * @param pad_val   the byte value to be used for padding
 * @param end_val   the marker byte to be written at the end of the padded area
 * @param len       the length of the padded area
 *
 * This is a helper function which pads a segment of a normalized key in dst with len
 * bytes of pad_val, and then inserts an end marker end_val. It returns the position in
 * dst immediately after the inserted bytes.
 */
static unsigned char *castle_norm_key_pad(unsigned char *dst, int pad_val, int end_val, size_t len)
{
    memset(dst, pad_val, len);
    dst += len;
    *dst++ = end_val;
    return dst;
}

/**
 * Construct a normalized key.
 * @param src       the source key that needs to be normalized
 * @param dst       the destination buffer to store the key, or NULL to allocate one
 * @param dst_len   the size of the destination buffer, if any
 *
 * The input of this function is a standard key structure, and it produces a normalized
 * key out of it. If dst is not set, the key returned is allocated with kmalloc(),
 * otherwise the buffer pointed to by dst is used. If kmalloc() fails to allocate, or if
 * the destination buffer is not large enough, then this function returns NULL -- no other
 * error conditions are possible.
 */
struct castle_norm_key *castle_norm_key_pack(const struct castle_var_length_btree_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len)
{
    size_t size = castle_norm_key_packed_size_predict(src);
    unsigned char *data;
    unsigned int dim;

    if (!(dst = castle_alloc_maybe(size, dst, dst_len)))
        return NULL;

    switch (src->length)
    {
        case VLBA_TREE_LENGTH_OF_MIN_KEY:
            dst->length = NORM_KEY_LENGTH_MIN_KEY;
            BUG_ON(size != 2);
            return dst;
        case VLBA_TREE_LENGTH_OF_MAX_KEY:
            dst->length = NORM_KEY_LENGTH_MAX_KEY;
            BUG_ON(size != 2);
            return dst;
        case VLBA_TREE_LENGTH_OF_INVAL_KEY:
            dst->length = NORM_KEY_LENGTH_INVAL_KEY;
            BUG_ON(size != 2);
            return dst;
        default:
            break;              /* fall through to the rest of the function */
    }

    castle_norm_key_len_put(dst, &data, NORM_KEY_SIZE_TO_LENGTH(size));
    castle_norm_key_dim_put(&data, src->nr_dims);

    for (dim = 0; dim < src->nr_dims; ++dim)
    {
        unsigned int flags = castle_object_btree_key_dim_flags_get(src, dim);
        if (flags & KEY_DIMENSION_MINUS_INFINITY_FLAG)
        {
            data = castle_norm_key_pad(data, 0, KEY_MARKER_MINUS_INFINITY, MARKER_STRIDE);
        }
        else if (flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)
        {
            data = castle_norm_key_pad(data, 0xff, KEY_MARKER_PLUS_INFINITY, MARKER_STRIDE);
        }
        else
        {
            int marker;
            size_t dim_len = castle_object_btree_key_dim_length(src, dim);
            if (dim_len != 0)
            {
                const char *dim_key = castle_object_btree_key_dim_get(src, dim);
                data = castle_norm_key_lace(data, dim_key, dim_len);
                /* calculate the length of the last segment: this is essentially dim_len %
                   MARKER_STRIDE, but in the range [1..MARKER_STRIDE] instead of
                   [0..MARKER_STRIDE-1] (except for 0) */
                dim_len = (dim_len + MARKER_STRIDE - 1) % MARKER_STRIDE + 1;
            }
            /*
             * calculate the value of the final marker byte:
             * - start with KEY_MARKER_END_BASE as the base value
             * - add 2 for each byte occupied since the last marker
             * - add an extra 1 if the key value has the "next" flag
             */
            marker = KEY_MARKER_END_BASE + dim_len * 2 + ((flags & KEY_DIMENSION_NEXT_FLAG) != 0);
            data = castle_norm_key_pad(data, 0, marker, MARKER_STRIDE - dim_len);
        }
    }

    BUG_ON(data - dst->data != size - 2);
    return dst;
}

/**
 * Copy a normalized key.
 * @param src       the key to copy
 * @param dst       the destination buffer to copy the key to, if any
 * @param dst_len   the size of the destination buffer, if any
 *
 * The key is copied either into a newly allocated area in memory or in the buffer pointed
 * to by dst. The function then returns the result of the copy.
 */
struct castle_norm_key *castle_norm_key_copy(const struct castle_norm_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len)
{
    return castle_dup_or_copy(src, castle_norm_key_size(src), dst, dst_len);
}

/*
 * Key comparison functions.
 */

/**
 * Compare the contents of two keys.
 * @param a_data    bytestream of the first key
 * @param a_len     length of the first key
 * @param b_data    bytestream of the second key
 * @param b_len     length of the second key
 *
 * The two keys are compared using memcmp(), resolving ties using the keys' lengths
 * (shorter is less).
 */
inline static int castle_norm_key_data_compare(const unsigned char *a_data, size_t a_len,
                                               const unsigned char *b_data, size_t b_len)
{
    int result = memcmp(a_data, b_data, min(a_len, b_len));
    return result ? result : (int) (a_len - b_len);
}

/**
 * Compare two normalized keys.
 * @param a         the first key of the comparison
 * @param b         the second key of the comparison
 *
 * This function lexicographically compares two normalized keys a and b and returns a
 * negative number if a < b, zero if a = b, and a positive number if a > b. It does so by
 * comparing them with memcmp() on their common bytes, or by comparing their lengths if
 * those are equal. It also handles all special types of keys correctly.
 */
int castle_norm_key_compare(const struct castle_norm_key *a, const struct castle_norm_key *b)
{
    if (likely(!NORM_KEY_SPECIAL(a) && !NORM_KEY_SPECIAL(b)))
    {
        const unsigned char *a_data, *b_data;
        size_t a_len = castle_norm_key_len_get(a, &a_data);
        size_t b_len = castle_norm_key_len_get(b, &b_data);
        return castle_norm_key_data_compare(a_data, a_len, b_data, b_len);
    }

    /* one of the keys is a special key */
    else return a->length - b->length;
}

/*
 * Functions which query and/or manipulate the dimensions of normalized keys.
 */

/**
 * Scan a key to find the start of the next dimension, or the end of the key.
 * @param pos       the current position inside the key
 */
inline static const unsigned char *castle_norm_key_dim_next(const unsigned char *pos)
{
    for (pos += MARKER_STRIDE; *pos == KEY_MARKER_CONTINUES;
         pos += MARKER_STRIDE + 1);
    return ++pos;
}

/**
 * Perform a bounding box comparison on a key.
 * @param key           the key to compare
 * @param lower         the lower bound of the bounding box
 * @param upper         the upper bound of the bounding box
 * @param offending_dim if non-NULL, used to store a pointer to the dimension which made
 *                      the comparison fail
 *
 * This function checks whether key is inside the hypercube defined by lower and upper. It
 * returns 0 if it is, <0 if one of its dimensions is less than the lower bound, or >0 if
 * one if its dimensions is greater than the upper bound. Additionally, if the bounding
 * box check fails, the index of the failing dimension is stored in offending_dim (if not
 * NULL).
 */
static int castle_norm_key_bounds_check(const struct castle_norm_key *key,
                                        const struct castle_norm_key *lower,
                                        const struct castle_norm_key *upper,
                                        unsigned int *offending_dim)
{
    const unsigned char *key_data, *key_end = castle_norm_key_end(key, &key_data), *key_curr = key_data;
    const unsigned char *lower_data, *lower_end = castle_norm_key_end(lower, &lower_data), *lower_curr = lower_data;
    const unsigned char *upper_data, *upper_end = castle_norm_key_end(upper, &upper_data), *upper_curr = upper_data;

    unsigned int dim;
    size_t key_dim = castle_norm_key_dim_get(&key_curr);
    size_t lower_dim = castle_norm_key_dim_get(&lower_curr);
    size_t upper_dim = castle_norm_key_dim_get(&upper_curr);
    BUG_ON(key_dim != lower_dim || key_dim != upper_dim);

    for (dim = 0; dim < key_dim; ++dim)
    {
        const unsigned char *key_next = castle_norm_key_dim_next(key_curr);
        const unsigned char *lower_next = castle_norm_key_dim_next(lower_curr);
        const unsigned char *upper_next = castle_norm_key_dim_next(upper_curr);

        /* the key must be >= the lower bound */
        if (castle_norm_key_data_compare(key_curr, key_next - key_curr,
                                         lower_curr, lower_next - lower_curr) < 0)
        {
            if (offending_dim)
                *offending_dim = dim;
            return -1;
        }

        /* the key must be <= the upper bound */
        if (castle_norm_key_data_compare(key_curr, key_next - key_curr,
                                         upper_curr, upper_next - upper_curr) > 0)
        {
            if (offending_dim)
                *offending_dim = dim;
            return 1;
        }

        /* proceed to the next dimension */
        key_curr = key_next;
        lower_curr = lower_next;
        upper_curr = upper_next;
    }

    /* if one key has reached its end, all of them must have */
    BUG_ON(key_curr != key_end || lower_curr != lower_end || upper_curr != upper_end);
    return 0;
}

/**
 * Set the "next" flag on a dimension of a key.
 * @param key       the key to modify
 * @param inc_dim   the dimension to set the "next" flag on
 */
static struct castle_norm_key *castle_norm_key_dim_inc(struct castle_norm_key *key,
                                                       unsigned int inc_dim)
{
    const unsigned char *curr;  /* const because other functions require it */
    size_t n_dim;
    unsigned int dim;

    castle_norm_key_len_get(key, &curr);
    n_dim = castle_norm_key_dim_get(&curr);
    BUG_ON(inc_dim >= n_dim);
    for (dim = 0; dim <= inc_dim; ++dim)
        curr = castle_norm_key_dim_next(curr);
    --curr;
    BUG_ON(*curr == KEY_MARKER_MINUS_INFINITY || *curr == KEY_MARKER_PLUS_INFINITY ||
           (*curr - KEY_MARKER_END_BASE) % 2 == 1);
    ++*((unsigned char *) curr); /* drop the constness here */

    return key;
}

/**
 * Create the "next" key of a given key.
 * @param src       the key to use for creating the next one
 * @param dst       the destination buffer to operate on, if any
 * @param dst_len   the size of the destination buffer, if any
 *
 * The "next" key is created by setting the "next" flag for the last dimension of the key.
 * This is done on a duplicate of the given key (which is not modified).
 */
struct castle_norm_key *castle_norm_key_next(const struct castle_norm_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len)
{
    const unsigned char *data;
    size_t n_dim;

    if (!(dst = castle_norm_key_copy(src, dst, dst_len)))
        return NULL;
    castle_norm_key_len_get(dst, &data);
    n_dim = castle_norm_key_dim_get(&data);
    return castle_norm_key_dim_inc(dst, n_dim-1);
}

static struct castle_norm_key *castle_norm_key_meld(const struct castle_norm_key *a,
                                                    const struct castle_norm_key *b,
                                                    unsigned int meld_point)
{
    struct castle_norm_key *result;
    unsigned char *data;

    const unsigned char *a_data, *a_end = castle_norm_key_end(a, &a_data), *a_curr, *a_split;
    const unsigned char *b_data, *b_end = castle_norm_key_end(b, &b_data), *b_curr, *b_split;
    size_t a_len, b_len, len;

    unsigned int dim;
    size_t a_dim = castle_norm_key_dim_get(&a_data);
    size_t b_dim = castle_norm_key_dim_get(&b_data);
    BUG_ON(a_dim < meld_point || b_dim < meld_point);

    /* locate the split points */
    for (dim = 0, a_curr = a_data, b_curr = b_data; dim < meld_point; ++dim)
    {
        a_curr = castle_norm_key_dim_next(a_curr);
        b_curr = castle_norm_key_dim_next(b_curr);
    }
    a_split = a_curr;
    b_split = b_curr;
    for (dim = meld_point; dim < a_dim; ++dim)
        a_curr = castle_norm_key_dim_next(a_curr);
    for (dim = meld_point; dim < b_dim; ++dim)
        b_curr = castle_norm_key_dim_next(b_curr);
    BUG_ON(a_curr != a_end || b_curr != b_end);

    /* calculate the length of the resulting key */
    a_len = a_split - a_data;
    b_len = b_end - b_split;
    len = NORM_KEY_DIM_SIZE(b_dim) + a_len + b_len;

    /* allocate and copy things over */
    result = castle_alloc(NORM_KEY_LENGTH_TO_SIZE(len));
    if (!result)
        return NULL;
    castle_norm_key_len_put(result, &data, len);
    castle_norm_key_dim_put(&data, b_dim);
    memcpy(data, a_data, a_len);
    memcpy(data + a_len, b_split, b_len);
    return result;
}

struct castle_norm_key *castle_norm_key_hypercube_next(const struct castle_norm_key *key,
                                                       const struct castle_norm_key *low,
                                                       const struct castle_norm_key *high)
{
    int offending_dim, out_of_range;
    out_of_range = castle_norm_key_bounds_check(key, low, high, &offending_dim);
    if (out_of_range)
    {
        if (offending_dim > 0)
        {
            struct castle_norm_key *result = castle_norm_key_meld(key, low, offending_dim);
            if (!result)
                return NULL;
            if (out_of_range > 0)
                castle_norm_key_dim_inc(result, offending_dim-1);
            return result;
        }
        else return NULL;
    }
    else return (struct castle_norm_key *) key;
}

/*
 * Functions which extract information from / destroy normalized keys.
 */

/**
 * Predict the size of a de-normalized key.
 * @param key       the key that needs to be de-normalized
 *
 * Similar to @see castle_norm_key_packed_size_predict(), this functions performs a "dummy
 * run" of the unpacking operation in order to figure out the size of the unpacked key.
 */
static size_t castle_norm_key_unpacked_size_predict(const struct castle_norm_key *key)
{
    /* initial size should be 16: 4 bytes length, 4 bytes nr_dims, 8 bytes _unused */
    size_t size = sizeof(struct castle_var_length_btree_key), n_dim;
    const unsigned char *curr, *next, *end;
    unsigned int dim;

    if (NORM_KEY_SPECIAL(key))
        return size;

    end = castle_norm_key_end(key, &curr);
    n_dim = castle_norm_key_dim_get(&curr);

    for (dim = 0; dim < n_dim; ++dim)
    {
        int marker;
        size += 4;              /* size of each dim_head */
        next = castle_norm_key_dim_next(curr);
        marker = *(next-1);
        if (marker != KEY_MARKER_MINUS_INFINITY && marker != KEY_MARKER_PLUS_INFINITY)
        {
            size += (next - curr) - (next - curr) / (MARKER_STRIDE + 1)
                - (MARKER_STRIDE - (marker - KEY_MARKER_END_BASE) / 2);
        }
        curr = next;
    }
    BUG_ON(curr != end);

    return size;
}

/**
 * Copy a normalized key bytestream, removing its marker bytes in the process.
 * @param dst       the destination buffer of the copy
 * @param src       the source buffer of the copy
 * @param len       used to store the number of content bytes which have been copied
 *
 * This does the opposite of @see castle_norm_key_lace(), copying the contents of a series
 * of segments of a normalized key out into dst, up until encountering a marker byte other
 * than KEY_MARKER_CONTINUES. The function returns the position in src immediately after
 * the last marker encountered, while the number of actual bytes copied is stored in len.
 */
static const unsigned char *castle_norm_key_unlace(char *dst, const unsigned char *src, size_t *len)
{
    const unsigned char *marker = src + MARKER_STRIDE;
    *len = 0;

    while (*marker == KEY_MARKER_CONTINUES)
    {
        memcpy(dst, src, MARKER_STRIDE);
        dst += MARKER_STRIDE;
        *len += MARKER_STRIDE;
        src = ++marker;
        marker += MARKER_STRIDE;
    }

    if (*marker != KEY_MARKER_MINUS_INFINITY && *marker != KEY_MARKER_PLUS_INFINITY)
    {
        size_t fin_len = (*marker - KEY_MARKER_END_BASE) / 2;
        memcpy(dst, src, fin_len);
        *len += fin_len;
    }
    return ++marker;
}

/**
 * Deconstruct a normalized key into the standard key structure.
 * @param src       the source key that needs to be de-normalized
 * @param dst       the destination buffer to store the result, or NULL to allocate one
 * @param dst_len   the size of the destination buffer, if any
 *
 * The input of this function is a normalized key, which it unpacks into the standard key
 * format. If dst is not set, the key returned is allocated with kmalloc(), otherwise the
 * buffer pointed to by dst is used. If kmalloc() fails to allocate, or if the destination
 * buffer is not large enough, then this function returns NULL -- no other error
 * conditions are possible.
 */
struct castle_var_length_btree_key *castle_norm_key_unpack(const struct castle_norm_key *src,
                                                           struct castle_var_length_btree_key *dst,
                                                           size_t *dst_len)
{
    size_t size = castle_norm_key_unpacked_size_predict(src), offset;
    const unsigned char *key_pos, *key_end;
    unsigned int dim;

    if (!(dst = castle_alloc_maybe(size, dst, dst_len)))
        return NULL;
    dst->nr_dims = 0;
    memset(dst->_unused, 0, sizeof dst->_unused);

    switch (src->length)
    {
        case NORM_KEY_LENGTH_MIN_KEY:
            dst->length = VLBA_TREE_LENGTH_OF_MIN_KEY;
            BUG_ON(size != sizeof *dst);
            return dst;
        case NORM_KEY_LENGTH_MAX_KEY:
            dst->length = VLBA_TREE_LENGTH_OF_MAX_KEY;
            BUG_ON(size != sizeof *dst);
            return dst;
        case NORM_KEY_LENGTH_INVAL_KEY:
            dst->length = VLBA_TREE_LENGTH_OF_INVAL_KEY;
            BUG_ON(size != sizeof *dst);
            return dst;
        default:
            break;              /* fall through to the rest of the function */
    }

    dst->length = size - sizeof dst->length;
    key_end = castle_norm_key_end(src, &key_pos);
    dst->nr_dims = castle_norm_key_dim_get(&key_pos);
    offset = sizeof *dst + dst->nr_dims * sizeof(uint32_t);
    memset(dst->dim_head, 0, offset - sizeof *dst);

    for (dim = 0; dim < dst->nr_dims; ++dim)
    {
        size_t dim_len;
        int marker;
        key_pos = castle_norm_key_unlace(((char *) dst) + offset, key_pos, &dim_len);
        marker = *(key_pos-1);

        dst->dim_head[dim] = offset << KEY_DIMENSION_FLAGS_SHIFT;
        if (marker == KEY_MARKER_MINUS_INFINITY)
            dst->dim_head[dim] |= KEY_DIMENSION_MINUS_INFINITY_FLAG;
        else if (marker == KEY_MARKER_PLUS_INFINITY)
            dst->dim_head[dim] |= KEY_DIMENSION_PLUS_INFINITY_FLAG;
        else if ((marker - KEY_MARKER_END_BASE) % 2 == 1)
            dst->dim_head[dim] |= KEY_DIMENSION_NEXT_FLAG;
        offset += dim_len;
    }

    BUG_ON(key_pos != key_end);
    return dst;
}

/**
 * Hash a normalized key.
 * @param key       the key to hash
 * @param seed      the seed value for the hash function
 */
uint32_t castle_norm_key_hash(const struct castle_norm_key *key, uint32_t seed)
{
    const unsigned char *data;
    size_t len = castle_norm_key_len_get(key, &data);
    return murmur_hash_32(data, len, seed);
}

/**
 * Print a normalized key.
 * @param level     the log level to pass to castle_printk()
 * @param key       the key to print
 */
void castle_norm_key_print(int level, const struct castle_norm_key *key)
{
    if (!key)
        castle_printk(level, "[null]\n");
    else if (key->length == NORM_KEY_LENGTH_MIN_KEY)
        castle_printk(level, "[min key]\n");
    else if (key->length == NORM_KEY_LENGTH_MAX_KEY)
        castle_printk(level, "[max key]\n");
    else if (key->length == NORM_KEY_LENGTH_INVAL_KEY)
        castle_printk(level, "[inval key]\n");
    else
    {
        const unsigned char *data;
        size_t len = castle_norm_key_len_get(key, &data);
        size_t n_dim = castle_norm_key_dim_get(&data);
        size_t buf_len = len * 2 + n_dim * 3 + 2; /* this is very conservative */
        char *buf = castle_alloc(buf_len), *p = buf;
        unsigned int dim, i;

        *p++ = '[';
        for (dim = 0; dim < n_dim; ++dim)
        {
            *p++ = '0';
            *p++ = 'x';
            do
            {
                for (i = 0; i < MARKER_STRIDE; ++i)
                {
                    sprintf(p, "%.2x", *data++);
                    p += 2;
                }
            }
            while (*data++ == KEY_MARKER_CONTINUES);
            *p++ = ',';
        }
        *(p-1) = ']';
        *p++ = '\0';
        BUG_ON(data != key->data + len);
        BUG_ON(p - buf > buf_len);

        castle_printk(level, "%s, len=%lu", buf, len);
        castle_free(buf);
    }
}

/**
 * Deallocate a normalized key.
 * @param key       the key to deallocate
 */
void castle_norm_key_free(struct castle_norm_key *key)
{
    castle_free(key);
}
