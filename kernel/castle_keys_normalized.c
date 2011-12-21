
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
#define ARRAY_SIZE(x)           (sizeof(x) / sizeof((x)[0]))
#define likely(x)               __builtin_expect(!!(x), 1)
#define roundup(x, y)           ((((x) + ((y) - 1)) / (y)) * (y))
#define min(x, y) ({                        \
        typeof(x) _min1 = (x);              \
        typeof(y) _min2 = (y);              \
        (void) (&_min1 == &_min2);          \
        _min1 < _min2 ? _min1 : _min2; })
#endif

/*
 * Local header file inclusions.
 */

#include "castle_public.h"
#include "castle_keys_vlba.h"   /* VLBA_TREE_LENGTH_OF_*_KEY */
#ifdef __KERNEL__
#include "castle_utils.h"
#else
void *castle_alloc_maybe(size_t len, void *dst, size_t *dst_len);
void *castle_dup_or_copy(const void *src, size_t src_len, void *dst, size_t *dst_len);
#endif
#include "castle_keys_normalized.h"

/*
 * Data structure definitions (see also castle_keys_normalized.h).
 *
 * Aside of the special value which denotes that the number of dimensions is too large to
 * be encoded with two bytes, the definitions here mainly deal with the structure of
 * individual dimensions inside the normalized key. Each of these dimensions is laid out
 * "laced", with a marker byte after every few content bytes. The important thing to
 * notice here is that the stride of marker bytes is variable-length, increasing as the
 * key size gets bigger.
 *
 * With the current implementation, a marker is inserted after the first content byte,
 * then after the fourth, then every four content bytes until the sixteenth, and then the
 * stride doubles every time the count of content bytes becomes a power of four (i.e.,
 * quadruples). The stride does not go beyond 64, because that's the largest power of two
 * which can be represented by our one-byte marker encoding scheme (though presumably a
 * larger non power of two could be used).
 *
 * This scheme (double the stride every time the key length quadruples) has been chosen in
 * order to minimize both the padding overhead (at the end of the dimension), as well as
 * the lacing overhead, for small and large key values alike. In particular, suppose we
 * have a dimension of size n, with a marker stride of k. Then the padding overhead can be
 * up to k/n, while the lacing overhead is around 1/k. To keep both these ratios low, the
 * obvious choice for k is sqrt(n), and this is what our scheme tries to approximate.
 * Furthermore, the marker byte after the first content byte guarantees that empty and
 * single-byte dimensions remain small.
 *
 * Implementation-wise, the STRIDE_VALUES array encodes the list of marker strides used,
 * while the STRIDE_BOUNDS array encodes the thresholds of the number of content bytes at
 * which the marker stride changes. One must always make sure that each bound occurs
 * exactly at a point where a marker is inserted, otherwise the code is not guaranteed to
 * work correctly.
 *
 * A couple of helper defines are also provided to reduce code duplication. Functions
 * which deal with markers should "call" STRIDE_INIT_VARS at the beginning of the
 * function, and then check if the stride needs to be increaded with
 * STRIDE_CHECK_BOUND(pos), where pos is the number of content bytes which have been seen
 * so far.
 *
 * Please note: the maximum key size for slim trees has been chosen based on the maximum
 * possible expansion of a VLBA key when it is normalized. If the size limit for VLBA keys
 * is changed, or if the variable-length marker scheme is modified, then that maximum key
 * size needs to be recalculated too.
 */

/* special values for the number of dimensions field */
enum {
    NORM_DIM_NUMBER_LARGE = NORM_KEY_LENGTH_LARGE
};

/* arrays of marker strides and length bounds where the stride changes */
static const unsigned int STRIDE_VALUES[] = { 1, 3, 4, 8, 16, 32, 64 };
static const unsigned int STRIDE_BOUNDS[] = { 1, 4, 16, 64, 256, 1024, 0 };

/* common code for all the functions which deal with variable-length strides */
#define STRIDE_INIT_VARS                                                \
    unsigned int str_idx = 0, stride = STRIDE_VALUES[str_idx], bound = STRIDE_BOUNDS[str_idx]
#define STRIDE_CHECK_BOUND(pos)                                         \
    if ((pos) == bound && ++str_idx < ARRAY_SIZE(STRIDE_VALUES))        \
    {                                                                   \
        stride = STRIDE_VALUES[str_idx];                                \
        bound = STRIDE_BOUNDS[str_idx];                                 \
    }

/* special values for the marker bytes */
enum {
    KEY_MARKER_RESERVED0      = 0x00,
    KEY_MARKER_MINUS_INFINITY = 0x01,
    KEY_MARKER_END_BASE       = 0x02,
    KEY_MARKER_CONTINUES      = 0xfe,
    KEY_MARKER_PLUS_INFINITY  = 0xff
};

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
 * Predict the size of a laced bytestream.
 * @param len       the length of the bytestream to be laced
 *
 * This helper function is used by castle_norm_key_packed_size_predict() to calculate the
 * space needed for each individual dimension of the normalized key.
 */
static size_t castle_norm_key_lace_predict(size_t len)
{
    STRIDE_INIT_VARS;
    size_t pos = 0, result = 0;

    while (pos + stride < len)
    {
        result += stride + 1;
        pos += stride;
        STRIDE_CHECK_BOUND(pos);
    }

    result += stride + 1;
    return result;
}

/**
 * Copy a bytestream and lace it with marker bytes.
 * @param dst       the destination buffer of the copy
 * @param src       the source buffer of the copy
 * @param len       number of src bytes to be copied
 *
 * This is a helper function which copies len bytes of a standard key from src into a
 * series of segments of a normalized key in dst, by lacing the source bytestream with the
 * KEY_MARKER_CONTINUES marker according to the rules defined by the STRIDE_VALUES /
 * STRIDE_BOUNDS arrays. It returns the position in dst immediately after the copied
 * bytes.
 */
static unsigned char *castle_norm_key_lace(unsigned char *dst, const char *src, size_t len)
{
    STRIDE_INIT_VARS;
    size_t pos = 0;

    while (pos + stride < len)
    {
        memcpy(dst, src, stride);
        dst += stride;
        *dst++ = KEY_MARKER_CONTINUES;
        src += stride;
        pos += stride;
        STRIDE_CHECK_BOUND(pos);
    }

    memcpy(dst, src, len - pos);
    memset(dst + (len - pos), 0x00, stride - (len - pos));
    dst += stride;
    *dst++ = KEY_MARKER_END_BASE + (len - pos) * 2;
    return dst;
}

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
            len += castle_norm_key_lace_predict(dim_len);
        }
        else len += castle_norm_key_lace_predict(0);
    }

    len += NORM_KEY_DIM_SIZE(dim);
    return NORM_KEY_LENGTH_TO_SIZE(len);
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
            data = castle_norm_key_pad(data, 0x00, KEY_MARKER_MINUS_INFINITY, STRIDE_VALUES[0]);
        }
        else if (flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)
        {
            data = castle_norm_key_pad(data, 0xff, KEY_MARKER_PLUS_INFINITY, STRIDE_VALUES[0]);
        }
        else
        {
            size_t dim_len = castle_object_btree_key_dim_length(src, dim);
            const char *dim_key = castle_object_btree_key_dim_get(src, dim);
            data = castle_norm_key_lace(data, dim_key, dim_len);
            if (flags & KEY_DIMENSION_NEXT_FLAG)
                *(data-1) |= 1;
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
 * Return the number of dimensions of a normalized key.
 * @param key       the key to examine
 */
int castle_norm_key_nr_dims(const struct castle_norm_key *key)
{
    const unsigned char *data;
    castle_norm_key_len_get(key, &data);
    return castle_norm_key_dim_get(&data);
}

/**
 * Scan a key to find the start of the next dimension, or the end of the key.
 * @param pos       the current position inside the key
 */
inline static const unsigned char *castle_norm_key_dim_next(const unsigned char *pos)
{
    STRIDE_INIT_VARS;
    size_t len = 0;

    for (pos += stride; *pos == KEY_MARKER_CONTINUES; pos += stride + 1)
    {
        len += stride;
        STRIDE_CHECK_BOUND(len);
    }
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
    const unsigned char *key_curr, *key_end = castle_norm_key_end(key, &key_curr);
    const unsigned char *lower_curr, *lower_end = castle_norm_key_end(lower, &lower_curr);
    const unsigned char *upper_curr, *upper_end = castle_norm_key_end(upper, &upper_curr);

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
 * Create the "next" key of a given normalized key.
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

/**
 * Strip a few dimensions off a normalized key.
 * @param src       the key to strip
 * @param dst       the destination buffer to operate on, if any
 * @param dst_len   the size of the destination buffer, if any
 * @param n_keep    how many dimensions of the key to keep when stripping it
 *
 * The resulting key does not actually consist of fewer dimensions; instead what happens
 * is that the "stripped" dimensions are replaced with minus infinities, so that the
 * stripped key will compare less than the corresponding non-stripped ones.
 */
struct castle_norm_key *castle_norm_key_strip(const struct castle_norm_key *src,
                                              struct castle_norm_key *dst,
                                              size_t *dst_len,
                                              int n_keep)
{
    const unsigned char *src_data, *boundary;
    unsigned char *dst_data;
    size_t n_dim, keep_len, total_len;
    unsigned int dim;

    /* locate the key boundary */
    castle_norm_key_len_get(src, &src_data);
    n_dim = castle_norm_key_dim_get(&src_data);
    BUG_ON(n_dim < n_keep);
    for (dim = 0, boundary = src_data; dim < n_keep; ++dim)
        boundary = castle_norm_key_dim_next(boundary);
    keep_len = boundary - src_data;

    /* allocate and copy things over */
    total_len = NORM_KEY_DIM_SIZE(n_dim) + keep_len + (STRIDE_VALUES[0] + 1) * (n_dim - n_keep);
    dst = castle_alloc_maybe(NORM_KEY_LENGTH_TO_SIZE(total_len), dst, dst_len);
    if (!dst)
        return NULL;
    castle_norm_key_len_put(dst, &dst_data, total_len);
    castle_norm_key_dim_put(&dst_data, n_dim);
    memcpy(dst_data, src_data, keep_len);
    for (dst_data += keep_len; dim < n_dim; ++dim) /* dim == n_keep from previous loop */
        dst_data = castle_norm_key_pad(dst_data, 0x00, KEY_MARKER_MINUS_INFINITY, STRIDE_VALUES[0]);
    return dst;
}

/**
 * Meld two normalized keys into one.
 * @param a         the key which will be used for the first part of the resulting key
 * @param b         the key which will be used for the second part of the resulting key
 * @param meld_point the number of dimensions to use from key a
 *
 * The resulting key is constructed by taking some dimensions from key a, up to
 * meld_point, and then by taking the rest of its dimensions from b (by skipping its first
 * meld_point ones). The resulting key is stored in a freshly-allocated buffer, which the
 * caller is then responsible for freeing.
 */
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

/**
 * Produce a "next" key suitable for a hypercube-style range query.
 * @param key       the key to use as the basis for the "next" key
 * @param low       the lower bound of the hypercube
 * @param high      the upper bound of the hypercube
 *
 * This function constructs a key which can be used as a basis for comparison to find the
 * next keys which still fall within the hypercube defined by low and high. On the other
 * hand, if key itself falls within the bounds of the hypercube, it simply returns that.
 * Finally, if the provided key is beyond the upper bound of the hypercube, the function
 * returns high to signify that.
 */
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
        else
        {
            BUG_ON(out_of_range < 0);
            return (struct castle_norm_key *) high;
        }
    }
    else return (struct castle_norm_key *) key;
}

/*
 * Functions which extract information from / destroy normalized keys.
 */

/**
 * Predict the size of a de-normalized bytestream.
 * @param src       The source buffer for the de-normalization.
 *
 * This helper function is used by castle_norm_key_unpacked_size_predict() to calculate
 * the space needed for each individual dimension of the key after removing the marker
 * bytes.
 */
static size_t castle_norm_key_unlace_predict(const unsigned char **src)
{
    STRIDE_INIT_VARS;
    size_t len = 0;

    for ( ; *(*src += stride) == KEY_MARKER_CONTINUES; ++*src)
    {
        len += stride;
        STRIDE_CHECK_BOUND(len);
    }

    if (**src != KEY_MARKER_MINUS_INFINITY && **src != KEY_MARKER_PLUS_INFINITY)
        len += (**src - KEY_MARKER_END_BASE) / 2;
    else
        BUG_ON(len > 0);
    ++*src;
    return len;
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
    STRIDE_INIT_VARS;
    const unsigned char *marker = src;
    *len = 0;

    for ( ; *(marker += stride) == KEY_MARKER_CONTINUES; src = ++marker)
    {
        memcpy(dst, src, stride);
        dst += stride;
        *len += stride;
        STRIDE_CHECK_BOUND(*len);
    }

    if (*marker != KEY_MARKER_MINUS_INFINITY && *marker != KEY_MARKER_PLUS_INFINITY)
    {
        size_t fin_len = (*marker - KEY_MARKER_END_BASE) / 2;
        memcpy(dst, src, fin_len);
        *len += fin_len;
    }
    else BUG_ON(*len > 0);
    return ++marker;
}

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
    const unsigned char *curr, *end;
    unsigned int dim;

    if (NORM_KEY_SPECIAL(key))
        return size;

    end = castle_norm_key_end(key, &curr);
    n_dim = castle_norm_key_dim_get(&curr);

    for (dim = 0; dim < n_dim; ++dim)
        size += castle_norm_key_unlace_predict(&curr) + 4 /* for the dim_head */;
    BUG_ON(curr != end);

    return size;
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
 * @param type      whether the key is a normal key or a "stripped" key
 * @param seed      the seed value for the hash function
 */
uint32_t castle_norm_key_hash(const struct castle_norm_key *key,
                              c_btree_hash_enum_t type,
                              uint32_t seed)
{
    const unsigned char *data, *boundary;
    size_t len = castle_norm_key_len_get(key, &data), n_dim;
    unsigned int dim;

    switch (type)
    {
        case HASH_WHOLE_KEY:
            return murmur_hash_32(data, len, seed);
        case HASH_STRIPPED_KEYS:
            n_dim = castle_norm_key_dim_get(&data);
            BUG_ON(n_dim < HASH_STRIPPED_DIMS);
            for (dim = 0, boundary = data; dim < HASH_STRIPPED_DIMS; ++dim)
                boundary = castle_norm_key_dim_next(boundary);
            return murmur_hash_32(data, boundary - data, seed);
        default:
            BUG();
    }
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
        size_t buf_len = len * 2 + n_dim * 4 + 2; /* conservative estimate */
        char *buf = castle_alloc(buf_len), *p = buf;
        unsigned int dim, i, pos;

        *p++ = '[';
        for (dim = 0; dim < n_dim; ++dim)
        {
            STRIDE_INIT_VARS;

            if (data[stride] == KEY_MARKER_MINUS_INFINITY ||
                data[stride] == KEY_MARKER_PLUS_INFINITY)
            {
                sprintf(p, data[stride] == KEY_MARKER_MINUS_INFINITY ? "-inf," : "+inf,");
                p += 5;
                continue;
            }

            pos = 0;
            *p++ = '0';
            *p++ = 'x';
            do
            {
                unsigned int seg_bytes = stride;
                int next = 0;

                if (data[stride] != KEY_MARKER_CONTINUES)
                {
                    seg_bytes = (data[stride] - KEY_MARKER_END_BASE) / 2;
                    next = (data[stride] - KEY_MARKER_END_BASE) % 2;
                }

                for (i = 0; i < seg_bytes; ++i)
                {
                    sprintf(p, "%.2x", *data++);
                    p += 2;
                }
                data += stride - seg_bytes;
                pos += stride;
                STRIDE_CHECK_BOUND(pos);

                if (next)
                    *p++ = '+';
            }
            while (*data++ == KEY_MARKER_CONTINUES);
            *p++ = ',';
        }
        *(p-1) = ']';
        *p++ = '\0';
        BUG_ON(data != key->data + len);
        BUG_ON(p - buf > buf_len);

        castle_printk(level, "%s, len=%lu\n", buf, len);
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
