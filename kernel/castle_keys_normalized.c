/*
 * Current issues:
 *
 * - switch from kerneldoc to doxygen
 * - switch from magic numbers like 2 and 4 to sizeof(uint32_t) and the like
 * - then also make those sizes typedefs to have a single definition
 */

#include <linux/types.h>
#include <linux/compiler.h>     /* likely() */
#include <linux/kernel.h>
#include <linux/slab.h>         /* kmalloc() and related constants */
#include <linux/string.h>       /* memcmp() etc */
#include <asm/byteorder.h>      /* htons() etc */
#include "castle_public.h"
#include "castle_debug.h"       /* castle_malloc() */
#include "castle_btree.h"       /* VLBA_TREE_LENGTH_OF_*_KEY */
#include "castle_keys_normalized.h"

/**
 * struct castle_norm_key - the normalized key structure
 * @length:     the length of the actual content of the key, in bytes
 * @data:       the bytestream of the key
 *
 * This is the structure that contains the normalized keys. As the key is essentially one
 * packed bytestream, a very simple structure suffices.
 *
 * The @length field contains the length of the actual contents of the key (i.e. does not
 * include itself), in bytes. The length field can also have some special values for the
 * minimum, maximum and invalid key; in that case the @data field is empty.
 *
 * The @length field is two bytes long, but keys of length larger than what can be encoded
 * in two bytes are supported too. This works as follows; if the length field contains the
 * special value %KEY_LENGTH_LARGE, then the first four bytes of the @data field contain
 * the actual length, and the key follows. In that case, the stored length does not
 * include those four bytes either. In other words, the stored length is always the value
 * which needs to be passed to memcmp() when comparing two keys, not the allocated size of
 * the structure or the total number of bytes after the start of @data.
 *
 * Following the @length field is the number of dimensions, stored in big-endian in order
 * to be memcmp()-able. These are stored using the same scheme as the length field: using
 * two bytes, or if these are not enough, a special value is stored in these two bytes and
 * they are followed by four bytes.
 *
 * Each of the key's dimensions is stored in order, one after the other. For each
 * dimension, the key value is laid out "laced", with a special marker byte after every
 * %MARKER_STRIDE bytes of the actual value, padded with zeroes if necessary. The
 * in-between markers of a key value are always %KEY_MARKER_CONTINUES, while the ending
 * marker is a computed value which encodes the number of bytes that the value occupied
 * after the last marker, and also whether this is a "next" value.
 *
 * There are also special markers to denote plus and minus infinity for this particular
 * dimension. Additionally, +infinity has the characteristic that the padding bytes that
 * precede it are 0xff, instead of zeroes.
 *
 * If you make any modifications to the definition of this structure, you must make sure,
 * at the very least, that castle_norm_key_pack() still produces memcmp()-ordered
 * bytestreams, and that castle_norm_key_compare() still works correctly!
 */
struct castle_norm_key {
    uint16_t      length;
    unsigned char data[0];
} PACKED;

/* special values for the length field */
enum {
    KEY_LENGTH_MIN_KEY   = 0x0000,
    KEY_LENGTH_LARGE     = 0xfffd, /* needs to be larger than valid lengths */
    KEY_LENGTH_MAX_KEY   = 0xfffe,
    KEY_LENGTH_INVAL_KEY = 0xffff
};

/* special values for the number of dimensions field */
enum {
    DIM_NUMBER_LARGE = KEY_LENGTH_LARGE
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

/**
 * norm_key_packed_size_predict() - predict the size of a normalized key
 * @src:        the source key that needs to be normalized
 *
 * Since normalized keys are variable-length, it's hard to predict how much space to
 * allocate for them in advance. This function performs a normalization "dummy run" in
 * order to count the number of bytes needed.
 *
 * The value returned is the number of bytes which need to be allocated, so it includes
 * the (variable-length) length field -- hence "size" and not "length".
 */
static size_t norm_key_packed_size_predict(const struct castle_var_length_btree_key *src)
{
    size_t size = 2;
    unsigned int dim;

    if (src->length == VLBA_TREE_LENGTH_OF_MIN_KEY ||
        src->length == VLBA_TREE_LENGTH_OF_MAX_KEY ||
        src->length == VLBA_TREE_LENGTH_OF_INVAL_KEY)
        return size;

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
            size += dim_len;
        }
        else size += MARKER_STRIDE + 1;
    }

    if (size - 2 >= KEY_LENGTH_LARGE)
        size += 4;
    if (dim >= DIM_NUMBER_LARGE)
        size += 4;

    return size;
}

/**
 * norm_key_lace() - copy a bytestream and lace it with marker bytes
 * @dst:        the destination buffer of the copy
 * @src:        the source buffer of the copy
 * @len:        number of @src bytes to be copied
 *
 * This helper function copies @len bytes of a standard key from @src into a series of
 * segments of a normalized key in @dst, by lacing the source bytestream with the
 * %KEY_MARKER_CONTINUES marker every %MARKER_STRIDE bytes. It returns the position in
 * @dst immediately after the copied bytes.
 */
static unsigned char *norm_key_lace(unsigned char *dst, const char *src, size_t len)
{
    while (len > MARKER_STRIDE) {
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
 * norm_key_pad() - pad a segment of a normalized key and insert an end marker
 * @dst:        the destination buffer for padding
 * @pad_val:    the byte value to be used for padding
 * @end_val:    the marker byte to be written at the end of the padded area
 * @len:        the length of the padded area
 *
 * This helper function pads a segment of a normalized key in @dst with @len bytes of
 * @pad_val, and then inserts an end marker @end_val. It returns the position in @dst
 * immediately after the inserted bytes.
 */
static unsigned char *norm_key_pad(unsigned char *dst, int pad_val, int end_val, size_t len)
{
    memset(dst, pad_val, len);
    dst += len;
    *dst++ = end_val;
    return dst;
}

/**
 * castle_norm_key_pack() - construct a normalized key
 * @src:        the source key that needs to be normalized
 *
 * This function takes a standard key structure and produces a normalized key out of it.
 * The key returned is allocated with kmalloc(). If kmalloc() fails to allocate, this
 * function returns NULL -- no other error conditions are possible.
 */
struct castle_norm_key *castle_norm_key_pack(const struct castle_var_length_btree_key *src)
{
    size_t size = norm_key_packed_size_predict(src);
    struct castle_norm_key *result = castle_malloc(size, GFP_KERNEL);
    unsigned char *data;
    unsigned int dim;
    if (!result)
        return NULL;

    switch (src->length)
    {
        case VLBA_TREE_LENGTH_OF_MIN_KEY:
            result->length = KEY_LENGTH_MIN_KEY;
            BUG_ON(size != 2);
            return result;
        case VLBA_TREE_LENGTH_OF_MAX_KEY:
            result->length = KEY_LENGTH_MAX_KEY;
            BUG_ON(size != 2);
            return result;
        case VLBA_TREE_LENGTH_OF_INVAL_KEY:
            result->length = KEY_LENGTH_INVAL_KEY;
            BUG_ON(size != 2);
            return result;
        default:
            break;              /* fall through to the rest of the function */
    }

    data = result->data;
    if (size >= KEY_LENGTH_LARGE + 6)
    {
        result->length = KEY_LENGTH_LARGE;
        *((uint32_t *) data) = size - 6;
        data += sizeof(uint32_t);
    }
    else result->length = size - 2;

    if (src->nr_dims < DIM_NUMBER_LARGE)
    {
        *((uint16_t *) data) = htons(src->nr_dims);
        data += sizeof(uint16_t);
    }
    else
    {
        *((uint16_t *) data) = htons(DIM_NUMBER_LARGE);
        data += sizeof(uint16_t);
        *((uint32_t *) data) = htonl(src->nr_dims);
        data += sizeof(uint32_t);
    }

    for (dim = 0; dim < src->nr_dims; ++dim)
    {
        unsigned int flags = castle_object_btree_key_dim_flags_get(src, dim);
        if (flags & KEY_DIMENSION_MINUS_INFINITY_FLAG)
        {
            data = norm_key_pad(data, 0, KEY_MARKER_MINUS_INFINITY, MARKER_STRIDE);
        }
        else if (flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)
        {
            data = norm_key_pad(data, 0xff, KEY_MARKER_PLUS_INFINITY, MARKER_STRIDE);
        }
        else
        {
            int marker;
            size_t dim_len = castle_object_btree_key_dim_length(src, dim);
            if (dim_len != 0)
            {
                const char *dim_key = castle_object_btree_key_dim_get(src, dim);
                data = norm_key_lace(data, dim_key, dim_len);
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
            data = norm_key_pad(data, 0, marker, MARKER_STRIDE - dim_len);
        }
    }

    BUG_ON(data - result->data != result->length);
    return result;
}

/**
 * castle_norm_key_duplicate() - duplicate a normalized key
 * @key:        the key to duplicate
 *
 * This function copies a normalized key into a newly allocated area in memory, and
 * returns the result.
 */
struct castle_norm_key *castle_norm_key_duplicate(const struct castle_norm_key *key)
{
    size_t size;
    struct castle_norm_key *result;

    if (key->length < KEY_LENGTH_LARGE)
        size = key->length + 2;
    else if (key->length == KEY_LENGTH_LARGE)
        size = *((uint32_t *) key->data) + 6;
    else
        size = 2;

    result = castle_malloc(size, GFP_KERNEL);
    if (!result)
        return NULL;
    memcpy(result, key, size);
    return result;
}

/**
 * norm_key_length() - compute the length of a normalized key
 * @key:        the key whose length we need to compute
 * @data:       used to store a pointer to the actual key data
 *
 * While &struct castle_norm_key has a length field, that field is only two bytes long,
 * and for large keys it is allowed to overflow and also take up the first four bytes of
 * the data field. This function computes the actual value of @key's length based on the
 * length field (and potentially the start of the data field), and also stores in @data
 * the pointer to the actual start of the key's data.
 */
static size_t norm_key_length(const struct castle_norm_key *key, const unsigned char **data)
{
    size_t len = key->length;
    *data = key->data;

    if (key->length == KEY_LENGTH_LARGE)
    {
        len = *((uint32_t *) key->data);
        *data += sizeof(uint32_t);
    }

    return len;
}

/**
 * norm_key_end() - locate the end of a normalized key
 * @key:        the key whose end we need to locate
 * @data:       used to store a pointer to the start of the key
 *
 * This function is similar to norm_key_length(), except that, instead of returning an
 * integer with the length of the key, it returns a pointer to its end.
 */
inline static const unsigned char *norm_key_end(const struct castle_norm_key *key, const unsigned char **data)
{
    size_t length = norm_key_length(key, data);
    return *data + length;
}

/**
 * norm_key_dimensions() - return the number of dimensions of a normalized key
 * @data:       pointer to the key's contents
 *
 * After the length of the key, the next thing stored in it is the number of dimensions,
 * in a similar format (first two bytes, then four more bytes if necessary). Unlike the
 * length field though, the number of dimensions is always stored in big-endian, in order
 * to be memcmp()-comparable. This function extracts the number of dimensions and advances
 * the @data pointer to point just after it.
 */
static size_t norm_key_dimensions(const unsigned char **data)
{
    size_t dim = ntohs(*((uint16_t *) *data));
    *data += sizeof(uint16_t);

    if (dim == DIM_NUMBER_LARGE)
    {
        dim = ntohl(*((uint32_t *) *data));
        *data += sizeof(uint32_t);
    }

    return dim;
}

/**
 * norm_key_data_compare() - compare the contents of two keys
 * @a_data:     bytestream of the first key
 * @a_len:      length of the first key
 * @b_data:     bytestream of the second key
 * @b_len:      length of the second key
 *
 * Compares two keys using memcmp(), resolving ties using the keys' lengths (shorter is
 * less).
 */
inline static int norm_key_data_compare(const unsigned char *a_data, size_t a_len,
                                        const unsigned char *b_data, size_t b_len)
{
    int result = memcmp(a_data, b_data, min(a_len, b_len));
    return result ? result : (int) (a_len - b_len);
}

/**
 * castle_norm_key_compare() - compare two normalized keys
 * @a:          the first key of the comparison
 * @b:          the second key of the comparison
 *
 * This function lexicographically compares two normalized keys @a and @b and returns a
 * negative number if @a < @b, zero if @a = @b, and a positive number if @a > @b. It does
 * so by comparing them with memcmp() on their common bytes, or by comparing their lengths
 * if those are equal. It also handles all special types of keys correctly.
 */
int castle_norm_key_compare(const struct castle_norm_key *a, const struct castle_norm_key *b)
{
    if (likely(a->length <= KEY_LENGTH_LARGE && b->length <= KEY_LENGTH_LARGE)) {
        const unsigned char *a_data, *b_data;
        size_t a_len = norm_key_length(a, &a_data), b_len = norm_key_length(b, &b_data);
        return norm_key_data_compare(a_data, a_len, b_data, b_len);
    }

    /* one of the keys is either the max key or the invalid key */
    else return a->length - b->length;
}

/**
 * norm_key_dim_next() - scan a key to find the start of the next dimension
 * @pos:        the current position inside the key
 *
 * Scans a key forward to locate the start of the next dimension, or the end of the key.
 */
inline static const unsigned char *norm_key_dim_next(const unsigned char *pos)
{
    for (pos += MARKER_STRIDE;
         *pos == KEY_MARKER_CONTINUES; pos += MARKER_STRIDE + 1);
    return ++pos;
}

/**
 * castle_norm_key_bounds_check() - perform a bounding box comparison on a key
 * @key:        the key to compare
 * @lower:      the lower bound of the bounding box
 * @upper:      the upper bound of the bounding box
 * @offending_dim: if non-NULL, used to store a pointer to the dimension which made the
 *                 comparison fail
 */
int castle_norm_key_bounds_check(const struct castle_norm_key *key,
                                 const struct castle_norm_key *lower,
                                 const struct castle_norm_key *upper,
                                 int *offending_dim)
{
    const unsigned char *key_data, *key_end = norm_key_end(key, &key_data), *key_curr = key_data;
    const unsigned char *lower_data, *lower_end = norm_key_end(lower, &lower_data), *lower_curr = lower_data;
    const unsigned char *upper_data, *upper_end = norm_key_end(upper, &upper_data), *upper_curr = upper_data;

    unsigned int dim;
    size_t key_dim = norm_key_dimensions(&key_curr);
    size_t lower_dim = norm_key_dimensions(&lower_curr);
    size_t upper_dim = norm_key_dimensions(&upper_curr);
    BUG_ON(key_dim != lower_dim || key_dim != upper_dim);

    for (dim = 0; dim < key_dim; ++dim)
    {
        const unsigned char *key_next = norm_key_dim_next(key_curr);
        const unsigned char *lower_next = norm_key_dim_next(lower_curr);
        const unsigned char *upper_next = norm_key_dim_next(upper_curr);

        /* the key must be >= the lower bound */
        if (norm_key_data_compare(key_curr, key_next - key_curr,
                                  lower_curr, lower_next - lower_curr) < 0)
        {
            if (offending_dim)
                *offending_dim = dim;
            return -1;
        }

        /* the key must be <= the upper bound */
        if (norm_key_data_compare(key_curr, key_next - key_curr,
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

static size_t norm_key_unpacked_size_predict(const struct castle_norm_key *key)
{
    /* initial size should be 16: 4 bytes length, 4 bytes nr_dims, 8 bytes _unused */
    size_t size = sizeof(struct castle_var_length_btree_key), n_dim;
    const unsigned char *curr, *next, *end;
    unsigned int dim;

    if (key->length == 0 || key->length > KEY_LENGTH_LARGE)
        return size;

    end = norm_key_end(key, &curr);
    n_dim = norm_key_dimensions(&curr);

    for (dim = 0; dim < n_dim; ++dim)
    {
        int marker;
        size += 4;              /* size of each dim_head */
        next = norm_key_dim_next(curr);
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

static const unsigned char *norm_key_unlace(char *dst, const unsigned char *src, size_t *len)
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
        len += fin_len;
    }
    return ++marker;
}

struct castle_var_length_btree_key *castle_norm_key_unpack(const struct castle_norm_key *key)
{
    size_t size = norm_key_unpacked_size_predict(key), offset;
    struct castle_var_length_btree_key *result = castle_malloc(size, GFP_KERNEL);
    const unsigned char *key_pos, *key_end;
    unsigned int dim;

    switch (key->length)
    {
        case KEY_LENGTH_MIN_KEY:
            result->length = VLBA_TREE_LENGTH_OF_MIN_KEY;
            BUG_ON(size != sizeof *result);
            return result;
        case KEY_LENGTH_MAX_KEY:
            result->length = VLBA_TREE_LENGTH_OF_MAX_KEY;
            BUG_ON(size != sizeof *result);
            return result;
        case KEY_LENGTH_INVAL_KEY:
            result->length = VLBA_TREE_LENGTH_OF_INVAL_KEY;
            BUG_ON(size != sizeof *result);
            return result;
        default:
            break;              /* fall through to the rest of the function */
    }

    result->length = size - sizeof result->length;
    key_end = norm_key_end(key, &key_pos);
    result->nr_dims = norm_key_dimensions(&key_pos);
    offset = sizeof *result + result->nr_dims * sizeof(uint32_t);
    memset(result->dim_head, 0, offset - sizeof *result);

    for (dim = 0; dim < result->nr_dims; ++dim)
    {
        size_t dim_len;
        int marker;
        key_pos = norm_key_unlace(((char *) result) + offset, key_pos, &dim_len);
        marker = *(key_pos-1);

        if (marker == KEY_MARKER_MINUS_INFINITY)
        {
            result->dim_head[dim] = KEY_DIMENSION_MINUS_INFINITY_FLAG;
        }
        else if (marker == KEY_MARKER_PLUS_INFINITY)
        {
            result->dim_head[dim] = KEY_DIMENSION_PLUS_INFINITY_FLAG;
        }
        else
        {
            result->dim_head[dim] = (offset << KEY_DIMENSION_FLAGS_SHIFT);
            if ((marker - KEY_MARKER_END_BASE) % 2 == 1)
                result->dim_head[dim] |= KEY_DIMENSION_NEXT_FLAG;
            offset += dim_len;
        }
    }

    BUG_ON(key_pos != key_end);
    return result;
}
