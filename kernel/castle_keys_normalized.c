/*
 * Current issues:
 *
 * - are zero-length key values supported?
 * - the length values of special keys cannot be #included -- what to do?
 * - how do we handle endianness issues?
 * - do we use some sort of source documentation system?
 */

#include <linux/types.h>
#include <linux/compiler.h>
#include <linux/kernel.h>
#include <linux/slab.h>
#include <linux/string.h>
#include "castle_debug.h"
#include "castle_public.h"
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
 * special value %KEY_LENGTH_LARGE_KEY, then the first four bytes of the @data field
 * contain the actual length, and the key follows. In that case, the stored length does
 * not include those four bytes either. In other words, the stored length is always the
 * value which needs to be passed to memcmp() when comparing two keys, not the allocated
 * size of the structure or the total number of bytes after the start of @data.
 *
 * Each of the key's dimensions is stored in order, one after the other. For each
 * dimension, the key value is laid out "laced", with a special marker byte after every
 * %KEY_MARKER_STRIDE bytes of the actual value, padded with zeroes if necessary. The
 * in-between markers of a key value are always %KEY_MARKER_CONTINUES, while the ending
 * marker is a computed value which encodes the number of bytes that the value occupied
 * after the last marker, whether this is a "next" value, and whether this is the end of
 * the entire key.
 *
 * There are also special markers to denote plus and minus infinity for this particular
 * dimension. Additionally, +infinity has the characteristic that the padding bytes that
 * precede it are 0xff, instead of zeroes.
 *
 * If you make any modifications to the definition of this structure, you must make sure,
 * at the very least, that castle_norm_key_construct() still produces memcmp()-ordered
 * bytestreams, and that castle_norm_key_compare() still works correctly!
 */
struct castle_norm_key {
    uint16_t length;
    char     data[0];
} PACKED;

/* special values for the length field */
enum {
    KEY_LENGTH_MIN_KEY   = 0x0000,
    KEY_LENGTH_LARGE_KEY = 0xfffd, /* needs to be larger than valid lengths */
    KEY_LENGTH_MAX_KEY   = 0xfffe,
    KEY_LENGTH_INVAL_KEY = 0xffff
};

/* insert a marker byte after this number of content bytes */
#define KEY_MARKER_STRIDE 8

/* special values for the marker bytes */
enum {
    KEY_MARKER_RESERVED0      = 0x00,
    KEY_MARKER_MINUS_INFINITY = 0x01,
    KEY_MARKER_KEY_END_BASE   = 0x02,
    KEY_MARKER_DIM_END_BASE   = 0x02 + (KEY_MARKER_STRIDE + 1) * 2,
    KEY_MARKER_CONTINUES      = 0xfe,
    KEY_MARKER_PLUS_INFINITY  = 0xff
};

/* the number of special values in the above enum */
#define KEY_MARKER_NUM_SPECIAL 4
#if (KEY_MARKER_STRIDE + 1) * 4 + KEY_MARKER_NUM_SPECIAL > 256
#error Normalized key marker values do not fit inside a byte.
#endif

/**
 * castle_norm_key_size_predict() - predict the size of a normalized key
 * @src:        the source key that needs to be normalized
 *
 * Since normalized keys are variable-length, it's hard to predict how much space to
 * allocate for them in advance. This function performs a normalization "dummy run" in
 * order to count the number of bytes needed.
 *
 * The value returned is the number of bytes which need to be allocated, so it includes
 * the (variable-length) length field -- hence "size" and not "length".
 */
size_t castle_norm_key_size_predict(const struct castle_var_length_btree_key *src)
{
    size_t size = 2;
    int dim;

    /* XXX: declare these constants somewhere where we can #include them */
    if (src->length == 0 || src->length == 0xfffffffe || src->length == 0xffffffff)
        return size;

    for (dim = 0; dim < src->nr_dims; ++dim)
    {
        unsigned int flags = castle_object_btree_key_dim_flags_get(src, dim);
        if (!(flags & KEY_DIMENSION_INFINITY_FLAGS_MASK))
        {
            size_t dim_len = castle_object_btree_key_dim_length(src, dim);
            if (dim_len != 0)
            {
                dim_len = roundup(dim_len, KEY_MARKER_STRIDE);
                dim_len += dim_len / KEY_MARKER_STRIDE;
            }
            else dim_len = KEY_MARKER_STRIDE + 1;
            size += dim_len;
        }
        else size += KEY_MARKER_STRIDE + 1;
    }

    if (size - 2 >= KEY_LENGTH_LARGE_KEY)
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
 * %KEY_MARKER_CONTINUES marker every %KEY_MARKER_STRIDE bytes. It returns the position in
 * @dst immediately after the copied bytes.
 */
static char *norm_key_lace(char *dst, const char *src, size_t len)
{
    while (len > KEY_MARKER_STRIDE) {
        memcpy(dst, src, KEY_MARKER_STRIDE);
        dst += KEY_MARKER_STRIDE;
        *dst++ = KEY_MARKER_CONTINUES;
        src += KEY_MARKER_STRIDE;
        len -= KEY_MARKER_STRIDE;
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
static char *norm_key_pad(char *dst, int pad_val, int end_val, size_t len)
{
    memset(dst, pad_val, len);
    dst += len;
    *dst++ = end_val;
    return dst;
}

/**
 * castle_norm_key_construct() - construct a normalized key
 * @src:        the source key that needs to be normalized
 *
 * This function takes a standard key structure and produces a normalized key out of it.
 * The key returned is allocated with kmalloc(). If kmalloc() fails to allocate, this
 * function returns NULL -- no other error conditions are possible.
 */
struct castle_norm_key *castle_norm_key_construct(const struct castle_var_length_btree_key *src)
{
    size_t size = castle_norm_key_size_predict(src);
    struct castle_norm_key *result = castle_malloc(size, GFP_KERNEL);
    char *data;
    int dim;
    if (!result)
        return NULL;

    /* XXX: declare these constants somewhere where we can #include them */
    switch (src->length) {
    case 0:
        result->length = KEY_LENGTH_MIN_KEY;
        BUG_ON(size != 2);
        return result;
    case 0xfffffffe:
        result->length = KEY_LENGTH_MAX_KEY;
        BUG_ON(size != 2);
        return result;
    case 0xffffffff:
        result->length = KEY_LENGTH_INVAL_KEY;
        BUG_ON(size != 2);
        return result;
    default:
        break;                  /* fall through to the rest of the function */
    }

    data = result->data;
    if (size >= KEY_LENGTH_LARGE_KEY + 6)
    {
        result->length = KEY_LENGTH_LARGE_KEY;
        /* XXX: should we care about byte order here? */
        *((uint32_t *) data) = size - 6;
        data += sizeof(uint32_t);
    }
    else result->length = size - 2;

    for (dim = 0; dim < src->nr_dims; ++dim)
    {
        unsigned int flags = castle_object_btree_key_dim_flags_get(src, dim);
        if (flags & KEY_DIMENSION_MINUS_INFINITY_FLAG)
        {
            data = norm_key_pad(data, 0, KEY_MARKER_MINUS_INFINITY, KEY_MARKER_STRIDE);
        }
        else if (flags & KEY_DIMENSION_PLUS_INFINITY_FLAG)
        {
            data = norm_key_pad(data, 0xff, KEY_MARKER_PLUS_INFINITY, KEY_MARKER_STRIDE);
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
                   KEY_MARKER_STRIDE, but in the range [1..KEY_MARKER_STRIDE] instead of
                   [0..KEY_MARKER_STRIDE-1] (except for 0) */
                dim_len = (dim_len + KEY_MARKER_STRIDE - 1) % KEY_MARKER_STRIDE + 1;
            }
            /*
             * calculate the value of the final marker byte:
             * - choose the base value based on whether this is the last dimension
             * - add 2 for each byte occupied since the last marker
             * - add an extra 1 if the key value has the "next" flag
             */
            marker = (dim + 1 < src->nr_dims ? KEY_MARKER_DIM_END_BASE : KEY_MARKER_KEY_END_BASE)
                + dim_len * 2 + ((flags & KEY_DIMENSION_NEXT_FLAG) != 0);
            data = norm_key_pad(data, 0, marker, KEY_MARKER_STRIDE - dim_len);
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

    if (key->length < KEY_LENGTH_LARGE_KEY)
        size = key->length + 2;
    else if (key->length == KEY_LENGTH_LARGE_KEY)
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
    if (likely(a->length <= KEY_LENGTH_LARGE_KEY && b->length <= KEY_LENGTH_LARGE_KEY)) {
        size_t a_len = a->length, b_len = b->length;
        const char *a_data = a->data, *b_data = b->data;
        int result;

        if (a_len == KEY_LENGTH_LARGE_KEY)
        {
            a_len = *((uint32_t *) a_data);
            a_data += sizeof(uint32_t);
        }
        if (b_len == KEY_LENGTH_LARGE_KEY)
        {
            b_len = *((uint32_t *) b_data);
            b_data += sizeof(uint32_t);
        }

        result = memcmp(a_data, b_data, min(a_len, b_len));
        return result ? result : a_len - b_len;
    }

    /* one of the keys is either the max key or the invalid key */
    else return a->length - b->length;
}
