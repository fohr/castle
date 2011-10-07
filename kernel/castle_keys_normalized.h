#ifndef __CASTLE_KEYS_NORMALIZED_H__
#define __CASTLE_KEYS_NORMALIZED_H__

#include <linux/types.h>

/**
 * The normalized key structure.
 *
 * This is the structure that contains the normalized keys. As the key is essentially one
 * packed bytestream, a very simple structure suffices.
 *
 * The length field contains the length of the actual contents of the key (i.e. does not
 * include itself), in bytes. The length field can also have some special values for the
 * minimum, maximum and invalid key; in that case the data field is empty.
 *
 * The length field is two bytes long, but keys of length larger than what can be encoded
 * in two bytes are supported too. This works as follows; if the length field contains the
 * special value KEY_LENGTH_LARGE, then the first four bytes of the data field contain the
 * actual length, and the key follows. In that case, the stored length does not include
 * those four bytes either. In other words, the stored length is always the value which
 * needs to be passed to memcmp() when comparing two keys, not the allocated size of the
 * structure or the total number of bytes after the start of data.
 *
 * Following the length field is the number of dimensions, stored in big-endian in order
 * to be memcmp()-able. These are stored using the same scheme as the length field: using
 * two bytes, or if these are not enough, a special value is stored in these two bytes and
 * they are followed by four bytes.
 *
 * Each of the key's dimensions is stored in order, one after the other. For each
 * dimension, the key value is laid out "laced", with a special marker byte after every
 * MARKER_STRIDE bytes of the actual value, padded with zeroes if necessary. The
 * in-between markers of a key value are always KEY_MARKER_CONTINUES, while the ending
 * marker is a computed value which encodes the number of bytes that the value occupied
 * after the last marker, and also whether this is a "next" value.
 *
 * There are also special markers to denote plus and minus infinity for this particular
 * dimension. Additionally, +infinity has the characteristic that the padding bytes that
 * precede it are 0xff, instead of zeroes.
 *
 * Even though the structure is declared here, external code should not attempt to access
 * / modify the structure directly, as even the semantics or the length field are
 * complicated. Instead one should always use the functions and macros defined in this
 * header file.
 *
 * If you make any modifications to the definition of the structure, you must make sure,
 * at the very least, that castle_norm_key_pack() still produces memcmp()-ordered
 * bytestreams, and that castle_norm_key_compare() still works correctly!
 */
struct castle_norm_key {
    uint16_t      length;       /**< the length of the actual content of the key, in bytes */
    unsigned char data[0];      /**< the bytestream of the key */
} PACKED;

/* special values for the length field */
enum {
    NORM_KEY_LENGTH_MIN_KEY   = 0x0000,
    NORM_KEY_LENGTH_LARGE     = 0xfffd, /* needs to be larger than valid lengths */
    NORM_KEY_LENGTH_MAX_KEY   = 0xfffe,
    NORM_KEY_LENGTH_INVAL_KEY = 0xffff
};

#define NORM_KEY_MIN(key)     ((key)->length == NORM_KEY_LENGTH_MIN_KEY)
#define NORM_KEY_MAX(key)     ((key)->length == NORM_KEY_LENGTH_MAX_KEY)
#define NORM_KEY_INVAL(key)   ((key)->length == NORM_KEY_LENGTH_INVAL_KEY)
/* includes all the above */
#define NORM_KEY_SPECIAL(key) ((key)->length == 0 || (key)->length > NORM_KEY_LENGTH_LARGE)

inline static size_t castle_norm_key_size(const struct castle_norm_key *key)
{
    return NORM_KEY_SPECIAL(key) ? 2 :
        (key->length != NORM_KEY_LENGTH_LARGE ?
         key->length + 2 : *((const uint32_t *) key->data) + 6);
}

struct castle_var_length_btree_key;

struct castle_norm_key *castle_norm_key_pack(const struct castle_var_length_btree_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len);
struct castle_norm_key *castle_norm_key_copy(const struct castle_norm_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len);
struct castle_norm_key *castle_norm_key_next(const struct castle_norm_key *src,
                                             struct castle_norm_key *dst, size_t *dst_len);
struct castle_norm_key *castle_norm_key_hypercube_next(const struct castle_norm_key *key,
                                                       const struct castle_norm_key *low,
                                                       const struct castle_norm_key *high);

int castle_norm_key_compare(const struct castle_norm_key *a, const struct castle_norm_key *b);
uint32_t castle_norm_key_hash(const struct castle_norm_key *key, uint32_t seed);
void castle_norm_key_print(int level, const struct castle_norm_key *key);

struct castle_var_length_btree_key *castle_norm_key_unpack(const struct castle_norm_key *src,
                                                           struct castle_var_length_btree_key *dst,
                                                           size_t *dst_len);
void castle_norm_key_free(struct castle_norm_key *);

#endif  /* !defined(__CASTLE_KEYS_NORMALIZED_H__) */
