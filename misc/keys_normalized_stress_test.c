/* compilation instructions: comment out / #if out hash() and print() in both
 * castle_keys_normalized.c and castle_keys_normalized.h, then compile with `gcc
 * keys_normalized_stress_test.c ../kernel/castle_keys_vlba.c -o
 * keys_normalized_stress_test` */

#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <assert.h>
#include "../kernel/castle_keys_vlba.h"
#include "../kernel/castle_keys_normalized.c"

/*
 * Constant values.
 */

static const int SPECIAL_KEY_INV_PROB = 1000;
static const int SPECIAL_DIM_INV_PROB = 1000;

static const int MIN_DIMENSIONS = 0;
static const int MAX_DIMENSIONS = 127;

static const int MIN_DIM_LENGTH = 0;
static const int MAX_DIM_LENGTH = 2047;

/*
 * Random number generation.
 */

inline static int rand_limit(int lim)
{
    return rand() * (lim / (RAND_MAX + 1.0));
}
inline static int rand_range(int min, int max)
{
    return min + rand_limit(max - min + 1);
}
inline static int rand_dim() { return rand_range(MIN_DIMENSIONS, MAX_DIMENSIONS); }
inline static int rand_len() { return rand_range(MIN_DIM_LENGTH, MAX_DIM_LENGTH); }

static unsigned char *rand_bytes(unsigned char *buf, int len)
{
    int i;
    for (i = 0; i < len; ++i)
        *buf++ = rand_limit(256);
    return buf;
}

static unsigned char *rand_bytes_laced(unsigned char *buf, int len)
{
    STRIDE_INIT_VARS;
    size_t pos = 0;

    while (pos + stride < len)
    {
        rand_bytes(buf, stride);
        buf += stride;
        *buf++ = KEY_MARKER_CONTINUES;
        pos += stride;
        STRIDE_CHECK_BOUND(pos);
    }

    rand_bytes(buf, len - pos);
    memset(buf + (len - pos), 0x00, stride - (len - pos));
    buf += stride;
    *buf++ = KEY_MARKER_END_BASE + (len - pos) * 2;
    return buf;
}

/*
 * Memory allocation.
 */

void *castle_alloc_maybe(size_t len, void *dst, size_t *dst_len)
{
    if (!dst)
        return malloc(len);
    else if (dst_len && *dst_len >= len)
        return *dst_len = len, dst;
    else
        return NULL;
}

void *castle_dup_or_copy(const void *src, size_t src_len, void *dst, size_t *dst_len)
{
    if ((dst = castle_alloc_maybe(src_len, dst, dst_len)))
        memcpy(dst, src, src_len);
    return dst;
}

/*
 * VLBA key helper functions.
 */

static int vlba_key_is_special(const struct castle_var_length_btree_key *key)
{
    return key->length == VLBA_TREE_LENGTH_OF_MIN_KEY
        || key->length == VLBA_TREE_LENGTH_OF_MAX_KEY
        || key->length == VLBA_TREE_LENGTH_OF_INVAL_KEY;
}

static int vlba_key_compare(const struct castle_var_length_btree_key *key1,
                            const struct castle_var_length_btree_key *key2)
{
    int key1_min, key2_min, key1_max, key2_max;

    if (key1->length == VLBA_TREE_LENGTH_OF_INVAL_KEY &&
        key2->length == VLBA_TREE_LENGTH_OF_INVAL_KEY)
        return 0;
    if (key1->length == VLBA_TREE_LENGTH_OF_INVAL_KEY)
        return 1;
    if (key2->length == VLBA_TREE_LENGTH_OF_INVAL_KEY)
        return -1;

    key1_min = (key1->length == VLBA_TREE_LENGTH_OF_MIN_KEY);
    key2_min = (key2->length == VLBA_TREE_LENGTH_OF_MIN_KEY);
    if (key1_min || key2_min)
        return key2_min - key1_min;

    key1_max = (key1->length == VLBA_TREE_LENGTH_OF_MAX_KEY);
    key2_max = (key2->length == VLBA_TREE_LENGTH_OF_MAX_KEY);
    if (key1_max || key2_max)
        return key1_max - key2_max;

    return castle_object_btree_key_compare(key1, key2);
}

static unsigned int VLBA_SPECIAL_KEYS[] = {
    VLBA_TREE_LENGTH_OF_MIN_KEY,
    VLBA_TREE_LENGTH_OF_MAX_KEY,
    VLBA_TREE_LENGTH_OF_INVAL_KEY
};

static unsigned int VLBA_SPECIAL_DIMS[] = {
    KEY_DIMENSION_NEXT_FLAG,
    KEY_DIMENSION_MINUS_INFINITY_FLAG,
    KEY_DIMENSION_PLUS_INFINITY_FLAG
};

static struct castle_var_length_btree_key *vlba_key_construct_random()
{
    struct castle_var_length_btree_key *result;
    int prob, dim, length, offset, nr_dims, *dim_lens, *dim_flags;

    /* generate special keys at a small probability */
    if ((prob = rand_limit(SPECIAL_KEY_INV_PROB)) < sizeof VLBA_SPECIAL_KEYS / sizeof VLBA_SPECIAL_KEYS[0])
    {
        result = malloc(sizeof *result);
        result->length = VLBA_SPECIAL_KEYS[prob];
        result->nr_dims = 0;
        return result;
    }

    /* figure out the number of dimensions */
    nr_dims = rand_dim();
    length = sizeof *result + nr_dims * 4;
    offset = length;
    dim_lens = alloca(nr_dims * sizeof *dim_lens);
    dim_flags = alloca(nr_dims * sizeof *dim_flags);

    for (dim = 0; dim < nr_dims; ++dim)
    {
        /* generate special flags at a small probability */
        if ((prob = rand_limit(SPECIAL_DIM_INV_PROB)) < sizeof VLBA_SPECIAL_DIMS / sizeof VLBA_SPECIAL_DIMS[0])
            dim_flags[dim] = VLBA_SPECIAL_DIMS[prob];
        else
            dim_flags[dim] = 0;

        /* figure out the length of the dimension */
        if (!(dim_flags[dim] & KEY_DIMENSION_INFINITY_FLAGS_MASK))
        {
            dim_lens[dim] = rand_len();
            length += dim_lens[dim];
        }
        else dim_lens[dim] = 0;
    }

    /* construct the key */
    result = malloc(length);
    result->length = length - 4;
    result->nr_dims = nr_dims;
    for (dim = 0; dim < nr_dims; ++dim)
    {
        result->dim_head[dim] = (offset << 8) + dim_flags[dim];
        rand_bytes(((unsigned char *) result) + offset, dim_lens[dim]);
        offset += dim_lens[dim];
    }

    return result;
}

static struct castle_var_length_btree_key *vlba_key_strip_next_flag(struct castle_var_length_btree_key *key)
{
    int i;
    if (!vlba_key_is_special(key))
        for (i = 0; i < key->nr_dims; ++i)
            key->dim_head[i] &= ~KEY_DIMENSION_NEXT_FLAG;
    return key;
}

static void vlba_key_print(FILE *file, const struct castle_var_length_btree_key *key)
{
    unsigned int i, j;

    if (vlba_key_is_special(key))
    {
        fprintf(file, "%u\n", key->length);
        return;
    }

    fprintf(file, "%u %u%s", key->length, key->nr_dims, key->nr_dims > 0 ? " (" : "\n");
    for (i = 0; i < key->nr_dims; ++i)
        fprintf(file, "%u/%u%s", castle_object_btree_key_dim_length(key, i),
                castle_object_btree_key_dim_flags_get(key, i),
                i < key->nr_dims-1 ? " " : ")\n");
    return;

    for (i = 0; i < key->nr_dims; ++i)
    {
        unsigned char *dim = (unsigned char *) castle_object_btree_key_dim_get(key, i);
        fprintf(file, "%2u:", i);
        for (j = 0; j < castle_object_btree_key_dim_length(key, i); ++j)
        {
            if (j % 20 == 0 && j > 0)
                fprintf(file, "\n   ");
            fprintf(file, " %02X", dim[j]);
        }
        fprintf(file, "\n");
    }
}

/*
 * Normalized key helper functions.
 */

static unsigned int NORM_SPECIAL_KEYS[] = {
    NORM_KEY_LENGTH_MIN_KEY,
    NORM_KEY_LENGTH_MAX_KEY,
    NORM_KEY_LENGTH_INVAL_KEY
};

static struct castle_norm_key *norm_key_construct_random()
{
    struct castle_norm_key *result;
    unsigned char *data;
    int prob, dim, size, nr_dims, *dim_lens, *dim_flags;

    /* generate special keys at a small probability */
    if ((prob = rand_limit(SPECIAL_KEY_INV_PROB)) < sizeof NORM_SPECIAL_KEYS / sizeof NORM_SPECIAL_KEYS[0])
    {
        result = malloc(2);
        result->length = NORM_SPECIAL_KEYS[prob];
        return result;
    }

    /* figure out the number of dimensions */
    size = 0;
    nr_dims = rand_dim();
    dim_lens = alloca(nr_dims * sizeof *dim_lens);
    dim_flags = alloca(nr_dims * sizeof *dim_flags);
    for (dim = 0; dim < nr_dims; ++dim)
    {
        /* generate special flags at a small probability */
        if ((prob = rand_limit(SPECIAL_DIM_INV_PROB)) < sizeof VLBA_SPECIAL_DIMS / sizeof VLBA_SPECIAL_DIMS[0])
            dim_flags[dim] = VLBA_SPECIAL_DIMS[prob];
        else
            dim_flags[dim] = 0;

        /* figure out the length of the dimension */
        if (!(dim_flags[dim] & KEY_DIMENSION_INFINITY_FLAGS_MASK))
            dim_lens[dim] = rand_len();
        else
            dim_lens[dim] = 0;
        size += castle_norm_key_lace_predict(dim_lens[dim]);
    }
    size += NORM_KEY_DIM_SIZE(nr_dims);
    size = NORM_KEY_LENGTH_TO_SIZE(size);

    /* construct the key */
    result = malloc(size);
    castle_norm_key_len_put(result, &data, NORM_KEY_SIZE_TO_LENGTH(size));
    castle_norm_key_dim_put(&data, nr_dims);
    for (dim = 0; dim < nr_dims; ++dim)
    {
        if (dim_flags[dim] == KEY_DIMENSION_MINUS_INFINITY_FLAG)
        {
            data = castle_norm_key_pad(data, 0x00, KEY_MARKER_MINUS_INFINITY, STRIDE_VALUES[0]);
        }
        else if (dim_flags[dim] == KEY_DIMENSION_PLUS_INFINITY_FLAG)
        {
            data = castle_norm_key_pad(data, 0xff, KEY_MARKER_PLUS_INFINITY, STRIDE_VALUES[0]);
        }
        else
        {
            unsigned int dim_len = dim_lens[dim];
            data = rand_bytes_laced(data, dim_len);
            if (dim_flags[dim] == KEY_DIMENSION_NEXT_FLAG)
                *(data-1) |= 1;
        }
    }

    assert(data == (unsigned char *) result + size);
    return result;
}

static struct castle_norm_key *norm_key_strip_next_flag(struct castle_norm_key *key)
{
    const unsigned char *data, *end;
    if (NORM_KEY_SPECIAL(key))
        return key;

    end = castle_norm_key_end(key, &data);
    castle_norm_key_dim_get(&data);
    while (data < end) {
        STRIDE_INIT_VARS;
        size_t pos = 0;
        for (data += stride; *data == KEY_MARKER_CONTINUES; data += stride+1)
        {
            pos += stride;
            STRIDE_CHECK_BOUND(pos);
        }
        if (*data != KEY_MARKER_MINUS_INFINITY && *data != KEY_MARKER_PLUS_INFINITY)
            *((unsigned char *) data) = KEY_MARKER_END_BASE + ((*data - KEY_MARKER_END_BASE) & ~1);
        ++data;
    }
    return key;
}

static void norm_key_print(FILE *file, const struct castle_norm_key *key)
{
    unsigned int i, j, len, n_dim, *dim_lens;
    const unsigned char *data, *dim_data;

    if (NORM_KEY_SPECIAL(key))
    {
        fprintf(file, "%u\n", key->length);
        return;
    }
    len = castle_norm_key_len_get(key, &data);
    fprintf(file, "%u ", len);

    n_dim = castle_norm_key_dim_get(&data);
    fprintf(file, "%u (", n_dim);

    dim_lens = alloca(n_dim * sizeof dim_lens[0]);
    for (i = 0, dim_data = data; i < n_dim; ++i, ++dim_data)
    {
        unsigned int dim_len, flags = 0;
        dim_len = castle_norm_key_unlace_predict(&dim_data);
        --dim_data;
        if (*dim_data == KEY_MARKER_MINUS_INFINITY)
            flags |= KEY_DIMENSION_MINUS_INFINITY_FLAG;
        else if (*dim_data == KEY_MARKER_PLUS_INFINITY)
            flags |= KEY_DIMENSION_PLUS_INFINITY_FLAG;
        else if ((*dim_data - KEY_MARKER_END_BASE) % 2 == 1)
            flags |= KEY_DIMENSION_NEXT_FLAG;
        fprintf(file, "%u/%u%s", dim_len, flags, i < n_dim-1 ? " " : ")\n");
        dim_lens[i] = dim_len;
    }
    return;

    dim_data = data;
    for (i = 0; i < n_dim; ++i)
    {
        STRIDE_INIT_VARS;
        size_t pos = 0;
        fprintf(file, "%2u:", i);
        do
        {
            for (j = 0; j < stride; ++j, ++pos, ++dim_data)
                if (pos < dim_lens[i])
                    fprintf(file, " %02X", *dim_data);
            ++dim_data;
            STRIDE_CHECK_BOUND(pos);
        }
        while (pos < dim_lens[i]);
        fprintf(file, "\n");
    }
}

/*
 * Main program function.
 */

int main(int argc, char *argv[])
{
    int i, iterations;

    if (argc != 2)
    {
        fprintf(stderr, "usage: %s <iterations>\n", argv[0]);
        return 1;
    }
    iterations = atoi(argv[1]);

    for (i = iterations; i; --i)
    {
        int initial_cmp, converted_cmp, roundtrip_cmp, key1_cmp, key2_cmp;
        struct castle_var_length_btree_key *initial1, *initial2, *roundtrip1, *roundtrip2;
        struct castle_norm_key *converted1, *converted2;

        initial1 = vlba_key_construct_random();
        initial2 = vlba_key_construct_random();
        vlba_key_strip_next_flag(initial2);
        initial_cmp = vlba_key_compare(initial1, initial2);
        if (initial_cmp != 0)
            initial_cmp /= abs(initial_cmp);
        if (initial_cmp == 0 && initial1->nr_dims > 0)
            fprintf(stderr, "The keys are equal!\n");

        converted1 = castle_norm_key_pack(initial1, NULL, NULL);
        converted2 = castle_norm_key_pack(initial2, NULL, NULL);
        converted_cmp = castle_norm_key_compare(converted1, converted2);
        if (converted_cmp != 0)
            converted_cmp /= abs(converted_cmp);
        if (converted_cmp != initial_cmp)
        {
            fprintf(stderr, "The converted keys compare different than the initial ones!\n");
            vlba_key_print(stderr, initial1);
            norm_key_print(stderr, converted1);
            vlba_key_print(stderr, initial2);
            norm_key_print(stderr, converted2);
            abort();
        }

        roundtrip1 = castle_norm_key_unpack(converted1, NULL, NULL);
        roundtrip2 = castle_norm_key_unpack(converted2, NULL, NULL);
        roundtrip_cmp = vlba_key_compare(roundtrip1, roundtrip2);
        if (roundtrip_cmp != 0)
            roundtrip_cmp /= abs(roundtrip_cmp);
        if (roundtrip_cmp != converted_cmp)
        {
            fprintf(stderr, "The roundtrip keys compare different than the converted ones!\n");
            vlba_key_print(stderr, initial1);
            norm_key_print(stderr, converted1);
            vlba_key_print(stderr, roundtrip1);
            vlba_key_print(stderr, initial2);
            norm_key_print(stderr, converted2);
            vlba_key_print(stderr, roundtrip2);
            abort();
        }

        key1_cmp = vlba_key_compare(vlba_key_strip_next_flag(initial1),
                                    vlba_key_strip_next_flag(roundtrip1));
        key2_cmp = vlba_key_compare(initial2, roundtrip2);
        if (key1_cmp != 0)
        {
            fprintf(stderr, "The roundtrip keys are not equal to the initial ones!\n");
            vlba_key_print(stderr, initial1);
            norm_key_print(stderr, converted1);
            vlba_key_print(stderr, roundtrip1);
            abort();
        }
        if (key2_cmp != 0)
        {
            fprintf(stderr, "The roundtrip keys are not equal to the initial ones!\n");
            vlba_key_print(stderr, initial2);
            norm_key_print(stderr, converted2);
            vlba_key_print(stderr, roundtrip2);
            abort();
        }

        free(roundtrip2);
        free(roundtrip1);
        free(converted2);
        free(converted1);
        free(initial2);
        free(initial1);
    }

    for (i = iterations; i; --i)
    {
        int initial_cmp, converted_cmp, roundtrip_cmp, key1_cmp, key2_cmp;
        struct castle_norm_key *initial1, *initial2, *roundtrip1, *roundtrip2;
        struct castle_var_length_btree_key *converted1, *converted2;

        initial1 = norm_key_construct_random();
        initial2 = norm_key_construct_random();
        norm_key_strip_next_flag(initial2);
        initial_cmp = castle_norm_key_compare(initial1, initial2);
        if (initial_cmp != 0)
            initial_cmp /= abs(initial_cmp);
        if (initial_cmp == 0 && *(((uint16_t *) initial1) + 1) > 0)
            fprintf(stderr, "The keys are equal!\n");

        converted1 = castle_norm_key_unpack(initial1, NULL, NULL);
        converted2 = castle_norm_key_unpack(initial2, NULL, NULL);
        converted_cmp = vlba_key_compare(converted1, converted2);
        if (converted_cmp != 0)
            converted_cmp /= abs(converted_cmp);
        if (converted_cmp != initial_cmp)
        {
            fprintf(stderr, "The converted keys compare different than the initial ones!\n");
            norm_key_print(stderr, initial1);
            vlba_key_print(stderr, converted1);
            norm_key_print(stderr, initial2);
            vlba_key_print(stderr, converted2);
            abort();
        }

        roundtrip1 = castle_norm_key_pack(converted1, NULL, NULL);
        roundtrip2 = castle_norm_key_pack(converted2, NULL, NULL);
        roundtrip_cmp = castle_norm_key_compare(roundtrip1, roundtrip2);
        if (roundtrip_cmp != 0)
            roundtrip_cmp /= abs(roundtrip_cmp);
        if (roundtrip_cmp != converted_cmp)
        {
            fprintf(stderr, "The roundtrip keys compare different than the converted ones!\n");
            norm_key_print(stderr, initial1);
            vlba_key_print(stderr, converted1);
            norm_key_print(stderr, roundtrip1);
            norm_key_print(stderr, initial2);
            vlba_key_print(stderr, converted2);
            norm_key_print(stderr, roundtrip2);
            abort();
        }

        key1_cmp = castle_norm_key_compare(initial1, roundtrip1);
        key2_cmp = castle_norm_key_compare(initial2, roundtrip2);
        if (key1_cmp != 0)
        {
            fprintf(stderr, "The roundtrip keys are not equal to the initial ones!\n");
            norm_key_print(stderr, initial1);
            vlba_key_print(stderr, converted1);
            norm_key_print(stderr, roundtrip1);
            abort();
        }
        if (key2_cmp != 0)
        {
            fprintf(stderr, "The roundtrip keys are not equal to the initial ones!\n");
            norm_key_print(stderr, initial2);
            vlba_key_print(stderr, converted2);
            norm_key_print(stderr, roundtrip2);
            abort();
        }

        free(roundtrip2);
        free(roundtrip1);
        free(converted2);
        free(converted1);
        free(initial2);
        free(initial1);
    }

    return 0;
}
