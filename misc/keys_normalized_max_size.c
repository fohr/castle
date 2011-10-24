/* compile with gcc -std=gnu99 */

#include <stdio.h>

/*
 * lifted from castle_keys_normalized.c
 */

#define ARRAY_SIZE(arr) (sizeof(arr) / sizeof((arr)[0]))

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

static size_t norm_key_lace_predict(size_t len)
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

/*
 * key size constants
 */

#define MIN_DIM_SIZE 4
#define MIN_KEY_SIZE 16
#define MAX_KEY_SIZE 512
#define MAX_DIMENSIONS ((MAX_KEY_SIZE - MIN_KEY_SIZE) / MIN_DIM_SIZE)

/*
 * dynamic programming tables
 */

static int norm_dim_len[MAX_KEY_SIZE+1];
static int norm_key_len[MAX_DIMENSIONS+1][MAX_KEY_SIZE+1];
static int norm_key_dim[MAX_DIMENSIONS+1][MAX_KEY_SIZE+1];

/*
 * dynamic programming functions
 */

static void print_dim_sizes(int dims, int key_size)
{
    printf("dimension sizes:");
    for ( ; dims > 0; --dims) {
	int dim_size = norm_key_dim[dims][key_size];
	printf(" %d", dim_size);
	key_size -= dim_size;
    }
    printf("\n");
}

static void tabulate_dim(void)
{
    for (int dim = MIN_DIM_SIZE; dim <= MAX_KEY_SIZE - MIN_KEY_SIZE; ++dim)
	norm_dim_len[dim] = norm_key_lace_predict(dim - MIN_DIM_SIZE);
}

static void tabulate_key(void)
{
    /* generate the first row -- O(n) */
    for (int key = MIN_KEY_SIZE + MIN_DIM_SIZE; key <= MAX_KEY_SIZE; ++key) {
	int dim = key - MIN_KEY_SIZE;
	norm_key_len[1][key] = 4 + norm_dim_len[dim];
	norm_key_dim[1][key] = dim;
    }
    printf("maximum key size for 1 dimension: %d\n",
	   norm_key_len[1][MAX_KEY_SIZE]);
    print_dim_sizes(1, MAX_KEY_SIZE);

    /* generate the rest of the rows -- O(n^3) */
    for (int dims = 2; dims <= MAX_DIMENSIONS; ++dims) {
	for (int key = MIN_KEY_SIZE + dims * MIN_DIM_SIZE;
	     key <= MAX_KEY_SIZE; ++key) {
	    for (int dim = MIN_DIM_SIZE; dim <= key - MIN_KEY_SIZE -
		     (dims-1) * MIN_DIM_SIZE; ++dim) {
		int key_size = norm_dim_len[dim] + norm_key_len[dims-1][key-dim];
		if (key_size > norm_key_len[dims][key]) {
		    norm_key_len[dims][key] = key_size;
		    norm_key_dim[dims][key] = dim;
		}
	    }
	}
	printf("maximum key size for %d dimensions: %d\n",
	       dims, norm_key_len[dims][MAX_KEY_SIZE]);
	print_dim_sizes(dims, MAX_KEY_SIZE);
    }
}

/*
 * main program function
 */

int main(void)
{
    tabulate_dim();
    tabulate_key();
    return 0;
}
