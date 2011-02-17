#include <linux/bitops.h>

#include "castle.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_da.h"
#include "castle_bloom.h"
#include "castle_extent.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)            ((void)0)
#else
#define debug(_f, _a...)          (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int castle_bloom_use = 1; /* 1 or 0 */
module_param(castle_bloom_use, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_bloom_use, "Use bloom filters");

static int castle_bloom_hdd = 0; /* 0: SSD, 1: HDD */
module_param(castle_bloom_hdd, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_bloom_hdd, "Use bloom filters on SSD");

/* the expected fp probability is 2^{-ln 2 * BITS_PER_ELEMENTS} */
#define BLOOM_BITS_PER_ELEMENT        8
#define BLOOM_MAX_BITS_PER_ELEMENT    16
/* ensure CHUNK_SIZE % BLOCK_SIZE == 0 */
#define BLOOM_CHUNK_SIZE              (1*1024*1024)
#define BLOOM_CHUNK_SIZE_PAGES        (BLOOM_CHUNK_SIZE / PAGE_SIZE)
#define BLOOM_BLOCK_SIZE_HDD_PAGES    64
#define BLOOM_BLOCK_SIZE_SSD_PAGES    2
#define BLOOM_BLOCK_SIZE_PAGES        (castle_bloom_hdd ? BLOOM_BLOCK_SIZE_HDD_PAGES : BLOOM_BLOCK_SIZE_SSD_PAGES)
#define BLOOM_BLOCK_SIZE(_bf)         (uint32_t)(_bf->block_size_pages * PAGE_SIZE)
#define BLOOM_MAX_HASHES              opt_hashes_per_bit[BLOOM_MAX_BITS_PER_ELEMENT-1]
#define BLOOM_CHUNK_SIZE_BITS         (BLOOM_CHUNK_SIZE * 8)
#define BLOOM_BLOCK_SIZE_BITS(_bf)    (BLOOM_BLOCK_SIZE(_bf) * 8)
#define BLOOM_ELEMENTS_PER_CHUNK      (BLOOM_CHUNK_SIZE_BITS / BLOOM_BITS_PER_ELEMENT)
#define BLOOM_ELEMENTS_PER_BLOCK(_bf) (BLOOM_BLOCK_SIZE_BITS(_bf) / BLOOM_BITS_PER_ELEMENT)
#define BLOOM_BLOCKS_PER_CHUNK(_bf)   (BLOOM_CHUNK_SIZE / BLOOM_BLOCK_SIZE(_bf))
/* The seed to use when calculating the hash for the block ID. Should be different to the
 * seed (which is 0) given to the first hash function for within the block. */
#define BLOOM_BLOCK_HASH_SEED         1

/* the maximum number of chunks in a bloom filter for which we softpin */
#define BLOOM_MAX_SOFTPIN_CHUNKS      (castle_cache_size_get() / (5 * BLOOM_CHUNK_SIZE_PAGES))

#define LAST_CHUNK(_bf, _chunk_id)           (_chunk_id == _bf->num_chunks - 1)
#define BLOCKS_IN_CHUNK(_bf, _chunk_id)      (LAST_CHUNK(_bf, _chunk_id) ? _bf->num_blocks_last_chunk : BLOOM_BLOCKS_PER_CHUNK(_bf))

uint32_t opt_hashes_per_bit[] =
{ 0, 1, 2, 3, 3, 4, 5, 5, 6, 7, 7, 8, 9, 10, 10, 11, 12 };

#define ceiling(_a, _b)         ((_a - 1) / _b + 1)

/**** Bloom filter builds ****/

struct castle_bloom_build_params
{
    uint64_t expected_num_elements;
    uint64_t elements_inserted;
    uint32_t chunks_complete;
    uint32_t cur_node_cur_chunk_id;
    struct castle_btree_node *cur_node;
    c2_block_t *node_c2b;
    c_ext_pos_t node_cep;
    void *cur_chunk_buffer;
    c2_block_t *chunk_c2b;
    c_ext_pos_t chunk_cep;
    uint32_t cur_chunk_num_blocks;
    uint32_t nodes_complete;
#ifdef DEBUG
    uint32_t *elements_inserted_per_block;
#endif
};

/**
 * Initialize a bloom filter.  Call castle_bloom_add to add a key and
 * castle_bloom_complete when all keys are added.  Call castle_bloom_destory
 * to delete the bloom filter from disk.
 *
 * @param   bf      The Bloom filter to initialize
 * @param   da_id   The doubling array the bloom filter belongs to
 * @param   num_elements    Expected number of elements.  The actual number of elements added
 *                          can be less, but not more.
 */
int castle_bloom_create(castle_bloom_t *bf, da_id_t da_id, uint64_t num_elements)
{
    uint32_t bits_per_element = BLOOM_BITS_PER_ELEMENT;
    uint32_t num_hashes = opt_hashes_per_bit[bits_per_element];
    uint32_t num_blocks, blocks_remainder;
    uint64_t nodes_size, chunks_size, size;
    int ret = 0;
    struct castle_bloom_build_params *bf_bp;
    struct castle_btree_type *btree = castle_btree_type_get(RO_VLBA_TREE_TYPE);
    c_rda_type_t rda_type = castle_bloom_hdd ? DEFAULT_RDA : SSD_ONLY_EXT;

    BUG_ON(num_elements == 0);

    if (!castle_bloom_use)
        return -ENOSYS;

    bf->block_size_pages = BLOOM_BLOCK_SIZE_PAGES;

    bf->private = castle_malloc(sizeof(struct castle_bloom_build_params), GFP_KERNEL);
    if (!bf->private)
    {
        printk("Failed to alloc castle_bloom_t\n");
        ret = -ENOMEM;
        goto err0;
    }
    bf_bp = bf->private;
    memset(bf_bp, 0, sizeof(struct castle_bloom_build_params));

#ifdef DEBUG
    bf_bp->elements_inserted_per_block = castle_malloc(sizeof(uint32_t) * BLOOM_BLOCKS_PER_CHUNK(bf), GFP_KERNEL);
#endif

    bf_bp->expected_num_elements = num_elements;
    bf->num_hashes = num_hashes;
    /* The given number of elements may be less so this is a maximum.
     * bf->num_chunks is updated to the actual number in castle_bloom_complete */
    num_blocks = ceiling(num_elements, BLOOM_ELEMENTS_PER_BLOCK(bf));
    bf->num_chunks = ceiling(num_blocks, BLOOM_BLOCKS_PER_CHUNK(bf));
    /* Estimated, will be updated to correct number in castle_bloom_complete */
    bf->num_btree_nodes = ceiling(bf->num_chunks, btree->nr_max_entries);
    blocks_remainder = num_blocks % BLOOM_BLOCKS_PER_CHUNK(bf);
    if (blocks_remainder == 0)
        bf->num_blocks_last_chunk = BLOOM_BLOCKS_PER_CHUNK(bf);
    else
        bf->num_blocks_last_chunk = blocks_remainder;
    bf->btree = btree;

    nodes_size = bf->num_btree_nodes * btree->node_size * C_BLK_SIZE;
    chunks_size = num_blocks * BLOOM_BLOCK_SIZE(bf);
    size = nodes_size + chunks_size;

    debug("castle_bloom_create num_elements=%llu num_chunks=%u num_blocks=%u size=%llu num_blocks_last_chunk=%u num_btree_nodes=%u\n",
            num_elements, bf->num_chunks, num_blocks, size, bf->num_blocks_last_chunk, bf->num_btree_nodes);

    bf->ext_id = castle_extent_alloc(rda_type, da_id, ceiling(size, C_CHK_SIZE));
    if (EXT_ID_INVAL(bf->ext_id))
    {
        printk("Failed to create extent for bloom\n");
        ret = -ENOSPC;
        goto err1;
    }

    bf->chunks_offset = nodes_size;

    bf_bp->node_cep.ext_id = bf->ext_id;
    bf_bp->node_cep.offset = 0;

    bf_bp->chunk_cep.ext_id = bf->ext_id;
    bf_bp->chunk_cep.offset = bf->chunks_offset;

#ifdef CASTLE_BLOOM_FP_STATS
    atomic64_set(&bf->queries, 0);
    atomic64_set(&bf->false_positives, 0);
#endif

    BUG_ON(bf->num_blocks_last_chunk == 0);

    return 0;

err1:
#ifdef DEBUG
    castle_free(bf->private->elements_inserted_per_block);
#endif
    castle_free(bf->private);
    bf->private = NULL;
err0: return ret;
}

/**
 * Sets the cvt to insert into the node
 */
static void castle_bloom_fill_value(c_val_tup_t *cvt)
{
    cvt->type = CVT_TYPE_TOMB_STONE;
    cvt->length = 0;
    cvt->val = NULL;
}

static void castle_bloom_node_buffer_init(struct castle_btree_type *btree, struct castle_btree_node *buffer)
{
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
     Initialise the required bits of the node, so that the types don't complain. */
    buffer->magic = BTREE_NODE_MAGIC;
    buffer->type = btree->magic;
    buffer->version = 0;
    buffer->used = 0;
    buffer->is_leaf = 1;
    buffer->next_node = INVAL_EXT_POS;
}

/**
 * Called when a btree node is full
 */
static void castle_bloom_complete_btree_node(castle_bloom_t *bf)
{
    struct castle_bloom_build_params *bf_bp = bf->private;

    BUG_ON(bf_bp->cur_node == NULL);

    dirty_c2b(bf_bp->node_c2b);
    write_unlock_c2b(bf_bp->node_c2b);
    put_c2b(bf_bp->node_c2b);

    debug("btree_node completed, offset was %llu, ", bf_bp->node_cep.offset);

    bf_bp->node_cep.offset += bf->btree->node_size * C_BLK_SIZE;
    bf_bp->nodes_complete++;

    debug("now %llu.\n", bf_bp->node_cep.offset);
}

/**
 * Called to advance to the next (possibly the first) btree node
 */
static void castle_bloom_next_btree_node(castle_bloom_t *bf)
{
    struct castle_bloom_build_params *bf_bp = bf->private;

    if (bf_bp->cur_node != NULL)
        castle_bloom_complete_btree_node(bf);

    bf_bp->node_c2b = castle_cache_block_get(bf_bp->node_cep, ceiling(bf->btree->node_size * C_BLK_SIZE, PAGE_SIZE));
    write_lock_c2b(bf_bp->node_c2b);
    castle_cache_advise(bf_bp->node_c2b->cep, C2_ADV_SOFTPIN, -1, -1, 0);
    update_c2b(bf_bp->node_c2b);
    /* Init the node properly */
    bf_bp->cur_node = c2b_bnode(bf_bp->node_c2b);
    castle_bloom_node_buffer_init(bf->btree, bf_bp->cur_node);
}

/**
 * Called when a chunk is complete
 */
static void castle_bloom_complete_chunk(castle_bloom_t *bf)
{
    struct castle_bloom_build_params *bf_bp = bf->private;
#ifdef DEBUG
    uint32_t block, bit, bits_set = 0;
#endif

    BUG_ON(bf_bp->chunk_c2b == NULL);

#ifdef DEBUG
    for (block = 0; block < bf_bp->cur_chunk_num_blocks; block++)
    {
        bits_set = 0;
        for (bit = 0; bit < BLOOM_BLOCK_SIZE_BITS(bf); bit++)
            if (test_bit(bit + block * BLOOM_BLOCK_SIZE_BITS(bf), bf_bp->cur_chunk_buffer))
                bits_set++;
        debug("Chunk %u block %u has %u/%u bits set, %u values.\n", bf_bp->chunks_complete,
                block, bits_set, BLOOM_BLOCK_SIZE_BITS(bf), bf_bp->elements_inserted_per_block[block]);
        /* reset for the next chunk */
        bf_bp->elements_inserted_per_block[block] = 0;
    }
#endif

    dirty_c2b(bf_bp->chunk_c2b);
    write_unlock_c2b(bf_bp->chunk_c2b);
    put_c2b(bf_bp->chunk_c2b);

    bf_bp->chunks_complete++;
    debug("chunk completed, offset was %llu, ", bf_bp->chunk_cep.offset);
    bf_bp->chunk_cep.offset += BLOOM_CHUNK_SIZE;
    debug("now %llu.\n", bf_bp->chunk_cep.offset);
}

/**
 * Called to advance to the next (possibly the first) chunk
 */
static void castle_bloom_next_chunk(castle_bloom_t *bf)
{
    struct castle_bloom_build_params *bf_bp = bf->private;

    BUG_ON(bf->num_chunks > 1 && bf_bp->chunks_complete + 1 == bf->num_chunks);
    BUG_ON(bf->num_chunks == 1 && bf_bp->chunks_complete > 0);

    if (bf_bp->chunk_c2b != NULL)
        castle_bloom_complete_chunk(bf);

    bf_bp->cur_chunk_num_blocks = BLOCKS_IN_CHUNK(bf, bf_bp->chunks_complete);

    bf_bp->chunk_c2b = castle_cache_block_get(bf_bp->chunk_cep, bf_bp->cur_chunk_num_blocks * bf->block_size_pages);
    write_lock_c2b(bf_bp->chunk_c2b);
    if (bf->num_chunks <= BLOOM_MAX_SOFTPIN_CHUNKS)
        castle_cache_advise(bf_bp->chunk_c2b->cep, C2_ADV_SOFTPIN, -1, -1, 0);
    update_c2b(bf_bp->chunk_c2b);
    bf_bp->cur_chunk_buffer = c2b_buffer(bf_bp->chunk_c2b);
    memset(bf_bp->cur_chunk_buffer, 0, bf_bp->cur_chunk_num_blocks * BLOOM_BLOCK_SIZE(bf));
}

/**
 * Adds a key to the current btree node
 */
static void castle_bloom_add_index_key(castle_bloom_t *bf, void *key)
{
    version_t version = 0;
    c_val_tup_t cvt;
    struct castle_bloom_build_params *bf_bp = bf->private;

    if (bf_bp->cur_node == NULL || bf->btree->need_split(bf_bp->cur_node, 1))
    {
        bf_bp->cur_node_cur_chunk_id = 0;
        castle_bloom_next_btree_node(bf);
    } else
        bf_bp->cur_node_cur_chunk_id++;

    castle_bloom_fill_value(&cvt);
    debug("Adding key for chunk_id %u to btree node.\n", bf_bp->cur_node_cur_chunk_id);
    bf->btree->entry_add(bf_bp->cur_node, bf_bp->cur_node_cur_chunk_id, key, version, cvt);
}

/**
 * Finish the bloom filter.
 *
 * In the case of intersecting key sets during the merge the number of elements will be
 * less than the given.  This function ensures the bloom filter is completed correctly.
 */
void castle_bloom_complete(castle_bloom_t *bf)
{
    struct castle_bloom_build_params *bf_bp = bf->private;

    debug("castle_bloom_complete, elements inserted %llu, expected %llu\n", bf_bp->elements_inserted, bf_bp->expected_num_elements);

    /* if got less elements than expected, we will need to add in the key into the index here
     * we don't have a copy of the key here, so insert the largest key
     */
    if (bf_bp->elements_inserted < bf_bp->expected_num_elements)
        castle_bloom_add_index_key(bf, bf->btree->max_key);

    castle_bloom_complete_btree_node(bf);
    castle_bloom_complete_chunk(bf);

#ifdef DEBUG
    castle_free(bf_bp->elements_inserted_per_block);
#endif
    castle_free(bf->private);
    bf->private = NULL;

    /* set number of chunks to actual number */
    debug("actual num_chunks was %u, expected was %u.\n", bf_bp->chunks_complete, bf->num_chunks);
    bf->num_chunks = bf_bp->chunks_complete;
    /* set number of btree nodes to actual number */
    debug("actual num_btree_nodes was %u, expected was %u.\n", bf_bp->nodes_complete, bf->num_btree_nodes);
    bf->num_btree_nodes = bf_bp->nodes_complete;
}

/**
 * Remove a bloom filter from disk.
 */
void castle_bloom_destroy(castle_bloom_t *bf)
{
    c_ext_pos_t cep;
    uint32_t i, j;

    debug("castle_bloom_destroy.\n");
    BUG_ON(bf->private);

    /* unsoftpin everything from the cache */
    cep.ext_id = bf->ext_id;
    cep.offset = 0;

    /* btree nodes are always softpinned */
    for (i = 0; i < bf->num_btree_nodes; i++)
    {
        castle_cache_advise_clear(cep, C2_ADV_SOFTPIN, -1, -1, 0);
        cep.offset += bf->btree->node_size * C_BLK_SIZE;
    }

    /* chunks are only softpinned if the BF is small enough */
    if (bf->num_chunks <= BLOOM_MAX_SOFTPIN_CHUNKS)
    {
        for (i = 0; i < bf->num_chunks; i++)
        {
            for (j = 0; j < BLOCKS_IN_CHUNK(bf, i); j++)
            {
                castle_cache_advise_clear(cep, C2_ADV_SOFTPIN, -1, -1, 0);
                cep.offset += BLOOM_BLOCK_SIZE(bf);
            }
        }
    }

    castle_extent_free(bf->ext_id);
}

/**
 * Get the block ID for a given key
 *
 * @param   num_blocks  The number of blocks in the chunk containing this key
 *
 * @return              The block ID.  In range [0, num_blocks-1].
 */
static uint32_t castle_bloom_get_block_id(castle_bloom_t *bf, void *key, uint32_t num_blocks)
{
    uint32_t block_hash;

    BUG_ON(num_blocks == 0);

    block_hash = bf->btree->key_hash(key, BLOOM_BLOCK_HASH_SEED);
    return block_hash % num_blocks;
}

/**
 * Add a key to the bloom filter
 *
 * @param   btree   The btree type that the key belongs to (used for key_hash)
 */
void castle_bloom_add(castle_bloom_t *bf, struct castle_btree_type *btree, void *key)
{
    uint32_t block_id;
    uint32_t hash1, hash2, hash;
    uint64_t bit_offset;
    uint32_t i;
    struct castle_bloom_build_params *bf_bp = bf->private;

    BUG_ON(bf_bp->elements_inserted == bf_bp->expected_num_elements);

    /* the last element of this chunk */
    if (bf_bp->elements_inserted % BLOOM_ELEMENTS_PER_CHUNK == BLOOM_ELEMENTS_PER_CHUNK - 1 ||
            bf_bp->elements_inserted == bf_bp->expected_num_elements - 1)
    {
        castle_bloom_add_index_key(bf, key);
    }

    /* start a new chunk */
    if (bf_bp->elements_inserted % BLOOM_ELEMENTS_PER_CHUNK == 0)
    {
        BUG_ON(bf_bp->chunks_complete >= bf->num_chunks);
        castle_bloom_next_chunk(bf);
    }

    bf_bp->elements_inserted++;

    /* insert value into filter */
    block_id = castle_bloom_get_block_id(bf, key, bf_bp->cur_chunk_num_blocks);
    bit_offset = block_id * BLOOM_BLOCK_SIZE_BITS(bf);

#ifdef DEBUG
    bf_bp->elements_inserted_per_block[block_id]++;
#endif

    hash1 = bf->btree->key_hash(key, 0);
    hash2 = bf->btree->key_hash(key, hash1);

    for (i = 0; i < bf->num_hashes; i++)
    {
        hash = hash1 + i * hash2;
        __set_bit(hash % BLOOM_BLOCK_SIZE_BITS(bf) + bit_offset, bf_bp->cur_chunk_buffer);
    }
}

/**
 * Calculates which chunk the key is in from the index stored in the cache block.
 *
 * @param   btree_nodes_c2b The cache block that contains the first btree node
 * @param   cep             Offset is set on this to the correct chunk offset, can be NULL
 * @param   chunk_id_out    Is set to the chunk_id if not NULL
 *
 * @return 0 if out of range, non-zero otherwise. cep and chunk_id_out are set if not NULL.
 */
static int castle_bloom_get_chunk_id(castle_bloom_t *bf, void *key, c2_block_t *btree_nodes_c2b, c_ext_pos_t *cep, uint32_t *chunk_id_out)
{
    uint32_t chunk_id = 0;
    uint32_t node_index;
    int found_index = -1;
    struct castle_btree_node *node;
    void *buffer;
    void *last_key;
    struct castle_btree_type *btree = bf->btree;

    BUG_ON(cep == NULL && chunk_id_out == NULL);
    BUG_ON(!c2b_uptodate(btree_nodes_c2b));

    buffer = c2b_buffer(btree_nodes_c2b);

    for (node_index = 0; node_index < bf->num_btree_nodes; node_index++)
    {
        node = (struct castle_btree_node *)buffer;

        BUG_ON(node->used == 0);

        btree->entry_get(node, node->used - 1, &last_key, NULL, NULL);

        if (btree->key_compare(key, last_key) <= 0)
        {
            castle_btree_lub_find(node, key, 0, &found_index, NULL);
            BUG_ON(found_index < 0 || found_index >= node->used);
            chunk_id += found_index;
            break;
        }

        chunk_id += node->used;
        buffer += bf->btree->node_size * C_BLK_SIZE;
    }

    /* it was never found i.e. greater than the last chunk key */
    if (found_index < 0)
    {
        debug("Key is off the end of the partition index so trivially not in Bloom filter.\n");
        return 0;
    }

    if (cep != NULL)
    {
        cep->ext_id = bf->ext_id;
        cep->offset = bf->chunks_offset + chunk_id * BLOOM_CHUNK_SIZE;
    }

    if (chunk_id_out != NULL)
        *chunk_id_out = chunk_id;

    return 1;
}

/**** Lookup ****/

/**
 * Call graph.
 *
 * Have three workqueues: a, b and c.  These are used to ensure the c2b write_locks are not taken by the thread
 * that unlocks them.
 *
 * castle_bloom_submit
 *   |
 *   | schedule on workqueue a
 *   v
 * _castle_bloom_submit
 *   |
 *   v
 * castle_bloom_index_read
 *   |                |
 *   | in cache       | not in cache, schedule I/O. This should happen very rarely.
 *   |                |
 *   |                v
 *   |              castle_bloom_end_index_io
 *   |                |
 *   |                |  schedule on workqueue b
 *   |                v
 *   |      _castle_bloom_end_index_io
 *    \        /
 *     \      /
 *      \    /
 *       \  /
 *        \/
 * castle_bloom_index_process
 *   |                   |
 *   | found chunk ID    | not in any chunk
 *   |                   |
 *   |                   v
 *   |                 castle_bloom_lookup_next_ct -> castle_bloom_submit
 *   |
 *   v
 * castle_bloom_chunk_read
 *   |                 |
 *   | block in cache  | block not in cache, schedule I/O
 *   |                 |
 *   |                 v
 *   |               castle_bloom_end_block_io
 *   |                 |
 *   |                 | schedule on workqueue c
 *   |                 v
 *   |       _castle_bloom_end_block_io
 *    \        /
 *     \      /
 *      \    /
 *       \  /
 *        \/
 * castle_bloom_block_process
 *   |                 |
 *   | found           | not found
 *   |                 |
 *   |                 v
 *   |               castle_bloom_lookup_next_ct -> castle_bloom_submit
 *   |
 *   v
 * castle_btree_submit
 *   |                   |
 *   | if found          | if not found (false positive)
 *   v                   v
 * c_bvec->endfind     castle_bloom_submit
 */

/**
 * Lookup a key in the bloom filter
 *
 * @param   c2b         Cache block for the Bloom filter block to query
 * @param   btree       The btree type for the key we are querying. NB this is not necessarily
 *                      the same as bf->btree
 *
 * @return  0           if not found
 * @return  non-zero    if found
 */
static int castle_bloom_lookup(castle_bloom_t *bf, c2_block_t *c2b, struct castle_btree_type *btree, void *key)
{
    uint32_t hash1, hash2, hash;
    uint32_t i;
#ifdef CASTLE_BLOOM_FP_STATS
    uint64_t queries, false_positives;
#endif

    BUG_ON(!c2b_uptodate(c2b));

    /*
     * See Kirsch and Mitzenmacher, ESA 2006, LNCS 4168, pp 456-467, 2006 for why this works.
     *
     * There are currently 3 hash evaluations per query (one has already been done to determine the
     * block).  Since the Murmur hash we use returns 128 bits of data, provided k isn't too large,
     * (<= 7 for the default parameters) we actually have enough hash bits to do this in 1 lookup.
     * But it is unknown how independent the bits are for the murmur hash so leave it like this.
     *
     * A test showed that 1 million hash evaluations on the same key with the previous hash as the
     * seed took an average of 32 ns per evaluation on a VM.  So the hash is pretty cheap.
     */
    hash1 = btree->key_hash(key, 0);
    hash2 = btree->key_hash(key, hash1);

#ifdef CASTLE_BLOOM_FP_STATS
    queries = atomic64_inc_return(&bf->queries);

    if (queries % 10000 == 0 && queries > 0)
    {
        false_positives = atomic64_read(&bf->false_positives);
        printk("************ bf %p, false positive rate is %llu%% for %llu queries.\n", bf, 100 * false_positives / queries, queries);
    }
#endif

    for (i = 0; i < bf->num_hashes; i++)
    {
        hash = hash1 + i * hash2;
        if (!test_bit(hash % BLOOM_BLOCK_SIZE_BITS(bf), c2b_buffer(c2b)))
            return 0;
    }

    return 1;
}

/**
 * Used to advance the search to the next tree.  If none left, report not found.
 */
static void castle_bloom_lookup_next_ct(c_bvec_t *c_bvec)
{
    struct castle_component_tree *ct, *next_ct;

    ct = c_bvec->tree;

    next_ct = castle_da_ct_next(ct);
    if (!next_ct)
    {
        /* We've finished looking through all the trees. */
        c_bvec->endfind(c_bvec, 0, INVAL_VAL_TUP);
        return;
    }
    castle_ct_put(ct, 0);
    c_bvec->tree = next_ct;

    castle_bloom_submit(c_bvec);
}

/**
 * Process the block i.e. perform the actual bloom lookup
 */
static void castle_bloom_block_process(c_bvec_t *c_bvec)
{
    castle_bloom_t *bf;
    c2_block_t *chunk_c2b;
    void *key = c_bvec->key;
    int found;

    bf = &c_bvec->tree->bloom;
    chunk_c2b = c_bvec->bloom_c2b;
    c_bvec->bloom_c2b = NULL;

    BUG_ON(!c2b_uptodate(chunk_c2b));

    found = castle_bloom_lookup(bf, chunk_c2b, castle_btree_type_get(c_bvec->tree->btree_type), key);

    put_c2b(chunk_c2b);

    if (!found)
    {
        castle_bloom_lookup_next_ct(c_bvec);
        return;
    }

    /* Bloom says yes, let's do the btree walk */
#ifdef CASTLE_BLOOM_FP_STATS
    c_bvec->bloom_positive = 1;
#endif
    castle_btree_submit(c_bvec);
}

/**
 * Callback when the block has been retrieved
 */
static void _castle_bloom_end_block_io(void *data)
{
    c_bvec_t *c_bvec = data;

    BUG_ON(!c_bvec->bloom_c2b);
    BUG_ON(!c2b_uptodate(c_bvec->bloom_c2b));

    write_unlock_c2b(c_bvec->bloom_c2b);

    castle_bloom_block_process(c_bvec);
}

/**
 * Callback from doing I/O to get block. Could be in the interrupt context.
 */
static void castle_bloom_end_block_io(c2_block_t *c2b)
{
    c_bvec_t *c_bvec = c2b->private;

    INIT_WORK(&c_bvec->work, _castle_bloom_end_block_io, c_bvec);
    queue_work(castle_da_wqs[1], &c_bvec->work);
}

/**
 * Find the block and schedule I/O if required
 */
static void castle_bloom_chunk_read(c_bvec_t *c_bvec, uint32_t chunk_id)
{
    castle_bloom_t *bf;
    c_ext_pos_t chunk_cep;
    c2_block_t *chunk_c2b;
    void *key = c_bvec->key;

    bf = &c_bvec->tree->bloom;
    chunk_cep.ext_id = bf->ext_id;
    chunk_cep.offset = bf->chunks_offset + chunk_id * BLOOM_CHUNK_SIZE +
            castle_bloom_get_block_id(bf, key, BLOCKS_IN_CHUNK(bf, chunk_id)) * BLOOM_BLOCK_SIZE(bf);
    chunk_c2b = castle_cache_block_get(chunk_cep, bf->block_size_pages);

    c_bvec->bloom_c2b = chunk_c2b;

    if (!c2b_uptodate(chunk_c2b))
    {
        write_lock_c2b(chunk_c2b);
        /* now we have the lock, it might be up to date */
        if (c2b_uptodate(chunk_c2b))
        {
            write_unlock_c2b(chunk_c2b);
            castle_bloom_block_process(c_bvec);
            return;
        }
        if (bf->num_chunks <= BLOOM_MAX_SOFTPIN_CHUNKS)
            castle_cache_advise(chunk_c2b->cep, C2_ADV_SOFTPIN, -1, -1, 0);
        chunk_c2b->end_io = castle_bloom_end_block_io;
        chunk_c2b->private = c_bvec;

        debug("Bloom filter block not in cache, scheduling I/O at offset %llu for bf %p.\n", chunk_c2b->cep.offset, bf);

        BUG_ON(submit_c2b(READ, chunk_c2b));
    } else
        castle_bloom_block_process(c_bvec);
}

/**
 * Process the bloom filter index to find the chunk
 */
static void castle_bloom_index_process(c_bvec_t *c_bvec)
{
    uint32_t chunk_id = 0;
    castle_bloom_t *bf;
    c2_block_t *btree_nodes_c2b;
    void *key = c_bvec->key;
    int found;

    bf = &c_bvec->tree->bloom;
    btree_nodes_c2b = c_bvec->bloom_c2b;
    c_bvec->bloom_c2b = NULL;

    BUG_ON(!c2b_uptodate(btree_nodes_c2b));

    found = castle_bloom_get_chunk_id(bf, key, btree_nodes_c2b, NULL, &chunk_id);

    put_c2b(btree_nodes_c2b);

    if (!found)
        castle_bloom_lookup_next_ct(c_bvec);
    else
        castle_bloom_chunk_read(c_bvec, chunk_id);
}

/**
 * Callback when the index nodes have been retrieved.
 */
static void _castle_bloom_end_index_io(void *data)
{
    c_bvec_t *c_bvec = data;

    BUG_ON(!c_bvec->bloom_c2b);
    BUG_ON(!c2b_uptodate(c_bvec->bloom_c2b));

    write_unlock_c2b(c_bvec->bloom_c2b);

    castle_bloom_index_process(c_bvec);
}

/**
 * Callback from doing I/O to get partition index.
 * Could be in the interrupt context.
 */
static void castle_bloom_end_index_io(c2_block_t *c2b)
{
    c_bvec_t *c_bvec = c2b->private;

    INIT_WORK(&c_bvec->work, _castle_bloom_end_index_io, c_bvec);
    queue_work(castle_da_wqs[0], &c_bvec->work);
}

/**
 * Reads the btree node from cache/disk
 */
static void castle_bloom_index_read(c_bvec_t *c_bvec)
{
    castle_bloom_t *bf;
    c_ext_pos_t btree_nodes_cep;
    c2_block_t *btree_nodes_c2b;

    bf = &c_bvec->tree->bloom;
    btree_nodes_cep.ext_id = bf->ext_id;
    btree_nodes_cep.offset = 0;
    btree_nodes_c2b = castle_cache_block_get(btree_nodes_cep,
            ceiling(bf->num_btree_nodes * bf->btree->node_size * C_BLK_SIZE, PAGE_SIZE));

    c_bvec->bloom_c2b = btree_nodes_c2b;

    if (!c2b_uptodate(btree_nodes_c2b))
    {
        /* we expect to not get here very often as this will require 2 I/Os per lookup */

        write_lock_c2b(btree_nodes_c2b);
        /* now we have the lock, it might be up to date */
        if (c2b_uptodate(btree_nodes_c2b))
        {
            write_unlock_c2b(btree_nodes_c2b);
            castle_bloom_index_process(c_bvec);
            return;
        }
        castle_cache_advise(btree_nodes_c2b->cep, C2_ADV_SOFTPIN, -1, -1, 0);
        btree_nodes_c2b->end_io = castle_bloom_end_index_io;
        btree_nodes_c2b->private = c_bvec;

        printk("Bloom filter partition index not in cache, scheduling I/O at offset %llu for bf %p.\n", btree_nodes_c2b->cep.offset, bf);

        BUG_ON(submit_c2b(READ, btree_nodes_c2b));
    } else
    {
        castle_bloom_index_process(c_bvec);
    }
}

/**
 * Start the chain of calls to do a Bloom filter lookup
 */
static void _castle_bloom_submit(void *data)
{
    castle_bloom_index_read(data);
}

/**
 * Perform a lookup in the entire Bloom filter.
 *
 * @param   c_bvec      The bvec to query
 */
void castle_bloom_submit(c_bvec_t *c_bvec)
{
    /* bloom filters won't exist for unmerged trees i.e. T0s */
    if (!castle_bloom_use || !c_bvec->tree->bloom_exists)
        castle_btree_submit(c_bvec);
    else
    {
        INIT_WORK(&c_bvec->work, _castle_bloom_submit, c_bvec);
        queue_work(castle_wqs[19], &c_bvec->work);
    }
}

/**** Marshalling ****/

void castle_bloom_marshall(castle_bloom_t *bf, struct castle_clist_entry *ctm)
{
    ctm->bloom_num_hashes = bf->num_hashes;
    ctm->bloom_block_size_pages = bf->block_size_pages;
    ctm->bloom_num_chunks = bf->num_chunks;
    ctm->bloom_num_blocks_last_chunk = bf->num_blocks_last_chunk;
    ctm->bloom_chunks_offset = bf->chunks_offset;
    ctm->bloom_num_btree_nodes = bf->num_btree_nodes;
    ctm->bloom_ext_id = bf->ext_id;
}

void castle_bloom_unmarshall(castle_bloom_t *bf, struct castle_clist_entry *ctm)
{
    bf->num_hashes = ctm->bloom_num_hashes;
    bf->block_size_pages = ctm->bloom_block_size_pages;
    bf->num_chunks = ctm->bloom_num_chunks;
    bf->num_blocks_last_chunk = ctm->bloom_num_blocks_last_chunk;
    bf->chunks_offset = ctm->bloom_chunks_offset;
    bf->num_btree_nodes = ctm->bloom_num_btree_nodes;
    bf->btree = castle_btree_type_get(RO_VLBA_TREE_TYPE);
    bf->ext_id = ctm->bloom_ext_id;

    debug("castle_bloom_unmarshall ext_id=%llu num_chunks=%u num_blocks_last_chunk=%u chunks_offset=%llu num_btree_nodes=%u\n",
                bf->ext_id, bf->num_chunks, bf->num_blocks_last_chunk, bf->chunks_offset, bf->num_btree_nodes);

    castle_extent_mark_live(bf->ext_id);

    bf->private = NULL;

#ifdef CASTLE_BLOOM_FP_STATS
    atomic64_set(&bf->queries, 0);
    atomic64_set(&bf->false_positives, 0);
#endif
}
