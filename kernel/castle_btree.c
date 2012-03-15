#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_utils.h"
#include "castle_versions.h"
#include "castle_da.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define iter_debug(_f, ...)     ((void)0)
#define enum_debug(_f, ...)     ((void)0)
#define rq_debug(_f, ...)       ((void)0)
#else
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, "%s:%.60s:%.4d: " _f,           \
                                                __FILE__, __func__, __LINE__ , ##_a))
#define iter_debug(_f, _a...)   (castle_printk(LOG_DEBUG, "Iterator  :%.60s:%.4d:  " _f,  \
                                                __func__, __LINE__ , ##_a))
#define enum_debug(_f, _a...)   (castle_printk(LOG_DEBUG, "Enumerator:%.60s:%.4d:  " _f,  \
                                                __func__, __LINE__ , ##_a))
#define rq_debug(_f, _a...)     (castle_printk(LOG_DEBUG, "Range Query:%.60s:%.4d:  " _f, \
                                                __func__, __LINE__ , ##_a))
#endif

#define __XOR(a, b) (((a) && !(b)) || (!(a) && (b)))

static DECLARE_WAIT_QUEUE_HEAD(castle_btree_iters_wq);
static atomic_t castle_btree_iters_cnt = ATOMIC_INIT(0);

struct castle_btree_node_save {
    struct castle_component_tree   *ct;
    c_ext_pos_t                     node_cep;
    uint32_t                        node_size;
    struct work_struct              work;
};



/**********************************************************************************************/
/* Array of btree types */

/* Lifted from the VLBA tree code. Only here pending removal of the leaf pointer code. */
#define RW_TREES_MAX_ENTRIES 2500UL

extern struct castle_btree_type castle_mtree;
extern struct castle_btree_type castle_vlba_tree;
extern struct castle_btree_type castle_slim_tree;

static struct castle_btree_type *castle_btrees[1<<(8 * sizeof(btree_t))] =
                                                       {[MTREE_TYPE]        = &castle_mtree,
                                                        [VLBA_TREE_TYPE]    = &castle_vlba_tree,
                                                        [SLIM_TREE_TYPE]    = &castle_slim_tree};


struct castle_btree_type *castle_btree_type_get(btree_t type)
{
#ifdef CASTLE_DEBUG
    BUG_ON((type != MTREE_TYPE) &&
           (type != VLBA_TREE_TYPE) &&
           (type != SLIM_TREE_TYPE));
#endif
    return castle_btrees[type];
}

size_t castle_btree_node_size_get(btree_t type)
{
    switch (type) {
        case MTREE_TYPE:
            return MTREE_NODE_SIZE;
        case VLBA_TREE_TYPE:    /* note that the RO tree size is set in the merge code */
        case SLIM_TREE_TYPE:
            return RW_TREE_NODE_SIZE;
        default:                /* unknown tree type */
            return 0;
    }
}


/**********************************************************************************************/
/* Common modlist btree code */
void castle_btree_ct_lock(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
    {
        down_write(&c_bvec->tree->lock);
        set_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        down_read(&c_bvec->tree->lock);
        clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }

    set_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
}

void castle_btree_ct_unlock(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
    {
        BUG_ON(!test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags));
        up_write(&c_bvec->tree->lock);
    }
    else
    {
        BUG_ON(test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
        up_read(&c_bvec->tree->lock);
    }

    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
}

static inline c_ext_pos_t castle_btree_root_get(c_bvec_t *c_bvec)
{
    struct castle_attachment *att = c_bvec->c_bio->attachment;

    down_read(&att->lock);
    c_bvec->version = att->version;
    up_read(&att->lock);
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_btree_c2b_forget() */
    castle_btree_ct_lock(c_bvec);

    return c_bvec->tree->root_node;
}

static void castle_btree_c2b_forget(c_bvec_t *c_bvec);
static void __castle_btree_submit(c_bvec_t *c_bvec,
                                  c_ext_pos_t  node_cep,
                                  void *parent_key);


static void castle_btree_io_end(c_bvec_t    *c_bvec,
                                c_val_tup_t  cvt,
                                int          err)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_bvec->tree->btree_type);

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_IO_END);
    /* We allow:
       -   valid block and no error
       - invalid block and    error
       - invalid block and no error (reads from non-yet written block)
       We disallow:
       -   valid block and    error
       - invalid block and no error on writes
     */
    BUG_ON((!CVT_INVALID(cvt)) && (err));
    BUG_ON((c_bvec_data_dir(c_bvec) == WRITE) && (CVT_INVALID(cvt)) && (!err));

    /* Deallocate parent_key. */
    if ((c_bvec_data_dir(c_bvec) == WRITE) && c_bvec->parent_key)
    {
        btree->key_dealloc(c_bvec->parent_key);
        c_bvec->parent_key = NULL;
    }

    /* If DA timestamped, and successful write, update ct->max_user_timestamp */
    if( (c_bvec->tree) &&
            (!TREE_GLOBAL(c_bvec->tree->seq)) &&
            (castle_da_user_timestamping_check(c_bvec->tree->da))  &&
            (c_bvec_data_dir(c_bvec) == WRITE) &&
            (!err) )
    {
        castle_atomic64_max(cvt.user_timestamp,
                            &c_bvec->tree->max_user_timestamp);
        castle_atomic64_min(cvt.user_timestamp,
                            &c_bvec->tree->min_user_timestamp);
    }

    /* Acquire the necessary value resources for reads */
    if (!err && (c_bvec_data_dir(c_bvec) == READ))
    {
        BUG_ON(!c_bvec->val_get);
        c_bvec->val_get(&cvt);
    }

    /* Free the c2bs correctly. Call twice to release parent and child
       (if both exist) */
    castle_btree_c2b_forget(c_bvec);
    castle_btree_c2b_forget(c_bvec);
    /* Finish the IO */
    c_bvec->submit_complete(c_bvec, err, cvt);
}

static void USED castle_btree_node_print(struct castle_btree_type *t, struct castle_btree_node *node)
{
    castle_printk(LOG_DEBUG, "Printing node version=%d with used=%d, flags=%d\n",
                  node->version, node->used, node->flags);

    t->node_print(node);
}

void castle_btree_lub_find(struct castle_btree_node *node,
                                  void *key,
                                  c_ver_t version,
                                  int *lub_idx_p,
                                  int *insert_idx_p)
{
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    c_ver_t version_lub;
    void *key_lub = NULL;
    int lub_idx, insert_idx, low, high, mid;

#define insert_candidate(_x)    if(insert_idx < 0) insert_idx=(_x)
    debug("Looking for (k,v) = (%p, 0x%x), node->used=%d\n",
            key, version, node->used);
    /* We should not search for an invalid key */
    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
    if (btree->key_compare(key, btree->max_key) == 0)
        iter_debug("looking for max_key\n");

    /* Binary search on the keys to find LUB key */
    low = -1;           /* Key in entry pointed to by low is guaranteed
                           to be less than 'key' */
    high = node->used;  /* Key in entry pointed to be high is guaranteed
                           to be higher or equal to the 'key' */
    debug(" (lo,hi) = (%d, %d)\n", low, high);
    while(low != high-1)
    {
        int key_cmp;

        BUG_ON(high <= low);
        mid = (low + high) / 2;
        btree->entry_get(node, mid, &key_lub, NULL, NULL);
        key_cmp = btree->key_compare(key_lub, key);
        debug("mid=%d, key_cmp=%d\n", mid, key_cmp);
        if(key_cmp < 0)
            low = mid;
        else
            high = mid;
        debug(" (lo,hi) = (%d, %d)\n", low, high);
    }
    /* 'high' is now pointing to the LUB key (left-most copy if there are a few instances
        of it in the node), or past the end of the node.
        We should start scanning to the right starting with the entry pointed by high (if
        one exists). Going this direction keys increase and versions go from newest to
        oldest.
        Set the insertion_index as soon as we find a key greater than what we are looking
        for, or if equal keys, when the version is ancestral (then insert_idx == lub_idx).
     */
    insert_idx = -1;
    for(lub_idx=high; lub_idx < node->used; lub_idx++)
    {
        int cmp, anc;

        btree->entry_get(node, lub_idx, &key_lub, &version_lub, NULL);

        debug(" (k,v) = (%p, 0x%x)\n", key_lub, version_lub);

        /* First (k,v) that's an upper bound is guaranteed to be the correct lub,
           because versions are arranged from newest to oldest */
        cmp = btree->key_compare(key_lub, key);
        BUG_ON(cmp < 0);
        if(cmp > 0)
            insert_candidate(lub_idx);
        castle_version_is_ancestor_and_compare(version_lub, version, &anc, &cmp);
        /* cmp is computed based on DFS order. Therefore, cmp <= 0 implies that:
           dfs(version_lub) <= dfs(version). This in turn means that version_lub is
           greater/equal to version in reverse DFS order. */
        if(cmp <= 0)
            insert_candidate(lub_idx);
        if(anc)
        {
            /* If version_lub is ancestral to version, version_lub must also be
               smaller/equal to version in DFS ordering. */
            BUG_ON(cmp > 0);
            /* ... therefore insert_idx should have been set by now. */
            BUG_ON(insert_idx < 0);
            /* Ancestor found, break out of the loop. Lub_idx now correctly set. */
            break;
        }
    }

    BUG_ON(lub_idx > node->used);
    insert_candidate(node->used);
    if(lub_idx == node->used)
    {
        //castle_printk(LOG_DEBUG, "%s::node %p, hit end of the node\n", __FUNCTION__, node);
        lub_idx = -1;
    }
    //if(key_lub)
    //{
    //    castle_printk(LOG_DEBUG, "%s::node %p, key_lub : ", __FUNCTION__, node);
    //    btree->key_print(LOG_DEBUG, key_lub);
    //}
    //if(key)
    //{
    //    castle_printk(LOG_DEBUG, "%s::node %p, key : ", __FUNCTION__, node);
    //    btree->key_print(LOG_DEBUG, key);
    //}
    /* Return the indices */
    if(lub_idx_p) *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

/**
 * Initialize the btree node header. This is a convenience function that calls
 * castle_btree_node_buffer_init().
 *
 * @param ct          component tree this node will belong to
 * @param node        pointer to where the node lives in memory
 * @param version     version of the node
 * @param node_size   size of the node in pages
 * @param rev_level   level at which this node will be used, counted from the leaves
 */
void castle_btree_node_init(struct castle_component_tree *ct,
                            struct castle_btree_node *node,
                            int version,
                            uint16_t node_size,
                            uint8_t rev_level)
{
    uint8_t node_flags = 0;

    if (rev_level == 0)
        node_flags |= BTREE_NODE_IS_LEAF_FLAG;
    if (!TREE_GLOBAL(ct->seq) && castle_da_user_timestamping_check(ct->da))
        node_flags |= BTREE_NODE_HAS_TIMESTAMPS_FLAG;

    castle_btree_node_buffer_init(ct->btree_type, node, node_size, node_flags, version);
}

static int castle_btree_node_space_get(struct castle_component_tree *ct,
                                       c_ext_pos_t *cep,
                                       uint16_t rev_level,
                                       int was_preallocated)
{
    uint16_t node_size;
    int ret;

    /* Get the node size first. */
    node_size = ct->node_sizes[rev_level];
    /* Use separate extent for internal nodes. The only exception is when we are
       working with the global tree. */
    if(rev_level > 0)
    {
        c_ext_free_t *ext_free;

        ext_free = &ct->internal_ext_free;
        if (ct == castle_global_tree)
            ext_free = &ct->tree_ext_free;
        BUG_ON(EXT_ID_INVAL(ext_free->ext_id));
        /* We never preallocate space for internal nodes. */
        BUG_ON(was_preallocated);

        /* Allocate the space. */
        return castle_ext_freespace_get(ext_free,
                                        node_size * C_BLK_SIZE,
                                        0,
                                        cep);
    }

    /* Otherwise we are allocating space for a leaf node. We always preallocate it,
       except when working with the global ct. */
    BUG_ON(rev_level != 0);
    BUG_ON((atomic_read(&ct->tree_depth) > 0) &&
           (!was_preallocated ^ (ct == castle_global_tree)));

    ret = castle_ext_freespace_get(&ct->tree_ext_free,
                                   node_size * C_BLK_SIZE,
                                   was_preallocated,
                                   cep);
    /* BUG if we are trying to allocate more nodes that were pre-allocated. */
    BUG_ON(was_preallocated && ret);

    return ret;
}

/**
 * DA code preallocated space for the leafs, but not for the internal nodes.
 */
static int castle_btree_node_was_preallocated(struct castle_component_tree *ct, uint16_t rev_level)
{
    /* Block allocations are never preallocated. */
    if(ct == castle_global_tree)
        return 0;

    return (rev_level == 0 ? 1 : 0);
}

/**
 * Allocate and initialise c2b for a ct->type btree node.
 *
 * @param ct               Component tree this node will belong to.
 * @param version          Version of the node.
 * @param rev_level        Level at which this node will be used. Important: counted from leafs,
 *                         same as in btree_type->node_size().
 * @param was_preallocated Has the space for this node been preallocated.
 */
c2_block_t* castle_btree_node_create(struct castle_component_tree *ct,
                                     int version,
                                     uint16_t rev_level,
                                     int was_preallocated)
{
    struct castle_btree_node *node;
    c2_block_t *c2b;
    c_ext_pos_t cep;
    uint16_t node_size;

    /* Allocate freespace for the node. */
    BUG_ON(castle_btree_node_space_get(ct, &cep, rev_level, was_preallocated) < 0);

    /* Bet the cache block. */
    node_size = ct->node_sizes[rev_level];
    c2b = castle_cache_block_get(cep, node_size);
    write_lock_c2b(c2b);
    update_c2b(c2b);
    dirty_c2b(c2b);
    node = c2b_buffer(c2b);

    /* Initialise it. */
    castle_btree_node_init(ct, node, version, node_size, rev_level);

    return c2b;
}

static c2_block_t* castle_btree_effective_node_create(struct castle_component_tree *ct,
                                                      c_bvec_t *c_bvec,
                                                      c2_block_t *orig_c2b,
                                                      uint8_t level,
                                                      c_ver_t version)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node, *eff_node;
    c2_block_t *c2b;
    void *last_eff_key;
    c_ver_t last_eff_version = 0;
    int i, insert_idx, moved_cnt, was_preallocated, need_dirty;
    uint16_t node_size;
    uint8_t rev_level;

    rev_level = c_bvec->btree_levels - level;
    node = c2b_bnode(orig_c2b);
    if(node->version == version)
        return NULL;
    btree = castle_btree_type_get(node->type);
    node_size = ct->node_sizes[rev_level];

    /* First build effective node in memory and allocate disk space only if it
     * is not same as original node. */
    eff_node = castle_alloc(node_size * C_BLK_SIZE);
    /* rev_level == 0 should be equivalent to the IS_LEAF flag */
    BUG_ON((rev_level == 0) ^ (BTREE_NODE_IS_LEAF(node) != 0));
    castle_btree_node_init(ct, eff_node, version, node_size, rev_level);

    last_eff_key = btree->inv_key;
    BUG_ON(eff_node->used != 0);
    insert_idx = 0;
    moved_cnt = 0;
    need_dirty = 0;
    for(i=0; i<node->used; i++)
    {
        void        *entry_key;
        c_ver_t      entry_version;
        c_val_tup_t  entry_cvt;
        int          need_move, disabled;

        disabled = btree->entry_get(node, i, &entry_key, &entry_version, &entry_cvt);
        /* Check if slot->version is ancestral to version. If not,
           reject straight away. */
        if(!castle_version_is_ancestor(entry_version, version))
            continue;

        /* There are never meant to be disabled entries ancestral to the
           query version. If that was the case, the query (write) should have gone
           to the node that's currently handling that disabled key. */
        BUG_ON(disabled);

        /* Ignore all versions of the key except of the left-most (=> newest) one. */
        if(btree->key_compare(last_eff_key, entry_key) == 0)
        {
            /* Check that the version really is older */
            BUG_ON(!castle_version_is_ancestor(entry_version, last_eff_version));
            continue;
        }
        /* Copy directly if:
            - we are not looking at a leaf node
            - the entry is already a leaf pointer
            - we making the entry in the old node unreachable (that will happen
              if the effective node version is the same as the entry version,
              but different from the old node version)
         */
        need_move = (entry_version == version) && (node->version != version);
        //if (!BTREE_NODE_IS_LEAF(node) || CVT_LEAF_PTR(entry_cvt) || need_move)
        //{
            /* If already a leaf pointer, or a non-leaf entry copy directly. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             entry_cvt);
#if 0
        } else
        {
            c_val_tup_t cvt;
            CVT_LEAF_PTR_INIT(cvt, orig_c2b->nr_pages * C_BLK_SIZE, orig_c2b->cep);
            /* Otherwise construct a new leaf pointer. */
            btree->entry_add(eff_node,
                             insert_idx,
                             entry_key,
                             entry_version,
                             cvt);
        }
#endif

        /* Remember what the last key/version was, so that we know whether to take the
           next entry we see in the original node or not */
        last_eff_key = entry_key;
        last_eff_version = entry_version;
        /* If we _moved_ something, we need to remove it from the old node */
        if(need_move)
        {
            need_dirty = 1;
            btree->entry_disable(node, i);
        }

        insert_idx++;
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL.
       Note that effective node is only identical to the original node if the
       entries match, AND also the version of the node itself also matches.
     */
    if((node->version == version) && (eff_node->used == node->used))
    {
        BUG_ON(moved_cnt > 0);
        BUG_ON(need_dirty);
        castle_free(eff_node);

        return NULL;
    }

    if(need_dirty)
        dirty_c2b(orig_c2b);
    /* Effective node is not same as original node - allocate space on the disk
     * now and copy. */
    was_preallocated = castle_btree_node_was_preallocated(c_bvec->tree, rev_level);
    if(was_preallocated)
        atomic_dec(&c_bvec->reserv_nodes);
    c2b = castle_btree_node_create(c_bvec->tree,
                                   version,
                                   rev_level,
                                   was_preallocated);
    memcpy(c2b_buffer(c2b), eff_node, node_size * C_BLK_SIZE);
    castle_free(eff_node);

    return c2b;
}

static c2_block_t* castle_btree_node_key_split(c_bvec_t *c_bvec,
                                               c2_block_t *orig_c2b,
                                               uint8_t level)
{
    struct castle_component_tree *ct;
    struct castle_btree_node *node, *sec_node;
    struct castle_btree_type *btree;
    c2_block_t *c2b;
    uint8_t rev_level;
    int i, j, nr_moved, was_preallocated;

    void        *entry_key;
    c_ver_t      entry_version;
    c_val_tup_t  entry_cvt;

    rev_level = c_bvec->btree_levels - level;
    node      = c2b_bnode(orig_c2b);
    ct        = c_bvec->tree;
    btree     = castle_btree_type_get(ct->btree_type);
    was_preallocated
              = castle_btree_node_was_preallocated(c_bvec->tree, rev_level);
    c2b       = castle_btree_node_create(ct,
                                         node->version,
                                         rev_level,
                                         was_preallocated);
    if(was_preallocated)
        atomic_dec(&c_bvec->reserv_nodes);
    sec_node  = c2b_bnode(c2b);
    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in its parent would have to change. We want
       to avoid that */
    BUG_ON(sec_node->used != 0);
    nr_moved = btree->mid_entry(node);
    for(i=0, j=0; i<nr_moved; i++)
    {
        int disabled;

        /* Copy the entries. Skip disabled entries, since they aren't reachable
           any more (plus it is not possible to insert disabled entry at once). */
        disabled = btree->entry_get(node, i, &entry_key, &entry_version, &entry_cvt);
        if(disabled)
            continue;

        /* If the entry isn't disabled, just copy it over to the new node. */
        btree->entry_add(sec_node, j, entry_key, entry_version, entry_cvt);
        j++;
    }

    /* Check that at least one entry got inserted.
       The following (very unlikely) corner case may cause this to happen:
       * a node gets created in version v,
       * entries get inserted in version v', which is descendant of v
       * node becomes full, and a new node gets version split in version v',
         in the process all entries in v' get disabled in the original node
       * v' gets snapshot deleted, and v becomes writable again
       * a new write reaches the node, and since the version of the node is
         identical to the version of the insert, effective node is not created
         (this is deemed to be pointless, which, in most circumstances it is)
       * key split is called on the node, but it turns out that all entries in [0, nr_moved-1]
         range are disabled. This produces empty sec node.
       This could be handled, but since it is so unlikely to happen the destabilisation
       due to such handlers is more risky.
       However, an explicit test to catch such case needs to be in place. */
    BUG_ON(j == 0);

    /* Check that the number of entries in the new node is as many as we've inserted. */
    BUG_ON(sec_node->used != j);

    /* Drop entries from the original node. */
    btree->entries_drop(node, 0, nr_moved - 1);

    /* c2b has already been dirtied by the node_create() function, but the orig_c2b
       needs to be dirtied here */
    dirty_c2b(orig_c2b);

    return c2b;
}

static void castle_btree_slot_insert(c2_block_t  *c2b,
                                     int          index,
                                     void        *key,
                                     c_ver_t      version,
                                     c_val_tup_t  cvt)
{
    struct castle_btree_node *node = c2b_buffer(c2b);
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    void      *lub_key      = btree->inv_key;
    c_ver_t    lub_version  = INVAL_VERSION;
    c_val_tup_t lub_cvt;

    BUG_ON(index > node->used);

    if (CVT_ON_DISK(cvt) || CVT_NODE(cvt))
        debug("Inserting "cep_fmt_str" under index=%d\n", cep2str(cvt.cep), index);
    else
        debug("%s::Inserting an inline value under index=%d\n",
                __FUNCTION__, index);

    if(index < node->used)
        btree->entry_get(node, index, &lub_key, &lub_version, &lub_cvt);

    /* Special case. Newly inserted block may make another entry unreachable.
       This would cause problems with future splits. And therefore unreachable
       entry has to be replaced by the new one.
       The entry will stop being reachable if:
       - keys match
       - version to insert descendant from the left_version (and different)
       - version to insert the same as the node version
      If all of the above true, replace rather than insert.
      The now unreachable entry must necessarily be the previous LUB entry.
      Therefore it will be pointed to by index.
     */
    if((btree->key_compare(lub_key, key) == 0) &&
       (lub_version != version) &&
        castle_version_is_ancestor(lub_version, version) &&
       (version == node->version))
    {
        /* In leaf nodes the element we are replacing MUST be a leaf pointer,
           because lub_version is strictly ancestral to the node version.
           It implies that the key hasn't been inserted here, because
           keys are only inserted to weakly ancestral nodes */
        /* Replace the slot */
        btree->entry_replace(node, index, key, version, cvt);
        dirty_c2b(c2b);
        return;
    }
    /* Insert the new entry */
    btree->entry_add(node, index, key, version, cvt);
    BUG_ON(node->used >= RW_TREES_MAX_ENTRIES);
    dirty_c2b(c2b);
}

static void castle_btree_node_insert(c2_block_t *parent_c2b,
                                     c2_block_t *child_c2b)
{
    struct castle_btree_node    *parent = c2b_buffer(parent_c2b);
    struct castle_btree_node    *child  = c2b_buffer(child_c2b);
    struct castle_btree_type    *btree  = castle_btree_type_get(parent->type);
    c_ver_t                      version = child->version;
    void                        *key;
    int                          insert_idx;
    c_val_tup_t                  cvt;

    BUG_ON(castle_btree_type_get(child->type) != btree);
    btree->entry_get(child, child->used-1, &key, NULL, NULL);

    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    CVT_NODE_INIT(cvt, child->size * C_BLK_SIZE, child_c2b->cep);
    castle_btree_slot_insert(parent_c2b,
                             insert_idx,
                             key,
                             version,
                             cvt);
}

static void castle_btree_node_under_key_insert(c2_block_t *parent_c2b,
                                               c2_block_t *child_c2b,
                                               void *key,
                                               c_ver_t version)
{
    struct castle_btree_node    *parent = c2b_buffer(parent_c2b);
    struct castle_btree_node    *child  = c2b_buffer(child_c2b);
    struct castle_btree_type    *btree = castle_btree_type_get(parent->type);
    int                          insert_idx;
    c_val_tup_t                  cvt;

    BUG_ON(btree->key_compare(key, btree->inv_key) == 0);
    castle_btree_lub_find(parent, key, version, NULL, &insert_idx);
    debug("Inserting child node into parent (used=0x%x), "
          "will insert (k,v)=(%p, 0x%x) at idx=%d.\n",
            parent->used, key, version, insert_idx);
    CVT_NODE_INIT(cvt, child->size * C_BLK_SIZE, child_c2b->cep);
    castle_btree_slot_insert(parent_c2b,
                             insert_idx,
                             key,
                             version,
                             cvt);
}

static void castle_btree_new_root_create(c_bvec_t *c_bvec, btree_t type)
{
    c2_block_t *c2b;
    struct castle_component_tree *ct;

    ct = c_bvec->tree;
    debug("Creating a new root node, while handling write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Internal nodes (and the root node always is), are never preallocated. */
    BUG_ON(castle_btree_node_was_preallocated(c_bvec->tree, atomic_read(&ct->tree_depth)));
    /* Create the node */
    c2b = castle_btree_node_create(ct,
                                   0              /* version */,
                                   atomic_read(&ct->tree_depth) /* level */,
                                   0              /* wasn't preallocated */);
    /* We should be under write lock here, check if we can read lock it (and BUG) */
    BUG_ON(down_read_trylock(&ct->lock));
    ct->root_node = c2b->cep;
    atomic_inc(&ct->tree_depth);
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
    /* Release the version lock (c2b_forget will no longer do that,
       because there will be a parent node). */
    castle_btree_ct_unlock(c_bvec);
    /* Also, make sure that the PARENT_WRITE_LOCKED flag is set, so that the new
       root will get unlocked correctly */
    set_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
}

static int castle_btree_node_split(c_bvec_t *c_bvec)
{
    struct castle_btree_node *node, *eff_node, *split_node;
    c2_block_t *eff_c2b, *split_c2b, *retain_c2b, *parent_c2b;
    struct castle_btree_type *btree;
    void *key = c_bvec->key;
    uint32_t version = c_bvec->version;
    int new_root;

    debug("Node full while inserting (%p,0x%x), creating effective node for it.\n",
            key, version);
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
    eff_c2b = split_c2b = NULL;
    retain_c2b = c_bvec->btree_node;

    BUG_ON(!test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags) ||
           !test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
    /* Create the effective node */
    eff_c2b = castle_btree_effective_node_create(c_bvec->tree,
                                                 c_bvec,
                                                 retain_c2b,
                                                 c_bvec->btree_depth,
                                                 version);
    if(eff_c2b)
    {
        debug("Effective node NOT identical to the original node.\n");
        /* Cast eff_c2b buffer to eff_node */
        eff_node = c2b_buffer(eff_c2b);
        /* We should continue the walk with the effective node, rather than the
           original node */
        retain_c2b = eff_c2b;
    } else
    {
        debug("Effective node identical to the original node.\n");
        /* IMPORTANT: point eff_node to the original node, but DO NOT change eff_c2b.
           We need to remember what needs to be inserted into the parent node later */
        eff_node = node;
    }

    /* Split the effective node if it's more than 2/3s full */
    if(btree->need_split(eff_node, 1 /* key split */))
    {
        void *max_split_key;

        debug("Effective node too full, splitting.\n");
        split_c2b = castle_btree_node_key_split(c_bvec,
                                                eff_c2b ? eff_c2b : c_bvec->btree_node,
                                                c_bvec->btree_depth);
        split_node = c2b_buffer(split_c2b);
        BUG_ON(split_node->version != c_bvec->version);
        /* Work out whether to take the split node for the further btree walk.
           Since in the effective & split node there is at most one version
           for each key, and this version is ancestral to what we are
           looking for, it's enough to check if the last entry in the
           split node (that's the node that contains left hand side elements
           from the original effective node) is greater-or-equal to the block
           we are looking for */
        btree->entry_get(split_node, split_node->used-1, &max_split_key, NULL, NULL);
        if(btree->key_compare(max_split_key, key) >= 0)
        {
            debug("Retaining the split node.\n");
            retain_c2b = split_c2b;
        }
    }

    /* If we don't have a parent, we have to create a new root node. */
    new_root = 0;
    if(!c_bvec->btree_parent_node)
    {
        /* When we are splitting the root node there must be an effective node
           (i.e. effective node must not be identical to the original node).
           This is because we are writing in a version != 0, and the version of
           root node is always 0 */
        BUG_ON(!eff_c2b);

        debug("Creating new root node.\n");
        castle_btree_new_root_create(c_bvec, node->type);
        new_root = 1;
    }

    /* Work out if we have a parent */
    parent_c2b  = c_bvec->btree_parent_node;
    BUG_ON(!parent_c2b);
    /* Insert!
       This is a bit complex, due to number of different cases. Each is described below
       in some detail.

       If split node got created then it should be inserted with the
       usual (b,v) in the parent.
     */
    if(split_c2b)
    {
        debug("Inserting split node.\n");
        castle_btree_node_insert(parent_c2b, split_c2b);
    }

    /* If effective node got created (rather than using the original node) then
       it either needs to be inserted in the usual way, or under MAX key if we are
       inserting into the new root. */
    if(eff_c2b)
    {
        if(new_root)
        {
            debug("Inserting effective node under MAX block key.\n");
            castle_btree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               btree->max_key,
                                               c_bvec->version);
        } else
        {
            debug("Inserting effective node under the usual key.\n");
            castle_btree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               c_bvec->parent_key,
                                               c_bvec->version);
        }
    }

    /* Finally, if new root got created, we must also insert the original node into it.
       This should be inserted under MAX_KEY,and version 0 (this is the version of the node). */
    if(new_root)
    {
        debug("Inserting original root node under MAX block key.\n");
        castle_btree_node_under_key_insert(parent_c2b,
                                           c_bvec->btree_node,
                                           btree->max_key,
                                           0);
    }

    /* All nodes inserted. Now, unlock all children nodes, except of the
       one with which we'll continue the walk with (saved in retained_c2b) */
    if(retain_c2b != c_bvec->btree_node)
    {
        debug("Unlocking the original node.\n");
        write_unlock_c2b(c_bvec->btree_node);
        put_c2b(c_bvec->btree_node);
    }
    if(eff_c2b && (retain_c2b != eff_c2b))
    {
        debug("Unlocking the effective node.\n");
        write_unlock_c2b(eff_c2b);
        put_c2b(eff_c2b);
    }
    if(split_c2b && (retain_c2b != split_c2b))
    {
        debug("Unlocking the split node.\n");
        write_unlock_c2b(split_c2b);
        put_c2b(split_c2b);
    }

    /* Save the retained_c2b */
    c_bvec->btree_node = retain_c2b;

    return 0;
}

/**
 * Perform write (insert/replace/delete) on btree specified by c_bvec.
 *
 * - Perform node split if there are not enough empty slots
 * - Search for LUB for (key,version)
 * - If current node is not leaf, recurse via __castle_btree_submit()
 * - Otherwise we have a leaf node that satisfies (key,version)
 * - If entry at LUB doesn't match (key,version) insert (could also be
 *   replace/delete further up DA) via the cvt_get() callback handler
 * - If entry at LUB matches (key,version) replace(/delete) via the
 *   cvt_get() callback handler
 *
 * @also castle_btree_process()
 * @also castle_btree_read_process()
 * @also castle_object_replace_cvt_get()
 */
static void castle_btree_write_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    c_ver_t                      lub_version, version = c_bvec->version;
    int                          lub_idx, insert_idx, ret, lub_key_different;
    c_val_tup_t                  lub_cvt = INVAL_VAL_TUP;
    c_val_tup_t                  new_cvt = INVAL_VAL_TUP;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_WPROCESS);

    /* Check if the node needs to be split first.
       A leaf node only needs to be split if there are _no_ empty slots in it.
       Internal nodes, if there are less than 2 free slots in them.
       The exception is, if we got here following a leaf pointer. If that's the
       case, we know that we'll be updating in place.
     */
    if((btree->key_compare(c_bvec->parent_key, btree->inv_key) != 0) &&
       (btree->need_split(node, 0 /* version split */)))
    {
        debug("===> Splitting node: leaf=%d, used=%d\n", BTREE_NODE_IS_LEAF(node), node->used);
        ret = castle_btree_node_split(c_bvec);
        if(ret)
        {
            /* End the IO in failure */
            castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
            return;
        }
        /* Make sure that node now points to the correct node after split */
        node = c_bvec_bnode(c_bvec);
    }

    /* Find out what to follow, and where to insert */
    castle_btree_lub_find(node, key, version, &lub_idx, &insert_idx);
    BUG_ON((insert_idx < 0) || (insert_idx > node->used));
    if(lub_idx >= 0)
        btree->entry_get(node, lub_idx, &lub_key, &lub_version,
                         &lub_cvt);

    /* Deal with non-leaf nodes first */
    if (!BTREE_NODE_IS_LEAF(node))
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        debug("Following write down the tree.\n");
        if (!CVT_NODE(lub_cvt))
        {
            castle_printk(LOG_ERROR, "0x%x-%llu-"cep_fmt_str_nl,
                    lub_cvt.type,
                    (uint64_t)lub_cvt.length,
                   cep2str(lub_cvt.cep));
            BUG();
        }
        __castle_btree_submit(c_bvec, lub_cvt.cep, lub_key);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!BTREE_NODE_IS_LEAF(node));

    /* Insert an entry if LUB doesn't match our (key,version) precisely. */
    lub_key_different = 1;
    if((lub_idx < 0) ||
       (lub_key_different = btree->key_compare(lub_key, key)) ||
       (lub_version != version))
    {
        /* Get the CVT from the client. Since this is a new insert (and not
           a replace) only provide the ancestral entry (lub_cvt), if the key
           matches. */
        if ((ret = c_bvec->cvt_get(c_bvec,
                                   INVAL_VAL_TUP,
                                   lub_key_different ? INVAL_VAL_TUP : lub_cvt,
                                   &new_cvt)))
        {
            /* End the IO in failure */
            castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
            return;
        }

        atomic64_inc(&c_bvec->tree->item_count);

        debug("%s::Need to insert (%p, 0x%x) into node (used: 0x%x, leaf=%d).\n",
                __FUNCTION__, key, version, node->used, BTREE_NODE_IS_LEAF(node));
        BUG_ON(btree->key_compare(c_bvec->parent_key, btree->inv_key) == 0);
        castle_btree_slot_insert(c_bvec->btree_node,
                                 insert_idx,
                                 key,
                                 version,
                                 new_cvt);

        castle_btree_io_end(c_bvec, new_cvt, 0);
        return;
    }

    /* Final case: (key,version) found in the leaf node. */
    BUG_ON((btree->key_compare(lub_key, key) != 0) ||
           (lub_version != version));
    BUG_ON(lub_idx != insert_idx);

    /* Get CVT from the client. Provide the current CVT. Ancestor isn't necessary
       even if it exists, since exact match was found. */
    if ((ret = c_bvec->cvt_get(c_bvec, lub_cvt, INVAL_VAL_TUP, &new_cvt)))
    {
       /* End the IO in failure */
       castle_btree_io_end(c_bvec, INVAL_VAL_TUP, ret);
       return;
    }

    btree->entry_replace(node, lub_idx, key, lub_version,
                         new_cvt);
    dirty_c2b(c_bvec->btree_node);
    debug("Key already exists, modifying in place.\n");
    castle_btree_io_end(c_bvec, new_cvt, 0);

}

/**
 * Performs counter accumulation over versions. It works for both RW and RO trees.
 * Starts from the specified location in the specified btree node, terminates
 * when accumulation terminates (on a set, or object), or when no more entries
 * for the specified key exist.
 *
 * @param node      Btree node containing the counter (all of its versions).
 * @param version   Version in which the query is performed.
 * @param key       Counter key.
 * @param idx       Index to the most recent version of the counter key.
 * @param cvt       Most recent counter CVT.
 *
 * @return Accumulated counter. Returned as a local counter.
 */
static c_val_tup_t castle_btree_counter_read(struct castle_btree_node *node,
                                             c_ver_t version,
                                             void *key,
                                             int idx,
                                             c_val_tup_t cvt)
{
    struct castle_btree_type *btree = castle_btree_type_get(node->type);
    c_val_tup_t accumulator, next_cvt;
    c_ver_t next_version;
    void *next_key;
    int finish;

    /* Accumulating counters already dealt with accumulations, read the right subcounter off. */
    if(CVT_ACCUM_COUNTER(cvt))
    {
        CVT_COUNTER_ACCUM_ALLV_TO_LOCAL(accumulator, cvt);
        accumulator.user_timestamp = cvt.user_timestamp;
        return accumulator;
    }

    /* Otherwise init the accumulator. */
    CVT_COUNTER_LOCAL_ADD_INIT(accumulator, 0);
    /* we don't support timestamped counters but let's explicitly set the timestamp field anyway */
    accumulator.user_timestamp = 0;

    /* Accumulate the start cvt. */
    finish = castle_counter_simple_reduce(&accumulator, cvt);

    /* Go through all CVTs that are weakly ancestral entries. */
    idx++;
    while(!finish && (idx < node->used))
    {
        /* Get the entry from the node. */
        btree->entry_get(node, idx, &next_key, &next_version, &next_cvt);

        /* Check whether the key hasn't changed, terminate if so. */
        if(btree->key_compare(next_key, key) != 0)
            return accumulator;

        /* Accumulate iff version of the entry is ancestral. */
        if(castle_version_is_ancestor(next_version, version))
            finish = castle_counter_simple_reduce(&accumulator, next_cvt);

        /* Read the next entry in the node. */
        idx++;
    }

    return accumulator;
}

/**
 * Perform read on btree specified by c_bvec.
 *
 * @also castle_btree_process()
 * @also castle_btree_write_process()
 */
static void castle_btree_read_process(c_bvec_t *c_bvec)
{
    struct castle_btree_node    *node = c_bvec_bnode(c_bvec);
    struct castle_btree_type    *btree = castle_btree_type_get(node->type);
    void                        *lub_key, *key = c_bvec->key;
    c_ver_t                      lub_version, version = c_bvec->version;
    int                          lub_idx;
    c_val_tup_t                  lub_cvt;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_RPROCESS);

    castle_btree_lub_find(node, key, version, &lub_idx, NULL);
    /* We should always find the LUB if we are not looking at a leaf node */
    /* UPDATE: now that we're doing orphan node preadoption and query redirection, this
               assertion is no longer true, so disable the BUG_ON. */
    //BUG_ON((lub_idx < 0) && (!BTREE_NODE_IS_LEAF(node)));

    /* If we haven't found the LUB (in the leaf node), return early */
    if (lub_idx < 0)
    {
        debug("Could not find the LUB for (k,v)=(%p, 0x%x)\n", key, version);
        castle_btree_io_end(c_bvec, INVAL_VAL_TUP, 0);
        return;
    }

    btree->entry_get(node, lub_idx, &lub_key, &lub_version, &lub_cvt);
    /* If we found the LUB, either complete the tree walk (if we are looking at a leaf). */
    if (BTREE_NODE_IS_LEAF(node))
    {
        BUG_ON(!CVT_LEAF_VAL(lub_cvt));
        if (CVT_ON_DISK(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), cep="cep_fmt_str_nl,
                    lub_key, lub_version, lub_cvt.cep.ext_id,
                    cep2str(lub_cvt.cep));
        else if (CVT_INLINE(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), inline value\n",
                    lub_key, lub_version);
        else if (CVT_TOMBSTONE(lub_cvt))
            debug(" Is a leaf, found (k,v)=(%p, 0x%x), tomb stone\n",
                    lub_key, lub_version);

        if (btree->key_compare(lub_key, key) == 0)
        {
            /* Deal with counters first. Accumulate if necessary. */
            if (CVT_ANY_COUNTER(lub_cvt))
                lub_cvt = castle_btree_counter_read(node, version, key, lub_idx, lub_cvt);
            castle_btree_io_end(c_bvec, lub_cvt, 0);
        }
        else castle_btree_io_end(c_bvec, INVAL_VAL_TUP, 0);
    }
    else
    {
        BUG_ON(CVT_LEAF_VAL(lub_cvt));
        if (CVT_NODE(lub_cvt))
            debug("Child node. Read and search - inline value\n");
        else
            BUG();
        /* parent_key is not needed when reading (also, we might be looking at a leaf ptr)
           use INVAL key instead. */
        __castle_btree_submit(c_bvec, lub_cvt.cep, btree->inv_key);
    }
}

/**
 * Perform actual query on btree.
 *
 * @also __castle_btree_submit()
 * @also castle_btree_write_process()
 * @also castle_btree_read_process()
 */
void castle_btree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if (write)
        castle_btree_write_process(c_bvec);
    else
        castle_btree_read_process(c_bvec);
}

static void castle_btree_c2b_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE), write_unlock;
    c2_block_t *c2b_to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    c2b_to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    write_unlock = (write ? test_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags) :
                            test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags));
    /* Release the buffer if one exists */
    if (c2b_to_forget)
    {
        if (write_unlock)
            write_unlock_c2b(c2b_to_forget);
        else
            read_unlock_node(c2b_to_forget);

        put_c2b(c2b_to_forget);
    }
    /* Also, release the component tree lock.
       On reads release as soon as possible. On writes make sure that we've got
       btree_node c2b locked. */
    if(test_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags) && (!write || c_bvec->btree_node))
        castle_btree_ct_unlock(c_bvec);
    /* Promote node to the parent on writes */
    if(write)
    {
        c_bvec->btree_parent_node = c_bvec->btree_node;
        if(test_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags))
            set_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
        else
            clear_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
    }
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_btree_c2b_remember(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    /* Save the new node buffer, and the lock flags */
    c_bvec->btree_node = c2b;
    if (test_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags))
    {
        BUG_ON(!c2b_write_locked(c2b));
        set_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        BUG_ON(!c2b_read_locked(c2b));
        clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    }
}


static void castle_btree_c2b_lock(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

#ifdef CASTLE_DEBUG
    c_bvec->locking = c2b;
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_GOT_NODE);
    /* Lock the c2b in the write mode if:
       - c2b not up-to-date (doesn't matter if we are doing a read or a write,
       - on writes, if we reached leaf level (possibly following leaf pointers)
       - on writes, if we are doing splits
     */
    if (!c2b_uptodate(c2b) || write)
    {
        write_lock_c2b(c2b);
        set_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    }
    else
    {
        read_lock_node(c2b);
        clear_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    }
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_LOCKED_NODE);
}

/**
 * Queues bvec on the right workqueue, on the right CPU (if one was specified).
 *
 * @param c_bvec    Castle bio vec to queue.
 */
static void castle_btree_bvec_queue(c_bvec_t *c_bvec)
{
    if(c_bvec->cpu >= 0)
        queue_work_on(c_bvec->cpu, castle_wqs[c_bvec->btree_depth], &c_bvec->work);
    else
        queue_work(castle_wqs[c_bvec->btree_depth], &c_bvec->work);
}

static void castle_btree_submit_io_end(c2_block_t *c2b)
{
#ifdef CASTLE_DEBUG
    struct castle_btree_node *node;
    struct castle_btree_type *btree;
#endif
    c_bvec_t *c_bvec = c2b->private;

    debug("Finished IO for: key %p, in version 0x%x\n",
            c_bvec->key, c_bvec->version);

    /* Callback on error */
    if(!c2b_uptodate(c2b))
    {
        castle_btree_io_end(c_bvec, INVAL_VAL_TUP, -EIO);
        return;
    }
    castle_btree_c2b_remember(c_bvec, c2b);
#ifdef CASTLE_DEBUG
    node = c_bvec_bnode(c_bvec);
    btree = castle_btree_type_get(node->type);
    /* @TODO: This function runs in interrupt context and node_validate might
     * block due to kmalloc() */
    btree->node_validate(node);
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);

    BUG_ON(c_bvec->btree_depth > MAX_BTREE_DEPTH);
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree.
       A single queue cannot be used, because a request blocked on
       lock_c2b() would block the entire queue (=> deadlock). */
    CASTLE_INIT_WORK(&c_bvec->work, castle_btree_process);
    castle_btree_bvec_queue(c_bvec);
}

static void __castle_btree_submit(c_bvec_t *c_bvec,
                                  c_ext_pos_t node_cep,
                                  void *parent_key)
{
    struct castle_component_tree *ct;
    struct castle_btree_type *btree;
    c2_block_t *c2b;
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    debug("%s::[%p] Asked for key: %p, in version 0x%x, on ct %d, reading ftree node" cep_fmt_str_nl,
            __FUNCTION__, c_bvec, c_bvec->key, c_bvec->version, c_bvec->tree->seq, cep2str(node_cep));

    ct = c_bvec->tree;
    btree = castle_btree_type_get(ct->btree_type);
    c_bvec->btree_depth++;

    if (write)
    {
        if (c_bvec->parent_key)
            btree->key_dealloc(c_bvec->parent_key);
        c_bvec->parent_key = btree->key_copy(parent_key, NULL, NULL);
    }

    castle_debug_bvec_btree_walk(c_bvec);

    /* On writes we can drop the lock on the grandparent node _before_ acquiring lock
       on the child. */
    if(write)
        castle_btree_c2b_forget(c_bvec);
    /* Get the cache block for the next node. */
    c2b = castle_cache_block_get(node_cep,
                                 ct->node_sizes[c_bvec->btree_levels - c_bvec->btree_depth]);
    castle_btree_c2b_lock(c_bvec, c2b);
    /* On reads, the parent can only be unlocked _after_ child got locked. */
    if(!write)
        castle_btree_c2b_forget(c_bvec);

    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_OUTOFDATE);
        c2b->private = c_bvec;
        c2b->end_io = castle_btree_submit_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    }
    else
    {
        /* sanity check */
        struct castle_btree_node *node;
        node = c2b_bnode(c2b);
        BUG_ON(node->magic != BTREE_NODE_MAGIC);
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2b_remember should not return an error, because
           the Btree node had been normalized already. */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
        castle_btree_c2b_remember(c_bvec, c2b);
        castle_btree_process(&c_bvec->work);
    }
}

/**
 * Submit request to btree (workqueue function).
 *
 * - Queuer should have placed us such that we are running on the
 *   request_cpus.cpus[] cpu that matches c_bvec->tree (CPU-affinity for T0 CT)
 * - Except for some stateful ops and gets we expect to go largely uncontended
 *   for CT locks
 */
static void _castle_btree_submit(struct work_struct *work)
{
    struct castle_component_tree *ct;
    struct castle_btree_type *btree;
    c_ext_pos_t root_cep;
    c_bvec_t *c_bvec;

    /* Work out various request details. */
    c_bvec = container_of(work, c_bvec_t, work);
    ct = c_bvec->tree;
    btree = castle_btree_type_get(ct->btree_type);

    /* Prepare the state flags, etc. */
    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    clear_bit(CBV_PARENT_WRITE_LOCKED, &c_bvec->flags);
    clear_bit(CBV_CHILD_WRITE_LOCKED, &c_bvec->flags);
    clear_bit(CBV_C2B_WRITE_LOCKED, &c_bvec->flags);
    /* This will lock the component tree. */
    root_cep = castle_btree_root_get(c_bvec);
    /* Number of levels in the tree can be read safely now */
    c_bvec->btree_levels = atomic_read(&ct->tree_depth);
    BUG_ON(EXT_POS_INVAL(root_cep));
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_btree_submit(c_bvec, root_cep, btree->max_key);
}

/**
 * Submit request to the btree.
 *
 * @param   c_bvec      Request to submit
 * @param   go_async    Whether to go asynchronous
 */
void castle_btree_submit(c_bvec_t *c_bvec, int go_async)
{
    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    c_bvec->parent_key        = NULL;

    CASTLE_INIT_WORK(&c_bvec->work, _castle_btree_submit);

    if (go_async)
        /* Submit asynchronously. */
        castle_btree_bvec_queue(c_bvec);
    else
        /* Submit directly. */
        _castle_btree_submit(&c_bvec->work);
}

/**********************************************************************************************/
/* Btree iterator */

static void castle_btree_iter_version_key_dealloc(c_iter_t *c_iter)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);

    if(c_iter->next_key.need_destroy)
        btree->key_dealloc(c_iter->next_key.key);
}

/* Put c2b's on the path from given depth. from = 0 means put entire path */
static void castle_btree_iter_path_put(c_iter_t *c_iter, int from)
{
    int i = 0;
    iter_debug("From=%d\n", from);

    for (i = from; i<MAX_BTREE_DEPTH; i++)
    {
        if(c_iter->path[i] == NULL)
            continue;

        put_c2b(c_iter->path[i]);
        c_iter->path[i] = NULL;
    }
}

static void castle_btree_iter_end(c_iter_t *c_iter, int err, int async)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);

    iter_debug("Putting path, ending\n");


    castle_btree_iter_version_key_dealloc(c_iter);
    btree->key_dealloc(c_iter->parent_key);

    castle_btree_iter_path_put(c_iter, 0);

    /* Run end() callback, if specified.  We should not need to reset
     * running_async here as the iterator is being terminated. */
    if (c_iter->end)
        c_iter->end(c_iter, err, c_iter->running_async);

    atomic_dec(&castle_btree_iters_cnt);
    wake_up(&castle_btree_iters_wq);
}

static int  __castle_btree_iter_start(c_iter_t *c_iter);

static void __castle_btree_iter_release(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    c2_block_t *leaf;

    iter_debug("Releasing leaf node.\n");
    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!BTREE_NODE_IS_LEAF(node));

    iter_debug("%p unlocks leaf (0x%x, 0x%x)\n",
        c_iter, leaf->cep.ext_id, leaf->cep.offset);
    read_unlock_node(leaf);
}

/**
 * Reschedule and continue iterating.
 */
void castle_btree_iter_continue(c_iter_t *c_iter)
{
    __castle_btree_iter_release(c_iter);
    castle_btree_iter_start(c_iter);
}

void castle_iter_parent_key_set(c_iter_t *iter, void *key)
{
    struct castle_btree_type *btree = castle_btree_type_get(iter->tree->btree_type);
#ifdef DEBUG
    iter_debug("iter %p key: ", iter);
    btree->key_print(LOG_DEBUG, key);
#endif
    if (iter->parent_key)
        btree->key_dealloc(iter->parent_key);
    iter->parent_key = btree->key_copy(key, NULL, NULL);
}

static int castle_btree_iter_version_leaf_process(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c2_block_t *leaf;
    int running_async, i;

    BUG_ON(VERSION_INVAL(c_iter->version));

    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!BTREE_NODE_IS_LEAF(node));

    iter_debug("Processing %d entries\n", node->used);

    /* We are in a leaf, then save the vblk number we followed to get here */
    castle_btree_iter_version_key_dealloc(c_iter);
    if (btree->key_compare(c_iter->parent_key, btree->inv_key) == 0)
    {
        c_iter->next_key.key          = btree->inv_key;
        c_iter->next_key.need_destroy = 0;
    }
    else
    {
        c_iter->next_key.key          = btree->key_next(c_iter->parent_key, NULL, NULL);
        c_iter->next_key.need_destroy = 1;
    }

    /* Perform consumer setup and determine index to start searching node. */
    if (c_iter->node_start != NULL)
        i = c_iter->node_start(c_iter);
    else
        i = 0;

    for (; i < node->used; i++)
    {
        c_ver_t     entry_version;
        c_val_tup_t entry_cvt;
        void       *entry_key;
        int         disabled;

        if (c_iter->cancelled)
            break;

        disabled = btree->entry_get(node, i, &entry_key, &entry_version, &entry_cvt);

        if (CVT_ON_DISK(entry_cvt))
            iter_debug("Current slot: (b=%p, v=%x)->(cep=0x%x, 0x%x)\n",
                       entry_key, entry_version, entry_cvt.cep.ext_id,
                       entry_cvt.cep.offset);
        if (entry_version == c_iter->version ||
            (c_iter->type == C_ITER_ANCESTRAL_VERSIONS &&
             castle_version_is_ancestor(entry_version, c_iter->version)))
        {
            /* If a disabled entry is about to be returned, we should have gone
               to the node that's currently handling this key instead. */
            BUG_ON(disabled);
#ifdef DEBUG
            /* Next key should always be greater than all the keys in the current node. */
            if ((btree->key_compare(c_iter->next_key.key, btree->inv_key) != 0) &&
                    btree->key_compare(c_iter->next_key.key, entry_key) <= 0)
            {
                castle_printk(LOG_ERROR, "Unexpected key ordering: %p, %p\n", c_iter, entry_key);
                BUG();
            }
#endif
            if (c_iter->each(c_iter, i, entry_key, entry_version, entry_cvt))
                break; /* Consumer advised us to terminate. */
        }
    }

    iter_debug("Done processing entries.\n");

    /* Run node_end() callback if specified, otherwise continue iterating. */
    running_async = c_iter->running_async;
    c_iter->running_async = 0;
    if (c_iter->node_end != NULL)
        /* The node_end() callback may restart us asynchronously.  Whether this
         * is the case or we were already running asynchronously we need to
         * return this information to the caller. */
        return c_iter->node_end(c_iter, running_async) || running_async;
    else
    {
        castle_btree_iter_continue(c_iter);

        return 1; /* inform caller we went async */
    }
}

static int   castle_btree_iter_path_traverse(c_iter_t *c_iter, c_ext_pos_t node_cep);
/**
 * @return  0   Completed synchronously (e.g. cancelled, error, did not execute
 *              async_iter callback handlers).
 * @return  1   Went asynchronous (e.g. had to issue I/O, will call async_iter
 *              callback handlers).
 */
static int __castle_btree_iter_path_traverse(c_iter_t *c_iter)
{
    struct castle_btree_node *node;
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_ext_pos_t entry_cep;
    void *entry_key;
    int index;
    c_val_tup_t cvt;

    /* Return early on error */
    if (c_iter->err)
    {
        /* Unlock the top of the stack, this is normally done by
           castle_btree_iter_continue. This will not happen now, because
           the iterator was cancelled between two btree nodes. */
        iter_debug("iter %p unlocking cep "cep_fmt_str"\n",
                c_iter,
                cep2str(c_iter->path[c_iter->depth]->cep));
        read_unlock_node(c_iter->path[c_iter->depth]);
        /* No need to reset running_async as the iterator is to terminate. */
        castle_btree_iter_end(c_iter, c_iter->err, c_iter->running_async);

        return 0;
    }

    /* Otherwise, we know that the node got read successfully. Its buffer is in the path. */
    node = c2b_bnode(c_iter->path[c_iter->depth]);
    iter_debug("iter %p node %p\n", c_iter, node);

    switch(c_iter->type)
    {
        case C_ITER_MATCHING_VERSIONS:
        case C_ITER_ANCESTRAL_VERSIONS:
            /* Deal with leafs first */
            if (BTREE_NODE_IS_LEAF(node))
                return castle_btree_iter_version_leaf_process(c_iter);

             /* If we are enumerating all entries for a particular version,
               find the occurrence of the next key. */
            BUG_ON(VERSION_INVAL(c_iter->version));
            castle_btree_lub_find(node, c_iter->next_key.key, c_iter->version, &index, NULL);
            iter_debug("Node index=%d\n", index);
            if(index==-1)
            {
                BUG_ON(node->used==0); /* empty node shouldn't have been part of the tree at all! */
                index=node->used-1;    /* node didn't have LUB for next_key, so include all of it */
            }
            iter_debug("ANCESTRAL_VERSIONS iter %p index=%d\n", c_iter, index);
            break;
    }

#ifdef DEBUG
    iter_debug("iter %p, node %p, ct = %d, ct->tree_depth = %d, ct root node "
            cep_fmt_str" version = %d\n",
            c_iter, node, c_iter->tree->seq, atomic_read(&c_iter->tree->tree_depth),
            cep2str(c_iter->tree->root_node), c_iter->version);
    iter_debug("iter %p, node %p, parent_key: ", c_iter, node);
    if (c_iter->parent_key)
        btree->key_print(LOG_DEBUG, c_iter->parent_key);
    iter_debug("iter %p, node %p, next_key: ", c_iter, node);
    if (c_iter->next_key.key)
        btree->key_print(LOG_DEBUG, c_iter->next_key.key);
#endif
    if(index == -1)
    {
        castle_printk(LOG_ERROR, "%s::lub_find returned -1, terminating iter %p\n",
                __FUNCTION__, c_iter);
        BUG();
    }
    btree->entry_get(node, index, &entry_key, NULL, &cvt);
    entry_cep = cvt.cep;
    if (!CVT_NODE(cvt))
    {
        castle_printk(LOG_ERROR, "0x%x-%llu-"cep_fmt_str_nl,
                cvt.type,
                (uint64_t)cvt.length,
                cep2str(cvt.cep));
        BUG();
    }

    c_iter->depth++;
    castle_iter_parent_key_set(c_iter, entry_key);

    return castle_btree_iter_path_traverse(c_iter, entry_cep);
}

/**
 * @also castle_btree_iter_path_traverse_endio()
 */
static void _castle_btree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    iter_debug("iter %p\n", c_iter);
    __castle_btree_iter_path_traverse(c_iter);
}

/**
 * IO completion callback handler for castle_btree_iter_path_traverse().
 *
 * On successful IO:
 * - Downgrades c2b writelock to node readlock
 * - Pushes c2b node onto the path stack
 * - Continues iterator via a workqueue
 *
 * @also castle_btree_iter_path_traverse()
 * @also _castle_btree_iter_path_traverse()
 */
static void castle_btree_iter_path_traverse_endio(c2_block_t *c2b)
{
    c_iter_t *c_iter = c2b->private;

    iter_debug("Finished reading btree node "cep_fmt_str" for iter %p.\n",
            cep2str(c2b->cep), c_iter);

    if (!c2b_uptodate(c2b))
    {
        iter_debug("Error reading the btree node. Cancelling iterator.\n");
        iter_debug("%p unlocking cep: (0x%x, 0x%x).\n", c_iter, c2b->cep.ext_id, c2b->cep.offset);
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        /* Save the error. This will be handled properly by __path_traverse */
        c_iter->err = -EIO;
    }
    else
    {
        downgrade_write_node(c2b);

        /* Push the node onto the path 'stack' */
        BUG_ON((c_iter->path[c_iter->depth] != NULL) && (c_iter->path[c_iter->depth] != c2b));
        c_iter->path[c_iter->depth] = c2b;
    }

    /* Put on to the workqueue.  Choose a workqueue which corresponds to how
     * deep we are in the btree.
     * A single queue cannot be used because a request blocked on lock_c2b()
     * would block the entire queue (=> deadlock).
     *
     * NOTE: The +1 is required to match the workqueues we are using in normal
     *       btree walks. */
    CASTLE_INIT_WORK(&c_iter->work, _castle_btree_iter_path_traverse);
    queue_work(castle_wqs[c_iter->depth+MAX_BTREE_DEPTH], &c_iter->work);
}

/**
 * @return  0   Completed synchronously (e.g. cancelled, error, did not execute
 *              async_iter callback handlers).
 * @return  1   Went asynchronous (e.g. had to issue I/O, will call async_iter
 *              callback handlers).
 */
static int castle_btree_iter_path_traverse(c_iter_t *c_iter, c_ext_pos_t node_cep)
{
    c2_block_t *c2b = NULL;
    int write_locked = 0;

    iter_debug("Starting the traversal for iter %p: depth=%d, node_cep="cep_fmt_str"\n",
                c_iter, c_iter->depth, cep2str(node_cep));

    /* Try to use the c2b we've saved in the path, if it matches node_cep */
    if(c_iter->path[c_iter->depth] != NULL)
    {
        c2b = c_iter->path[c_iter->depth];

        if(!EXT_POS_EQUAL(c2b->cep, node_cep))
        {
            castle_btree_iter_path_put(c_iter, c_iter->depth);
            c2b = NULL;
        }
    }

    /* If we haven't found node_cep in path, get it from the cache instead */
    if(c2b == NULL)
        c2b = castle_cache_block_get(node_cep,
                                     c_iter->tree->node_sizes[c_iter->btree_levels - c_iter->depth - 1]);

    iter_debug("iter %p locking cep "cep_fmt_str"\n", c_iter, cep2str(c2b->cep));

    /* If the c2b is up to date within the cache, take a read lock.
     * Otherwise get a write lock and retest, somebody could have completed IO
     * while we waited; if so, downgrade to a read lock. */
    if (c2b_uptodate(c2b))
    {
        read_lock_node(c2b);
    }
    else
    {
        write_lock_c2b(c2b);
        if (c2b_uptodate(c2b))
            /* Somebody else did IO for us. */
            downgrade_write_node(c2b);
        else
            /* We need to schedule IO. */
            write_locked = 1;
    }

    /* Unlock the tree if we've just locked the root */
    if(c_iter->depth == 0)
    {
        /* We have just started the iteration - lets unlock the version tree */
        iter_debug("Unlocking component tree.\n");
        up_read(&c_iter->tree->lock);
    }
    /* Unlock previous c2b */
    if((c_iter->depth > 0) && (c_iter->path[c_iter->depth - 1] != NULL))
    {
        c2_block_t *prev_c2b = c_iter->path[c_iter->depth - 1];
        iter_debug("iter %p unlocking cep "cep_fmt_str"\n",
                c_iter, cep2str(prev_c2b->cep));
        read_unlock_node(prev_c2b);
        /* Don't put_c2b(), handy if we need to rewalk the tree. */
    }

    /* Continue the traverse, scheduling and waiting for IO if necessary. */
    if (write_locked)
    {
        iter_debug("Not uptodate, submitting\n");

        c_iter->running_async = 1;
        c2b->end_io = castle_btree_iter_path_traverse_endio;
        c2b->private = c_iter;
        BUG_ON(submit_c2b(READ, c2b));

        return 1; /* inform caller we issued async I/O */
    }
    else
    {
        iter_debug("iter %p Uptodate, carrying on\n", c_iter);

        /* Push the node onto the path 'stack' */
        BUG_ON((c_iter->path[c_iter->depth] != NULL) && (c_iter->path[c_iter->depth] != c2b));
        c_iter->path[c_iter->depth] = c2b;

        return __castle_btree_iter_path_traverse(c_iter);
    }
}

/**
 * Start the main castle btree iterator.
 *
 * @return  0   Completed synchronously (e.g. cancelled, error, did not execute
 *              async_iter callback handlers).
 * @return  1   Went asynchronous (e.g. had to issue I/O, will call async_iter
 *              callback handlers).
 */
static int __castle_btree_iter_start(c_iter_t *c_iter)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);
    c_ext_pos_t  root_cep;

    BUG_ON((!strncmp(current->comm, "castle_wq", 9)
                && strncmp(current->comm, "castle_wq0", 10)));

    iter_debug("-------------- STARTING THE ITERATOR %p ct %d root cep "cep_fmt_str" -------------------\n",
            c_iter, c_iter->tree->seq, cep2str(c_iter->tree->root_node));

    /*
     * End conditions: we must be done if:
     *    - we start again at depth 0 - ie the root is a leaf
     *    - we followed max key to a leaf
     *    - we were cancelled
     *
     *    @TODO we can probably bum some cycles here.  we're checking that
     *    next_key is the invalid key... we must have set this somewhere else
     *    in the code, so why do the comparison again (every single time we
     *    skip, continue, etc.)
     */
    if ((c_iter->depth == 0) ||
       ((c_iter->type == C_ITER_MATCHING_VERSIONS) &&
            (btree->key_compare(c_iter->next_key.key, btree->inv_key) == 0)) ||
       ((c_iter->type == C_ITER_ANCESTRAL_VERSIONS) &&
            (btree->key_compare(c_iter->next_key.key, btree->inv_key) == 0)) ||
        (c_iter->cancelled))
    {
        castle_btree_iter_end(c_iter, c_iter->err, c_iter->running_async);
        return 0;
    }

    /*
     * Let's start from the root again...
     */
    iter_debug("Locking version tree for version: %d\n", c_iter->version);

    down_read(&c_iter->tree->lock);

    c_iter->depth = 0;
    c_iter->btree_levels = atomic_read(&c_iter->tree->tree_depth);
    root_cep = c_iter->tree->root_node;
    if(EXT_POS_INVAL(root_cep))
    {
        iter_debug("Warning: Invalid disk block for the root.\n");
        up_read(&c_iter->tree->lock);
        /* Complete the request early, end exit */
        castle_btree_iter_end(c_iter, -EINVAL, c_iter->running_async);
        return 0;
    }

    castle_iter_parent_key_set(c_iter, btree->inv_key);
    return castle_btree_iter_path_traverse(c_iter, root_cep);
}

static void _castle_btree_iter_start(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);

    __castle_btree_iter_start(c_iter);
}

/**
 * Asynchronously start the btree iterator.
 *
 * NOTE: castle_wqs[0] is a safe place to start the iterator; any IO will be
 *       done asynchronously and the iterator will be requeued at a workqueue
 *       of the correct depth.
 */
void castle_btree_iter_start(c_iter_t* c_iter)
{
    c_iter->running_async = 1;
    CASTLE_INIT_WORK(&c_iter->work, _castle_btree_iter_start);
    queue_work(castle_wqs[0], &c_iter->work);
}

/**
 * Start the btree iterator, asynchronously if we are on a btree workqueue.
 */
static int castle_btree_iter_safe_start(c_iter_t *c_iter)
{
    if (!strncmp(current->comm, "castle_wq", 9)
            && strncmp(current->comm, "castle_wq0", 10))
    {
        /* We're running on level > 0 btree workqueue.  Go async. */
        castle_btree_iter_start(c_iter);

        return 1; /* inform caller we went asynchronous */
    }
    else
        return __castle_btree_iter_start(c_iter);
}

void castle_btree_iter_cancel(c_iter_t *c_iter, int err)
{
    iter_debug("Cancelling version=0x%x iterator, error=%d\n", c_iter->version, err);

    c_iter->err = err;
    wmb();
    c_iter->cancelled = 1;
}

void castle_btree_iter_init(c_iter_t *c_iter, c_ver_t version, int type)
{
    struct castle_btree_type *btree = castle_btree_type_get(c_iter->tree->btree_type);

    iter_debug("Initialising iterator for version=0x%x\n", version);

    atomic_inc(&castle_btree_iters_cnt);

    BUG_ON((type != C_ITER_MATCHING_VERSIONS) && (type != C_ITER_ANCESTRAL_VERSIONS));
    c_iter->type = type;
    c_iter->version = version;
    castle_iter_parent_key_set(c_iter, btree->min_key);
    c_iter->next_key.key = btree->min_key;
    c_iter->next_key.need_destroy = 0;
    c_iter->depth = -1;
    c_iter->err = 0;
    c_iter->cancelled = 0;
    memset(c_iter->path, 0, sizeof(c_iter->path));
}

/***** Init/fini functions *****/
/* We have a static array of btree types indexed by btree_t, don't let it grow too
   large. */
STATIC_BUG_ON(sizeof(btree_t) != 1);
int castle_btree_init(void)
{
    return 0;
}

void castle_btree_free(void)
{
    /* Wait until all iterators are completed */
    wait_event(castle_btree_iters_wq, (atomic_read(&castle_btree_iters_cnt) == 0));
}

void castle_btree_node_buffer_init(btree_t type,
                                   struct castle_btree_node *buffer,
                                   uint16_t node_size,
                                   uint8_t flags,
                                   int version)
{
    debug("Resetting btree node buffer.\n");
    /* memset the node, so that btree nodes are easily recognisable in hexdump. */
    memset(buffer, 0x77, node_size * C_BLK_SIZE);
    /* Buffers are proper btree nodes understood by castle_btree_node_type function sets.
       Initialise the required bits of the node, so that the types don't complain. */
    buffer->magic   = BTREE_NODE_MAGIC;
    buffer->type    = type;
    buffer->version = version;
    buffer->used    = 0;
    buffer->flags   = flags;
    buffer->size    = node_size;
    if( (node_size*C_BLK_SIZE) > NODE_SIZE_WARN)
    {
        castle_printk(LOG_WARN, "%s:: made a very large node; %u blocks\n",
            __FUNCTION__, node_size);
        WARN_ON(1);
    }
}

static struct node_buf_t* node_buf_alloc(c_rq_iter_t *rq_iter)
{
    struct node_buf_t *node_buf;
    struct castle_component_tree *ct;
    uint16_t leaf_node_size;

    ct = rq_iter->tree;
    leaf_node_size = ct->node_sizes[0];
    node_buf = castle_alloc(sizeof(struct node_buf_t));
    BUG_ON(!node_buf);
    if (leaf_node_size * C_BLK_SIZE > MAX_KMALLOC_SIZE)
        leaf_node_size = MAX_KMALLOC_SIZE / C_BLK_SIZE;
    node_buf->node = castle_alloc(leaf_node_size * C_BLK_SIZE);
    BUG_ON(!node_buf->node);

    castle_btree_node_init(rq_iter->tree, node_buf->node, 0, leaf_node_size, 0);
    rq_iter->buf_count++;

    return node_buf;
}

/**
 * Call castle_btree_lub_find() to find search start index for RQ.
 *
 * @return  Index within node to start looking for entries.
 *
 * @also castle_btree_lub_find()
 */
static int castle_rq_iter_node_start(c_iter_t *c_iter)
{
    c_rq_iter_t *rq_iter = (c_rq_iter_t *)c_iter->private;
    struct castle_btree_node *node;
    c2_block_t *leaf;
    int idx;

    /* If the enumerator is 'in_range' it means that it's walking keys sequentially.
       Therefore there is no need to binary chop in the btree node. In fact, start_key
       may be/will likely be NULL. Which will make the binary chop impossible. */
    if (rq_iter->in_range)
        return 0;
    /* If the enumerator is not 'in_range', start_key must be non-NULL. */
    BUG_ON(rq_iter->start_key == NULL);

    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);

    node = c2b_bnode(leaf);
    BUG_ON(!BTREE_NODE_IS_LEAF(node));

    castle_btree_lub_find(node, rq_iter->start_key, rq_iter->version, &idx, NULL);

    /* Only return idx if we found a match. */
    if (idx >= 0)
        return idx;
    else
        return 0;
}

/**
 * Resets all counter accumulation variables stored in rq_iter structure to their default
 * values (NULLs, -1s).
 */
static void castle_rq_iter_counter_reset(c_rq_iter_t *rq_iter)
{
    CVT_INVALID_INIT(rq_iter->counter_accumulator);
    rq_iter->counter_key    = NULL;
    rq_iter->counter_buf    = NULL;
    rq_iter->counter_idx    = -1;
}

/**
 * Terminates counter accumulation, by updating the counter in the buffer and resetting
 * all the counter accumulation variables in rq_iter.
 *
 * If accumulation isn't being performed this function is a no-op.
 */
static void castle_rq_iter_counter_accum_fini(c_rq_iter_t *rq_iter)
{
    struct castle_btree_type *btree;
    struct castle_btree_node *node;

    /* Don't terminate if there isn't an accumulation going on. */
    if(CVT_INVALID(rq_iter->counter_accumulator))
        return;

    /* Otherwise, write out the entry into the right place in the buffer. */
    node = rq_iter->counter_buf->node;
    btree = castle_btree_type_get(node->type);

    /* Use the saved key pointer (should match cur_key), version after accumulation
       is no longer meaningful, therefore use the iterator version. */
    btree->entry_replace(node,
                         rq_iter->counter_idx,
                         rq_iter->counter_key,
                         rq_iter->version,
                         rq_iter->counter_accumulator);

    /* Reset all the variables. */
    castle_rq_iter_counter_reset(rq_iter);
}

/**
 * Continues accumulation of a counter by folding the cvt provided into the accumulator
 * stored in rq_iter structure.
 *
 * It terminates the accumulation if a counter set, or an non-counter is encountered.
 * It also terminates on accumulating counters (in the case of RW trees).
 *
 * If accumulation isn't being performed this function is a no-op.
 */
static void castle_rq_iter_counter_accum_continue(c_rq_iter_t *rq_iter,
                                                  c_val_tup_t cvt)
{
    int finish;

    /* Don't accumulate if accumulator hasn't been prepared. */
    if(CVT_INVALID(rq_iter->counter_accumulator))
        return;

    /* Accumulator must be a local add counter. Otherwise the accumulation should have
       finished by now, or shouldn't have started at all. */
    BUG_ON(!CVT_COUNTER_LOCAL_ADD(rq_iter->counter_accumulator));

    /* Deal with accumulating counters (they already have all the data in them). */
    finish = 0;
    if(CVT_ACCUM_COUNTER(cvt))
    {
        CVT_COUNTER_ACCUM_ALLV_TO_LOCAL(rq_iter->counter_accumulator, cvt);
        finish = 1;
    }

    /* Accumulate. And terminate possibly terminate. */
    if(finish || castle_counter_simple_reduce(&rq_iter->counter_accumulator, cvt))
        castle_rq_iter_counter_accum_fini(rq_iter);
}

/**
 * Initiates counter accumulation if the cvt provided is a counter.
 *
 * All accumulation variables are initialised on the basis of the current state of the
 * enumerator, and the cvt provided.
 *
 * If the accumulation is trivially terminable (either on counter sets, or on
 * accumulating counters), it terminates.
 */
static void castle_rq_iter_counter_accum_init(c_rq_iter_t *rq_iter, c_val_tup_t cvt)
{
    /* Don't init if we aren't looking at a counter. */
    if(!CVT_ANY_COUNTER(cvt))
        return;

    /* There shouldn't be an accumulation going on. */
    BUG_ON(!CVT_INVALID(rq_iter->counter_accumulator));
    BUG_ON(rq_iter->counter_key != NULL);
    BUG_ON(rq_iter->counter_buf != NULL);
    BUG_ON(rq_iter->counter_idx >= 0);

    /* Save the key. */
    rq_iter->counter_key = rq_iter->cur_key;

    /* Save the position of the counter (node & index). */
    rq_iter->counter_buf = rq_iter->prod_buf;
    rq_iter->counter_idx = rq_iter->prod_idx;

    /* Initialise the accumulator. */
    CVT_COUNTER_LOCAL_ADD_INIT(rq_iter->counter_accumulator, 0);
    /* we don't support timestamped counters but let's explicitly set the timestamp field anyway */
    rq_iter->counter_accumulator.user_timestamp = 0;

    /* Deal with the current cvt. */
    castle_rq_iter_counter_accum_continue(rq_iter, cvt);
}

/**
 * @return  0 => Iterator should continue
 * @return >0 => Iterator should terminate
 */
static int castle_rq_iter_each(c_iter_t *c_iter,
                               int index,
                               void *key,
                               c_ver_t version,
                               c_val_tup_t cvt)
{
    struct castle_btree_type *btree;
    c_rq_iter_t *rq_iter = (c_rq_iter_t *)c_iter->private;
    struct node_buf_t *prod_buf = rq_iter->prod_buf;
    struct node_buf_t *cons_buf = rq_iter->cons_buf;
    struct castle_btree_node *node = prod_buf->node;
    int cmp;

    btree = castle_btree_type_get(node->type);
    BUG_ON(rq_iter->prod_idx != node->used);

    /* Check if the node buffer is full */
    if (btree->need_split(node, 0))
    {
        debug("Need split - producer buffer: %p\n", prod_buf);
        /* Check to not overwrite last node of previous buffer */
        if (prod_buf->list.next == &cons_buf->list ||
            prod_buf->list.next->next == &cons_buf->list)
        {
            struct node_buf_t *new_buf;

            new_buf = node_buf_alloc(rq_iter);
            list_add(&new_buf->list, &prod_buf->list);
            rq_iter->prod_buf = new_buf;
            debug("Creating new node buffer: %p\n", rq_iter->prod_buf);
        }
        else
        {
            rq_iter->prod_buf = list_entry(prod_buf->list.next,
                                           struct node_buf_t, list);
            castle_btree_node_init(rq_iter->tree,
                                   rq_iter->prod_buf->node,
                                   0,
                                   rq_iter->prod_buf->node->size,
                                   0);
            debug("Moving prod_buf to next node_buf: %p\n", rq_iter->prod_buf);
        }
        rq_iter->prod_idx = 0;
    }

    if (!rq_iter->in_range)
    {
        BUG_ON(rq_iter->start_key == NULL);
        if (btree->key_compare(rq_iter->start_key, key) <= 0)
            rq_iter->in_range = 1;
        else
            return 0; /* Iterator to continue */
    }

    /* If curr_key is set, figure out whether the new key is the same, or different. */
    cmp = 1;    /* Just to make the compiler happy. */
    if (rq_iter->cur_key)
        cmp = btree->key_compare(rq_iter->cur_key, key);

    /* Check whether we moving on to a new key. */
    if (!rq_iter->cur_key || cmp)
    {
        /* If there is a counter accumulation happening, terminate it. */
        castle_rq_iter_counter_accum_fini(rq_iter);
        debug("Adding entry to node buffer: %p\n", rq_iter->prod_buf);
        /* Keys should not go backwards. */
        if (rq_iter->cur_key && (cmp > 0))
        {
            castle_printk(LOG_ERROR, "re_enum: %p, cur_key: %p, key: %p\n",
                    rq_iter, rq_iter->cur_key, key);
            BUG();
        }
        /* Add the entry into the buffer, in the version of the rq. This guarantees that
           results from different arrays will be merged properly by the merged iterator
           (in castle_da_rq_iter). */
        btree->entry_add(rq_iter->prod_buf->node, rq_iter->prod_idx, key, rq_iter->version, cvt);
        btree->entry_get(rq_iter->prod_buf->node, rq_iter->prod_idx, &rq_iter->cur_key, NULL, NULL);
        castle_rq_iter_counter_accum_init(rq_iter, cvt);
        rq_iter->prod_idx++;

        if (unlikely(btree->key_compare(key, rq_iter->end_key) > 0))
            return 1; /* Iterator to terminate */
    }
    else
        /* Key is the same as the previous one, but we may be accumulating a counter. */
        castle_rq_iter_counter_accum_continue(rq_iter, cvt);

    return 0; /* Iterator to continue */
}

static int castle_rq_iter_prep_next(c_rq_iter_t *rq_iter);

/**
 * @return  0   This callback did not cause calling iterator to go async.
 * @return  1   This callback started the calling iterator asynchronously.
 */
static int castle_rq_iter_node_end(c_iter_t *c_iter, int async)
{
    c_rq_iter_t *rq_iter = c_iter->private;

    rq_debug("%s:%p\n", __FUNCTION__, rq_iter);
    /* Check consumer idx for 0 */
    BUG_ON(rq_iter->cons_idx != 0);

    /* There may be an ongoing counter accumulation. We assume that in never needs
       to span multiple nodes => terminate it now. */
    castle_rq_iter_counter_accum_fini(rq_iter);

    /* We have no entries to process if rq_iter->prod_idx == 0.  If the btree
     * iterator was running asynchronously, continue iterating, otherwise wait
     * for control to be returned to castle_rq_iter_prep_next() which will
     * detect this and continue iterating without requeuing. */
    if (async && rq_iter->prod_idx == 0)
    {
        rq_debug("%p - async reschedule\n", rq_iter);
        castle_btree_iter_continue(c_iter);

        return 1;
    }

    /* Release the iterator resources and mark node process completed */
    __castle_btree_iter_release(c_iter);
    rq_iter->iter_running = 0;

    /* prep_next() cancels the iterator, if end_key is found. Iterator
     * cancellation is executed on different thread. */
    if (async)
    {
        /* Call callback of the higher level iterator */
        rq_debug("%p - Done\n", rq_iter);
        rq_iter->async_iter.end_io(rq_iter, 0);
    }

    wake_up(&rq_iter->iter_wq);

    return 0;
}

static void castle_rq_iter_end(c_iter_t *c_iter, int err, int async)
{
    c_rq_iter_t *rq_iter = c_iter->private;

    if(err) rq_iter->err = err;
    rq_iter->iter_completed = 1;
    rq_iter->iter_running = 0;
    wmb();
    rq_debug("Nothing left in %p\n", rq_iter);

    /* end_io() would be set to NULL, if this callback is result of rq_iter_cancel(). */
    if (async && rq_iter->async_iter.end_io)
    {
        rq_debug("%p - Done\n", rq_iter);

        /* Call callback of the higher level iterator */
        rq_iter->async_iter.end_io(rq_iter, 0);
    }

    wake_up(&rq_iter->iter_wq);
}

static void castle_rq_iter_fini(c_rq_iter_t *rq_iter)
{
    struct node_buf_t *buf = rq_iter->buf_head;
    struct node_buf_t *next;
    int count = 0;

    do {
        next = list_entry(buf->list.next,
                          struct node_buf_t, list);
        castle_free(buf->node);
        castle_free(buf);
        buf = next;
        count++;
        BUG_ON(count > rq_iter->buf_count);
    } while (buf != rq_iter->buf_head);
    BUG_ON(count != rq_iter->buf_count);
    debug("Free rq_iter: %p\n", rq_iter);
}

void castle_rq_iter_init(c_rq_iter_t *rq_iter, c_ver_t version,
                         struct castle_component_tree *tree,
                         void *start_key,
                         void *end_key)
{
    struct castle_btree_type *btype;
    struct castle_iterator *iter;

    btype = castle_btree_type_get(tree->btree_type);
    BUG_ON(btype->key_compare(start_key, btype->inv_key) == 0 ||
           btype->key_compare(end_key, btype->inv_key) == 0);

    rq_iter->tree           = tree;
    rq_iter->err            = 0;
    rq_iter->async_iter.end_io = NULL;
    rq_iter->async_iter.iter_type = &castle_rq_iter;
    rq_iter->version        = version;
    rq_iter->iter_completed = 0;
    init_waitqueue_head(&rq_iter->iter_wq);
    rq_iter->iter_running   = 0;
    rq_iter->prod_idx       = 0;
    rq_iter->cons_idx       = 0;
    rq_iter->buf_count      = 0;
    rq_iter->buf_head       = node_buf_alloc(rq_iter);
    INIT_LIST_HEAD(&rq_iter->buf_head->list);
    rq_iter->prod_buf       = rq_iter->buf_head;
    debug("0: Creating new node buffer: %p\n", rq_iter->prod_buf);
    rq_iter->cons_buf       = rq_iter->buf_head;
    rq_iter->cur_key        = NULL;
    rq_iter->last_key       = NULL;
    rq_iter->start_key      = start_key;
    rq_iter->end_key        = end_key;
    rq_iter->in_range       = 0;
    castle_rq_iter_counter_reset(rq_iter);

    iter = &rq_iter->iterator;
    iter->tree          = rq_iter->tree;
    iter->need_visit    = NULL;
    iter->node_start    = castle_rq_iter_node_start;
    iter->each          = castle_rq_iter_each;
    iter->node_end      = castle_rq_iter_node_end;
    iter->end           = castle_rq_iter_end;
    iter->private       = rq_iter;
    iter->running_async = 0;

    castle_btree_iter_init(iter, version, C_ITER_ANCESTRAL_VERSIONS);
    iter->next_key.key          = start_key;
    iter->next_key.need_destroy = 0;
    rq_debug("New Iterator - %p\n", iter);

    return;
    /* @TODO: do we need to handle out of memory conditions better than with BUG_ON? */
#if 0
no_mem:
    rq_iter->err = -ENOMEM;
    castle_rq_iter_fini(rq_iter);
#endif
}

static void castle_rq_iter_buffer_switch(c_rq_iter_t *rq_iter)
{
    /* Only switch the buffer if the old buffer actually had anything in it,
       this prevents problems when the iterator below hasn't returned anything
       in the range we are interested in (double buffer swap will start invalidating
       the memory area used by the key pointer returned by previous _next()) */
    /* @TODO: check if enumerator also suffers from the same problem */
    if(rq_iter->prod_idx > 0)
    {
        if (rq_iter->prod_buf->list.next == &rq_iter->prod_buf->list)
        {
            struct node_buf_t *new_buf;

            new_buf = node_buf_alloc(rq_iter);
            list_add(&new_buf->list, &rq_iter->prod_buf->list);
            debug("1: Creating new node buffer: %p\n", rq_iter->prod_buf);
        }
        BUG_ON(rq_iter->prod_buf->list.next == &rq_iter->prod_buf->list);
        rq_iter->prod_buf = list_entry(rq_iter->prod_buf->list.next,
                                       struct node_buf_t, list);
        debug("1: Moving prod_buf to next node_buf: %p\n", rq_iter->prod_buf);
    } else
    {
        BUG_ON(rq_iter->cons_idx != 0 && rq_iter->cons_buf == rq_iter->prod_buf);
    }
    rq_iter->cons_buf = rq_iter->prod_buf;
    rq_iter->cons_idx = 0;
    rq_iter->prod_idx = 0;

    castle_btree_node_init(rq_iter->tree,
                           rq_iter->prod_buf->node,
                           0,
                           rq_iter->prod_buf->node->size,
                           0);
}

int cons_idx_prod_idx_compare(c_rq_iter_t *rq_iter)
{
    if (rq_iter->cons_buf != rq_iter->prod_buf
            || rq_iter->cons_idx < rq_iter->prod_idx)
        return 1;

    /* If we are consuming and producing in different buffers, we should not get here */
    BUG_ON(rq_iter->cons_buf != rq_iter->prod_buf);
    /* In same buffer, consumer buffer must not overtake the producer index */
    BUG_ON(rq_iter->cons_idx > rq_iter->prod_idx);

    return 0;
}

static void castle_rq_iter_register_cb(c_rq_iter_t *iter,
                                       castle_iterator_end_io_t cb,
                                       void *data)
{
    iter->async_iter.end_io  = cb;
    iter->async_iter.private = data;
}

/**
 * @return  1   Ready for has_next() to be called.
 * @return  0   Waiting for some I/O operation to finish (will complete
 *              asynchronously).
 */
static int castle_rq_iter_prep_next(c_rq_iter_t *rq_iter)
{
    struct castle_iterator *iter = &rq_iter->iterator;
    struct castle_btree_type *btree =
                            castle_btree_type_get(rq_iter->prod_buf->node->type);
    void *key;

    rq_debug("%p\n", rq_iter);

    BUG_ON(rq_iter->iter_running); /* not re-entrant if iter_running */
    BUG_ON(rq_iter->async_iter.end_io == NULL);

    do {
        BUG_ON(rq_iter->iter_completed && cons_idx_prod_idx_compare(rq_iter));

        rq_debug("Checking for %p\n", rq_iter);
        /* Return if iterator is already completed */
        if (rq_iter->iter_completed)
            return 1;

        /* Check if the first entry in buffer is smaller than end key. */
        if (cons_idx_prod_idx_compare(rq_iter))
        {
            btree->entry_get(rq_iter->cons_buf->node, rq_iter->cons_idx, &key, NULL, NULL);
            if (btree->key_compare(rq_iter->end_key, key) < 0)
            {
                /* Key is greater than end_key, terminate the iterator. */
                rq_iter->cons_buf = rq_iter->prod_buf;
                rq_iter->cons_idx = rq_iter->prod_idx = 0;
                castle_btree_iter_cancel(iter, 0);
                /* iter_start() will call iter_end() */
            }
            else
                /* Success: first entry in buffer is smaller than end key. */
                return 1;
        }
        else
        {
            castle_rq_iter_buffer_switch(rq_iter);
            rq_debug("%p - schedule\n", rq_iter);
        }

        /* Schedule iterator to get few more entries into buffer */
        rq_iter->iter_running = 1;
        wmb();
    } while (castle_btree_iter_safe_start(iter) == EXIT_SUCCESS);

    return 0;
}

int castle_rq_iter_has_next(c_rq_iter_t *rq_iter)
{
    BUG_ON(rq_iter->iter_running);

    /* Return 1, if buffer has entries. */
    if (cons_idx_prod_idx_compare(rq_iter))
        return 1;

    BUG_ON(!rq_iter->iter_completed);

    return 0;
}

void castle_rq_iter_next(c_rq_iter_t *rq_iter,
                         void **key_p,
                         c_ver_t *version_p,
                         c_val_tup_t *cvt_p)
{
    struct castle_btree_type *btree = castle_btree_type_get(rq_iter->tree->btree_type);

    rq_debug("%p\n", rq_iter);
    BUG_ON(rq_iter->iter_running);
    /* Make sure that consumer index is less than the producer (there is an assert in
       the comparator). */
    cons_idx_prod_idx_compare(rq_iter);
    btree->entry_get(rq_iter->cons_buf->node, rq_iter->cons_idx, key_p, version_p,
                     cvt_p);
    rq_iter->last_key = *key_p;
    rq_iter->cons_idx++;
    if (rq_iter->cons_buf != rq_iter->prod_buf &&
        rq_iter->cons_idx == rq_iter->cons_buf->node->used)
    {
        rq_iter->cons_buf = list_entry(rq_iter->cons_buf->list.next,
                                       struct node_buf_t, list);
        rq_iter->cons_idx = 0;
    }
}

void castle_rq_iter_skip(c_rq_iter_t *rq_iter,
                         void *key)
{
    struct castle_btree_type *btree = castle_btree_type_get(rq_iter->tree->btree_type);
    int i;

    rq_debug("%p\n", rq_iter);
    BUG_ON(rq_iter->iter_running);
    cons_idx_prod_idx_compare(rq_iter);

    /* Should never try to skip to the key before last key returned. */
    if (rq_iter->last_key && (btree->key_compare(key, rq_iter->last_key) <= 0))
    {
        castle_printk(LOG_ERROR, "Trying to skip to a key[%p] smaller than "
                "last_key [%p], iter - %p\n", key, rq_iter->last_key, rq_iter);
        BUG();
    }

    /* Go through all buffers and skip keys smaller than the key to be skipped to. */
    while(1)
    {
        int last_idx;

        last_idx = (rq_iter->cons_buf == rq_iter->prod_buf)
                    ? rq_iter->prod_idx
                    : (rq_iter->cons_buf->node->used);
        /* Check if the seeking key is in buffer, if so skip to it and return */
        for (i=rq_iter->cons_idx; i < last_idx; i++)
        {
            void *buf_key;

            btree->entry_get(rq_iter->cons_buf->node, i, &buf_key, NULL, NULL);
            /* If the key is within the buffer already we are going to advance
               consumer pointer, but there is no need to change the state of
               castle_iterator. Consequently, we don't need the start_key.
               In fact, we want to set it to NULL, so that
               castle_rq_iter_node_start() can use it to detect whether or
               not to binary chop in btree nodes. */
            if (btree->key_compare(buf_key, key) >= 0)
            {
                BUG_ON(!rq_iter->in_range);
                rq_iter->cons_idx = i;
                rq_iter->start_key = NULL;
                return;
            }
        }
        if (rq_iter->cons_buf == rq_iter->prod_buf)
            break;

        /* Move consumer to next buffer. */
        rq_iter->cons_buf = list_entry(rq_iter->cons_buf->list.next,
                                       struct node_buf_t, list);
        rq_iter->cons_idx = 0;
    }

    /* Key that iterator is skipping to must be bigger than last key of the node
     * (which is stored in rq_iter->cur_key). */
    BUG_ON(btree->key_compare(rq_iter->cur_key, key) >= 0);

    castle_rq_iter_buffer_switch(rq_iter);
    castle_btree_iter_version_key_dealloc(&rq_iter->iterator);
    rq_iter->iterator.next_key.key = key;
    rq_iter->iterator.next_key.need_destroy = 0;
    /* Reset range to handle next key in the middle of a node */
    rq_iter->in_range = 0;
    rq_iter->start_key = key;
}

void castle_rq_iter_cancel(c_rq_iter_t *rq_iter)
{
    /* Wait for the iterator to complete */
    wait_event(rq_iter->iter_wq, (rq_iter->iter_running == 0));

    if (!rq_iter->iter_completed)
    {
        struct castle_iterator *iter = &rq_iter->iterator;

        castle_btree_iter_cancel(iter, 0);
        rq_iter->iter_running = 1;
        /* castle_btree_iter_start() would call end() on the cancellation of iterator.
         * We don't need this call get promoted to higher level iterators. Reset end_io here.
         * We don't need this anymore. */
        rq_iter->async_iter.end_io = NULL;
        wmb();
        castle_btree_iter_safe_start(iter);
        wait_event(rq_iter->iter_wq, (rq_iter->iter_running == 0));
    }

    castle_rq_iter_fini(rq_iter);
}

struct castle_iterator_type castle_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_rq_iter_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_rq_iter_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_rq_iter_has_next,
    .next       = (castle_iterator_next_t)       castle_rq_iter_next,
    .skip       = (castle_iterator_skip_t)       castle_rq_iter_skip,
    .cancel     = (castle_iterator_cancel_t)     castle_rq_iter_cancel,
};
