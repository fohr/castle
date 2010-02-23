#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_block.h"
#include "castle_cache.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static void castle_ftree_c2p_forget(c_bvec_t *c_bvec);
static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb);

static void castle_ftree_io_end(c_bvec_t *c_bvec,
                                c_disk_blk_t cdb,
                                int err)
{
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_IO_END);
    /* We allow:
       -   valid block and no error
       - invalid block and    error
       - invalid block and no error (reads from non-yet written block)
       We disallow:
       -   valid block and    error 
       - invalid block and no error on writes
     */
    BUG_ON((!DISK_BLK_INVAL(cdb)) && (err));
    BUG_ON((c_bvec_data_dir(c_bvec) == WRITE) && (DISK_BLK_INVAL(cdb)) && (!err));
    /* Free the c2ps correctly. Call twice to release parent and child
       (if both exist) */
    castle_ftree_c2p_forget(c_bvec);
    castle_ftree_c2p_forget(c_bvec);
    /* Once buffers have been freed, save the cdb */
    c_bvec->cdb = cdb;
    /* Finish the IO (call _io_end directly on an error */
    if(err)
        castle_bio_data_io_end(c_bvec, err);
    else
        castle_bio_data_io(c_bvec);
}

static void castle_ftree_slot_normalize(struct castle_ftree_slot *slot)
{
    /* Look for 'last' slot, and if block is zero, assign the maximum value instead */
    if(FTREE_SLOT_IS_NODE_LAST(slot) &&
       (slot->block == 0))
    {
        slot->type  = FTREE_SLOT_NODE;
        slot->block = MAX_BLK;
    }
}

static int castle_ftree_node_normalize(struct castle_ftree_node *node)
{
    int i;

    if((node->capacity > FTREE_NODE_SLOTS) ||
       (node->used     > node->capacity) ||
       (node->used     == 0))
    {
        printk("Invalid ftree node capacity or/and used: (%d, %d)\n",
               node->capacity, node->used);
        return -EIO;
    }
    /* There is at least one slot in the node */ 
    node->is_leaf = FTREE_SLOT_IS_LEAF(&node->slots[0]);

    for(i=0; i < node->used; i++)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        /* Fail if node is_leaf doesn't match with the slot. ! needed 
           to guarantee canonical value for boolean true */
        if(!(node->is_leaf) != !(FTREE_SLOT_IS_LEAF(slot)))
            return -EIO;
        castle_ftree_slot_normalize(slot);
    }

    return 0;
}

static void castle_ftree_node_print(struct castle_ftree_node *node)
{
    int i;

    printk("Printing node version=%d with (cap, use) = (%d, %d), is_leaf=%d\n",
        node->version, node->capacity, node->used, node->is_leaf);
    for(i=0; i<node->used; i++)
        printk("(0x%x, 0x%x) ", node->slots[i].block, node->slots[i].version);
    printk("\n");
}

static void castle_ftree_lub_find(struct castle_ftree_node *node,
                                  uint32_t block, 
                                  uint32_t version,
                                  int *lub_idx_p,
                                  int *insert_idx_p)
{
    struct castle_ftree_slot *slot;
    uint32_t block_lub, version_lub;
    int      lub_idx, insert_idx, i;

    debug("Looking for (b,v) = (0x%x, 0x%x), node->used=%d, capacity=%d\n",
            block, version, node->used, node->capacity);
        
    lub_idx   = -1;
    block_lub = INVAL_BLK; 
    for(i=node->used-1; i >= 0; i--)
    {
        slot = &node->slots[i];

        debug(" (b,v) = (0x%x, 0x%x)\n", 
               slot->block,
               slot->version);

        /* If the block is already too small, we must have gone past the least
           upper bound */
        if(slot->block < block)
            break;

        /* Do not consider versions which are not ancestral to the version we 
           are looking for.
           Also, don't update the LUB index if the block number doesn't change.
           This is because the most recent ancestor will be found first when
           scanning from right to left */
        if((block_lub != slot->block) &&
            castle_version_is_ancestor(slot->version, version))
        {
            block_lub   = slot->block;
            version_lub = slot->version;
            lub_idx = i;
            debug("  set b_lub=0x%x, lub_idx=%d\n", block_lub, lub_idx);
        }
    } 

    /* If we are insterting something into the node, work out where should it go */
    /* Case 1: (block_lub == block) && (version_lub == version)
               no need to insert, we have exactly the (b,v) we wanted
       Case 2: (block_lub == block) && (version_lub != version)
               but we know that is_ancestor(version_lub, version) == 1
               this means that 'version' is more recent than version_lub, and
               it needs to go (just) to the right of the LUB
               => insert_idx = lub_idx + 1
       Case 3: (block_lub > block)
               there is no (b_x, v_x) such that 
               (block <= b_x < block_lub) && (is_ancestor(v_x, version)) because then 
               (b_x, v_x) would be the LUB.
               Therefore, in the inclusive range [i+1, lub_idx-1] there are no 
               ancestors of 'version'. It follows that we should insert on the basis
               of block numbers only. Therefore i+1 will point to the correct place.
       Case 4: There is no LUB.
               This case is similar to Case 3, in that there is no (b_x, v_x) such
               that (block <= b_x) && (is_ancestor(v_x, version)).
               Insert at i+1.
       Cases are exhaustive, because either LUB doesn't exist (Case 4), or it does,
       in which case, block_lub > block (Case 3) or block_lub == block (Case 2 and Case 1).
    */
    if((lub_idx < 0) || (block_lub > block))
    /* Case 4 and Case 3 */
    {
        insert_idx = i+1;    
    }
    else
    if (version_lub != version)
    /* Case 2 */
    {
        BUG_ON(block_lub != block);
        insert_idx = lub_idx + 1;
    } else
    /* Case 1 */
    {
        BUG_ON(block_lub   != block);
        BUG_ON(version_lub != version);
        insert_idx = lub_idx;
    }

    if(lub_idx_p)    *lub_idx_p = lub_idx;
    if(insert_idx_p) *insert_idx_p = insert_idx;
}

static int castle_ftree_write_idx_find(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int i, idx;
    
    idx = node->used;
    for(i=node->used-1; i >= 0; i--)
    {
        slot = &node->slots[i];
        
        /* We've went to far now */
        if(slot->block < block)
            break;

        /* Check versions if the block is the same */
        if(slot->block == block)
        {
            /* If we found our own ancestor we must have gone too far ... */
            if(castle_version_is_ancestor(slot->version, version)) 
            {
                /* ... unless we are looking at exactly the same version,
                       in which case we've got exactly the entry we were 
                       looking to insert */
                if(slot->version == version)
                    idx = i;
                break;
            }
        }    
        idx = i;
    }

    return idx;
}

static c2_page_t* castle_ftree_effective_node_create(struct castle_ftree_node *node,
                                                     uint32_t version)
{
    c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
    c2_page_t   *c2p = castle_cache_page_get(cdb);
    struct castle_ftree_node *eff_node = pfn_to_kaddr(page_to_pfn(c2p->page));
    struct castle_ftree_slot *last_eff_slot, *slot;
    int i;

    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    eff_node->magic    = FTREE_NODE_MAGIC;
    eff_node->version  = version;
    eff_node->capacity = FTREE_NODE_SLOTS;
    eff_node->used     = 0;
    eff_node->is_leaf  = node->is_leaf;

    for(i=0, last_eff_slot = NULL; i<node->used; i++)
    {
        slot = &node->slots[i];

        BUG_ON(eff_node->used >= eff_node->capacity);
        /* Check if slot->version is ancestoral to version. If not,
           reject straigt away. */
        if(!castle_version_is_ancestor(slot->version, version))
            continue;

        if(!last_eff_slot || last_eff_slot->block != slot->block)
        {
            /* Allocate a new slot if the last eff slot doesn't exist
               or refers to a different block */
            last_eff_slot = &eff_node->slots[eff_node->used++]; 
        } else
        {
            /* last_eff_slot != NULL && last_eff_slot->block == slot->block
               => do not allocate a new slot, replace it instead.
               Since we are scanning from left to right, we should be
               looking on more recent versions of the block now. Check for that.
             */
            /* TODO: these asserts should really be turned into
                     'corrupt btree' exception. */
            BUG_ON(!castle_version_is_ancestor(last_eff_slot->version, 
                                               slot->version));
        }
        memcpy(last_eff_slot,
               slot,
               sizeof(struct castle_ftree_slot)); 
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL.
       Note that effective node is only identical to the original node if the
       entries match, BUT also the version of the node itself also match. 
     */ 
    if((node->version == version) && (eff_node->used == node->used))
    {
        unlock_c2p(c2p);
        put_c2p(c2p);
        /* TODO: should also return the allocated disk block, but our allocator
                 is too simple to handle this ATM */
        return NULL;
    }

    /* Mark the node dirty, so that it'll get written out, even if nothing gets
       inserted into it */ 
    dirty_c2p(c2p);

    return c2p;
}

static c2_page_t* castle_ftree_node_key_split(c2_page_t *orig_c2p)
{
    c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
    c2_page_t   *c2p = castle_cache_page_get(cdb);
    struct castle_ftree_node *node = pfn_to_kaddr(page_to_pfn(orig_c2p->page));
    struct castle_ftree_node *sec_node = pfn_to_kaddr(page_to_pfn(c2p->page));

    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    sec_node->magic    = FTREE_NODE_MAGIC;
    sec_node->version  = node->version;
    sec_node->capacity = FTREE_NODE_SLOTS;
    sec_node->used     = node->used >> 1;
    sec_node->is_leaf  = node->is_leaf;

    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    node->used -= sec_node->used;
    memcpy(sec_node->slots, 
           node->slots, 
           sec_node->used * sizeof(struct castle_ftree_slot));
    memmove( node->slots, 
            &node->slots[sec_node->used], 
             node->used * sizeof(struct castle_ftree_slot));
    /* c2p for node will be dirtied by the caller, we cannot work out its c2p from here */
    dirty_c2p(orig_c2p);
    dirty_c2p(c2p);

    return c2p;
}

static void castle_ftree_slot_insert(c2_page_t *c2p,
                                     int index,
                                     uint32_t type,
                                     uint32_t block,
                                     uint32_t version,
                                     c_disk_blk_t cdb)
{
    struct castle_ftree_node *node = pfn_to_kaddr(page_to_pfn(c2p->page));
    struct castle_ftree_slot *slot;

    BUG_ON(index      >  node->used);
    BUG_ON(node->used >= node->capacity);
    
    /* Make space for the extra slot. */
    memmove(&node->slots[index+1],
            &node->slots[index],
            sizeof(struct castle_ftree_slot) * (node->used - index));
    slot = &node->slots[index]; 
    slot->type    = type;
    slot->block   = block;
    slot->version = version;
    slot->cdb     = cdb;
    node->used++;
    dirty_c2p(c2p);
}

static void castle_ftree_node_insert(c2_page_t *parent_c2p,
                                     c2_page_t *child_c2p)
{
    struct castle_ftree_node *parent
                     = pfn_to_kaddr(page_to_pfn(parent_c2p->page));
    struct castle_ftree_node *child
                     = pfn_to_kaddr(page_to_pfn(child_c2p->page));
    uint32_t block   = child->slots[child->used-1].block; 
    uint32_t version = child->version;
    int insert_idx;

    castle_ftree_lub_find(parent, block, version, NULL, &insert_idx);
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), will insert (b,v)=(0x%x, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, block, version, insert_idx);
    castle_ftree_slot_insert(parent_c2p, 
                             insert_idx, 
                             FTREE_SLOT_NODE,
                             block,
                             version,
                             child_c2p->cdb);
}

static void castle_ftree_node_under_key_insert(c2_page_t *parent_c2p,
                                               c2_page_t *child_c2p,
                                               uint32_t block,
                                               uint32_t version)
{
    struct castle_ftree_node *parent
                     = pfn_to_kaddr(page_to_pfn(parent_c2p->page));
    int insert_idx;

    castle_ftree_lub_find(parent, block, version, NULL, &insert_idx);
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), will insert (b,v)=(0x%x, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, block, version, insert_idx);
    castle_ftree_slot_insert(parent_c2p, 
                             insert_idx, 
                             FTREE_SLOT_NODE,
                             block,
                             version,
                             child_c2p->cdb);
}

static int castle_ftree_new_root_create(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node;
    c_disk_blk_t cdb; 
    c2_page_t *c2p;
    int ret;
    
    debug("Creating a new root node, while handli write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Allocate a new block */
    cdb = castle_slaves_disk_block_get(); 
    debug("Allocated new disk block (0x%x, 0x%x).\n", cdb.disk, cdb.block);
    c2p = castle_cache_page_get(cdb);
    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    node = pfn_to_kaddr(page_to_pfn(c2p->page));
    /* Init the node correctly */
    node->magic    = FTREE_NODE_MAGIC;
    node->version  = c_bvec->version;
    node->capacity = FTREE_NODE_SLOTS;
    node->used     = 0;
    node->is_leaf  = 0;
    /* Update the version tree, and release the version lock (c2p_forget will 
       no longer do that, because there will be a parent node). */
    debug("About to update version tree.\n");
    /* TODO: Check if we hold the version lock */
    ret = castle_version_ftree_update(c_bvec->version, cdb);
    /* If we failed to update the version tree, dealloc the root */
    if(ret)
    {
        debug("Failed.\n");
        /* TODO: dealloc the block */
        unlock_c2p(c2p);
        put_c2p(c2p);
        return ret;
    }
    debug("Succeeded.\n");
    /* Set the node dirty (it'll also get set dirty when inserting into it later),
       but dirty_c2p can be called multiple times just fine. */
    dirty_c2p(c2p);
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2p;
    castle_version_ftree_unlock(c_bvec->version);
    return 0;
}

static int castle_ftree_node_split(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node, *eff_node, *split_node, *parent_node;
    c2_page_t *eff_c2p, *split_c2p, *retain_c2p, *parent_c2p;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int new_root;
    
    debug("Node full while inserting (0x%x,0x%x), creating effective node for it.\n",
            block, version);
    node = c_bvec_bnode(c_bvec);
    eff_c2p = split_c2p = NULL;
    retain_c2p = c_bvec->btree_node;

    /* Create the effective node */
    eff_c2p = castle_ftree_effective_node_create(node, version);
    if(eff_c2p)
    {
        debug("Effective node NOT identical to the original node.\n");
        /* Cast eff_c2p buffer to eff_node */
        eff_node = pfn_to_kaddr(page_to_pfn(eff_c2p->page));
        /* We should continue the walk with the effective node, rather than the
           original node */
        retain_c2p = eff_c2p;
    } else
    {
        debug("Effective node identical to the original node.\n");
        /* IMPORTANT: point eff_node to the original node, but DO NOT change eff_c2p.
           We need to remember what needs to be inserted into the parent node later */
        eff_node = node;
    }

    /* Split the effective node if it's more than 75% full */
    if(eff_node->used > (eff_node->capacity >> 1) + (eff_node->capacity >> 2))
    {
        debug("Effective node too full, splitting.\n");
        split_c2p = castle_ftree_node_key_split(eff_c2p ? eff_c2p : c_bvec->btree_node);
        split_node = pfn_to_kaddr(page_to_pfn(split_c2p->page));
        BUG_ON(split_node->version != c_bvec->version);
        /* Work out whether to take the split node for the further btree walk.
           Since in the effective & split node there is at most one version
           for each block, and this version is ancestoral to what we are
           looking for, it's enough to check if the last entry in the 
           split node (that's the node that contains left hand side elements
           from the original effective node) is greater-or-equal to the block
           we are looking for */
        if(split_node->slots[split_node->used-1].block >= block)
        {
            debug("Retaing the split node.\n");
            retain_c2p = split_c2p;
        }
    }

    /* If we don't have a parent, we may may need to create a new root node.
       If not, the effective node will act as the new root node. In either 
       case (version -> root cdb) mapping has to be updated. */
    new_root = 0;
    if(!c_bvec->btree_parent_node)
    {
        int ret;
        
        if(split_c2p)
        {
            debug("Creating new root node.\n");
            ret = castle_ftree_new_root_create(c_bvec);
            new_root = 1;
        } else
        {
            debug("Effective node will be the new root node\n");
            BUG_ON(!eff_c2p);
            ret = castle_version_ftree_update(version, eff_c2p->cdb);
        }
        /* If ret != 0, we failed to update (version -> root) mapping */ 
        if(ret)
        {
            debug("Failed to update version->root mapping.\n");
            /* Free the newly created nodes */
            /* TODO: we should also free the blocks */
            if(split_c2p)
            {
                unlock_c2p(split_c2p);
                put_c2p(split_c2p);
            }
            if(eff_c2p)
            {
                unlock_c2p(eff_c2p);
                put_c2p(eff_c2p);
            }
            return ret;
        }
    }

    /* Work out if we have a parent */
    parent_c2p  = c_bvec->btree_parent_node;
    parent_node = parent_c2p ? pfn_to_kaddr(page_to_pfn(parent_c2p->page)) : NULL;
    /* Insert!
       This is a bit complex, due to number of different cases. Each is described below
       in some detail.
     
       If split node got created then it should be inserted with the
       usual (b,v) in the parent. Parent must have existed, or has just been 
       created
     */
    if(split_c2p)
    {
        debug("Inserting split node.\n");
        BUG_ON(!parent_c2p);
        castle_ftree_node_insert(parent_c2p, split_c2p);
    }

    /* If effective node got created (rather than using the original node) then
       it either needs to be inserted in the usual way, or under MAX block
       if we are insterting into a new root.
       Also, note that if effective node is our new root, and we don't have to
       insert it anywhere. In this case parent_c2p will be NULL. */
    if(eff_c2p && parent_c2p)
    {
        if(new_root)
        {
            debug("Inserting effective node under MAX block key.\n");
            castle_ftree_node_under_key_insert(parent_c2p,
                                               eff_c2p,
                                               MAX_BLK,
                                               c_bvec->version);
        } else
        {
            debug("Inserting effective node under usual key.\n");
            castle_ftree_node_insert(parent_c2p, eff_c2p);
        }
    }

    /* Finally, if new root got created, and the effective node was identical
       to the original node. Insert the original node under MAX block key */
    if(new_root && !eff_c2p)
    {
        debug("Inserting original root node under MAX block key.\n");
        castle_ftree_node_under_key_insert(parent_c2p,
                                           c_bvec->btree_node,
                                           MAX_BLK,
                                           c_bvec->version);
    }

    /* All nodes inserted. Now, unlock all children nodes, except of the
       one with which we'll continue the walk with (saved in retained_c2p) */
    if(retain_c2p != c_bvec->btree_node)
    {
        debug("Unlocking the original node.\n");
        unlock_c2p(c_bvec->btree_node);
        put_c2p(c_bvec->btree_node);
    }
    if((retain_c2p != eff_c2p) && (eff_c2p))
    {
        debug("Unlocking the effective node.\n");
        unlock_c2p(eff_c2p);
        put_c2p(eff_c2p);
    }
    if((retain_c2p != split_c2p) && (split_c2p))
    {
        debug("Unlocking the split node.\n");
        unlock_c2p(split_c2p);
        put_c2p(split_c2p);
    }

    /* Save the retained_c2p */
    c_bvec->btree_node = retain_c2p;

    return 0;
}

static void castle_ftree_write_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *lub_slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      lub_idx, insert_idx, ret;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_WPROCESS);

    /* Check if the node needs to be split first. 
       A leaf node only needs to be split if there are _no_ empty slots in it.
       Internal nodes, if there are less than 2 free slots in them. */ 
    if((FTREE_NODE_IS_LEAF(node) && (node->capacity == node->used)) ||
      (!FTREE_NODE_IS_LEAF(node) && (node->capacity - node->used < 2)))
    {
        debug("===> Splitting node: leaf=%d, cap,use=(%d,%d)\n",
                node->is_leaf, node->capacity, node->used);
        ret = castle_ftree_node_split(c_bvec);
        if(ret)
        {
            /* End the IO in failure */
            castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, ret);
            return;
        }
        /* Make sure that node now points to the correct node after split */
        node = c_bvec_bnode(c_bvec);
    }
 
    /* Find out what to follow, and where to insert */
    castle_ftree_lub_find(node, block, version, &lub_idx, &insert_idx);
    if(lub_idx >= 0) lub_slot = &node->slots[lub_idx];

    /* Deal with non-leaf nodes first */
    if(!FTREE_NODE_IS_LEAF(node))
    {
        /* We should always find the LUB if we are not looking at a leaf node */
        BUG_ON(lub_idx < 0);
        lub_slot = &node->slots[lub_idx];
        debug("Following write down the tree.\n");
        __castle_ftree_find(c_bvec, lub_slot->cdb);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!FTREE_NODE_IS_LEAF(node));

    /* Insert an entry if LUB doesn't match our (b,v) precisely. */
    if(lub_idx < 0 || (lub_slot->block != block) || (lub_slot->version != version))
    {
        c_disk_blk_t cdb = castle_slaves_disk_block_get(); 
        debug("Need to insert (0x%x, 0x%x) into node (used: 0x%x, capacity: 0x%x, leaf=%d).\n",
                block, version,
                node->used, node->capacity, FTREE_NODE_IS_LEAF(node));
        BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);
        castle_ftree_slot_insert(c_bvec->btree_node,
                                 insert_idx,
                                 FTREE_SLOT_LEAF,
                                 block,
                                 version,
                                 cdb);
        dirty_c2p(c_bvec->btree_node);
        castle_ftree_io_end(c_bvec, cdb, 0);
        return;
    } 
    
    /* Final case: (b,v) found in the leaf node */
    BUG_ON((lub_slot->block != block) || (lub_slot->version != version));
    BUG_ON(lub_idx != insert_idx);
    BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);

    debug("Block already exists, modifying in place.\n");
    castle_ftree_io_end(c_bvec, lub_slot->cdb, 0);
}

static void castle_ftree_read_process(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node = c_bvec_bnode(c_bvec);
    struct castle_ftree_slot *slot;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int      lub_idx;

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_RPROCESS);

    castle_ftree_lub_find(node, block, version, &lub_idx, NULL);
    /* We should always find the LUB if we are not looking at a leaf node */
    BUG_ON((lub_idx < 0) && !FTREE_NODE_IS_LEAF(node));
    
    /* If we haven't found the LUB (in the leaf node), return early */
    if(lub_idx < 0)
    {
        debug(" Could not find the LUB for (b,v)=(0x%x, 0x%x)\n", 
            block, version);
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, 0);
        return;
    }

    slot = &node->slots[lub_idx];
    /* If we found the LUB, either complete the ftree walk (if we are looking 
       at a leaf), or go to the next level */
    if(FTREE_SLOT_IS_LEAF(slot))
    {
        debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", 
            slot->block, slot->version);
        if(slot->block == block)
            castle_ftree_io_end(c_bvec, slot->cdb, 0);
        else
            castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, 0);
    }
    else
    {
        debug("Is not a leaf. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                slot->cdb.disk, slot->cdb.block);
        __castle_ftree_find(c_bvec, slot->cdb);
    }
}

void castle_ftree_process(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    if(write)
        castle_ftree_write_process(c_bvec);
    else
        castle_ftree_read_process(c_bvec);
}


/* TODO move locking of c2ps here?. Possibly rename the function */
static int castle_ftree_c2p_remember(c_bvec_t *c_bvec, c2_page_t *c2p)
{
    int ret = 0;

    /* Forget the parent node buffer first */
    castle_ftree_c2p_forget(c_bvec);
    
    /* Sanity check to make sure that the node fits in the buffer */
    BUG_ON(sizeof(struct castle_ftree_node) > PAGE_SIZE);

    /* Save the new node buffer */
    c_bvec->btree_node = c2p;

    /* Format the node to make sure everything is as expected by the rest of the code.
       Only need to do that on the IO read, ie. when updating the buffer. */
    BUG_ON(!c2p_locked(c2p));
    if(!c2p_uptodate(c2p))
        ret = castle_ftree_node_normalize(c_bvec_bnode(c_bvec));

    return ret; 
}

static void castle_ftree_c2p_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    c2_page_t *c2p_to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    c2p_to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    /* Release the buffer if one exists */
    if(c2p_to_forget)
    {
        unlock_c2p(c2p_to_forget);
        put_c2p(c2p_to_forget);
    }
    /* Also, release the version lock.
       On writes: release when there already is a btree_node locked (that's going
                  to be our parent now). But only if there is no parent node yet.
       On reads:  release on first call to forget (btree_node will be NULL)
     */
    if( (  write  &&   c_bvec->btree_node && (!c_bvec->btree_parent_node)) ||
        ((!write) && (!c_bvec->btree_node)) )
    {
        castle_version_ftree_unlock(c_bvec->version); 
    }
    /* Promote node to the parent on writes */
    if(write) c_bvec->btree_parent_node = c_bvec->btree_node;
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_ftree_find_io_end(c2_page_t *c2p, int uptodate)
{
    c_bvec_t *c_bvec = c2p->private;

    debug("Finished IO for: block 0x%lx, in version 0x%x\n", 
            c_bvec->block, c_bvec->version);
    
    /* Callback on error */
    if(!uptodate || castle_ftree_c2p_remember(c_bvec, c2p))
    {
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, -EIO);
        return;
    }

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
    set_c2p_uptodate(c2p);
    /* Put on to the workqueue */
    INIT_WORK(&c_bvec->work, castle_ftree_process);
    queue_work(castle_wq, &c_bvec->work); 
}

static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb)
{
    c2_page_t *c2p;
    int ret;

    debug("Asked for block: 0x%lx, in version 0x%x, reading ftree node (0x%x, 0x%x)\n", 
            c_bvec->block, c_bvec->version, node_cdb.disk, node_cdb.block);
    ret = -ENOMEM;

    castle_debug_bvec_btree_walk(c_bvec);
    c2p = castle_cache_page_get(node_cdb);
    debug("Got the buffer, trying to lock it\n");
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_GOT_NODE);
    lock_c2p(c2p);
    debug("Locked for ftree node (0x%x, 0x%x)\n", 
            node_cdb.disk, node_cdb.block);
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_LOCKED_NODE);
    if(!c2p_uptodate(c2p))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        debug("Buffer not up to date. Scheduling a read.\n");
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_OUTOFDATE);
        c2p->private = c_bvec;
        c2p->end_io = castle_ftree_find_io_end;
        submit_c2p(READ, c2p);
    } else
    {
        debug("Buffer up to date. Processing!\n");
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2p_remember should not return an error, because
           the Btree node had been normalized already. */
        BUG_ON(castle_ftree_c2p_remember(c_bvec, c2p) != 0);
        castle_ftree_process(&c_bvec->work);
    }
}

void castle_ftree_find(c_bvec_t *c_bvec)
{
    c_disk_blk_t root_cdb;

    c_bvec->btree_node = NULL;
    c_bvec->btree_parent_node = NULL;
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_ftree_c2p_forget() */
    root_cdb = castle_version_ftree_lock(c_bvec->version);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    }
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_ftree_find(c_bvec, root_cdb);
}

/***** Init/fini functions *****/
int castle_btree_init(void)
{
    int ret = 0;

    return ret;
}

void castle_btree_free(void)
{
}
