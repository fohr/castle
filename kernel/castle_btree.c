#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_freespace.h"
#include "castle_versions.h"
#include "castle_block.h"
#include "castle_debug.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define iter_debug(_f, ...)     ((void)0)
#else
#define debug(_f, _a...)        (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define iter_debug(_f, _a...)   (printk("Iterator:%.60s:%.4d:  " _f, __func__, __LINE__ , ##_a))
#endif

static void castle_ftree_c2b_forget(c_bvec_t *c_bvec);
static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb,
                                sector_t key_block);

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
    /* Free the c2bs correctly. Call twice to release parent and child
       (if both exist) */
    castle_ftree_c2b_forget(c_bvec);
    castle_ftree_c2b_forget(c_bvec);
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
    /* Does anything have to be done when the node is read off the disk? */
    /* It should go here */
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
    node->is_leaf = FTREE_SLOT_IS_ANY_LEAF(&node->slots[0]);

    for(i=0; i < node->used; i++)
    {
        struct castle_ftree_slot *slot = &node->slots[i];
        /* Fail if node is_leaf doesn't match with the slot. ! needed 
           to guarantee canonical value for boolean true */
        if(!(node->is_leaf) != !(FTREE_SLOT_IS_ANY_LEAF(slot)))
            return -EIO;
        castle_ftree_slot_normalize(slot);
    }

    return 0;
}

static void USED castle_ftree_node_print(struct castle_ftree_node *node)
{
    int i;

    printk("Printing node version=%d with (cap, use) = (%d, %d), is_leaf=%d\n",
        node->version, node->capacity, node->used, node->is_leaf);
    for(i=0; i<node->used; i++)
        printk("[%d] (0x%x, 0x%x) -> (0x%x, 0x%x)\n", 
            i,
            node->slots[i].block,
            node->slots[i].version,
            node->slots[i].cdb.disk,
            node->slots[i].cdb.block);
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
    BUG_ON(BLOCK_INVAL(block));
        
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

c2_block_t* castle_ftree_node_create(int version, int is_leaf)
{
    c_disk_blk_t cdb;
    c2_block_t  *c2b;
    struct castle_ftree_node *node;
    
    cdb = castle_freespace_block_get(0 /* Used to denote nodes used by metadata */); 
    c2b = castle_cache_block_get(cdb);
    
    lock_c2b(c2b);
    set_c2b_uptodate(c2b);

    node = pfn_to_kaddr(page_to_pfn(c2b->page));
    node->magic    = FTREE_NODE_MAGIC;
    node->version  = version;
    node->capacity = FTREE_NODE_SLOTS;
    node->used     = 0;
    node->is_leaf  = is_leaf;

    dirty_c2b(c2b);

    return c2b;
}

static c2_block_t* castle_ftree_effective_node_create(c2_block_t *orig_c2b,
                                                      uint32_t version)
{
    struct castle_ftree_node *node, *eff_node;
    struct castle_ftree_slot *last_eff_slot, *slot;
    c2_block_t *c2b;
    int i;

    node = c2b_bnode(orig_c2b); 
    c2b = castle_ftree_node_create(version, node->is_leaf);
    eff_node = pfn_to_kaddr(page_to_pfn(c2b->page));

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
        
        if(FTREE_SLOT_IS_LEAF_PTR(slot))
        {
            /* If already a leaf pointer, copy directly. */
            memcpy(last_eff_slot,
                   slot,
                   sizeof(struct castle_ftree_slot)); 
        } else
        {
            /* Otherwise construct a new leaf pointer. */
            last_eff_slot->type    = FTREE_SLOT_LEAF_PTR;
            last_eff_slot->block   = slot->block; 
            last_eff_slot->version = slot->version; 
            /* CDB of the block we are splitting from */
            last_eff_slot->cdb     = orig_c2b->cdb; 
        }
    }

    /* If effective node is the same size as the original node, throw it away,
       and return NULL.
       Note that effective node is only identical to the original node if the
       entries match, BUT also the version of the node itself also match. 
     */ 
    if((node->version == version) && (eff_node->used == node->used))
    {
        /* TODO: should clean_c2b? */
        unlock_c2b(c2b);
        put_c2b(c2b);
        /* TODO: should also return the allocated disk block, but our allocator
                 is too simple to handle this ATM */
        return NULL;
    }

    return c2b;
}

static c2_block_t* castle_ftree_node_key_split(c2_block_t *orig_c2b)
{
    c2_block_t *c2b;
    struct castle_ftree_node *node, *sec_node;

    node     = pfn_to_kaddr(page_to_pfn(orig_c2b->page));
    c2b      = castle_ftree_node_create(node->version, node->is_leaf);
    sec_node = pfn_to_kaddr(page_to_pfn(c2b->page));
    /* The original node needs to contain the elements from the right hand side
       because otherwise the key in it's parent would have to change. We want
       to avoid that */
    sec_node->used = node->used >> 1;
    node->used    -= sec_node->used;
    memcpy(sec_node->slots, 
           node->slots, 
           sec_node->used * sizeof(struct castle_ftree_slot));
    memmove( node->slots, 
            &node->slots[sec_node->used], 
             node->used * sizeof(struct castle_ftree_slot));
    
    /* c2b has already been dirtied by the node_create() function, but the orig_c2b
       needs to be dirtied here */
    dirty_c2b(orig_c2b);

    return c2b;
}

static void castle_ftree_slot_insert(c2_block_t *c2b,
                                     int index,
                                     uint8_t type,
                                     uint32_t block,
                                     uint32_t version,
                                     c_disk_blk_t cdb)
{
    struct castle_ftree_node *node = pfn_to_kaddr(page_to_pfn(c2b->page));
    /* TODO: Check that that 'index-1' is really always correct! */
    struct castle_ftree_slot *left_slot = (index > 0 ? &node->slots[index-1] : NULL);
    version_t left_version = (left_slot ? left_slot->version : INVAL_VERSION);
    block_t   left_block   = (left_slot ? left_slot->block   : INVAL_BLOCK);
    struct castle_ftree_slot *slot;

    BUG_ON(index      >  node->used);
    BUG_ON(node->used >= node->capacity);
    
    /* Special case. Newly inserted block may make another entry unreachable.
       This would cause problems with future splits. And therefore unreachable
       entry has to be replaced by the new one.
       The potentially unreachable entry is neccessarily just to the left. 
       It will stop being reachable if:
       - blocks match
       - version to insert descendant from the left_version (and different)
       - version to insert the same as the node version
      If all of the above true, replace rather than insert */ 
    if((left_block   == block) &&
       (left_version != version) &&
        castle_version_is_ancestor(left_version, version) &&
       (version == node->version))
    {
        /* The element we are replacing MUST be a leaf pointer, 
           because left_version is strictly ancestoral to the node version.
           It implies that the block hasn't been insterted here, because 
           blocks are only inserted to weakly ancestoral nodes */
        BUG_ON(!FTREE_SLOT_IS_LEAF_PTR(left_slot));
        /* Replace the slot */
        left_slot->type    = FTREE_SLOT_LEAF_VAL;
        /* We've already checked it just above, but the block #s must match */
        BUG_ON(left_slot->block != block);
        left_slot->version = version;
        left_slot->cdb     = cdb;
        dirty_c2b(c2b);
        return;
    }
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
    dirty_c2b(c2b);
}

static void castle_ftree_node_insert(c2_block_t *parent_c2b,
                                     c2_block_t *child_c2b)
{
    struct castle_ftree_node *parent
                     = pfn_to_kaddr(page_to_pfn(parent_c2b->page));
    struct castle_ftree_node *child
                     = pfn_to_kaddr(page_to_pfn(child_c2b->page));
    uint32_t block   = child->slots[child->used-1].block; 
    uint32_t version = child->version;
    int insert_idx;

    castle_ftree_lub_find(parent, block, version, NULL, &insert_idx);
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), will insert (b,v)=(0x%x, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, block, version, insert_idx);
    castle_ftree_slot_insert(parent_c2b, 
                             insert_idx, 
                             FTREE_SLOT_NODE,
                             block,
                             version,
                             child_c2b->cdb);
}

static void castle_ftree_node_under_key_insert(c2_block_t *parent_c2b,
                                               c2_block_t *child_c2b,
                                               uint32_t block,
                                               uint32_t version)
{
    struct castle_ftree_node *parent
                     = pfn_to_kaddr(page_to_pfn(parent_c2b->page));
    int insert_idx;

    BUG_ON(BLOCK_INVAL(block));
    castle_ftree_lub_find(parent, block, version, NULL, &insert_idx);
    debug("Inserting child node into parent (cap=0x%x, use=0x%x), "
          "will insert (b,v)=(0x%x, 0x%x) at idx=%d.\n",
            parent->capacity, parent->used, block, version, insert_idx);
    castle_ftree_slot_insert(parent_c2b, 
                             insert_idx, 
                             FTREE_SLOT_NODE,
                             block,
                             version,
                             child_c2b->cdb);
}

static int castle_ftree_new_root_create(c_bvec_t *c_bvec)
{
    c2_block_t *c2b;
    struct castle_ftree_node *node;
    int ret;
    
    debug("Creating a new root node, while handling write to version: %d.\n",
            c_bvec->version);
    BUG_ON(c_bvec->btree_parent_node);
    /* Create the node */
    c2b = castle_ftree_node_create(c_bvec->version, 0);
    node = pfn_to_kaddr(page_to_pfn(c2b->page));
    /* Update the version tree, and release the version lock (c2b_forget will 
       no longer do that, because there will be a parent node). */
    debug("About to update version tree.\n");
    /* TODO: Check if we hold the version lock */
    ret = castle_version_ftree_update(c_bvec->version, c2b->cdb);
    /* If we failed to update the version tree, dealloc the root */
    if(ret)
    {
        debug("Failed.\n");
        /* TODO: dealloc the block, possibly clean c2b */
        unlock_c2b(c2b);
        put_c2b(c2b);
        return ret;
    }
    debug("Succeeded.\n");
    /* If all succeeded save the new node as the parent in bvec */
    c_bvec->btree_parent_node = c2b;
    castle_version_ftree_unlock(c_bvec->version);
    clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);

    return 0;
}

static int castle_ftree_node_split(c_bvec_t *c_bvec)
{
    struct castle_ftree_node *node, *eff_node, *split_node, *parent_node;
    c2_block_t *eff_c2b, *split_c2b, *retain_c2b, *parent_c2b;
    uint32_t block = c_bvec->block;
    uint32_t version = c_bvec->version;
    int new_root;
    
    debug("Node full while inserting (0x%x,0x%x), creating effective node for it.\n",
            block, version);
    node = c_bvec_bnode(c_bvec);
    eff_c2b = split_c2b = NULL;
    retain_c2b = c_bvec->btree_node;

    /* Create the effective node */
    eff_c2b = castle_ftree_effective_node_create(retain_c2b, version);
    if(eff_c2b)
    {
        debug("Effective node NOT identical to the original node.\n");
        /* Cast eff_c2b buffer to eff_node */
        eff_node = pfn_to_kaddr(page_to_pfn(eff_c2b->page));
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

    /* Split the effective node if it's more than 75% full */
    if(eff_node->used > (eff_node->capacity >> 1) + (eff_node->capacity >> 2))
    {
        debug("Effective node too full, splitting.\n");
        split_c2b = castle_ftree_node_key_split(eff_c2b ? eff_c2b : c_bvec->btree_node);
        split_node = pfn_to_kaddr(page_to_pfn(split_c2b->page));
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
            retain_c2b = split_c2b;
        }
    }

    /* If we don't have a parent, we may may need to create a new root node.
       If not, the effective node will act as the new root node. In either 
       case (version -> root cdb) mapping has to be updated. */
    new_root = 0;
    if(!c_bvec->btree_parent_node)
    {
        int ret;
        
        if(split_c2b)
        {
            debug("Creating new root node.\n");
            ret = castle_ftree_new_root_create(c_bvec);
            new_root = 1;
        } else
        {
            debug("Effective node will be the new root node\n");
            BUG_ON(!eff_c2b);
            ret = castle_version_ftree_update(version, eff_c2b->cdb);
        }
        /* If ret != 0, we failed to update (version -> root) mapping */ 
        if(ret)
        {
            debug("Failed to update version->root mapping.\n");
            /* Free the newly created nodes */
            /* TODO: we should also free the blocks */
            if(split_c2b)
            {
                unlock_c2b(split_c2b);
                put_c2b(split_c2b);
            }
            if(eff_c2b)
            {
                unlock_c2b(eff_c2b);
                put_c2b(eff_c2b);
            }
            return ret;
        }
    }

    /* Work out if we have a parent */
    parent_c2b  = c_bvec->btree_parent_node;
    parent_node = parent_c2b ? pfn_to_kaddr(page_to_pfn(parent_c2b->page)) : NULL;
    /* Insert!
       This is a bit complex, due to number of different cases. Each is described below
       in some detail.
     
       If split node got created then it should be inserted with the
       usual (b,v) in the parent. Parent must have existed, or has just been 
       created
     */
    if(split_c2b)
    {
        debug("Inserting split node.\n");
        BUG_ON(!parent_c2b);
        castle_ftree_node_insert(parent_c2b, split_c2b);
    }

    /* If effective node got created (rather than using the original node) then
       it either needs to be inserted in the usual way, or under MAX block
       if we are insterting into a new root.
       Also, note that if effective node is our new root, and we don't have to
       insert it anywhere. In this case parent_c2b will be NULL. */
    if(eff_c2b && parent_c2b)
    {
        if(new_root)
        {
            debug("Inserting effective node under MAX block key.\n");
            castle_ftree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               MAX_BLK,
                                               c_bvec->version);
        } else
        {
            debug("Inserting effective node under usual key.\n");
            castle_ftree_node_under_key_insert(parent_c2b,
                                               eff_c2b,
                                               c_bvec->key_block,
                                               c_bvec->version);
        }
    }

    /* Finally, if new root got created, and the effective node was identical
       to the original node. Insert the original node under MAX block key */
    if(new_root && !eff_c2b)
    {
        debug("Inserting original root node under MAX block key.\n");
        castle_ftree_node_under_key_insert(parent_c2b,
                                           c_bvec->btree_node,
                                           MAX_BLK,
                                           c_bvec->version);
    }

    /* All nodes inserted. Now, unlock all children nodes, except of the
       one with which we'll continue the walk with (saved in retained_c2b) */
    if(retain_c2b != c_bvec->btree_node)
    {
        debug("Unlocking the original node.\n");
        unlock_c2b(c_bvec->btree_node);
        put_c2b(c_bvec->btree_node);
    }
    if((retain_c2b != eff_c2b) && (eff_c2b))
    {
        debug("Unlocking the effective node.\n");
        unlock_c2b(eff_c2b);
        put_c2b(eff_c2b);
    }
    if((retain_c2b != split_c2b) && (split_c2b))
    {
        debug("Unlocking the split node.\n");
        unlock_c2b(split_c2b);
        put_c2b(split_c2b);
    }

    /* Save the retained_c2b */
    c_bvec->btree_node = retain_c2b;

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
       Internal nodes, if there are less than 2 free slots in them. 
       The exception is, if we got here following a leaf pointer. If that's the
       case, we know that we'll be updating in place.
     */ 
    if(!BLOCK_INVAL(c_bvec->key_block) &&
       ((FTREE_NODE_IS_LEAF(node) && (node->capacity == node->used)) ||
       (!FTREE_NODE_IS_LEAF(node) && (node->capacity - node->used < 2))))
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
        BUG_ON(BLOCK_INVAL(c_bvec->key_block));
        lub_slot = &node->slots[lub_idx];
        debug("Following write down the tree.\n");
        __castle_ftree_find(c_bvec, lub_slot->cdb, lub_slot->block);
        return;
    }

    /* Deal with leaf nodes */
    BUG_ON(!FTREE_NODE_IS_LEAF(node));

    /* Insert an entry if LUB doesn't match our (b,v) precisely. */
    if(lub_idx < 0 || (lub_slot->block != block) || (lub_slot->version != version))
    {
        c_disk_blk_t cdb = castle_freespace_block_get(version); 
        
        /* TODO: should memset the page to zero (because we return zeros on reads)
                 this can be done here, or beter still in _main.c, in data_copy */
        debug("Need to insert (0x%x, 0x%x) into node (used: 0x%x, capacity: 0x%x, leaf=%d).\n",
                block, version,
                node->used, node->capacity, FTREE_NODE_IS_LEAF(node));
        BUG_ON(BLOCK_INVAL(c_bvec->key_block));
        BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);
        castle_ftree_slot_insert(c_bvec->btree_node,
                                 insert_idx,
                                 FTREE_SLOT_LEAF_VAL,
                                 block,
                                 version,
                                 cdb);
        dirty_c2b(c_bvec->btree_node);
        castle_ftree_io_end(c_bvec, cdb, 0);
        return;
    } 
    
    /* Final case: (b,v) found in the leaf node. */
    BUG_ON((lub_slot->block != block) || (lub_slot->version != version));
    BUG_ON(lub_idx != insert_idx);
    BUG_ON(castle_ftree_write_idx_find(c_bvec) != insert_idx);

    /* If we are looking at the leaf pointer, follow it */
    if(FTREE_SLOT_IS_LEAF_PTR(lub_slot))
    {
        debug("Following a leaf pointer to (0x%x, 0x%x).\n", 
                lub_slot->cdb.disk, lub_slot->cdb.block);
        __castle_ftree_find(c_bvec, lub_slot->cdb, INVAL_BLOCK);
        return;
    }

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
       at a 'proper' leaf), or go to the next level (possibly follow a leaf ptr) */
    if(FTREE_SLOT_IS_LEAF_VAL(slot))
    {
        debug(" Is a leaf, found (b,v)=(0x%x, 0x%x)\n", slot->block, slot->version);
        if(slot->block == block)
            castle_ftree_io_end(c_bvec, slot->cdb, 0);
        else
            castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, 0);
    }
    else
    {
        debug("Not a leaf, or a leaf ptr. Read and search (disk,blk#)=(0x%x, 0x%x)\n",
                slot->cdb.disk, slot->cdb.block);
        /* key_block is not needed when reading (also, we might be looking at a leaf ptr)
           use INVAL_BLOCK instead. */
        __castle_ftree_find(c_bvec, slot->cdb, INVAL_BLOCK);
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


/* TODO move locking of c2bs here?. Possibly rename the function */
static int castle_ftree_c2b_remember(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    int ret = 0;

    /* Forget the parent node buffer first */
    castle_ftree_c2b_forget(c_bvec);
    
    /* Sanity check to make sure that the node fits in the buffer */
    BUG_ON(sizeof(struct castle_ftree_node) > PAGE_SIZE);

    /* Save the new node buffer */
    c_bvec->btree_node = c2b;

    /* Format the node to make sure everything is as expected by the rest of the code.
       Only need to do that on the IO read, ie. when updating the buffer. */
    BUG_ON(!c2b_locked(c2b));
    if(!c2b_uptodate(c2b))
        ret = castle_ftree_node_normalize(c_bvec_bnode(c_bvec));

    return ret; 
}

/* TODO check that the root node lock will be released correctly, even on 
   node splits! */
static void castle_ftree_c2b_forget(c_bvec_t *c_bvec)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    c2_block_t *c2b_to_forget;

    /* We don't lock parent nodes on reads */
    BUG_ON(!write && c_bvec->btree_parent_node);
    /* On writes we forget the parent, on reads the node itself */
    c2b_to_forget = (write ? c_bvec->btree_parent_node : c_bvec->btree_node);
    /* Release the buffer if one exists */
    if(c2b_to_forget)
    {
        unlock_c2b(c2b_to_forget);
        put_c2b(c2b_to_forget);
    }
    /* Also, release the version lock.
       On reads release as soon as possible. On writes make sure that we've got
       btree_node c2b locked. */
    if(test_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags) && (!write || c_bvec->btree_node))
    {
        castle_version_ftree_unlock(c_bvec->version); 
        clear_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    }
    /* Promote node to the parent on writes */
    if(write) c_bvec->btree_parent_node = c_bvec->btree_node;
    /* Forget */
    c_bvec->btree_node = NULL;
}

static void castle_ftree_find_io_end(c2_block_t *c2b, int uptodate)
{
    c_bvec_t *c_bvec = c2b->private;

    debug("Finished IO for: block 0x%lx, in version 0x%x\n", 
            c_bvec->block, c_bvec->version);
    
    /* Callback on error */
    if(!uptodate || castle_ftree_c2b_remember(c_bvec, c2b))
    {
        castle_ftree_io_end(c_bvec, INVAL_DISK_BLK, -EIO);
        return;
    }

    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
    set_c2b_uptodate(c2b);

    BUG_ON(c_bvec->btree_depth > MAX_BTREE_DEPTH);
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree. 
       A single queue cannot be used, because a request blocked on 
       lock_c2b() would block the entire queue (=> deadlock). */
    INIT_WORK(&c_bvec->work, castle_ftree_process);
    queue_work(castle_wqs[c_bvec->btree_depth], &c_bvec->work); 
}

static void __castle_ftree_find(c_bvec_t *c_bvec,
                                c_disk_blk_t node_cdb,
                                sector_t key_block)
{
    c2_block_t *c2b;
    int ret;

    debug("Asked for block: 0x%lx, in version 0x%x, reading ftree node (0x%x, 0x%x)\n", 
            c_bvec->block, c_bvec->version, node_cdb.disk, node_cdb.block);
    ret = -ENOMEM;

    c_bvec->btree_depth++;
    c_bvec->key_block = key_block;
    castle_debug_bvec_btree_walk(c_bvec);

    c2b = castle_cache_block_get(node_cdb);
#ifdef CASTLE_DEBUG
    c_bvec->locking = c2b;
#endif
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_GOT_NODE);
    lock_c2b(c2b);
    castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_LOCKED_NODE);

    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_OUTOFDATE);
        c2b->private = c_bvec;
        c2b->end_io = castle_ftree_find_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    } else
    {
        /* If the buffer is up to date, copy data, and call the node processing
           function directly. c2b_remember should not return an error, because
           the Btree node had been normalized already. */
        castle_debug_bvec_update(c_bvec, C_BVEC_BTREE_NODE_UPTODATE);
        BUG_ON(castle_ftree_c2b_remember(c_bvec, c2b) != 0);
        castle_ftree_process(&c_bvec->work);
    }
}

static void _castle_ftree_find(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_device *c_dev = c_bvec->c_bio->c_dev;
    c_disk_blk_t root_cdb;

    c_bvec->btree_depth       = 0;
    c_bvec->btree_node        = NULL;
    c_bvec->btree_parent_node = NULL;
    /* Lock the pointer to the root node.
       This is unlocked by the (poorly named) castle_ftree_c2b_forget() */
    down_read(&c_dev->lock);
    c_bvec->version = c_dev->version;
    root_cdb = castle_version_ftree_lock(c_bvec->version);
    up_read(&c_dev->lock);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        castle_bio_data_io_end(c_bvec, -EINVAL);
        return;
    }
    set_bit(CBV_ROOT_LOCKED_BIT, &c_bvec->flags);
    castle_debug_bvec_update(c_bvec, C_BVEC_VERSION_FOUND);
    __castle_ftree_find(c_bvec, root_cdb, MAX_BLK);
}

void castle_ftree_find(c_bvec_t *c_bvec)
{
    INIT_WORK(&c_bvec->work, _castle_ftree_find);
    queue_work(castle_wqs[19], &c_bvec->work); 
}

/* Btree iterate functions */

/* Put c2b's on the path from given depth. from = 0 means put entire path */
static void castle_ftree_iter_path_put(c_iter_t *c_iter, int from)
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

static void castle_ftree_iter_end(c_iter_t *c_iter, int err)
{
    iter_debug("Putting path, ending\n");
    
    castle_ftree_iter_path_put(c_iter, 0);
    
    if (c_iter->end) 
        c_iter->end(c_iter, err);
}

#define indirect_node(_i)      (c_iter->indirect_nodes[(_i)]) 
#define cdb_lt(_cdb1, _cdb2) ( ((_cdb1).disk  < (_cdb2).disk ) ||            \
                              (((_cdb1).disk == (_cdb2).disk ) &&            \
                               ((_cdb1).block < (_cdb2).block)) )           
#define c2b_follow_ptr(_i)     indirect_node(indirect_node(_i).r_idx).c2b

#define slot_follow_ptr(_i, _real_c2b, _real_slot)                           \
({                                                                           \
    struct castle_ftree_node *_n;                                            \
                                                                             \
    (_real_c2b)  = c_iter->path[c_iter->depth];                              \
    _n           = c2b_bnode(_real_c2b);                                     \
    (_real_slot) = &_n->slots[_i];                                           \
    if(FTREE_SLOT_IS_LEAF_PTR(_real_slot))                                   \
    {                                                                        \
        (_real_c2b)  = c2b_follow_ptr(_i);                                   \
        _n           = c2b_bnode(_real_c2b);                                 \
        (_real_slot) = &_n->slots[indirect_node(_i).node_idx];               \
    }                                                                        \
 })

void castle_ftree_iter_replace(c_iter_t *c_iter, int index, c_disk_blk_t cdb)
{
    struct castle_ftree_slot *real_slot;
    c2_block_t *real_c2b;
#ifdef DEBUG    
    struct castle_ftree_node *node;
    
    iter_debug("Version=0x%x, index=%d\n", c_iter->version, index);

    real_c2b = c_iter->path[c_iter->depth];
    BUG_ON(real_c2b == NULL);
    
    node = c2b_bnode(real_c2b);
    BUG_ON(!FTREE_NODE_IS_LEAF(node));
    BUG_ON(index >= node->used);
#endif    
    
    slot_follow_ptr(index, real_c2b, real_slot);
    iter_debug("Current=(0x%x, 0x%x), new=(0x%x, 0x%x), "
               "in btree node: (0x%x, 0x%x), index=%d\n", 
                slot->cdb.disk, 
                slot->cdb.block, 
                cdb.disk, 
                cdb.block, 
                leaf->cdb.disk, 
                leaf->cdb.block, 
                index);
    
    real_slot->cdb = cdb;
    dirty_c2b(real_c2b);
}

static void __castle_ftree_iter_start(c_iter_t *c_iter);

void castle_ftree_iter_continue(c_iter_t *c_iter)
{
    struct castle_ftree_node *node;
    c2_block_t *leaf; 
    int i;

    iter_debug("Continuing.\n");
    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);
    
    node = c2b_bnode(leaf);
    BUG_ON(!FTREE_NODE_IS_LEAF(node));
    
    /* Unlock all the indirect nodes. */
    for(i=FTREE_NODE_SLOTS-1; i>=0; i--)
    {
        if(indirect_node(i).c2b)
        {
            unlock_c2b(indirect_node(i).c2b);
            put_c2b(indirect_node(i).c2b);
            indirect_node(i).c2b = NULL;
        }
    }
    iter_debug("Unlocking cdb=(0x%x, 0x%x)\n", 
        leaf->cdb.disk, leaf->cdb.block);
    unlock_c2b(leaf);
    
    castle_ftree_iter_start(c_iter);
}

static void castle_ftree_iter_leaf_ptrs_sort(c_iter_t *c_iter, int nr_ptrs)
{
    int i, root, child, start, end, last_r_idx;
    c_disk_blk_t last_cdb;

    /* We use heapsort, using Wikipedia's pseudo-code as the reference */
#define swap(_i, _j)                                                      \
           {c_disk_blk_t tmp_cdb;                                         \
            uint8_t      tmp_f_idx;                                       \
            tmp_cdb   = indirect_node(_i).cdb;                            \
            tmp_f_idx = indirect_node(_i).f_idx;                          \
            indirect_node(_i).cdb   = indirect_node(_j).cdb;              \
            indirect_node(_i).f_idx = indirect_node(_j).f_idx;            \
            indirect_node(_j).cdb   = tmp_cdb;                            \
            indirect_node(_j).f_idx = tmp_f_idx;}
    
#define sift_down(_start, _end)                                           \
   {root = (_start);                                                      \
    while((2*root + 1) <= (_end))                                         \
    {                                                                     \
        child = 2 * root + 1;                                             \
        if((child < (_end)) &&                                            \
            cdb_lt(indirect_node(child).cdb, indirect_node(child+1).cdb)) \
                child = child+1;                                          \
        if(cdb_lt(indirect_node(root).cdb, indirect_node(child).cdb))     \
        {                                                                 \
            swap(root, child)                                             \
            root = child;                                                 \
        } else                                                            \
        {                                                                 \
            break;                                                        \
        }                                                                 \
    }}

    /* Arrange the array into a heap */
    for(start = (nr_ptrs - 2)/2; start >= 0; start--)
        sift_down(start, nr_ptrs-1);

    /* Sort */ 
    for(end=nr_ptrs-1; end > 0; end--)
    {
        swap(end, 0);
        sift_down(0, end-1);
    }

    /* Create the reverse map. Also, remove duplicate cdbs from the array */
    last_cdb   = INVAL_DISK_BLK;
    last_r_idx = -1;
    for(i=0; i < nr_ptrs; i++)
    {
        if(DISK_BLK_EQUAL(indirect_node(i).cdb, last_cdb))
        {
            BUG_ON(last_r_idx < 0);
            indirect_node(indirect_node(i).f_idx).r_idx = last_r_idx;
            indirect_node(i).cdb = INVAL_DISK_BLK;
        } else
        {
            indirect_node(indirect_node(i).f_idx).r_idx = i;
            last_cdb   = indirect_node(i).cdb;
            last_r_idx = i;
        }
    }
}

static void castle_ftree_iter_leaf_ptrs_lock(c_iter_t *c_iter)
{
    struct castle_ftree_node *node;
    struct castle_ftree_slot *slot;
    c2_block_t *c2b;
    int i, j, nr_ptrs;

    node = c2b_bnode(c_iter->path[c_iter->depth]);
    /* Make sure that node->used is smaller than what we can index in 1 byte f/r_idx */
    BUG_ON(node->used >= 256);
    
    /* Find all leaf pointers */
    j=0;
    for(i=0; i<node->used; i++)
    {
        slot = &node->slots[i];
        if(slot->version != c_iter->version)
            continue;
        if(FTREE_SLOT_IS_LEAF_PTR(slot))
        {
            BUG_ON(indirect_node(j).c2b);
            indirect_node(j).cdb   = slot->cdb;
            indirect_node(j).f_idx = i;
            j++;
        }
    }
    nr_ptrs = j;

    /* Sort the pointers on cdb ordering */
    castle_ftree_iter_leaf_ptrs_sort(c_iter, nr_ptrs);

    /* Now that leafs have been sorted, lock them all */
    for(i=0; i<nr_ptrs; i++)
    {
        c_disk_blk_t cdb = indirect_node(i).cdb;
        /* Skip over the invalid (previously duplicated) blocks */
        if(DISK_BLK_INVAL(cdb))
        {
            indirect_node(i).c2b = NULL; 
            continue;
        }
        c2b = castle_cache_block_get(cdb);
        lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
            submit_c2b_sync(READ, c2b);
        indirect_node(i).c2b = c2b; 
    }
    /* Finally, find out where in the indirect block the individual ptrs are */
    for(i=0; i<FTREE_NODE_SLOTS; i++)
        indirect_node(i).node_idx = -1;
    for(i=0; i<node->used; i++)
    {
        slot = &node->slots[i];
        if(slot->version != c_iter->version)
            continue;
        if(FTREE_SLOT_IS_LEAF_PTR(slot))
        {
            int lub_idx;

            castle_ftree_lub_find(c2b_bnode(c2b_follow_ptr(i)), 
                                  slot->block, 
                                  slot->version, 
                                 &lub_idx, 
                                  NULL);
            /* Check that we _really_ found the right entry in the indirect node */
            BUG_ON(lub_idx < 0);
            BUG_ON((c2b_bnode(c2b)->slots[lub_idx].block   != slot->block) ||
                   (c2b_bnode(c2b)->slots[lub_idx].version != slot->version));
            indirect_node(i).node_idx = lub_idx;
        }
    }
}

static void castle_ftree_iter_leaf_process(c_iter_t *c_iter)
{
    struct castle_ftree_node *node;
    struct castle_ftree_slot *slot, *real_slot;
    c2_block_t *leaf; 
    int i;
    
    leaf = c_iter->path[c_iter->depth];
    BUG_ON(leaf == NULL);
    
    node = c2b_bnode(leaf);
    BUG_ON(!FTREE_NODE_IS_LEAF(node));
    
    iter_debug("Processing %d entries\n", node->used);
    
    /* We are in a leaf, then save the vblk number we followed to get here */
    c_iter->next_vblk = BLOCK_INVAL(c_iter->parent_vblk) ? INVAL_BLOCK : c_iter->parent_vblk + 1;

    if (c_iter->node_start != NULL) 
        c_iter->node_start(c_iter);
    
    castle_ftree_iter_leaf_ptrs_lock(c_iter);

    for(i=0; i<node->used; i++)
    {
        if (c_iter->cancelled)
            break;

        slot = &node->slots[i];

        iter_debug("Current slot: (b=0x%x, v=%x)->(cdb=0x%x, 0x%x)\n",
                slot->block, slot->version, slot->cdb.disk, slot->cdb.block);
        if (slot->version == c_iter->version)
        {
            c2_block_t *c2b;

            slot_follow_ptr(i, c2b, real_slot);
            c_iter->each(c_iter, i, real_slot->cdb);
        }
    }

    iter_debug("Done processing entries.\n");

    /* 
     * Send end node callback if one not specified. Otherwise continue automatically.
     */   
    if (c_iter->node_end != NULL)
       c_iter->node_end(c_iter);
    else
       castle_ftree_iter_continue(c_iter);
}

static void castle_ftree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb);

static void __castle_ftree_iter_path_traverse(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);
    struct castle_ftree_node *node;
    struct castle_ftree_slot *slot;
    int index; 

    /* Return early on error */
    if(c_iter->err)
    {
        /* Unlock the top of the stack, this is normally done by 
           castle_ftree_iter_continue. This will not happen now, because 
           the iterator was cancelled between two btree nodes. */
        unlock_c2b(c_iter->path[c_iter->depth]);
        castle_ftree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /* Otherwise, we know that the node got read successfully. Its buffer is in the path. */
    node = c2b_bnode(c_iter->path[c_iter->depth]);

    /* Are we at a leaf? */
    if(FTREE_NODE_IS_LEAF(node))
    {
        castle_ftree_iter_leaf_process(c_iter);
        return;        
    }

    /* Otherwise, 'recurse' - find the occurance of the next vblk */
    castle_ftree_lub_find(node, c_iter->next_vblk, c_iter->version, &index, NULL);
    slot = &node->slots[index];
    iter_debug("Node index=%d\n", index);

    c_iter->depth++;
    c_iter->parent_vblk = slot->block;

    castle_ftree_iter_path_traverse(c_iter, slot->cdb);
}

static void _castle_ftree_iter_path_traverse(c2_block_t *c2b, int uptodate)
{
    c_iter_t *c_iter = c2b->private;

    iter_debug("Finished reading btree node.\n");
   
    if(!uptodate)
    {
        iter_debug("Error reading the btree node. Cancelling iterator.\n");
        unlock_c2b(c2b);
        put_c2b(c2b);
        /* Save the error. This will be handled properly by __path_traverse */
        c_iter->err = -EIO;
    } else
    {
        /* Push the node onto the path 'stack' */
        set_c2b_uptodate(c2b);
        BUG_ON((c_iter->path[c_iter->depth] != NULL) && (c_iter->path[c_iter->depth] != c2b));
        c_iter->path[c_iter->depth] = c2b;
    }
    
    /* Put on to the workqueue. Choose a workqueue which corresponds
       to how deep we are in the tree. 
       A single queue cannot be used, because a request blocked on 
       lock_c2b() would block the entire queue (=> deadlock). 
       NOTE: The +1 is required to match the wqs we are using in normal btree walks. */
    INIT_WORK(&c_iter->work, __castle_ftree_iter_path_traverse);
    queue_work(castle_wqs[c_iter->depth+MAX_BTREE_DEPTH], &c_iter->work);
}

static void castle_ftree_iter_path_traverse(c_iter_t *c_iter, c_disk_blk_t node_cdb)
{
    c2_block_t *c2b = NULL;
    
    iter_debug("Starting the traversal: depth=%d, node_cdb=(0x%x, 0x%x)\n", 
                c_iter->depth, node_cdb.disk, node_cdb.block);
    
    /* Try to use the c2b we've saved in the path, if it matches node_cdb */
    if(c_iter->path[c_iter->depth] != NULL)
    {
        c2b = c_iter->path[c_iter->depth];
        
        if(!DISK_BLK_EQUAL(c2b->cdb, node_cdb))
        {
            castle_ftree_iter_path_put(c_iter, c_iter->depth);
            c2b = NULL;
        }
    }
    
    /* If we haven't found node_cdb in path, get it from the cache instead */
    if(c2b == NULL)
        c2b = castle_cache_block_get(node_cdb);
  
    iter_debug("Locking cdb=(0x%x, 0x%x)\n", 
        c2b->cdb.disk, c2b->cdb.block);
    lock_c2b(c2b);
    
    /* Unlock the ftree if we've just locked the root */
    if(c_iter->depth == 0)
    {
        /* We have just started the iteration - lets unlock the version tree */
        iter_debug("Unlocking version tree.\n");
        castle_version_ftree_unlock(c_iter->version);
    }
    /* Unlock previous c2b */
    if((c_iter->depth > 0) && (c_iter->path[c_iter->depth - 1] != NULL))
    {
        c2_block_t *prev_c2b = c_iter->path[c_iter->depth - 1];
        iter_debug("Unlocking cdb=(0x%x, 0x%x)\n", 
            prev_c2b->cdb.disk, prev_c2b->cdb.block);
        unlock_c2b(prev_c2b);
        /* NOTE: not putting the c2b. Might be useful if we have to walk the tree again */
    }
 
    /* Read from disk where nessecary */
    c2b->private = c_iter;
    if(!c2b_uptodate(c2b))
    {
        iter_debug("Not uptodate, submitting\n");
        
        /* If the buffer doesn't contain up to date data, schedule the IO */
        c2b->end_io = _castle_ftree_iter_path_traverse;
        BUG_ON(submit_c2b(READ, c2b));
    } 
    else
    {
        iter_debug("Uptodate, carrying on\n");
        /* If the buffer is up to date */
        _castle_ftree_iter_path_traverse(c2b, 1);
    }
}

static void __castle_ftree_iter_start(c_iter_t *c_iter)
{
    c_disk_blk_t root_cdb;

    iter_debug("-------------- STARTING THE ITERATOR -------------------\n");

    /* 
     * End conditions: we must be done if:
     *    - we start again at depth 0 - ie the root is a leaf
     *    - we followed MAX_BLK to a leaf
     *    - we were cancelled
     */
    if ((c_iter->depth == 0) || 
        (c_iter->next_vblk == MAX_BLK + 1) ||
        (c_iter->cancelled))
    {
        castle_ftree_iter_end(c_iter, c_iter->err);
        return;
    }
    
    /*
     * Let's start from the root again...
     */
    c_iter->depth = 0;
    
    iter_debug("Locking version tree\n");
    
    root_cdb = castle_version_ftree_lock(c_iter->version);
    if(DISK_BLK_INVAL(root_cdb))
    {
        /* Complete the request early, end exit */
        castle_ftree_iter_end(c_iter, -EINVAL);
        return;
    }

    c_iter->parent_vblk = INVAL_BLOCK;
    castle_ftree_iter_path_traverse(c_iter, root_cdb);
}

static void _castle_ftree_iter_start(struct work_struct *work)
{
    c_iter_t *c_iter = container_of(work, c_iter_t, work);

    __castle_ftree_iter_start(c_iter);
}

void castle_ftree_iter_start(c_iter_t* c_iter)
{
    INIT_WORK(&c_iter->work, _castle_ftree_iter_start);
    queue_work(castle_wq, &c_iter->work);
}

void castle_ftree_iter_init(c_iter_t *c_iter, version_t version)
{
    iter_debug("Initialising iterator for version=0x%x\n", c_iter->version);
    
    c_iter->version = version;
    c_iter->parent_vblk = 0;
    c_iter->next_vblk = 0;
    c_iter->depth = -1;
    c_iter->err = 0;
    c_iter->cancelled = 0;
    memset(c_iter->indirect_nodes, 0, sizeof(c_iter->indirect_nodes));
    memset(c_iter->path, 0, sizeof(c_iter->path));
}

void castle_ftree_iter_cancel(c_iter_t *c_iter, int err)
{
    iter_debug("Cancelling version=0x%x iterator, error=%d\n", c_iter->version, err);
    
    c_iter->err = err;
    wmb();
    c_iter->cancelled = 1;
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
