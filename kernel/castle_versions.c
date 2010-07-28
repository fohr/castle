#include <linux/list.h>
#include <linux/slab.h>
#include <linux/hardirq.h>
#include <linux/sched.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_freespace.h"
#include "castle_versions.h"
#include "castle_sysfs.h"
#include "castle_cache.h"
#include "castle_events.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int castle_versions_process(void);

static struct kmem_cache *castle_versions_cache  = NULL;

#define CASTLE_VERSIONS_HASH_SIZE       (1000)
static struct list_head  *castle_versions_hash   = NULL;
static          LIST_HEAD(castle_versions_init_list);

static version_t          castle_versions_last   = INVAL_VERSION;
static c_mstore_t        *castle_versions_mstore = NULL;
static c_mstore_t        *castle_roots_mstore    = NULL;

struct castle_tree_root {
    tree_seq_t       tree_seq; 
    version_t        version;
    c_disk_blk_t     root;
    c_mstore_key_t   mstore_key;
    struct list_head version_list;
    struct list_head ct_list; 
};

#define CV_INITED_BIT             (0)
#define CV_INITED_MASK            (1 << CV_INITED_BIT)
#define CV_ATTACHED_BIT           (1)
#define CV_ATTACHED_MASK          (1 << CV_ATTACHED_BIT)
#define CV_SNAP_BIT               (2)
#define CV_SNAP_MASK              (1 << CV_SNAP_BIT)
#define CV_FTREE_LOCKED_BIT       (3)
#define CV_FTREE_LOCKED_MASK      (1 << CV_FTREE_LOCKED_BIT)
struct castle_version {
    /* Various tree links */
    version_t                  version;
    union {
        version_t              parent_v;  /* Vaild if !inited */
        struct castle_version *parent;    /* Vaild if  inited */
    };
    struct castle_version     *first_child;
    struct castle_version     *next_sybling;

    /* Aux data */
    c_mstore_key_t   mstore_key;
    version_t        o_order;
    version_t        r_order;
    da_id_t          da_id;
    struct list_head tree_roots;
    uint32_t         size;

    /* Lists for storing versions the hash table & the init list*/
    struct list_head hash_list; 
    unsigned long    flags;
    struct list_head init_list;
};

DEFINE_HASH_TBL(castle_versions, castle_versions_hash, CASTLE_VERSIONS_HASH_SIZE, struct castle_version, hash_list, version_t, version);

static int castle_version_hash_remove(struct castle_version *v, void *unused) 
{
    list_del(&v->hash_list);
    kmem_cache_free(castle_versions_cache, v);

    return 0;
}

static void castle_versions_hash_destroy(void)
{
   castle_versions_hash_iterate(castle_version_hash_remove, NULL); 
   kfree(castle_versions_hash);
}

static void castle_versions_init_add(struct castle_version *v)
{
    v->flags &= (~CV_INITED_MASK);
    list_add(&v->init_list, &castle_versions_init_list);
}

version_t castle_version_max_get(void)
{
    return castle_versions_last + 1;
}

static struct castle_version* castle_version_add(version_t version, 
                                                 version_t parent, 
                                                 da_id_t da_id,
                                                 uint32_t size)
{
    struct castle_version *v;
    
    v = kmem_cache_alloc(castle_versions_cache, GFP_KERNEL);
    if(!v || castle_freespace_version_add(version)) 
        goto out_dealloc;
    
    debug("Adding: (v, p)=(%d,%d)\n", version, parent);
    
    v->version      = version;
    v->parent_v     = parent;
    v->first_child  = NULL; 
    v->next_sybling = NULL; 
    v->o_order      = INVAL_VERSION;
    v->r_order      = INVAL_VERSION;
    INIT_LIST_HEAD(&v->tree_roots);
    v->da_id        = da_id;
    v->size         = size; 
    v->flags        = 0;
    INIT_LIST_HEAD(&v->hash_list);
    INIT_LIST_HEAD(&v->init_list);

    /* Initialise version 0 fully, defer full init of all other versions by 
       putting it on the init list. */ 
    if(v->version == 0)
    {
        if(castle_sysfs_version_add(v->version))
            goto out_dealloc;

        v->parent       = NULL;
        v->first_child  = NULL; /* This will be updated later */
        v->next_sybling = NULL;
        v->flags       |= CV_INITED_MASK;

        castle_versions_hash_add(v);
    } else
    {
        /* Defer the initialisation until all the ancestral nodes are
           available. */
        castle_versions_init_add(v);
        castle_versions_hash_add(v);
    }

    return v;

out_dealloc:
    kmem_cache_free(castle_versions_cache, v);

    return NULL;
}

static struct castle_tree_root *__castle_version_root_get(struct castle_version *v,
                                                          tree_seq_t tree)
{
    struct castle_tree_root *ct;
    struct list_head *l;

    BUG_ON(!test_bit(CV_FTREE_LOCKED_BIT, &v->flags));
    list_for_each(l, &v->tree_roots)
    {
        ct = list_entry(l, struct castle_tree_root, version_list);
        if(ct->tree_seq == tree)
            return ct;
    }

    return NULL;
}

c_disk_blk_t castle_version_root_get(version_t version, tree_seq_t tree)
{
    struct castle_tree_root *ct;
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return INVAL_DISK_BLK;

    ct = __castle_version_root_get(v, tree);
    if(!ct)
        return INVAL_DISK_BLK;

    return ct->root;
}

void castle_version_root_next(tree_seq_t tree,
                              version_t *next_version,
                              c_disk_blk_t *btree_root)
{
    struct castle_component_tree *ct;
    struct castle_tree_root *tr;
    struct list_head *l;
    
    ct = castle_component_tree_get(tree);
    BUG_ON(!ct);

    /* Return invalid if list is empty */
    if(list_empty(&ct->roots_list))
    {
        *next_version = INVAL_VERSION;
        *btree_root = INVAL_DISK_BLK;
        return;
    }

    /* Otherwise, return the first entry from the front of the list, and 
       move it to the tail */
    l = ct->roots_list.next;
    tr = list_entry(l, struct castle_tree_root, ct_list); 
    list_move_tail(l, &ct->roots_list);

    /* Return */
    *next_version = tr->version;
    *btree_root = tr->root;
}

static int castle_version_root_add(version_t version,
                                   tree_seq_t tree_seq, 
                                   c_disk_blk_t root,
                                   c_mstore_key_t mstore_key)
{
    struct castle_component_tree *ct; 
    struct castle_tree_root *r;
    struct castle_version *v;

    debug("Adding root: (v, tree, cdb)=(%d, 0x%x, (0x%x, 0x%x))\n",
            version, tree_seq, root.disk, root.block);
    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;
    
    ct = castle_component_tree_get(tree_seq);
    if(!ct)
        return -EINVAL;
     
    r = kzalloc(sizeof(struct castle_tree_root), GFP_KERNEL);
    if(!r)
        return -ENOMEM;

    r->tree_seq     = tree_seq;
    r->version      = version;
    r->root         = root;
    r->mstore_key   = mstore_key;
    INIT_LIST_HEAD(&r->version_list);
    list_add(&r->version_list, &v->tree_roots);
    INIT_LIST_HEAD(&r->ct_list);
    list_add(&r->ct_list, &ct->roots_list);

    return 0;
}

/* TODO who should handle errors in writeback? */
static void castle_version_writeback(struct castle_version *v, int new)
{
    struct castle_vlist_entry mstore_ventry;
    struct castle_rlist_entry mstore_rentry;
    struct castle_tree_root *root;
    struct list_head *l;
    c_mstore_key_t key;
    
    debug("Writing back version %d\n", v->version);

    mstore_ventry.version_nr = v->version;
    mstore_ventry.parent     = (v->parent ? v->parent->version : 0);
    mstore_ventry.size       = v->size;
    mstore_ventry.da_id      = v->da_id;
    key                      = v->mstore_key;

    if(new)
    {
        debug("New version, inserting.\n");
        v->mstore_key = 
            castle_mstore_entry_insert(castle_versions_mstore, &mstore_ventry);
    }
    else
    {
        debug("Existing version, updating.\n");
        castle_mstore_entry_update(castle_versions_mstore, key, &mstore_ventry);
    }

    list_for_each(l, &v->tree_roots)
    {
        root = list_entry(l, struct castle_tree_root, version_list); 
        
        debug("Writing back root for tree_seq=%d.\n", root->tree_seq);
        BUG_ON(v->version != root->version);
        mstore_rentry.version   = root->version;
        mstore_rentry.tree_seq  = root->tree_seq;
        mstore_rentry.cdb       = root->root;
        key                     = root->mstore_key;
        if(MSTORE_KEY_INVAL(key))
        {
            debug("Inserting the root.\n");
            root->mstore_key = 
                castle_mstore_entry_insert(castle_roots_mstore, &mstore_rentry);
        }
        else
        {
            debug("Updating the root.\n");
            castle_mstore_entry_update(castle_roots_mstore, key, &mstore_rentry);
        }
    }
}

/***** External functions *****/
int castle_version_root_update(version_t version, tree_seq_t tree_id, c_disk_blk_t cdb)
{
    struct castle_tree_root *r;
    struct castle_version *v;
    int ret;

    printk("Updating root for version=%d, tree_id=%d\n", version, tree_id);
    v = castle_versions_hash_get(version);
    BUG_ON(!v);

    r = __castle_version_root_get(v, tree_id);
    if(!r)
    {
        printk("Haven't found root for version=%d, tree_id=%d\n", version, tree_id);
        printk("Creating one.\n");
        ret = castle_version_root_add(version, tree_id, cdb, INVAL_MSTORE_KEY);
        if(ret)
            return ret;
    } else
    {
        r->root = cdb;
    }
  
    castle_version_writeback(v, 0 /* Not new */); 

    return 0;
}

void castle_version_roots_delete(tree_seq_t tree_id)
{
    struct castle_component_tree *ct; 
    struct castle_tree_root *r;
    struct list_head *l, *t;

    printk("Deleting roots for tree_id=%d\n", tree_id);
    ct = castle_component_tree_get(tree_id);
    BUG_ON(!ct);

    list_for_each_safe(l, t, &ct->roots_list)
    {
        r = list_entry(l, struct castle_tree_root, ct_list); 
        list_del(&r->ct_list);
        list_del(&r->version_list);
        
        if(!MSTORE_KEY_INVAL(r->mstore_key))
            castle_mstore_entry_delete(castle_roots_mstore, r->mstore_key);
        kfree(r);
    }
}

static int castle_version_roots_clone(struct castle_version *dst,
                                      struct castle_version *src)
{
    struct castle_tree_root *r;
    struct list_head *l, *t;
    int ret;

    BUG_ON(!list_empty(&dst->tree_roots));
    list_for_each(l, &src->tree_roots)
    {
        r = list_entry(l, struct castle_tree_root, version_list); 
        BUG_ON(src->version != r->version);
        if((ret = castle_version_root_add(dst->version, 
                                          r->tree_seq, 
                                          r->root, 
                                          INVAL_MSTORE_KEY)))
            goto err_out;
    }

    return 0;
err_out:
    /* Free the already created roots, and exit */
    list_for_each_safe(l, t, &dst->tree_roots)
    {
        list_del(l);
        r = list_entry(l, struct castle_tree_root, version_list); 
        kfree(r);
    }

    return ret;
}

static struct castle_version* castle_version_new_create(int snap_or_clone,
                                                        version_t parent,
                                                        da_id_t da_id,
                                                        uint32_t size)
{
    struct castle_version *v, *p;
    uint32_t parent_size;
    version_t version;

    /* Read ftree root from the parent (also, make sure parent exists) */
    p = castle_versions_hash_get(parent);
    if(!p)
    {
        printk("Asked to create a child of non-existant parent: %d\n",
            parent);
        return NULL;
    }
    
    /* Be careful about reading the ftree_root.
       If we are creating a clone, the parent is not attached (by definition)
       and therefore the root will not change. Attach/detach races are 
       prevented by control command serialisation.

       If we are creating a snapshot, we must make sure that there are no
       ongoing writes, because they could key-split the root node (version 
       splits would be fine).

       We prevent this from happening by locking the ftree first. This 
       guarantees that any ongoing writes have already released the root node.
       We can then release the ftree lock straight away, beacuse we are
       doing snapshots under device lock. Therefore, no new IOs will be
       accepted before we release it (by this time the new vesion will 
       be saved to castle_device structure) */ 
    debug("Locking the parent (%d) ftree.\n", parent);
    castle_version_lock(parent);
    castle_version_unlock(parent);
    parent_size = p->size;

    /* Allocate a new version number. */
    BUG_ON(VERSION_INVAL(castle_versions_last));
    version = ++castle_versions_last;
    BUG_ON(VERSION_INVAL(castle_versions_last));

    /* Try to add it to the hash. Use the da_id provided or the parent's */
    BUG_ON(!DA_INVAL(da_id) && !DA_INVAL(p->da_id));
    da_id = DA_INVAL(da_id) ? p->da_id : da_id;
    v = castle_version_add(version, parent, da_id, size);
    if(!v) 
        return NULL;
    
    if(castle_version_roots_clone(v, p))
    {
        castle_versions_hash_remove(v);
        kmem_cache_free(castle_versions_cache, v);
        return NULL;
    }
        
    /* If our parent has the size set, inherit it (ignores the size argument) */
    if(parent_size != 0)
        v->size = parent_size;
    
    /* Set clone/snap bit in flags */ 
    if(snap_or_clone)
        v->flags |= CV_SNAP_MASK;
    else
        v->flags &= ~CV_SNAP_MASK;

    /* Run processing (which will thread the new version into the tree,
       and recalculate the order numbers) */
    castle_versions_process(); 
    
    /* Check if the version got initialised */
    if(!(v->flags & CV_INITED_MASK))
    {
        spin_lock_irq(&castle_versions_hash_lock);
        __castle_versions_hash_remove(v);
        spin_unlock_irq(&castle_versions_hash_lock);
        kmem_cache_free(castle_versions_cache, v);

        return NULL;
    }

    castle_events_version_create(version);

    return v;
}

version_t castle_version_new(int snap_or_clone,
                             version_t parent,
                             da_id_t da_id,
                             uint32_t size)
{
    struct castle_version *v;
    
    debug("New version: snap_or_clone=%d, parent=%d, size=%d\n",
            snap_or_clone, parent, size);
    /* Get a new version number */
    v = castle_version_new_create(snap_or_clone,
                                  parent,
                                  da_id,
                                  size);
        
    /* Return if we couldn't create the version correctly
       (possibly because we trying to clone attached version,
        or because someone asked for more than one snapshot to
        an attached version */
    if(!v)
        return INVAL_VERSION;

    /* We've succeeded at creating a new version number.
       Let's find where to store it on the disk. */

    /* TODO: Error handling? */
    castle_version_writeback(v, 1); 
    
    return v->version; 
}

static int castle_version_ftree_yield(void *word)
{
    /* If you need the version struct here is how you work it out:
	struct castle_version *v = container_of(word, struct castle_version, flags); */

	smp_mb();
    debug("In ftree_yield.\n");
	io_schedule();

	return 0;
}

void castle_version_lock(version_t version)
{
    struct castle_version *v;

    /* This function may sleep on the ftree lock */
	might_sleep();

    v = castle_versions_hash_get(version);

    if(!v) 
        return;

	if (test_and_set_bit(CV_FTREE_LOCKED_BIT, &v->flags))
    {
        /* Slow path */
	    wait_on_bit_lock(&v->flags, 
                          CV_FTREE_LOCKED_BIT, 
                          castle_version_ftree_yield,
                          TASK_UNINTERRUPTIBLE);
    }
}

void castle_version_unlock(version_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    BUG_ON(!v);

    /* Clear the bit, wake up anyone waiting */
	smp_mb__before_clear_bit();
    BUG_ON(!test_bit(CV_FTREE_LOCKED_BIT, &v->flags));
	clear_bit(CV_FTREE_LOCKED_BIT, &v->flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&v->flags, CV_FTREE_LOCKED_BIT);
}

int castle_version_attach(version_t version) 
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    if(test_and_set_bit(CV_ATTACHED_BIT, &v->flags))
        return -EAGAIN;

    return 0;
}

int castle_version_read(version_t version, 
                        da_id_t *da,
                        version_t *parent,
                        uint32_t *size,
                        int *leaf)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;
    
    /* Set these even if we fail to set the attached bit */
    if(da)     *da     =  v->da_id;
    if(size)   *size   =  v->size;
    if(parent) *parent =  v->parent ? v->parent->version : 0;
    if(leaf)   *leaf   = (v->first_child == NULL);

    return 0;
} 

void castle_version_detach(version_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    BUG_ON(!v);
    BUG_ON(!test_and_clear_bit(CV_ATTACHED_BIT, &v->flags));
}

static void castle_versions_insert(struct castle_version *p,
                                   struct castle_version *v)
{
    struct castle_version *sybling_list;
    struct castle_version **pprev;

    /* We know who our parent is */
    v->parent = p;
    /* Sybling list starts with whatever the parent is pointing at. pprev will point to
       the address where sybling list was stored. This allows us to update it without
       special casing first child etc. */
    pprev = &p->first_child;
    sybling_list = *pprev;
    while(sybling_list && (sybling_list->version > v->version))
    {
        pprev = &sybling_list->next_sybling;
        sybling_list = *pprev;
    }
    BUG_ON(!pprev);
    v->next_sybling = sybling_list;
    *pprev = v;
}

static int castle_versions_process(void)
{
    struct castle_version *v, *p, *n;
    LIST_HEAD(sysfs_list); 
    version_t id;
    int children_first, ret;
    int err = 0;

    spin_lock_irq(&castle_versions_hash_lock);
    /* Start processing elements from the init list, one at the time */
    while(!list_empty(&castle_versions_init_list))
    {
        v = list_first_entry(&castle_versions_init_list, 
                              struct castle_version,
                              init_list);
process_version:        
        /* Remove the element from the list */
        list_del(&v->init_list);
        BUG_ON(v->flags & CV_INITED_MASK);

        /* Find it's parent, and check if it's been inited already */
        p = __castle_versions_hash_get(v->parent_v);
        BUG_ON(!p);
        debug("Processing version: %d, parent: %d\n", v->version, p->version);
        /* We can only snapshot leaf nodes */ 
        if((v->flags & CV_SNAP_MASK) &&   /* version is a snapshot    */
           (p->first_child != NULL))      /* there already is a child */
        {
            printk("Warn: ignoring snapshot: %d, parent: %d has a child %d already.\n",
                    v->version, p->version, p->first_child->version);
            err = -1;
            continue;
        }
        /* Clones can only be made if the parent isn't attached writeably
           Which is the same as to say that the parent is a leaf */
        if(!(v->flags & CV_SNAP_MASK) &&        /* version is a clone */
            (p->flags & CV_ATTACHED_MASK) &&    /* parent is attached */
            (p->first_child == NULL))           /* parent is a leaf   */
        {
            printk("Warn: ignoring clone: %d, parent: %d is a leaf.\n",
                    v->version, p->version);
            err = -2;
            continue;
        }
        /* If the parent hasn't been initialised yet, initialise it instead */
        if(!(p->flags & CV_INITED_MASK))
        {
            /* Re-add v back to the init list.
               Because the element is added to the front of the list O(n) is guaranteed.
               This is because after following parent pointers up to the root of the tree,
               we will come back down initialising all children on the path. */
            list_add(&v->init_list, &castle_versions_init_list);
            debug("Changing version to parent.\n");
            /* Set v to the parent */
            v = p;
            /* Retry processing, this time starting with the parent. 
               This has to succeed at some point because version 0 
               is guaranteed to be inited */
            goto process_version;
        }
        /* If we got here we know that the parent has been inited */
        debug(" Parent initialised, (v,p)=(%d,%d)\n", v->version, p->version);
        /* Insert v at the start of the sybling list. */
        castle_versions_insert(p, v);
        list_add(&v->init_list, &sysfs_list);

        /* We are done setting this version up. */
        v->flags |= CV_INITED_MASK;
    }
    debug("Done with tree init.\n");

    /* Now, once the tree has been built, assign the order to the nodes
       We assign two id's to each node. o_order is based on when is the node 
       visited first time in DFS, r_order when the node is visited last. 
       The code below implements non-recursive DFS (we don't have enough stack for
       potentialy deep recursion */  
    v = __castle_versions_hash_get(0); 
    BUG_ON(!v);
    BUG_ON(!(v->flags & CV_INITED_MASK));
    BUG_ON(v->parent);
    id = 0;
    children_first = 1;
    
    while(v)
    {
        debug("Looking at version: %d\n", v->version);
        n = NULL;
        /* If going down the tree select the next node in the following order
           of preference:
           - first child
           - next sybling
           - parent
           On the way up select:
           - next sybling
           - parent
           Note that the next sybling & parent cases are common to both cases.
           Also, if the parent is selected, make sure 'children_first' is not set */
        if(children_first)
        {
            v->o_order = ++id;
            debug("Assigned version=%d o_order %d\n", v->version, v->o_order);
            /* Only attempt to go to the child on the way down the tree */
            n = v->first_child;
            /* Special case for leaf nodes: r_order = o_order */
            if(!n) v->r_order = v->o_order;
        } else
        {
            /* Assign the r order first (the id of the last decendant) */
            v->r_order = id;
            debug("Assigned version=%d r_order %d\n", v->version, v->r_order);
        }
        children_first = 1;
        if(!n) 
            n = v->next_sybling;
        if(!n) {
            n = v->parent;
            children_first = 0;
        }
        if(n) debug("Next version is: %d\n", n->version);
        v = n;
    }
    spin_unlock_irq(&castle_versions_hash_lock);

    while(!list_empty(&sysfs_list))
    {
        v = list_first_entry(&sysfs_list, 
                              struct castle_version,
                              init_list);
        list_del(&v->init_list);
        /* Now that we are done setting the version up, try to add it to sysfs. */
        ret = castle_sysfs_version_add(v->version);
        if(ret)
        {
            printk("Could not add version %d to sysfs. Errno=%d.\n", v->version, ret);
            err = -3;
            continue; 
        }
    }
 
    /* Done. */
    return err;
}

int castle_version_is_ancestor(version_t candidate, version_t version)
{
    struct castle_version *c, *v;
    int ret;

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    c = __castle_versions_hash_get(candidate);
    /* Sanity checks */
    BUG_ON(!v);
    BUG_ON(!(v->flags & CV_INITED_MASK));
    BUG_ON(VERSION_INVAL(v->o_order));
    BUG_ON(!c);
    BUG_ON(!(c->flags & CV_INITED_MASK));
    BUG_ON(VERSION_INVAL(c->o_order));
    BUG_ON(VERSION_INVAL(c->r_order));
    /* c is an ancestor of v if v->o_order is in range c->o_order to c->r_order
       inclusive */
    ret = (v->o_order >= c->o_order) && (v->o_order <= c->r_order);
    spin_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

int castle_version_compare(version_t version1, version_t version2)
{
    struct castle_version *v1, *v2;
    int ret;

    spin_lock_irq(&castle_versions_hash_lock);
    v1 = __castle_versions_hash_get(version1);
    v2 = __castle_versions_hash_get(version2);
    /* Sanity checks */
    BUG_ON(!v1);
    BUG_ON(!(v1->flags & CV_INITED_MASK));
    BUG_ON(VERSION_INVAL(v1->o_order));
    BUG_ON(!v2);
    BUG_ON(!(v2->flags & CV_INITED_MASK));
    BUG_ON(VERSION_INVAL(v2->o_order));

    ret = v1->o_order - v2->o_order;
    spin_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

/* Write root version (version 0) to mstore, which will then be processed by
   castle_versions_read() */
int castle_versions_zero_init(c_disk_blk_t ftree_root)
{
    struct castle_vlist_entry mstore_ventry;
    struct castle_rlist_entry mstore_rentry;
    
    debug("Initialising version root.\n");
    castle_versions_mstore = 
        castle_mstore_init(MSTORE_VERSIONS_ID, sizeof(struct castle_vlist_entry));
    castle_roots_mstore = 
        castle_mstore_init(MSTORE_ROOTS, sizeof(struct castle_rlist_entry));

    if(!castle_versions_mstore || !castle_roots_mstore)
        return -ENOMEM;

    mstore_ventry.version_nr = 0;
    mstore_ventry.parent     = 0;
    mstore_ventry.size       = 0;
    mstore_ventry.da_id      = INVAL_DA;
    castle_mstore_entry_insert(castle_versions_mstore, &mstore_ventry); 

    mstore_rentry.version    = 0;
    mstore_rentry.tree_seq   = 0;
    mstore_rentry.cdb        = ftree_root;
    castle_mstore_entry_insert(castle_roots_mstore, &mstore_rentry); 

    return 0;
}

int castle_versions_read(void)
{
    struct castle_vlist_entry mstore_ventry;
    struct castle_rlist_entry mstore_rentry;
    struct castle_mstore_iter* iterator;
    struct castle_version* v; 
    c_mstore_key_t key;

    if(!castle_versions_mstore)
        castle_versions_mstore = 
            castle_mstore_open(MSTORE_VERSIONS_ID, sizeof(struct castle_vlist_entry));
    if(!castle_roots_mstore)
        castle_roots_mstore = 
            castle_mstore_open(MSTORE_ROOTS, sizeof(struct castle_rlist_entry));

    if(!castle_versions_mstore || !castle_roots_mstore)
        return -ENOMEM;

    iterator = castle_mstore_iterate(castle_versions_mstore);
    if(!iterator)
        return -EINVAL;

    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_ventry, &key);
        v = castle_version_add(mstore_ventry.version_nr, 
                               mstore_ventry.parent, 
                               mstore_ventry.da_id,
                               mstore_ventry.size);
        if(!v)
        {
            castle_mstore_iterator_destroy(iterator);
            return -ENOMEM;
        }
        if(VERSION_INVAL(castle_versions_last) || v->version > castle_versions_last)
            castle_versions_last = v->version;
        v->mstore_key = key;
    }
    castle_mstore_iterator_destroy(iterator);

    iterator = castle_mstore_iterate(castle_roots_mstore);
    if(!iterator)
        return -EINVAL;

    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_rentry, &key);
        if(castle_version_root_add(mstore_rentry.version,
                                   mstore_rentry.tree_seq,
                                   mstore_rentry.cdb,
                                   key))
        {
            castle_mstore_iterator_destroy(iterator);
            printk("Error! Could not add root, version=%d, ct=%d.\n",
                    mstore_rentry.version, mstore_rentry.tree_seq);
            return -ENOMEM;
        }
    }
    castle_mstore_iterator_destroy(iterator);

    return castle_versions_process(); 
}

/***** Init/fini functions *****/
int castle_versions_init(void)
{
    int ret;

    ret = -ENOMEM;
    castle_versions_cache = kmem_cache_create("castle_versions",
                                               sizeof(struct castle_version),
                                               0,     /* align */
                                               0,     /* flags */
                                               NULL); /* ctor */
    if(!castle_versions_cache)
    {
        printk("Could not allocate kmem cache for castle versions.\n");
        goto err_out;
    }
    
    castle_versions_hash = castle_versions_hash_alloc();
    if(!castle_versions_hash)
    {
        printk("Could not allocate versions hash\n");
        goto err_out;
    }
    castle_versions_hash_init();

    return 0;

err_out:
    if(castle_versions_cache)
        kmem_cache_destroy(castle_versions_cache);
    if(castle_versions_hash)
        kfree(castle_versions_hash);
    return ret;
}

void castle_versions_fini(void)
{
    castle_versions_hash_destroy();
    kmem_cache_destroy(castle_versions_cache);
}
