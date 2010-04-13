/* TODOs:
   Locking & concurrency needs to be worked out here 
   - what happens when someone clones a version that's currently attached (this should fail)
 */

#include <linux/module.h>
#include <linux/workqueue.h> 
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/hardirq.h>
#include <linux/fs.h>
#include <asm/semaphore.h>

#include "castle_public.h"
#include "castle.h"
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
static c2_page_t* castle_versions_node_init(void);

static struct kmem_cache *castle_versions_cache = NULL;

#define CASTLE_VERSIONS_HASH_SIZE       (1000)
static    DEFINE_SPINLOCK(castle_versions_hash_lock);
static struct list_head  *castle_versions_hash  = NULL;
static          LIST_HEAD(castle_versions_init_list);

static      DECLARE_MUTEX(castle_versions_last_lock);
static version_t          castle_versions_last;
static c_disk_blk_t       castle_versions_last_node_cdb;
static int                castle_versions_last_node_unused;

#define CV_INITED_BIT             (0)
#define CV_INITED_MASK            (1 << CV_INITED_BIT)
#define CV_ATTACHED_BIT           (1)
#define CV_ATTACHED_MASK          (1 << CV_ATTACHED_BIT)
#define CV_SNAP_BIT               (2)
#define CV_SNAP_MASK              (1 << CV_ATTACHED_BIT)
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
    c_disk_blk_t cdb;  /* Where is this version stored on disk */
    version_t    o_order;
    version_t    r_order;
    c_disk_blk_t ftree_root;
    uint32_t     size;

    /* Lists for storing versions the hash table & the init list*/
    struct list_head hash_list; 
    unsigned long    flags;
    struct list_head init_list;
};

struct castle_version_update {
    version_t version;
    int       new;
    c2_page_t *c2p;
}; 

/***** Hash table & init list *****/
static int castle_versions_hash_idx(version_t version)
{
    return (version % CASTLE_VERSIONS_HASH_SIZE);
} 

static void castle_versions_hash_add(struct castle_version *v)
{
    int idx = castle_versions_hash_idx(v->version);
    
    spin_lock_irq(&castle_versions_hash_lock);
    list_add(&v->hash_list, &castle_versions_hash[idx]);
    spin_unlock_irq(&castle_versions_hash_lock);
}

static void __castle_versions_hash_remove(struct castle_version *v)
{
    list_del(&v->hash_list);
}

static struct castle_version* __castle_versions_hash_get(version_t version)
{
    struct castle_version *v;
    struct list_head *l;
    int idx = castle_versions_hash_idx(version); 

    list_for_each(l, &castle_versions_hash[idx])
    {
        v = list_entry(l, struct castle_version, hash_list);
        if(v->version == version)
            return v;
    }

    return NULL;
} 
static void castle_versions_hash_destroy(void)
{
    struct list_head *l, *t;
    struct castle_version *v;
    int i;

    spin_lock_irq(&castle_versions_hash_lock);
    for(i=0; i<CASTLE_VERSIONS_HASH_SIZE; i++)
    {
        list_for_each_safe(l, t, &castle_versions_hash[i])
        {
            list_del(l);
            v = list_entry(l, struct castle_version, hash_list);
            kmem_cache_free(castle_versions_cache, v);
        }
    }
    spin_unlock_irq(&castle_versions_hash_lock);
}

static void castle_versions_init_add(struct castle_version *v)
{
    spin_lock_irq(&castle_versions_hash_lock);
    v->flags &= (~CV_INITED_MASK);
    list_add(&v->init_list, &castle_versions_init_list);
    spin_unlock_irq(&castle_versions_hash_lock);
}


static int castle_version_add(c_disk_blk_t cdb,
                              version_t version, 
                              version_t parent, 
                              c_disk_blk_t ftree_root,
                              uint32_t size)
{
    struct castle_version *v;
    int ret;
    
    v = kmem_cache_alloc(castle_versions_cache, GFP_KERNEL);
    if(!v) return -ENOMEM;
    ret = castle_freespace_version_add(version);
    if(ret) return -ENOMEM;
    debug("Adding: (v, p)=(%d,%d)\n", version, parent);

    v->version      = version;
    v->parent_v     = parent;
    v->first_child  = NULL; 
    v->next_sybling = NULL; 
    v->cdb          = cdb;
    v->o_order      = INVAL_VERSION;
    v->r_order      = INVAL_VERSION;
    v->ftree_root   = ftree_root;
    v->size         = size;
    v->flags        = 0;
    INIT_LIST_HEAD(&v->hash_list);
    INIT_LIST_HEAD(&v->init_list);

    castle_versions_hash_add(v);
    /* Initialise version 0 (root version) fully */ 
    if(v->version == 0)
    {
        v->parent       = NULL;
        v->first_child  = NULL; /* This will be updated later */
        v->next_sybling = NULL;
        v->flags       |= CV_INITED_MASK;

        return castle_sysfs_version_add(v->version); 

    } else
    {
        /* Defer the initialisation until all the parent 
           nodes have been collected */
        castle_versions_init_add(v);
    }

    return 0;
}

static void castle_version_update(struct castle_version_update *vu)
{
    struct castle_vlist_node *node;
    struct castle_vlist_slot *slot;
    struct castle_version *v;
    unsigned long flags;
    int i;

    BUG_ON(!c2p_uptodate(vu->c2p));
    node = pfn_to_kaddr(page_to_pfn(vu->c2p->page));
    /* Find the version in the node */
    for(i=0; i<node->used; i++)
    {
        slot = &node->slots[i];
        if(slot->version_nr == vu->version)
        {
            debug("Found version on disk, updating it.\n");
            break;
        }
    }
    /* If we allocating new node allocate the first free slot */ 
    if(vu->new)
    {
        debug("Allocating new slot in node (0x%x, 0x%x), idx=%d.\n",
            vu->c2p->cdb.disk, vu->c2p->cdb.block, node->used);
        BUG_ON(node->used >= node->capacity);
        slot = &node->slots[node->used++];
    }
    /* Some sanity checks */
    BUG_ON((!vu->new) && (slot->version_nr != vu->version));
    BUG_ON(( vu->new) && (i != (node->used-1)));

    debug("Writing verison update to the cached page.\n");
    spin_lock_irqsave(&castle_versions_hash_lock, flags);
    v = __castle_versions_hash_get(vu->version);
    slot->version_nr = v->version;
    slot->parent     = (v->parent ? v->parent->version : 0);
    slot->size       = v->size;
    slot->cdb        = v->ftree_root;
    spin_unlock_irqrestore(&castle_versions_hash_lock, flags);

    /* Finish-off and cleanup */
    dirty_c2p(vu->c2p);
    unlock_c2p(vu->c2p);
    put_c2p(vu->c2p);
    kfree(vu);
}

static void castle_version_node_read_end(c2_page_t *c2p, int uptodate)
{
    struct castle_version_update *vu = c2p->private;
    if(!uptodate)
    {
        /* TODO: This failure NEEDs to be handled properly. 
                 Quite possibly ftree_update() and others 
                 using this function should do a blocking IO
                 and handle the failure there */
        printk("Failed to read version node off the disk.\n");
        printk("Cannot handle that ATM.\n");
        kfree(vu);
        BUG();
    } 
    debug("Read version node from disk.\n");
    set_c2p_uptodate(c2p);
    
    castle_version_update(vu);
}

/* TODO who should handle errors in writeback? */
static void castle_version_writeback(version_t version, int new)
{
    struct castle_version_update *vu;
    struct castle_version *v;
    c_disk_blk_t node_cdb;
    c2_page_t *c2p;

    vu = kmalloc(sizeof(struct castle_version_update), GFP_KERNEL);
    if(!vu) goto error_out;

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(!v) 
    {
        spin_unlock_irq(&castle_versions_hash_lock);
        goto error_out;
    }
    node_cdb = v->cdb;
    spin_unlock_irq(&castle_versions_hash_lock);

    /* Lock the disk node, and defer the writeback */
    c2p = castle_cache_page_get(node_cdb);
    lock_c2p(c2p);
    vu->version = version;
    vu->new = new;
    vu->c2p = c2p;
    if(!c2p_uptodate(c2p))
    {
        c2p->end_io  = castle_version_node_read_end; 
        c2p->private = vu;
        submit_c2p(READ, c2p);
        return;
    }
    
    castle_version_update(vu);
    return;

error_out:    
    if(vu) kfree(vu);
    return;
}

/***** External functions *****/
int castle_version_ftree_update(version_t version, c_disk_blk_t cdb)
{
    struct castle_version *v;

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(!v) 
    {
        spin_unlock_irq(&castle_versions_hash_lock);
        return -EINVAL;
    }
    /* Test if the lock is taken out (check not 100% since it 
       could be taken by someone else than us) */
    BUG_ON(!test_bit(CV_FTREE_LOCKED_BIT, &v->flags));
    v->ftree_root = cdb;
    spin_unlock_irq(&castle_versions_hash_lock);
  
    /* TODO: Error handling? */
    castle_version_writeback(version, 0); 

    return 0;
}

static version_t castle_version_new_create(int snap_or_clone,
                                           version_t parent,
                                           uint32_t size)
{
    struct castle_version *v;
    c_disk_blk_t ftree_root;
    uint32_t parent_size;
    version_t version;
    int ret;

    /* Read ftree root from the parent (also, make sure parent exists) */
    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(parent);
    if(!v)
    {
        printk("Asked to create a child of non-existant parent: %d\n",
            parent);
        spin_unlock_irq(&castle_versions_hash_lock);
        return INVAL_VERSION;
    }
    spin_unlock_irq(&castle_versions_hash_lock);
    
    /* Lock the root, to make sure that there are no ongoing writes 
       which may split the root node. New writes will not be accepted
       until we are done, because we are working under device lock.
       If we are doing clones rather than snapshots (and there is no
       locked device), there won't be any IO for the version either.
       Finally, because control commands are serialised, if someone
       tries to attach the version while we are cloning it, he'll have
       to wait for us to finish. */
    ftree_root = castle_version_ftree_lock(parent);
    castle_version_ftree_unlock(parent);
    parent_size = v->size;

    /* Allocate a new version number. */
    down(&castle_versions_last_lock);
    BUG_ON(VERSION_INVAL(castle_versions_last));
    version = ++castle_versions_last;
    up(&castle_versions_last_lock);

    /* Try to add it to the hash */
    ret = castle_version_add(INVAL_DISK_BLK, version, parent, ftree_root, size);
    if(ret) return INVAL_VERSION;

    /* Set clone/snap bit in flags */ 
    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    if(parent_size != 0) v->size = parent_size;
    BUG_ON(v->size == 0);
    if(snap_or_clone)
        v->flags |= CV_SNAP_MASK;
    else
        v->flags &= ~CV_SNAP_MASK;
    spin_unlock_irq(&castle_versions_hash_lock);

    /* Run processing (which will thread the new version into the tree,
       and recalculate the order numbers) */
    castle_versions_process(); 
    
    /* Check if the version got initialised */
    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    if(!(v->flags & CV_INITED_MASK))
    {
        __castle_versions_hash_remove(v);
        kmem_cache_free(castle_versions_cache, v);
        version = INVAL_VERSION;
    }
    spin_unlock_irq(&castle_versions_hash_lock);

    castle_events_version_create(version);

    return version;
}

/* BIG TODO:
   1. Is it possible for the ftree_root for the parent version to
      split after it gets read here?
   2. If so, is it fine?
   3. If not, how to prevent it?
 */
version_t castle_version_new(int snap_or_clone,
                             version_t parent,
                             uint32_t size)
{
    struct castle_version *v;
    c_disk_blk_t cdb;
    c2_page_t *c2p;
    version_t version;
    
    /* Get a new version number */
    version = castle_version_new_create(snap_or_clone,
                                        parent,
                                        size);
    /* Return if we couldn't create the version correctly
       (possibly because we trying to clone attached version,
        or because someone asked for more than one snapshot to
        an attached version */
    if(VERSION_INVAL(version))
        return INVAL_VERSION;

    /* We've succeeded at creating a new version number.
       Let's find where to store it on the disk. */
    down(&castle_versions_last_lock);
    cdb = castle_versions_last_node_cdb; 
    /* Create a new list node, if we've just used up the last slot */
    if(--castle_versions_last_node_unused == 0)
    {
        printk("Need to allocate a new node for version list.\n");
        c2p = castle_versions_node_init();
        if(!c2p)
        {
            up(&castle_versions_last_lock);
            /* Could remove version from the hash, but this is 
               so unlikely that it doesn't matter really */
            return INVAL_VERSION;
        }
        castle_versions_last_node_cdb    = c2p->cdb; 
        castle_versions_last_node_unused = VLIST_SLOTS;
        unlock_c2p(c2p);
        put_c2p(c2p);
    }
    up(&castle_versions_last_lock);
    
    debug("New version %d will be written in (d,b)=(0x%x, 0x%x)\n",
            version, cdb.disk, cdb.block);
    /* Update the version */
    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    v->cdb = cdb;
    spin_unlock_irq(&castle_versions_hash_lock);

    /* TODO: Error handling? */
    castle_version_writeback(version, 1); 
    
    return version; 
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

c_disk_blk_t castle_version_ftree_lock(version_t version)
{
    struct castle_version *v;

    /* This function may sleep on the ftree lock */
	might_sleep();

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    spin_unlock_irq(&castle_versions_hash_lock);

    if(!v) return INVAL_DISK_BLK;

	if (test_and_set_bit(CV_FTREE_LOCKED_BIT, &v->flags))
    {
        /* Slow path */
	    wait_on_bit_lock(&v->flags, 
                          CV_FTREE_LOCKED_BIT, 
                          castle_version_ftree_yield,
                          TASK_UNINTERRUPTIBLE);
    }
    /* We've locked the node, we can now read the root cdb */
    BUG_ON(!test_bit(CV_FTREE_LOCKED_BIT, &v->flags));

    return v->ftree_root;
}

void castle_version_ftree_unlock(version_t version)
{
    unsigned long flags;
    struct castle_version *v;

    spin_lock_irqsave(&castle_versions_hash_lock, flags);
    v = __castle_versions_hash_get(version);
    spin_unlock_irqrestore(&castle_versions_hash_lock, flags);
    BUG_ON(!v);

    /* Clear the bit, wake up anyone waiting */
	smp_mb__before_clear_bit();
    /* TODO: Check what happens to the locks if a new snapshot is being created */
    BUG_ON(!test_bit(CV_FTREE_LOCKED_BIT, &v->flags));
	clear_bit(CV_FTREE_LOCKED_BIT, &v->flags);
	smp_mb__after_clear_bit();
	wake_up_bit(&v->flags, CV_FTREE_LOCKED_BIT);
}

int castle_version_snap_get(version_t version, 
                            version_t *parent,
                            uint32_t *size,
                            int *leaf)
{
    struct castle_version *v;
    int ret = -EINVAL;

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(v) 
    {
        ret = 0;
        if(size)   *size =  v->size;
        if(parent) *parent = v->parent ? v->parent->version : 0;
        if(leaf)   *leaf = (v->first_child == NULL);
        if(test_and_set_bit(CV_ATTACHED_BIT, &v->flags))
            ret = -EAGAIN;
    }
    spin_unlock_irq(&castle_versions_hash_lock);

    return ret;
} 

void castle_version_snap_put(version_t version)
{
    struct castle_version *v;

    spin_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    BUG_ON(!test_and_clear_bit(CV_ATTACHED_BIT, &v->flags));
    spin_unlock_irq(&castle_versions_hash_lock);
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
        v->parent       = p;
        v->next_sybling = p->first_child;
        p->first_child  = v;
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

static c2_page_t* castle_versions_node_init(void)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_vlist_node *node, *prev_node;
    c_disk_blk_t cdb;
    c2_page_t *c2p, *prev_c2p;
    int ret;

    c2p   = prev_c2p  = NULL;
    node  = prev_node = NULL;
    cdb   = INVAL_DISK_BLK;
    fs_sb = NULL;
    /* Get the FS superblock, because we will have to insert
       the new node into the doubly linked list, rooted at the 
       superblock */
    debug("Initialising vlist node.\n");
    fs_sb = castle_fs_superblocks_get();
    debug("Got fs superblock.\n");
    /* Get the last node */
    if(!DISK_BLK_INVAL(fs_sb->fwd_tree2))
    {
        debug("Valid last vlist node.\n");
        prev_c2p  = castle_cache_page_get(fs_sb->fwd_tree2);
        lock_c2p(prev_c2p);
        ret = 0;
        if(!c2p_uptodate(prev_c2p))
            ret = submit_c2p_sync(READ, prev_c2p);
        if(ret) goto error_out;
        debug("Last vlist node uptodate now.\n");
        prev_node = pfn_to_kaddr(page_to_pfn(prev_c2p->page));
    }
    /* Allocate a new node */
    cdb = castle_freespace_block_get(0);
    c2p = castle_cache_page_get(cdb);
    lock_c2p(c2p);
    set_c2p_uptodate(c2p);
    debug("Allocated new block (0x%x, 0x%x).\n", cdb.disk, cdb.block);
    /* Init the node correctly */
    node = pfn_to_kaddr(page_to_pfn(c2p->page));
    node->magic               = VLIST_NODE_MAGIC;
    node->version             = 0;
    node->capacity            = VLIST_SLOTS;
    node->used                = 0;
    node->next                = INVAL_DISK_BLK;
    node->prev                = fs_sb->fwd_tree2;
    dirty_c2p(c2p);
    debug("Initialised and dirtied the new node.\n");
    /* Update relevant pointers to point to us */
    if(prev_node)
    {
        debug("Updating prev node.\n");
        prev_node->next = cdb;
        dirty_c2p(prev_c2p);
        unlock_c2p(prev_c2p);
        put_c2p(prev_c2p);
    } else
    {
        debug("Updating fwd1 in superblock to: (0x%x, 0x%x).\n",
                cdb.disk, cdb.block);
        fs_sb->fwd_tree1 = cdb;
    }
    debug("Updating fwd2 in superblock to: (0x%x, 0x%x).\n",
            cdb.disk, cdb.block);
    fs_sb->fwd_tree2 = cdb;
    /* The fs has been updated, dirty+release */
    castle_fs_superblocks_put(fs_sb, 1);

    /* Return the (locked) c2p for the new node we've just created */
    return c2p;

error_out:
    debug("Failed to allocate new vlist node.\n");
    if(prev_c2p) {unlock_c2p(prev_c2p); put_c2p(prev_c2p);}
    if(c2p)      {unlock_c2p(c2p);      put_c2p(c2p);     }
    if(fs_sb)    {castle_fs_superblocks_put(fs_sb, 0);    }
    /* TODO: return the block back to the allocator */

    return NULL; 
}

int castle_versions_list_init(c_disk_blk_t ftree_root)
{
    struct castle_vlist_node *node;
    c2_page_t *c2p;
    int ret;
    
    debug("Initialising version list.\n");
    c2p = castle_versions_node_init();
    if(!c2p) return -EIO;

    node = pfn_to_kaddr(page_to_pfn(c2p->page));
    node->used                = 1;
    node->slots[0].version_nr = 0;
    node->slots[0].parent     = 0;
    node->slots[0].size       = 0;
    node->slots[0].cdb        = ftree_root;
    dirty_c2p(c2p);
    ret = submit_c2p_sync(WRITE, c2p); 
    unlock_c2p(c2p);
    put_c2p(c2p);
    debug("Done initialising version list, ret=%d.\n", ret);

    return ret;
}

int castle_versions_read(void)
{
    struct castle_fs_superblock *fs_sb;
    struct castle_vlist_node *node;
    struct castle_vlist_slot *slot;
    c2_page_t *c2p, *prev_c2p;
    c_disk_blk_t list_cdb;
    int i, ret = 0;

    fs_sb = castle_fs_superblocks_get(); 
    list_cdb = fs_sb->fwd_tree1;
    debug("Read first version list node from the superblock (0x%x, 0x%x)\n",
            list_cdb.disk, list_cdb.block);
    castle_fs_superblocks_put(fs_sb, 0); 

    prev_c2p = c2p = NULL;
    while(!DISK_BLK_INVAL(list_cdb))
    {
        debug("Reading next version list node: (0x%x, 0x%x)\n",
                list_cdb.disk, list_cdb.block);
        c2p = castle_cache_page_get(list_cdb);
        lock_c2p(c2p);         
        /* Now that we've locked c2p, unlock prev (if exists) */
        if(prev_c2p)
        {
            unlock_c2p(prev_c2p);
            put_c2p(prev_c2p);
        }
        if(!c2p_uptodate(c2p)) 
            ret = submit_c2p_sync(READ, c2p);
        if(ret) goto out; 
        node = pfn_to_kaddr(page_to_pfn(c2p->page));
        /* TODO: handle this properly */
        if(node->magic != VLIST_NODE_MAGIC)
            printk("WARN: Version list magics don't agree!\n");
        for(i=0; i<node->used; i++)
        {
            slot = &node->slots[i];
            ret = castle_version_add(list_cdb,
                                     slot->version_nr,
                                     slot->parent,
                                     slot->cdb,
                                     slot->size);
            if(ret) goto out; 
            /* TODO should we hold the last_lock? (also make sure last_node
               protected) */
            if(VERSION_INVAL(castle_versions_last) ||
               slot->version_nr > castle_versions_last)
                castle_versions_last = slot->version_nr;
        }
        /* Save this node as potentially the last node. If it is, it should
           not be full. */
        BUG_ON(DISK_BLK_INVAL(node->next) && (node->used == node->capacity));
        castle_versions_last_node_cdb = c2p->cdb;
        castle_versions_last_node_unused = node->capacity - node->used;
        list_cdb = node->next;
        prev_c2p = c2p;
    }
out:    
    if(c2p)
    {
        unlock_c2p(c2p);
        put_c2p(c2p);
    }
    if(ret) 
    {
        printk("ERROR: Failed to read versions in!\n");
        return ret;
    }
    ret = castle_versions_process(); 
    if(ret)
    {
        printk("ERROR: Failed to init versions, %d!\n", ret);
        return ret;
    }

    return ret;
}

/***** Init/fini functions *****/
int castle_versions_init(void)
{
    int i, ret;

    castle_versions_last = INVAL_VERSION;
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
    
    castle_versions_hash = 
        kmalloc(sizeof(struct list_head) * CASTLE_VERSIONS_HASH_SIZE,
                GFP_KERNEL); 
    if(!castle_versions_hash)
    {
        printk("Could not allocate versions hash\n");
        goto err_out;
    }
    /* We've allocated everything, we'll succeed after here */
    ret = 0;

    for(i=0; i<CASTLE_VERSIONS_HASH_SIZE; i++)
        INIT_LIST_HEAD(&castle_versions_hash[i]); 

    return ret;

err_out:
    if(castle_versions_cache)
        kmem_cache_destroy(castle_versions_cache);
    if(castle_versions_hash)
        kfree(castle_versions_hash);
    return ret;
}

void castle_versions_fini(void)
{
    // TODO: there seem to be a bug when a snapshot failed. kmem cache cannot be destroyed.
    castle_versions_hash_destroy();
    kmem_cache_destroy(castle_versions_cache);
    kfree(castle_versions_hash);
}
