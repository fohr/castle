#include <linux/list.h>
#include <linux/slab.h>
#include <linux/hardirq.h>
#include <linux/sched.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_versions.h"
#include "castle_sysfs.h"
#include "castle_cache.h"
#include "castle_events.h"
#include "castle_ctrl.h"
#include "castle_btree.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (castle_printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int castle_versions_process(void);

static struct kmem_cache *castle_versions_cache  = NULL;

#define CASTLE_VERSIONS_MAX                 (200)   /**< Maximum number of versions per-DA.     */
#define CASTLE_VERSIONS_HASH_SIZE           (1000)  /**< Size of castle_versions_hash.          */
#define CASTLE_VERSIONS_COUNTS_HASH_SIZE    (1000)  /**< Size of castle_versions_counts_hash.   */
static struct list_head  *castle_versions_hash          = NULL;
static          LIST_HEAD(castle_versions_init_list);
static struct list_head  *castle_versions_counts_hash   = NULL;

static version_t          castle_versions_last   = INVAL_VERSION;
static c_mstore_t        *castle_versions_mstore = NULL;

LIST_HEAD(castle_versions_deleted);

#define CV_INITED_BIT             (0)
#define CV_INITED_MASK            (1 << CV_INITED_BIT)
#define CV_ATTACHED_BIT           (1)
#define CV_ATTACHED_MASK          (1 << CV_ATTACHED_BIT)
#define CV_DELETED_BIT            (2)
#define CV_DELETED_MASK           (1 << CV_DELETED_BIT)
/* If a version has no children or if all children are marked as deleted, then
 * it is marked as leaf. */
#define CV_LEAF_BIT               (3)
#define CV_LEAF_MASK              (1 << CV_LEAF_BIT)

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
    version_t        o_order;
    version_t        r_order;
    da_id_t          da_id;
    c_byte_off_t     size;

    /* Lists for storing versions the hash table & the init list*/
    struct list_head hash_list; 
    unsigned long    flags;
    union {
        struct list_head init_list;
        struct list_head free_list;
    };
    struct list_head del_list;
};

/**
 * Maintains the number of active versions in each doubling array.
 */
struct castle_version_count {
    da_id_t             da_id;      /**< DA we are counting live versions for.          */
    int                 count;      /**< Number of live versions for da_id.             */
    struct list_head    hash_list;  /**< Threading onto castle_versions_counts_hash.    */
};

DEFINE_HASH_TBL(castle_versions, castle_versions_hash, CASTLE_VERSIONS_HASH_SIZE, struct castle_version, hash_list, version_t, version);
DEFINE_HASH_TBL(castle_versions_counts, castle_versions_counts_hash, CASTLE_VERSIONS_COUNTS_HASH_SIZE, struct castle_version_count, hash_list, da_id_t, da_id);

/**
 * Disassociate all castle_versions from hash and free them.
 */
static int castle_version_hash_remove(struct castle_version *v, void *unused) 
{
    list_del(&v->hash_list);
    kmem_cache_free(castle_versions_cache, v);

    return 0;
}

/**
 * Free castle_versions_hash and all members.
 */
static void castle_versions_hash_destroy(void)
{
    castle_versions_hash_iterate(castle_version_hash_remove, NULL); 
    castle_free(castle_versions_hash);
}

static void castle_versions_init_add(struct castle_version *v)
{
    v->flags &= (~CV_INITED_MASK);
    list_add(&v->init_list, &castle_versions_init_list);
}

/**
 * Disassociate all castle_version_count from hash and free them.
 */
static int castle_version_counts_hash_remove(struct castle_version_count *vc, void *unused)
{
    list_del(&vc->hash_list);
    castle_free(vc);

    return 0;
}

/**
 * Free castle_versions_counts_hash and all members.
 */
static void castle_version_counts_hash_destroy(void)
{
    castle_versions_counts_hash_iterate(castle_version_counts_hash_remove, NULL);
    castle_free(castle_versions_counts_hash);
}

/**
 * Increment the active version count for DA.
 *
 * @param   da_id   DA to increment version count for
 *
 * NOTE: Must be called during a CASTLE_TRANSACTION
 * NOTE: castle_versions_counts_hash members protected by CASTLE_TRANSACTION
 *
 * @return  0       Successfully incremented version count
 * @return -ENOMEM  Couldn't allocate castle_version_count structure
 * @return -EINVAL  Already at maximum number of versions per DA
 */
static int castle_versions_count_inc(da_id_t da_id)
{
    struct castle_version_count *vc;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    vc = castle_versions_counts_hash_get(da_id);
    if (!vc)
    {
        /* No castle_version_count for da_id.  Create a new one. */
        vc = castle_malloc(sizeof(struct castle_version_count), GFP_KERNEL);
        if (!vc)
            return -ENOMEM;
        vc->da_id = da_id;
        vc->count = 1;
        INIT_LIST_HEAD(&vc->hash_list);
        castle_versions_counts_hash_add(vc);
    }
    else if (vc->count < CASTLE_VERSIONS_MAX)
        /* Increment count for existing castle_version_count. */
        vc->count++;
    else
        /* DA is already at maximum number of versions. */
        return -E2BIG;

    return EXIT_SUCCESS;
}

/**
 * Decrement the active version count for DA.
 *
 * @param   da_id   DA to decrement version count for
 *
 * NOTE: Must be called during a CASTLE_TRANSACTION
 * NOTE: castle_versions_counts_hash members protected by CASTLE_TRANSACTION
 *
 * @return  0   Successfully decremented version count
 */
static int castle_versions_count_dec(da_id_t da_id)
{
    struct castle_version_count *vc;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    vc = castle_versions_counts_hash_get(da_id);
    BUG_ON(!vc); /* must always exist for decrements */
    vc->count--;
    if (vc->count == 0)
    {
        list_del(&vc->hash_list);
        castle_free(vc);
    }
    else
        BUG_ON(vc->count < 0);

    return EXIT_SUCCESS;
}

version_t castle_version_max_get(void)
{
    int last;

    read_lock_irq(&castle_versions_hash_lock);
    last = castle_versions_last + 1;
    read_unlock_irq(&castle_versions_hash_lock);

    return last;
}

static void castle_versions_drop(struct castle_version *p);
static int castle_version_writeback(struct castle_version *v, void *unused);

int castle_version_attached(version_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    return test_bit(CV_ATTACHED_BIT, &v->flags);
}

int castle_version_deleted(version_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    castle_printk("Flags in version %d: 0x%lx\n", version, v->flags);
    return test_bit(CV_DELETED_BIT, &v->flags);
}

int castle_version_is_leaf(version_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    return test_bit(CV_LEAF_BIT, &v->flags);
}

/**
 * Determines whether the version v depends on its parent for the current key. 
 *
 * @param v [in] version to be determined
 * @param state [in] state of snapshot delete for current key
 *
 * @return 1 if v depends on parent
 */
static int castle_version_needs_parent(struct castle_version *v, struct castle_version_delete_state *state)
{
    struct castle_version *w;

    /* If version is occupied (key exists in the version), not dependent on parent. */
    if (test_bit(v->version, state->occupied))
        return 0;

    /* Version is not occupied. */
    /* Version is not marked for deletion, dependent on parent. */
    if (!test_bit(CV_DELETED_BIT, &v->flags))
        return 1;

    /* Not occupied and Marked for deletion. */
    /* Marked as leaf, no more live descendents; just respond from here. */
    if (test_bit(CV_LEAF_BIT, &v->flags))
        return 0;

    /* Check if there is a child that has dependency on parent. Even if one child
     * is dependent on parent, keep the parent alive. */
    for (w=v->first_child; w; w=w->next_sybling)
    {
        version_t ver_id = w->version;

        if (test_bit(ver_id, state->occupied))
            continue;

        if (!test_bit(CV_DELETED_BIT, &w->flags) || test_bit(ver_id, state->need_parent))
            return 1;
    }

    return 0;
}

/**
 * Determines if any strictly descendant version depends on the current version (all, 
 * for the particular key being processed at the moment). Assumption is that occupied 
 * bit is valid for all versions. But, need_parent bit is valid only for deleted versions. 
 * For other versions, need_parent doesnt represent any thing.
 *
 * @param state [in] state of the snapshot delete for current key
 * @param version [in] version of the current entry
 *
 * @return 1 if, version is deletable. 
 */
int castle_version_is_deletable(struct castle_version_delete_state *state, version_t version)
{
    struct castle_version *cur_v = NULL, *w;
    struct list_head *list;
    int ret = 1;

    /* Set occupied bit for this version. Merge is single-threaded and runs on
     * same processor. No need of set_bit. */
    BUG_ON(version >= state->last_version);
    __set_bit(version, state->occupied);

    read_lock_irq(&castle_versions_hash_lock);

    cur_v = __castle_versions_hash_get(version);
    BUG_ON(!cur_v);

    /* Version is not deleted, keep the entry. */
    if (!test_bit(CV_DELETED_BIT, &cur_v->flags))
    {
        ret = 0;
        goto out;
    }

    /* If the version is marked as LEAF, it is safe to delete the entry. No need to
     * calculate need_parent bit(f-value) for this version now. */
    if (test_bit(CV_LEAF_BIT, &cur_v->flags))
        goto out;

    if (state->next_deleted == NULL)
        state->next_deleted = castle_versions_deleted.next;

    /* Go through all deleted versions in reverse-DFS order until the current version. */
    list_for_each_from(state->next_deleted, list, &castle_versions_deleted)
    {
        struct castle_version *del_v = list_entry(list, struct castle_version, del_list);

        /* dont look at versions created after merge started. */
        if (del_v->version > state->last_version)
            continue;

        if (del_v->o_order < cur_v->o_order)
            break;

        BUG_ON(!test_bit(CV_DELETED_BIT, &del_v->flags));

        if (castle_version_needs_parent(del_v, state))
        {
            if (del_v->version >= state->last_version)
            {
                castle_printk("del_v: %p, state: %p, v1: %d, v2: %d\n",
                        del_v, state, del_v->version, state->last_version);
                BUG_ON(1);
            }

            __set_bit(del_v->version, state->need_parent);
        }
    }
    state->next_deleted = list;
   
    /* Check the version required by childs. For undeleted childs, dont look
     * at need_parent bit (its not calculated for them). */
    for (w=cur_v->first_child; w; w=w->next_sybling)
    {
        if (test_bit(w->version, state->occupied))
            continue;

        if (!test_bit(CV_DELETED_BIT, &w->flags) || 
                test_bit(w->version, state->need_parent))
        {
            ret = 0;
            goto out;
        }
    }

out:
    read_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

/**
 * Mark version for deletion during merges.
 *
 * @param version [in] version to be deleted
 *
 * @return non-zero if version couldn't be deleted
 */
int castle_version_delete(version_t version)
{
    struct castle_version *v, *p, *sybling;
    struct list_head *pos;
    da_id_t da_id;

    write_lock_irq(&castle_versions_hash_lock);

    v = __castle_versions_hash_get(version);
    if(!v)
    {
        write_unlock_irq(&castle_versions_hash_lock);
        return -EINVAL;
    }

    /* Sanity check flags. */
    BUG_ON(test_bit(CV_ATTACHED_BIT, &v->flags));
    BUG_ON(!test_bit(CV_INITED_BIT, &v->flags));

    if(test_and_set_bit(CV_DELETED_BIT, &v->flags))
    {
        write_unlock_irq(&castle_versions_hash_lock);
        return -EAGAIN;
    }

    /* Add to list of deleted versions in reverse-DFS order. */
    list_for_each(pos, &castle_versions_deleted)
    {
        struct castle_version *d = list_entry(pos, struct castle_version, del_list);

        if (d->o_order < v->o_order)
            break;

        BUG_ON(d->o_order == v->o_order);
    }
    list_add_tail(&v->del_list, pos);
    castle_versions_count_dec(v->da_id);

    castle_printk("Marked version %d for deletion: 0x%lx\n", version, v->flags);
    da_id = v->da_id;

    /* Check if ancestors can be marked as leaf. Go upto root. */
    while(v->version != 0)
    {
        p = v->parent;

        /* Check if version P can be marked as leaf. */
        for (sybling = p->first_child; sybling; sybling = sybling->next_sybling)
        {
            /* Don't mark P as leaf if any of the children are non-leafs or
             * alive. */
            if (!test_bit(CV_LEAF_BIT, &sybling->flags) || !test_bit(CV_DELETED_BIT, &sybling->flags))
            {
                debug("Version %d is still parent of %d\n", p->version, sybling->version);
                break;
            }
        }
 
        /* If all children are leafs and marked for deletion mark P as leaf. */
        if (!sybling)
        {
            castle_printk("Marking verion %d as leaf\n", p->version);
            set_bit(CV_LEAF_BIT, &p->flags);
        }
        else
            break;

        /* Check the parent also. */
        v = p;
    }

    write_unlock_irq(&castle_versions_hash_lock);

    castle_sysfs_version_del(version);

    castle_da_version_delete(da_id);

    /* raise event */
    castle_events_version_destroy(version);

    return 0;
}


/** 
 * Delete a version from version tree. Only possible, while deleting complete
 * collection. 
 *
 * @param v [in] delete structure for version v from version tree.
 *
 * @return parent of version v.
 * */
static struct castle_version * castle_version_subtree_delete(struct castle_version *v, 
                                                             struct list_head *version_list)
{
    struct castle_version *parent;

    if (!v)
        return NULL;

    /* Sanity check flags. */
    BUG_ON(test_bit(CV_ATTACHED_BIT, &v->flags));
    BUG_ON(!test_bit(CV_INITED_BIT, &v->flags));

    parent = v->parent;

    /* Remove version from hash. */
    castle_versions_drop(v);
    __castle_versions_hash_remove(v);
    list_add_tail(&v->free_list, version_list);
    
    return parent;
}

/** 
 * Delete the complete version subtree from the tree. Can be done only while
 * deleting complete collection. 
 * 
 * @param version [in] delete version sub-tree with root version from version tree.
 *
 * @return non-zero if, failed to destroy version sub-tree.
 */
int castle_version_tree_delete(version_t version)
{
    struct castle_version *v, *cur;
    int ret = 0;
    struct list_head *pos, *tmp;
    LIST_HEAD(version_list);

    v = castle_versions_hash_get(version);
    if (!v)
    {
        castle_printk("Asked to delete a non-existent version: %u\n", version);
        ret = -EINVAL;
        goto error_out;
    }

    write_lock_irq(&castle_versions_hash_lock);
    BUG_ON(!(v->flags & CV_INITED_MASK));
    cur = v;
    while (1)
    {
        /* Check if the version is leaf. */
        if (!cur->first_child)
        {
            int done = 0;

            /* If the node to be deleted is cur, then exit. */
            if (cur == v)
                done = 1;

            /* Delete version and handle Parent. castle_version_subtree_delete()
             * returns parent of the deleted node. */
            cur = castle_version_subtree_delete(cur, &version_list);
            if (cur == NULL)
            {
                ret = -EINVAL;
                goto error_out;
            }

            if (done)
                break;
            else
                continue;
        }

        /* For non-leaf nodes, delete first child. */
        cur = cur->first_child;
    }
    write_unlock_irq(&castle_versions_hash_lock);

    list_for_each_safe(pos, tmp, &version_list)
    {
        struct castle_version *del_v = list_entry(pos, struct castle_version, free_list);

        castle_sysfs_version_del(del_v->version);
        castle_events_version_destroy(del_v->version);
        list_del(pos);
        kmem_cache_free(castle_versions_cache, del_v);
    }

    /* Run processing to re-calculate the version ordering. */
    castle_versions_process();

error_out:
    return ret;
}

static struct castle_version* castle_version_add(version_t version, 
                                                 version_t parent, 
                                                 da_id_t da_id,
                                                 c_byte_off_t size)
{
    struct castle_version *v;
    int ret;

    /* Check we are under the per-DA version limit. */
    if ((ret = castle_versions_count_inc(da_id)) != EXIT_SUCCESS)
    {
        if (ret == -E2BIG)
            castle_printk("Beta cannot create more than %d versions per DA.\n",
                    CASTLE_VERSIONS_MAX);
        return NULL;
    }

    v = kmem_cache_alloc(castle_versions_cache, GFP_KERNEL);
    if (!v)
        goto out_dealloc;
    
    debug("Adding: (v, p)=(%d,%d)\n", version, parent);
    
    v->version      = version;
    v->parent_v     = parent;
    v->first_child  = NULL; 
    v->next_sybling = NULL; 
    v->o_order      = INVAL_VERSION;
    v->r_order      = INVAL_VERSION;
    v->da_id        = da_id;
    v->size         = size; 
    v->flags        = 0;
    INIT_LIST_HEAD(&v->hash_list);
    INIT_LIST_HEAD(&v->init_list);

    /* Initialise version 0 fully, defer full init of all other versions by 
       putting it on the init list. */ 
    if (v->version == 0)
    {
        if(castle_sysfs_version_add(v->version))
            goto out_dealloc;

        v->parent       = NULL;
        v->first_child  = NULL; /* This will be updated later */
        v->next_sybling = NULL;
        v->flags       |= CV_INITED_MASK;

        castle_versions_hash_add(v);
    }
    else
    {
        /* Defer the initialisation until all the ancestral nodes are
           available. */
        castle_versions_init_add(v);
        castle_versions_hash_add(v);
    }

    return v;

out_dealloc:
    kmem_cache_free(castle_versions_cache, v);
    castle_versions_count_dec(da_id);

    return NULL;
}

da_id_t castle_version_da_id_get(version_t version)
{
    struct castle_version *v;
    da_id_t da_id;

    read_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    /* Sanity checks */
    BUG_ON(!v);
    BUG_ON(!(v->flags & CV_INITED_MASK));
    da_id = v->da_id;
    read_unlock_irq(&castle_versions_hash_lock);
 
    return da_id; 
}

/* TODO who should handle errors in writeback? */
static int castle_version_writeback(struct castle_version *v, void *unused)
{
    struct castle_vlist_entry mstore_ventry;
    
    debug("Writing back version %d\n", v->version);

    mstore_ventry.version_nr = v->version;
    mstore_ventry.parent     = (v->parent ? v->parent->version : 0);
    mstore_ventry.size       = v->size;
    mstore_ventry.da_id      = v->da_id;
    mstore_ventry.flags      = (v->flags & (CV_DELETED_MASK | CV_LEAF_MASK));

    read_unlock_irq(&castle_versions_hash_lock);
    castle_mstore_entry_insert(castle_versions_mstore, &mstore_ventry);
    read_lock_irq(&castle_versions_hash_lock);

    return 0;
}

int castle_versions_writeback(void)
{ /* Should be called in CASTLE_TRANSACTION. */
    BUG_ON(castle_versions_mstore);

    castle_versions_mstore = 
        castle_mstore_init(MSTORE_VERSIONS_ID, sizeof(struct castle_vlist_entry));
    if(!castle_versions_mstore)
        return -ENOMEM;
    
    /* Writeback new copy. */
    castle_versions_hash_iterate(castle_version_writeback, NULL);

    castle_mstore_fini(castle_versions_mstore);
    castle_versions_mstore = NULL;

    return 0;
}

/***** External functions *****/
static struct castle_version* castle_version_new_create(int snap_or_clone,
                                                        version_t parent,
                                                        da_id_t da_id,
                                                        c_byte_off_t size)
{
    struct castle_version *v, *p;
    c_byte_off_t parent_size;
    version_t version;

    /* Read ftree root from the parent (also, make sure parent exists) */
    p = castle_versions_hash_get(parent);
    if(!p)
    {
        castle_printk("Asked to create a child of non-existant parent: %d\n",
            parent);
        return NULL;
    }
    
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
    
    /* If our parent has the size set, inherit it (ignores the size argument) */
    if(parent_size != 0)
        v->size = parent_size;
    
    /* Run processing (which will thread the new version into the tree,
       and recalculate the order numbers) */
    castle_versions_process(); 
    
    /* Check if the version got initialised */
    if(!(v->flags & CV_INITED_MASK))
    {
        castle_versions_hash_remove(v);
        kmem_cache_free(castle_versions_cache, v);

        return NULL;
    }

    /* Set is_leaf bit for the the child and clear for parent. */
    set_bit(CV_LEAF_BIT, &v->flags);
    clear_bit(CV_LEAF_BIT, &p->flags);

    castle_events_version_create(version);

    return v;
}

version_t castle_version_new(int snap_or_clone,
                             version_t parent,
                             da_id_t da_id,
                             c_byte_off_t size)
{
    struct castle_version *v;
    int is_leaf = castle_version_is_leaf(parent);
    int is_attached = castle_version_attached(parent);
    
    /* Snapshot is not possible on non-leafs. */
    if (snap_or_clone && !is_leaf)
    {
        castle_printk("Couldn't snapshot non-leaf version: %d.\n", parent);
        return INVAL_VERSION;
    }

    /* Clone is not possible on leafs which are attached. */
    if (!snap_or_clone && is_leaf && is_attached)
    {
        castle_printk("Couldn't clone leaf versions: %d.\n", parent);
        return INVAL_VERSION;
    }

    debug("New version: snap_or_clone=%d, parent=%d, size=%lld\n",
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

    return v->version; 
}

int castle_version_attach(version_t version) 
{
    struct castle_version *v;
    int ret = 0;

    write_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(!v)
    {
        ret = -EINVAL;
        goto out;
    }

    if(test_and_set_bit(CV_ATTACHED_BIT, &v->flags))
    {
        castle_printk("attach bit not valid\n");
        ret = -EAGAIN;
        goto out;
    }

out:
    write_unlock_irq(&castle_versions_hash_lock);
    return ret;
}

int castle_version_read(version_t version, 
                        da_id_t *da,
                        version_t *parent,
                        version_t *live_parent,
                        c_byte_off_t *size,
                        int *leaf)
{
    struct castle_version *v;

    read_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(!v)
    {
        read_unlock_irq(&castle_versions_hash_lock);
        return -EINVAL;
    }
    
    /* Set these even if we fail to set the attached bit */
    if(da)     *da     =  v->da_id;
    if(size)   *size   =  v->size;
    if(parent) *parent =  v->parent ? v->parent->version : 0;
    if(leaf)   *leaf   =  test_bit(CV_LEAF_BIT, &v->flags);
    /* Walk the tree up to the root, searching for first live ancestor. */
    if(live_parent)
    {
        v = v->parent;
        while(v && test_bit(CV_DELETED_BIT, &v->flags))
            v = v->parent;
        *live_parent = v ? v->version : 0;
    }
    read_unlock_irq(&castle_versions_hash_lock);

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

static void castle_versions_drop(struct castle_version *v)
{
    struct castle_version *sybling_list, *prev, *p;

    if (!v)
        return;

    p = v->parent;
    prev = NULL;
    sybling_list = p->first_child;
    while(sybling_list)
    {
        if (sybling_list == v)
        {
            if (prev)
                prev->next_sybling = v->next_sybling;
            else
                p->first_child = v->next_sybling;
        }
        prev = sybling_list;
        sybling_list = sybling_list->next_sybling;
    }
    v->next_sybling = v->parent = NULL;
}

static int castle_versions_process(void)
{
    struct castle_version *v, *p, *n;
    LIST_HEAD(sysfs_list); 
    version_t id;
    int children_first, ret;
    int err = 0;

    write_lock_irq(&castle_versions_hash_lock);
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

        if (!test_bit(CV_DELETED_BIT, &v->flags))
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
    write_unlock_irq(&castle_versions_hash_lock);

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
            castle_printk("Could not add version %d to sysfs. Errno=%d.\n", v->version, ret);
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

    read_lock_irq(&castle_versions_hash_lock);
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
    read_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

int castle_version_compare(version_t version1, version_t version2)
{
    struct castle_version *v1, *v2;
    int ret;

    read_lock_irq(&castle_versions_hash_lock);
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
    read_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

int castle_versions_zero_init(void)
{
    struct castle_version *v;

    debug("Initialising version root.\n");

    v = castle_version_add(0, 0, INVAL_DA, 0);
    if (!v)
    {
        castle_printk("Failed to create verion ZERO\n");
        return -1;
    }
    castle_versions_last = v->version;

    return 0;
}

int castle_versions_read(void)
{
    struct castle_vlist_entry mstore_ventry;
    struct castle_mstore_iter* iterator = NULL;
    struct castle_version* v; 
    c_mstore_key_t key;
    int ret = 0;

    BUG_ON(castle_versions_mstore);
    castle_versions_mstore = 
        castle_mstore_open(MSTORE_VERSIONS_ID, sizeof(struct castle_vlist_entry));

    if(!castle_versions_mstore)
    {
        ret = -ENOMEM;
        goto out;
    }

    iterator = castle_mstore_iterate(castle_versions_mstore);
    if(!iterator)
    {
        ret = -EINVAL;
        goto out;
    }

    while(castle_mstore_iterator_has_next(iterator))
    {
        castle_mstore_iterator_next(iterator, &mstore_ventry, &key);
        v = castle_version_add(mstore_ventry.version_nr, 
                               mstore_ventry.parent, 
                               mstore_ventry.da_id,
                               mstore_ventry.size);
        if(!v)
        {
            ret = -ENOMEM;
            goto out;
        }
        else
            v->flags |= mstore_ventry.flags;

        if(VERSION_INVAL(castle_versions_last) || v->version > castle_versions_last)
            castle_versions_last = v->version;
    }
    ret = castle_versions_process(); 

out:
    if (iterator)               castle_mstore_iterator_destroy(iterator);
    if (castle_versions_mstore) castle_mstore_fini(castle_versions_mstore);
    castle_versions_mstore = NULL;

    return ret; 
}

/***** Init/fini functions *****/
int castle_versions_init(void)
{
    int ret;

    /* Check that the version limit is set correctly (i.e. below the number of
       entries we are guanateed to fit into leaf nodes). */
    BUG_ON(castle_btree_vlba_max_nr_entries_get(VLBA_HDD_RO_TREE_NODE_SIZE) < CASTLE_VERSIONS_MAX);
    ret = -ENOMEM;
    castle_versions_cache = kmem_cache_create("castle_versions",
                                               sizeof(struct castle_version),
                                               0,     /* align */
                                               0,     /* flags */
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
                                               NULL, NULL); /* ctor, dtor */
#else                                               
                                               NULL); /* ctor */
#endif

    if (!castle_versions_cache)
    {
        castle_printk("Could not allocate kmem cache for castle versions.\n");
        goto err_out;
    }
    
    castle_versions_hash = castle_versions_hash_alloc();
    if (!castle_versions_hash)
    {
        castle_printk("Could not allocate versions hash.\n");
        goto err_out;
    }
    castle_versions_hash_init();

    castle_versions_counts_hash = castle_versions_counts_hash_alloc();
    if (!castle_versions_counts_hash)
    {
        castle_printk("Could not allocate version counts hash.\n");
        goto err_out;
    }
    castle_versions_counts_hash_init();

    return 0;

err_out:
    if (castle_versions_cache)
        kmem_cache_destroy(castle_versions_cache);
    if (castle_versions_hash)
        castle_free(castle_versions_hash);
    if (castle_versions_counts_hash)
        castle_free(castle_versions_counts_hash);
    return ret;
}

void castle_versions_fini(void)
{
    castle_versions_hash_destroy();
    castle_version_counts_hash_destroy();
    kmem_cache_destroy(castle_versions_cache);
}
