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
#include "castle_mstore.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static int castle_versions_process(int lock);

static struct kmem_cache *castle_versions_cache  = NULL;

#define CASTLE_VERSIONS_MAX                 (200)   /**< Maximum number of live versions per-DA.*/
#define CASTLE_VERSIONS_HASH_SIZE           (1000)  /**< Size of castle_versions_hash.          */
#define CASTLE_VERSIONS_COUNTS_HASH_SIZE    (1000)  /**< Size of castle_versions_counts_hash.   */
static struct list_head  *castle_versions_hash          = NULL;
static          LIST_HEAD(castle_versions_init_list);
static struct list_head  *castle_versions_counts_hash   = NULL;

/* castle_version_last should be same type as c_ver_t. */
/* Note: we need this variable to be atomic, as max_get() can race with version_add(). */
static atomic_t           castle_versions_last   = ATOMIC(INVAL_VERSION);
static atomic_t           castle_versions_count  = ATOMIC(0);

static int castle_versions_deleted_sysfs_hide = 1;  /**< Hide deleted versions from sysfs?      */
module_param(castle_versions_deleted_sysfs_hide, int, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_versions_deleted_sysfs_hide, "Hide deleted versions from sysfs");

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

#define V_IMMUTABLE_INIT(_v)                       \
{                                                  \
    if (test_bit(CV_LEAF_BIT, &(_v)->flags))      \
    {                                              \
        do_gettimeofday(&(_v)->immute_timestamp);  \
        barrier();                                 \
        clear_bit(CV_LEAF_BIT, &(_v)->flags);      \
    }                                              \
}                                                  \

struct castle_version {
    /* Various tree links */
    c_ver_t                    version;     /**< Version ID, unique across all Doubling Arrays. */
    union {
        c_ver_t                parent_v;    /**< Valid if !initialised.                         */
        struct castle_version *parent;      /**< Valid if  initialised.                         */
    };
    struct castle_version     *first_child;
    struct castle_version     *next_sybling;

    /* Aux data */
    c_ver_t          o_order;
    c_ver_t          r_order;
    c_da_t           da_id;             /**< Doubling Array ID this version exists within.      */
    c_byte_off_t     size;

    /* We keep two sets of version stats: live and delayed.
     *
     * The live stats are updated during inserts, merges, deletes and provide
     * an insight into the current state of the DA.  These live stats are
     * exposed to userland consumers via sysfs.
     *
     * The delayed stats are updated in a crash-consistent manner as merges
     * get 'snapshotted', see castle_da_merge_serialise(). */
    struct castle_version_stats stats;  /**< Stats associated with version (crash consistent).  */

    struct list_head hash_list;         /**< List for hash table, protected by hash lock.       */
    unsigned long    flags;
    union {                             /**< All lists in this union are protected by the
                                             ctrl mutex.                                        */
        struct list_head init_list;     /**< Used when the version is being initialised.        */
        struct list_head free_list;     /**< Used when the version is being removed.            */
    };
    struct list_head del_list;

    /* Misc info about the version. */
    struct timeval creation_timestamp;
    struct timeval immute_timestamp; /* the time the version was made immutable */
};

/**
 * Describes the number of versions per DA.
 */
struct castle_versions_count {
    c_da_t              da_id;      /**< DA we are counting live versions for.          */

    int                 live;       /**< Number of live versions.                       */
    int                 deleted;    /**< Number of deleted versions.                    */
    int                 dead;       /**< Number of dead versions.                       */

    int                 total;      /**< Sum of all version counts.                     */

    struct list_head    hash_list;  /**< Threading onto castle_versions_counts_hash.    */
};

DEFINE_HASH_TBL(castle_versions,
                castle_versions_hash,
                CASTLE_VERSIONS_HASH_SIZE,
                struct castle_version,
                hash_list,
                c_ver_t,
                version);
DEFINE_HASH_TBL(castle_versions_counts,
                castle_versions_counts_hash,
                CASTLE_VERSIONS_COUNTS_HASH_SIZE,
                struct castle_versions_count,
                hash_list,
                c_da_t,
                da_id);

/********************************************************
 * Functions related to the castle_versions_counts hash *
 *******************************************************/

/**
 * Disassociate all castle_version_count from hash and free them.
 */
static int castle_version_counts_hash_remove(struct castle_versions_count *vc, void *unused)
{
    list_del(&vc->hash_list);
    castle_free(vc);

    return 0;
}

/**
 * Free castle_versions_counts_hash and all members.
 */
static void castle_versions_counts_hash_destroy(void)
{
    castle_versions_counts_hash_iterate(castle_version_counts_hash_remove, NULL);
    castle_free(castle_versions_counts_hash);
}

/**
 * Adjust per-DA version counts in response to version add/delete.
 *
 * @param   da_id       Which DA's version stats to update
 * @param   health      Health of the version being adjusted
 * @param   add         Set implies add version, unset delete version
 * @param   propagate   Whether to propagate subsequent health state counters
 *                      on delete.
 *                        - If set during a live version delete, the deleted
 *                          versions count will be bumped.
 *                        - If unset during a live version delete, only the
 *                          live version count will be decremented.  Required
 *                          if a version allocation fails.
 *
 * @return  0       SUCCESS
 * @return -ENOMEM  Failed to allocate new castle_versions_count struct
 * @return -E2BIG   Already at maximum live versions for DA
 *
 * @also castle_version_add()
 */
int _castle_versions_count_adjust(c_da_t da_id, cv_health_t health, int add, int propagate)
{
    struct castle_versions_count *vc;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    vc = castle_versions_counts_hash_get(da_id);
    if (!vc)
    {
        BUG_ON(!add);

        vc = castle_zalloc(sizeof(struct castle_versions_count));
        if (!vc)
            return -ENOMEM;
        vc->da_id = da_id;
        /* zalloc initialised counts for us */
        INIT_LIST_HEAD(&vc->hash_list);
        castle_versions_counts_hash_add(vc);
    }

    if (add) /* incrementing version count */
    {
        switch (health)
        {
            case CVH_LIVE:
                if (vc->live < CASTLE_VERSIONS_MAX)
                    vc->live++;
                else
                    return -E2BIG;
                break;

            case CVH_DELETED:
                vc->deleted++;
                break;

            case CVH_DEAD:
            case CVH_TOTAL:
            default:
                BUG();
        }

        vc->total++;
    }
    else /* decrementing version count */
    {
        switch (health)
        {
            case CVH_LIVE:
                BUG_ON(--vc->live < 0);
                if (likely(propagate))
                    vc->deleted++;
                else
                    BUG_ON(--vc->total < 0);
                break;

            case CVH_DELETED:
                BUG_ON(--vc->deleted < 0);
                if (likely(propagate))
                    vc->dead++;
                else
                    BUG_ON(--vc->total < 0);
                break;

            case CVH_DEAD:
                BUG_ON(--vc->dead < 0);
                BUG_ON(--vc->total < 0);
                break;

            case CVH_TOTAL:
            default:
                BUG();
        }

        /* Free the version count structure if the total count reaches 0. */
        if (vc->total == 0)
        {
            BUG_ON(vc->live + vc->deleted + vc->dead != 0);

            list_del(&vc->hash_list);
            castle_free(vc);
        }
    }

    BUG_ON(vc->live + vc->deleted + vc->dead != vc->total);

    return EXIT_SUCCESS;
}

/**
 * Adjust per-DA version counts.
 *
 * @param   da_id   DA ID
 * @param   health  Adjust which type of version
 * @param   add     If set implies a bump of health
 *                      Unset implies decrement
 *
 * @also _castle_versions_count_adjust()
 */
int castle_versions_count_adjust(c_da_t da_id, cv_health_t health, int add)
{
    return _castle_versions_count_adjust(da_id, health, add, 1 /*propagate*/);
}

/**
 * Get number of health versions for DA.
 *
 * @param   da_id   DA to check
 * @param   health  Versions of which health
 */
int castle_versions_count_get(c_da_t da_id, cv_health_t health)
{
    struct castle_versions_count *vc;

    vc = castle_versions_counts_hash_get(da_id);
    BUG_ON(!vc);

    switch (health)
    {
        case CVH_LIVE:      return vc->live;    break;
        case CVH_DELETED:   return vc->deleted; break;
        case CVH_DEAD:      return vc->dead;    break;
        case CVH_TOTAL:     return vc->total;   break;
    }

    return -EINVAL;
}

/***************************************************
 * Functions associated with castle_versions_hash. *
 **************************************************/

/**
 * Disassociate all castle_versions from hash and free them.
 */
static int castle_version_hash_remove(struct castle_version *v, void *unused)
{
    atomic_dec(&castle_versions_count);
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
    castle_check_free(castle_versions_hash);
}

static void castle_versions_init_add(struct castle_version *v)
{
    v->flags &= (~CV_INITED_MASK);
    list_add(&v->init_list, &castle_versions_init_list);
}

c_ver_t castle_version_max_get(void)
{
    return atomic_read(&castle_versions_last) + 1;
}

static void castle_versions_drop(struct castle_version *p);
static int castle_version_writeback(struct castle_version *v, void *unused);

int castle_version_attached(c_ver_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    return test_bit(CV_ATTACHED_BIT, &v->flags);
}

int castle_version_deleted(c_ver_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    if(!v)
        return -EINVAL;

    castle_printk(LOG_INFO, "Flags in version %d: 0x%lx\n", version, v->flags);
    return test_bit(CV_DELETED_BIT, &v->flags);
}

int castle_version_is_leaf(c_ver_t version)
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
        c_ver_t ver_id = w->version;

        /* If the child is created after merge started, assume that this version needs the
         * key from parent.
         * Note: Even if the version is deleted, it is possible that it's child might need it.
         * We don't have much information to take any decision, so assume it needs the parent. */
        if (ver_id >= state->last_version)
            return 1;

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
 * For other versions, need_parent doesn't represent any thing.
 *
 * @param state [in] state of the snapshot delete for current key
 * @param version [in] version of the current entry
 *
 * @return 1 if, version is deletable.
 */
int castle_version_is_deletable(struct castle_version_delete_state *state,
                                c_ver_t version,
                                int is_new_key)
{
    struct castle_version *cur_v = NULL, *w;
    struct list_head *list;
    int ret = 1;

    BUG_ON(version >= state->last_version);

    /* Set occupied bit for this version. Merge is single-threaded and runs on
     * same processor. No need of set_bit.
     */
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

    /* If this is the first key in merge stream, don't delete. As we know this version is not
     * leaf and descendents are not visible. */
    if (is_new_key)
    {
        ret = 0;
        goto out;
    }

    if (state->next_deleted == NULL)
        state->next_deleted = castle_versions_deleted.next;

    /* Go through all deleted versions in reverse-DFS order until the current version. */
    list_for_each_from(state->next_deleted, list, &castle_versions_deleted)
    {
        struct castle_version *del_v = list_entry(list, struct castle_version, del_list);

        /* don't look at versions created after merge started. */
        if (del_v->version >= state->last_version)
            continue;

        if (del_v->o_order < cur_v->o_order)
            break;

        BUG_ON(!test_bit(CV_DELETED_BIT, &del_v->flags));

        if (castle_version_needs_parent(del_v, state))
        {
            if (del_v->version >= state->last_version)
            {
                castle_printk(LOG_ERROR, "del_v: %p, state: %p, v1: %d, v2: %d\n",
                        del_v, state, del_v->version, state->last_version);
                BUG_ON(1);
            }

            __set_bit(del_v->version, state->need_parent);
        }
    }
    state->next_deleted = list;

    /* Check the version required by children. For undeleted children, don't look
     * at need_parent bit (its not calculated for them). */
    for (w=cur_v->first_child; w; w=w->next_sybling)
    {
        /* If the child version isn't tracked in the bitmaps (out of bounds), assume
           that it needs the parent, and don't check any of the bitmaps. */
        if (w->version >= state->last_version)
        {
            ret = 0;
            goto out;
        }

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
 * Appends version to the @see castle_versions_deleted list in the reverse-DFS order.
 *
 * @param v     Deleted version to process.
 */
static void castle_version_deleted_list_add(struct castle_version *v)
{
    struct list_head *pos;

    /* Should only be called for deleted versions. */
    BUG_ON(!test_bit(CV_DELETED_BIT, &v->flags));

    /* Go through the list, until the right position is found. */
    list_for_each(pos, &castle_versions_deleted)
    {
        struct castle_version *d = list_entry(pos, struct castle_version, del_list);

        if (d->o_order < v->o_order)
            break;

        BUG_ON(d->o_order == v->o_order);
    }

    /* Add the version before pos. */
    list_add_tail(&v->del_list, pos);
}


/**
 * Mark version for deletion during merges.
 *
 * @param version [in]  Version to be deleted
 *
 * NOTE: Can not be used to delete block device versions.
 *
 * @return non-zero if version couldn't be deleted
 */
int castle_version_delete(c_ver_t version)
{
    struct castle_version *v, *p, *n, *d, *sybling;
    c_da_t da_id;
    int children_first, event_vs_idx;
    c_ver_t *event_vs;

    /* Allocate memory for event notifications before taking the spinlock. */
    event_vs = castle_alloc(sizeof(c_ver_t) * CASTLE_VERSIONS_MAX);
    if(!event_vs)
        castle_printk(LOG_WARN, "Cannot allocate memory to notify of version deletions.\n");

    /* Lock. */
    write_lock_irq(&castle_versions_hash_lock);

    v = __castle_versions_hash_get(version);
    if(!v)
    {
        write_unlock_irq(&castle_versions_hash_lock);
        castle_free(event_vs);
        return -EINVAL;
    }
    da_id = v->da_id;

    /* Ensure we're not trying to delete a block device version. */
    BUG_ON(DA_INVAL(da_id));

    /* Sanity check flags. */
    BUG_ON(test_bit(CV_ATTACHED_BIT, &v->flags));
    BUG_ON(!test_bit(CV_INITED_BIT, &v->flags));

    if (!castle_double_array_alive(da_id))
    {
        castle_printk(LOG_INFO, "Couldn't find DA for version %u, must be marked deletion.\n",
                                version);
        write_unlock_irq(&castle_versions_hash_lock);
        castle_free(event_vs);
        return -EINVAL;
    }

    /* Before making any changes check if this is the last version to delete. */
    if (castle_versions_count_get(da_id, CVH_LIVE) == 1)
    {
        /* This is the last version. Don't delete the version, instead destroy DA. */

        /* Release resources. */
        write_unlock_irq(&castle_versions_hash_lock);
        castle_free(event_vs);

        castle_printk(LOG_USERINFO, "Last version is getting deleted; destroying Version Tree.\n");

        return castle_double_array_destroy(da_id);
    }

    if(test_and_set_bit(CV_DELETED_BIT, &v->flags))
    {
        write_unlock_irq(&castle_versions_hash_lock);
        castle_free(event_vs);
        return -EAGAIN;
    }

    /* Add to list of deleted versions in reverse-DFS order. */
    castle_version_deleted_list_add(v);

    castle_printk(LOG_USERINFO, "Marked version %d for deletion: 0x%lx\n", version, v->flags);

    /* Check if ancestors can be marked as leaf. Go upto root. */
    while(v->version != 0)
    {
        p = v->parent;

        /* Check if version P can be marked as leaf. */
        for (sybling = p->first_child; sybling; sybling = sybling->next_sybling)
        {
            /* Don't mark P as leaf if any of the children are non-leafs or
             * alive. */
            if (!test_bit(CV_LEAF_BIT, &sybling->flags) ||
                !test_bit(CV_DELETED_BIT, &sybling->flags))
            {
                debug("Version %d is still parent of %d\n", p->version, sybling->version);
                break;
            }
        }

        /* If all children are leafs and marked for deletion mark P as leaf. */
        if (!sybling)
        {
            castle_printk(LOG_INFO, "Marking verion %d as leaf\n", p->version);
            set_bit(CV_LEAF_BIT, &p->flags);
        }
        else
            break;

        /* Check the parent also. */
        v = p;
    }

    /* Collect all live children versions, for which we need to send the notifications. */
    d = v = __castle_versions_hash_get(version);
    event_vs_idx = 0;
    children_first = !test_bit(CV_LEAF_BIT, &v->flags);
    /* Keep walking until 'v' goes back to the root of the subtree, by which time
       children_first will not be set. */
    while((v != d) || children_first)
    {
        /* Select the next node in the following order of preference:
           If children_first is true (i.e. we are trying to walk down the tree)
           - first child, if child is deleted
           - next sybling
           - parent
           If child first is false
           - next sybling
           - parent
           This walk approximates the DFS walk to assign order numbers in
           castle_versions_process().
         */
        n = NULL;
        if(children_first)
            n = v->first_child;
        children_first = 1;
        if(!n)
            n = v->next_sybling;
        if(!n)
        {
            n = v->parent;
            BUG_ON(!n);
            BUG_ON(!test_bit(CV_DELETED_BIT, &n->flags));
            /* Stop the walk from going down the tree, if we are going back to the parent. */
            children_first = 0;
        }
        /* Next version must always exist, at the end of the walk we'll get back to 'd'. */
        BUG_ON(!n);
        /* Stop the walk from going down the tree, if 'n' is not deleted. */
        if(!test_bit(CV_DELETED_BIT, &n->flags))
        {
            children_first = 0;
            /* Add next version to the list of notifications. */
            BUG_ON(event_vs_idx >= CASTLE_VERSIONS_MAX);
            if(event_vs)
                event_vs[event_vs_idx++] = n->version;
        }
        v = n;
    }

    write_unlock_irq(&castle_versions_hash_lock);

    if (castle_versions_deleted_sysfs_hide)
        BUG_ON(castle_sysfs_version_del(version));
    for(event_vs_idx--; event_vs_idx >= 0; event_vs_idx--)
        castle_events_version_changed(event_vs[event_vs_idx]);
    castle_check_free(event_vs);

    castle_versions_count_adjust(da_id, CVH_LIVE, 0 /*add*/);

    /* raise event */
    castle_events_version_delete_version(version);

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
static struct castle_version * castle_version_delete_from_tree(struct castle_version *v,
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
    atomic_dec(&castle_versions_count);
    __castle_versions_hash_remove(v);
    list_del(&v->del_list);
    if (version_list)
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
int castle_version_tree_delete(c_ver_t version)
{
    struct castle_version *v, *cur;
    int ret = 0;
    struct list_head *pos, *tmp;
    LIST_HEAD(version_list);
    int batch;

    v = castle_versions_hash_get(version);
    if (!v)
    {
        castle_printk(LOG_WARN, "Asked to delete a non-existent version: %u\n", version);
        ret = -EINVAL;
        goto error_out;
    }

    write_lock_irq(&castle_versions_hash_lock);
    BUG_ON(!(v->flags & CV_INITED_MASK));
    cur = v;
    batch = 100;
    while (1)
    {
        /* Preemption point ever 'batch' versions. */
        if(batch-- < 0)
        {
            write_unlock_irq(&castle_versions_hash_lock);
            might_resched();
            write_lock_irq(&castle_versions_hash_lock);
            batch = 100;
        }

        /* Check if the version is leaf. */
        if (!cur->first_child)
        {
            int done = 0;

            /* If the node to be deleted is cur, then exit. */
            if (cur == v)
                done = 1;

            /* Delete version and handle Parent. castle_version_subtree_delete()
             * returns parent of the deleted node. */
            cur = castle_version_delete_from_tree(cur, &version_list);
            BUG_ON(cur == NULL);

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

        BUG_ON(castle_sysfs_version_del(del_v->version));
        castle_events_version_delete_version(del_v->version);
        list_del(pos);
        kmem_cache_free(castle_versions_cache, del_v);
    }

    /* Run processing to re-calculate the version ordering. */
    castle_versions_process(1);

error_out:
    return ret;
}

void castle_versions_orphans_check(void)
{
    struct castle_version *t, *v, *root = castle_versions_hash_get(0);

    BUG_ON(root == NULL);

    v = root->first_child;
    while (v != NULL)
    {
        t = v->next_sybling;
        if (!DA_INVAL(v->da_id) && !castle_double_array_alive(v->da_id))
        {
            BUG_ON(v->size != 0);
            castle_printk(LOG_WARN, "Found an orphan version tree: %u\n", v->version);
            castle_version_tree_delete(v->version);
        }
        v = t;
    }
}

/**
 * Free the resources used by version.
 */
int castle_version_free(c_ver_t version)
{
    struct castle_version *v;

    /* Should be holding the transaction lock. */
    BUG_ON(!CASTLE_IN_TRANSACTION);

    v = castle_versions_hash_get(version);
    if (v == NULL)
        return -EINVAL;

    BUG_ON(castle_version_delete_from_tree(v, NULL) == NULL);

    BUG_ON(castle_sysfs_version_del(version));
    castle_events_version_delete_version(version);
    kmem_cache_free(castle_versions_cache, v);

    return 0;
}


/**
 * Allocate a new version structure and add it to castle_versions_hash.
 *
 * @param   version [in]    Version number to add
 * @param   parent  [in]    New version's parent version number
 * @param   da_id   [in]    DA new version is associated with
 * @param   size    [in]    ??? Size of version ???
 * @param   health  [in]    What state the version is in (e.g. live, deleted, etc.)
 * @param   ver_out [out]   Pointer to new version structure
 *
 * - Updates per-DA version counts (based on health).
 *
 * @return  0           Version successfully added
 * @return -E2BIG       Per-DA live version limit reached
 * @return -EINVAL      Memory allocation or sysfs failure
 *
 * @also castle_version_delete()
 * @also castle_versions_count_adjust()
 */
static int castle_version_add(c_ver_t version,
                              c_ver_t parent,
                              c_da_t da_id,
                              c_byte_off_t size,
                              cv_health_t health,
                              struct castle_version **ver_out)
{
    struct castle_version *v;
    int ret;

    /* Update version counts and verify we're under live version limit. */
    if ((ret = castle_versions_count_adjust(da_id, health, 1 /*add*/)) != EXIT_SUCCESS)
    {
        if (ret == -E2BIG)
            castle_printk(LOG_USERINFO,
                    "Maximum live version limit (%d) reached for DA 0x%x\n",
                    CASTLE_VERSIONS_MAX, da_id);
        *ver_out = NULL;
        return -E2BIG;
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
    INIT_LIST_HEAD(&v->del_list);

    /* Initialise crash-consistent version stats. */
    atomic64_set(&v->stats.keys, 0);
    atomic64_set(&v->stats.tombstones, 0);
    atomic64_set(&v->stats.tombstone_deletes, 0);
    atomic64_set(&v->stats.version_deletes, 0);
    atomic64_set(&v->stats.key_replaces, 0);

    /* Clean timestamp. */
    memset(&v->creation_timestamp, 0, sizeof(struct timeval));
    memset(&v->immute_timestamp, 0, sizeof(struct timeval));

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
    /* Increment the number of versions known to the filesystem. */
    atomic_inc(&castle_versions_count);

    *ver_out = v;
    return 0;

out_dealloc:
    if (v)
        kmem_cache_free(castle_versions_cache, v);
    /* Revert bump to version counts.  Don't propagate as this decrement does
     * not imply health -> health+1. */
    _castle_versions_count_adjust(da_id, health, 0 /*add*/, 0 /*propagate*/);

    *ver_out = NULL;
    return -EINVAL;
}

c_da_t castle_version_da_id_get(c_ver_t version)
{
    struct castle_version *v;
    c_da_t da_id;

    read_lock_irq(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);

    /* Sanity checks */
    if (!v)
    {
        read_unlock_irq(&castle_versions_hash_lock);
        return INVAL_DA;
    }

    BUG_ON(!(v->flags & CV_INITED_MASK));
    da_id = v->da_id;
    read_unlock_irq(&castle_versions_hash_lock);

    return da_id;
}

/**
 * Determine hash bucket for version.
 */
static inline int castle_version_states_hash_idx(c_ver_t version)
{
    unsigned long hash = 0UL;

    return (int)(((unsigned long)version) % CASTLE_VERSION_STATES_HASH_SIZE);

    memcpy(&hash, &version, sizeof(c_ver_t) > 8 ? 8 : sizeof(c_ver_t));

    return (int)(hash % CASTLE_VERSION_STATES_HASH_SIZE);
}

/**
 * Add castle_version_state to hash.
 */
inline void castle_version_states_hash_add(cv_states_t *states, cv_state_t *state)
{
    int idx;

    idx = castle_version_states_hash_idx(state->version);
    list_add(&state->hash_list, &states->hash[idx]);
}

/**
 * Return castle_version_state structure for version, if it exists.
 */
inline cv_state_t* castle_version_states_hash_get(cv_states_t *states, c_ver_t version)
{
    cv_state_t *state;
    struct list_head *l;
    int idx;

    idx = castle_version_states_hash_idx(version);
    list_for_each(l, &states->hash[idx])
    {
        state = list_entry(l, cv_state_t, hash_list);
        if (state->version == version)
            return state;
    }

    return NULL;
}

/**
 * Return castle_version_state structure for version, allocate if necessary.
 */
inline cv_state_t* castle_version_states_hash_get_alloc(cv_states_t *states, c_ver_t version)
{
    cv_state_t *state;

    state = castle_version_states_hash_get(states, version);
    if (state)
        return state;

    /* Allocate new castle_version_state structure, add it to the hash
     * and return a pointer to the user. */
    state = &states->array[states->free_idx++];
    BUG_ON(states->free_idx > states->max_idx);
    memset(state, 0, sizeof(cv_state_t));
    state->version = version;
    castle_version_states_hash_add(states, state);

    return state;
}

/**
 * Update version stats as described by adjust.
 *
 * @param   adjust      Describe adjustments to be made/retrieved.
 *
 * NOTE: Only one set of stats (consistent or private) can be adjusted
 *       per call.
 *
 * @also castle_version_stats_adjust()
 * @also castle_version_stats_get()
 */
static cv_nonatomic_stats_t _castle_version_stats_adjust(c_ver_t version,
                                                         cv_nonatomic_stats_t adjust)
{
    cv_nonatomic_stats_t return_stats;
    struct castle_version *v;
    cv_stats_t *stats;

    read_lock_irq(&castle_versions_hash_lock); // @FIXME do we need irq disabled?
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    BUG_ON(!(v->flags & CV_INITED_MASK));

    stats = &v->stats;

    return_stats.keys               = atomic64_add_return(adjust.keys, &stats->keys);
    return_stats.tombstones         = atomic64_add_return(adjust.tombstones,
                                                          &stats->tombstones);
    return_stats.tombstone_deletes  = atomic64_add_return(adjust.tombstone_deletes,
                                                          &stats->tombstone_deletes);
    return_stats.version_deletes    = atomic64_add_return(adjust.version_deletes,
                                                          &stats->version_deletes);
    return_stats.key_replaces       = atomic64_add_return(adjust.key_replaces,
                                                          &stats->key_replaces);
    return_stats.timestamp_rejects  = atomic64_add_return(adjust.timestamp_rejects,
                                                          &stats->timestamp_rejects);

    read_unlock_irq(&castle_versions_hash_lock);

    return return_stats;
}

/**
 * Adjust state of crash-consistent per-version stats by amounts in adjust.
 *
 * See _castle_version_stats_adjust() for argument info.
 *
 * @also _castle_version_stats_adjust()
 * @also castle_version_consistent_stats_get()
 */
static void castle_version_consistent_stats_adjust(c_ver_t version, cv_nonatomic_stats_t adjust)
{
    _castle_version_stats_adjust(version, adjust);
}

/**
 * Return current state of crash consistent per-version stats.
 *
 * See _castle_version_stats_adjust() for argument info.
 *
 * @also _castle_version_stats_adjust()
 */
cv_nonatomic_stats_t castle_version_consistent_stats_get(c_ver_t version)
{
    cv_nonatomic_stats_t null_adjust = { 0, 0, 0, 0, 0 };

    return _castle_version_stats_adjust(version, null_adjust);
}

/**
 * Commit and zero private version stats to global crash-consistent tree.
 */
void castle_version_states_commit(cv_states_t *states)
{
    int i;

    for (i = 0; i < states->free_idx; i++)
    {
        cv_state_t *state;

        state = &states->array[i];
        castle_version_consistent_stats_adjust(state->version, state->stats);
        memset(&state->stats, 0, sizeof(cv_nonatomic_stats_t));
    }
}

/**
 * Deallocate version states array and hash.
 *
 * @return  0   Structure was fully allocated
 * @return >0   Structure was not fully allocated
 */
int castle_version_states_free(cv_states_t *states)
{
    int ret = 2;

    if (states->array)
    {
        castle_free(states->array);
        states->array = NULL;
        ret--;
    }

    if (states->hash)
    {
        castle_free(states->hash);
        states->hash = NULL;
        ret--;
    }

    return ret;
}

/**
 * Allocate and initialise version states array and hash.
 *
 * @param   states          Version states structure to initialise
 * @param   max_versions    Maximum possible versions to handle in array
 *
 * @return  0               Success
 * @return  1               Failed to allocate structures
 */
int castle_version_states_alloc(cv_states_t *states, int max_versions)
{
    int i;

    states->array = castle_alloc(max_versions * sizeof(cv_state_t));
    if (!states->array)
        goto err_out;
    states->hash = castle_alloc(CASTLE_VERSION_STATES_HASH_SIZE
            * sizeof(struct list_head));
    if (!states->hash)
        goto err_out;
    states->free_idx = 0;
    states->max_idx = max_versions;

    /* Initialise hash buckets. */
    for (i = 0; i < CASTLE_VERSION_STATES_HASH_SIZE; i++)
        INIT_LIST_HEAD(&states->hash[i]);

    return EXIT_SUCCESS;

err_out:
    castle_version_states_free(states);

    return 1;
}

/**
 * Update version stats when an entry is replaced by another entry. (k,v) must be the same.
 * Update is made in the private version stats hash provided as an argument.
 *
 * @param version Version in which the replace is happening
 * @param old_tup CVT being replaced
 * @param new_tup New CVT
 * @param private Private stats hash
 */
void castle_version_stats_entry_replace(c_ver_t version,
                                        c_val_tup_t old_cvt,
                                        c_val_tup_t new_cvt,
                                        cv_states_t *private)
{
    cv_nonatomic_stats_t *stats;
    cv_state_t *state;

    state = castle_version_states_hash_get_alloc(private, version);
    stats = &state->stats;

    /* If the old cvt was a real key (not a tombstone), decrement the keys count.
       Increment the delete ops count (decide which one depending what we are
       replacing with). */
    if(!CVT_TOMBSTONE(old_cvt))
    {
        stats->keys--;
        if(CVT_TOMBSTONE(new_cvt))
            stats->tombstone_deletes++;
        else
            stats->key_replaces++;
    }
    else
    {
        /* If the new entry is also a tombstone, don't bump the tombstone delete
         * counter: deleting something that is already deleted makes no sense. */

        /* If the new entry is a key, don't bump the key replaces counter:
         * merging a newer key with an older tombstone is logically the same as
         * inserting a new key. */
        stats->tombstones--;
    }
}

/**
 * Update private version stats when an entry is discarded.
 *
 * @param version Version in which the discard is happening
 * @param old_tup CVT being discarded
 * @param new_tup Reason for discarding the entry (version delete or timestamp ordering)
 * @param private Private stats hash
 */
void castle_version_stats_entry_discard(c_ver_t version,
                                        c_val_tup_t cvt,
                                        cvs_discard_t reason,
                                        cv_states_t *private)
{
    cv_nonatomic_stats_t *stats;
    cv_state_t *state;

    state = castle_version_states_hash_get_alloc(private, version);
    stats = &state->stats;

    /* Adjust the key/tombstone counters. */
    if (CVT_TOMBSTONE(cvt))
        stats->tombstones--;
    else
        stats->keys--;

    /* Adjust the ops counters. */
    BUG_ON((reason != CVS_VERSION_DISCARD) && (reason != CVS_TIMESTAMP_DISCARD));
    switch(reason)
    {
        case CVS_VERSION_DISCARD:
            stats->version_deletes++;
            break;
        case CVS_TIMESTAMP_DISCARD:
            stats->timestamp_rejects++;
            break;
        default:
            BUG();
    }
}

/**
 * Update private version stats when an entry is added.
 *
 * @param version Version in which the entry is added
 * @param old_tup CVT being added
 * @param private Private stats hash
 */
void castle_version_stats_entry_add(c_ver_t version,
                                    c_val_tup_t cvt,
                                    cv_states_t *private)
{
    cv_nonatomic_stats_t *stats;
    cv_state_t *state;

    state = castle_version_states_hash_get_alloc(private, version);
    stats = &state->stats;

    /* Adjust the key/tombstone counters. */
    if (CVT_TOMBSTONE(cvt))
        stats->tombstones++;
    else
        stats->keys++;
}

/**
 * Return the creation timestamp for a particular version.
 *
 * The version asked for is expected to exist (BUG otherwise).
 */
struct timeval castle_version_creation_timestamp_get(c_ver_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    BUG_ON(!v);

    return v->creation_timestamp;
}

/**
 * Return the immutisation timestamp for a particular version.
 *
 * The version asked for is expected to exist, and must be immutable (BUG otherwise).
 */
struct timeval castle_version_immute_timestamp_get(c_ver_t version)
{
    struct castle_version *v;

    v = castle_versions_hash_get(version);
    BUG_ON(!v);
    BUG_ON(test_bit(CV_LEAF_BIT, &v->flags));

    return v->immute_timestamp;
}

struct castle_version_writeback_state {
    struct castle_mstore *mstore;
    int is_fini;
};

/* TODO who should handle errors in writeback? */
static int castle_version_writeback(struct castle_version *v, void *_data)
{
    struct castle_vlist_entry mstore_ventry;
    struct castle_version_writeback_state *writeback_state =
                            (struct castle_version_writeback_state *)_data;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    debug("Writing back version %d\n", v->version);

    BUG_ON(writeback_state->is_fini &&
           !DA_INVAL(v->da_id) &&
           !castle_double_array_alive(v->da_id));

    mstore_ventry.version_nr        = v->version;
    mstore_ventry.parent            = (v->parent ? v->parent->version : 0);
    mstore_ventry.size              = v->size;
    mstore_ventry.da_id             = v->da_id;
    mstore_ventry.flags             = (v->flags & (CV_DELETED_MASK | CV_LEAF_MASK));
    mstore_ventry.keys              = atomic64_read(&v->stats.keys);
    mstore_ventry.tombstones        = atomic64_read(&v->stats.tombstones);
    mstore_ventry.tombstone_deletes = atomic64_read(&v->stats.tombstone_deletes);
    mstore_ventry.version_deletes   = atomic64_read(&v->stats.version_deletes);
    mstore_ventry.key_replaces      = atomic64_read(&v->stats.key_replaces);
    mstore_ventry.timestamp_rejects = atomic64_read(&v->stats.timestamp_rejects);
    mstore_ventry.creation_time_s   = v->creation_timestamp.tv_sec;
    mstore_ventry.creation_time_us  = v->creation_timestamp.tv_usec;
    mstore_ventry.immute_time_s     = v->immute_timestamp.tv_sec;
    mstore_ventry.immute_time_us    = v->immute_timestamp.tv_usec;

    read_unlock_irq(&castle_versions_hash_lock);
    castle_mstore_entry_insert(writeback_state->mstore,
                               &mstore_ventry,
                               sizeof(struct castle_vlist_entry));
    read_lock_irq(&castle_versions_hash_lock);

    return 0;
}

int castle_versions_writeback(int is_fini)
{
    struct castle_version_writeback_state writeback_state;

    BUG_ON(!CASTLE_IN_TRANSACTION);

    writeback_state.mstore = castle_mstore_init(MSTORE_VERSIONS_ID);
    if(!writeback_state.mstore)
        return -ENOMEM;

    writeback_state.is_fini = is_fini;

    /* Writeback new copy. */
    castle_versions_hash_iterate(castle_version_writeback, &writeback_state);

    castle_mstore_fini(writeback_state.mstore);

    return 0;
}

/***** External functions *****/
/**
 *
 * @return -EFBIG       Global version limit reached
 * @return -E2BIG       Per-DA live version limit reached
 * @return -EEXIST      Non-existent parent
 */
static int castle_version_new_create(int snap_or_clone,
                                     c_ver_t parent,
                                     c_da_t da_id,
                                     c_byte_off_t size,
                                     struct castle_version **ver_out)
{
    struct castle_version *v, *p;
    c_byte_off_t parent_size;
    c_ver_t version;
    int ret;

    /* Updates to some variables (especially castle_versions_last) are protected by the
       ctrl lock. Make sure its locked. */
    BUG_ON(!castle_ctrl_is_locked());
    /* We'll use last version + 1. */
    version = atomic_read(&castle_versions_last) + 1;

    /* Only accept 50k versions. This guarantees that we won't run out of space in
       the mstore extent. */
    if(atomic_read(&castle_versions_count) >= 50000)
    {
        castle_printk(LOG_WARN, "Too many versions created: %d, rejecting an attempt "
                                "to create a new one.\n",
                                atomic_read(&castle_versions_count));
        *ver_out = NULL;
        return -E2BIG;
    }

    /* Read ftree root from the parent (also, make sure parent exists) */
    p = castle_versions_hash_get(parent);
    if(!p)
    {
        castle_printk(LOG_WARN, "Asked to create a child of non-existent parent: %d\n",
            parent);
        *ver_out = NULL;
        return -EEXIST;
    }

    parent_size = p->size;

    /* Try to add it to the hash. Use the da_id provided or the parent's */
    BUG_ON(!DA_INVAL(da_id) && !DA_INVAL(p->da_id));
    da_id = DA_INVAL(da_id) ? p->da_id : da_id;
    ret = castle_version_add(version, parent, da_id, size, CVH_LIVE, &v);
    if (!v)
    {
        *ver_out = NULL;
        return ret;
    }

    /* If our parent has the size set, inherit it (ignores the size argument) */
    if(parent_size != 0)
        v->size = parent_size;

    /* Run processing (which will thread the new version into the tree,
       and recalculate the order numbers) */
    castle_versions_process(1);

    /* Check if the version got initialised */
    if(!(v->flags & CV_INITED_MASK))
    {
        atomic_dec(&castle_versions_count);
        castle_versions_hash_remove(v);
        kmem_cache_free(castle_versions_cache, v);

        *ver_out = NULL;
        return -EINVAL;
    }

    /* Set is_leaf bit for the the child and clear for parent. */
    set_bit(CV_LEAF_BIT, &v->flags);
    V_IMMUTABLE_INIT(p);

    castle_events_version_create(version);
    BUG_ON(version != atomic_read(&castle_versions_last) + 1);
    atomic_inc(&castle_versions_last);

    *ver_out = v;
    return 0;
}

/**
 *
 * @return -EROFS   Version is non-leaf
 * @return -EUNATCH Version is attached
 *
 * @also castle_version_new_create()
 */
int castle_version_new(int snap_or_clone,
                       c_ver_t parent,
                       c_da_t da_id,
                       c_byte_off_t size,
                       c_ver_t *version)
{
    struct castle_version *v;
    int is_leaf = castle_version_is_leaf(parent);
    int is_attached = castle_version_attached(parent);
    int ret = 0;

    /* Snapshot is not possible on non-leafs. */
    if (snap_or_clone && !is_leaf)
    {
        castle_printk(LOG_WARN, "Couldn't snapshot non-leaf version: %d.\n", parent);
        *version = INVAL_VERSION;

        return -EROFS;
    }

    /* Clone is not possible on leafs which are attached. */
    if (!snap_or_clone && is_leaf && is_attached)
    {
        castle_printk(LOG_WARN, "Couldn't clone leaf versions: %d.\n", parent);
        *version = INVAL_VERSION;
        return -EUNATCH;
    }

    debug("New version: snap_or_clone=%d, parent=%d, size=%lld\n",
            snap_or_clone, parent, size);
    /* Get a new version number */
    ret = castle_version_new_create(snap_or_clone,
                                    parent,
                                    da_id,
                                    size,
                                    &v);

    /* Return if we couldn't create the version correctly
       (possibly because we trying to clone attached version,
        or because someone asked for more than one snapshot to
        an attached version */
    if (!v)
    {
        *version = INVAL_VERSION;
        return ret;
    }

    /* Timestamp the creation. */
    do_gettimeofday(&v->creation_timestamp);

    /* We've succeeded at creating a new version number.
       Let's find where to store it on the disk. */

    *version = v->version;
    return 0;
}

int castle_version_attach(c_ver_t version)
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
        castle_printk(LOG_WARN, "version is already attached\n");
        ret = -EAGAIN;
        goto out;
    }

out:
    write_unlock_irq(&castle_versions_hash_lock);
    return ret;
}

int castle_version_read(c_ver_t version,
                        c_da_t *da,
                        c_ver_t *parent,
                        c_ver_t *live_parent,
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

void castle_version_detach(c_ver_t version)
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

static int castle_versions_process(int lock)
{
    struct castle_version *v, *p, *n;
    LIST_HEAD(sysfs_list);
    c_ver_t id;
    int children_first, ret;
    int err = 0;

    if(lock)
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
       potentially deep recursion */
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
            /* Assign the r order first (the id of the last descendant) */
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
    if(lock)
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
            castle_printk(LOG_WARN, "Could not add version %d to sysfs. Errno=%d.\n",
                    v->version, ret);
            err = -3;
            continue;
        }
    }

    /* Done. */
    return err;
}

static int _castle_version_is_ancestor(c_ver_t candidate, c_ver_t version)
{
    struct castle_version *c, *v;
    int ret;

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

    return ret;
}

int castle_version_is_ancestor(c_ver_t candidate, c_ver_t version)
{
    int ret;

    if (candidate == version)
        return 1;

    read_lock_irq(&castle_versions_hash_lock);
    ret = _castle_version_is_ancestor(candidate, version);
    read_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

static inline int _castle_version_compare(c_ver_t version1, c_ver_t version2)
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

int castle_version_compare(c_ver_t version1, c_ver_t version2)
{
    int ret;

    if (version1 == version2)
        return 0;

    read_lock_irq(&castle_versions_hash_lock);
    ret = _castle_version_compare(version1, version2);
    read_unlock_irq(&castle_versions_hash_lock);

    return ret;
}

void castle_version_is_ancestor_and_compare(c_ver_t version1,
                                            c_ver_t version2,
                                            int *ver1_is_anc_of_ver2,
                                            int *cmp)
{
    if (version1 == version2)
    {
        *ver1_is_anc_of_ver2 = 1;
        *cmp = 0;
        return;
    }

    read_lock_irq(&castle_versions_hash_lock);
    *ver1_is_anc_of_ver2 = _castle_version_is_ancestor(version1, version2);
    *cmp = _castle_version_compare(version1, version2);
    read_unlock_irq(&castle_versions_hash_lock);
}

/**
 * Initialise root version.
 */
int castle_versions_zero_init(void)
{
    struct castle_version *v;
    int ret;

    debug("Initialising version root.\n");

    ret = castle_version_add(0, 0, INVAL_DA, 0, CVH_LIVE, &v);
    if (!v)
    {
        castle_printk(LOG_ERROR, "Failed to create verion ZERO\n");
        return -1;
    }
    atomic_set(&castle_versions_last, v->version);

    return 0;
}

/**
 * Tests whether the specified version is deleted, and adds it to the @see castle_versions_deleted.
 * Can be used from unlocked hash iterators, the trailing void* argument is ignored.
 * Explicit preemption point is included (since the iterator + this fn implement O(n^2) algorithm).
 *
 * @param v      Version to process
 * @param unused Unused
 * @return 0     Since it shouldn't ever stops the hash iterator
 */
static int castle_version_del_process(struct castle_version *v, void *unused)
{
    might_resched();
    if(test_bit(CV_DELETED_BIT, &v->flags))
    {
        castle_version_deleted_list_add(v);
        castle_printk(LOG_DEBUG,
                "%s::Adding deleted version %d [flags: 0x%lx] to castle_versions_deleted list\n",
                __FUNCTION__, v->version, v->flags);
    }
    return 0;
}

/**
 * Unmarshall all castle_versions structures from disk.
 */
int castle_versions_read(void)
{
    struct castle_mstore_iter* iterator = NULL;
    struct castle_version* v;
    int ret = 0;

    iterator = castle_mstore_iterate(MSTORE_VERSIONS_ID);
    if(!iterator)
    {
        ret = -EINVAL;
        goto out;
    }

    while(castle_mstore_iterator_has_next(iterator))
    {
        struct castle_vlist_entry mstore_ventry;
        size_t mstore_ventry_size;
        cv_health_t health;

        castle_mstore_iterator_next(iterator, &mstore_ventry, &mstore_ventry_size);

        BUG_ON(mstore_ventry_size != sizeof(struct castle_vlist_entry));
        health = test_bit(CV_DELETED_BIT, &mstore_ventry.flags)
                ? CVH_DELETED : CVH_LIVE;
        ret = castle_version_add(mstore_ventry.version_nr,
                                 mstore_ventry.parent,
                                 mstore_ventry.da_id,
                                 mstore_ventry.size,
                                 health,
                                 &v);
        if (!v)
        {
            ret = -ENOMEM;
            goto out;
        }
        else
        {
            v->flags |= mstore_ventry.flags;

            /* Load crash-consistent version stats. */
            atomic64_set(&v->stats.keys, mstore_ventry.keys);
            atomic64_set(&v->stats.tombstones, mstore_ventry.tombstones);
            atomic64_set(&v->stats.tombstone_deletes, mstore_ventry.tombstone_deletes);
            atomic64_set(&v->stats.version_deletes, mstore_ventry.version_deletes);
            atomic64_set(&v->stats.key_replaces, mstore_ventry.key_replaces);
            atomic64_set(&v->stats.timestamp_rejects, mstore_ventry.timestamp_rejects);

            /* Misc. */
            v->creation_timestamp.tv_sec  = mstore_ventry.creation_time_s;
            v->creation_timestamp.tv_usec = mstore_ventry.creation_time_us;
            v->immute_timestamp.tv_sec    = mstore_ventry.immute_time_s;
            v->immute_timestamp.tv_usec   = mstore_ventry.immute_time_us;
        }

        if (VERSION_INVAL(atomic_read(&castle_versions_last)) ||
                        v->version > atomic_read(&castle_versions_last))
            atomic_set(&castle_versions_last, v->version);
    }
    ret = castle_versions_process(0);

    /* Restore castle_versions_deleted list */
    __castle_versions_hash_iterate(castle_version_del_process, NULL);
out:
    if (iterator)
        castle_mstore_iterator_destroy(iterator);

    return ret;
}

/***** Init/fini functions *****/
int castle_versions_init(void)
{
    int ret;

    /* Check that the version limit is set correctly (i.e. below the number of
       entries we are guaranteed to fit into leaf nodes). */
    BUG_ON(castle_btree_type_get(VLBA_TREE_TYPE)->max_entries(HDD_RO_TREE_NODE_SIZE) < CASTLE_VERSIONS_MAX ||
           castle_btree_type_get(SLIM_TREE_TYPE)->max_entries(HDD_RO_TREE_NODE_SIZE) < CASTLE_VERSIONS_MAX);
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
        castle_printk(LOG_ERROR, "Could not allocate kmem cache for castle versions.\n");
        goto err_out;
    }

    castle_versions_hash = castle_versions_hash_alloc();
    if (!castle_versions_hash)
    {
        castle_printk(LOG_ERROR, "Could not allocate versions hash.\n");
        goto err_out;
    }
    castle_versions_hash_init();

    castle_versions_counts_hash = castle_versions_counts_hash_alloc();
    if (!castle_versions_counts_hash)
    {
        castle_printk(LOG_ERROR, "Could not allocate version counts hash.\n");
        goto err_out;
    }
    castle_versions_counts_hash_init();

    return 0;

err_out:
    if (castle_versions_cache)
        kmem_cache_destroy(castle_versions_cache);
    castle_check_free(castle_versions_hash);
    castle_check_free(castle_versions_counts_hash);
    return ret;
}

void castle_versions_fini(void)
{
    castle_versions_hash_destroy();
    castle_versions_counts_hash_destroy();
    kmem_cache_destroy(castle_versions_cache);
}
