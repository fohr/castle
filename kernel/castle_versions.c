#include <linux/module.h>
#include <linux/workqueue.h> 
#include <linux/list.h>
#include <linux/slab.h>
#include <linux/hardirq.h>

#include "castle.h"
#include "castle_versions.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define INVAL_VERSION       ((version_t)-1) 
#define VERSION_INVAL(_v)   ((_v) == INVAL_VERSION) 

static struct kmem_cache *castle_versions_cache = NULL;

#define CASTLE_VERSIONS_HASH_SIZE       (1000)
static    DEFINE_SPINLOCK(castle_versions_hash_lock);
static struct list_head  *castle_versions_hash  = NULL;
static          LIST_HEAD(castle_versions_init_list);

struct castle_version {
    /* Various tree links, saved as version #s (rather than pointers) */
    version_t    version;
    version_t    parent;
    version_t    first_child;
    version_t    next_sybling;

    /* Aux data */
    c_disk_blk_t ftree_root;
    uint32_t     size;

    /* Lists for storing versions the hash table & the init list*/
    struct list_head hash_list; 
    int              inited;
    struct list_head init_list;
};


/***** Hash table & init list *****/
static int castle_versions_hash_idx(version_t version)
{
    return (version % CASTLE_VERSIONS_HASH_SIZE);
} 

static void castle_versions_hash_add(struct castle_version *v)
{
    int idx = castle_versions_hash_idx(v->version);
    
    spin_lock(&castle_versions_hash_lock);
    list_add(&v->hash_list, &castle_versions_hash[idx]);
    spin_unlock(&castle_versions_hash_lock);
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

    spin_lock(&castle_versions_hash_lock);
    for(i=0; i<CASTLE_VERSIONS_HASH_SIZE; i++)
    {
        list_for_each_safe(l, t, &castle_versions_hash[i])
        {
            list_del(l);
            v = list_entry(l, struct castle_version, hash_list);
            kmem_cache_free(castle_versions_cache, v);
        }
    }
    spin_unlock(&castle_versions_hash_lock);
}

static void castle_versions_init_add(struct castle_version *v)
{
    spin_lock(&castle_versions_hash_lock);
    v->inited = 0;
    list_add(&v->init_list, &castle_versions_init_list);
    spin_unlock(&castle_versions_hash_lock);
}


/***** External functions *****/
int castle_version_add(version_t version, 
                       version_t parent, 
                       c_disk_blk_t ftree_root,
                       uint32_t  size)
{
    struct castle_version *v;

    v = kmem_cache_alloc(castle_versions_cache, GFP_KERNEL);
    if(!v) return -ENOMEM;
    debug("Adding: (v, p)=(%d,%d)\n", version, parent);

    v->version      = version;
    v->parent       = parent;
    v->first_child  = INVAL_VERSION;
    v->next_sybling = INVAL_VERSION;
    v->ftree_root   = ftree_root;
    v->size         = size;
    INIT_LIST_HEAD(&v->hash_list);
    v->inited       = 1; 
    INIT_LIST_HEAD(&v->init_list);

    castle_versions_hash_add(v);
    /* Version 0 doesn't need to be initialised any further */
    if(v->version != 0)
        castle_versions_init_add(v);

    return 0;
}

int castle_version_snap_get(version_t version, 
                            c_disk_blk_t *ftree_root,
                            uint32_t *size)
{
    struct castle_version *v;
    int ret = -EINVAL;

    spin_lock(&castle_versions_hash_lock);
    v = __castle_versions_hash_get(version);
    if(v) 
    {
        if(ftree_root) *ftree_root = v->ftree_root;
        if(size)       *size       = v->size;
        ret = 0;
    }
    spin_unlock(&castle_versions_hash_lock);

    return ret;
} 

void castle_versions_process(void)
{
    struct castle_version *v, *p;

    spin_lock(&castle_versions_hash_lock);
    /* Start processing elements from the init list, one at the time */
    while(!list_empty(&castle_versions_init_list))
    {
        v = list_first_entry(&castle_versions_init_list, 
                              struct castle_version,
                              init_list);
process_version:        
        /* Remove the element from the list */
        list_del(&v->init_list);
        BUG_ON(v->inited);

        /* Find it's parent, and check if it's been inited already */
        p = __castle_versions_hash_get(v->parent);
        BUG_ON(!p);
        /* If the parent hasn't been initialised yet, initialise it instead */
        if(!p->inited)
        {
            /* Re-add v back to the init list */
            list_add_tail(&v->init_list, &castle_versions_init_list);
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
        v->next_sybling = p->first_child;
        p->first_child  = v->version;
        debug(" Versions's sybling is version %d\n", v->next_sybling);
        /* We are done */
        v->inited = 1;
    }

    spin_unlock(&castle_versions_hash_lock);
}

int castle_version_is_ancestor(version_t candidate, version_t version)
{
    struct castle_version *v;
    int ret;

    spin_lock(&castle_versions_hash_lock);
again:    
    if(candidate == version)
    {
        ret = 1;
        goto out;
    }
    if(version == 0)
    {
        ret = 0;
        goto out;
    }
    v = __castle_versions_hash_get(version);
    BUG_ON(!v);
    version = v->parent;
    goto again;

out:
    spin_unlock(&castle_versions_hash_lock);
    return ret;
}

/***** Init/fini functions *****/
int castle_versions_init(void)
{
    int i, ret;

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
    castle_versions_hash_destroy();
    kmem_cache_destroy(castle_versions_cache);
    kfree(castle_versions_hash);
}
