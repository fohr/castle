#include "castle_timestamps.h"
#include "castle_versions.h"
#include "castle_da.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)            ((void)0)
#else
#define debug(_f, _a...)          (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static void castle_dfs_resolver_reset(c_dfs_resolver *dfs_resolver);

/* should be called by merge_init */
int castle_dfs_resolver_construct(c_dfs_resolver *dfs_resolver, struct castle_da_merge *merge)
{
    signed int ret = 0;
    uint32_t new_node_size;
    int max_entries;

    BUG_ON(!merge);
    BUG_ON(!merge->da->user_timestamping);
    BUG_ON(!dfs_resolver);

    /* Set resolver functions */
    if( merge->da->user_timestamping )
        dfs_resolver->functions |= DFS_RESOLVE_TIMESTAMPS;
    if( merge->out_tree->data_age == 1)
        dfs_resolver->functions |= DFS_RESOLVE_TOMBSTONES;
    if(!dfs_resolver->functions)
    {
        ret = -EINVAL;
        goto err1;
    }

    /* Allocate and init btree node buffer */
    new_node_size = castle_da_merge_node_size_get(merge, 0);
    dfs_resolver->buffer_node = castle_alloc(new_node_size * C_BLK_SIZE);
    if(!dfs_resolver->buffer_node)
    {
        ret = -ENOMEM;
        goto err0;
    }
    castle_da_node_buffer_init(merge->out_btree, dfs_resolver->buffer_node, new_node_size);

    /* Allocate the inclusion flag buffer */
    BUG_ON(!merge->out_btree);
    max_entries = merge->out_btree->max_entries(new_node_size);
    dfs_resolver->inclusion_buffer = castle_alloc(sizeof(struct castle_da_entry_candidate_t) *
                                                        max_entries);
    if(!dfs_resolver->inclusion_buffer)
    {
        ret = -ENOMEM;
        goto err1;
    }

    /* Alloc DFS walker stack base structure */
    dfs_resolver->stack = castle_zalloc(sizeof(c_uint32_stack), GFP_KERNEL);
    if( !dfs_resolver->stack )
    {
        ret = -ENOMEM;
        goto err2;
    }

    /* Construct DFS walker stack */
    ret = castle_uint32_stack_construct(dfs_resolver->stack, max_entries);
    if(ret)
        goto err3;

    /* Init stuff */
    dfs_resolver->_buffer_max      = max_entries;
    dfs_resolver->top_index        = 0;
    dfs_resolver->curr_index       = 0;
    dfs_resolver->merge            = merge;
    dfs_resolver->mode             = DFS_RESOLVER_NULL;

#ifdef DEBUG
    {
        int i;
        for(i=0; i<dfs_resolver->_buffer_max; i++)
        {
            dfs_resolver->inclusion_buffer[i].included = 2;
        }
    }
#endif
    castle_printk(LOG_DEBUG, "%s::merge id %u, function mode %u, with capacity for %u entries\n",
            __FUNCTION__, dfs_resolver->merge->id, dfs_resolver->functions, dfs_resolver->_buffer_max);
    return 0;

err3:
    castle_free(dfs_resolver->stack);
    dfs_resolver->stack = NULL;
err2:
    castle_free(dfs_resolver->inclusion_buffer);
    dfs_resolver->inclusion_buffer = NULL;
err1:
    castle_free(dfs_resolver->buffer_node);
    dfs_resolver->buffer_node = NULL;
err0:
    castle_printk(LOG_ERROR, "%s::failed for merge id %u (%p)\n",
        __FUNCTION__,
        merge->id,
        merge);
    return ret;
}

/* should be called by merge_dealloc */
void castle_dfs_resolver_destroy(c_dfs_resolver *dfs_resolver)
{
    BUG_ON(!dfs_resolver);

    castle_printk(LOG_DEBUG, "%s::merge id %u\n", __FUNCTION__, dfs_resolver->merge->id);

    /* Destroy stack */
    BUG_ON(!dfs_resolver->stack);
    castle_uint32_stack_destroy(dfs_resolver->stack);
    dfs_resolver->stack = NULL;

    /* Dealloc inclusion buffer */
    BUG_ON(!dfs_resolver->inclusion_buffer);
    castle_free(dfs_resolver->inclusion_buffer);
    dfs_resolver->inclusion_buffer = NULL;

    /* Dealloc btree node buffer */
    BUG_ON(!dfs_resolver->buffer_node);
    castle_free(dfs_resolver->buffer_node);
    dfs_resolver->buffer_node = NULL;
}

/* should be called by merge_da_entry_add for a set of same k entries */
int castle_dfs_resolver_entry_add(c_dfs_resolver *dfs_resolver,
                                  void *key,
                                  c_val_tup_t cvt,
                                  c_ver_t version,
                                  castle_user_timestamp_t u_ts)
{
    struct castle_btree_type *btree;

    BUG_ON(!dfs_resolver);
    BUG_ON(!key);
    BUG_ON(!CVT_LEAF_VAL(cvt) && !CVT_LOCAL_COUNTER(cvt));
    BUG_ON(!dfs_resolver->merge);
    BUG_ON(!dfs_resolver->merge->out_btree);

    btree = dfs_resolver->merge->out_btree;
    BUG_ON(!btree);

    if(dfs_resolver->mode == DFS_RESOLVER_NULL)
    {
        /* first insert */
        BUG_ON(dfs_resolver->top_index != 0);
#ifdef DEBUG
        BUG_ON(!castle_dfs_resolver_is_new_key_check(dfs_resolver, key));
#endif
        castle_printk(LOG_DEBUG, "%s::merge id %u first add\n",
                __FUNCTION__,
                dfs_resolver->merge->id);
        dfs_resolver->mode = DFS_RESOLVER_ENTRY_ADD;

#if 0
        /* if we already have a key, dealloc it. */
        if( dfs_resolver->key )
            castle_free(dfs_resolver->key);

        dfs_resolver->key = btree->key_copy(key, NULL, NULL);
        if(!dfs_resolver->key)
        {
            castle_printk(LOG_WARN, "%s::failed to allocate space for key!\n", __FUNCTION__);
            BUG();
            WARN_ON(1);
            return -ENOMEM;
        }
#endif
    }
    else
    {
        BUG_ON(dfs_resolver->mode != DFS_RESOLVER_ENTRY_ADD);
        BUG_ON(dfs_resolver->top_index == 0); /* must have added at least 1 entry so far */
#ifdef DEBUG
        BUG_ON(castle_dfs_resolver_is_new_key_check(dfs_resolver, key));
#endif
    }

    /* we must not have already reached the max expected entries */
    BUG_ON(dfs_resolver->top_index == dfs_resolver->_buffer_max);

    /* finally, add to the buffer */
#if 0
    dfs_resolver->buffer[dfs_resolver->top_index].cvt     = cvt;
    dfs_resolver->buffer[dfs_resolver->top_index].version = version;
    dfs_resolver->buffer[dfs_resolver->top_index].u_ts    = u_ts;
#endif

    btree->entry_add(dfs_resolver->buffer_node, dfs_resolver->top_index, key, version, cvt);

    castle_printk(LOG_DEBUG, "%s::merge id %u adding entry %llu with version %u timestamp %llu of key : ",
            __FUNCTION__,
            dfs_resolver->merge->id,
            dfs_resolver->top_index,
            version,
            cvt.user_timestamp);
    dfs_resolver->merge->out_btree->key_print(LOG_DEBUG, key);
    castle_printk(LOG_DEBUG, "\n");

    dfs_resolver->top_index++;

    return 0;
}

/**
 * Pop entries in the buffer that are marked 'included' by the process method.
 *
 * @return 0 if there are no entries to pop; else returns EAGAIN.
 */
int castle_dfs_resolver_entry_pop(c_dfs_resolver *dfs_resolver,
                                  void **key_p,
                                  c_val_tup_t *cvt_p,
                                  c_ver_t *version_p,
                                  castle_user_timestamp_t *u_ts_p)
{
    struct castle_btree_type *btree;

    BUG_ON(!dfs_resolver);
    BUG_ON(!key_p);
    BUG_ON(!cvt_p);
    BUG_ON(!version_p);
    BUG_ON(!u_ts_p);

    btree = dfs_resolver->merge->out_btree;
    BUG_ON(!btree);

    if(dfs_resolver->mode == DFS_RESOLVER_NULL)
        return 0; /* nothing processed yet; just return nothing to pop */

    if(dfs_resolver->mode == DFS_RESOLVER_BUFFER_PROCESS)
    {
        /* first pop */
        castle_printk(LOG_DEBUG, "%s::merge id %u first pop\n",
                __FUNCTION__,
                dfs_resolver->merge->id);
        BUG_ON(dfs_resolver->curr_index != 0);
        dfs_resolver->mode = DFS_RESOLVER_ENTRY_POP;
    }
    else
    {
        BUG_ON(dfs_resolver->curr_index == 0); /* must have been something popped already */
        BUG_ON(dfs_resolver->mode != DFS_RESOLVER_ENTRY_POP);
    }

    if(dfs_resolver->curr_index == dfs_resolver->top_index)
        goto no_more_entries;

    /* skip over excluded entries */
    while(dfs_resolver->inclusion_buffer[dfs_resolver->curr_index].included == 0)
    {
        /* The locally "oldest" entry must be included; there is no v-order older entry
           to deprecate it (UNLESS we are discarding tombstones...) */
        BUG_ON( !( dfs_resolver->functions & DFS_RESOLVE_TOMBSTONES ) &&
                (dfs_resolver->curr_index == dfs_resolver->top_index - 1) );

        dfs_resolver->curr_index++;

        if(dfs_resolver->curr_index == dfs_resolver->top_index)
            goto no_more_entries;
    }

    BUG_ON(dfs_resolver->inclusion_buffer[dfs_resolver->curr_index].included != 1);

    /* Pop the entry */

#if 0
    *key_p     = dfs_resolver->key;
    *cvt_p     = dfs_resolver->buffer[dfs_resolver->curr_index].cvt;
    *version_p = dfs_resolver->buffer[dfs_resolver->curr_index].version;
    *u_ts_p    = dfs_resolver->buffer[dfs_resolver->curr_index].u_ts;
#endif

    btree->entry_get(dfs_resolver->buffer_node,
                     dfs_resolver->curr_index,
                     key_p,
                     version_p,
                     cvt_p);
    *u_ts_p    = cvt_p->user_timestamp;

    castle_printk(LOG_DEBUG, "%s::merge id %u popping entry %llu with version %u timestamp %llu of key : ",
            __FUNCTION__,
            dfs_resolver->merge->id,
            dfs_resolver->curr_index,
            *version_p,
            *u_ts_p);
    dfs_resolver->merge->out_btree->key_print(LOG_DEBUG, *key_p);
    castle_printk(LOG_DEBUG, "\n");

    /* Prepare for next pop */
    dfs_resolver->curr_index++;
    return EAGAIN;

    BUG(); /* Impossible to arrive here */

no_more_entries:
    castle_dfs_resolver_reset(dfs_resolver);
    return 0;
}

#ifdef DEBUG
static void DEBUG_castle_dfs_resolver_stack_check(c_uint32_stack *stack)
{
    BUG_ON(!stack);

    if(stack->top == 0)
        return;

    /* Check index ordering... it must be sorted, and there can't be repeats. Because it must be
       sorted, there's no need for full blown tortoise and hare; any repeats will be adjacent. */
    if(stack->top != 1){
        unsigned int t = 0;
        unsigned int h = 1;

        do {
            if(!(stack->_stack[h++] < stack->_stack[t++]))
                BUG();
        } while(h!=stack->top);
    }
}
#endif

/**
 * Process the resolver buffer; mark entries as included/not included for the benefit of
 * the entry_pop method.
 *
 * @return number of included entries (i.e. number of entries that will be returned by repeated
 *         calls to the entry_pop method).
 */
uint32_t castle_dfs_resolver_process(c_dfs_resolver *dfs_resolver)
{
    int64_t i;
    struct castle_btree_type *btree;
    uint32_t entries_included = 0;
    uint32_t entries_excluded = 0;

    BUG_ON(!dfs_resolver);
    btree = dfs_resolver->merge->out_btree;
    BUG_ON(!btree);

    if(dfs_resolver->mode == DFS_RESOLVER_NULL)
        return 0; /* nothing added yet; just return nothing to pop */

    /* at least one entry must have been added */
    BUG_ON(dfs_resolver->top_index < 1);
    BUG_ON(dfs_resolver->mode != DFS_RESOLVER_ENTRY_ADD);
    dfs_resolver->mode = DFS_RESOLVER_BUFFER_PROCESS;

    castle_uint32_stack_reset(dfs_resolver->stack);

    /*
    Das Algorithm fur deciding whether entries are timestamp deprecated or not:
    for each entry e (from end of buffer_node to 0)
        while (stack not empty) and (top of stack not ancestral to e)
            pop stack

        if(stack empty) || e.ts > stack.top.ts
            include e and push it onto the stack

        (does not include tombstone discardation magic)
    */

    BUG_ON(dfs_resolver->top_index != dfs_resolver->buffer_node->used);
    for(i = dfs_resolver->top_index - 1; i>=0; i--)
    {
        int entry_included = 0;
        castle_user_timestamp_t entry_i_ts,
                                stack_top_ts = 0;
        c_ver_t                 entry_i_version,
                                stack_top_version;
        c_val_tup_t             entry_i_cvt,
                                stack_top_cvt;

        btree->entry_get(dfs_resolver->buffer_node, i, NULL, &entry_i_version, &entry_i_cvt);
        entry_i_ts = entry_i_cvt.user_timestamp;

        while( dfs_resolver->stack->top != 0 )
        {
            uint32_t stack_top_index = castle_uint32_stack_top_val_ret(dfs_resolver->stack);
            btree->entry_get(dfs_resolver->buffer_node,
                             stack_top_index,
                             NULL,
                             &stack_top_version,
                             &stack_top_cvt);
            stack_top_ts = stack_top_cvt.user_timestamp;
            if(castle_version_is_ancestor(stack_top_version, entry_i_version))
                break;
            else
                castle_uint32_stack_pop(dfs_resolver->stack);
        }

        /* Handle timestamps first */
        if( dfs_resolver->functions & DFS_RESOLVE_TIMESTAMPS )
        {
            if( (dfs_resolver->stack->top == 0) || !(stack_top_ts > entry_i_ts) )
                entry_included = 1;
        }
        else /* No timestamping, so entries cannot be timestamp deprecated */
            entry_included = 1;

        /* Handle tombstone discardation */
        if( ( dfs_resolver->functions & DFS_RESOLVE_TOMBSTONES ) && /* Discarding tombstones... */
            ( CVT_TOMBSTONE(entry_i_cvt) ) &&           /* this is a tombstone... */
            ( (dfs_resolver->stack->top == 0) || /* it has no included ancestors, or */
              CVT_TOMBSTONE(stack_top_cvt) ) )   /* it's immediate ancestor is a tombstone... */
        {
            castle_printk(LOG_DEBUG, "%s::merge id %u, tombstone discarded\n",
                    __FUNCTION__, dfs_resolver->merge->id);
            entry_included = 0;                         /* ... so, we can discard it! */
        }

        //if( (dfs_resolver->functions & DFS_RESOLVE_TOMBSTONES) && entry_included)
        //{
        //    if( CVT_TOMBSTONE(entry_i_cvt) )
        //    {
        //        if( dfs_resolver->stack->top == 0 ) /* local root version */
        //        {
        //            entry_included = 0;
        //            dfs_resolver->inclusion_buffer[i].discardable = 1;
        //        }
        //        else /* got local ancestor */
        //        {
        //            dfs_resolver->inclusion_buffer[i].discardable =
        //                dfs_resolver->inclusion_buffer[stack_top_index].discardable;
        //            /* included only if it's ancestor was not discarded */
        //            entry_included = !discardable[i];
        //            // does this block mean effectively that the entry will be included????????
        //        }
        //    }
        //    else
        //        /* non-tombstone included entry; entries from this point on in the dfs path
        //           cannot be discarded */
        //        dfs_resolver->inclusion_buffer[i].discardable = 0;
        //}


        if(entry_included)
        {
                castle_uint32_stack_push(dfs_resolver->stack, i);
                dfs_resolver->inclusion_buffer[i].included = 1;
                entries_included++;
#ifdef DEBUG
                DEBUG_castle_dfs_resolver_stack_check(dfs_resolver->stack)
#endif
        }
        else
        {
            /* Top of the stack is never excluded, unless we are discarding tombstones */
            BUG_ON( !( dfs_resolver->functions & DFS_RESOLVE_TOMBSTONES ) &&
                    dfs_resolver->stack->top == 0);
            dfs_resolver->inclusion_buffer[i].included = 0;
            entries_excluded++;
        }
    }//for each entry (reverse iter)

    BUG_ON(dfs_resolver->top_index != entries_included + entries_excluded);
    BUG_ON( !( dfs_resolver->functions & DFS_RESOLVE_TOMBSTONES ) &&
        (entries_included == 0)); /* at least the root entry must be included (UNLESS we are
                                     discarding tombstones...)*/

    debug(LOG_DEBUG, "%s::merge id %u, entries included = %u out of %u\n",
                  __FUNCTION__,
                  dfs_resolver->merge->id,
                  entries_included,
                  dfs_resolver->top_index);
    return entries_included;
}

/* This is a replacement for the merge->is_new_key flag, which doesn't work if we are using a
   dfs_resolver, since the merge->last_key pointer is only updated during da_entry_add().     */
int castle_dfs_resolver_is_new_key_check(c_dfs_resolver *dfs_resolver, void *key)
{
    struct castle_btree_type *btree;
    void *key_b;
    BUG_ON(!dfs_resolver);
    BUG_ON(!key);

    if(!dfs_resolver->buffer_node->used)
    {
        BUG_ON(dfs_resolver->mode != DFS_RESOLVER_NULL);
        return 1;
    }

    BUG_ON(dfs_resolver->mode != DFS_RESOLVER_ENTRY_ADD);
    btree = dfs_resolver->merge->out_btree;
    BUG_ON(!btree);
    btree->entry_get(dfs_resolver->buffer_node, 0, &key_b, NULL, NULL);
    return btree->key_compare(key, key_b);
}

/* called after the last (draining) pop, to reset state for subsequent keys */
static void castle_dfs_resolver_reset(c_dfs_resolver *dfs_resolver)
{
    struct castle_btree_type *btree;
    BUG_ON(!dfs_resolver);
    BUG_ON(!dfs_resolver->merge);
    BUG_ON(dfs_resolver->mode != DFS_RESOLVER_ENTRY_POP);

#ifdef DEBUG
    {
        int i;
        for(i=0; i<dfs_resolver->_buffer_max; i++)
        {
            dfs_resolver->inclusion_buffer[i].included = 2;
        }
    }
#endif

    /* if we were popping, we must have had at least one entry */
    BUG_ON(dfs_resolver->top_index == 0);

    dfs_resolver->top_index  = 0;
    dfs_resolver->curr_index = 0;
    dfs_resolver->mode = DFS_RESOLVER_NULL;

    /* drop all entries in the buffer */
    BUG_ON(!dfs_resolver->buffer_node->used); /* there must have been at least 1 entry */
    btree = dfs_resolver->merge->out_btree;
    BUG_ON(!btree);
    btree->entries_drop(dfs_resolver->buffer_node, 0, dfs_resolver->buffer_node->used - 1);
}



