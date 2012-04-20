#include <linux/delay.h>

#include "castle_public.h"
#include "castle_defines.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_versions.h"
#include "castle_objects.h"
#include "castle_extent.h"
#include "castle_systemtap.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#define debug_rq(_f, ...)       ((void)0)
#define debug_obj(_f, ...)      ((void)0)
#else
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_rq(_f, _a...)     (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_obj(_f, _a...)    (castle_printk(LOG_DEBUG, "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static const uint32_t OBJ_TOMBSTONE = ((uint32_t)-1);

/**********************************************************************************************/
/* Helper functions */

/* this is unsafe to use after we've replied to the backend */
inline static void castle_object_bvec_attach_key_dealloc(struct castle_bio_vec *c_bvec)
{
    castle_double_array_btree_type_get(c_bvec->c_bio->attachment)->key_dealloc(c_bvec->key);
    c_bvec->key = NULL;
}

/* this is unsafe to use if we're not guaranteed to have a proxy structure */
inline static void castle_object_bvec_proxy_key_dealloc(struct castle_bio_vec *c_bvec)
{
    castle_btree_type_get(c_bvec->cts_proxy->btree_type)->key_dealloc(c_bvec->key);
    c_bvec->key = NULL;
}

/**********************************************************************************************/
/* Iterator(s) */

static void castle_objects_rq_iter_register_cb(castle_object_iterator_t *iter,
                                               castle_iterator_end_io_t cb,
                                               void *data)
{
    iter->async_iter.private = data;
    iter->async_iter.end_io = cb;
}

static void castle_objects_rq_iter_next(castle_object_iterator_t *iter,
                                        void **k,
                                        c_ver_t *v,
                                        c_val_tup_t *cvt)
{
    BUG_ON(!iter->cached);
    if(k)   *k   = iter->cached_k;
    if(v)   *v   = iter->cached_v;
    if(cvt) *cvt = iter->cached_cvt;
    iter->cached = 0;
}

static void castle_objects_rq_iter_next_key_free(castle_object_iterator_t *iter)
{
    if (iter->last_next_key)
        iter->btree->key_dealloc(iter->last_next_key);
    iter->last_next_key = NULL;
}

static int castle_objects_rq_iter_prep_next(castle_object_iterator_t *iter)
{
    void *k, *next_key;
    c_ver_t v;
    c_val_tup_t cvt;

    while(1)
    {
        if(iter->cached || iter->completed)
            return 1;
        if(!castle_da_rq_iter.prep_next(&iter->da_rq_iter))
            return 0;
        /* Nothing cached, check if da_rq_iter has anything */
        if(!castle_da_rq_iter.has_next(&iter->da_rq_iter))
        {
            iter->completed = 1;
            return 1;
        }

        /* Nothing cached, but there is something in the da_rq_iter.
           Check if that's within the rq hypercube */
        castle_da_rq_iter.next(&iter->da_rq_iter, &k, &v, &cvt);
        next_key = iter->btree->key_hc_next(k, iter->start_key, iter->end_key);

        if (next_key != k)      /* key is outside the hypercube */
        {
            if (next_key == iter->end_key) /* key is completely past end_key */
            {
                iter->completed = 1;
                return 1;
            }

            /* Save the key, to be freed the next time around the loop/on cancel */
            castle_objects_rq_iter_next_key_free(iter);
            iter->last_next_key = next_key;

#ifdef DEBUG
            debug("Skipping to:\n");
            iter->btree->key_print(next_key);
#endif
            castle_da_rq_iter.skip(&iter->da_rq_iter, next_key);
        }
        else
        {
            /* Found something to cache, save */
            iter->cached_k = k;
            iter->cached_v = v;
            iter->cached_cvt = cvt;
            iter->cached = 1;
        }
    }

    /* We should never get here */
    BUG();
}

static void castle_objects_rq_iter_end_io(void *da_iter,
                                          int err)
{
    castle_object_iterator_t *iter = ((c_da_rq_iter_t *)da_iter)->async_iter.private;

    if (castle_objects_rq_iter_prep_next(iter))
        iter->async_iter.end_io(iter, 0);
}

static int castle_objects_rq_iter_has_next(castle_object_iterator_t *iter)
{
    debug_obj("%s:%p\n", __FUNCTION__, iter);
    if(iter->cached)
        return 1;

    /* End of iterator. */
    BUG_ON(!iter->completed);

    return 0;
#if 0
    /* Nothing cached, check if da_rq_iter has anything */
    BUG_ON(castle_da_rq_iter.has_next(&iter->da_rq_iter));
    debug_obj("%s:%p - reschedule\n", __FUNCTION__, iter);

    return 0;
#endif
}

static void castle_objects_rq_iter_cancel(castle_object_iterator_t *iter)
{
    castle_da_rq_iter.cancel(&iter->da_rq_iter);
    castle_objects_rq_iter_next_key_free(iter);
}

struct castle_iterator_type castle_objects_rq_iter = {
    .register_cb= (castle_iterator_register_cb_t)castle_objects_rq_iter_register_cb,
    .prep_next  = (castle_iterator_prep_next_t)  castle_objects_rq_iter_prep_next,
    .has_next   = (castle_iterator_has_next_t)   castle_objects_rq_iter_has_next,
    .next       = (castle_iterator_next_t)       castle_objects_rq_iter_next,
    .skip       = NULL,
    .cancel     = (castle_iterator_cancel_t)     castle_objects_rq_iter_cancel,
};

/**
 * Complete initialisation of iterator and asynchronously inform caller.
 *
 * @param   private castle_object_iterator_t pointer
 *
 * Asynchronous callback from castle_da_rq_iter_init().  Propagate da_rq_iter
 * errors up the stack and asynchronously call caller via the init_cb.
 *
 * @also castle_objects_rq_iter_init()
 * @also castle_da_rq_iter_init()
 */
void _castle_objects_rq_iter_init(void *private)
{
    castle_object_iterator_t *iter = private;

    /* Propagate iterator errors up the stack. */
    iter->err = iter->da_rq_iter.err;

    /* Register callback handler. */
    castle_da_rq_iter.register_cb(&iter->da_rq_iter,
                                  castle_objects_rq_iter_end_io,
                                  (void *)iter);

    /* Go up the stack */
    iter->init_cb(iter);
}

/**
 * Initialise range query iterator.
 *
 * @param   iter    Iterator to initialise
 * @param   init_cb Asynchronous callback when initialisation is complete
 *
 * Sets up basic iterator state and then hands off to castle_da_rq_iter_init()
 * which goes asynchronous.  Iterator completion is handled in
 * _castle_objects_rq_iter_init().
 *
 * @also _castle_objects_rq_iter_init()
 */
static void castle_objects_rq_iter_init(castle_object_iterator_t *iter,
                                        castle_object_iter_init_cb_t init_cb)
{
    BUG_ON(!iter->start_key || !iter->end_key);
    BUG_ON(!init_cb);

    iter->err = 0;
    iter->init_cb = init_cb;
    iter->async_iter.end_io = NULL;
    iter->async_iter.iter_type = &castle_objects_rq_iter;
    iter->cached = 0;
    /* Set the error on da_rq_iter, which will get cleared by the init,
       but will prevent castle_object_rq_iter_cancel from cancelling the
       da_rq_iter unnecessarily */
    iter->da_rq_iter.err = -EINVAL;
    iter->last_next_key = NULL;
    iter->completed     = 0;
#ifdef DEBUG
    castle_printk(LOG_DEBUG, "====================== RQ start keys =======================\n");
    iter->btree->key_print(iter->start_key);
    castle_printk(LOG_DEBUG, "======================= RQ end keys ========================\n");
    iter->btree->key_print(iter->end_key);
    castle_printk(LOG_DEBUG, "============================================================\n");
#endif

    castle_da_rq_iter_init(&iter->da_rq_iter,
                           iter->version,
                           iter->da_id,
                           iter->start_key,
                           iter->end_key,
                           iter->seq_id,
                           _castle_objects_rq_iter_init, /*init_cb*/
                           iter /*private*/);

    /* Init completes asynchronously in _castle_objects_rq_iter_init(). */
}

/**********************************************************************************************/
/* High level interface functions */
/**********************************************************************************************/

#define OBJ_IO_MAX_BUFFER_SIZE      (10)    /* In C_BLK_SIZE blocks */

static c_ext_pos_t  castle_object_write_next_cep(c_ext_pos_t  old_cep,
                                                 uint32_t data_length)
{
    uint32_t data_c2b_length;
    c_ext_pos_t new_data_cep;
    int nr_blocks;

    /* Work out how large buffer to allocate */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1;
    debug("Allocating new buffer of size %d blocks, for data_length=%d\n",
        nr_blocks, data_length);
    new_data_cep.ext_id  = old_cep.ext_id;
    new_data_cep.offset = old_cep.offset + (nr_blocks * C_BLK_SIZE);

    return new_data_cep;
}

static c2_block_t* castle_object_write_buffer_alloc(c_ext_pos_t new_data_cep,
                                                    uint64_t data_length)
{
    uint64_t data_c2b_length;
    c2_block_t *new_data_c2b;
    int nr_blocks;

    /* Work out how large the buffer is */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1;
    new_data_c2b = castle_cache_block_get(new_data_cep, nr_blocks, MERGE_OUT);
#ifdef CASTLE_DEBUG
    write_lock_c2b(new_data_c2b);
    update_c2b(new_data_c2b);
    /* Poison the data block */
    memset(c2b_buffer(new_data_c2b), 0xf4, nr_blocks * C_BLK_SIZE);
    dirty_c2b(new_data_c2b);
    write_unlock_c2b(new_data_c2b);
#endif

    return new_data_c2b;
}

static void castle_object_replace_data_copy(struct castle_object_replace *replace,
                                            void *buffer, uint32_t buffer_length, int not_last)
{
    struct castle_double_array *da = replace->c_bvec->tree->da;

    replace->data_copy(replace, buffer, buffer_length, not_last);
    atomic64_add(buffer_length, &da->write_data_bytes);

    /* Do rate control checks. We take samples, once per sample_delay. */
    castle_da_write_rate_check(da, buffer_length);
}

static int castle_object_data_write(struct castle_object_replace *replace)
{
    c2_block_t *data_c2b;
    uint64_t data_c2b_offset, data_c2b_length, data_length, packet_length;
    int c2b_locked = 0;

    /* Work out how much data we've got, and how far we've got so far */
    data_c2b = replace->data_c2b;
    data_c2b_offset = replace->data_c2b_offset;
    data_length = replace->data_length;

    debug("Data write. replace=%p, data_c2b=%p, data_c2b_offset=%d, data_length=%d\n",
        replace, data_c2b, data_c2b_offset, data_length);
    data_c2b_length = data_c2b->nr_pages * C_BLK_SIZE;
    packet_length = replace->data_length_get(replace);

    debug("Packet length=%d, data_length=%d\n", packet_length, data_length);

    if (((int64_t)packet_length < 0) || (packet_length > replace->value_len))
    {
        castle_printk(LOG_ERROR, "Unexpected Packet length=%llu, data_length=%llu\n",
                packet_length, data_length);
        BUG();
    }

    do {
        char *data_c2b_buffer;
        int copy_length;
        int last_copy;

        BUG_ON(data_c2b_offset >= data_c2b_length);
        data_c2b_buffer = (char *)c2b_buffer(data_c2b) + data_c2b_offset;
        copy_length = data_c2b_length - data_c2b_offset >= packet_length ?
                                           packet_length :
                                           data_c2b_length - data_c2b_offset;
        debug("Could copy %d bytes.\n", copy_length);
        last_copy = 0;
        if(copy_length >= data_length)
        {
            debug("data_length=%d is smaller than copy_length=%d, resetting copy_length.\n",
                    data_length, copy_length);
            last_copy = 1;
            copy_length = data_length;
        }
        if (copy_length < 0 || copy_length > (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE))
        {
            castle_printk(LOG_ERROR, "Unexpected copy_length %d\n", copy_length);
            BUG();
        }

        write_lock_c2b(data_c2b);
        update_c2b(data_c2b);
        c2b_locked = 1;

        castle_object_replace_data_copy(replace, data_c2b_buffer, copy_length,
                                        last_copy ? 0 : 1);

        data_length     -= copy_length;
        data_c2b_offset += copy_length;
        packet_length   -= copy_length;
        debug("Read %d bytes from the packet.\n", copy_length);


        /* Allocate a new buffer if there will be more data (either in the current
           packet, or in future packets). */
        if((data_c2b_offset == data_c2b_length) && (data_length > 0))
        {
            c2_block_t *new_data_c2b;
            c_ext_pos_t new_data_cep;
            debug("Run out of buffer space, allocating a new one.\n");
            new_data_cep = castle_object_write_next_cep(data_c2b->cep, data_c2b_length);
            if (EXT_POS_COMP(new_data_cep, data_c2b->cep) <= 0)
            {
                castle_printk(LOG_ERROR, "Unexpected change in CEP while copy"cep_fmt_str
                        cep_fmt_str_nl, cep2str(data_c2b->cep), cep2str(new_data_cep));
                BUG();
            }
            new_data_c2b = castle_object_write_buffer_alloc(new_data_cep, data_length);
            data_c2b_length = new_data_c2b->nr_pages * C_BLK_SIZE;
            data_c2b_offset = 0;
            /* Release the (old) buffer */
            dirty_c2b(data_c2b);
            write_unlock_c2b(data_c2b);
            put_c2b(data_c2b);
            c2b_locked = 0;
            /* Swap the new buffer in, if one was initialised. */
            data_c2b = new_data_c2b;
        }
    }
    while((packet_length > 0) && (data_length > 0));

    debug("Exiting data_write with data_c2b_offset=%d, data_length=%d, data_c2b=%p\n",
            data_c2b_offset, data_length, data_c2b);

    /* Release the locks on c2b. */
    if (c2b_locked)
    {
        dirty_c2b(data_c2b);
        write_unlock_c2b(data_c2b);
    }

    replace->data_c2b = data_c2b;
    replace->data_c2b_offset = data_c2b_offset;
    replace->data_length = data_length;

    return (data_length == 0);
}

/**
 * Frees up the large object specified by the CVT provided to this function.
 * It deals with accounting, large object refcounting and extent freeing (the last two
 * indirectly through the DA code).
 */
static void castle_object_replace_large_object_free(struct castle_component_tree *ct,
                                                    c_val_tup_t cvt)
{
    uint64_t chk_cnt;

    BUG_ON(!CVT_LARGE_OBJECT(cvt));
    /* Update the large object chunk count on the tree */
    chk_cnt = castle_extent_size_get(cvt.cep.ext_id);
    atomic64_sub(chk_cnt, &ct->large_ext_chk_cnt);
    debug("Freeing Large Object of size - %u\n", chk_cnt);
    castle_ct_large_obj_remove(cvt.cep.ext_id,
                               &ct->large_objs,
                               &ct->lo_mutex);
}

/**
 * Wraps up object replace operation after either:
 * - btree insertion was completed
 * - there was an error allocating space for the value/btree
 * - the replace was cancelled
 *
 * Specifically this function is responsible for storing the last key (if that was requested),
 * freeing the btree key structure, freeing up large object extents on errors, freeing up the
 * BIO structure and releasing the reference on CT.
 *
 * It calls back to the user, unless the replace operation was cancelled by the user (in which
 * case it already knows).
 */
static void castle_object_replace_complete(struct castle_bio_vec *c_bvec,
                                           int err,
                                           c_val_tup_t cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    c_bio_t *c_bio = c_bvec->c_bio;
    struct castle_component_tree *ct = c_bvec->tree;
    int cancelled;

    /* This function is used to cleanup when cancelling a request, with err set to -EPIPE. */
    cancelled = (err == -EPIPE);

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);
    BUG_ON(replace->data_c2b);
    BUG_ON(!err && memcmp(&replace->cvt, &cvt, sizeof(c_val_tup_t)));
    BUG_ON((c_bvec->cvt_get == NULL) && err);

    debug("castle_object_replace_complete\n");

    if (err == -EEXIST)
        debug(LOG_WARN, "Failed to insert into btree (timestamp violation).\n");

    /* If there was an error inserting on large objects, free the extent.
       Since there was an error, the object hasn't been threaded onto large object list yet.
       There is no need to remove it from there, or to change any accounting. */
    if (err && CVT_LARGE_OBJECT(replace->cvt))
        castle_extent_free(replace->cvt.cep.ext_id);

    /* Release kmalloced memory for inline objects. */
    CVT_INLINE_FREE(replace->cvt);

    /* Unreserve any space we may still hold in the CT. Drop the CT ref. */
    if (ct)
    {
        castle_double_array_unreserve(c_bvec);
        castle_ct_put(ct, WRITE /*rw*/);
    }
    BUG_ON(atomic_read(&c_bvec->reserv_nodes) != 0);

    /* Free the packed key and the bio. */
    castle_object_bvec_attach_key_dealloc(c_bvec);
    castle_utils_bio_free(c_bio);

    /* Tell the client everything is finished. */
    if (!cancelled)
        replace->complete(replace, err);
}

/**
 * Wrapper for @see castle_object_replace_complete(), called after
 * @see castle_double_array_submit(), responsible for deregistering BIOs from the
 * internal debugger.
 */
static void castle_object_da_replace_complete(struct castle_bio_vec *c_bvec,
                                              int err,
                                              c_val_tup_t cvt)
{
    /* Deregister the BIO. */
    castle_debug_bio_deregister(c_bvec->c_bio);
    /* Call the actual complete function. */
    castle_object_replace_complete(c_bvec, err, cvt);
}

/**
 * Schedules the DA key insertion.
 */
static void castle_object_replace_key_insert(struct castle_object_replace *replace)
{
    c_bvec_t *c_bvec = replace->c_bvec;

    FAULT(REPLACE_FAULT);

    /* Register with the debugger. */
    castle_debug_bio_register(c_bvec->c_bio, c_bvec->c_bio->attachment->version, 1);
    /* Set the callback. */
    c_bvec->submit_complete = castle_object_da_replace_complete;
    /* Submit to the DA. */
    BUG_ON(replace->data_c2b);
    castle_double_array_submit(c_bvec);
}

int castle_object_replace_continue(struct castle_object_replace *replace)
{
    int copy_end;

    FAULT(REPLACE_FAULT);

    debug("Replace continue.\n");
    copy_end = castle_object_data_write(replace);
    if(copy_end)
    {
        c2_block_t *data_c2b = replace->data_c2b;
        uint32_t data_length = replace->data_length;

        BUG_ON(data_length != 0);
        put_c2b(data_c2b);
        replace->data_c2b = NULL;

        /* Finished writing the data out, insert the key into the btree. */
        castle_object_replace_key_insert(replace);
        return 0;
    }

    /* If the data writeout isn't finished, notify the client. */
    replace->replace_continue(replace);

    return 0;
}

int castle_object_replace_cancel(struct castle_object_replace *replace)
{
    debug("Replace cancel.\n");

    /* Release the data c2b. */
    put_c2b(replace->data_c2b);
    replace->data_c2b = NULL;

    /* Btree reservation is going to be released by replace_complete().
       No need to release medium object extent, because we allocated space from it
      (haven't used it, but its too late to free it). */

    /* The rest of the cleanup will be done by: */
    castle_object_replace_complete(replace->c_bvec, -EPIPE, replace->cvt);

    return 0;
}

/**
 * Start up an on disk (medium/large) object replace.
 *
 * It initialises the c_bvec->data_c2b, and calls the functions handling data write.
 * If all the data is already available, it will clean up the data_c2b too (release the c2b
 * reference, and set the field to NULL).
 */
static void castle_object_replace_on_disk_start(struct castle_object_replace *replace)
{
    c2_block_t *c2b;
    c_val_tup_t cvt;

    cvt = replace->cvt;
    BUG_ON(!CVT_ON_DISK(cvt));
    BUG_ON(replace->value_len != cvt.length);

    /* Init the c2b for data writeout. */
    c2b = castle_object_write_buffer_alloc(cvt.cep, cvt.length);
    replace->data_c2b = c2b;
    replace->data_c2b_offset = 0;
    replace->data_length = cvt.length;

    if (replace->data_length_get(replace) > 0)
    {
        int complete_write;

        complete_write = castle_object_data_write(replace);
        BUG_ON(complete_write && (replace->data_length != 0));
        if(complete_write)
        {
            put_c2b(replace->data_c2b);
            replace->data_c2b = NULL;
        }
    }
}

/**
 * Returns the CVT for the object being inserted and does the appropriate bookkeeping
 * (by registering large objects with the DA code, and updating the chunk counter on
 * the component tree). Also, it frees up and cleans up after large objects that used
 * to be stored under the same key.
 */
static int castle_object_replace_cvt_get(c_bvec_t    *c_bvec,
                                         c_val_tup_t prev_cvt,
                                         c_val_tup_t ancestral_cvt,
                                         c_val_tup_t *cvt)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    uint64_t nr_chunks;
    castle_user_timestamp_t existing_object_user_timestamp = 0;
    c_val_tup_t *new_cvt = &replace->cvt;

    /* We should be handling a write (possibly a tombstone write). */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE);
    /* Some sanity checks on the prev_cvt. */
    BUG_ON(!CVT_INVALID(prev_cvt) && !CVT_LEAF_VAL(prev_cvt));
    BUG_ON(CVT_TOMBSTONE(prev_cvt) && (prev_cvt.length != 0));

    /* Check if this insert should be disabled immediately because of it's timestamp vs
       other entries in the T0. */

    if(!CVT_INVALID(prev_cvt))
        existing_object_user_timestamp = prev_cvt.user_timestamp;
    if(!CVT_INVALID(ancestral_cvt))
        existing_object_user_timestamp = ancestral_cvt.user_timestamp;

    debug("%s::existing timestamp: %llu, new timestamp: %llu\n",
        __FUNCTION__, existing_object_user_timestamp, replace->user_timestamp);
    if(existing_object_user_timestamp > replace->user_timestamp)
    {
        *cvt = INVAL_VAL_TUP;
        atomic64_inc(&c_bvec->tree->da->stats.user_timestamps.t0_discards);
        debug("%s::dropping an insert (of cvt type %d) because it's timestamp (%llu) "
                "is \"older\" than the timestamp of an existing entry (%llu).\n",
                __FUNCTION__, new_cvt->type, replace->user_timestamp, existing_object_user_timestamp);
        return -EEXIST; /* existential crisis */
    }
    /* this object passed the timestamp smell test...proceed with replace. */
    new_cvt->user_timestamp = replace->user_timestamp;

    /* Bookkeeping for large objects (about to be inserted into the tree). */
    if(CVT_LARGE_OBJECT(*new_cvt))
    {
        if (castle_ct_large_obj_add(new_cvt->cep.ext_id,
                                    replace->value_len,
                                    &c_bvec->tree->large_objs,
                                    &c_bvec->tree->lo_mutex))
        {
            castle_printk(LOG_WARN, "Failed to intialize large object\n");
            return -ENOMEM;
        }

        /* Update the large object chunk count on the tree */
        nr_chunks = (replace->value_len - 1) / C_CHK_SIZE + 1;
        atomic64_add(nr_chunks, &c_bvec->tree->large_ext_chk_cnt);
    }

    /* For counter add operation (which uses ACCUM_ADD_ADD cvt type). Reduce with
       either the previous entry or ancestral entry if either exists. */
    if(CVT_COUNTER_ACCUM_ADD_ADD(*new_cvt))
    {
        if(!CVT_INVALID(prev_cvt))
            castle_counter_accumulating_reduce(new_cvt, prev_cvt, 0);
        else
        if(!CVT_INVALID(ancestral_cvt))
            castle_counter_accumulating_reduce(new_cvt, ancestral_cvt, 1);
    }

    /* Free the space occupied by large object, if prev_cvt points to a large object. */
    if(CVT_LARGE_OBJECT(prev_cvt))
        castle_object_replace_large_object_free(c_bvec->tree, prev_cvt);

    /* Set cvt_get to NULL, to tell the replace_complete function that cvt_get was done
       successfully */
    c_bvec->cvt_get = NULL;
    /* Finally set the cvt. */
    *cvt = *new_cvt;

    /* Update stats. */

    /* Add new entry to stats. */
    castle_tree_size_stats_update(c_bvec->key, new_cvt, c_bvec->tree, 1 /* Add */);

    /* Deduct old entry from stats. No need to deduct key length. */
    if (!CVT_INVALID(prev_cvt))
        castle_tree_size_stats_update(c_bvec->key, &prev_cvt, c_bvec->tree, -1 /* Deduct */);

    /* Deduct length of previous medium sized value from tree-size. */
    if (CVT_MEDIUM_OBJECT(prev_cvt))
        castle_data_extent_update(prev_cvt.cep.ext_id,
                                  NR_BLOCKS(prev_cvt.length) * C_BLK_SIZE, -1);

    /* Add length of new medium sized value to tree-size. */
    if (CVT_MEDIUM_OBJECT(*new_cvt))
        castle_data_extent_update(new_cvt->cep.ext_id,
                                  NR_BLOCKS(new_cvt->length) * C_BLK_SIZE, 1);

    /* Inc counter for per-DA tombstone discard stats. */
    if (CVT_TOMBSTONE(*new_cvt))
    {
        struct castle_double_array *da = c_bvec->tree->da;
        BUG_ON(!da);
        atomic64_inc(&da->stats.tombstone_discard.tombstone_inserts);
    }
    FAULT(REPLACE_FAULT);

    return 0;
}

/**
 * Reserves memory for inline objects, extent space in medium object extent, or a brand new
 * extent for large objects. It sets the CVT.
 *
 * For inline objects, the data is copied into memory allocated too.
 *
 * This function may fail in variety of ways in which case an appropriate code will be
 * returned, replace->cvt will be set to INVAL_VAL_TUP in such case.
 */
static int castle_object_replace_space_reserve(struct castle_object_replace *replace)
{
    c_bvec_t *c_bvec = replace->c_bvec;
    int tombstone = c_bvec_data_del(c_bvec);
    uint64_t value_len, nr_blocks, nr_chunks;
    c_ext_pos_t cep;

    replace->cvt = INVAL_VAL_TUP;
    /* Deal with tombstones first. */
    if(tombstone)
    {
        CVT_TOMBSTONE_INIT(replace->cvt);
        /* No need to allocate any memory/extent space for tombstones. */
        return 0;
    }

    value_len = replace->value_len;
    /* Reserve memory for inline values. */
    if(value_len <= MAX_INLINE_VAL_SIZE)
    {
        void *value;
        int counter;

        counter = (replace->counter_type != CASTLE_OBJECT_NOT_COUNTER);
        BUG_ON(counter && (value_len != 8));
        /* Allocate memory. 16 bytes for accumulating counter. */
        value = castle_alloc(counter ? 16 : value_len);
        if(!value)
            return -ENOMEM;

        /* Construct the cvt. */
        if(replace->has_user_timestamp)
        {
            if(unlikely(replace->counter_type == CASTLE_OBJECT_COUNTER_SET) ||
                (replace->counter_type == CASTLE_OBJECT_COUNTER_SET))
            {
                castle_free(value);
                castle_printk(LOG_ERROR, "%s::counters cannot be timestamped... we don't even provide an interface to do it, so what's going on?!?\n", __FUNCTION__);
                WARN_ON(1);
                return -EINVAL;
            }
        }
        if(unlikely(replace->counter_type == CASTLE_OBJECT_COUNTER_SET))
        {
            CVT_COUNTER_ACCUM_SET_SET_INIT(replace->cvt, 16, value);
        }
        else if(replace->counter_type == CASTLE_OBJECT_COUNTER_ADD)
        {
            CVT_COUNTER_ACCUM_ADD_ADD_INIT(replace->cvt, 16, value);
        }
        else
            {CVT_INLINE_INIT(replace->cvt, value_len, value);}
        /* Get the data copied into the cvt. It should all be available in one shot. */
        BUG_ON(replace->data_length_get(replace) < value_len);
        castle_object_replace_data_copy(replace, value, value_len, 0 /* not partial */);
        /* If we are handling a counter, accumulating sub-counter needs to be the same
           as the non-accumulating sub-counter. */
        if(counter)
            memcpy(value + 8, value, 8);

        return 0;
    }

    BUG_ON(replace->counter_type != CASTLE_OBJECT_NOT_COUNTER); /* counters must be inline */

    /* Out of line objects. */
    nr_blocks = (value_len - 1) / C_BLK_SIZE + 1;
    nr_chunks = (value_len - 1) / C_CHK_SIZE + 1;
    /* Medium objects. */
    if(value_len <= MEDIUM_OBJECT_LIMIT)
    {
        /* Allocate space in the medium object extent. This has already been preallocated
           therefore the allocation should always succeed. */
        BUG_ON(castle_ext_freespace_get(&c_bvec->tree->data_ext_free,
                                         nr_blocks * C_BLK_SIZE,
                                         1,
                                        &cep) < 0);
        CVT_MEDIUM_OBJECT_INIT(replace->cvt, value_len, cep);
        debug("Medium Object in %p, cep: "cep_fmt_str_nl, c_bvec->tree, __cep2str(cvt->cep));

        return 0;
    }

    /* Large objects. */
    memset(&cep, 0, sizeof(c_ext_pos_t));
    cep.ext_id = castle_extent_alloc(castle_get_rda_lvl(),
                                     c_bvec->tree->da->id,
                                     EXT_T_LARGE_OBJECT,
                                     nr_chunks, 0,  /* Not in transaction. */
                                     NULL, NULL);

    if(EXT_ID_INVAL(cep.ext_id))
    {
        castle_printk(LOG_WARN, "Failed to allocate space for Large Object.\n");
        return -ENOSPC;
    }
    CVT_LARGE_OBJECT_INIT(replace->cvt, value_len, cep);

    return 0;
}

/**
 * Callback used after the request went through the DA throttling, and btree/medium
 * object extent space has been reserved.
 *
 * This function allocates memory/extent space, and starts the write.
 *
 * If the write is completed in one shot it schedules the key insert. If not, it notifies
 * the client and exits.
 */
static void castle_object_replace_queue_complete(struct castle_bio_vec *c_bvec, int err)
{
    struct castle_object_replace *replace = c_bvec->c_bio->replace;
    int write_complete;

    /* Handle the error case first. Notify the client, and exit. */
    if(err)
    {
        /* If we failed to queue, there should be no CT set, and no CVT. */
        BUG_ON(c_bvec->tree);
        BUG_ON(!CVT_INVALID(replace->cvt));
        goto err_out;
    }
    /* Otherwise the CT should be set. */
    BUG_ON(!c_bvec->tree);

    /* Reserve space (memory or extent space) to store the value. */
    err = castle_object_replace_space_reserve(replace);
    if(err)
    {
        BUG_ON(!CVT_INVALID(replace->cvt));
        goto err_out;
    }

    /*
     * For on disk objects, kick off the write-out (inline objects/tombstones have already been
     * dealt with by now).
     * If the entire value gets written out (which is trivially true for inline values/tombstones)
     * insert the key into the btree.
     */
    write_complete = 1;
    if(CVT_ON_DISK(replace->cvt))
    {
        castle_object_replace_on_disk_start(replace);
        write_complete = (replace->data_length == 0);
    }

    if(write_complete)
        castle_object_replace_key_insert(replace);
    else
        /* If the data writeout isn't finished, notify the client. */
        replace->replace_continue(replace);

    return;

err_out:
    BUG_ON(err == 0);
    /* This cleans everything up, including the CT ref. */
    castle_object_replace_complete(c_bvec, err, replace->cvt);
}

/**
 * Starts object replace.
 * It allocates memory for the BIO and btree key, sets up the requests, and submits the
 * request to the queue. The request may go straight through and be handled on the
 * current thread, but otherwise will be queued up in the DA, and handled asynchronously later.
 */
int castle_object_replace(struct castle_object_replace *replace,
                          struct castle_attachment *attachment,
                          int cpu_index,
                          int tombstone)
{
    struct castle_btree_type *btree;
    void *key;
    c_bio_t *c_bio;
    c_bvec_t *c_bvec;
    int ret;

    if(replace->has_user_timestamp)
        debug("%s::user provided timestamp %llu\n", __FUNCTION__, replace->user_timestamp);
    else
    {
        /* Further work: If we decide to use suspicion tags, then here we need to infer the
                         implicit timestamp of this non-timestamped entry from user_timestamp
                         state that we would be maintaining on the version tree - to be precise,
                         instead of 0, we would use v->creation_user_ts. */
        replace->user_timestamp = 0;
    }


    /* Sanity checks. */
    BUG_ON(!attachment);

    /*
     * Make sure that the filesystem has been fully initialised before accepting any requests.
     * @TODO consider moving this check to castle_back_open().
     */
    if (!castle_fs_inited)
        return -ENODEV;

    /* Create the packed key out of the backend key. */
    btree = castle_double_array_btree_type_get(attachment);
    key = btree->key_pack(replace->key, NULL, NULL);
    if (!key)
        return -ENOMEM;

    /* Allocate castle bio with a single bvec. */
    ret = -ENOMEM;
    c_bio = castle_utils_bio_alloc(1);
    if (!c_bio)
        goto err0;

    /* Initialise the bio. */
    c_bio->attachment    = attachment;
    c_bio->replace       = replace;
    c_bio->data_dir      = WRITE;
    if (tombstone)
        c_bio->data_dir |= REMOVE;

    /* Initialise the bvec. */
    c_bvec = c_bio->c_bvecs;
    c_bvec->key            = key;
    c_bvec->tree           = NULL;
    c_bvec->cpu_index      = cpu_index;
    c_bvec->cpu            = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->cvt_get        = castle_object_replace_cvt_get;
    c_bvec->queue_complete = castle_object_replace_queue_complete;
    c_bvec->orig_complete  = NULL;
    atomic_set(&c_bvec->reserv_nodes, 0);

    /* Save c_bvec in the replace. */
    replace->c_bvec = c_bvec;
    CVT_INVALID_INIT(replace->cvt);
    replace->data_c2b = NULL;

    /* Queue up in the DA. */
    castle_double_array_queue(c_bvec);
    return 0;

err0:
    btree->key_dealloc(key);
    return ret;
}
EXPORT_SYMBOL(castle_object_replace);

void castle_object_slice_get_end_io(void *obj_iter, int err);

/**
 * Asynchronous callback handler for castle_objects_rq_iter_init().
 *
 * Calls asynchronous callback passed to castle_object_iter_init().
 *
 * @also castle_objects_rq_iter_init()
 * @also castle_object_iter_init()
 */
void _castle_object_iter_init(castle_object_iterator_t *iterator)
{
    castle_object_iter_start_cb_t start_cb = iterator->start_cb;
    void *start_private = iterator->start_private;
    int err = iterator->err;

    if (err)
    {
        iterator->btree->key_dealloc(iterator->end_key);
        iterator->btree->key_dealloc(iterator->start_key);
        castle_free(iterator);
    }
    else
        castle_objects_rq_iter_register_cb(iterator,
                                           castle_object_slice_get_end_io,
                                           NULL);

    debug_rq("rq_iter_init done, err=%d\n", err);
    start_cb(start_private, err);
}

/**
 * Initialise a range query.
 *
 * @param   seq_id      Unique ID for tracing purposes
 * @param   start_cb    Callback in the event we go asynchronous
 * @param   private     Caller-provided data passed to start_cb()
 *
 * If we are able to allocate all necessary structures and caller-provided keys
 * are valid we call into castle_objects_rq_iter_init() which handles the
 * initialisation of the DA range query iterator - the initialisation has now
 * gone asynchronous and the caller should wait for their callback to fire,
 * this happens from our own callback, _castle_object_iter_init().
 *
 * @return  0       Initialisation went asynchronous
 * @return -EINVAL  Invalid start and/or end key
 * @return -ENOMEM  Failed to allocate memory for initialisation
 *
 * @also castle_objects_rq_iter_init()
 * @also _castle_object_iter_init()
 */
int castle_object_iter_init(struct castle_attachment *attachment,
                             c_vl_bkey_t *start_key,
                             c_vl_bkey_t *end_key,
                             castle_object_iterator_t **iter,
                             int seq_id,
                             castle_object_iter_start_cb_t start_cb,
                             void *private)
{
    castle_object_iterator_t *iterator;
    int i, ret;

    BUG_ON(!start_cb || !private);

    /* Checks on keys. */
    if (start_key->nr_dims != end_key->nr_dims)
    {
        castle_printk(LOG_WARN, "Range query with different # of dimensions.\n");
        return -EINVAL;
    }

    /* Empty dimensions on start_key are allowed only if it is -ve infinity. */
    for (i = 0; i < start_key->nr_dims; i++)
        if (castle_object_btree_key_dim_length(start_key, i) == 0 &&
            !(castle_object_btree_key_dim_flags_get(start_key, i) & KEY_DIMENSION_MINUS_INFINITY_FLAG))
            return -EINVAL;

    /* Empty dimensions on end_key are allowed only if it is +ve infinity. */
    for (i = 0; i < end_key->nr_dims; i++)
        if (castle_object_btree_key_dim_length(end_key, i) == 0 &&
            !(castle_object_btree_key_dim_flags_get(end_key, i) & KEY_DIMENSION_PLUS_INFINITY_FLAG))
            return -EINVAL;

    iterator = castle_zalloc(sizeof(castle_object_iterator_t));
    if (!iterator)
        return -ENOMEM;
    *iter = iterator;

    /* Create the packed keys out of the backend keys. */
    ret = -ENOMEM;
    iterator->btree = castle_double_array_btree_type_get(attachment);
    iterator->start_key = iterator->btree->key_pack(start_key, NULL, NULL);
    if (!iterator->start_key)
        goto err0;
    iterator->end_key = iterator->btree->key_pack(end_key, NULL, NULL);
    if (!iterator->end_key)
        goto err1;

    /* Initialise the rest of the iterator */
    iterator->seq_id        = seq_id;
    iterator->version       = attachment->version;
    iterator->da_id         = castle_version_da_id_get(iterator->version);
    iterator->start_cb      = start_cb;
    iterator->start_private = private;

    debug_rq("rq_iter_init.\n");
    castle_objects_rq_iter_init(iterator, _castle_object_iter_init);

    /* Init completes asynchronously in _castle_object_iter_init(). */

    return 0;

err1: iterator->btree->key_dealloc(iterator->start_key);
err0: castle_free(iterator);
    return ret;
}

int castle_object_iter_next(castle_object_iterator_t *iterator,
                            castle_object_iter_next_available_t callback,
                            void *data)
{
    c_vl_bkey_t *key;
    void *k;
    c_val_tup_t val;
    c_ver_t v;
    int continue_iterator = 1;

    iterator->next_available = callback;
    iterator->next_available_data = data;

    while (continue_iterator)
    {
        if (castle_objects_rq_iter.prep_next(iterator) == 0)
        {
            /* We're waiting for the iterator */
            debug_rq("Waiting for next available.\n");
            return 0;
        }
        else if (castle_objects_rq_iter.has_next(iterator) == 0)
        {
            /* Iterator has no further values to return. */
            debug_rq("Iterator at end.\n");
            debug_rq("Calling next available callback with NULL key.\n");
            continue_iterator = callback(iterator, NULL, NULL, 0, iterator->next_available_data);
        }
        else
        {
            /* Iterator ready to return another value. */
            debug_rq("Getting an entry for the range query.\n");
            castle_objects_rq_iter.next(iterator, &k, &v, &val);
            debug_rq("Got an entry for the range query.\n");

            if (!k || !(key = iterator->btree->key_unpack(k, NULL, NULL)))
            {
                callback(iterator, NULL, NULL, -ENOMEM, iterator->next_available_data);
                return 0;
            }

            debug_rq("Calling next available callback with key=%p.\n", key);
            continue_iterator = callback(iterator, key, &val, 0, iterator->next_available_data);
            castle_free(key);
        }

        debug_rq("Next available callback gave response %d.\n", continue_iterator);
    }

    return 0;
}

int castle_object_iter_finish(castle_object_iterator_t *iterator)
{
    castle_objects_rq_iter_cancel(iterator);
    debug_rq("Freeing iterators & buffers.\n");
    iterator->btree->key_dealloc(iterator->end_key);
    iterator->btree->key_dealloc(iterator->start_key);
    castle_free(iterator);

    return 0;
}

static void castle_object_next_available(castle_object_iterator_t *iter)
{
    castle_object_iter_next(iter, iter->next_available, iter->next_available_data);
}
DEFINE_WQ_TRACE_FN(castle_object_next_available, castle_object_iterator_t);

void castle_object_slice_get_end_io(void *obj_iter, int err)
{
    castle_object_iterator_t *iter = obj_iter;

    BUG_ON(!castle_objects_rq_iter_prep_next(iter));
    debug_rq("Done async key read: Re-scheduling slice_get()- iterator: %p\n", iter);
    CASTLE_INIT_WORK_AND_TRACE(&iter->work, castle_object_next_available, iter);
    queue_work(castle_wq, &iter->work);
}

static void castle_object_value_acquire(c_val_tup_t *cvt)
{
    if (CVT_INLINE(*cvt) && !CVT_ANY_COUNTER(*cvt))
    {
        char *buf = castle_alloc(cvt->length);
        memcpy(buf, CVT_INLINE_VAL_PTR(*cvt), cvt->length);
        cvt->val_p = buf;
    }

    /* We know LOs don't resize dynamically. It is safe to get a link, instead of a
     * reference, which would require us to store the reference ID (extent mask ID). */
    /* Note: Might need to revisit this code with unknown Big-object implementation. */
    else if (CVT_LARGE_OBJECT(*cvt))
        BUG_ON(castle_extent_link(cvt->cep.ext_id));
}

static void castle_object_value_release(c_val_tup_t *cvt)
{
    if (CVT_INLINE(*cvt) && !CVT_ANY_COUNTER(*cvt))
    {
        CVT_INLINE_FREE(*cvt);
    }

    else if (CVT_LARGE_OBJECT(*cvt))
        castle_extent_unlink(cvt->cep.ext_id);
}

void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_object_get *get,
                                c_ext_pos_t  data_cep,
                                uint64_t data_length);

static void __castle_object_get_complete(c_bvec_t *c_bvec)
{
    struct castle_object_get *get = c_bvec->c_bio->get;
    c2_block_t *c2b = get->data_c2b;
    c_ext_pos_t cep;
    uint64_t data_c2b_length = get->data_c2b_length;
    uint64_t data_length = get->data_length;
    int first = get->first;
    int last, dont_want_more;
    c_val_tup_t cvt = get->cvt;

    /* Deal with error case first */
    if (!c2b_uptodate(c2b))
    {
        debug("Not up to date.\n");
        if (first)
            get->reply_start(get, -EIO, 0, NULL, 0);
        else
            get->reply_continue(get, -EIO, NULL, 0, 1 /* last */);
        goto out;
    }

    /* If data_length is zero, it means we are supposed to finish this get call */
    last = (data_length == 0);
    debug("Last=%d\n", last);
    read_lock_c2b(c2b);
    if (first)
        dont_want_more = get->reply_start(get,
                                          0,
                                          data_c2b_length + data_length,
                                          c2b_buffer(c2b),
                                          data_c2b_length);
    else
        dont_want_more = get->reply_continue(get,
                                             0,
                                             c2b_buffer(c2b),
                                             data_c2b_length,
                                             last);
    read_unlock_c2b(c2b);

    /* Safe to access to tree structure, we still got the reference. Accessing DA from attachment,
     * seems expensive. */
    atomic64_add(data_c2b_length, &c_bvec->cts_proxy->da->read_data_bytes);

    if (last || dont_want_more)
        goto out;

    BUG_ON(data_c2b_length != OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE);
    cep.ext_id = c2b->cep.ext_id;
    cep.offset = c2b->cep.offset + (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE);
    debug("Continuing for cep="cep_fmt_str_nl, cep2str(cep));

    /* @TODO: how much of this is a no-op from above? */
    get->data_c2b        = c2b;
    get->data_c2b_length = data_c2b_length;
    get->data_length     = data_length;
    get->first           = 0; /* not first any more */

    castle_object_get_continue(c_bvec,
                               get,
                               cep,
                               data_length);
    return;

out:
    debug("Finishing with get %p, putting c2b->cep="cep_fmt_str_nl,
        get, cep2str(c2b->cep));
    put_c2b(c2b);

    /* free the key via the proxy btree_type */
    castle_object_bvec_proxy_key_dealloc(c_bvec);
    castle_da_cts_proxy_put(c_bvec->cts_proxy); /* castle_da_ct_read_complete() */
    castle_object_value_release(&cvt);
    castle_utils_bio_free(c_bvec->c_bio);
}
DEFINE_WQ_TRACE_FN(__castle_object_get_complete, c_bvec_t);

void castle_object_get_io_end(c2_block_t *c2b, int did_io)
{
    c_bvec_t *c_bvec = c2b->private;

#ifdef CASTLE_DEBUG
    struct castle_object_get *get = c_bvec->c_bio->get;
    c2_block_t *data_c2b = get->data_c2b;
    BUG_ON(c2b != data_c2b);
#endif
    write_unlock_c2b(c2b);
    /* @TODO: io error handling. */

    if (did_io)
        debug("IO end for cep "cep_fmt_str_nl, cep2str(c2b->cep));

    /* Requeue regardless of did_io as castle_object_get() is recursive. */
    CASTLE_INIT_WORK_AND_TRACE(&c_bvec->work, __castle_object_get_complete, c_bvec);
    queue_work(castle_wq, &c_bvec->work);
}

/**
 * Continue object get by reading in out-of-line values.
 *
 * @also castle_object_get_complete()
 */
void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_object_get *get,
                                c_ext_pos_t  data_cep,
                                uint64_t data_length)
{
    c2_block_t *c2b;
    int nr_blocks;

    c2_block_t *old_c2b = get->data_c2b;
    uint64_t data_c2b_length = get->data_c2b_length;
    uint64_t old_data_length = get->data_length;

    BUG_ON(c_bvec->c_bio->get != get);

    debug("get_continue for get=%p, data_c2b_length=%d, "
           "old_data_length=%d, data_length=%d, first=%d\n",
        get, data_c2b_length, old_data_length, data_length, get->first);
    BUG_ON(data_length != old_data_length);
    /* If old_c2b exists, we must have completed a MAX chunk */
    BUG_ON( old_c2b &&
           (old_c2b->cep.ext_id != data_cep.ext_id) &&
           (old_c2b->cep.offset + (OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE) != data_cep.offset));

    /* Work out if we can read the (remaining part of the) object in full,
       or if we are going to be reading just a part of it */
    if(data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE)
    {
        nr_blocks = OBJ_IO_MAX_BUFFER_SIZE;
        data_c2b_length = nr_blocks * C_BLK_SIZE;
        debug("Too many blocks required, reducing to %d\n", nr_blocks);
    } else
    {
        nr_blocks = (data_length - 1) / C_BLK_SIZE + 1;
        data_c2b_length = data_length;
    }
    debug("Nr blocks this time around: %d\n", nr_blocks);
    debug("data_c2b_length=%d, data_length=%d\n", data_c2b_length, data_length);
    data_length -= data_c2b_length;

    /* Unlock the old c2b if we had one */
    if(old_c2b)
    {
        debug("Putting old_cep "cep_fmt_str_nl, cep2str(old_c2b->cep));
        put_c2b(old_c2b);
    }

    debug("Reading cep "cep_fmt_str_nl, cep2str(data_cep));
    c2b = castle_cache_block_get(data_cep, nr_blocks, USER);
    get->data_c2b        = c2b;
    get->data_c2b_length = data_c2b_length;
    get->data_length     = data_length;
    BUG_ON(castle_cache_block_read(c2b, castle_object_get_io_end, c_bvec));

    /* completes in __castle_object_get_complete(). */
}

/**
 * Get callback handler.
 *
 * Arranges an out-of-line read for medium objects.  Large objects are not
 * handled here as they would be too large to return in a single buffer.
 *
 * Called via orig_complete in castle_da_ct_read_complete().
 *
 * @also castle_da_ct_read_complete()
 */
void castle_object_get_complete(struct castle_bio_vec *c_bvec,
                                int err,
                                c_val_tup_t cvt)
{
    struct castle_object_get *get = c_bvec->c_bio->get;
    c_bio_t *c_bio = c_bvec->c_bio;

    debug("Returned from btree walk with value of type 0x%x and length 0x%llu and timestamp %llu\n",
          cvt.type, (uint64_t)cvt.length, cvt.user_timestamp);

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != READ);
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    get->cvt = cvt;

    /* Deal with error case, or non-existent value. */
    if (err || CVT_INVALID(cvt) || CVT_TOMBSTONE(cvt))
    {
        if (!err)
            castle_da_cts_proxy_put(c_bvec->cts_proxy);

        if (!err && CVT_TOMBSTONE(cvt) && (get->flags & CASTLE_RING_FLAG_RET_TOMBSTONE))
        {
            /* got a tombstone and user asked for it back */
            castle_object_bvec_attach_key_dealloc(c_bvec);
            castle_utils_bio_free(c_bvec->c_bio);
            get->reply_start(get,
                             0,
                             cvt.length,
                             CVT_TOMBSTONE_VAL_PTR(cvt),
                             cvt.length);
        }
        else
        {
            /* got (an error), or (an inval cvt), or (a tombstone and user didn't ask for it back) */
            /* Turn tombstones into invalid CVTs. */
            CVT_INVALID_INIT(get->cvt);
            castle_object_bvec_attach_key_dealloc(c_bvec);
            castle_utils_bio_free(c_bvec->c_bio);
            /* WARNING: after reply_start() its unsafe to access the attachment
               (since the ref may be dropped). Its also unsafe to bvec_attach_key_dealloc()
               since that function uses the attachment. */
            get->reply_start(get, err, 0, NULL, 0);
        }
    }

    /* Inline values and local (all) counters. */
    else if (CVT_INLINE(cvt))
    {
        atomic64_add(cvt.length, &c_bvec->cts_proxy->da->read_data_bytes);
        castle_da_cts_proxy_put(c_bvec->cts_proxy);
        castle_object_bvec_attach_key_dealloc(c_bvec);
        castle_utils_bio_free(c_bvec->c_bio);
        /* WARNING: after reply_start() its unsafe to access the attachment
           (since the ref may be dropped). Its also unsafe to bvec_attach_key_dealloc()
           since that function uses the attachment. */
        get->reply_start(get,
                         0,
                         cvt.length,
                         CVT_INLINE_VAL_PTR(cvt),
                         cvt.length);
        castle_object_value_release(&cvt);

        FAULT(GET_FAULT);
    }

    /* Out-of-line values (medium objects). */
    else
    {
#if 0
        BUG_ON(CVT_MEDIUM_OBJECT(cvt) &&
                cvt.cep.ext_id != c_bvec->tree->data_ext_free.ext_id);
#endif
        BUG_ON(!c_bvec->cts_proxy); /* da_ct_read_complete() leaves this for us */
        BUG_ON(!CVT_ON_DISK(cvt));

        /* Initialise call variables for object_get_continue(). */
        get->data_c2b        = NULL;
        get->data_c2b_length = 0;
        get->data_length     = cvt.length;
        get->first           = 1; /* first */

        castle_object_get_continue(c_bvec, get, cvt.cep, cvt.length);

        FAULT(GET_FAULT);
    }
}

/**
 * Lookup and return an object from btree.
 *
 * @param   cpu_index   CPU index (to determine correct T0 CT)
 *
 * @also castle_back_get()
 */
int castle_object_get(struct castle_object_get *get,
                      struct castle_attachment *attachment,
                      int cpu_index)
{
    struct castle_btree_type *btree;
    void *key;
    c_bio_t *c_bio;
    c_bvec_t *c_bvec;
    int ret;

    debug("castle_object_get get=%p\n", get);
    BUG_ON(!attachment);

    if (!castle_fs_inited)
        return -ENODEV;

    /* Create the packed key out of the backend key. */
    btree = castle_double_array_btree_type_get(attachment);
    key = btree->key_pack(get->key, NULL, NULL);
    if (!key)
        return -ENOMEM;

    /* Single c_bvec for the bio */
    ret = -ENOMEM;
    c_bio = castle_utils_bio_alloc(1);
    if (!c_bio)
        goto err0;

    CVT_INVALID_INIT(get->cvt);

    c_bio->attachment    = attachment;
    c_bio->get           = get;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs;
    c_bvec->key             = key;
    c_bvec->cpu_index       = cpu_index;
    c_bvec->cpu             = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->val_get         = castle_object_value_acquire;
    c_bvec->val_put         = castle_object_value_release;
    c_bvec->submit_complete = castle_object_get_complete;
    c_bvec->orig_complete   = NULL;
    c_bvec->seq_id          = atomic_inc_return(&castle_req_seq_id);

    trace_CASTLE_REQUEST_BEGIN(c_bvec->seq_id, CASTLE_RING_GET);

    /* in the beginning, we will be willing to resolve timestamps or counters, but upon
       retrieval of the first candidate return value, we will pick one or the other. */

    atomic_set(&c_bvec->reserv_nodes, 0);

    /* @TODO: add bios to the debugger! */
    castle_double_array_submit(c_bvec);

    trace_CASTLE_REQUEST_RELEASE(c_bvec->seq_id);

    return 0;

err0:
    btree->key_dealloc(key);
    return ret;
}
EXPORT_SYMBOL(castle_object_get);

/**
 * Release references held by object pull.
 *
 * @also __castle_object_chunk_pull_complete()
 * @also castle_object_pull_complete()
 * @also castle_object_chunk_pull()
 * @also castle_da_ct_read_complete()
 */
void castle_object_pull_finish(struct castle_object_pull *pull)
{
    castle_da_cts_proxy_put(pull->cts_proxy);
    castle_object_value_release(&pull->cvt);
}

void __castle_object_chunk_pull_complete(struct work_struct *work)
{
    struct castle_object_pull *pull = container_of(work, struct castle_object_pull, work);
    uint32_t to_copy = pull->to_copy;

    BUG_ON(!pull->buf);

    read_lock_c2b(pull->curr_c2b);
    memcpy(pull->buf, c2b_buffer(pull->curr_c2b), to_copy);

    /* For non-inline values we should have the proxy reference; update stats by reading DA
     * pointer from proxy ref. */
    atomic64_add(to_copy, &pull->cts_proxy->da->read_data_bytes);

    pull->offset += to_copy;
    pull->remaining -= to_copy;

    debug("Unlocking old_cdb (0x%x, 0x%x)\n", pull->curr_c2b->cdb.disk, pull->curr_c2b->cdb.block);
    read_unlock_c2b(pull->curr_c2b);
    put_c2b(pull->curr_c2b);

    pull->curr_c2b = NULL;
    pull->buf = NULL;
    pull->to_copy = 0;

    pull->pull_continue(pull, 0 /*err*/, to_copy, pull->remaining == 0 /*done*/);
}

void castle_object_chunk_pull_io_end(c2_block_t *c2b, int did_io)
{
    struct castle_object_pull *pull = c2b->private;

    debug("IO end for cdb, c2b->nr_pages=%d, cep" cep_fmt_str_nl, c2b->nr_pages, cep2str(c2b->cep));
    write_unlock_c2b(pull->curr_c2b);

    /* @TODO deal with not up to date - get error and pass it on? */

    if (did_io)
    {
        CASTLE_INIT_WORK(&pull->work, __castle_object_chunk_pull_complete);
        queue_work(castle_wq, &pull->work);
    }
    else
        __castle_object_chunk_pull_complete(&pull->work);
}

/**
 * Copy buf_len's worth of pull->cvt into userland buf.
 *
 * @also castle_back_big_get_do_chunk()
 */
void castle_object_chunk_pull(struct castle_object_pull *pull, void *buf, size_t buf_len)
{
    /* @TODO currently relies on objects being page aligned. */
    c_ext_pos_t cep;

    if(!castle_fs_inited)
        return;

    BUG_ON(buf_len % PAGE_SIZE);
    BUG_ON(pull->curr_c2b != NULL);
    BUG_ON(pull->buf != NULL);

    pull->to_copy = min(pull->remaining, (uint64_t)buf_len);

    BUG_ON(pull->to_copy == 0);

    /* Handle inline values. */
    if (CVT_INLINE(pull->cvt))
    {
        atomic64_add(pull->cvt.length, &pull->cts_proxy->da->read_data_bytes);
        /* this is assured since buf_len >= PAGE_SIZE > MAX_INLINE_VAL_SIZE */
        BUG_ON(buf_len < pull->remaining);
        memcpy(buf, CVT_INLINE_VAL_PTR(pull->cvt), pull->remaining);

        pull->pull_continue(pull, 0, pull->remaining, 1 /*done*/);
        return;
    }

    /* Handle out-of-line values. */
    BUG_ON(!CVT_ON_DISK(pull->cvt));
    BUG_ON(!pull->cts_proxy);
    cep.ext_id = pull->cvt.cep.ext_id;
    cep.offset = pull->cvt.cep.offset + pull->offset; /* @TODO in bytes or blocks? */

    debug("Locking cdb (0x%x, 0x%x)\n", cep.ext_id, cep.offset);
    pull->buf      = buf;
    pull->curr_c2b = castle_cache_block_get(cep,
                                            (pull->to_copy - 1) / PAGE_SIZE + 1,
                                            USER);
    castle_cache_advise(pull->curr_c2b->cep, C2_ADV_PREFETCH, USER, 0);
    BUG_ON(castle_cache_block_read(pull->curr_c2b,
                                   castle_object_chunk_pull_io_end,
                                   pull));

    /* completes in __castle_object_chunk_pull_complete(). */
}
EXPORT_SYMBOL(castle_object_chunk_pull);

static void castle_object_pull_continue(struct castle_bio_vec *c_bvec, int err, c_val_tup_t cvt)
{
    struct castle_object_pull *pull = c_bvec->c_bio->pull;

    pull->cts_proxy = c_bvec->cts_proxy;
    pull->cvt       = cvt;

    castle_object_bvec_attach_key_dealloc(c_bvec);
    castle_utils_bio_free(c_bvec->c_bio);

    /* Deal with error case, or non-existent value. */
    if (err || CVT_INVALID(cvt) || CVT_TOMBSTONE(cvt))
    {
        CVT_INVALID_INIT(pull->cvt);
        pull->pull_continue(pull, err, 0, 1 /*done*/);
    }

    else
    {
        pull->offset    = 0;
        pull->curr_c2b  = NULL;
        pull->buf       = NULL;
        pull->remaining = cvt.length;

        pull->pull_continue(pull, err /*now: 0*/, cvt.length, 0 /*done*/);
    }
}

/**
 * Look up and return a (large) object from DA.
 *
 * @param   cpu_index   CPU index (to determine correct T0 CT)
 */
int castle_object_pull(struct castle_object_pull *pull,
                       struct castle_attachment *attachment,
                       int cpu_index)
{
    struct castle_btree_type *btree;
    void *key;
    c_bio_t *c_bio;
    c_bvec_t *c_bvec;
    int ret;

    debug("castle_object_pull pull=%p\n", pull);
    BUG_ON(!attachment);

    if (!castle_fs_inited)
        return -ENODEV;

    /* Create the packed key out of the backend key. */
    btree = castle_double_array_btree_type_get(attachment);
    key = btree->key_pack(pull->key, NULL, NULL);
    if (!key)
        return -ENOMEM;

    /* Single c_bvec for the bio */
    ret = -ENOMEM;
    c_bio = castle_utils_bio_alloc(1);
    if (!c_bio)
        goto err0;

    CVT_INVALID_INIT(pull->cvt);

    c_bio->attachment    = attachment;
    c_bio->pull          = pull;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs;
    c_bvec->key             = key;
    c_bvec->cpu_index       = cpu_index;
    c_bvec->cpu             = castle_double_array_request_cpu(c_bvec->cpu_index);
    c_bvec->val_get         = castle_object_value_acquire;
    c_bvec->val_put         = castle_object_value_release;
    c_bvec->submit_complete = castle_object_pull_continue;
    c_bvec->orig_complete   = NULL;

    /* in the beginning, we will be willing to resolve timestamps or counters, but upon
       retrieval of the first candidate return value, we will pick one or the other. */

    atomic_set(&c_bvec->reserv_nodes, 0);

    /* @TODO: add bios to the debugger! */
    castle_double_array_submit(c_bvec);
    return 0;

err0:
    btree->key_dealloc(key);
    return ret;
}
EXPORT_SYMBOL(castle_object_pull);
