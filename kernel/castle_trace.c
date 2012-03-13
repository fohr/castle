#include <linux/mutex.h>
#include <linux/debugfs.h>
#include <linux/relay.h>

#include "castle.h"
#include "castle_trace.h"
#include "castle_debug.h"
#include "castle_utils.h"

static int            castle_trace_ready          = 0;
static atomic_t       castle_trace_files_cnt      = ATOMIC(0);
static struct rchan  *castle_trace_rchan          = NULL;
static struct dentry *castle_trace_dir            = NULL;
static char          *castle_trace_dir_str        = NULL;

/**********************************************************************************************
 * Using castle_trace.c
 *
 * XXX
 * XXX Don't forget to bump CASTLE_TRACE_MAGIC in castle_public.h!
 * XXX Once bumped copy to libcastle.hg
 * XXX
 *
 * Trace events are broken down by:
 *    provider (e.g. DA, CACHE, etc.)
 *    event (TRACE_START, TRACE_END, TRACE_VALUE)
 *    variable (e.g. TRACE_CACHE_DIRTY_PGS, TRACE_MERGE_UNIT_GET_C2B_NS, etc.)
 *    values (v1, v2, v3, v4, v5)
 * Generally value reporting should be handled by a top-level provider function, e.g.
 * castle_trace_cache() or castle_trace_merge().
 *
 * ADDING A NEW PROVIDER (e.g. foo provider):
 *
 * kernel hg: fs.hg/kernel:
 * 1. castle_public.h: bump CASTLE_TRACE_MAGIC
 * 2. castle_public.h: add TRACE_FOO to c_trc_prov_t
 * 3. castle_public.h: create c_trc_foo_var_t enum in similar style to c_trc_cache_var_t
 * 4. castle_trace.h: Add new CASTLE_DEFINE_TRACE(foo, ...) macro call
 * 5. castle_trace.c: Add trace_register(foo), trace_register_fail(foo) to
 *                    castle_trace_tracepoints_register()
 * 6. castle_trace.c: Add castle_trace_foo_unregister(castle_trace_foo_event) to
 *                    castle_trace_tracepoints_unregister()
 * 7. castle_trace.c: Write castle_trace_foo_event(...) which should call _castle_trace_event()
 *                    to allocate and dispatch the event
 *
 * userland hg: castle-utils.hg/castle-trace:
 * 1. Copy castle_public.h from fs.hg/kernel to libcastle.hg
 * 2. castle_trace.c: Add foo_var_name[] string index array (see cache_var_name[])
 * 3. castle_trace.c: Add TRACE_FOO provider to decode_trace()'s main switch statement
 *
 * ADDING A NEW REPORTING VALUE (e.g. clean pages to TRACE_CACHE provider):
 *
 * 1. fs.hg/kernel/castle_public.h: bump CASTLE_TRACE_MAGIC
 * 2. fs.hg/kernel/castle_public.h: add TRACE_CACHE_CLEAN_PGS to c_trc_cache_var_t enum
 * 3. Update castle_public.h in libcastle.hg (see above)
 * 4. castle-utils.hg/castle-trace/castle_trace.c: add TRACE_CACHE_CLEAN_PGS to cache_var_name[]
 *
 * USING TRACE_PERCENTAGE (for castle_trace_cache() only, at current):
 *
 * - Create five new sequential c_trc_cache_var_t variables in order:
 *     1. ...V1_V2_ID
 *     2. ...V1_ID
 *     3. ...V2_ID
 *     4. ...V1_PCT_ID
 *     5. ...V2_PCT_ID
 * - Use TRACE_PERCENTAGE and pass the two values in the sequential order defined above
 * - Update castle_trace.c as standard, but do not define a string for ..V1_V2_ID
 *
 * castle-trace takes the two values from TRACE_PERCENTAGE and outputs ***value for both
 * v1 and v2 then ***percentage for v1 and v2, e.g. (100*v1)/(v1+v2) and (100*v2)/(v1+v2).
 */

static c_trc_evt_t* castle_trace_buffer_alloc(void)
{
    c_trc_evt_t *t;

    BUG_ON(!castle_trace_rchan);
    t = relay_reserve(castle_trace_rchan, sizeof(c_trc_evt_t));
    if(!t)
        return NULL;

    t->magic = CASTLE_TRACE_MAGIC;
    do_gettimeofday(&t->timestamp);
    t->cpu = smp_processor_id();

    return t;
}

/**
 * Trace an event.
 *
 * @param provider          Event provider (e.g. TRACE_CACHE, TRACE_DA, etc.)
 * @param type              Event type (TRACE_VALUE, TRACE_START, TRACE_END)
 * @param var               Event variable (e.g. TRACE_MERGE_UNIT, TRACE_CACHE_READS)
 * @param da                Doubling Array ID
 * @param v1,v2,v3,v4,v5    Consumer defined
 */
static void _castle_trace_event(c_trc_prov_t provider,
                                c_trc_type_t type,
                                int var,
                                uint64_t v1, uint64_t v2, uint64_t v3, uint64_t v4, uint64_t v5)
{
    unsigned long flags;
    c_trc_evt_t *evt;

    local_irq_save(flags);
    evt = castle_trace_buffer_alloc();
    if (evt)
    {
        evt->provider   = provider;
        evt->type       = type;
        evt->var        = var;
        evt->v1         = v1;
        evt->v2         = v2;
        evt->v3         = v3;
        evt->v4         = v4;
        evt->v5         = v5;
    }
    local_irq_restore(flags);
}

/**************************************************************************************************/

/* castle_trace_cache() */
static void castle_trace_cache_event(c_trc_type_t type,
                                     c_trc_cache_var_t var,
                                     uint64_t v1,
                                     uint64_t v2)
{
    _castle_trace_event(TRACE_CACHE, type, var, v1, v2, 0, 0, 0);
}

/* castle_trace_da() */
static void castle_trace_da_event(c_trc_type_t type,
                                  c_trc_cache_var_t var,
                                  c_da_t da,
                                  uint64_t v2)
{
    _castle_trace_event(TRACE_DA, type, var, da, v2, 0, 0, 0);
}

/* castle_trace_da_merge() */
static void castle_trace_da_merge_event(c_trc_type_t type,
                                        c_trc_cache_var_t var,
                                        c_da_t da,
                                        uint8_t level,
                                        uint64_t v4,
                                        uint64_t v5)
{
    _castle_trace_event(TRACE_DA_MERGE, type, var, da, level, 0, v4, v5);
}

/* castle_trace_da_merge_unit() */
static void castle_trace_da_merge_unit_event(c_trc_type_t type,
                                             c_trc_cache_var_t var,
                                             c_da_t da,
                                             uint8_t level,
                                             uint64_t unit,
                                             uint64_t v4)
{
    _castle_trace_event(TRACE_DA_MERGE_UNIT, type, var, da, level, unit, v4, 0);
}

/* castle_trace_io_sched() */
static void castle_trace_io_sched_event(c_trc_type_t type,
                                        c_trc_io_sched_var_t var,
                                        uint64_t val)
{
    _castle_trace_event(TRACE_IO_SCHED, type, var, val, 0, 0, 0, 0);
}


/**************************************************************************************************/

static int castle_trace_subbuf_start(struct rchan_buf *buf,
                                     void *subbuf,
                                     void *prev_subbuf,
                                     size_t prev_padding)
{
    if (!relay_buf_full(buf))
        return 1;

    return 0;
}

static int castle_trace_buf_file_remove(struct dentry *dentry)
{
    castle_printk(LOG_INFO, "Deleting a buf file (%p), ref count in parent (%p) = %d\n",
            dentry, castle_trace_dir, atomic_read(&castle_trace_dir->d_count));
    debugfs_remove(dentry);
    atomic_dec(&castle_trace_files_cnt);

    return 0;
}

static struct dentry *castle_trace_buf_file_create(const char *filename,
                                                   struct dentry *parent,
                                                   int mode,
                                                   struct rchan_buf *buf,
                                                   int *is_global)
{
    struct dentry *dentry;

    dentry = debugfs_create_file(filename, mode, parent, buf, &relay_file_operations);
    castle_printk(LOG_INFO, "Opened a buf file, ref count in parent (%p) = %d\n",
            parent, atomic_read(&parent->d_count));
    if(dentry)
        atomic_inc(&castle_trace_files_cnt);

    return dentry;
}

static struct rchan_callbacks castle_trace_relay_callbacks = {
    .subbuf_start       = castle_trace_subbuf_start,
    .create_buf_file    = castle_trace_buf_file_create,
    .remove_buf_file    = castle_trace_buf_file_remove,
};

#define last_trace_register(tpoint)                                                 \
    ret = castle_trace_##tpoint##_register(castle_trace_##tpoint##_event);          \
    if (ret) {                                                                      \
        castle_printk(LOG_WARN, "Failed to register trace point: %s\n", #tpoint);   \
        goto *exit_point;                                                           \
    }

#define trace_register(tpoint)                                                      \
    last_trace_register(tpoint)                                                     \
    else exit_point = &&fail_unregister_probe_##tpoint;

#define trace_register_fail(tpoint)                                                 \
    fail_unregister_probe_##tpoint:                                                 \
        castle_trace_##tpoint##_unregister(castle_trace_##tpoint##_event)

/**
 * Register tracepoints.
 *
 * @also castle_trace_tracepoints_unregister()
 */
static int castle_trace_tracepoints_register(void)
{
    int ret;
    void *exit_point = &&error;

    trace_register(cache);
    trace_register(da);
    trace_register(da_merge);
    trace_register(da_merge_unit);
    last_trace_register(io_sched);

    return 0;

    trace_register_fail(da_merge_unit);
    trace_register_fail(da_merge);
    trace_register_fail(da);
    trace_register_fail(cache);
error:
    return ret;
}

/**
 * Unregister tracepoints.
 *
 * NOTE: pass the name of the function that gets created by trace_register() to
 * the _unregister() function.  This is the name of the function that was
 * registered with _event suffixed.
 *
 * @also castle_trace_tracepoints_register()
 */
static void castle_trace_tracepoints_unregister(void)
{
    castle_trace_cache_unregister(castle_trace_cache_event);
    castle_trace_da_unregister(castle_trace_da_event);
    castle_trace_da_merge_unregister(castle_trace_da_merge_event);
    castle_trace_da_merge_unit_unregister(castle_trace_da_merge_unit_event);
    castle_trace_io_sched_unregister(castle_trace_io_sched_event);
}

int castle_trace_setup(char *dir_str)
{
    struct dentry *dir;
    int ret;

    BUG_ON(!castle_ctrl_is_locked());
    if(castle_trace_ready)
        return -EEXIST;

    __module_get(THIS_MODULE);
    dir = NULL;

    /* Create tracing directory. */
    ret = -ENOENT;
    castle_trace_dir = debugfs_create_dir(dir_str, NULL);
    if(!castle_trace_dir)
        goto err1;

    /* Create relay channel. */
    BUG_ON(castle_trace_rchan);
    if(!(castle_trace_rchan = relay_open("trace",
                                         castle_trace_dir,
                                         sizeof(c_trc_evt_t),
                                         1024,
                                         &castle_trace_relay_callbacks)))
        goto err2;
    /* Finally, save the dir name string. */
    castle_trace_dir_str = dir_str;
    castle_trace_ready   = 1;

    return 0;

err2:
    debugfs_remove(dir);
err1:
    castle_free(dir_str);
    module_put(THIS_MODULE);

    return ret;
}

int castle_trace_start(void)
{
    BUG_ON(!castle_ctrl_is_locked());
    if(!castle_trace_ready)
        return -EINVAL;

    return castle_trace_tracepoints_register();
}

int castle_trace_stop(void)
{
    BUG_ON(!castle_ctrl_is_locked());
    if(!castle_trace_ready)
        return -EINVAL;

    castle_trace_tracepoints_unregister();
    relay_flush(castle_trace_rchan);

    return 0;
}

int castle_trace_teardown(void)
{
    int trace_files_nr;

    BUG_ON(!castle_ctrl_is_locked());
    if(!castle_trace_ready)
        return -EINVAL;

    castle_trace_tracepoints_unregister();
    if(castle_trace_rchan)
    {
        relay_flush(castle_trace_rchan);
        relay_close(castle_trace_rchan);
        castle_trace_rchan = NULL;
    }
    /* relay_close() should have released all the trace files. */
    trace_files_nr = atomic_read(&castle_trace_files_cnt);
    if(castle_trace_dir)
    {
         debugfs_remove(castle_trace_dir);
         castle_trace_dir = NULL;
         castle_free(castle_trace_dir_str);
    }

    if(trace_files_nr == 0)
    {
        module_put(THIS_MODULE);
        castle_trace_ready = 0;
        return 0;
    }
    else
    {
        castle_printk(LOG_WARN, "Not all trace files have been closed, failing the teardown.\n");
        return -EEXIST;
    }
}

int castle_trace_init(void)
{
    return 0;
}

void castle_trace_fini(void)
{
    BUG_ON(castle_trace_rchan);
}
