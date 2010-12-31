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

static c_trc_evt_t* castle_trace_buffer_alloc(c_trace_id_t id)
{
    c_trc_evt_t *t;

    BUG_ON(!castle_trace_rchan);
    t = relay_reserve(castle_trace_rchan, sizeof(c_trc_evt_t));
    if(!t)
        return NULL;

    t->magic = CASTLE_TRACE_MAGIC;
    do_gettimeofday(&t->timestamp);
    t->id = id;
    t->cpu = smp_processor_id(); 

    return t;
}

static void castle_trace_cache_event(c_trc_cache_var_id_t var_id, uint32_t var_val)
{
    unsigned long flags;
    c_trc_evt_t *t;

    /* TODO: what if we are racing probe remove, with a call here?. */
    local_irq_save(flags);
    t = castle_trace_buffer_alloc(TRACE_CACHE_ID);
    if(t)
    {
        t->cache.var_id  = var_id; 
        t->cache.var_val = var_val; 
    }
    local_irq_restore(flags);
}

static void castle_trace_merge_start_event(da_id_t da, 
                                           uint8_t level, 
                                           tree_seq_t in_tree1, 
                                           tree_seq_t in_tree2)
{
    unsigned long flags;
    c_trc_evt_t *t;

    local_irq_save(flags);
    t = castle_trace_buffer_alloc(TRACE_MERGE_ID);
    if(t)
    {
        t->merge.da       = da; 
        t->merge.level    = level; 
        t->merge.flags    = MERGE_START_FLAG; 
        t->merge.tree_id1 = in_tree1; 
        t->merge.tree_id2 = in_tree2; 
    }
    local_irq_restore(flags);
}

static void castle_trace_merge_finish_event(da_id_t da, uint8_t level, tree_seq_t out_tree)
{
    unsigned long flags;
    c_trc_evt_t *t;

    local_irq_save(flags);
    t = castle_trace_buffer_alloc(TRACE_MERGE_ID);
    if(t)
    {
        t->merge.da       = da; 
        t->merge.level    = level; 
        t->merge.flags    = MERGE_END_FLAG; 
        t->merge.tree_id1 = out_tree; 
    }
    local_irq_restore(flags);
}

static void castle_trace_merge_unit_start_event(da_id_t da, uint8_t level, uint64_t unit)
{
    unsigned long flags;
    c_trc_evt_t *t;

    local_irq_save(flags);
    t = castle_trace_buffer_alloc(TRACE_MERGE_UNIT_ID);
    if(t)
    {
        t->merge_unit.da       = da; 
        t->merge_unit.level    = level; 
        t->merge_unit.flags    = MERGE_START_FLAG; 
        t->merge_unit.unit     = unit; 
    }
    local_irq_restore(flags);
}

static void castle_trace_merge_unit_finish_event(da_id_t da, uint8_t level, uint64_t unit)
{
    unsigned long flags;
    c_trc_evt_t *t;

    local_irq_save(flags);
    t = castle_trace_buffer_alloc(TRACE_MERGE_UNIT_ID);
    if(t)
    {
        t->merge_unit.da       = da; 
        t->merge_unit.level    = level; 
        t->merge_unit.flags    = MERGE_END_FLAG; 
        t->merge_unit.unit     = unit; 
    }
    local_irq_restore(flags);
}

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
    printk("Deleting a buf file (%p), ref count in parent (%p) = %d\n",
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
    printk("Opened a buf file, ref count in parent (%p) = %d\n",
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

#define last_trace_register(tpoint)                                            \
    ret = castle_trace_##tpoint##_register(castle_trace_##tpoint##_event);     \
    if (ret) {                                                                 \
        printk("Failed to register trace point: %s\n", #tpoint);               \
        goto *exit_point;                                                      \
    }

#define trace_register(tpoint)                                                 \
    last_trace_register(tpoint)                                                \
    else exit_point = &&fail_unregister_probe_##tpoint;                        
                                                                               
#define trace_register_fail(tpoint)                                            \
    fail_unregister_probe_##tpoint:                                            \
        castle_trace_##tpoint##_unregister(castle_trace_##tpoint##_event)

static int castle_trace_tracepoints_register(void)
{
    int ret;
    void *exit_point = &&error;

    trace_register(cache);
    trace_register(merge_start);
    trace_register(merge_finish);
    trace_register(merge_unit_start);
    last_trace_register(merge_unit_finish);

    return 0;

    trace_register_fail(merge_unit_start);
    trace_register_fail(merge_finish);
    trace_register_fail(merge_start);
    trace_register_fail(cache);
error:
    return ret;
}

static void castle_trace_tracepoints_unregister(void)
{
    castle_trace_cache_unregister(castle_trace_cache_event);
    castle_trace_merge_start_unregister(castle_trace_merge_start_event);
    castle_trace_merge_finish_unregister(castle_trace_merge_finish_event);
    castle_trace_merge_unit_start_unregister(castle_trace_merge_unit_start_event);
    castle_trace_merge_unit_finish_unregister(castle_trace_merge_unit_finish_event);
}

int castle_trace_setup(char *dir_str)
{
    struct dentry *dir, *root;
    int ret;

    BUG_ON(!castle_ctrl_is_locked());
    if(castle_trace_ready)
        return -EEXIST;

    __module_get(THIS_MODULE);
    dir = NULL;
    root = NULL;

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
        printk("Not all trace files have been closed, failing the teardown.\n");
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
