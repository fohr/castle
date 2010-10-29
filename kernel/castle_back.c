#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
#include <linux/list.h>
#include <linux/vmalloc.h>
#include <asm/pgtable.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_objects.h"
#include "castle_cache.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_debug.h"
#include "castle_back.h"
#include "ring.h"

DEFINE_RING_TYPES(castle, castle_request_t, castle_response_t);

#define MAX_BUFFER_PAGES  (256)
#define MAX_BUFFER_SIZE   (MAX_BUFFER_PAGES << PAGE_SHIFT)

#define MAX_STATEFUL_OPS  (1024)

#define CASTLE_BACK_NAME  "castle-back"

#define USED              __attribute__((used))
#define error(_f, _a...)  (printk(KERN_ERR "%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)              ((void)0)
#define debug_iter(_f, ...)         ((void)0)
#define debug_ref_count(_f, ...)    ((void)0)
#else
#define debug(_f, _a...)            (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_iter(_f, _a...)       (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#define debug_ref_count(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

static struct workqueue_struct *castle_back_wq;

struct castle_back_op;

#define CASTLE_BACK_CONN_INITIALISED_BIT    (0)
#define CASTLE_BACK_CONN_INITIALISED_FLAG   (1 << CASTLE_BACK_CONN_INITIALISED_BIT)
#define CASTLE_BACK_CONN_DISCONNECTING_BIT  (1)
#define CASTLE_BACK_CONN_DISCONNECTING_FLAG (1 << CASTLE_BACK_CONN_DISCONNECTING_BIT)
#define CASTLE_BACK_CONN_NOTIFY_BIT         (2)
#define CASTLE_BACK_CONN_NOTIFY_FLAG        (1 << CASTLE_BACK_CONN_NOTIFY_BIT)

struct castle_back_conn 
{
    unsigned long           flags;
    
    /* details of the shared ring buffer */
    unsigned long           rings_vstart; /* Where is the ring mapped in? */
    castle_back_ring_t      back_ring;
    struct work_struct      work;
    wait_queue_head_t       wait;
    spinlock_t              response_lock;
    atomic_t                ref_count;
    
    /* 
     * in kernel state for each operation 
     * should be RING_SIZE(back_ring) of these
     * and a free list to get new ones
     */
    struct castle_back_op           *ops;
    struct list_head                 free_ops;

    struct castle_back_stateful_op  *stateful_ops;
    struct list_head                 free_stateful_ops;
    struct timer_list                stateful_op_timeout_check_timer;
    int                              restart_timer;
        
    /* details of the shared buffers */
    spinlock_t                       buffers_lock;
    struct rb_root                   buffers_rb; /* red-black tree of castle_back_buffers */
};

struct castle_back_buffer
{
    struct rb_node     rb_node;
    unsigned long      user_addr; /* address in user process TODO should this be a void*? */
    uint32_t           size;
    uint32_t           ref_count;
    void              *buffer; /* pointer to buffer in kernel address space */
};

struct castle_back_op
{
    struct list_head                 list;
    
    castle_request_t                 req; /* contains call_id etc */
    struct castle_back_conn         *conn;
    struct castle_back_buffer       *buf;
    
    /* use for assembling a get and partial writes in puts */
    size_t value_length;
    size_t buffer_offset; 
    
    union 
    {
        struct castle_object_replace replace;
        struct castle_object_get get;
    };
};

struct castle_back_iterator
{
    uint64_t                      flags;
    collection_id_t               collection_id;
    c_vl_okey_t                  *start_key;
    c_vl_okey_t                  *end_key;
    /* saved key and value that couldn't fit in the buffer this time */
    c_vl_okey_t                  *saved_key;
    c_val_tup_t                   saved_val;
    castle_object_iterator_t     *iterator;
    /* the tail of the kv_list being built by this iterator */
    struct castle_key_value_list *kv_list_tail;
    /* the amount of buffer the kv_list is using */
    size_t                        kv_list_size;
    /* the amount of buffer the kv_list can fill */
    size_t                        buf_len;
};

typedef void (*castle_back_stateful_op_expire_t) (struct castle_back_stateful_op *stateful_op);

struct castle_back_stateful_op
{
    struct list_head                    list;
    /* token is calculated by index + use_count * MAX_STATEFUL_OPS where index is the
     * index in the stateful_ops array in the connection. So the index is calculated by
     * token % MAX_STATEFUL_OPS.  This means tokens are reused at most every 2^32/MAX_STATEFUL_OPS
     * calls so shouldn't get collisions.
     */
    castle_interface_token_t            token;
    /* use_count counts how many times this stateful op has been reused.
     * Wraps around on overflow.
     */
    uint32_t                            use_count;
    /* a check to see if this stateful_op is being used */
    int                                 in_use;
    uint32_t                            tag;

    struct list_head                    op_queue;
    spinlock_t                          lock;
    struct castle_back_conn            *conn;
    
    /* sum of size of all buffers queued up */
    uint32_t                            queued_size;
    struct castle_back_op              *curr_op;
    struct work_struct                  work;

    unsigned long                       last_used_jiffies;
    struct work_struct                  expire_work;
    collection_id_t                     collection_id;
    /* is called with stateful_op->lock held, and should drop it */
    castle_back_stateful_op_expire_t    expire;

    union
    {
        struct castle_back_iterator     iterator;
        struct castle_object_replace    replace;
        struct castle_object_get        get;
        struct castle_object_pull       pull;
    };
};

/******************************************************************
 * Utilities to reserve ("pin"?) & map some vmalloc'd pages etc
 */

static inline void ReservePages(void *buffer, unsigned long size)
{
    int i, pages = size >> PAGE_SHIFT;
    for (i = 0; i < pages; i++)
        SetPageReserved(vmalloc_to_page(buffer + (i * PAGE_SIZE))); 
}

static inline void UnReservePages(void *buffer, unsigned long size)
{    
    int i, pages = size >> PAGE_SHIFT;
    for (i = 0; i < pages; i++)
        ClearPageReserved(vmalloc_to_page(buffer + (i * PAGE_SIZE)));
}

static inline int castle_vma_map(struct vm_area_struct *vma, void *buffer, unsigned long size)
{
    int i, err, offset, pages = size >> PAGE_SHIFT;
    
    for (i=0; i<pages; i++)
    {
        offset = i << PAGE_SHIFT;
        err = remap_pfn_range(vma, vma->vm_start + offset, 
            vmalloc_to_pfn(buffer + offset),
            PAGE_SIZE, vma->vm_page_prot);
        if (err)
        {
            error("castle_back: mapping failed!\n");
            err = -ENOMEM; // TODO should I do this or just return remap_pfn_range?
            goto err_out;
        }
    }
    
    return 0;

err_out:
   zap_page_range(vma, vma->vm_start, vma->vm_end - vma->vm_start, NULL);
   return err;
}

static USED void castle_back_print_page(char *buff, int length)
{
    int i=0;
    while(i<length)
    {
        printk(" [%d]=", i);
        
        while(i<length)
        {
            printk("%2x, ", (unsigned char)buff[i]);
            i++;
            if (i % 8 == 0)
                break;
        }
        
        printk("\n");
    } 
}

/******************************************************************
 * Functions to deal with getting and putting buffers, inserting 
 * new ones into tree
 */
 
#define castle_back_user_to_kernel(__buffer, __user_addr) \
    (__buffer->buffer + ((unsigned long)__user_addr - __buffer->user_addr))

#define castle_back_kernel_to_user(__buffer, __kernel_addr) \
    (__buffer->user_addr + ((unsigned long)__kernel_addr - (unsigned long)__buffer->buffer))

#define castle_back_user_addr_in_buffer(__buffer, __user_addr) \
    ((unsigned long) __user_addr < (__buffer->user_addr + __buffer->size))

static inline int __castle_back_buffer_exists(struct castle_back_conn *conn,
                                              unsigned long start, unsigned long end)
{
    struct castle_back_buffer *buffer;
    struct rb_node *node;

    BUG_ON(!spin_is_locked(&conn->buffers_lock));

    node = conn->buffers_rb.rb_node;

    while (node)
    {
        buffer = rb_entry(node, struct castle_back_buffer, rb_node);

        //debug("Considering buffer (%lx, %ld, %p)\n", buffer->user_addr, 
        //    buffer->size, buffer->buffer);

        if (end <= buffer->user_addr)
            node = node->rb_left;
        else if (start >= buffer->user_addr + buffer->size)
            node = node->rb_right;
        else
        {
            return 1; /* Found buffer between start and end */
        }
    }

    return 0;
}

static inline struct castle_back_buffer *__castle_back_buffer_get(struct castle_back_conn *conn,
                                                                  unsigned long user_addr)
{
    struct rb_node *node;
    struct castle_back_buffer *buffer;

    BUG_ON(!spin_is_locked(&conn->buffers_lock));

    node = conn->buffers_rb.rb_node;

    while (node)
    {
        buffer = rb_entry(node, struct castle_back_buffer, rb_node);

        //debug("Considering buffer (%lx, %ld, %p)\n", buffer->user_addr, 
        //    buffer->size, buffer->buffer);

        if (user_addr < buffer->user_addr)
            node = node->rb_left;
        else if (user_addr >= buffer->user_addr + buffer->size)
            node = node->rb_right;
        else
        {
            buffer->ref_count++;
            debug("__castle_back_buffer_get ref_count is now %d\n", buffer->ref_count);
            return buffer;
        }
    }
    
    return NULL;
}

static inline struct castle_back_buffer *castle_back_buffer_get(struct castle_back_conn *conn,
                                                                unsigned long user_addr)
{
    struct castle_back_buffer *buffer;
    
    spin_lock(&conn->buffers_lock);
    buffer = __castle_back_buffer_get(conn, user_addr);
    spin_unlock(&conn->buffers_lock);
    
    return buffer;
}

static void castle_back_buffer_put(struct castle_back_conn *conn,
                                   struct castle_back_buffer *buf)
{
    spin_lock(&conn->buffers_lock);
    
    debug("castle_back_buffer_put ref_count=%i, buf=%p\n", buf->ref_count, buf);

    buf->ref_count--;
    /* remove buffer from rb tree so no-one else can find it
       this allows us to free it outside the lock */
    if (buf->ref_count <= 0)
        rb_erase(&buf->rb_node, &conn->buffers_rb);

    debug("castle_back_buffer_put ref_count=%i, buf=%p\n", buf->ref_count, buf);

    spin_unlock(&conn->buffers_lock);
    
    if (buf->ref_count > 0)
        return;
        
    debug("Freeing buffer %lx\n", buf->user_addr);
    
    UnReservePages(buf->buffer, buf->size);
    vfree(buf->buffer);
    castle_free(buf);
}

static inline struct castle_back_buffer 
*__castle_back_buffers_rb_insert(struct castle_back_conn *conn,
                                 unsigned long user_addr,
                                 struct rb_node *node)
{
    struct rb_node **p;
    struct rb_node *parent = NULL;
    struct castle_back_buffer *buffer;

    BUG_ON(!spin_is_locked(&conn->buffers_lock));
    p = &conn->buffers_rb.rb_node;

    while (*p)
    {
        parent = *p;
        buffer = rb_entry(parent, struct castle_back_buffer, rb_node);

        if (user_addr < buffer->user_addr)
            p = &(*p)->rb_left;
        else if (user_addr >= buffer->user_addr + buffer->size)
            p = &(*p)->rb_right;
        else
            return buffer; /* user_addr is in this buffer */
    }

    rb_link_node(node, parent, p);

    return NULL;
}

static inline struct castle_back_buffer 
*castle_back_buffers_rb_insert(struct castle_back_conn *conn,
                               unsigned long user_addr,
                               struct rb_node *node)
{
    struct castle_back_buffer *buffer;
    if ((buffer = __castle_back_buffers_rb_insert(conn, user_addr, node)))
        goto out;
    rb_insert_color(node, &conn->buffers_rb);
out:
    return buffer;
}

/******************************************************************
 * ops for dealing with the stateful ops pool
 */

static struct castle_back_stateful_op *castle_back_find_stateful_op(struct castle_back_conn *conn,
                                                                    castle_interface_token_t token,
                                                                    uint32_t tag)
{
    struct castle_back_stateful_op *stateful_op = conn->stateful_ops + (token % MAX_STATEFUL_OPS);

    if (!stateful_op->in_use || stateful_op->token != token || stateful_op->tag != tag)
        return NULL;

    debug("castle_back_find_stateful_op returning: token = %x, use_count = %u, index = %ld\n",
            stateful_op->token, stateful_op->use_count, stateful_op - conn->stateful_ops);

    return stateful_op;
}

static void castle_back_stateful_op_expire(struct work_struct *work);

/* *op_ptr is NULL if there are no free ones */
static castle_interface_token_t 
castle_back_get_stateful_op(struct castle_back_conn *conn,
                            struct castle_back_stateful_op **op_ptr)
{
    struct castle_back_stateful_op *stateful_op;

    spin_lock(&conn->response_lock);
    if (list_empty(&conn->free_stateful_ops))
    {
        spin_unlock(&conn->response_lock);
        *op_ptr = NULL;
        return 0;
    }
    stateful_op = list_entry(conn->free_stateful_ops.next, struct castle_back_stateful_op, list);
    list_del(&stateful_op->list);
    spin_unlock(&conn->response_lock);

    debug("castle_back_get_stateful_op got op: in_use = %d, "
            "token = %u, use_count = %u, index = %ld\n",
            stateful_op->in_use, stateful_op->token,
            stateful_op->use_count, stateful_op - conn->stateful_ops);

    spin_lock(&stateful_op->lock);
    BUG_ON(stateful_op->in_use);
    stateful_op->last_used_jiffies = jiffies;
    stateful_op->expire = NULL;
    CASTLE_INIT_WORK(&stateful_op->expire_work, castle_back_stateful_op_expire);
    stateful_op->in_use = 1;
    /* see def of castle_back_stateful_op */
    stateful_op->token = (stateful_op - conn->stateful_ops) + (stateful_op->use_count * MAX_STATEFUL_OPS);
    stateful_op->use_count++;
    stateful_op->conn = conn;
    stateful_op->collection_id = -1;
    INIT_LIST_HEAD(&stateful_op->op_queue);
    spin_unlock(&stateful_op->lock);

    *op_ptr = stateful_op;

    debug_ref_count("inc conn ref_count.\n");
    atomic_inc(&conn->ref_count);

    return stateful_op->token;
}

static void castle_back_cleanup_conn(void *data);

static void castle_back_put_stateful_op(struct castle_back_conn *conn,
                                        struct castle_back_stateful_op *stateful_op)
{
    debug("castle_back_put_stateful_op putting: token = %x, use_count = %u, index = %ld\n",
            stateful_op->token, stateful_op->use_count, stateful_op - conn->stateful_ops);

    BUG_ON(!spin_is_locked(&stateful_op->lock));
    BUG_ON(!stateful_op->in_use);
    BUG_ON(!list_empty(&stateful_op->op_queue));
    BUG_ON(stateful_op->curr_op != NULL);
    
    stateful_op->in_use = 0;

    /* Put op back on freelist */
    spin_lock(&conn->response_lock);
    list_add_tail(&stateful_op->list, &conn->free_stateful_ops);
    spin_unlock(&conn->response_lock);
    
    castle_collection_put(stateful_op->collection_id);
    spin_unlock(&stateful_op->lock);

    debug_ref_count("dec conn ref_count.\n");
    if (atomic_dec_and_test(&conn->ref_count))
        castle_back_cleanup_conn(conn);
}

#define STATEFUL_OP_TIMEOUT_CHECK_INTERVAL 10 * HZ
#define STATEFUL_OP_TIMEOUT 10 * HZ

static void castle_back_stateful_op_timeout_check(unsigned long data);

/*
 * The timer doesn't inc conn->ref_count, so del_timer_sync is used to ensure the callback
 * is not being executed when conn is freed.
 */
static void castle_back_start_stateful_op_timeout_check_timer(struct castle_back_conn *conn)
{
    struct timer_list *timer = &conn->stateful_op_timeout_check_timer;

    debug("Scheduling stateful_op_timeout_check_timer for conn %p.\n", conn);

    setup_timer(timer, castle_back_stateful_op_timeout_check, (unsigned long)conn);
    mod_timer(timer, jiffies + STATEFUL_OP_TIMEOUT_CHECK_INTERVAL);
}

static void castle_back_stateful_op_timeout_check(unsigned long data)
{
    struct castle_back_conn *conn = (struct castle_back_conn *)(data);
    struct castle_back_stateful_op *stateful_ops = conn->stateful_ops;
    uint32_t i;

    debug("castle_back_stateful_op_timeout_check for conn = %p\n", conn);

    for (i = 0; i < MAX_STATEFUL_OPS; i++)
    {
        /* Don't get the lock here because we're in the interrupt context. At worst we get an
         * inconsistent set of params for the stateful op which cause us to schedule
         * when we shouldn't, but it's checked later on.
         */
        if (stateful_ops[i].in_use &&
                jiffies - stateful_ops[i].last_used_jiffies > STATEFUL_OP_TIMEOUT &&
                stateful_ops[i].expire)
        {
            debug("stateful_op index %u, token %u has expired.\n", i, stateful_ops[i].token);
            debug_ref_count("inc conn ref_count.\n");
            atomic_inc(&conn->ref_count);
            queue_work(castle_back_wq, &stateful_ops[i].expire_work);
        }
    }

    /* reschedule ourselves */
    if (conn->restart_timer)
        castle_back_start_stateful_op_timeout_check_timer(conn);
}

static void castle_back_stateful_op_expire(struct work_struct *work)
{
    struct castle_back_stateful_op *stateful_op;
    struct castle_back_conn *conn;

    stateful_op = container_of(work, struct castle_back_stateful_op, expire_work);
    conn = stateful_op->conn;

    debug("castle_back_stateful_op_expire for stateful_op = %p\n", stateful_op);

    spin_lock(&stateful_op->lock);

    if (!stateful_op->in_use || !stateful_op->expire)
    {
        spin_unlock(&stateful_op->lock);
        return;
    }

    BUG_ON(!list_empty(&stateful_op->op_queue));

    /* check it hasn't been used since expire was queued up */
    if (jiffies - stateful_op->last_used_jiffies > STATEFUL_OP_TIMEOUT)
    {
        /* drops the lock */
        stateful_op->expire(stateful_op);
    }
    else
        spin_unlock(&stateful_op->lock);

    debug_ref_count("dec conn ref_count.\n");
    if (atomic_dec_and_test(&conn->ref_count))
        castle_back_cleanup_conn(conn);
}

/* return 1 -> call continue function */
static int castle_back_stateful_op_prod(struct castle_back_stateful_op *stateful_op)
{
    BUG_ON(!spin_is_locked(&stateful_op->lock));

    if (stateful_op->curr_op != NULL)
        return 0;

    if (list_empty(&stateful_op->op_queue))
        return 0;

    stateful_op->expire = NULL;

    /* take an op off the queue and process it */
    stateful_op->curr_op = list_first_entry(&stateful_op->op_queue, struct castle_back_op, list);
    list_del(&stateful_op->curr_op->list);

    debug_iter("stateful_op->curr_op = %p\n", stateful_op->curr_op);

    return 1;
}

/*
 * Finish all ops on the stateful op queue, giving them err & closing their buffers
 */
static int castle_back_reply(struct castle_back_op *op, int err, 
     castle_interface_token_t token, int length);
static void castle_back_stateful_op_finish_all(struct castle_back_stateful_op *stateful_op, int err)
{
    struct list_head *pos, *tmp;
    struct castle_back_op *op;
    
    BUG_ON(!spin_is_locked(&stateful_op->lock));
    
    /* Return err on all queued ops */
    
    list_for_each_safe(pos, tmp, &stateful_op->op_queue) {
        op = list_entry(pos, struct castle_back_op, list);
        list_del(pos);
        castle_back_buffer_put(op->conn, op->buf);
        castle_back_reply(op, err, 0, 0);
    }
}

/******************************************************************
 * Castle VM ops for buffers etc
 */

/*
 * This should only be call on a partial munmap, when
 * the vma is split.  We use it to up the ref count on 
 * the buffer, to stop the buffer going away when you 
 * do multiple, partial munmaps.
 */
static void castle_back_vm_open(struct vm_area_struct *vma)
{
    struct castle_back_conn *conn = NULL;
    struct castle_back_buffer *buf = NULL;
    
    debug("castle_back_vm_open vm_start=%lx vm_end=%lx\n", vma->vm_start, vma->vm_end);
    
    if (vma->vm_file != NULL)
        conn = vma->vm_file->private_data;
    
    if (conn == NULL)
    {
        error("castle_back_vm_open: no connection!\n");
        return;
    }

    buf = castle_back_buffer_get(conn, vma->vm_start);
    
    if (buf == NULL)
    {
        error("castle_back_vm_open: could not find buffer!\n");
        return;
    }
    
    debug("castle_back_vm_open buf=%p, size=%d, vm_start=%lx, vm_end=%lx\n", 
        buf, buf->size, vma->vm_start, vma->vm_end);
    
    spin_lock(&conn->buffers_lock);
    buf->ref_count++;
    spin_unlock(&conn->buffers_lock);
    
    castle_back_buffer_put(conn, buf);
}

static void castle_back_vm_close(struct vm_area_struct *vma)
{
    struct castle_back_conn *conn = NULL;
    struct castle_back_buffer *buf = NULL;
    
    debug("castle_back_vm_close vm_start=%lx vm_end=%lx\n", vma->vm_start, vma->vm_end);
    debug("castle_back_vm_close mm->mmap_sem.activity=%d\n", vma->vm_mm->mmap_sem.activity);
    
    if (vma->vm_file != NULL)
        conn = vma->vm_file->private_data;
    
    if (conn == NULL)
    {
        error("castle_back_vm_close: no connection!\n");
        return;
    }

    buf = castle_back_buffer_get(conn, vma->vm_start);

    if (buf == NULL)
    {
        error("castle_back_vm_close: could not find buffer!\n");
        return;
    }
    
    debug("castle_back_vm_close buf=%p, size=%d, vm_start=%lx, vm_end=%lx\n",
        buf, buf->size, vma->vm_start, vma->vm_end);
    
    /* Double put - This is the reverse of the ref_count=1 in buffer_map */
    castle_back_buffer_put(conn, buf);
    castle_back_buffer_put(conn, buf);
}

static struct vm_operations_struct castle_back_vm_ops = {
    open:     castle_back_vm_open,
    close:    castle_back_vm_close,
};

/******************************************************************
 * High(er) level rpc callbacks
 */

static int castle_back_reply(struct castle_back_op *op, int err, 
                             castle_interface_token_t token, int length)
{
    struct castle_back_conn *conn = op->conn;
    castle_back_ring_t *back_ring = &conn->back_ring;
    castle_response_t resp;
    int notify;

    resp.call_id = op->req.call_id;
    resp.err = err;
    resp.token = token;
    resp.length = length;

    debug("castle_back_reply op=%p, call_id=%d, err=%d, token=%x, length=%d\n",
        op, op->req.call_id, err, token, length);

    // TODO check with GM that this is in the correct place
    spin_lock(&conn->response_lock);

    memcpy(RING_GET_RESPONSE(back_ring, back_ring->rsp_prod_pvt), &resp, sizeof(resp));
    back_ring->rsp_prod_pvt++;

    RING_PUSH_RESPONSES_AND_CHECK_NOTIFY(back_ring, notify);
    
    // Put op back on freelist
    list_add(&op->list, &conn->free_ops);
    
    spin_unlock(&conn->response_lock);

    // TODO if(notify)?
    debug(">>>notifying user\n");
    set_bit(CASTLE_BACK_CONN_NOTIFY_BIT, &conn->flags);
    wake_up(&conn->wait);

    debug_ref_count("dec conn ref_count.\n");
    if (atomic_dec_and_test(&conn->ref_count))
        castle_back_cleanup_conn(conn);

    return 0;
}

static int castle_back_key_copy_get(struct castle_back_conn *conn, c_vl_okey_t *user_key, 
                                    size_t key_len, c_vl_okey_t **key_out)
{
    struct castle_back_buffer *buf;
    unsigned long buf_end;
    unsigned long user_key_long = (unsigned long) user_key;
    c_vl_okey_t *key;
    int i, err;
    
    /*
     * Get buffer with key in it and create a temporary copy
     * of it, doing whole bunch of checks to make sure we have
     * a valid key
     */
    
    if (key_len < sizeof(c_vl_okey_t))
    {
        error("Bad key length %lu\n", key_len);
        err = -EINVAL;        
        goto err0;
    }
    
    buf = castle_back_buffer_get(conn, user_key_long);
    if (!buf)
    {
        error("Bad user pointer %p\n", user_key);
        err = -EINVAL;        
        goto err0;
    }

    /* buf_end is the end address of the buffer in userspace */
    buf_end = buf->user_addr + buf->size;

    if (user_key_long + key_len > buf_end)
    {
        error("Key too big for buffer! (key_len = %lu)\n", key_len);
        err = -EINVAL;
        goto err1;
    }

    key = castle_malloc(key_len, GFP_KERNEL);
    if (key == NULL)
    {
        error("Could not kmalloc for key copy!\n");
        err = -ENOMEM;
        goto err1;
    }

    memcpy(key, castle_back_user_to_kernel(buf, user_key), key_len);

    if (sizeof(c_vl_okey_t) + (key->nr_dims * sizeof(c_vl_key_t *)) > key_len)
    {
        error("Too many dimensions %d\n", key->nr_dims);
        err = -EINVAL;        
        goto err2;
    }

    debug("Original key pointer %p\n", user_key);

    /* translate pointers in the key to be valid in kernelspace */
    for (i=0; i < key->nr_dims; i++)
    {
        unsigned long dim_i = (unsigned long) key->dims[i];
        unsigned long dim_size;
        
        debug("  dim[%d] = %p (user)\n", i, key->dims[i]);
        
        if (dim_i < buf->user_addr || dim_i > buf_end)
        {
            error("Bad pointer %p (out of buffer, start=%lx, length=%u)\n", 
                key->dims[i], buf->user_addr, buf->size);
            err = -EINVAL;
            goto err2;
        }
        
        key->dims[i] = (c_vl_key_t *)((unsigned long)key + 
            (unsigned long)key->dims[i] - user_key_long);
        
        debug("  dim[%d] = %p (kernel)\n", i, key->dims[i]);

        /* This compares old pointer + length (found by following new pointer)
           to address in userspace of the end of the buffer */
        dim_size = sizeof(c_vl_key_t) + (key->dims[i]->length * sizeof(uint8_t));
        if (dim_i + dim_size > buf_end)
        {    
            error("Dimension %d goes beyond end of buffer\n", i);
            err = -EINVAL;
            goto err2;
        }
    }
    
    castle_back_buffer_put(conn, buf);
    
#ifdef DEBUG    
    vl_okey_print(key);
#endif
    
    *key_out = key;
    
    return 0;
    
err2: castle_free(key);
err1: castle_back_buffer_put(conn, buf);
err0: return err;
}

/* if doesn't fit into the buffer, *buf_used will be set to 0 */
static void castle_back_key_kernel_to_user(c_vl_okey_t *key, struct castle_back_buffer *buf, 
                                           unsigned long user_buf, size_t buf_len, 
                                           size_t *buf_used)
{
    uint32_t i;
    c_vl_okey_t *key_copy;
    size_t total_size;

#ifdef DEBUG
    debug("castle_back_key_kernel_to_user copying key:\n");
    vl_okey_print(key);
    debug("user_buf = %p\n", (void *)user_buf);
#endif

    total_size = sizeof(c_vl_okey_t) + sizeof(c_vl_key_t *) * key->nr_dims;
    if (total_size > buf_len)
    {
        *buf_used = 0;
        return;
    }
    key_copy = (c_vl_okey_t *)castle_back_user_to_kernel(buf, user_buf);

    key_copy->nr_dims = key->nr_dims;

    for (i = 0; i < key->nr_dims; i++)
    {
        size_t sub_key_size;
        c_vl_key_t *vlk;

        sub_key_size = sizeof(c_vl_key_t) + key->dims[i]->length;

        key_copy->dims[i] = (c_vl_key_t *)(user_buf + total_size);
        total_size += sub_key_size;
        if (total_size > buf_len)
        {
            *buf_used = 0;
            return;
        }

        vlk = castle_back_user_to_kernel(buf, key_copy->dims[i]);

        vlk->length = key->dims[i]->length;
        memcpy(vlk->key, key->dims[i]->key, key->dims[i]->length);
    }

    *buf_used = total_size;

    return;
}

/* if doesn't fit into the buffer, *buf_used will be set to 0 */
static void castle_back_val_kernel_to_user(c_val_tup_t *val, struct castle_back_buffer *buf, 
                                           unsigned long user_buf, size_t buf_len, 
                                           size_t *buf_used, collection_id_t collection_id)
{
    size_t length, val_length;
    struct castle_iter_val *val_copy;

    if (val->type & CVT_TYPE_INLINE)
        val_length = val->length;
    else
        val_length = 0;

    length = sizeof(struct castle_iter_val) + val_length;

    if (buf_len < length)
    {
        *buf_used = 0;
        return;
    }

    val_copy = (struct castle_iter_val *)castle_back_user_to_kernel(buf, user_buf);

    val_copy->type = val->type;
    val_copy->length = val->length;
    if (val->type & CVT_TYPE_INLINE)
    {
        val_copy->val = (uint8_t *)(user_buf + sizeof(struct castle_iter_val));
        memcpy((uint8_t *)castle_back_user_to_kernel(buf, val_copy->val), val->val, val->length);
    } else {
        val_copy->collection_id = collection_id;
    }

    *buf_used = length;
}

static void castle_back_replace_complete(struct castle_object_replace *replace, int err)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);

    debug("castle_back_replace_complete\n");

    castle_back_buffer_put(op->conn, op->buf);

    castle_back_reply(op, err, 0, 0);

    castle_collection_put(op->req.replace.collection_id); 
}

static uint32_t castle_back_replace_data_length_get(struct castle_object_replace *replace)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);
    
    return op->req.replace.value_len;
}

static void castle_back_replace_data_copy(struct castle_object_replace *replace, 
                                          void *buffer, int buffer_length, int not_last)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);

    debug("castle_back_replace_data_copy buffer=%p, buffer_length=%d, not_last=%d, value_len=%ld\n", 
        buffer, buffer_length, not_last, op->req.replace.value_len);

    // TODO: actual zero copy!

    BUG_ON(op->buffer_offset + buffer_length > op->req.replace.value_len);
    
    memcpy(buffer, castle_back_user_to_kernel(op->buf, op->req.replace.value_ptr) + op->buffer_offset, 
        buffer_length);

    op->buffer_offset += buffer_length;
}

static void castle_back_replace(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    
    attachment = castle_collection_get(op->req.replace.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.replace.collection_id);
        err = -EINVAL;
        goto err0;
    }

    err = castle_back_key_copy_get(conn, op->req.replace.key_ptr, op->req.replace.key_len, &key);
    if (err)
        goto err0;

    /*
     * Get buffer with value in it and save it
     */
    op->buf = castle_back_buffer_get(conn, (unsigned long) op->req.replace.value_ptr);
    if (op->buf == NULL)
    {
        error("Could not get buffer for pointer=%p\n", op->req.replace.value_ptr);
        err = -EINVAL;
        goto err1;
    }

    if (!castle_back_user_addr_in_buffer(op->buf, op->req.replace.value_ptr + op->req.replace.value_len - 1))
    {
        error("Invalid value length %ld (ptr=%p)\n", op->req.replace.value_len, op->req.replace.value_ptr);
        err = -EINVAL;
        goto err2;
    }

    op->buffer_offset = 0;

    op->replace.value_len = op->req.replace.value_len;
    op->replace.replace_continue = NULL;
    op->replace.complete = castle_back_replace_complete;
    op->replace.data_length_get = castle_back_replace_data_length_get;
    op->replace.data_copy = castle_back_replace_data_copy;

    err = castle_object_replace(&op->replace, attachment, key, 0);
    if (err)
        goto err2;
        
    castle_free(key);
    return;
    
err2: castle_back_buffer_put(conn, op->buf);
err1: castle_free(key);
err0: castle_back_reply(op, err, 0, 0);
      castle_collection_put(op->req.replace.collection_id);
}

static void castle_back_remove_complete(struct castle_object_replace *replace, int err)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);

    debug("castle_back_remove_complete\n");

    castle_back_reply(op, err, 0, 0);
    castle_collection_put(op->req.replace.collection_id); 
}

static void castle_back_remove(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    
    attachment = castle_collection_get(op->req.remove.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.remove.collection_id);
        err = -EINVAL;
        goto err0;
    }

    err = castle_back_key_copy_get(conn, op->req.replace.key_ptr, op->req.replace.key_len, &key);
    if (err)
        goto err0;

    op->buf = NULL;
    op->replace.value_len = 0;
    op->replace.replace_continue = NULL;
    op->replace.complete = castle_back_remove_complete;
    op->replace.data_length_get = NULL;
    op->replace.data_copy = NULL;

    err = castle_object_replace(&op->replace, attachment, key, 1 /* tombstone */);
    if (err)
        goto err1;

    castle_free(key);
    return;
    
err1: castle_free(key);
err0: castle_back_reply(op, err, 0, 0);
      castle_collection_put(op->req.replace.collection_id); 
}

void castle_back_get_reply_continue(struct castle_object_get *get,
                                    int err,
                                    void *buffer,
                                    uint32_t buffer_len,
                                    int last)
{
    struct castle_back_op *op = container_of(get, struct castle_back_op, get);
    void *dest = castle_back_user_to_kernel(op->buf, op->req.get.value_ptr + op->buffer_offset);
    uint32_t to_copy = min(buffer_len, (uint32_t) (op->req.get.value_len - op->buffer_offset));

    if (err)
    {
        castle_back_buffer_put(op->conn, op->buf);
        castle_back_reply(op, err, 0, 0);
        castle_collection_put(op->req.get.collection_id); 
    }
    
    BUG_ON(!buffer);
    
    if (to_copy > 0)
    {
        memcpy(dest, buffer, to_copy); 
        op->buffer_offset += to_copy;
    }
    
    if (last)
    {
        castle_back_buffer_put(op->conn, op->buf);
        castle_back_reply(op, 0, 0, op->value_length);
        castle_collection_put(op->req.get.collection_id); 
    }

    return;
}

void castle_back_get_reply_start(struct castle_object_get *get, 
                                  int err, 
                                  uint32_t data_length,
                                  void *buffer, 
                                  uint32_t buffer_length)
{
    struct castle_back_op *op = container_of(get, struct castle_back_op, get);
    int err_prime;
    
    BUG_ON(buffer_length > data_length);    
        
    if (!buffer)
    {
        BUG_ON((data_length != 0) || (buffer_length != 0));
        err_prime = -ENOENT;
        goto err;
    }        
        
    if (err)
    {
        err_prime = err;
        goto err;
    }

    op->value_length = data_length;
    op->buffer_offset = 0;
    
    castle_back_get_reply_continue(get, 0, buffer, buffer_length, buffer_length == data_length);

    return;
    
err:
    castle_back_buffer_put(op->conn, op->buf);
    castle_back_reply(op, err_prime, 0, 0);
    castle_collection_put(op->req.get.collection_id); 
}

static void castle_back_get(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    
    attachment = castle_collection_get(op->req.get.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.get.collection_id);
        err = -EINVAL;
        goto err0;
    }

    err = castle_back_key_copy_get(conn, op->req.get.key_ptr, op->req.get.key_len, &key);
    if (err)
        goto err0;

    /*
     * Get buffer with value in it and save it
     */
    op->buf = castle_back_buffer_get(conn, (unsigned long) op->req.get.value_ptr);
    if (op->buf == NULL)
    {
        error("Invalid value ptr %p\n", op->req.get.value_ptr);
        err = -EINVAL;
        goto err1;
    }

    if (!castle_back_user_addr_in_buffer(op->buf, op->req.get.value_ptr + op->req.get.value_len - 1))
    {
        error("Invalid value length %d (ptr=%p)\n", op->req.get.value_len, op->req.get.value_ptr);
        err = -EINVAL;
        goto err2;
    }

    op->get.reply_start = castle_back_get_reply_start;
    op->get.reply_continue = castle_back_get_reply_continue;

    err = castle_object_get(&op->get, attachment, key);
    if (err)
        goto err2;

    castle_free(key);
    return;

err2: castle_back_buffer_put(conn, op->buf);
err1: castle_free(key);
err0: castle_back_reply(op, err, 0, 0);
      castle_collection_put(op->req.get.collection_id);
}

/**** ITERATORS ****/

static void _castle_back_iter_next(void *data);
static void _castle_back_iter_finish(void *data);
static void castle_back_iter_cleanup(struct castle_back_stateful_op *stateful_op);

static void castle_back_iter_expire(struct castle_back_stateful_op *stateful_op)
{
    debug("castle_back_iter_expire token=%u.\n", stateful_op->token);

    BUG_ON(!spin_is_locked(&stateful_op->lock));
    BUG_ON(!list_empty(&stateful_op->op_queue));
    BUG_ON(stateful_op->curr_op != NULL);

    castle_object_iter_finish(stateful_op->iterator.iterator);

    // will drop stateful_op->lock
    castle_back_iter_cleanup(stateful_op);
}

static void castle_back_iter_call_queued(struct castle_back_stateful_op *stateful_op)
{
    int call_next;

    BUG_ON(!stateful_op->in_use);

    spin_lock(&stateful_op->lock);
    call_next = castle_back_stateful_op_prod(stateful_op);
    spin_unlock(&stateful_op->lock);

    if (call_next)
    {
        debug_iter("castle_back_iter_call_queued add next op to work queue, token = %x.\n",
                stateful_op->token);
        switch (stateful_op->curr_op->req.tag)
        {
            case CASTLE_RING_ITER_NEXT:
                INIT_WORK(&stateful_op->work, _castle_back_iter_next, stateful_op);
                queue_work(castle_back_wq, &stateful_op->work);
                break;

            case CASTLE_RING_ITER_FINISH:
                INIT_WORK(&stateful_op->work, _castle_back_iter_finish, stateful_op);
                queue_work(castle_back_wq, &stateful_op->work);
                break;

            default:
                error("Invalid tag %d in castle_back_iter_call_queued.\n",
                        stateful_op->curr_op->req.tag);
                BUG();
        }
    } else

        debug_iter("castle_back_iter_call_queued not calling since "
                "ongoing op or no ops in queue, token = %x.\n", stateful_op->token);
}

static void castle_back_iter_reply(struct castle_back_stateful_op *stateful_op, int err)
{
    debug_iter("castle_back_iter_reply, token = %x.\n", stateful_op->token);

    castle_back_reply(stateful_op->curr_op, err, 0, 0);

    spin_lock(&stateful_op->lock);

    stateful_op->last_used_jiffies = jiffies;
    stateful_op->expire = castle_back_iter_expire;
    stateful_op->curr_op = NULL;

    debug_iter("stateful_op->curr_op = %p\n", stateful_op->curr_op);

    spin_unlock(&stateful_op->lock);

    castle_back_iter_call_queued(stateful_op);
}

static void castle_back_iter_start(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *start_key;
    c_vl_okey_t *end_key;
    castle_interface_token_t token;
    struct castle_back_stateful_op *stateful_op;
    int col_put = 0;

    debug_iter("castle_back_iter_start\n");

    attachment = castle_collection_get(op->req.iter_start.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.iter_start.collection_id);
        err = -EINVAL;
        goto err0;
    }

    /* start_key and end_key are freed by castle_object_iter_finish */
    err = castle_back_key_copy_get(conn, op->req.iter_start.start_key_ptr, 
        op->req.iter_start.start_key_len, &start_key);
    if (err)
        goto err0;

    err = castle_back_key_copy_get(conn, op->req.iter_start.end_key_ptr, 
        op->req.iter_start.end_key_len, &end_key);
    if (err)
        goto err1;

#ifdef DEBUG
    debug_iter("start_key: \n");
    vl_okey_print(start_key);

    debug_iter("end_key: \n");
    vl_okey_print(end_key);
#endif

    token = castle_back_get_stateful_op(conn, &stateful_op);
    if (!stateful_op)
    {
        error("castle_back: no more free stateful ops!\n");
        err = -EAGAIN;
        goto err2;
    }
    /* need the lock here as the timer is running */
    spin_lock(&stateful_op->lock);
    stateful_op->tag = CASTLE_RING_ITER_START;
    stateful_op->curr_op = NULL;
    debug_iter("stateful_op->curr_op = %p\n", stateful_op->curr_op);
    stateful_op->last_used_jiffies = jiffies;
    stateful_op->expire = castle_back_iter_expire;
    spin_unlock(&stateful_op->lock);

    stateful_op->iterator.flags = op->req.iter_start.flags;
    stateful_op->iterator.collection_id = op->req.iter_start.collection_id;
    stateful_op->iterator.saved_key = NULL;
    stateful_op->iterator.start_key = start_key;
    stateful_op->iterator.end_key = end_key;
    stateful_op->collection_id = op->req.iter_start.collection_id;

    err = castle_object_iter_start(attachment, start_key, end_key, &stateful_op->iterator.iterator);
    if (err)
        goto err3;

    castle_back_reply(op, 0, token, 0);

    return;

err3:
    // No one could have added another op to queue as we haven't returns token yet
    spin_lock(&stateful_op->lock);
    stateful_op->curr_op = NULL;
    castle_back_put_stateful_op(conn, stateful_op);
    col_put = 1;
err2:
    castle_free(end_key);
err1:
    castle_free(start_key);
err0:
    castle_back_reply(op, err, 0, 0);
    if (!col_put)
        castle_collection_put(op->req.iter_start.collection_id);
}

static size_t castle_back_save_key_value_to_list(struct castle_key_value_list *kv_list,
        c_vl_okey_t *key, c_val_tup_t *val,
        collection_id_t collection_id,
        struct castle_back_buffer *back_buf,
        size_t buf_len, /* space left in the buffer */
        int save_val /* should values be saved too? */)
{
    size_t buf_used, key_len, val_len;

    BUG_ON(!kv_list);

    buf_used = sizeof(struct castle_key_value_list);
    if (buf_used >= buf_len)
    {
        buf_used = 0;
        goto err0;
    }

    kv_list->key = (c_vl_okey_t *)castle_back_kernel_to_user(back_buf,
            (unsigned long)kv_list + buf_used);

    castle_back_key_kernel_to_user(key, back_buf, (unsigned long)kv_list->key,
            buf_len - buf_used, &key_len);
    if (key_len == 0)
    {
        buf_used = 0;
        goto err1;
    }
    buf_used += key_len;

    if (!save_val)
        kv_list->val = NULL;
    else
    {
        kv_list->val = (struct castle_iter_val *)((unsigned long)kv_list->key + key_len);
        castle_back_val_kernel_to_user(val, back_buf,
            (unsigned long)kv_list->val, buf_len - buf_used, &val_len, collection_id);

        if (val_len == 0)
        {
            buf_used = 0;
            goto err2;
        }
        buf_used += val_len;
    }

    return buf_used;

err2: kv_list->val = NULL;
err1: kv_list->key = NULL;
err0:

    return buf_used;
}

static int castle_back_iter_next_callback(struct castle_object_iterator *iterator,
        c_vl_okey_t *key,
        c_val_tup_t *val,
        int err,
        void *data)
{
    struct castle_back_stateful_op *stateful_op;
    struct castle_back_conn *conn;
    struct castle_back_op *op;
    size_t cur_len;
    struct castle_key_value_list *kv_list_cur;
    size_t buf_len, buf_used;

    BUG_ON(!data);
    stateful_op = (struct castle_back_stateful_op *)data;
    conn = stateful_op->conn;
    op = stateful_op->curr_op;
    BUG_ON(!op);

    if (err)
        goto err0;

    if (stateful_op->iterator.kv_list_size == 0)
    {
        kv_list_cur = stateful_op->iterator.kv_list_tail;
        /* set the key to NULL to signify empty list if there
         * are no values
         */
        stateful_op->iterator.kv_list_tail->key = NULL;
    }
    else
        kv_list_cur = castle_back_user_to_kernel(op->buf,
                stateful_op->iterator.kv_list_tail->next);

    /* if no more values */
    if (key == NULL)
    {
        stateful_op->iterator.kv_list_tail->next = NULL;

        debug_iter("Iterator has no more values, replying. kv_list_size=%zu.\n",
                stateful_op->iterator.kv_list_size);

        castle_back_buffer_put(conn, op->buf);
        castle_back_iter_reply(stateful_op, 0);

        return 0;
    }

    buf_len = stateful_op->iterator.buf_len;
    buf_used = stateful_op->iterator.kv_list_size;

    cur_len = castle_back_save_key_value_to_list(kv_list_cur,
                        key,
                        val,
                        stateful_op->iterator.collection_id,
                        op->buf,
                        buf_len - buf_used,
                        !(stateful_op->iterator.flags & CASTLE_RING_ITER_FLAG_NO_VALUES));

    if (cur_len == 0)
    {
        stateful_op->iterator.kv_list_tail->next = NULL;

        debug_iter("Not enough space on buffer, saving a key for next time.\n");

        stateful_op->iterator.saved_key = castle_object_okey_copy(key);
        if (!stateful_op->iterator.saved_key)
        {
            err = -ENOMEM;
            goto err0;
        }
        stateful_op->iterator.saved_val = *val;
        if (val->type & CVT_TYPE_INLINE)
        {
            /* copy the value since it may get removed from the cache */
            stateful_op->iterator.saved_val.val =
                castle_malloc(val->length, GFP_KERNEL);
            memcpy(stateful_op->iterator.saved_val.val, val->val, val->length);
        }
        else
            stateful_op->iterator.saved_val.val = NULL;

        castle_back_buffer_put(conn, op->buf);
        castle_back_iter_reply(stateful_op, 0);

        return 0;
    }

    kv_list_cur->next = (struct castle_key_value_list *)
            castle_back_kernel_to_user(op->buf, ((unsigned long)kv_list_cur + cur_len));
    stateful_op->iterator.kv_list_tail = kv_list_cur;
    stateful_op->iterator.kv_list_size += cur_len;

    /* we have space for more so request it */
    return 1;

err0:
    castle_back_buffer_put(conn, op->buf);
    castle_back_iter_reply(stateful_op, err);

    return 0;
}

static void _castle_back_iter_next(void *data)
{
    struct castle_back_conn        *conn;
    struct castle_back_op          *op;
    struct castle_key_value_list   *kv_list_head;
    castle_object_iterator_t       *iterator;
    size_t                          buf_used;
    size_t                          buf_len;
    int                             err;
    struct castle_back_stateful_op *stateful_op = data;

    debug_iter("_castle_back_iter_next, token = %x\n", stateful_op->token);

    BUG_ON(!stateful_op->in_use);

    conn = stateful_op->conn;
    op = stateful_op->curr_op;
    BUG_ON(!op);
    iterator = stateful_op->iterator.iterator;

    stateful_op->iterator.kv_list_tail = castle_back_user_to_kernel(op->buf,
            op->req.iter_next.buffer_ptr);
    stateful_op->iterator.kv_list_size = 0;
    stateful_op->iterator.buf_len = op->req.iter_next.buffer_len;

    kv_list_head = stateful_op->iterator.kv_list_tail;
    kv_list_head->next = NULL;
    kv_list_head->key = NULL;
    buf_used = 0;
    buf_len = op->req.iter_next.buffer_len;

#ifdef DEBUG
    debug_iter("iter_next start_key\n");
    vl_okey_print(iterator->start_okey);

    debug_iter("iter_next end_key\n");
    vl_okey_print(iterator->end_okey);
#endif

    /* if we have a saved key and value from the last call, add them to the buffer */
    if (stateful_op->iterator.saved_key != NULL)
    {
        debug_iter("iter_next found saved key, adding to buffer\n");

        buf_used = castle_back_save_key_value_to_list(kv_list_head,
                stateful_op->iterator.saved_key,
                &stateful_op->iterator.saved_val,
                stateful_op->iterator.collection_id,
                op->buf,
                buf_len,
                !(stateful_op->iterator.flags & CASTLE_RING_ITER_FLAG_NO_VALUES));

        if (buf_used == 0)
        {
            error("iterator buffer too small\n");
            err = -EINVAL;
            goto err0;
        }

        castle_object_okey_free(stateful_op->iterator.saved_key);
        /* we copied it so free it */
        if (stateful_op->iterator.saved_val.type & CVT_TYPE_INLINE)
            castle_free(stateful_op->iterator.saved_val.val);

        debug_iter("iter_next added saved key\n");

        stateful_op->iterator.saved_key = NULL;

        stateful_op->iterator.kv_list_size = buf_used;

        kv_list_head->next = (struct castle_key_value_list *)
                    castle_back_kernel_to_user(op->buf, ((unsigned long)kv_list_head + buf_used));
    }

    castle_object_iter_next(iterator, castle_back_iter_next_callback, stateful_op);

    return;

err0:
    castle_back_buffer_put(conn, op->buf);
    castle_back_iter_reply(stateful_op, err);
}

static void castle_back_iter_next(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_back_stateful_op *stateful_op;

    debug_iter("castle_back_iter_next, token = %x\n", op->req.iter_finish.token);

    stateful_op = castle_back_find_stateful_op(conn,
            op->req.iter_next.token, CASTLE_RING_ITER_START);

    if (!stateful_op)
    {
        error("Token not found %x\n", op->req.iter_next.token);
        err = -EINVAL;
        castle_back_reply(op, err, 0, 0);
        return;
    }

    if (op->req.iter_next.buffer_len < PAGE_SIZE)
    {
        error("castle_back_iter_next buffer_len smaller than a page\n");
        err = -EINVAL;
        goto err0;
    }
    
    /*
     * Get buffer with value in it and save it
     */
    op->buf = castle_back_buffer_get(conn, (unsigned long)op->req.iter_next.buffer_ptr);
    if (op->buf == NULL)
    {
        err = -EINVAL;
        goto err0;
    }

    spin_lock(&stateful_op->lock);
    /* Put this op on the queue for the iterator */
    debug_iter("Adding iter_next to stateful_op %p queue.\n", stateful_op);
    list_add_tail(&op->list, &stateful_op->op_queue);
    spin_unlock(&stateful_op->lock);

    castle_back_iter_call_queued(stateful_op);

    return;

err0: castle_back_iter_reply(stateful_op, err);
}

static void castle_back_iter_cleanup(struct castle_back_stateful_op *stateful_op)
{
    BUG_ON(!spin_is_locked(&stateful_op->lock));
    BUG_ON(stateful_op->tag != CASTLE_RING_ITER_START);
    BUG_ON(!list_empty(&stateful_op->op_queue));
    BUG_ON(stateful_op->curr_op != NULL);

    if (stateful_op->iterator.saved_key != NULL)
    {
        castle_object_okey_free(stateful_op->iterator.saved_key);
        if (stateful_op->iterator.saved_val.type & CVT_TYPE_INLINE)
        {
            BUG_ON(!stateful_op->iterator.saved_val.val);
            castle_free(stateful_op->iterator.saved_val.val);
        }
    }

    castle_free(stateful_op->iterator.start_key);
    castle_free(stateful_op->iterator.end_key);

    // will drop stateful_op->lock
    castle_back_put_stateful_op(stateful_op->conn, stateful_op);
}

static void _castle_back_iter_finish(void *data)
{
    struct castle_back_stateful_op *stateful_op = data;
    int err;

    debug_iter("_castle_back_iter_finish, token = %x\n", stateful_op->token);

    spin_lock(&stateful_op->lock);

    err = castle_object_iter_finish(stateful_op->iterator.iterator);
    
    castle_back_reply(stateful_op->curr_op, err, 0, 0);
    stateful_op->curr_op = NULL;

    castle_back_stateful_op_finish_all(stateful_op, -EINVAL);

    // will drop stateful_op->lock
    castle_back_iter_cleanup(stateful_op);
}

static void castle_back_iter_finish(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_back_stateful_op *stateful_op;

    debug_iter("castle_back_iter_finish, token = %x\n", op->req.iter_finish.token);

    stateful_op = castle_back_find_stateful_op(conn,
            op->req.iter_finish.token, CASTLE_RING_ITER_START);

    if (!stateful_op)
    {
        error("Token not found %x\n", op->req.iter_finish.token);
        err = -EINVAL;
        goto err0;
    }

    /*
     * Put this op on the queue for the iterator
     */
    spin_lock(&stateful_op->lock);
    list_add_tail(&op->list, &stateful_op->op_queue);
    spin_unlock(&stateful_op->lock);

    castle_back_iter_call_queued(stateful_op);

    return;

err0:
    castle_back_reply(op, err, 0, 0);
}

/**** BIG PUT ****/

static void castle_back_big_put_expire(struct castle_back_stateful_op *stateful_op)
{
    debug("castle_back_big_put_expire token=%u.\n", stateful_op->token);
    
    BUG_ON(!spin_is_locked(&stateful_op->lock));
    BUG_ON(!list_empty(&stateful_op->op_queue));
    BUG_ON(stateful_op->curr_op != NULL);
    
    castle_object_replace_cancel(&stateful_op->replace);
    
    // Will drop stateful_op->lock
    castle_back_put_stateful_op(stateful_op->conn, stateful_op);
}

static void castle_back_big_put_continue(struct castle_object_replace *replace)
{
    struct castle_back_stateful_op *stateful_op = 
        container_of(replace, struct castle_back_stateful_op, replace);
    int replace_continue, is_last;
    
    spin_lock(&stateful_op->lock);
    
    if (stateful_op->curr_op != NULL);
    {
        struct castle_back_op *op = stateful_op->curr_op;
        if (op->req.tag == CASTLE_RING_PUT_CHUNK && op->buf)
            castle_back_buffer_put(stateful_op->conn, op->buf);

        castle_back_reply(op, 0, stateful_op->token, 0);
        stateful_op->curr_op = NULL;

        stateful_op->expire = castle_back_big_put_expire;
        stateful_op->last_used_jiffies = jiffies;
    }

    replace_continue = castle_back_stateful_op_prod(stateful_op);
    is_last = stateful_op->queued_size == stateful_op->replace.value_len
        && list_empty(&stateful_op->op_queue);
    
    spin_unlock(&stateful_op->lock);
    
    if (replace_continue)
        castle_object_replace_continue(&stateful_op->replace, is_last);
}

static void castle_back_big_put_complete(struct castle_object_replace *replace, int err)
{
    struct castle_back_stateful_op *stateful_op = 
        container_of(replace, struct castle_back_stateful_op, replace);

    debug("castle_back_big_put_complete err=%d\n", err);

    spin_lock(&stateful_op->lock);
    
    if (stateful_op->curr_op != NULL);
    {
        struct castle_back_op *op = stateful_op->curr_op;
        if (op->req.tag == CASTLE_RING_PUT_CHUNK && op->buf)
            castle_back_buffer_put(stateful_op->conn, op->buf);

        castle_back_reply(op, err, stateful_op->token, 0);
        stateful_op->curr_op = NULL;
    }
    
    castle_back_stateful_op_finish_all(stateful_op, err);

    // Will drop stateful_op->lock
    castle_back_put_stateful_op(stateful_op->conn, stateful_op);
}

static uint32_t castle_back_big_put_data_length_get(struct castle_object_replace *replace)
{
    struct castle_back_stateful_op *stateful_op = 
        container_of(replace, struct castle_back_stateful_op, replace);

    uint32_t length = 0; 

    spin_lock(&stateful_op->lock);
    // curr_op could be the BIG_PUT
    if (stateful_op->curr_op != NULL && stateful_op->curr_op->req.tag == CASTLE_RING_PUT_CHUNK)
        length = stateful_op->curr_op->req.put_chunk.buffer_len;
    spin_unlock(&stateful_op->lock);
    
    return length;
}

static void castle_back_big_put_data_copy(struct castle_object_replace *replace, 
                                          void *buffer, int buffer_length, int not_last)
{
    struct castle_back_stateful_op *stateful_op = 
        container_of(replace, struct castle_back_stateful_op, replace);
    struct castle_back_op *op;

    spin_lock(&stateful_op->lock);
    
    op = stateful_op->curr_op;
    
    BUG_ON(op == NULL);

    debug("castle_back_big_put_data_copy buffer=%p, buffer_length=%d,"
        "not_last=%d, value_len=%ld\n, buffer_offset=%ld\n",
        buffer, buffer_length, not_last, op->req.put_chunk.buffer_len, op->buffer_offset);

    BUG_ON(op->req.tag != CASTLE_RING_PUT_CHUNK);
    BUG_ON(op->buffer_offset + buffer_length > op->req.put_chunk.buffer_len);

    // TODO: actual zero copy!

    memcpy(buffer, castle_back_user_to_kernel(op->buf, op->req.put_chunk.buffer_ptr)
        + op->buffer_offset, buffer_length);
    
    op->buffer_offset += buffer_length;

    spin_unlock(&stateful_op->lock);
}

static void castle_back_big_put(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    castle_interface_token_t token;
    struct castle_back_stateful_op *stateful_op;
    int col_put = 0;

    debug_iter("castle_back_big_put\n");

    attachment = castle_collection_get(op->req.big_put.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.big_put.collection_id);
        err = -EINVAL;
        goto err0;
    }

    /* start_key and end_key are freed by castle_object_iter_finish */
    err = castle_back_key_copy_get(conn, op->req.big_put.key_ptr, 
        op->req.big_put.key_len, &key);
    if (err)
        goto err0;

    #ifdef DEBUG
    debug("key: \n");
    vl_okey_print(key);
    #endif

    token = castle_back_get_stateful_op(conn, &stateful_op);
    if (!stateful_op)
    {
        err = -EAGAIN;
        goto err1;
    }
    
    spin_lock(&stateful_op->lock);
    stateful_op->tag = CASTLE_RING_BIG_PUT;
    stateful_op->queued_size = 0;
    stateful_op->curr_op = op;
    stateful_op->expire = castle_back_big_put_expire;
    stateful_op->last_used_jiffies = jiffies;
    spin_unlock(&stateful_op->lock);
    
    stateful_op->replace.value_len = op->req.big_put.value_len;
    stateful_op->replace.replace_continue = castle_back_big_put_continue;
    stateful_op->replace.complete = castle_back_big_put_complete;
    stateful_op->replace.data_length_get = castle_back_big_put_data_length_get;
    stateful_op->replace.data_copy = castle_back_big_put_data_copy;
    stateful_op->collection_id = op->req.big_put.collection_id;

    err = castle_object_replace(&stateful_op->replace, attachment, key, 0);
    if (err)
        goto err2;

    castle_free(key);

    return;

err2: // Safe as no-one could have queued up an op - we have not returned token
      spin_lock(&stateful_op->lock);
      stateful_op->curr_op = NULL;
      castle_back_put_stateful_op(conn, stateful_op);
      col_put = 1;
err1: castle_free(key);
err0: castle_back_reply(op, err, 0, 0);
      if (!col_put)
        castle_collection_put(op->req.big_put.collection_id);
}

static void castle_back_put_chunk(struct castle_back_conn *conn, struct castle_back_op *op)
{
    struct castle_back_stateful_op *stateful_op;
    int replace_continue, is_last, err;

    stateful_op = castle_back_find_stateful_op(conn,
            op->req.put_chunk.token, CASTLE_RING_BIG_PUT);

    if (!stateful_op)
    {
        error("Token not found %x\n", op->req.put_chunk.token);
        err = -EINVAL;
        goto err1;
    }
    
    /*
     * Get buffer with value in it and save it
     */
    op->buf = castle_back_buffer_get(conn, (unsigned long) op->req.put_chunk.buffer_ptr);
    if (op->buf == NULL)
    {
        error("Could not get buffer for pointer=%p\n", op->req.put_chunk.buffer_ptr);
        err = -EINVAL;
        goto err1;
    }

    if (!castle_back_user_addr_in_buffer(op->buf, op->req.put_chunk.buffer_ptr + op->req.put_chunk.buffer_len - 1))
    {
        error("Invalid value length %ld (ptr=%p)\n", op->req.put_chunk.buffer_len, op->req.put_chunk.buffer_ptr);
        err = -EINVAL;
        goto err2;
    }
    
    op->buffer_offset = 0;
    
    /*
     * Put this op on the queue for the big put
     */
    spin_lock(&stateful_op->lock);
    
    if (op->req.put_chunk.buffer_len + stateful_op->queued_size > stateful_op->replace.value_len)
    {
        spin_unlock(&stateful_op->lock);
        error("Invalid value length %ld (ptr=%p)\n", op->req.put_chunk.buffer_len, op->req.put_chunk.buffer_ptr);
        err = -EINVAL;
        goto err2;
    }
    
    stateful_op->queued_size += op->req.put_chunk.buffer_len;
    
    list_add_tail(&op->list, &stateful_op->op_queue);
    
    replace_continue = castle_back_stateful_op_prod(stateful_op);
    is_last = stateful_op->queued_size == stateful_op->replace.value_len
        && list_empty(&stateful_op->op_queue);

    spin_unlock(&stateful_op->lock);
    
    // TODO: BEWARE DEEP RECURSION
    if (replace_continue)
        castle_object_replace_continue(&stateful_op->replace, is_last);

    return;
       
err2: castle_back_buffer_put(conn, op->buf);
err1: castle_back_reply(op, err, 0, 0);
}

/*
 * BIG GET
 */

static void castle_back_big_get_do_chunk(struct castle_back_stateful_op *stateful_op)
{
    struct castle_back_op *op = stateful_op->curr_op;
    
    BUG_ON(stateful_op->tag != CASTLE_RING_BIG_GET);
    BUG_ON(op == NULL);
    BUG_ON(op->req.tag != CASTLE_RING_GET_CHUNK);
    
    castle_object_chunk_pull(&stateful_op->pull, castle_back_user_to_kernel(op->buf, 
        op->req.get_chunk.buffer_ptr), op->req.get_chunk.buffer_len);
}

static void castle_back_big_get_continue(struct castle_object_pull *pull, int err, int length, int done)
{
    struct castle_back_stateful_op *stateful_op = 
        container_of(pull, struct castle_back_stateful_op, pull);
    int get_continue;

    debug("castle_back_big_get_continue stateful_op=%p err=%d length=%d done=%d\n", 
        stateful_op, err, length, done);
    
    BUG_ON(stateful_op->tag != CASTLE_RING_BIG_GET);
    BUG_ON(stateful_op->curr_op == NULL);
    BUG_ON(stateful_op->curr_op->req.tag != CASTLE_RING_GET_CHUNK 
        && stateful_op->curr_op->req.tag != CASTLE_RING_BIG_GET);
    
    castle_back_reply(stateful_op->curr_op, err, stateful_op->token, length);

    spin_lock(&stateful_op->lock);

    stateful_op->curr_op = NULL;

    if (err || done)
    {
        castle_back_stateful_op_finish_all(stateful_op, err);
        // Will drop stateful_op->lock
        castle_back_put_stateful_op(stateful_op->conn, stateful_op);
        return;
    }
    
    get_continue = castle_back_stateful_op_prod(stateful_op);
    spin_unlock(&stateful_op->lock);

    // TODO: BEWARE DEEP RECURSION
    if (get_continue)
        castle_back_big_get_do_chunk(stateful_op);
}

static void castle_back_big_get(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    castle_interface_token_t token;
    struct castle_back_stateful_op *stateful_op;
    int col_put = 0;

    debug_iter("castle_back_big_get stateful_op=%p\n", stateful_op);

    // TODO should we ref count attachments
    attachment = castle_collection_get(op->req.big_get.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.big_get.collection_id);
        err = -EINVAL;
        goto err0;
    }

    token = castle_back_get_stateful_op(conn, &stateful_op);
    if (!stateful_op)
    {
        err = -EAGAIN;
        goto err0;
    }

    stateful_op->tag = CASTLE_RING_BIG_GET;
    stateful_op->curr_op = op;    
    stateful_op->collection_id = op->req.big_get.collection_id;

    stateful_op->pull.pull_continue = castle_back_big_get_continue;

    err = castle_back_key_copy_get(conn, op->req.big_get.key_ptr, 
        op->req.big_get.key_len, &key);
    if (err)
    {
        error("Error copying key err=%d\n", err);
        goto err1;
    }

    #ifdef DEBUG
    debug_iter("key: \n");
    vl_okey_print(key);
    #endif

    err = castle_object_pull(&stateful_op->pull, attachment, key);
    if (err)
        goto err2;

    castle_free(key);

    /* TODO: add timeout to cleanup get if client goes away */

    return;

err2: castle_free(key);
err1: // Safe as no one will have queued up a op - we haven't returned token yet
      spin_lock(&stateful_op->lock);
      stateful_op->curr_op = NULL;
      castle_back_put_stateful_op(conn, stateful_op);
      col_put = 1;
err0: castle_back_reply(op, err, 0, 0);
      if (!col_put)
        castle_collection_put(op->req.big_get.collection_id);
}

static void castle_back_get_chunk(struct castle_back_conn *conn, struct castle_back_op *op)
{
    struct castle_back_stateful_op *stateful_op;
    int get_continue, err;

    stateful_op = castle_back_find_stateful_op(conn, 
        op->req.get_chunk.token, CASTLE_RING_BIG_GET);
    if (!stateful_op)
    {
        error("Token not found %x\n", op->req.get_chunk.token);
        err = -EINVAL;
        goto err1;
    }

    /*
     * Get buffer with value in it and save it
     */
    op->buf = castle_back_buffer_get(conn, (unsigned long) op->req.get_chunk.buffer_ptr);
    if (op->buf == NULL)
    {
        error("Could not get buffer for pointer=%p\n", op->req.get_chunk.buffer_ptr);
        err = -EINVAL;
        goto err1;
    }

    if (!castle_back_user_addr_in_buffer(op->buf, op->req.get_chunk.buffer_ptr + op->req.get_chunk.buffer_len - 1))
    {
        error("Invalid value length %ld (ptr=%p)\n", op->req.get_chunk.buffer_len, op->req.get_chunk.buffer_ptr);
        err = -EINVAL;
        goto err2;
    }
    
    if (((unsigned long) op->req.get_chunk.buffer_ptr) % PAGE_SIZE)
    {
        error("Invalid ptr, not page aligned (ptr=%p)\n", op->req.put_chunk.buffer_ptr);
        err = -EINVAL;
        goto err2;
    }

    if ((op->req.get_chunk.buffer_len) % PAGE_SIZE)
    {
        error("Invalid len, not page aligned (len=%ld)\n", op->req.put_chunk.buffer_len);
        err = -EINVAL;
        goto err2;
    }

    /*
     * Put this op on the queue for the big put
     */
    spin_lock(&stateful_op->lock);

    list_add_tail(&op->list, &stateful_op->op_queue);
    get_continue = castle_back_stateful_op_prod(stateful_op);

    spin_unlock(&stateful_op->lock);

    if (get_continue)
        castle_back_big_get_do_chunk(stateful_op);

    return;

err2: castle_back_buffer_put(conn, op->buf);
err1: castle_back_reply(op, err, 0, 0);  
}

/******************************************************************
 * Castle device functions
 */

unsigned int castle_back_poll(struct file *file, poll_table *wait)
{
    struct castle_back_conn *conn = file->private_data;
    if (conn == NULL) 
    {
        error("castle_back: poll, retrieving connection failed\n");
        return -EINVAL;
    }
    
    debug(">>>castle_back_poll\n");

    poll_wait(file, &conn->wait, wait);

    debug("castle_back_poll done\n");

    if (conn->flags & CASTLE_BACK_CONN_NOTIFY_FLAG) {
        clear_bit(CASTLE_BACK_CONN_NOTIFY_BIT, &conn->flags);
        RING_PUSH_RESPONSES(&conn->back_ring);
        return POLLIN | POLLRDNORM;
    }

    debug("castle_back_poll nothing to say\n");

    return 0;
}

static void castle_back_request_process(struct castle_back_conn *conn, struct castle_back_op *op)
{
    debug("Got a request call=%d tag=%d\n", op->req.call_id, op->req.tag);
    
    switch (op->req.tag)
    {
        case CASTLE_RING_REMOVE:
            castle_back_remove(conn, op);
            break;
       
        case CASTLE_RING_REPLACE:
            castle_back_replace(conn, op);
            break;

        case CASTLE_RING_ITER_START:
            castle_back_iter_start(conn, op);
            break;

        case CASTLE_RING_BIG_PUT:
            castle_back_big_put(conn, op);
            break;
            
        case CASTLE_RING_PUT_CHUNK:
            castle_back_put_chunk(conn, op);
            break;

        case CASTLE_RING_BIG_GET:
            castle_back_big_get(conn, op);
            break;

        case CASTLE_RING_GET_CHUNK:
            castle_back_get_chunk(conn, op);
            break;

        case CASTLE_RING_ITER_NEXT:
            castle_back_iter_next(conn, op);
            break;

        case CASTLE_RING_ITER_FINISH:
            castle_back_iter_finish(conn, op);
            break;
        
        case CASTLE_RING_GET:
            castle_back_get(conn, op);
            break;
            
        default:
            error("Unknown request tag %d\n", op->req.tag);
            castle_back_reply(op, -EINVAL, 0, 0);
            break;
    }
}

/*
 * We guarantee there is only one running copy of this
 * by using a single threaded workqueue.  TODO make better
 */
static void castle_back_work_do(void *data) 
{
    struct castle_back_conn *conn = data;
    castle_back_ring_t *back_ring = &conn->back_ring;
    int more;
    RING_IDX cons, rp;
    struct castle_back_op *op;
    
    debug("castle_back: doing work\n");
    
    while(!(conn->flags & CASTLE_BACK_CONN_DISCONNECTING_FLAG))
    {
        rp = back_ring->sring->req_prod;
        xen_rmb();
        
        //debug("castle_back: rp=%d\n", rp);
    
        while ((cons = back_ring->req_cons) != rp)
        {
            spin_lock(&conn->response_lock);
            BUG_ON(list_empty(&conn->free_ops));
            op = list_entry(conn->free_ops.next, struct castle_back_op, list);
            list_del(&op->list);
            spin_unlock(&conn->response_lock);
            
            memcpy(&op->req, RING_GET_REQUEST(back_ring, cons), sizeof(castle_request_t));
        
            back_ring->req_cons++;

            /* this is decremented in castle_back_reply */
            debug_ref_count("inc conn ref_count.\n");
            atomic_inc(&conn->ref_count);

            castle_back_request_process(conn, op);
        }
    
        RING_FINAL_CHECK_FOR_REQUESTS(back_ring, more);
        if(!more) break;
    }
    
    debug_ref_count("dec conn ref_count.\n");
    if (atomic_dec_and_test(&conn->ref_count))
        castle_back_cleanup_conn(conn);

    debug("castle_back: done work\n");
}

long castle_back_unlocked_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
    struct castle_back_conn *conn = file->private_data;
    if (conn == NULL) 
    {
        error("castle_back: ioctl, retrieving connection failed\n");
        return -EINVAL;
    }
    
    debug("castle_back_ioctl\n");
    
    switch (cmd)
    {
        case CASTLE_IOCTL_POKE_RING:
            debug_ref_count("inc conn ref_count.\n");
            atomic_inc(&conn->ref_count);
            queue_work(castle_back_wq, &conn->work);
            break;
        
        default:
            return -ENOIOCTLCMD;
    }

    return 0;
}

int castle_back_open(struct inode *inode, struct file *file)
{
    castle_sring_t *sring;
    struct castle_back_conn *conn;
    int i, err = 0;
    
    debug("castle_back_dev_open\n");

    if (!try_module_get(THIS_MODULE))
    {
        error("castle_back_open: failed to inc module ref count!\n");
        err = -EAGAIN;
        goto err0;
    }

    conn = castle_malloc(sizeof(struct castle_back_conn), GFP_KERNEL);
    if (conn == NULL)
    {
        error("castle_back: failed to kzalloc new connection\n");
        err = -ENOMEM;
        goto err1;
    }
        
    conn->flags = 0;
    debug_ref_count("set conn ref_count = 1.\n");
    atomic_set(&conn->ref_count, 1);
    
    INIT_WORK(&conn->work, castle_back_work_do, conn);
    init_waitqueue_head(&conn->wait);
    spin_lock_init(&conn->response_lock);
    spin_lock_init(&conn->buffers_lock);
    conn->buffers_rb = RB_ROOT;

    sring = (castle_sring_t *)vmalloc(CASTLE_RING_SIZE);
    if (conn == NULL)
    {
        error("castle_back: failed to vmalloc shared ring\n");
        err = -ENOMEM;
        goto err2;
    }

    ReservePages(sring, CASTLE_RING_SIZE);

    SHARED_RING_INIT(sring);
    BACK_RING_INIT(&conn->back_ring, sring, CASTLE_RING_SIZE);

    /* init the ops pool */
    conn->ops = vmalloc(sizeof(struct castle_back_op) * RING_SIZE(&conn->back_ring));
    if (conn->ops == NULL)
    {
        error("castle_back: failed to vmalloc mirror buffer for ops");
        err = -ENOMEM;
        goto err3;
    }
    
    INIT_LIST_HEAD(&conn->free_ops);
    
    for (i=0; i<RING_SIZE(&conn->back_ring); i++)
    {
        conn->ops[i].conn = conn;
        list_add(&conn->ops[i].list, &conn->free_ops);
    }

    /* init the stateful ops pool */
    conn->stateful_ops = vmalloc(sizeof(struct castle_back_stateful_op) * MAX_STATEFUL_OPS);
    if (conn->stateful_ops == NULL)
    {
        error("castle_back: failed to vmalloc buffer for stateful_ops");
        err = -ENOMEM;
        goto err3;
    }
    memset(conn->stateful_ops, 0, sizeof(struct castle_back_stateful_op) * MAX_STATEFUL_OPS);
    
    INIT_LIST_HEAD(&conn->free_stateful_ops);
    
    for (i=0; i<MAX_STATEFUL_OPS; i++)
    {
        list_add_tail(&conn->stateful_ops[i].list, &conn->free_stateful_ops);
        spin_lock_init(&conn->stateful_ops[i].lock);
    }

    file->private_data = conn;

    conn->restart_timer = 1;
    castle_back_start_stateful_op_timeout_check_timer(conn);

    return 0;

err3:
    UnReservePages(conn->back_ring.sring, CASTLE_RING_SIZE);
    vfree(conn->back_ring.sring);
err2:
    castle_free(conn);
err1:
    module_put(THIS_MODULE);
err0:
    return err;
}

static void castle_back_cleanup_conn(void *data)
{
    struct castle_back_conn *conn = data;
    struct castle_back_stateful_op *stateful_ops = conn->stateful_ops;
    uint32_t i;

    debug("castle_back_cleanup_conn for conn = %p\n", data);

    BUG_ON(atomic_read(&conn->ref_count) > 0);

    /* shouldn't be any stateful_ops running here for ref_count to be 0 */
    for (i = 0; i < MAX_STATEFUL_OPS; i++)
        BUG_ON(stateful_ops[i].in_use);

    /* del the timer and wait until it has finished the callback */
    conn->restart_timer = 0;
    del_timer_sync(&conn->stateful_op_timeout_check_timer);

    debug("castle_back_cleanup_conn for conn = %p cleaned up and freeing\n", data);

    UnReservePages(conn->back_ring.sring, CASTLE_RING_SIZE);
    vfree(conn->back_ring.sring);
    vfree(conn->ops);
    vfree(conn->stateful_ops);

    /*
     * We don't clean up buffers (buffer_put does that),
     * and they should have been freed by now since conn->ref_count is zero
     */

    castle_free(conn);
    module_put(THIS_MODULE);
}

static void castle_back_cleanup(void *data)
{
    struct castle_back_conn *conn = data;

    BUG_ON(conn == NULL);
    
    debug("castle_back_cleanup, conn = %p\n", conn);

    debug_ref_count("dec conn ref_count.\n");
    if (atomic_dec_and_test(&conn->ref_count))
        castle_back_cleanup_conn(conn);

    /* TODO: should cancel any ongoing ops. For now, they will carry on
     * until they complete and castle_back_cleanup_conn will be called
     * when they complete and decrease the ref count.
     */
}

int castle_back_release(struct inode *inode, struct file *file)
{
    struct castle_back_conn *conn = file->private_data;
    if (conn == NULL) 
    {
        error("castle_back: release, retrieving connection failed\n");
        return -EINVAL;
    }
    
    debug("castle_back_release\n");
    
    set_bit(CASTLE_BACK_CONN_DISCONNECTING_BIT, &conn->flags);
    
    wake_up(&conn->wait);
    
    /* don't increment ref count here, the ref count was incremented
     * on castle_back_open for this
     */
    PREPARE_WORK(&conn->work, castle_back_cleanup, conn);
    queue_work(castle_back_wq, &conn->work);
    
    return 0;
}

static int castle_buffer_map(struct castle_back_conn *conn, struct vm_area_struct *vma)
{
    int err;
    unsigned long size;
    struct castle_back_buffer *buffer;
    
    size = vma->vm_end - vma->vm_start;
    if (size > MAX_BUFFER_SIZE) 
    {
        error("castle_back: you tried to map %ld bytes, max is %d!\n", size, MAX_BUFFER_SIZE);
        err = -EAGAIN;
        goto err1;     
    }
    else if (vma->vm_start % PAGE_SIZE)
    {
        error("castle_back: you tried to map at addr %ld, not page aligned!\n", vma->vm_start);
        err = -EAGAIN;
        goto err1;
    }
    else if (size % PAGE_SIZE)
    {
        error("castle_back: you tried to map %ld bytes, not multiple of page size!\n", size);
        err = -EAGAIN;
        goto err1;
    }

    buffer = castle_zalloc(sizeof(struct castle_back_buffer), GFP_KERNEL);
    if (!buffer)
    {
        error("castle_back: failed to alloc memory for rb entry\n");
        err = -ENOMEM;
        goto err1;
    }

    debug("castle_buffer_map buffer=%p, size=%ld, vm_start=%lx, vm_end=%lx\n", buffer, size, vma->vm_start, vma->vm_end);
    
    vma->vm_flags |= VM_RESERVED;
    vma->vm_ops = &castle_back_vm_ops;

    buffer->user_addr = vma->vm_start;
    buffer->size = size;
    buffer->ref_count = 1;
    buffer->buffer = vmalloc(size);
    if (!buffer->buffer)
    {
        error("castle_back: failed to alloc memory for buffer\n");
        err = -ENOMEM;
        goto err2;
    }
    
    /* 
     * Add entry to our rb tree so we can find the buffer later 
     * there is only one mmap at once, so no worries about concurrency here
     */
    spin_lock(&conn->buffers_lock);
    if (__castle_back_buffer_exists(conn, vma->vm_start, vma->vm_end))
    {
        spin_unlock(&conn->buffers_lock);
        error("castle_back: mapping exists!\n");
        err = -EEXIST;
        goto err3;
    } 
    spin_unlock(&conn->buffers_lock);

    ReservePages(buffer->buffer, size);
    
    vma->vm_flags |= VM_DONTCOPY;
    
    err = castle_vma_map(vma, buffer->buffer, size);
    if (err)
    {
        error("castle_back: mapping failed!\n");
        goto err4;
    }
     
    spin_lock(&conn->buffers_lock);
    BUG_ON(castle_back_buffers_rb_insert(conn, vma->vm_start, &buffer->rb_node) != NULL);   
    spin_unlock(&conn->buffers_lock);
        
    debug("Create shared buffer kernel=%p, user=%lx, size=%u\n", 
        buffer->buffer, buffer->user_addr, buffer->size);
    
    return 0;

err4:
    UnReservePages(buffer->buffer, buffer->size);
err3:
    vfree(buffer->buffer);
err2:
    castle_free(buffer);
err1:
    return err;
}

static int castle_ring_map(struct castle_back_conn *conn, struct vm_area_struct *vma)
{
    unsigned long size;
    int err;

    size = vma->vm_end - vma->vm_start;
    if (size != CASTLE_RING_SIZE) 
    {
        error("castle_back: you _must_ map exactly %d bytes (you asked for %ld)!\n", 
            CASTLE_RING_SIZE, size);
        return -EAGAIN;
    }
    else if (vma->vm_start % PAGE_SIZE)
    {
        error("castle_back: you tried to map at addr %ld, not page aligned!\n", vma->vm_start);
        return -EAGAIN;
    }
    
    vma->vm_flags |= VM_RESERVED;
    // ring doesn't really need our VM ops
    // vma->vm_ops = &castle_vm_ops;
    
    conn->rings_vstart = vma->vm_start;
    
    err = castle_vma_map(vma, conn->back_ring.sring, CASTLE_RING_SIZE);
    if (err)
    {
        error("castle_back: mapping failed!\n");
        return err;
    }
            
    vma->vm_flags |= VM_DONTCOPY;
    
    return 0;
}

int castle_back_mmap(struct file *file, struct vm_area_struct *vma)
{
    int err;
    struct castle_back_conn *conn = file->private_data;
    if (conn == NULL) 
    {
        error("castle_back: castle, retrieving connection failed\n");
        return -EINVAL;
    }
    
    debug("castle_back_mmap mm->mmap_sem.activity=%d\n", vma->vm_mm->mmap_sem.activity);

    if(!test_and_set_bit(CASTLE_BACK_CONN_INITIALISED_BIT, &conn->flags))
    {
        err = castle_ring_map(conn, vma);
        if (err)
        {
            clear_bit(CASTLE_BACK_CONN_INITIALISED_BIT, &conn->flags);
            goto err_out;
        }
    }
    else
    {
        err = castle_buffer_map(conn, vma);
        if (err)
            goto err_out;
    }

    return 0;
    
err_out:
    return err;
}

int castle_back_init(void)
{
    int err;
    debug("castle_back initing...");
        
    /* TODO: use multithreaded wq, make sure queue_works don't happen concurrently */
	castle_back_wq = create_singlethread_workqueue("castle_back");
	if (!castle_back_wq)
	{
		error(KERN_ALERT "Error: Could not alloc wq\n");
		err = -ENOMEM;
		goto err1;
	}
	
	debug("done!\n");
	
    return 0;

    destroy_workqueue(castle_back_wq); /* unreachable */
err1: 
    return err;
}

void castle_back_fini(void)
{
    debug("castle_back exiting...");
    
    /*
     * don't need to wait for connections to close because won't get here
     * until they have all closed due to reference counting on the module
     */
    
    destroy_workqueue(castle_back_wq);

    debug("done!\n");
}
