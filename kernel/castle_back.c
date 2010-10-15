#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/completion.h>
#include <linux/wait.h>
#include <linux/workqueue.h>
#include <linux/mm.h>
#include <linux/miscdevice.h>
#include <linux/poll.h>
#include <linux/rbtree.h>
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

#define MAX_BUFFER_PAGES  (256)
#define MAX_BUFFER_SIZE   (MAX_BUFFER_PAGES << PAGE_SHIFT)

#define MAX_STATEFUL_OPS  (1024)

#define CASTLE_BACK_NAME  "castle-back"

#define USED              __attribute__((used))
#define error             printk

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)      ((void)0)
#define debug_iter(_f, ...) ((void)0)
#else
#define debug(_f, _a...)       (printk("%ld: " _f, jiffies, ##_a))
#define debug_iter(_f, _a...)  (printk("%ld: " _f, jiffies, ##_a))
#endif

struct proc_dir_entry          *castle_back_procfile = NULL;
static struct workqueue_struct *castle_back_wq;
static struct workqueue_struct *castle_back_stateful_op_wq;

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
    
    /* 
     * in kernel state for each operation 
     * should be RING_SIZE(back_ring) of these
     * and a free list to get new ones
     */
    struct castle_back_op           *ops;
    struct list_head                 free_ops;

    struct castle_back_stateful_op  *stateful_ops;
    struct list_head                 free_stateful_ops;
        
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
    uint64_t                  flags;
    c_vl_okey_t              *start_key;
    c_vl_okey_t              *end_key;
    c_vl_okey_t              *saved_key;
    c_val_tup_t               saved_val;
    castle_object_iterator_t *iterator;
};

struct castle_back_stateful_op
{
    struct list_head               list;
    /* token is calculated by index + use_count * MAX_STATEFUL_OPS where index is the
     * index in the stateful_ops array in the connection. So the index is calculated by
     * token % MAX_STATEFUL_OPS.  This means tokens are reused at most every 2^32/MAX_STATEFUL_OPS
     * calls so shouldn't get collisions.
     */
    castle_interface_token_t       token;
    /* use_count counts how many times this stateful op has been reused.
     * Wraps around on overflow.
     */
    uint32_t                       use_count;
    /* a check to see if this stateful_op is being used */
    int                            in_use;
    uint32_t                       tag;

    struct work_struct             work;
    struct list_head               op_queue;
    spinlock_t                     op_queue_lock;
    struct castle_back_conn       *conn;

    union
    {
        struct castle_back_iterator  iterator;
    };
};

/*
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

    node = conn->buffers_rb.rb_node;

    while (node)
    {
        buffer = rb_entry(node, struct castle_back_buffer, rb_node);

        //debug("Considering buffer (%lx, %ld, %p)\n", buffer->user_addr, 
        //    buffer->size, buffer->buffer);

        if (end < buffer->user_addr)
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
            debug("ref_count is now %d\n", buffer->ref_count);
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
    
    debug("castle_back_buffer_put ref_count=%i\n", buf->ref_count);

    buf->ref_count--;
    /* remove buffer from rb tree so no-one else can find it
       this allows us to free is outside the lock */
    if (buf->ref_count <= 0)
        rb_erase(&buf->rb_node, &conn->buffers_rb);

    debug("castle_back_buffer_put ref_count=%i\n", buf->ref_count);

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
    struct rb_node **p = &conn->buffers_rb.rb_node;
    struct rb_node *parent = NULL;
    struct castle_back_buffer *buffer;

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

/*
 * ops for dealing with the stateful ops pool
 */

static struct castle_back_stateful_op *castle_back_find_stateful_op(struct castle_back_conn *conn,
                                                                    castle_interface_token_t token)
{
    struct castle_back_stateful_op *op = conn->stateful_ops + (token % MAX_STATEFUL_OPS);
    BUG_ON(!op);

    if (!op->in_use || op->token != token)
        return NULL;

    debug("castle_back_find_stateful_op returning: token = %x\n use_count = %u\n index = %ld\n", 
        op->token, op->use_count, op - conn->stateful_ops);

    return op;
}

/* *op_ptr is NULL if there are no free ones */
static castle_interface_token_t 
castle_back_get_stateful_op(struct castle_back_conn *conn,
                            struct castle_back_stateful_op **op_ptr)
{
    struct castle_back_stateful_op *op;

    spin_lock(&conn->response_lock);
    if (list_empty(&conn->free_stateful_ops))
    {
        spin_unlock(&conn->response_lock);
        *op_ptr = NULL;
        return 0;
    }
    op = list_entry(conn->free_stateful_ops.next, struct castle_back_stateful_op, list);
    list_del(&op->list);
    spin_unlock(&conn->response_lock);

    debug("castle_back_get_stateful_op got op: in_use = %d\n token = %u\n use_count = %u\n index = %ld\n", 
        op->in_use, op->token, op->use_count, op - conn->stateful_ops);

    BUG_ON(op->in_use);

    /* see def of castle_back_stateful_op */
    op->in_use = 1;
    op->token = (op - conn->stateful_ops) + (op->use_count * MAX_STATEFUL_OPS);
    op->use_count++;
    op->conn = conn;

    INIT_LIST_HEAD(&op->op_queue);
    spin_lock_init(&op->op_queue_lock);

    *op_ptr = op;

    return op->token;
}

static void castle_back_put_stateful_op(struct castle_back_conn *conn,
                                        struct castle_back_stateful_op *op)
{
    debug("castle_back_put_stateful_op putting: token = %x\n use_count = %u\n index = %ld\n", 
        op->token, op->use_count, op - conn->stateful_ops);

    BUG_ON(!op->in_use);
    op->in_use = 0;

    /* Put op back on freelist */
    spin_lock(&conn->response_lock);
    list_add_tail(&op->list, &conn->free_stateful_ops);
    spin_unlock(&conn->response_lock);
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
    
    debug("castle_back_vm_close buf=%p, size=%d, vm_end=%lx, vm_start=%lx\n", 
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
            error("Bad pointer %p (out of buffer, start=%lu, length=%u)\n", 
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
                                           size_t *buf_used)
{
    size_t length;
    struct castle_iter_val *val_copy;

    BUG_ON(val->type != CVT_TYPE_INLINE);

    length = sizeof(struct castle_iter_val) + val->length;

    if (buf_len < length)
    {
        *buf_used = 0;
        return;
    }

    val_copy = (struct castle_iter_val *)castle_back_user_to_kernel(buf, user_buf);

    val_copy->type = val->type;
    val_copy->length = val->length;
    val_copy->val = (uint8_t *)(user_buf + sizeof(struct castle_iter_val));
    memcpy((uint8_t *)castle_back_user_to_kernel(buf, val_copy->val), val->val, val->length);

    *buf_used = length;
}

static void castle_back_replace_complete(struct castle_object_replace *replace, int err)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);

    debug("castle_back_replace_complete\n");

    castle_back_buffer_put(op->conn, op->buf);

    castle_back_reply(op, err, 0, 0);
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
    
    // TODO should we ref count attachments?
    attachment = castle_collection_find(op->req.replace.collection_id);
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
}

static void castle_back_remove_complete(struct castle_object_replace *replace, int err)
{
    struct castle_back_op *op = container_of(replace, struct castle_back_op, replace);

    debug("castle_back_remove_complete\n");

    castle_back_buffer_put(op->conn, op->buf);

    castle_back_reply(op, err, 0, 0);
}

static void castle_back_remove(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    
    // TODO should we ref count attachments?
    attachment = castle_collection_find(op->req.replace.collection_id);
    if (attachment == NULL)
    {
        error("Collection not found id=%x\n", op->req.replace.collection_id);
        err = -EINVAL;
        goto err0;
    }

    err = castle_back_key_copy_get(conn, op->req.replace.key_ptr, op->req.replace.key_len, &key);
    if (err)
        goto err0;

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
        return;
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
    }
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
}

static void castle_back_get(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    
    // TODO should we ref count attachments?
    attachment = castle_collection_find(op->req.get.collection_id);
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
}

static void castle_back_iter_next(struct work_struct *work);

static void castle_back_iter_start(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_attachment *attachment;
    c_vl_okey_t *start_key;
    c_vl_okey_t *end_key;
    castle_interface_token_t token;
    struct castle_back_stateful_op *stateful_op;

    debug_iter("castle_back_iter_start\n");

    // TODO should we ref count attachments
    attachment = castle_collection_find(op->req.iter_start.collection_id);
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
        err = -EAGAIN;
        goto err2;
    }
    stateful_op->tag = CASTLE_RING_ITER_START;

    err = castle_object_iter_start(attachment, start_key, end_key, &stateful_op->iterator.iterator);
    if (err)
        goto err3;

    stateful_op->iterator.flags = op->req.iter_start.flags;
    stateful_op->iterator.saved_key = NULL;
    stateful_op->iterator.start_key = start_key;
    stateful_op->iterator.end_key = end_key;

    CASTLE_INIT_WORK(&stateful_op->work, castle_back_iter_next);

    castle_back_reply(op, 0, token, 0);

    /* TODO: add timeout to cleanup iterator if client goes away */

    return;

err3:
    castle_back_put_stateful_op(conn, stateful_op);
err2:
    castle_free(end_key);
err1:
    castle_free(start_key);
err0:
    castle_back_reply(op, err, 0, 0);
}

static void castle_back_iter_next(struct work_struct *work)
{
    int err;
    struct castle_back_op *op;
    struct castle_back_stateful_op *stateful_op;
    struct castle_back_conn *conn;
    struct castle_key_value_list *kv_list_head;
    struct castle_key_value_list *kv_list_prev;
    struct castle_key_value_list *kv_list_cur;
    castle_object_iterator_t *iterator;
    size_t buf_used;
    size_t buf_used_up_to_last;
    size_t buf_len;
    c_vl_okey_t *key;
    c_val_tup_t  val;
    size_t key_len;
    size_t val_len;

    debug_iter("castle_back_iter_next\n");

    stateful_op = container_of(work, struct castle_back_stateful_op, work);
    conn = stateful_op->conn;

    /* loop for each op on the op queue for this stateful op */
    while (1)
    {
        spin_lock(&stateful_op->op_queue_lock);
        if (list_empty(&stateful_op->op_queue))
        {
            spin_unlock(&stateful_op->op_queue_lock);
            break;
        }
        op = list_first_entry(&stateful_op->op_queue, struct castle_back_op, list);
        list_del(&op->list);
        spin_unlock(&stateful_op->op_queue_lock);

        if (op->req.iter_next.buffer_len < PAGE_SIZE)
        {
            error("castle_back_iter_next buffer_len smaller than a page\n");
            err = -EINVAL;
            goto err0;
        }

        if (stateful_op->tag != CASTLE_RING_ITER_START)
        {
            error("Token %x does not correspond to an iterator\n", op->req.iter_next.token);
            err = -EINVAL;
            goto err0;
        }

        iterator = stateful_op->iterator.iterator;

        /*
         * Get buffer with value in it and save it
         */
        op->buf = castle_back_buffer_get(conn, (unsigned long)op->req.iter_next.buffer_ptr);
        if (op->buf == NULL)
        {
            err = -EINVAL;
            goto err1;
        }

        kv_list_head = castle_back_user_to_kernel(op->buf, op->req.iter_next.buffer_ptr);
        kv_list_head->next = NULL;
        kv_list_head->key = NULL;
        kv_list_cur = kv_list_head;
        kv_list_prev = NULL;
        buf_used = 0;
        buf_used_up_to_last = 0;
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

            buf_used += sizeof(struct castle_key_value_list);
            if (buf_used >= buf_len)
            {
                error("iterator buffer too small\n");
                err = -EINVAL;
                goto err2;
            }

            kv_list_cur->key = (c_vl_okey_t *) castle_back_kernel_to_user(op->buf, 
                (unsigned long)kv_list_head + buf_used);
            castle_back_key_kernel_to_user(stateful_op->iterator.saved_key, op->buf, 
                (unsigned long)kv_list_cur->key, buf_len - buf_used, &key_len);
            /* we should be able to fit the key in by assumption of sizes */
            buf_used += key_len;
            if (key_len == 0)
            {
                error("iterator buffer too small\n");
                err = -EINVAL;
                goto err2;
            }

            if (stateful_op->iterator.flags & CASTLE_RING_ITER_FLAG_NO_VALUES)
                kv_list_cur->val = NULL;
            else
            {
                kv_list_cur->val = (struct castle_iter_val *)
                    ((unsigned long)kv_list_cur->key + key_len);
                castle_back_val_kernel_to_user(&stateful_op->iterator.saved_val, op->buf, 
                    (unsigned long)kv_list_cur->val, buf_len - buf_used, &val_len);
                buf_used += val_len;
                if (val_len == 0)
                {
                    error("iterator buffer too small\n");
                    err = -EINVAL;
                    goto err2;
                }
            }

            castle_object_okey_free(stateful_op->iterator.saved_key);
            /* we copied it so free it */
            castle_free(stateful_op->iterator.saved_val.val);

            kv_list_prev = kv_list_cur;
            kv_list_cur = (struct castle_key_value_list *)((unsigned long)kv_list_head + buf_used);

            debug_iter("iter_next added saved key\n");

            stateful_op->iterator.saved_key = NULL;
        }

        while (1)
        {
            buf_used += sizeof(struct castle_key_value_list);
            if (buf_used >= buf_len)
                break;

            err = castle_object_iter_next(iterator, &key, &val);
            if (err)
                goto err2;

            /* there are no more keys */
            if (key == NULL)
                break;

            if (val.type != CVT_TYPE_INLINE)
            {
                debug_iter("ignoring not inlined value, type %d, length %u\n", val.type, val.length);
                castle_object_okey_free(key);
                continue;
            }

            kv_list_cur->key = (c_vl_okey_t *) castle_back_kernel_to_user(op->buf, 
                (unsigned long)kv_list_head + buf_used);
            castle_back_key_kernel_to_user(key, op->buf, (unsigned long)kv_list_cur->key, 
                buf_len - buf_used, &key_len);
            if (key_len == 0)
                break;
            buf_used += key_len;

            if (stateful_op->iterator.flags & CASTLE_RING_ITER_FLAG_NO_VALUES)
                kv_list_cur->val = NULL;
            else
            {
                kv_list_cur->val = (struct castle_iter_val *)
                    ((unsigned long)kv_list_cur->key + key_len);
                castle_back_val_kernel_to_user(&val, op->buf, (unsigned long)kv_list_cur->val, 
                    buf_len - buf_used, &val_len);
                if (val_len == 0)
                    break;
                buf_used += val_len;
            }

            castle_object_okey_free(key);
            /* don't free the value; it is freed when purged from the cache */

            if (kv_list_prev)
                kv_list_prev->next = (struct castle_key_value_list *) 
                    castle_back_kernel_to_user(op->buf, kv_list_cur);

            kv_list_prev = kv_list_cur;
            kv_list_cur = (struct castle_key_value_list *)((unsigned long)kv_list_head + buf_used);

            buf_used_up_to_last = buf_used;

            key = NULL;
        }

        if (kv_list_prev)
            kv_list_prev->next = NULL;

        if (key != NULL)
        {
            debug_iter("not enough space on buffer, saving a key for next time...\n");
            stateful_op->iterator.saved_key = key;
            stateful_op->iterator.saved_val = val;
            /* copy the value since it may get removed from the cache */
            stateful_op->iterator.saved_val.val = 
                castle_malloc(stateful_op->iterator.saved_val.length, GFP_KERNEL);
            memcpy(stateful_op->iterator.saved_val.val, val.val, 
                stateful_op->iterator.saved_val.length);
        }

        castle_back_reply(op, 0, 0, 0);

        castle_back_buffer_put(conn, op->buf);
    }

    return;

err2:
    castle_back_buffer_put(conn, op->buf);
err1:
    castle_back_put_stateful_op(conn, stateful_op);
err0:
    castle_back_reply(op, err, 0, 0);
}

static void castle_back_iter_finish(struct castle_back_conn *conn, struct castle_back_op *op)
{
    int err;
    struct castle_back_stateful_op *stateful_op;

    debug_iter("castle_back_iter_finish, token = %x\n", op->req.iter_finish.token);

    stateful_op = castle_back_find_stateful_op(conn, op->req.iter_finish.token);

    if (!stateful_op)
    {
        error("Token not found %x\n", op->req.iter_finish.token);
        err = -EINVAL;
        goto err0;
    }

    if (stateful_op->tag != CASTLE_RING_ITER_START)
    {
        error("Token %x does not correspond to an iterator\n", op->req.iter_next.token);
        err = -EINVAL;
        goto err0;
    }

    if (stateful_op->iterator.saved_key != NULL)
    {
        castle_object_okey_free(stateful_op->iterator.saved_key);
        castle_free(stateful_op->iterator.saved_val.val);
    }

    castle_free(stateful_op->iterator.start_key);
    castle_free(stateful_op->iterator.end_key);

    err = castle_object_iter_finish(stateful_op->iterator.iterator);
    if (err)
        goto err1;

    castle_back_put_stateful_op(conn, stateful_op);

    castle_back_reply(op, 0, 0, 0);
    return;

err1:
    castle_back_put_stateful_op(conn, stateful_op);
err0:
    castle_back_reply(op, err, 0, 0);
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

static void castle_back_queue_stateful_work(struct castle_back_conn *conn, 
                                            struct castle_back_op *op,
                                            castle_interface_token_t token, 
                                            void callback(struct work_struct *))
{
    int err;
    struct castle_back_stateful_op *stateful_op;

    stateful_op = castle_back_find_stateful_op(conn, token);

    if (!stateful_op)
    {
        error("Token not found %x\n", token);
        err = -EINVAL;
        goto err0;
    }

    spin_lock(&stateful_op->op_queue_lock);
    list_add_tail(&op->list, &stateful_op->op_queue);
    spin_unlock(&stateful_op->op_queue_lock);

    queue_work(castle_back_stateful_op_wq, &stateful_op->work);

    return;

err0:
    castle_back_reply(op, err, 0, 0);
}

static void castle_back_request_process(struct castle_back_conn *conn, struct castle_back_op *op)
{
    //debug("Got a request call=%d tag=%d\n", req->call_id, req->tag);
    
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

        case CASTLE_RING_ITER_NEXT:
            castle_back_queue_stateful_work(conn, op, op->req.iter_next.token, 
                castle_back_iter_next);
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
            
            castle_back_request_process(conn, op);
        }
    
        RING_FINAL_CHECK_FOR_REQUESTS(back_ring, more);
        if(!more) break;
    }
    
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
    }

    file->private_data = conn;

    return 0;

// TODO clean up waitqueues etc?

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

static void castle_back_cleanup(void *data)
{
    struct castle_back_conn *conn = data;
    //struct rb_node *node;
    //struct castle_back_buffer *buf;
    BUG_ON(conn == NULL);
    
    debug("castle_back_cleanup\n");
    
    UnReservePages(conn->back_ring.sring, CASTLE_RING_SIZE);
    vfree(conn->back_ring.sring);
    vfree(conn->ops); // TODO: ref count ops
    vfree(conn->stateful_ops);
    
    /*
     * We don't clean up buffers (buffer_put does that),
     * but we should wait until they have all gone away
     */
    
    castle_free(conn);
    module_put(THIS_MODULE);

    debug("castle_back_cleanup done\n");
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
	
	/* TODO: use multithreaded wq, make sure queue_works don't happen concurrently */
	castle_back_stateful_op_wq = create_singlethread_workqueue("castle_back_stateful_op");
	if (!castle_back_stateful_op_wq)
    {
        error(KERN_ALERT "Error: Could not alloc stateful op wq\n");
        err = -ENOMEM;
        goto err2;
    }

	debug("done!\n");
	
    return 0;

    destroy_workqueue(castle_back_stateful_op_wq); /* unreachable */
err2:
    destroy_workqueue(castle_back_wq);
err1: 
    return err;
}

void castle_back_fini(void)
{
    debug("castle_back exiting...");
    
    // TODO do something about the outstanding connections?
    
    destroy_workqueue(castle_back_wq);
    
    destroy_workqueue(castle_back_stateful_op_wq);

    debug("done!\n");
}
