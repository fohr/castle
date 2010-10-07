#define __OPTIMIZE__
#include <linux/kthread.h>
#include <linux/bio.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <net/sock.h>
#include <linux/rxrpc.h>
#include <net/af_rxrpc.h>
#include <linux/errqueue.h>
#include <rxrpc/packet.h>
#include <linux/sched.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"
#include "castle_debug.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_rxrpc.h"
#include "castle_ctrl.h"
#include "castle_objects.h"
#include "castle_freespace.h"
#include "castle_versions.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

/* Forward definitions */
struct castle_rxrpc_call;
static const struct castle_rxrpc_call_type castle_rxrpc_op_call;
static const struct castle_rxrpc_call_type castle_rxrpc_get_call;
static const struct castle_rxrpc_call_type castle_rxrpc_replace_call;
static const struct castle_rxrpc_call_type castle_rxrpc_replace_multi_call;
static const struct castle_rxrpc_call_type castle_rxrpc_slice_call;
static const struct castle_rxrpc_call_type castle_rxrpc_ctrl_call;
static void castle_rxrpc_reply_send       (struct castle_rxrpc_call *call, 
                                           const void *buf, size_t len, int last);
static void castle_rxrpc_double_reply_send(struct castle_rxrpc_call *call, 
                                           const void *buf1, size_t len1,
                                           const void *buf2, size_t len2,
                                           int last);

static struct socket            *socket;
static struct workqueue_struct  *rxrpc_wq;          /* <s>Need singlethreaded WQs,
                                                       because individual calls handling
                                                       is not multithread safe. Collection
                                                       of queues will alow concurrency
                                                       between calls through.</s> - using queue_work_on now */
static struct sk_buff_head       rxrpc_incoming_calls;
static void castle_rxrpc_incoming_call_collect(struct work_struct *work);
static CASTLE_DECLARE_WORK(castle_rxrpc_incoming_call_work, castle_rxrpc_incoming_call_collect);

/* Wait Queue to delay module exit (rmmod) till all outstanding requests are over */
static DECLARE_WAIT_QUEUE_HEAD(castle_rxrpc_rmmod_wq); 
static atomic_t castle_outst_call_cnt = ATOMIC_INIT(0);

struct castle_rxrpc_call_type {
    /* Deliver packet to this call type. Deliver should consume ENTIRE packet, 
       free it using rxrpc_kernel_data_delivered() */
    char  *name;
    int  (*deliver)    (struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last);
    void (*destructor) (struct castle_rxrpc_call *call);
};

struct castle_rxrpc_call {
    struct work_struct             work;
    int                            cpu;
    unsigned long                  call_id;
    struct rxrpc_call             *rxcall;
    struct sk_buff_head            rx_queue;    /* Queue of packets for this call */
    struct sk_buff                *current_skb; /* Set when packet is processed asynchronously */

    int                            op_id;
    const struct castle_rxrpc_call_type *type;
    volatile enum {
        /* Copied from AFS */
        RXRPC_CALL_AWAIT_OP_ID,   /* awaiting op ID on incoming call */
        RXRPC_CALL_AWAIT_REQUEST, /* awaiting request data on incoming call */
        RXRPC_CALL_AWAIT_DATA,    /* for large requests, awaiting more data */
        RXRPC_CALL_REPLYING,      /* replying to incoming call */
        RXRPC_CALL_AWAIT_ACK,     /* awaiting final ACK of incoming call */
        RXRPC_CALL_COMPLETE,      /* successfully completed */
        RXRPC_CALL_BUSY,          /* server was busy */
        RXRPC_CALL_ABORTED,       /* call was aborted */
        RXRPC_CALL_ERROR,         /* call failed due to error */
    }                              state;
    int                            error;
    int                            packet_cnt;
    /* Extra information needed by various types of calls */
    union
    {
        /* For CASTLE_OBJ_REQ_GET */
        struct castle_object_get get;
        /* For CASTLE_OBJ_REQ_REPLACE */
        struct castle_object_replace replace;
        /* For CASTLE_OBJ_REQ_REPLACE_MULTI */
        struct {
            char       *buf;
            uint32_t    buf_offset;
            uint32_t    buf_length;
            uint32_t    num_objects;
            uint32_t    objects_processed;
            struct castle_attachment *attachment;
        } replace_multi;
    };
};

static void castle_rxrpc_state_update(struct castle_rxrpc_call *call, int state)
{
    /* AWAIT_DATA -> AWAIT_REQUEST is allowed */
    if((state < call->state) && 
      !((state == RXRPC_CALL_AWAIT_REQUEST) && (call->state == RXRPC_CALL_AWAIT_DATA)))
    {
        printk("Asked to update state backwards: %d->%d\n", call->state, state);
        BUG();
    }
    call->state = state;
    /* Make sure that the change is visible from other threads.
       This is (especially) important for RXRPC_CALL_AWAIT_ACK which 
       is set from some da/btree wq, but read by rxrpc processors */
    mb();
}

uint64_t get_cnt, replace_cnt, replace_multi_cnt, slice_cnt, ctrl_cnt, call_cnt;

/* Definition of different call types */
static int castle_rxrpc_op_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    if(skb->len < 4)
        return -EBADMSG;

#ifdef DEBUG    
    printk("\n Got following RxRPC packet:\n");
    skb_print(skb);
#endif

    castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_REQUEST);
    call->op_id = SKB_L_GET(skb);
    debug("op id: %d\n", call->op_id);

    switch(call->op_id)
    {
        case CASTLE_OBJ_REQ_GET:
            call->type = &castle_rxrpc_get_call;
            get_cnt++;
            break;
        case CASTLE_OBJ_REQ_REPLACE:
            call->type = &castle_rxrpc_replace_call;
            replace_cnt++;
            break;
        case CASTLE_OBJ_REQ_REPLACE_MULTI:
            call->type = &castle_rxrpc_replace_multi_call;
            replace_multi_cnt++;
            break;
        case CASTLE_OBJ_REQ_SLICE:
            call->type = &castle_rxrpc_slice_call;
            slice_cnt++;
            break;
        case CASTLE_CTRL_REQ:
            call->type = &castle_rxrpc_ctrl_call;
            ctrl_cnt++;
            break;
        default:
            return -ENOTSUPP;
    }
    call_cnt++;
#ifdef DEBUG
    if (call_cnt % 500 == 0)
    {
        printk("\n");
        printk("     Get          : %10llu\n", get_cnt);
        printk("     Replace      : %10llu\n", replace_cnt);
        printk("     Replace multi: %10llu\n", replace_multi_cnt);
        printk("     Slice        : %10llu\n", slice_cnt);
        printk("     Ctrl         : %10llu\n", ctrl_cnt);
        printk("---------------------------------------\n");
        printk(" Total no of calls: %10llu\n", call_cnt);
        printk("---------------------------------------\n");
    }
#endif

    return call->type->deliver(call, skb, last);
}

#define BUFFER_PUT(_value, _value_len)                                          \
({                                                                              \
    uint32_t _pad_len;                                                          \
                                                                                \
    /* Work out how much pading do we need */                                   \
    _pad_len = (_value_len % 4 == 0 ? 0 : 4 - _value_len % 4);                  \
    if(buffer_len < _value_len + _pad_len)                                      \
        return 1;                                                               \
    /* Copy the value in */                                                     \
    memcpy(buffer, _value, _value_len);                                         \
    /* Copy the pad in */                                                       \
    memcpy(buffer + _value_len, &pad, _pad_len);                                \
    *buffer_used += _value_len + _pad_len;                                      \
     buffer_len  -= _value_len + _pad_len;                                      \
     buffer      += _value_len + _pad_len;                                      \
})
    

int castle_rxrpc_get_slice_reply_marshall(struct castle_rxrpc_call *call,
                                          c_vl_okey_t *k,
                                          char *value,
                                          uint32_t value_len,
                                          char *buffer,
                                          uint32_t buffer_len,
                                          uint32_t *buffer_used)
{
    uint32_t pad = 0;
    uint32_t rsp_val;
    int i;

    /* There has to be some space in the buffer, otherwise this function shouldn't be called */
    BUG_ON(buffer_len < 4);
    *buffer_used = 0;
    /* Key has to be marshalled first. Number of dimensions should be written out first. */
    rsp_val = htonl(k->nr_dims);
    BUFFER_PUT(&rsp_val, 4);
    /* Next, write out each dimension */
    for(i=0; i<k->nr_dims; i++)
    {
        /* Write the length of the key */
        rsp_val = htonl(k->dims[i]->length);
        BUFFER_PUT(&rsp_val, 4);
        /* Write the key itself */
        BUFFER_PUT(k->dims[i]->key, k->dims[i]->length); 
    }
    /* All keys written out, write out the value itself */
    rsp_val = htonl(CASTLE_OBJ_VALUE);
    BUFFER_PUT(&rsp_val, 4);
    rsp_val = htonl(value_len);
    BUFFER_PUT(&rsp_val, 4);
    BUFFER_PUT(value, value_len); 

    return 0;
}

static void inline castle_rxrpc_call_reply_continue(struct castle_rxrpc_call *call,
                                                    int err,
                                                    void *buffer,
                                                    uint32_t buffer_length,
                                                    int last)
{
    /* Deal with errors first (this will basically advance the state to AWAIT_ACK) */
    if(err)
    {
        castle_rxrpc_reply_send(call, NULL, 0, 1 /* last */);
        return;
    }

    /* Otherwise send the buffer through */ 
    castle_rxrpc_reply_send(call, buffer, buffer_length, last);
}

void castle_rxrpc_get_slice_reply_start(struct castle_rxrpc_call *call,
                                        int err,
                                        int nr_vals,
                                        char *buffer,
                                        uint32_t buffer_len,
                                        int last)
{
    uint32_t reply[2];
    
    /* Deal with errors first */
    if(err)
    {   
        reply[0] = htonl(CASTLE_OBJ_REPLY_ERROR);
        castle_rxrpc_reply_send(call, reply, 4, 1 /* last */);
        return;
    }

    /* Otherwise return the buffered reply message */
    reply[0] = htonl(CASTLE_OBJ_REPLY_GET_SLICE);
    reply[1] = htonl(nr_vals);

    castle_rxrpc_double_reply_send(call, 
                                   reply, 8,
                                   buffer, buffer_len,
                                   last);
    return;
}

void castle_rxrpc_get_slice_reply_continue(struct castle_rxrpc_call *call,
                                           char *buffer,
                                           uint32_t buffer_len,
                                           int last)
{
    castle_rxrpc_call_reply_continue(call, 0, buffer, buffer_len, last); 
}

void castle_rxrpc_get_reply_start(struct castle_object_get *get, 
                                  int err, 
                                  uint32_t data_length,
                                  void *buffer, 
                                  uint32_t buffer_length)
{
    struct castle_rxrpc_call *call = container_of(get, struct castle_rxrpc_call, get);
    uint32_t reply[3];
  
    debug("castle_rxrpc_get_reply_start call=%p get=%p\n", call, get);
  
    /* Deal with errors first */
    if(err)
    {
        reply[0] = htonl(CASTLE_OBJ_REPLY_ERROR);
        castle_rxrpc_reply_send(call, reply, 4, 1 /* last */);
        return;
    }

    reply[0] = htonl(CASTLE_OBJ_REPLY_GET);
    /* Deal with tombstones next */
    if(!buffer)
    {
        BUG_ON((data_length != 0) || (buffer_length != 0));
        reply[1] = htonl(CASTLE_OBJ_TOMBSTONE);
        castle_rxrpc_reply_send(call, reply, 8, 1 /* last */);
        return;
    }
    
    /* Finally, deal with full values */
    reply[1] = htonl(CASTLE_OBJ_VALUE);
    /* Write out the entire data length, but send buffer_length worth of stuff now */
    reply[2] = htonl(data_length);

    castle_rxrpc_double_reply_send(call, 
                                   reply, 12,
                                   buffer, buffer_length,
                                  (data_length == buffer_length));
}


void castle_rxrpc_get_reply_continue(struct castle_object_get *get,
                                     int err,
                                     void *buffer,
                                     uint32_t buffer_length,
                                     int last)
{
    struct castle_rxrpc_call *call = container_of(get, struct castle_rxrpc_call, get);
    
    debug("castle_rxrpc_get_reply_continue call=%p get=%p\n", call, get);
    
    castle_rxrpc_call_reply_continue(call, err, buffer, buffer_length, last); 
}

void castle_rxrpc_replace_complete(struct castle_object_replace *op, int err)
{
    struct castle_rxrpc_call *call = container_of(op, struct castle_rxrpc_call, replace);
    uint32_t reply[1];

    debug("Replace complete for call=%p\n", call); 
    rxrpc_kernel_data_delivered(call->current_skb);
    castle_rxrpc_state_update(call, RXRPC_CALL_REPLYING);

    if(err)
        reply[0] = htonl(CASTLE_OBJ_REPLY_ERROR);
    else
        reply[0] = htonl(CASTLE_OBJ_REPLY_REPLACE);

    castle_rxrpc_reply_send(call, reply, 4, 1 /* last */);
}

void castle_rxrpc_call_continue(struct castle_rxrpc_call *call)
{
    debug("Continuing call type \"%s\" (checking for more packets on the queue).\n",
            call->type->name);
    rxrpc_kernel_data_delivered(call->current_skb);
    /* Go back in the state, because otherwise packet_process() will ignore us. */
    castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_REQUEST);
    if(!skb_queue_empty(&call->rx_queue));
    {
        debug("Queueing packet process.\n");
        queue_work_on(call->cpu, rxrpc_wq, &call->work);
    }
}

void castle_rxrpc_replace_continue(struct castle_object_replace *op)
{
    struct castle_rxrpc_call *call = container_of(op, struct castle_rxrpc_call, replace);
    castle_rxrpc_call_continue(call);
}

void castle_rxrpc_replace_multi_complete(struct castle_rxrpc_call *call, int err)
{
    uint32_t reply[1];

    BUG_ON(!call->replace_multi.buf);
    castle_free(call->replace_multi.buf);

    debug("Call=%p\n", call);
    rxrpc_kernel_data_delivered(call->current_skb);
    castle_rxrpc_state_update(call, RXRPC_CALL_REPLYING);

    if(err)
        reply[0] = htonl(CASTLE_OBJ_REPLY_ERROR);
    else
        reply[0] = htonl(CASTLE_OBJ_REPLY_REPLACE);

    castle_rxrpc_reply_send(call, reply, 4, 1 /* last */);
}

void castle_rxrpc_replace_multi_continue(struct castle_rxrpc_call *call)
{
    castle_rxrpc_call_continue(call);
}

uint32_t castle_rxrpc_packet_length(struct castle_rxrpc_call *call)
{
    return call->current_skb->len;
}

uint32_t castle_rxrpc_replace_packet_length(struct castle_object_replace *op)
{
    struct castle_rxrpc_call *call = container_of(op, struct castle_rxrpc_call, replace);
    return castle_rxrpc_packet_length(call);
}

void castle_rxrpc_str_copy(struct castle_rxrpc_call *call, void *buffer, int str_length, int partial)
{
    SKB_STR_CPY(call->current_skb, buffer, str_length, !partial);
}

void castle_rxrpc_replace_str_copy(struct castle_object_replace *op, void *buffer, int str_length, int partial)
{
    struct castle_rxrpc_call *call = container_of(op, struct castle_rxrpc_call, replace); 
    castle_rxrpc_str_copy(call, buffer, str_length, partial);
}

uint32_t castle_rxrpc_uint32_get_buf(struct castle_rxrpc_call *call)
{
    uint32_t val;

    BUG_ON(call->replace_multi.buf_length - call->replace_multi.buf_offset < 4);
    val = BUF_L_GET(call->replace_multi.buf + call->replace_multi.buf_offset);
    call->replace_multi.buf_offset += 4;
    return val;
}

static inline int castle_rxrpc_rounded_length(uint32_t len)
{
    return len + (len % 4 == 0 ? 0 : - len % 4);
}

void castle_rxrpc_str_copy_buf(struct castle_rxrpc_call *call, void *buffer, int str_length, int partial)
{
    BUG_ON(call->replace_multi.buf_length - call->replace_multi.buf_offset < str_length);
    memcpy(buffer, call->replace_multi.buf + call->replace_multi.buf_offset, str_length);
    if(!partial)
        str_length = castle_rxrpc_rounded_length(str_length);
    call->replace_multi.buf_offset += str_length;
}

/* Returns negative on error, positive return is amount of data read, 
   0 if there was not enough data. */
static int castle_rxrpc_key_get_check(const char *buf,
                                      uint32_t buf_length,
                                      c_vl_okey_t **key_p)
{
    c_vl_okey_t *key;
    uint32_t nr_dims, i;
    int ret;
    uint32_t buf_offset = 0;

    if(buf_length < 4)
        return 0;

    nr_dims = BUF_L_GET(buf);
    buf_offset += 4;

    key = castle_zalloc(sizeof(c_vl_okey_t) + sizeof(c_vl_key_t *) * nr_dims, GFP_KERNEL);
    if(!key)
        return -ENOMEM;

    /* Init the key */
    key->nr_dims = nr_dims;
    for(i=0; i<nr_dims; i++)
    {
        uint32_t key_len;
        uint32_t rounded_key_len;

        if(buf_length - buf_offset < 4)
        {
            ret = 0;
            goto clean_up;
        }
        key_len = BUF_L_GET(buf + buf_offset);
        buf_offset += 4;

        rounded_key_len = castle_rxrpc_rounded_length(key_len);

        if(buf_length - buf_offset < rounded_key_len)
        {
            ret = 0;
            goto clean_up;
        }

        if(key_len > 128 || !(key->dims[i] = castle_zalloc(key_len+4, GFP_KERNEL)))
        {
            ret = -ENOMEM;
            goto clean_up;
        }

        key->dims[i]->length = key_len;
        memcpy(&key->dims[i]->key, buf + buf_offset, key_len);
        buf_offset += rounded_key_len;
    }
    *key_p = key;

    return buf_offset;

clean_up:
    while (i > 0)
        castle_free(key->dims[--i]);
    castle_free(key);

    return ret;
}

static int castle_rxrpc_collection_get(struct sk_buff *skb,
                                       struct castle_attachment **attachment_p)
{
    struct castle_attachment *ca;

    ca = castle_collection_find(SKB_L_GET(skb));
    *attachment_p = ca;

    return (ca == NULL) ? -EINVAL : 0;
}
    
static int castle_rxrpc_key_get(struct sk_buff *skb,
                                c_vl_okey_t **key_p)
{
    uint32_t nr_dims, i;
    c_vl_okey_t *key;

    nr_dims = SKB_L_GET(skb);
    key = castle_zalloc(sizeof(c_vl_okey_t) + sizeof(c_vl_key_t *) * nr_dims, GFP_KERNEL);
    if(!key)
        return -ENOMEM;

    /* Init the key */
    key->nr_dims = nr_dims;
    for(i=0; i<nr_dims; i++)
    {
        key->dims[i] = SKB_VL_KEY_GET(skb, 128);
        if(!key->dims[i])
        {
            while (i > 0)
                castle_free(key->dims[--i]);
            castle_free(key);

            return -ENOMEM;
        }
    }

    *key_p = key;

    return 0;
}

static int castle_rxrpc_collection_key_get(struct sk_buff *skb, 
                                           struct castle_attachment **attachment_p,
                                           c_vl_okey_t **key_p)
{
    int ret;

    ret = castle_rxrpc_collection_get(skb, attachment_p);
    if(ret)
        return ret;

    ret = castle_rxrpc_key_get(skb, key_p);
    if(ret)
        return ret;

    return 0;
}

static int castle_rxrpc_get_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    int ret;

    ret = castle_rxrpc_collection_key_get(skb, &attachment, &key);
    if(ret)
        goto out;

    debug("castle_rxrpc_get_decode call=%p get=%p\n", call, &call->get);

    call->get.reply_start = castle_rxrpc_get_reply_start;
    call->get.reply_continue = castle_rxrpc_get_reply_continue;

    ret = castle_object_get(&call->get, attachment, key);
    castle_object_okey_free(key);
    if(ret)
        goto out;

out:
    rxrpc_kernel_data_delivered(skb);
    castle_rxrpc_state_update(call, RXRPC_CALL_REPLYING);
    if(ret)
        castle_rxrpc_get_reply_start(&call->get, ret, -1, NULL, -1);

    return 0;
}
 
static int castle_rxrpc_replace_decode(struct castle_rxrpc_call *call, struct sk_buff *skb, bool last)
{
    struct castle_attachment *attachment;
    c_vl_okey_t *key;
    uint32_t value_len, is_tombstone;
    int ret;
#ifdef DEBUG
    static int cnt = 0;
    
    if((cnt++) % 100 == 0)
       debug("Got %d replaces\n", cnt);
#endif

    debug("Packed %d in replace, is it last=%d\n", call->packet_cnt, last);
    call->current_skb = skb;
    /* First packet processing */
    if(call->packet_cnt == 1)
    {
        ret = castle_rxrpc_collection_key_get(skb, &attachment, &key);
        if(ret)
            goto out;
        is_tombstone = SKB_L_GET(skb) == CASTLE_OBJ_TOMBSTONE;
        value_len = is_tombstone ? 0 : SKB_L_GET(skb);

        castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_DATA);
        
        call->replace.value_len = value_len;
        call->replace.replace_continue = castle_rxrpc_replace_continue;
        call->replace.complete = castle_rxrpc_replace_complete;
        call->replace.data_length_get = castle_rxrpc_replace_packet_length;
        call->replace.data_copy = castle_rxrpc_replace_str_copy;
        
        ret = castle_object_replace(&call->replace, attachment, key, is_tombstone);
        castle_object_okey_free(key);
    } else
    /* Subsequent packet processing */
    {
        if(call->replace.data_length == 0)
        {
            printk("ERROR? Got packet for finished replace in call %p"
                   "(data_length=0, packet_length=%d, last=%d). Ignoring.\n",
                    call, skb->len, last);
        }
        ret = castle_object_replace_continue(&call->replace, last);
    }

out:
    if(ret)
        castle_rxrpc_replace_complete(&call->replace, ret);

    return 0;
}

static int castle_rxrpc_replace_multi_decode(struct castle_rxrpc_call *call, 
                                             struct sk_buff *skb, 
                                             bool last)
{
    uint32_t len;

    call->current_skb = skb;
    /* First packet processing */
    if (call->packet_cnt == 1)
    {
        int ret;

        debug("Got first packet length %u\n", castle_rxrpc_packet_length(call));
        ret = castle_rxrpc_collection_get(skb, &call->replace_multi.attachment);
        if (ret)
            goto out;
        call->replace_multi.num_objects = SKB_L_GET(skb);
        call->replace_multi.objects_processed = 0;

        len = castle_rxrpc_packet_length(call);
        call->replace_multi.buf = castle_zalloc(len, GFP_KERNEL);
        if (!call->replace_multi.buf)
        {
            ret = -ENOMEM;
            goto out;
        }
        call->replace_multi.buf_length = len;
        call->replace_multi.buf_offset = 0;

        castle_rxrpc_str_copy(call, call->replace_multi.buf, len, 1);
        castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_DATA);
        castle_rxrpc_replace_multi_next_process(call, 0);

out:
        if(ret)
            castle_rxrpc_replace_multi_complete(call, ret);

        return 0;
    }
    else
    {
        char *new_buf;
        uint32_t remaining_len; /* the data left from the last packet */

        debug("Got %uth packet length %u\n", call->packet_cnt, castle_rxrpc_packet_length(call));

        len = castle_rxrpc_packet_length(call);
        remaining_len = call->replace_multi.buf_length - call->replace_multi.buf_offset;
        new_buf = castle_zalloc(len + remaining_len, GFP_KERNEL);
        if (!new_buf)
            return -ENOMEM;
        memcpy(new_buf, call->replace_multi.buf + call->replace_multi.buf_offset, remaining_len);
        castle_rxrpc_str_copy(call, new_buf + remaining_len, len, 1);

        castle_free(call->replace_multi.buf);
        call->replace_multi.buf = new_buf;
        call->replace_multi.buf_length = len + remaining_len;
        call->replace_multi.buf_offset = 0;

        debug("Got more data, new length %d\n", call->replace_multi.buf_length);

        castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_DATA);
        castle_rxrpc_replace_multi_next_process(call, 0);

        return 0;
    }
}

void castle_rxrpc_replace_multi_next_process(struct castle_rxrpc_call *call, int err)
{
    c_vl_okey_t *key;
    int key_len;
    uint32_t val_len, val_type;
    uint32_t peak_read = 0; /* the amount of buf we've read but might not keep */

    debug("With objects_processed=%u, offset=%u.\n",
            call->replace_multi.objects_processed,
            call->replace_multi.buf_offset);

    BUG_ON(call->replace_multi.objects_processed > call->replace_multi.num_objects);

    if (call->replace_multi.objects_processed == call->replace_multi.num_objects || err)
    {
        /* Finished. */
        BUG_ON(call->replace_multi.buf_length - call->replace_multi.buf_offset > 0);
        castle_rxrpc_replace_multi_complete(call, err);
        return;
    }

    /* See if we don't have any data. */
    if(call->replace_multi.buf_length - call->replace_multi.buf_offset == 0)
    {
        debug("Has no data, waiting for more...\n");
        castle_rxrpc_replace_multi_continue(call);
        return;
    }

    key_len = castle_rxrpc_key_get_check(call->replace_multi.buf + call->replace_multi.buf_offset,
                                         call->replace_multi.buf_length - call->replace_multi.buf_offset,
                                         &key);

    /* Error reading the key. */
    if (key_len < 0)
    {
        debug("Key read error %d\n", key_len);
        castle_rxrpc_replace_multi_complete(call, key_len);
        return;
    }

    if(key_len == 0)
    {
        debug("Not enough data for key, waiting for more...\n");
        castle_rxrpc_replace_multi_continue(call);
        return;
    }

    peak_read += key_len;

    /* Need to read in value type. */
    if(call->replace_multi.buf_length - (call->replace_multi.buf_offset + peak_read) < 4)
    {
        debug("Not enough data for value type, waiting for more...\n");
        castle_rxrpc_replace_multi_continue(call);
        return;
    }

    val_type = BUF_L_GET(call->replace_multi.buf + (call->replace_multi.buf_offset + peak_read));
    peak_read += 4;

    if (val_type == CASTLE_OBJ_TOMBSTONE)
    {
        call->replace_multi.buf_offset += peak_read;
        castle_object_replace_multi(call,
                                        call->replace_multi.attachment,
                                        key,
                                        1);
        call->replace_multi.objects_processed++;
        return;
    }

    /* Need to read in value length. */
    if(call->replace_multi.buf_length - (call->replace_multi.buf_offset + peak_read) < 4)
    {
        debug("Not enough data for value length, waiting for more...\n");
        castle_rxrpc_replace_multi_continue(call);
        return;
    }

    val_len = BUF_L_GET(call->replace_multi.buf + (call->replace_multi.buf_offset + peak_read));
    peak_read += 4;

    if(call->replace_multi.buf_length - (call->replace_multi.buf_offset + peak_read) < 
            castle_rxrpc_rounded_length(val_len))
    {
        debug("Not enough data for value, waiting for more...\n");
        castle_rxrpc_replace_multi_continue(call);
        return;
    }

    BUG_ON(val_len > MAX_INLINE_VAL_SIZE);

    /* We now have enough data for this value, so proceed. */
    /* Want to read the value length again, so subtract 4. */
    call->replace_multi.buf_offset += peak_read - 4;

    castle_object_replace_multi(call, 
                                call->replace_multi.attachment, 
                                key, 
                                0);

    call->replace_multi.objects_processed++;
}

static int castle_rxrpc_slice_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    struct castle_attachment *attachment;
    c_vl_okey_t *start_key, *end_key;
    uint32_t max_entries;
    int ret;

#ifdef DEBUG
    skb_print(skb);
#endif
    ret = castle_rxrpc_collection_get(skb, &attachment);
    if(ret)
        goto out;
    ret = castle_rxrpc_key_get(skb, &start_key);
    if(ret)
        goto out;
    ret = castle_rxrpc_key_get(skb, &end_key);
    if(ret)
    {
        castle_object_okey_free(start_key);
        goto out;
    }
    max_entries = SKB_L_GET(skb);

out:
    rxrpc_kernel_data_delivered(skb);
    castle_rxrpc_state_update(call, RXRPC_CALL_REPLYING);
    
    if(ret)
    {
        castle_object_okey_free(start_key);
        castle_object_okey_free(end_key);
        castle_rxrpc_get_slice_reply_start(call, ret, -1, NULL, -1, -1);
        return 0;
    }
    
    debug("Executing a range query.\n");
    return castle_object_slice_get(call, attachment, start_key, end_key, max_entries);
}

static void castle_rxrpc_call_free(struct castle_rxrpc_call *call)
{
    debug("Freeing call: %p\n", call);    
    BUG_ON(call->rxcall != NULL);
    BUG_ON(!skb_queue_empty(&call->rx_queue));
    castle_free(call);

    /* Decrement outstanding call count */
    atomic_dec(&castle_outst_call_cnt);
    wake_up(&castle_rxrpc_rmmod_wq);
}

static void castle_rxrpc_msg_send(struct castle_rxrpc_call *call, struct msghdr *msg, size_t len)
{
    int n;

    debug("castle_rxrpc_msg_send call=%p\n", call);

    if(call->state >= RXRPC_CALL_COMPLETE)
    {
        printk("Warning, trying to sent data on completed call, type=%s.\n",
                call->type->name);
        return;
    } 
    /* Check if we are sending the last message for this call, if so advance the state */
    if(!(msg->msg_flags & MSG_MORE))
        castle_rxrpc_state_update(call, RXRPC_CALL_AWAIT_ACK);
    n = rxrpc_kernel_send_data(call->rxcall, msg, len);
    debug("Sent %d bytes.\n", n);
    if (n != len)
    {
        printk("Failed to send the reply, wanted to send %ld bytes, sent %d bytes.\n",
                len, n);
        rxrpc_kernel_abort_call(call->rxcall, RX_USER_ABORT);
        castle_rxrpc_state_update(call, RXRPC_CALL_ERROR);
        return;
    }
    if (n >= 0) 
        return;
}

static void castle_rxrpc_reply_send(struct castle_rxrpc_call *call, 
                                    const void *buf, 
                                    size_t len, 
                                    int last)
{
    struct msghdr msg;
    struct iovec iov[1];

    iov[0].iov_base     = (void *) buf;
    iov[0].iov_len      = len;
    msg.msg_name        = NULL;
    msg.msg_namelen     = 0;
    msg.msg_iov         = buf ? iov : NULL;
    msg.msg_iovlen      = buf ? 1 : 0;
    msg.msg_control     = NULL;
    msg.msg_controllen  = 0;
    msg.msg_flags       = last ? 0 : MSG_MORE;

    castle_rxrpc_msg_send(call, &msg, len);
}

static void castle_rxrpc_double_reply_send(struct castle_rxrpc_call *call, 
                                           const void *buf1, 
                                           size_t len1,
                                           const void *buf2, 
                                           size_t len2,
                                           int last)
{
    struct msghdr msg;
    struct iovec iov[3];
    uint8_t pad_buff[3] = {0, 0, 0};
    int pad = (4 - (len2 % 4)) % 4;
    
    iov[0].iov_base     = (void *) buf1;
    iov[0].iov_len      = len1;
    iov[1].iov_base     = (void *) buf2;
    iov[1].iov_len      = len2;
    if(pad)
    { 
        iov[2].iov_base = (void *)pad_buff;
        iov[2].iov_len  = pad;
    }

    msg.msg_name        = NULL;
    msg.msg_namelen     = 0;
    msg.msg_iov         = iov;
    msg.msg_iovlen      = pad ? 3 : 2;
    msg.msg_control     = NULL;
    msg.msg_controllen  = 0;
    msg.msg_flags       = last ? 0 : MSG_MORE;
    
    castle_rxrpc_msg_send(call, &msg, len1 + len2 + pad);
}

static void castle_rxrpc_call_delete(struct work_struct *work)
{
    struct castle_rxrpc_call *call = container_of(work, struct castle_rxrpc_call, work);

    castle_rxrpc_call_free(call);
}

static void castle_rxrpc_packet_process(struct work_struct *work)
{
    struct castle_rxrpc_call *call = container_of(work, struct castle_rxrpc_call, work);
    uint32_t abort_code;
    struct sk_buff *skb;
    int last, ret;

    /* Exit early if there are no packet on the queue (e.g. queue is flushed for 
       completed calls) */
    if (skb_queue_empty(&call->rx_queue))
        return;

    debug("Processing packets for call: %p, call->state=%d.\n", call, call->state);
    while ((call->state == RXRPC_CALL_AWAIT_OP_ID   ||
            call->state == RXRPC_CALL_AWAIT_REQUEST ||
            call->state == RXRPC_CALL_AWAIT_ACK) &&
           (skb = skb_dequeue(&call->rx_queue)))
    {
        debug("Processing packet: %d.\n", skb->mark);
        call->packet_cnt++;
        switch(skb->mark)
        {
            case RXRPC_SKB_MARK_DATA:
                last = rxrpc_kernel_is_data_last(skb);
                /* Deliver the packet to the call */
                ret = call->type->deliver(call, skb, last);
                debug("Processed data packet, got ret=%d\n", ret);
                switch (ret)
                {
                    case 0:
                        break;
                    case -ENOTCONN:
                        abort_code = RX_CALL_DEAD;
                        goto do_abort;
                    case -ENOTSUPP:
                        abort_code = RX_INVALID_OPERATION;
                        goto do_abort;
                    default:
                        abort_code = RXGEN_SS_UNMARSHAL;
                    do_abort:
                        rxrpc_kernel_abort_call(call->rxcall, abort_code);
                        call->error = ret;
                        castle_rxrpc_state_update(call, RXRPC_CALL_ERROR);
                        break;
                }
                skb = NULL;
                continue;
            case RXRPC_SKB_MARK_FINAL_ACK:
                castle_rxrpc_state_update(call, RXRPC_CALL_COMPLETE);
                break;
            case RXRPC_SKB_MARK_BUSY:
                call->error = -EBUSY;
                castle_rxrpc_state_update(call, RXRPC_CALL_BUSY);
                break;
            case RXRPC_SKB_MARK_REMOTE_ABORT:
                call->error = -rxrpc_kernel_get_abort_code(skb);
                castle_rxrpc_state_update(call, RXRPC_CALL_ABORTED);
                break;
            case RXRPC_SKB_MARK_NET_ERROR:
            case RXRPC_SKB_MARK_LOCAL_ERROR:
                call->error = -rxrpc_kernel_get_error_number(skb);
                castle_rxrpc_state_update(call, RXRPC_CALL_ERROR);
                break;
            default:
                BUG();
                break;
        }
        debug("Freeing non-DATA skb.\n");
        /* SKB processed, free it */
        rxrpc_kernel_free_skb(skb);
    }
    
    debug("Call state is %d.\n", call->state);

    /* make sure the queue is empty if the call is done with (we might have
     * aborted the call early because of an unmarshalling error) */
    if (call->state >= RXRPC_CALL_COMPLETE) {
        rxrpc_kernel_end_call(call->rxcall);
        while ((skb = skb_dequeue(&call->rx_queue)))
        {
            printk("WARNING: Untested, freeing rxrpc SKB after ending the call.\n");
            rxrpc_kernel_free_skb(skb);
        }

        call->rxcall = NULL;
        if(call->type->destructor)
            call->type->destructor(call);

        debug("Queueing call delete.\n");
        CASTLE_PREPARE_WORK(&call->work, castle_rxrpc_call_delete);
        queue_work_on(call->cpu, rxrpc_wq, &call->work);
    }
}

static DEFINE_SPINLOCK(castle_rxrpc_next_cpu_lock);
static int castle_rxrpc_next_cpu;

static void castle_rxrpc_incoming_call_collect(struct work_struct *work)
{
    struct castle_rxrpc_call *c_rxcall;
    struct sk_buff *skb;
    static atomic_t call_id = ATOMIC(0);

    while((skb = skb_dequeue(&rxrpc_incoming_calls)))
    {
        /* Nothing interesting in the packet, free it */
        rxrpc_kernel_free_skb(skb);

        /* Try to allocate a call struct, reject call if failed */
        c_rxcall = castle_zalloc(sizeof(struct castle_rxrpc_call), GFP_KERNEL);
        if(!c_rxcall)
        {
            rxrpc_kernel_reject_call(socket);
            continue;
        }

        debug("Collecting call %p.\n", c_rxcall);
        /* Init the call struct */
        CASTLE_INIT_WORK(&c_rxcall->work, castle_rxrpc_packet_process);
        skb_queue_head_init(&c_rxcall->rx_queue);
        
        spin_lock_irq(&castle_rxrpc_next_cpu_lock);
        c_rxcall->cpu = castle_rxrpc_next_cpu;
        do {
            if (castle_rxrpc_next_cpu >= NR_CPUS)
                castle_rxrpc_next_cpu = first_cpu(cpu_online_map);
            else
                castle_rxrpc_next_cpu = next_cpu(castle_rxrpc_next_cpu, cpu_online_map);
        } while (castle_rxrpc_next_cpu >= NR_CPUS);
        spin_unlock_irq(&castle_rxrpc_next_cpu_lock);
        
        c_rxcall->call_id    = atomic_inc_return(&call_id);
        
        debug("Starting call 0x%lx cpu=%d\n", c_rxcall->call_id, c_rxcall->cpu);
        
        c_rxcall->type       = &castle_rxrpc_op_call;
        c_rxcall->packet_cnt = 0;
        castle_rxrpc_state_update(c_rxcall, RXRPC_CALL_AWAIT_OP_ID);

        c_rxcall->rxcall = rxrpc_kernel_accept_call(socket,
                                                    (unsigned long)c_rxcall);
        if(IS_ERR(c_rxcall->rxcall))
        {
            castle_rxrpc_call_free(c_rxcall);
        }
        else 
        {
            /* Increment outstanding call count */
            atomic_inc(&castle_outst_call_cnt);
        }
    }
}

static void castle_rxrpc_interceptor(struct sock *sk,
                                     unsigned long user_call_ID,
			                         struct sk_buff *skb)
{
    struct castle_rxrpc_call *call = (struct castle_rxrpc_call *) user_call_ID;

    if(!call)
    {
        debug("Intercepting new call request.\n");
        skb_queue_tail(&rxrpc_incoming_calls, skb);
        schedule_work(&castle_rxrpc_incoming_call_work);
    } else
    {
        debug("Intercepting call 0x%lx cpu=%d\n", user_call_ID, call->cpu);
        skb_queue_tail(&call->rx_queue, skb);
        queue_work_on(call->cpu, rxrpc_wq, &call->work);
    }
}

int castle_rxrpc_init(void)
{
	struct sockaddr_rxrpc srx;
    int ret;
    
    castle_rxrpc_next_cpu = first_cpu(cpu_online_map);

    printk("Castle RXRPC init.\n");
    skb_queue_head_init(&rxrpc_incoming_calls);
    rxrpc_wq = create_workqueue("castle_rxrpc");
    if(!rxrpc_wq)
        return -ENOMEM;

	ret = sock_create_kern(AF_RXRPC, SOCK_DGRAM, PF_INET, &socket);
    if(ret < 0)
    {
        destroy_workqueue(rxrpc_wq);
        return ret;
    }

	socket->sk->sk_allocation = GFP_NOIO;

	srx.srx_family						= AF_RXRPC;
	srx.srx_service						= 1;
	srx.transport_type					= SOCK_DGRAM;
	srx.transport_len					= sizeof(srx.transport.sin);
	srx.transport.sin.sin_addr.s_addr   = htonl(INADDR_LOOPBACK);
	srx.transport.sin.sin_family	    = AF_INET;
	srx.transport.sin.sin_port	        = htons(34876);
	memset(&srx.transport.sin.sin_addr, 0, sizeof(srx.transport.sin.sin_addr));

    ret = kernel_bind(socket, (struct sockaddr *) &srx, sizeof(srx));
	if (ret < 0) {
        destroy_workqueue(rxrpc_wq);
		sock_release(socket);
        return ret;
	}

	rxrpc_kernel_intercept_rx_messages(socket, castle_rxrpc_interceptor);

    return 0;
}

void castle_rxrpc_fini(void)
{
    printk("Castle RXRPC fini.\n");
    /* Wait until all outstanding calls are finished */
    wait_event(castle_rxrpc_rmmod_wq, (atomic_read(&castle_outst_call_cnt) == 0));
	sock_release(socket);
    destroy_workqueue(rxrpc_wq);
}

static void castle_control_reply_error(uint32_t *reply, 
                                       int ret_code,
                                       size_t *len)
{
    reply[0] = CASTLE_CTRL_REPLY;
    reply[1] = CASTLE_CTRL_REPLY_FAIL;
    reply[2] = ret_code;
    *len = 3;
}

static void castle_control_reply_process(uint32_t *reply, size_t len, size_t *length)
{
    size_t i;
    
    /* Convert to network byte order */
    for(i=0; i<len; i++)
        reply[i] = htonl(reply[i]);

    #ifdef DEBUG        
    debug("Reply message:\n");
    for(i=0; i<4*len; i++)
        debug(" [%ld]=%d\n", i, *(((uint8_t *)reply) + i));
    debug("\n");
    #endif

    /* length is in bytes */
    *length = 4*len;
}

static void castle_control_reply(uint32_t *reply, 
                                 size_t *length, 
                                 int op_code, 
                                 int ret_code, 
                                 uint32_t token)
{
    size_t len;

    /* Deal with error condition first */
    if(ret_code)
    {
        castle_control_reply_error(reply, ret_code, &len);
    } else
    /* Next, void replies */
    if(op_code == CASTLE_CTRL_REPLY_VOID)
    {
        reply[0] = CASTLE_CTRL_REPLY;
        reply[1] = CASTLE_CTRL_REPLY_VOID;
        len = 2;
    } else
    /* All the rest */
    {
        reply[0] = CASTLE_CTRL_REPLY;
        reply[1] = op_code;
        reply[2] = token;
        len = 3;
    } 

    castle_control_reply_process(reply, len, length);
}

static void castle_control_get_valid_counts(slave_uuid_t slave_uuid, uint32_t *reply, size_t length, size_t *len_p)
{
    int ret = 0;
    size_t count = 0;
    struct castle_slave *slave = NULL;

    slave = castle_slave_find_by_uuid(slave_uuid);

    debug("castle_control_get_valid_counts slave_uuid=0x%x slave=%p\n", slave_uuid, slave);

    if (!slave)
    {
        ret = -ENOENT;
        goto error;
    }

    ret = castle_freespace_summary_get(slave, reply + 3, length - 3, &count);
    if (ret)
        goto error;

    debug("castle_control_get_valid_counts ret=%d\n", ret);

    reply[0] = CASTLE_CTRL_REPLY;
    reply[1] = CASTLE_CTRL_REPLY_VALID_COUNTS;
    reply[2] = count >> 1; // count should only ever be 2^33, so this number will be 2^32
    count += 3;

error:
    if (ret)
        castle_control_reply_error(reply, ret, &count);

    castle_control_reply_process(reply, count, len_p);
}

static void castle_control_get_invalid_counts(slave_uuid_t slave_uuid, uint32_t *reply, size_t length, size_t *len_p)
{
    int ret = 0;
    size_t count = 0;
    struct castle_slave *slave = NULL;

    slave = castle_slave_find_by_uuid(slave_uuid);

    debug("castle_control_get_invalid_counts slave_uuid=0x%x slave=%p\n", slave_uuid, slave);

    if (!slave)
    {
        ret = -ENOENT;
        goto error;
    }

    debug("castle_control_get_invalid_counts castle_freespace_summary_get ret=%d\n", ret);

    reply[0] = CASTLE_CTRL_REPLY;
    reply[1] = CASTLE_CTRL_REPLY_INVALID_COUNTS;
    reply[2] = 0;
    count = 3;

error:
    if (ret)
        castle_control_reply_error(reply, ret, &count);

    castle_control_reply_process(reply, count, len_p);
}

int castle_control_packet_process(struct sk_buff *skb, void **reply, size_t *len_p)
{
    uint32_t *reply32; /* For now, all reply values are 32 bit wide */
    uint32_t ctrl_op;
    size_t reply32_size = 0;

    debug("Processing control packet (in_atomic=%d).\n", in_atomic());
#ifdef DEBUG
    skb_print(skb);
#endif
    if(skb->len < 4)
        return -EBADMSG;

    castle_control_lock_up();
    ctrl_op = SKB_L_GET(skb);
    debug("Ctrl op=%d\n", ctrl_op);
    
    switch(ctrl_op)
    {
        case CASTLE_CTRL_REQ_VALID_STATS:
        case CASTLE_CTRL_REQ_INVALID_STATS:
        {
            // must not forget version zero!
            int versions = castle_version_max_get() + 1;
            reply32_size = (versions * 2) + 3;
            break;
        }
        default:
            reply32_size = 64;
            break;
    }

    *reply = reply32 = castle_malloc(reply32_size * sizeof(uint32_t), GFP_KERNEL);
    if (!reply32)
        return -ENOMEM;
    
    switch(ctrl_op)
    {
        case CASTLE_CTRL_REQ_CLAIM:
        {
            int ret;
            slave_uuid_t id;

            if(skb->len != 4) goto bad_msg;
            castle_control_claim(SKB_L_GET(skb), &ret, &id);
            castle_control_reply(reply32, 
                                 len_p, 
                                 CASTLE_CTRL_REPLY_NEW_SLAVE,
                                 ret, 
                                 id);
            break;
        }
        case CASTLE_CTRL_REQ_RELEASE:
        {
            int ret/*, i*/;

            if(skb->len != 4) goto bad_msg;
            castle_control_release(SKB_L_GET(skb), &ret); 
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);

            break;
        }
        case CASTLE_CTRL_REQ_ATTACH:
        {
            int ret;
            uint32_t dev;

            if(skb->len != 4) goto bad_msg;
            castle_control_attach(SKB_L_GET(skb), 
                                  &ret, 
                                  &dev);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_DEVICE,
                                 ret,
                                 dev);
            break;
        }
        case CASTLE_CTRL_REQ_DETACH:
        {
            int ret;

            if(skb->len != 4) goto bad_msg;
            castle_control_detach(SKB_L_GET(skb), &ret); 
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_CREATE:
        {
            int ret;
            version_t version;

            if(skb->len != 8) goto bad_msg;
            castle_control_create(SKB_LL_GET(skb), 
                                  &ret, 
                                  &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_CLONE:
        {
            int ret;
            version_t version;

            if(skb->len != 4) goto bad_msg;
            castle_control_clone(SKB_L_GET(skb),
                                 &ret,
                                 &version); 
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_SNAPSHOT:
        {
            int ret;
            version_t version;
            
            if(skb->len != 4) goto bad_msg;
            castle_control_snapshot(SKB_L_GET(skb), 
                                    &ret, 
                                    &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_INIT:
        {
            int ret;
            
            if(skb->len != 0) goto bad_msg;
            castle_control_fs_init(&ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_RESERVE_FOR_TRANSFER:
        {
            int version, type, reservations_count, i;
            int *reservations_disk, *reservations_length;

            debug("Reserve_for_transfer skb->len=%d", skb->len);

            if(skb->len < 12) goto bad_msg;
            
            version = SKB_L_GET(skb);
            type = SKB_L_GET(skb);
            reservations_count = SKB_L_GET(skb);
            
            debug("Reserve_for_transfer version=0x%x type=0x%x reservations_count=%d", 
                    version, type, reservations_count);
            
            if(skb->len < (reservations_count * 2)) goto bad_msg;
            
            reservations_disk = castle_malloc(reservations_count * sizeof(int), GFP_KERNEL);
            reservations_length = castle_malloc(reservations_count * sizeof(int), GFP_KERNEL);
            
            for (i = 0; i < reservations_count; i++) {
                reservations_disk[i] = SKB_L_GET(skb);
                reservations_length[i] = SKB_L_GET(skb);
            }
            
            castle_free(reservations_disk);
            castle_free(reservations_length);
            
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 -EINVAL,
                                 0);
            break;
        }

        case CASTLE_CTRL_REQ_TRANSFER_CREATE:
        {
            int ret;
            transfer_id_t transfer;

            if(skb->len != 8) goto bad_msg;
            castle_control_transfer_create(SKB_L_GET(skb),
                                           SKB_L_GET(skb),
                                           &ret,
                                           &transfer);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_TRANSFER,
                                 ret,
                                 transfer);
            break;
        }
        case CASTLE_CTRL_REQ_TRANSFER_DESTROY:
        {
            int ret;

            if(skb->len != 4) goto bad_msg;
            castle_control_transfer_destroy(SKB_L_GET(skb),
                                            &ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_ATTACH:
        {
            int ret;
            collection_id_t collection;

            version_t version;
            char *name;

            if(skb->len < 8) goto bad_msg;
            version = SKB_L_GET(skb);
            name = SKB_STR_GET(skb, 128);
            if(!name) goto bad_msg;

            castle_control_collection_attach(version, name,
                                             &ret,
                                             &collection);

            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_COLLECTION,
                                 ret,
                                 collection);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_DETACH:
        {
            int ret;
            
            if(skb->len != 4) goto bad_msg;
            castle_control_collection_detach(SKB_L_GET(skb),
                                             &ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
        case CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT:
        {
            int ret;
            version_t version;

            if(skb->len != 4) goto bad_msg;
            castle_control_collection_snapshot(SKB_L_GET(skb),
                                               &ret,
                                               &version);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_NEW_VERSION,
                                 ret,
                                 version);
            break;
        }
        case CASTLE_CTRL_REQ_VALID_STATS:
        {
            slave_uuid_t slave_uuid;
            
            if(skb->len != 4) goto bad_msg;

            slave_uuid = SKB_L_GET(skb);
            
            castle_control_get_valid_counts(slave_uuid, reply32, reply32_size, len_p);
            
            break;
        }
        case CASTLE_CTRL_REQ_INVALID_STATS:
        {
            slave_uuid_t slave_uuid;
            
            if(skb->len != 4) goto bad_msg;

            slave_uuid = SKB_L_GET(skb);
            
            castle_control_get_invalid_counts(slave_uuid, reply32, reply32_size, len_p);
            
            break;
        }
        case CASTLE_CTRL_REQ_SET_TARGET:
        {
            int ret, value;
            slave_uuid_t slave_uuid;
            
            if(skb->len != 8) goto bad_msg;

            slave_uuid = SKB_L_GET(skb);
            value = SKB_L_GET(skb);
            
            castle_control_set_target(slave_uuid,
                                      value,
                                      &ret);
            castle_control_reply(reply32,
                                 len_p,
                                 CASTLE_CTRL_REPLY_VOID,
                                 ret,
                                 0);
            break;
        }
    }
    castle_control_lock_down();

    return 0;

bad_msg:
    castle_control_lock_down();

    return -EBADMSG;
}

static int castle_rxrpc_ctrl_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    int ret;
    size_t len;
    void *reply = NULL;

    debug("Delivering ctrl packet.\n");
    ret = castle_control_packet_process(skb, &reply, &len);
    debug("Ctrl ret=%d\n", ret);

    rxrpc_kernel_data_delivered(skb);
    /* Advance the state, if we succeeded at decoding the packet */
    if(ret) 
    {
        if(reply) castle_free(reply);
        return ret;
    }
    
    castle_rxrpc_state_update(call, RXRPC_CALL_REPLYING);
    debug("Sending reply of length=%ld\n", len);
    castle_rxrpc_reply_send(call, reply, len, 1 /* last */);

    castle_free(reply);
    return 0;
}


static const struct castle_rxrpc_call_type castle_rxrpc_op_call =
{
    .name    = "op decode",
    .deliver = castle_rxrpc_op_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_get_call =
{
    .name    = "get",
    .deliver = castle_rxrpc_get_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_replace_call =
{
    .name    = "replace",
    .deliver = castle_rxrpc_replace_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_replace_multi_call =
{
    .name    = "multi replace",
    .deliver = castle_rxrpc_replace_multi_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_slice_call =
{
    .name    = "slice",
    .deliver = castle_rxrpc_slice_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_ctrl_call =
{
    .name    = "control",
    .deliver = castle_rxrpc_ctrl_decode,
};

