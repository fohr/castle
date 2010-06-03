#include <linux/module.h>
#include <linux/kthread.h>
#include <linux/workqueue.h>
#include <linux/fs.h>
#include <linux/bio.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <linux/time.h>
#include <net/sock.h>
#include <linux/rxrpc.h>
#include <net/af_rxrpc.h>
#include <linux/errqueue.h>
#include <rxrpc/packet.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"
#include "castle_rxrpc.h"
#include "castle_ctrl.h"

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
static const struct castle_rxrpc_call_type castle_rxrpc_slice_call;
static const struct castle_rxrpc_call_type castle_rxrpc_ctrl_call;
void castle_rxrpc_reply_send(struct castle_rxrpc_call *call, const void *buf, size_t len);


#define NR_WQS    4
static struct socket            *socket;
static struct workqueue_struct  *rxrpc_wqs[NR_WQS]; /* Need singlethreaded WQs,
                                                       because individual calls handling
                                                       is not multithread safe. Collection
                                                       of queues will alow concurrency
                                                       between calls through. */
static struct sk_buff_head       rxrpc_incoming_calls;
static void castle_rxrpc_incoming_call_collect(struct work_struct *work);
static DECLARE_WORK(castle_rxrpc_incoming_call_work, castle_rxrpc_incoming_call_collect);

struct castle_rxrpc_call_type {
    /* Deliver packet to this call type. Deliver should consume ENTIRE packet, 
       free it using rxrpc_kernel_data_delivered() */
    int (*deliver)     (struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last);
    void (*destructor) (struct castle_rxrpc_call *call);
};

struct castle_rxrpc_call {
    struct workqueue_struct       *wq;         /* One of the rxrpc_wqs. Used to process the call. */
    struct work_struct             work;
    unsigned long                  call_id;
    struct rxrpc_call             *rxcall;
    struct sk_buff_head            rx_queue;   /* Queue of packets for this call */

    int                            op_id;
    const struct castle_rxrpc_call_type *type;
    enum {
        /* Copied from AFS */
        RXRPC_CALL_AWAIT_OP_ID,   /* awaiting op ID on incoming call */
        RXRPC_CALL_AWAIT_REQUEST, /* awaiting request data on incoming call */
        RXRPC_CALL_REPLYING,      /* replying to incoming call */
        RXRPC_CALL_AWAIT_ACK,     /* awaiting final ACK of incoming call */
        RXRPC_CALL_COMPLETE,      /* successfully completed */
        RXRPC_CALL_BUSY,          /* server was busy */
        RXRPC_CALL_ABORTED,       /* call was aborted */
        RXRPC_CALL_ERROR,         /* call failed due to error */
    }                              state;
    int                            error;

    uint8_t                       *buffer;
};

/* Definition of different call types */
int castle_rxrpc_op_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    if(skb->len < 4)
        return -EBADMSG;

    call->state = RXRPC_CALL_AWAIT_REQUEST;
    call->op_id = SKB_L_GET(skb);
    debug("op id: %d\n", call->op_id);

    switch(call->op_id)
    {
        case CASTLE_OBJ_REQ_GET:
            call->type = &castle_rxrpc_get_call;
            break;
        case CASTLE_OBJ_REQ_REPLACE:
            call->type = &castle_rxrpc_replace_call;
            break;
        case CASTLE_OBJ_REQ_SLICE:
            call->type = &castle_rxrpc_slice_call;
            break;
        case CASTLE_CTRL_REQ:
            call->type = &castle_rxrpc_ctrl_call;
            break;
        default:
            return -ENOTSUPP;
    }

    return call->type->deliver(call, skb, last);
}

int castle_rxrpc_get_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    printk("Obj Get.\n");
    return -ENOTSUPP;
}

int castle_rxrpc_replace_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    printk("Obj Replace.\n");
    return -ENOTSUPP;
}

int castle_rxrpc_slice_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    printk("Obj Slice.\n");
    return -ENOTSUPP;
}

int castle_rxrpc_ctrl_decode(struct castle_rxrpc_call *call, struct sk_buff *skb,  bool last)
{
    int ret, len;
    char reply[256];

    ret = castle_control_packet_process(skb, reply, &len);
    debug("=> Ctrl ret=%d\n", ret);
    rxrpc_kernel_data_delivered(skb);
    /* Advance the state, if we succeeded at decoding the packet */
    if(ret) return ret;

    call->state = RXRPC_CALL_REPLYING;
    debug("=> Sending reply of length=%d\n", len);
    castle_rxrpc_reply_send(call, reply, len);
    call->state = RXRPC_CALL_AWAIT_ACK;

    return 0;
}


static const struct castle_rxrpc_call_type castle_rxrpc_op_call =
{
    .deliver = castle_rxrpc_op_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_get_call =
{
    .deliver = castle_rxrpc_get_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_replace_call =
{
    .deliver = castle_rxrpc_replace_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_slice_call =
{
    .deliver = castle_rxrpc_slice_decode,
};

static const struct castle_rxrpc_call_type castle_rxrpc_ctrl_call =
{
    .deliver = castle_rxrpc_ctrl_decode,
};


static void castle_rxrpc_call_free(struct castle_rxrpc_call *call)
{
    debug("Freeing call: %p\n", call);    
    BUG_ON(call->rxcall != NULL);
    BUG_ON(!skb_queue_empty(&call->rx_queue));
    kfree(call);
}

void castle_rxrpc_reply_send(struct castle_rxrpc_call *call, const void *buf, size_t len)
{
    struct msghdr msg;
    struct iovec iov[1];
    int n;

    iov[0].iov_base     = (void *) buf;
    iov[0].iov_len      = len;
    msg.msg_name        = NULL;
    msg.msg_namelen     = 0;
    msg.msg_iov         = iov;
    msg.msg_iovlen      = 1;
    msg.msg_control     = NULL;
    msg.msg_controllen  = 0;
    msg.msg_flags       = 0;

    call->state = RXRPC_CALL_AWAIT_ACK;
    n = rxrpc_kernel_send_data(call->rxcall, &msg, len);
    debug("Sent %d bytes.\n", n);
    if (n >= 0) 
        return;
    if (n == -ENOMEM)
        rxrpc_kernel_abort_call(call->rxcall, RX_USER_ABORT);
}

static void USED castle_rxrpc_packet_repspond(struct castle_rxrpc_call *call)
{
    struct msghdr msg;
    struct iovec iov[1];

    call->buffer[0]     = 0;
    call->buffer[1]     = 1;
    call->buffer[2]     = 2;
    call->buffer[3]     = 3;

    iov[0].iov_base     = call->buffer;
    iov[0].iov_len      = 4; /* <- same as in send_data? */
    msg.msg_name        = NULL;
    msg.msg_namelen     = 0;
    msg.msg_iov         = iov;
    msg.msg_iovlen      = 1;
    msg.msg_control     = NULL;
    msg.msg_controllen  = 0;
    msg.msg_flags       = 0;

    BUG_ON(rxrpc_kernel_send_data(call->rxcall, &msg, 4) != 4);
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

    debug("Processing packets for call: %p.\n", call);
    while ((call->state == RXRPC_CALL_AWAIT_OP_ID   ||
            call->state == RXRPC_CALL_AWAIT_REQUEST ||
            call->state == RXRPC_CALL_AWAIT_ACK) &&
           (skb = skb_dequeue(&call->rx_queue)))
    {
        debug("Processing packet: %d.\n", skb->mark);
        switch(skb->mark)
        {
            case RXRPC_SKB_MARK_DATA:
                last = rxrpc_kernel_is_data_last(skb);
                /* Deliver the packet to the call */
                ret = call->type->deliver(call, skb, last);
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
                        call->state = RXRPC_CALL_ERROR;
                        break;
                }
                skb = NULL;
                continue;
            case RXRPC_SKB_MARK_FINAL_ACK:
                call->state = RXRPC_CALL_COMPLETE;
                break;
            case RXRPC_SKB_MARK_BUSY:
                call->error = -EBUSY;
                call->state = RXRPC_CALL_BUSY;
                break;
            case RXRPC_SKB_MARK_REMOTE_ABORT:
                call->error = -rxrpc_kernel_get_abort_code(skb);
                call->state = RXRPC_CALL_ABORTED;
                break;
            case RXRPC_SKB_MARK_NET_ERROR:
            case RXRPC_SKB_MARK_LOCAL_ERROR:
                call->error = -rxrpc_kernel_get_error_number(skb);
                call->state = RXRPC_CALL_ERROR;
                break;
            default:
                BUG();
                break;
        }
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

        PREPARE_WORK(&call->work, castle_rxrpc_call_delete);
        queue_work(call->wq, &call->work);
    }

}

static void castle_rxrpc_incoming_call_collect(struct work_struct *work)
{
    struct castle_rxrpc_call *c_rxcall;
    struct sk_buff *skb;
    static atomic_t call_id = ATOMIC_INIT(0);
    uint8_t *buffer;
    static int wq_nr = 0;

    while((skb = skb_dequeue(&rxrpc_incoming_calls)))
    {
        /* Nothing interesting in the packet, free it */
        rxrpc_kernel_free_skb(skb);

        /* Try to allocate a call struct, reject call if failed */
        c_rxcall = kzalloc(sizeof(struct castle_rxrpc_call), GFP_KERNEL);
        /* TMP buffering */
        buffer = kmalloc(17000, GFP_KERNEL);
        if(!c_rxcall || !buffer)
        {
            rxrpc_kernel_reject_call(socket);
            continue;
        }

        debug("Collecting call %p.\n", c_rxcall);
        /* Init the call struct */
        INIT_WORK(&c_rxcall->work, castle_rxrpc_packet_process);
        skb_queue_head_init(&c_rxcall->rx_queue); 	
        c_rxcall->wq      = rxrpc_wqs[(wq_nr++) % NR_WQS];
        c_rxcall->call_id = atomic_inc_return(&call_id);
        c_rxcall->buffer  = buffer;
        c_rxcall->type    = &castle_rxrpc_op_call;
        c_rxcall->state   = RXRPC_CALL_AWAIT_OP_ID;

        c_rxcall->rxcall = rxrpc_kernel_accept_call(socket,
                                                    (unsigned long)c_rxcall);
        if(IS_ERR(c_rxcall->rxcall))
            castle_rxrpc_call_free(c_rxcall);
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
        debug("Intercepting call 0x%lx\n", user_call_ID);
        skb_queue_tail(&call->rx_queue, skb);
        queue_work(call->wq, &call->work);
    }
}

int castle_rxrpc_init(void)
{
	struct sockaddr_rxrpc srx;
    int i, ret;
    char *wq_name;

    printk("Castle RXRPC init.\n");
    skb_queue_head_init(&rxrpc_incoming_calls);
    for(i=0; i<NR_WQS; i++)
    {
        char *name_prefix = "castle_rxrpc_";
        wq_name = kzalloc(strlen(name_prefix)+3, GFP_KERNEL);
        if(!wq_name)
            goto wq_error;
        sprintf(wq_name, "%s%d", name_prefix, i);
        rxrpc_wqs[i] = create_singlethread_workqueue(wq_name);
        if(!rxrpc_wqs[i])
        {
wq_error:
            kfree(wq_name);
            for(; i>=0; i--)
                destroy_workqueue(rxrpc_wqs[i]);

            return -ENOMEM;
        }
    }

	ret = sock_create_kern(AF_RXRPC, SOCK_DGRAM, PF_INET, &socket);
    if(ret < 0)
    {
        for(i=0; i<NR_WQS; i++)
            destroy_workqueue(rxrpc_wqs[i]);
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
        for(i=0; i<NR_WQS; i++)
            destroy_workqueue(rxrpc_wqs[i]);
		sock_release(socket);
        return ret;
	}

	rxrpc_kernel_intercept_rx_messages(socket, castle_rxrpc_interceptor);

    return 0;
}

void castle_rxrpc_fini(void)
{
    int i;

    printk("Castle RXRPC fini.\n");
	sock_release(socket);
    for(i=0; i<NR_WQS; i++)
        destroy_workqueue(rxrpc_wqs[i]);
}

