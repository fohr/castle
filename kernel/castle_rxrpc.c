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

#include "castle_public.h"
#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"

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

struct castle_rxrpc_call {
    struct workqueue_struct *wq;         /* One of the rxrpc_wqs. Used to process the call. */
    struct work_struct       work;
    unsigned long            call_id;
    struct rxrpc_call       *rxcall;
    struct sk_buff_head      rx_queue;   /* Queue of packets for this call */

    uint8_t                 *buffer;
};

static void castle_rxrpc_packet_repspond(struct castle_rxrpc_call *call)
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

static void castle_rxrpc_packet_process(struct work_struct *work)
{
    struct castle_rxrpc_call *c_rxcall = container_of(work, struct castle_rxrpc_call, work);
    struct sk_buff *skb;
    int last;

    while((skb = skb_dequeue(&c_rxcall->rx_queue)))
    {
        if(skb->mark != RXRPC_SKB_MARK_DATA)
        {
            rxrpc_kernel_free_skb(skb);
            /* Queue should be empty. */
            BUG_ON(!skb_queue_empty(&c_rxcall->rx_queue));
            rxrpc_kernel_end_call(c_rxcall->rxcall);
            return;
        }
        last = rxrpc_kernel_is_data_last(skb);
        if(skb_copy_bits(skb, 0, c_rxcall->buffer, skb->len) >= 0)
            print_hex_dump_bytes("", DUMP_PREFIX_OFFSET, c_rxcall->buffer, skb->len);
        else
            printk("Could not copy data out of the packet.\n");
        
        rxrpc_kernel_data_delivered(skb);
        castle_rxrpc_packet_repspond(c_rxcall);
    }
}

static void castle_rxrpc_call_free(struct castle_rxrpc_call *call)
{       
    BUG_ON(call->rxcall != NULL);
    BUG_ON(!skb_queue_empty(&call->rx_queue));
    kfree(call);
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
        /* Init the call struct */ 
        INIT_WORK(&c_rxcall->work, castle_rxrpc_packet_process);
        skb_queue_head_init(&c_rxcall->rx_queue); 	
        c_rxcall->wq = rxrpc_wqs[(wq_nr++) % NR_WQS];
        c_rxcall->call_id = atomic_inc_return(&call_id); 
        c_rxcall->buffer = buffer;
        
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
        skb_queue_tail(&rxrpc_incoming_calls, skb);
        schedule_work(&castle_rxrpc_incoming_call_work);
    } else
    {
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

