#ifndef __CASTLE_RXRPC_H__
#define __CASTLE_RXRPC_H__

static inline uint32_t SKB_L_GET(struct sk_buff *skb)
{
    __be32 word;

    BUG_ON(skb_copy_bits(skb, 0, &word, 4) < 0);
    BUG_ON(!pskb_pull(skb, 4));

    return ntohl(word);
}

static inline uint64_t SKB_LL_GET(struct sk_buff *skb)
{
    __be64 qword;

    BUG_ON(skb_copy_bits(skb, 0, &qword, 8) < 0);
    BUG_ON(!pskb_pull(skb, 8));

    return be64_to_cpu(qword);
}

int  castle_rxrpc_init(void);
void castle_rxrpc_fini(void);

#endif /* __CASTLE_RXRPC_H__ */
