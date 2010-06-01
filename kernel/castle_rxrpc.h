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

static inline char* SKB_STR_GET(struct sk_buff *skb, int max_len)
{
    uint32_t str_len = SKB_L_GET(skb);
    char *str;
    
    if((str_len > max_len) || (str_len > skb->len))
        return NULL;

    if(!(str = kzalloc(str_len+1, GFP_KERNEL)))
        return NULL;

    BUG_ON(skb_copy_bits(skb, 0, str, str_len) < 0);
    str_len += (str_len % 4 == 0 ? 0 : 4 - str_len % 4);
    BUG_ON(!pskb_pull(skb, str_len));

    return str;
}

int  castle_rxrpc_init(void);
void castle_rxrpc_fini(void);

#endif /* __CASTLE_RXRPC_H__ */
