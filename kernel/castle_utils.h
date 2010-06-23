#ifndef __CASTLE_UTILS_H__
#define __CASTLE_UTILS_H__

#include <linux/skbuff.h>

#define DEFINE_HASH_TBL(_prefix, _tab, _tab_size, _struct, _list_mbr, _key_t, _key)  \
                                                                                     \
static DEFINE_SPINLOCK(_prefix##_hash_lock);                                         \
                                                                                     \
static inline int _prefix##_hash_idx(_key_t key)                                     \
{                                                                                    \
    unsigned long hash = 0UL;                                                        \
                                                                                     \
    memcpy(&hash, &key, sizeof(_key_t) > 8 ? 8 : sizeof(_key_t));                    \
                                                                                     \
    return (int)(key % _tab_size);                                                   \
}                                                                                    \
                                                                                     \
static inline void _prefix##_hash_add(_struct *v)                                    \
{                                                                                    \
    int idx = _prefix##_hash_idx(v->_key);                                           \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    list_add(&v->_list_mbr, &_tab[idx]);                                             \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
}                                                                                    \
                                                                                     \
static inline void __##_prefix##_hash_remove(_struct *v)                             \
{                                                                                    \
    list_del(&v->_list_mbr);                                                         \
}                                                                                    \
                                                                                     \
static inline void _prefix##_hash_remove(_struct *v)                                 \
{                                                                                    \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    list_del(&v->_list_mbr);                                                         \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
}                                                                                    \
                                                                                     \
static inline _struct* __##_prefix##_hash_get(_key_t key)                            \
{                                                                                    \
    _struct *v;                                                                      \
    struct list_head *l;                                                             \
    int idx = _prefix##_hash_idx(key);                                               \
                                                                                     \
    list_for_each(l, &_tab[idx])                                                     \
    {                                                                                \
        v = list_entry(l, _struct, _list_mbr);                                       \
        if(memcmp(&v->_key, &key, sizeof(_key_t)) == 0)                              \
            return v;                                                                \
    }                                                                                \
                                                                                     \
    return NULL;                                                                     \
}                                                                                    \
                                                                                     \
static inline _struct* _prefix##_hash_get(_key_t key)                                \
{                                                                                    \
    _struct *v;                                                                      \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    v = __##_prefix##_hash_get(key);                                                 \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
                                                                                     \
    return v;                                                                        \
}                                                                                    \
                                                                                     \
static inline void _prefix##_hash_iterate(int (*fn)(_struct*, void*), void *arg)     \
{                                                                                    \
    struct list_head *l, *t;                                                         \
    _struct *v;                                                                      \
    int i;                                                                           \
                                                                                     \
    spin_lock_irq(&_prefix##_hash_lock);                                             \
    for(i=0; i<_tab_size; i++)                                                       \
    {                                                                                \
        list_for_each_safe(l, t, &_tab[i])                                           \
        {                                                                            \
            v = list_entry(l, _struct, hash_list);                                   \
            if(fn(v, arg)) goto out;                                                 \
        }                                                                            \
    }                                                                                \
out:                                                                                 \
    spin_unlock_irq(&_prefix##_hash_lock);                                           \
}                                                                                    \
                                                                                     \
static inline struct list_head* _prefix##_hash_alloc(void)                           \
{                                                                                    \
    return kmalloc(sizeof(struct list_head) * _tab_size, GFP_KERNEL);                \
}                                                                                    \
                                                                                     \
static void inline _prefix##_hash_init(void)                                         \
{                                                                                    \
    int i;                                                                           \
    for(i=0; i<_tab_size; i++)                                                       \
        INIT_LIST_HEAD(&_tab[i]);                                                    \
}

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

void inline list_swap(struct list_head *t1, struct list_head *t2);
void        list_sort(struct list_head *list, 
                      int (*compare)(struct list_head *l1, struct list_head *l2));
void        skb_print(struct sk_buff *skb);

#endif /* __CASTLE_UTILS_H__ */

