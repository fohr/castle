#ifndef __CASTLE_UTILS_H__
#define __CASTLE_UTILS_H__

#include <linux/skbuff.h>
#include "castle_public.h"
#include "castle.h"
#include "castle_debug.h"

#define ATOMIC(_i)  ((atomic_t)ATOMIC_INIT(_i))

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
    return (int)(hash % _tab_size);                                                  \
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
static inline void __##_prefix##_hash_iterate(int (*fn)(_struct*, void*), void *arg) \
{                                                                                    \
    struct list_head *l, *t;                                                         \
    _struct *v;                                                                      \
    int i;                                                                           \
                                                                                     \
    if(!_tab) goto out;                                                              \
    for(i=0; i<_tab_size; i++)                                                       \
    {                                                                                \
        list_for_each_safe(l, t, &_tab[i])                                           \
        {                                                                            \
            v = list_entry(l, _struct, hash_list);                                   \
            if(fn(v, arg)) goto out;                                                 \
        }                                                                            \
    }                                                                                \
out:                                                                                 \
   return;                                                                           \
}                                                                                    \
                                                                                     \
static inline void _prefix##_hash_iterate(int (*fn)(_struct*, void*), void *arg)     \
{                                                                                    \
    spin_lock_irq(&_prefix##_hash_lock);                                             \
    __##_prefix##_hash_iterate(fn, arg);                                             \
    spin_unlock_irq(&_prefix##_hash_lock);                                           \
}                                                                                    \
                                                                                     \
static inline struct list_head* _prefix##_hash_alloc(void)                           \
{                                                                                    \
    return castle_malloc(sizeof(struct list_head) * _tab_size, GFP_KERNEL);          \
}                                                                                    \
                                                                                     \
static void inline _prefix##_hash_init(void)                                         \
{                                                                                    \
    int i;                                                                           \
    for(i=0; i<_tab_size; i++)                                                       \
        INIT_LIST_HEAD(&_tab[i]);                                                    \
}

/* Reference Hash Table with reference count on each structure */
#define DEFINE_RHASH_TBL(_prefix, _tab, _tab_size, _struct, _list_mbr, _key_t, _key, _ref_mbr) \
                                                                                     \
DEFINE_HASH_TBL(_prefix, _tab, _tab_size, _struct, _list_mbr, _key_t, _key)          \
static DECLARE_WAIT_QUEUE_HEAD(_prefix##_wait_q);                                    \
                                                                                     \
static inline void _prefix##_rhash_add(_struct *v)                                   \
{                                                                                    \
    int idx = _prefix##_hash_idx(v->_key);                                           \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    v->_ref_mbr  = 0;                                                                \
    list_add(&v->_list_mbr, &_tab[idx]);                                             \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
}                                                                                    \
                                                                                     \
static inline _struct* _prefix##_rhash_get(_key_t key)                               \
{                                                                                    \
    _struct *v;                                                                      \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    v = __##_prefix##_hash_get(key);                                                 \
    if (v)                                                                           \
        v->_ref_mbr++;                                                               \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
                                                                                     \
    return v;                                                                        \
}                                                                                    \
                                                                                     \
static inline void _prefix##_rhash_put(_struct *v)                                   \
{                                                                                    \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    if (v)                                                                           \
    {                                                                                \
        v->_ref_mbr--;                                                               \
        wake_up(&_prefix##_wait_q);                                                  \
    }                                                                                \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
}                                                                                    \
                                                                                     \
static inline void _prefix##_rhash_remove(_struct *v)                                \
{                                                                                    \
    unsigned long flags;                                                             \
                                                                                     \
    spin_lock_irqsave(&_prefix##_hash_lock, flags);                                  \
    debug("Waiting to delete ext: %llu|ref:%u\n", v->ext_id, v->_ref_mbr);           \
    while (v->_ref_mbr != 0)                                                         \
    {                                                                                \
        spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                         \
        wait_event(_prefix##_wait_q, (v->_ref_mbr == 0));                            \
        spin_lock_irqsave(&_prefix##_hash_lock, flags);                              \
    }                                                                                \
    list_del(&v->_list_mbr);                                                         \
    debug("Deleted extent: %llu\n", v->ext_id);                                      \
    spin_unlock_irqrestore(&_prefix##_hash_lock, flags);                             \
}                                                                                    \

static inline uint32_t BUF_L_GET(const char *buf)
{
    __be32 word;

    memcpy(&word, buf, 4);

    return ntohl(word);
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

    BUG_ON(skb == NULL);
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

    if(!(str = castle_zalloc(str_len+1, GFP_KERNEL)))
        return NULL;

    BUG_ON(skb_copy_bits(skb, 0, str, str_len) < 0);
    str_len += (str_len % 4 == 0 ? 0 : 4 - str_len % 4);
    BUG_ON(!pskb_pull(skb, str_len));

    return str;
}

static inline void SKB_STR_CPY(struct sk_buff *skb, void *dst, int str_len, int round)
{
    uint32_t *dst32 = (uint32_t *)dst;
    
    BUG_ON(str_len > skb->len);
    BUG_ON(skb_copy_bits(skb, 0, dst32, str_len) < 0);
    if(round)
        str_len += (str_len % 4 == 0 ? 0 : 4 - str_len % 4);
    BUG_ON(!pskb_pull(skb, str_len));
}

static inline c_vl_key_t* SKB_VL_KEY_GET(struct sk_buff *skb, int max_len)
{
    uint32_t key_len = SKB_L_GET(skb);
    c_vl_key_t *vlk;
    
    if((key_len > max_len) || (key_len > skb->len))
        return NULL;

    if(!(vlk = castle_zalloc(key_len+4, GFP_KERNEL)))
        return NULL;

    vlk->length = key_len;
    BUG_ON(skb_copy_bits(skb, 0, &vlk->key, key_len) < 0);
    key_len += (key_len % 4 == 0 ? 0 : 4 - key_len % 4);
    BUG_ON(!pskb_pull(skb, key_len));

    return vlk;
}

static inline c_bio_t* castle_utils_bio_alloc(int nr_bvecs)
{
    c_bio_t *c_bio;
    c_bvec_t *c_bvecs;
    int i;

    /* Allocate bio & bvec structures in one memory block */
    c_bio = castle_malloc(sizeof(c_bio_t) + nr_bvecs * sizeof(c_bvec_t), GFP_NOIO);
    if(!c_bio)
        return NULL;
    c_bvecs = (c_bvec_t *)(c_bio + 1);
    for(i=0; i<nr_bvecs; i++)
    {
        c_bvecs[i].c_bio = c_bio;
#ifdef CASTLE_PERF_DEBUG    
        c_bvecs[i].timeline = NULL;
#endif
    }
    c_bio->c_bvecs = c_bvecs; 
    /* Single reference taken out, the user decides how many more to take */
    c_bio->count   = ATOMIC(1);
    c_bio->err     = 0;

    return c_bio;
}

static inline void castle_utils_bio_free(c_bio_t *bio)
{
    castle_free(bio);
}

static inline int list_length(struct list_head *head)
{
    struct list_head *l;
    int length = 0; 

    list_for_each(l, head)
        length++;

    return length;
}

#ifdef DEBUG
#include <linux/sched.h>
static USED void check_stack_usage(void)
{
    unsigned long *n = end_of_stack(current) + 1;
    unsigned long free;

    while (*n == 0)
        n++;
    free = (unsigned long)n - (unsigned long)end_of_stack(current);

    printk("%s used greatest stack depth: %lu bytes left, currently left %lu\n",
                current->comm, 
                free,
                (unsigned long)&free - (unsigned long)end_of_stack(current));
}
#endif

#ifdef PERF_DEBUG
#define perf_event(_f, _a...)  do {                                                \
                                  struct timeval time;                             \
                                  do_gettimeofday(&time);                          \
                                  printk("***mark("_f", %ld, %ld)\n",              \
                                      ##_a, time.tv_sec, time.tv_usec);            \
                               } while(0)
#else
#define perf_event(_f, ...)    ((void)0)
#endif

void inline list_swap(struct list_head *t1, struct list_head *t2);
void        list_sort(struct list_head *list, 
                      int (*compare)(struct list_head *l1, struct list_head *l2));
void        vl_key_print(c_vl_key_t *vl_key);
void        vl_okey_print(c_vl_okey_t *key);
void        vl_bkey_print(c_vl_bkey_t *key);
void        skb_print(struct sk_buff *skb);


void        castle_unmap_vm_area(void *addr_p, int nr_pages);
int         castle_map_vm_area(void *addr_p, struct page **pages, int nr_pages, pgprot_t prot);

#endif /* __CASTLE_UTILS_H__ */

