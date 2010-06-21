#ifndef __CASTLE_UTILS_H__
#define __CASTLE_UTILS_H__

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

void inline list_swap(struct list_head *t1, struct list_head *t2);
void        list_sort(struct list_head *list, 
                      int (*compare)(struct list_head *l1, struct list_head *l2));

#endif /* __CASTLE_UTILS_H__ */

