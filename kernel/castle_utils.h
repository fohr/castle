#ifndef __CASTLE_UTILS_H__
#define __CASTLE_UTILS_H__

#include <linux/log2.h>
#include <linux/skbuff.h>
#include "castle_public.h"
#include "castle.h"
#include "castle_debug.h"
#include "castle_cache.h"

#define ATOMIC(_i)    ((atomic_t)  ATOMIC_INIT(_i))
#define ATOMIC64(_i)  ((atomic64_t)ATOMIC64_INIT(_i))

/* Uses RW spinlock for synchronization. Use iterate_exclusive() for exclusive
 * access while iterating over the hash table. */
#define DEFINE_HASH_TBL(_prefix, _tab, _tab_size, _struct, _list_mbr, _key_t, _key)            \
                                                                                               \
static DEFINE_RWLOCK(_prefix##_hash_lock);                                                     \
static int _prefix##_nr_entries = 0;                                                           \
                                                                                               \
static inline int _prefix##_hash_idx(_key_t key)                                               \
{                                                                                              \
    unsigned long hash = 0UL;                                                                  \
                                                                                               \
    memcpy(&hash, &key, sizeof(_key_t) > 8 ? 8 : sizeof(_key_t));                              \
                                                                                               \
    return (int)(hash % _tab_size);                                                            \
}                                                                                              \
                                                                                               \
static inline _struct* __##_prefix##_hash_get(_key_t key);                                     \
                                                                                               \
static inline void _prefix##_hash_add(_struct *v)                                              \
{                                                                                              \
    int idx = _prefix##_hash_idx(v->_key);                                                     \
    unsigned long flags;                                                                       \
                                                                                               \
    write_lock_irqsave(&_prefix##_hash_lock, flags);                                           \
    BUG_ON(__##_prefix##_hash_get(v->_key));                                                   \
    list_add(&v->_list_mbr, &_tab[idx]);                                                       \
    _prefix##_nr_entries++;                                                                    \
    write_unlock_irqrestore(&_prefix##_hash_lock, flags);                                      \
}                                                                                              \
                                                                                               \
static inline void __##_prefix##_hash_remove(_struct *v)                                       \
{                                                                                              \
    list_del(&v->_list_mbr);                                                                   \
    _prefix##_nr_entries--;                                                                    \
}                                                                                              \
                                                                                               \
static inline void _prefix##_hash_remove(_struct *v)                                           \
{                                                                                              \
    unsigned long flags;                                                                       \
                                                                                               \
    write_lock_irqsave(&_prefix##_hash_lock, flags);                                           \
    list_del(&v->_list_mbr);                                                                   \
    BUG_ON(__##_prefix##_hash_get(v->_key));                                                   \
    write_unlock_irqrestore(&_prefix##_hash_lock, flags);                                      \
}                                                                                              \
                                                                                               \
static inline _struct* __##_prefix##_hash_get(_key_t key)                                      \
{                                                                                              \
    _struct *v;                                                                                \
    struct list_head *l;                                                                       \
    int idx = _prefix##_hash_idx(key);                                                         \
                                                                                               \
    list_for_each(l, &_tab[idx])                                                               \
    {                                                                                          \
        v = list_entry(l, _struct, _list_mbr);                                                 \
        if(memcmp(&v->_key, &key, sizeof(_key_t)) == 0)                                        \
            return v;                                                                          \
    }                                                                                          \
                                                                                               \
    return NULL;                                                                               \
}                                                                                              \
                                                                                               \
static inline _struct* _prefix##_hash_get(_key_t key)                                          \
{                                                                                              \
    _struct *v;                                                                                \
    unsigned long flags;                                                                       \
                                                                                               \
    read_lock_irqsave(&_prefix##_hash_lock, flags);                                            \
    v = __##_prefix##_hash_get(key);                                                           \
    read_unlock_irqrestore(&_prefix##_hash_lock, flags);                                       \
                                                                                               \
    return v;                                                                                  \
}                                                                                              \
                                                                                               \
static inline int __##_prefix##_nr_entries_get(void)                                           \
{                                                                                              \
    return _prefix##_nr_entries;                                                               \
}                                                                                              \
                                                                                               \
static inline int _prefix##_nr_entries_get(void)                                               \
{                                                                                              \
    int nr_entries;                                                                            \
    unsigned long flags;                                                                       \
                                                                                               \
    read_lock_irqsave(&_prefix##_hash_lock, flags);                                            \
    nr_entries = __##_prefix##_nr_entries_get();                                               \
    read_unlock_irqrestore(&_prefix##_hash_lock, flags);                                       \
                                                                                               \
    return nr_entries;                                                                         \
}                                                                                              \
                                                                                               \
static inline void __##_prefix##_hash_iterate(int (*fn)(_struct*, void*), void *arg)           \
{                                                                                              \
    struct list_head *l, *t;                                                                   \
    _struct *v;                                                                                \
    int i;                                                                                     \
                                                                                               \
    if(!_tab) goto out;                                                                        \
    for(i=0; i<_tab_size; i++)                                                                 \
    {                                                                                          \
        list_for_each_safe(l, t, &_tab[i])                                                     \
        {                                                                                      \
            v = list_entry(l, _struct, hash_list);                                             \
            if(fn(v, arg)) goto out;                                                           \
        }                                                                                      \
    }                                                                                          \
out:                                                                                           \
   return;                                                                                     \
}                                                                                              \
                                                                                               \
static inline void _prefix##_hash_iterate(int (*fn)(_struct*, void*), void *arg)               \
{                                                                                              \
    read_lock_irq(&_prefix##_hash_lock);                                                       \
    __##_prefix##_hash_iterate(fn, arg);                                                       \
    read_unlock_irq(&_prefix##_hash_lock);                                                     \
}                                                                                              \
                                                                                               \
static inline void _prefix##_hash_iterate_exclusive(int (*fn)(_struct*, void*), void *arg)     \
{                                                                                              \
    write_lock_irq(&_prefix##_hash_lock);                                                      \
    __##_prefix##_hash_iterate(fn, arg);                                                       \
    write_unlock_irq(&_prefix##_hash_lock);                                                    \
}                                                                                              \
                                                                                               \
static inline struct list_head* _prefix##_hash_alloc(void)                                     \
{                                                                                              \
    return castle_alloc(sizeof(struct list_head) * _tab_size);                                 \
}                                                                                              \
                                                                                               \
static inline void _prefix##_hash_init(void)                                                   \
{                                                                                              \
    int i;                                                                                     \
    for(i=0; i<_tab_size; i++)                                                                 \
        INIT_LIST_HEAD(&_tab[i]);                                                              \
}

/**
 * list_for_each_from - iterate over list of given type from the current point
 * @from:   current point to start from
 * @pos:    the &struct list_head to use as a loop cursor.
 * @head:   the head for your list.
 *
 * Iterate over list of given type, continuing from current position.
 */
#define list_for_each_from(from, pos, head)                                                    \
    for (pos = (from); prefetch(pos->next), pos != (head); pos = pos->next)

void list_append(struct list_head *head1, struct list_head *head2);

void * castle_alloc_func(size_t size);
void * castle_zalloc_func(size_t size);
void castle_free_func(void *ptr);

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

    if(!(str = castle_zalloc(str_len+1)))
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

c_bio_t *castle_utils_bio_alloc(int nr_bvecs);

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

/**
 * Checks whether there is an overlap between two pointer ranges. Check is inclusive,
 * that is function will return true, even if the ranges only have one point in common.
 *
 * @arg min1    Start of range1
 * @arg max1    End of range1
 * @arg min2    Start of range2
 * @arg max2    End of range2
 * @return true if there is an overlap in at least one point
 */
static inline int overlap(void *min1, void *max1, void *min2, void *max2)
{
    return (max1 >= min2) && (min1 <= max2);
}

/**
 * Checks whether a pointer is in the specified range.
 */
static inline int ptr_in_range(void *ptr, void *range_start, size_t range_size)
{
    return overlap(ptr, ptr, range_start, range_start + range_size);
}

/**
 * Converts the CVT type to the type field that will be stored in the btree.
 * It deals with local counters correctly, other than that it just returns
 * the CVT type field.
 */
inline static int cvt_type_to_btree_entry_type(int type)
{
    /* Local counters will be turned into inline counters. */
    if (type == CVT_TYPE_COUNTER_LOCAL_SET)
        return CVT_TYPE_COUNTER_SET;
    if (type == CVT_TYPE_COUNTER_LOCAL_ADD)
        return CVT_TYPE_COUNTER_ADD;

    /* Otherwise, just use the cvt type directly. */
    return type;
}

/**
 * Returns number of slaves known to the filesystem (including out of service slaves).
 */
static inline int castle_nr_slaves_get(void)
{
    struct list_head *lh;
    int nr_slaves;

    nr_slaves = 0;
    rcu_read_lock();
    list_for_each_rcu(lh, &castle_slaves.slaves)
        nr_slaves++;
    rcu_read_unlock();

    return nr_slaves;
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

    castle_printk(LOG_DEBUG, "%s used greatest stack depth: %lu bytes left, currently left %lu\n",
                current->comm,
                free,
                (unsigned long)&free - (unsigned long)end_of_stack(current));
}
#endif

/****** Stack implementation, designed to hold array indices ******/
typedef struct castle_uint32t_stack_t{
    uint32_t *_stack;
    uint32_t top; /* can't be bothered to provide an 'is_empty'; just check this! */
    uint32_t _max_top;
} c_uint32_stack;
int      castle_uint32_stack_construct(c_uint32_stack *stack, uint32_t size);
void     castle_uint32_stack_destroy(c_uint32_stack *stack);
void     castle_uint32_stack_push(c_uint32_stack *stack, uint32_t new_element);
uint32_t castle_uint32_stack_top_val_ret(c_uint32_stack *stack);
uint32_t castle_uint32_stack_pop(c_uint32_stack *stack);
void     castle_uint32_stack_reset(c_uint32_stack *stack);
/******************************************************************/


void castle_key_ptr_destroy(struct castle_key_ptr_t *key_ptr);
void castle_key_ptr_ref_cp(struct castle_key_ptr_t *dest, struct castle_key_ptr_t *src);

void *castle_alloc_maybe_func(size_t len, void *dst, size_t *dst_len);
void *castle_dup_or_copy_func(const void *src, size_t src_len, void *dst, size_t *dst_len);

/**
 * Store per-level castle_printk() ratelimit state.
 */
struct castle_printk_state {
    int             ratelimit_jiffies;
    int             ratelimit_burst;
    int             missed;             /**< Number of missed printk() since last message.  */
    unsigned long   toks;
    unsigned long   last_msg;
};

/**
 * Defines castle_printk() log levels.
 */
typedef enum {
    LOG_DEBUG = 0,  /**< Debug-related messages                     */
    LOG_INFO,       /**< Filesystem informational messages          */
    LOG_PERF,       /**< Performance related messages               */
    LOG_DEVEL,      /**< Ephemeral development messages             */
    LOG_USERINFO,   /**< Information messages aimed at the user     */
    LOG_WARN,       /**< Filesystem warnings                        */
    LOG_INIT,       /**< Init()/fini() messages                     */
    LOG_ERROR,      /**< Major error messages                       */
    LOG_UNLIMITED,  /**< Log level that does not get ratelimited    */
    MAX_CONS_LEVEL  /**< Counts number of levels (has to be last)   */
} c_printk_level_t;

void castle_printk(c_printk_level_t level, const char *fmt, ...);
int castle_printk_init(void);
void castle_printk_fini(void);

/**
 * Timer structure used to track how long an operation take.
 * It tracks when the interval is first initialised, how long it takes until it is
 * finished. It also supports pause/unpause (stop/start). It maintains the
 * total activity (sum of periods between start-stop).
 */
typedef struct castle_time_interval {
    struct timeval start;
    struct timeval end;
    struct timeval last_start;
    struct timeval total_active;
} c_time_interval_t;

/**
 * Re-implementation of a helper function for converting ns to timeval structure.
 * Note that timeval is lower resolution than nsecs.
 */
static inline struct timeval ns_to_timeval_private(const s64 nsec)
{
    struct timeval tv;

    tv.tv_sec  =  nsec / 1000000000LL;
    tv.tv_usec = (nsec % 1000000000LL) / 1000LL;

    return tv;
}

/**
 * Initialise timeval structure. Record NOW() as the start of the interval existence.
 */
static inline void castle_time_interval_init(c_time_interval_t *interval)
{
    memset(interval, 0, sizeof(c_time_interval_t));
    do_gettimeofday(&interval->start);
}

/**
 * Start an activity period. After @see castle_time_interval_init() the interval is stopped.
 * This needs to be started to start the activity.
 */
static inline void castle_time_interval_start(c_time_interval_t *interval)
{
    /* Last start must be set NULL if we starting again. */
    BUG_ON((interval->last_start.tv_sec != 0) || (interval->last_start.tv_usec != 0));
    do_gettimeofday(&interval->last_start);
}

/**
 * Finishes the activity period. Accounts the time delta (since start) into the total activity
 * period.
 */
static inline void castle_time_interval_stop(c_time_interval_t *interval)
{
    struct timeval current_time;
    long total_active;

    /* Last start must not be set NULL when stopping . */
    BUG_ON((interval->last_start.tv_sec == 0) && (interval->last_start.tv_usec == 0));
    /* Record current time. */
    do_gettimeofday(&current_time);
    /* Update total_active. */
    total_active  = timeval_to_ns(&interval->total_active);
    total_active += timeval_to_ns(&current_time);
    total_active -= timeval_to_ns(&interval->last_start);
    interval->total_active = ns_to_timeval_private(total_active);
    /* Reset last_start. */
    memset(&interval->last_start, 0, sizeof(struct timeval));
}

/**
 * Record the end of the interval existence. Note: no implicit @see castle_time_interval_stop().
 */
static inline void castle_time_interval_fini(c_time_interval_t *interval)
{
    do_gettimeofday(&interval->end);
}

/**
 * Print activity interval stats (start time, duration, and total activity period).
 *
 * @param printk_level @see c_printk_level_t
 * @param interval     interval to be printed
 * @param active_label what label string to use for total active period
 */
static inline void castle_time_interval_print(c_printk_level_t printk_level,
                                              c_time_interval_t *interval,
                                              char *active_label)
{
    long duration_ns;

    duration_ns  = timeval_to_ns(&interval->end);
    duration_ns -= timeval_to_ns(&interval->start);
    castle_printk(printk_level, "Started at: %ld.%06ld000, "
                                "duration: %ld.%09ld, "
                                "%s: %ld.%06ld000.\n",
                                interval->start.tv_sec,
                                interval->start.tv_usec,
                                (duration_ns / 1000000000LL),
                                (duration_ns % 1000000000LL),
                                active_label,
                                interval->total_active.tv_sec,
                                interval->total_active.tv_usec);
}


void        castle_counter_accumulating_reduce(c_val_tup_t *accumulator,
                                               c_val_tup_t delta_cvt,
                                               int delta_ancestral);
int         castle_counter_simple_reduce(c_val_tup_t *accumulator, c_val_tup_t delta_cvt);

void        castle_component_tree_prefetch(struct castle_component_tree *ct);

inline void list_swap(struct list_head *t1, struct list_head *t2);
void        list_sort(struct list_head *list,
                      int (*compare)(struct list_head *l1, struct list_head *l2));

void        skb_print(struct sk_buff *skb);
void        vl_bkey_print(c_printk_level_t level, const c_vl_bkey_t *key);

c_val_tup_t convert_to_cvt(uint8_t type, uint64_t length, c_ext_pos_t cep, void *inline_ptr,
                           castle_user_timestamp_t user_timestamp);

int         castle_from_user_copy(const char __user *from, int len, int max_len, char **to);

void        castle_wake_up_task(struct task_struct *task, int inhibit_cs);

void        castle_unmap_vm_area(void *addr_p, int nr_pages);
int         castle_map_vm_area(void *addr_p, struct page **pages, int nr_pages, pgprot_t prot);

uint32_t    murmur_hash_32(const void *key, int len, uint32_t seed);
uint64_t    murmur_hash_64(const void *key, int len, uint32_t seed);
void        castle_atomic64_max(uint64_t new_val, atomic64_t *v);
void        castle_atomic64_min(uint64_t new_val, atomic64_t *v);
uint32_t    castle_atomic_inc_cycle(uint32_t max, atomic_t *v);

#endif /* __CASTLE_UTILS_H__ */
