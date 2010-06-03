#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

enum c2b_state_bits {
    C2B_uptodate,
    C2B_dirty,
    C2B_lock,
};

#define INIT_C2B_BITS (0)

typedef struct castle_cache_block {
    c_disk_blk_t cdb;
    struct list_head pages;
    struct list_head list;
    /* TODO: dirty >> dirty_or_clean */
    struct list_head dirty;

    unsigned long state;
	atomic_t count;
    void (*end_io)(struct castle_cache_block *c2b, int uptodate);
    void *private; /* Can only be used if c2b is locked */
#ifdef CASTLE_DEBUG    
    char *file;
    int   line;
#endif

} c2_block_t;

#define CACHE_FNS(bit, name)					                    \
static inline void set_c2b_##name(c2_block_t *c2b)		            \
{									                                \
	set_bit(C2B_##bit, &(c2b)->state);				                \
}									                                \
static inline void clear_c2b_##name(c2_block_t *c2b)		        \
{									                                \
	clear_bit(C2B_##bit, &(c2b)->state);				            \
}									                                \
static inline int c2b_##name(c2_block_t *c2b)		                \
{									                                \
	return test_bit(C2B_##bit, &(c2b)->state);			            \
}

#define TAS_CACHE_FNS(bit, name)					                \
static inline int test_set_c2b_##name(c2_block_t *c2b)	            \
{									                                \
	return test_and_set_bit(C2B_##bit, &(c2b)->state);		        \
}									                                \
static inline int test_clear_c2b_##name(c2_block_t *c2b)	        \
{									                                \
	return test_and_clear_bit(C2B_##bit, &(c2b)->state);		    \
}

CACHE_FNS(uptodate, uptodate)
CACHE_FNS(dirty, dirty)
TAS_CACHE_FNS(dirty, dirty)
CACHE_FNS(lock, locked)
TAS_CACHE_FNS(lock, locked)

void fastcall __lock_c2b(c2_block_t *c2b);
void fastcall unlock_c2b(c2_block_t *c2b);
void fastcall dirty_c2b(c2_block_t *c2b);

#ifdef CASTLE_DEBUG
#define lock_c2b(_c2b)                \
{                                     \
	might_sleep();                    \
	if (test_set_c2b_locked(_c2b))    \
		__lock_c2b(_c2b);             \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#else
static inline void lock_c2b(c2_block_t *c2b)
{
	might_sleep();
	if (test_set_c2b_locked(c2b))
		__lock_c2b(c2b);
}
#endif


static inline void get_c2b(c2_block_t *c2b)
{
    atomic_inc(&c2b->count);
}

static inline void put_c2b(c2_block_t *c2b)
{
    atomic_dec(&c2b->count);
}

#define c2b_buffer(_c2b) ({                              \
    void *_buf;                                          \
    struct list_head *_l;                                \
    struct page *_pg;                                    \
    BUG_ON((_c2b)->pages.next       == &(_c2b)->pages);  \
    BUG_ON((_c2b)->pages.next->next != &(_c2b)->pages);  \
    _l  = (_c2b)->pages.next;                            \
    _pg = list_entry(_l, struct page, lru);              \
    _buf = pfn_to_kaddr(page_to_pfn(_pg));               \
    _buf;                                                \
})

/* The 'interesting' cache interface functions */
int         submit_c2b                (int rw, c2_block_t *c2b);
int         submit_c2b_sync           (int rw, c2_block_t *c2b);
c2_block_t* castle_cache_block_get    (c_disk_blk_t cdb);
void        castle_cache_flush_wakeup (void);


int castle_cache_init(void);
void castle_cache_fini(void);

#endif /* __CASTLE_CACHE_H__ */
