#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

enum c2p_state_bits {
    C2P_uptodate,
    C2P_dirty,
    C2P_lock,
};

#define INIT_C2P_BITS (0)

typedef struct castle_cache_page {
    c_disk_blk_t cdb;
    struct page *page;
    struct list_head list;
    struct list_head dirty;

    unsigned long state;
	atomic_t count;
    void (*end_io)(struct castle_cache_page *c2p, int uptodate);
    void *private; /* Can only be used if c2p is locked */
} c2_page_t;

#define CACHE_FNS(bit, name)					                    \
static inline void set_c2p_##name(c2_page_t *c2p)		            \
{									                                \
	set_bit(C2P_##bit, &(c2p)->state);				                \
}									                                \
static inline void clear_c2p_##name(c2_page_t *c2p)		            \
{									                                \
	clear_bit(C2P_##bit, &(c2p)->state);				            \
}									                                \
static inline int c2p_##name(c2_page_t *c2p)		                \
{									                                \
	return test_bit(C2P_##bit, &(c2p)->state);			            \
}

#define TAS_CACHE_FNS(bit, name)					                \
static inline int test_set_c2p_##name(c2_page_t *c2p)	            \
{									                                \
	return test_and_set_bit(C2P_##bit, &(c2p)->state);		        \
}									                                \
static inline int test_clear_c2p_##name(c2_page_t *c2p)	            \
{									                                \
	return test_and_clear_bit(C2P_##bit, &(c2p)->state);		    \
}

CACHE_FNS(uptodate, uptodate)
CACHE_FNS(dirty, dirty)
TAS_CACHE_FNS(dirty, dirty)
CACHE_FNS(lock, locked)
TAS_CACHE_FNS(lock, locked)

void fastcall __lock_c2p(c2_page_t *c2p);
void fastcall unlock_c2p(c2_page_t *c2p);
void fastcall dirty_c2p(c2_page_t *c2p);
static inline void lock_c2p(c2_page_t *c2p)
{
	might_sleep();
	if (test_set_c2p_locked(c2p))
		__lock_c2p(c2p);
}

static inline void get_c2p(c2_page_t *c2p)
{
    atomic_inc(&c2p->count);
}

static inline void put_c2p(c2_page_t *c2p)
{
    atomic_dec(&c2p->count);
}

/* The 'interesting' cache interface functions */
int        submit_c2p                (int rw, c2_page_t *c2p);
c2_page_t* castle_cache_page_get     (c_disk_blk_t cdb);
void       castle_cache_flush_wakeup (void);


int castle_cache_init(void);
void castle_cache_fini(void);

#endif /* __CASTLE_CACHE_H__ */
