#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

enum c2p_state_bits {
    c2p_lock,
};

typedef struct castle_cache_page {
    unsigned long state;
    void (*end_io)(struct castle_cache_page *c2p, int uptodate);
    c_disk_blk_t cdb;
    struct page *page;
    struct list_head list;
} c2_page_t;

#define CACHE_FNS(bit, name)					                    \
static inline void set_c2p_##name(c2_page_t *c2p)		            \
{									                                \
	set_bit(c2p_##bit, &(c2p)->state);				                \
}									                                \
static inline void clear_c2p_##name(c2_page_t *c2p)		            \
{									                                \
	clear_bit(c2p_##bit, &(c2p)->state);				            \
}									                                \
static inline int c2p_##name(c2_page_t *c2p)		                \
{									                                \
	return test_bit(c2p_##bit, &(c2p)->state);			            \
}

#define TAS_CACHE_FNS(bit, name)					                \
static inline int test_set_c2p_##name(c2_page_t *c2p)	            \
{									                                \
	return test_and_set_bit(c2p_##bit, &(c2p)->state);		        \
}									                                \
static inline int test_clear_c2p_##name(c2_page_t *c2p)	            \
{									                                \
	return test_and_clear_bit(c2p_##bit, &(c2p)->state);		    \
}

CACHE_FNS(lock, locked)
TAS_CACHE_FNS(lock, locked)

void fastcall __lock_c2p(c2_page_t *c2p);
void fastcall unlock_c2p(c2_page_t *c2p);
static inline void lock_c2p(c2_page_t *c2p)
{
	might_sleep();
	if (test_set_c2p_locked(c2p))
		__lock_c2p(c2p);
}


int castle_cache_init(void);
void castle_cache_fini(void);

#endif /* __CASTLE_CACHE_H__ */
