#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

enum c2b_state_bits {
    C2B_uptodate,
    C2B_dirty,
    C2B_flushing,
};

#define INIT_C2B_BITS (0)

typedef struct castle_cache_block {
    c_ext_pos_t           cep;
    atomic_t              remaining;
    int                   nr_pages;
    struct list_head      pages;
    void                 *buffer; /* Linear mapping of the pages */
    struct list_head      list;
    struct list_head      dirty_or_clean;

    struct rw_semaphore   lock;
    unsigned long         state;
	atomic_t              count;
    void                (*end_io)(struct castle_cache_block *c2b, int uptodate);
    void                 *private; /* Can only be used if c2b is locked */
#ifdef CASTLE_DEBUG       
    char                 *file;
    int                   line;
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
CACHE_FNS(flushing, flushing)
TAS_CACHE_FNS(flushing, flushing)

void __lock_c2b(c2_block_t *c2b, int write_mode);
int __trylock_c2b(c2_block_t *c2b, int write_mode);
void unlock_c2b(c2_block_t *c2b);
void unlock_c2b_read(c2_block_t *c2b);
int c2b_locked(c2_block_t *c2b);
void dirty_c2b(c2_block_t *c2b);

#ifdef CASTLE_DEBUG
#define lock_c2b(_c2b)                \
{                                     \
	might_sleep();                    \
     __lock_c2b(_c2b, 1);             \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#define lock_c2b_read(_c2b)           \
{                                     \
	might_sleep();                    \
     __lock_c2b(_c2b, 0);             \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#else
static inline void lock_c2b(c2_block_t *c2b)
{
     __lock_c2b(c2b, 1);
}
static inline void lock_c2b_read(c2_block_t *c2b)
{
     __lock_c2b(c2b, 0);
}
#endif

static inline int trylock_c2b(c2_block_t *c2b)
{
     return __trylock_c2b(c2b, 1);
}
static inline int trylock_c2b_read(c2_block_t *c2b)
{
     return __trylock_c2b(c2b, 0);
}

static inline void get_c2b(c2_block_t *c2b)
{
    atomic_inc(&c2b->count);
}

static inline void put_c2b(c2_block_t *c2b)
{
    BUG_ON(atomic_read(&c2b->count) == 0);
    atomic_dec(&c2b->count);
}

#define c2b_buffer(_c2b)    ((_c2b)->buffer)

/* The 'interesting' cache interface functions */
int         submit_c2b                (int rw, c2_block_t *c2b);
int         submit_c2b_sync           (int rw, c2_block_t *c2b);
#define     castle_cache_page_block_get(_cep) \
            castle_cache_block_get    (_cep, 1)
c2_block_t* castle_cache_block_get    (c_ext_pos_t  cep, int nr_pages);
void        castle_cache_flush_wakeup (void);

/* MStore related functions */ 
int                        castle_mstore_iterator_has_next (struct castle_mstore_iter *iter);
void                       castle_mstore_iterator_next     (struct castle_mstore_iter *iter,
                                                            void *entry,
                                                            c_mstore_key_t *key);
void                       castle_mstore_iterator_destroy  (struct castle_mstore_iter *iter);
struct castle_mstore_iter* castle_mstore_iterate           (struct castle_mstore *store);
void                       castle_mstore_entry_update      (struct castle_mstore *store,
                                                            c_mstore_key_t key,
                                                            void *entry);
void                       castle_mstore_entry_delete      (struct castle_mstore *store,
                                                            c_mstore_key_t key);
c_mstore_key_t             castle_mstore_entry_insert      (struct castle_mstore *store,
                                                            void *entry);
struct castle_mstore*      castle_mstore_open              (c_mstore_id_t store_id,
                                                            size_t entry_size);
struct castle_mstore*      castle_mstore_init              (c_mstore_id_t store_id,
                                                            size_t entry_size);
void                       castle_mstore_fini              (struct castle_mstore *store);

void                       castle_cache_print_stats        (void);

/* Cache init/fini */
int  castle_cache_init(void);
void castle_cache_fini(void);

#ifdef CASTLE_DEBUG
void castle_cache_debug(void);
#endif

#endif /* __CASTLE_CACHE_H__ */
