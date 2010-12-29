#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

struct castle_cache_page;
typedef struct castle_cache_block {
    c_ext_pos_t                cep;
    atomic_t                   remaining;
    int                        nr_pages;

    struct castle_cache_page **c2ps; 

    void                      *buffer; /* Linear mapping of the pages */
    struct hlist_node          hlist;
    union {
        struct list_head       dirty;
        struct list_head       clean;
        struct list_head       free;
    };
                             
    unsigned long              state;
    atomic_t                   lock_cnt;
	atomic_t                   count;
    void                     (*end_io)(struct castle_cache_block *c2b);
    void                      *private; /* Can only be used if c2b is locked */
#ifdef CASTLE_DEBUG            
    char                      *file;
    int                        line;
#endif
} c2_block_t;

/**********************************************************************************************
 * Locking. 
 */
void __lock_c2b      (c2_block_t *c2b, int write_mode);
int  __trylock_c2b   (c2_block_t *c2b, int write_mode);
void write_unlock_c2b(c2_block_t *c2b);
void read_unlock_c2b (c2_block_t *c2b);
int  c2b_read_locked (c2_block_t *c2b);
int  c2b_write_locked(c2_block_t *c2b);

#ifdef CASTLE_DEBUG
#define write_lock_c2b(_c2b)          \
{                                     \
	might_sleep();                    \
     __lock_c2b(_c2b, 1);             \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#define read_lock_c2b(_c2b)           \
{                                     \
	might_sleep();                    \
     __lock_c2b(_c2b, 0);             \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#else /* CASTLE_DEBUG */
#define write_lock_c2b(_c2b)          \
     __lock_c2b(_c2b, 1);

#define read_lock_c2b(_c2b)           \
     __lock_c2b(_c2b, 0);
#endif /* CASTLE_DEBUG */

static inline int write_trylock_c2b(c2_block_t *c2b)
{
     return __trylock_c2b(c2b, 1);
}
static inline int read_trylock_c2b(c2_block_t *c2b)
{
     return __trylock_c2b(c2b, 0);
}

/**********************************************************************************************
 * Dirting & up-to-date. 
 */
int  c2b_dirty   (c2_block_t *c2b);
void dirty_c2b   (c2_block_t *c2b);
int  c2b_uptodate(c2_block_t *c2b);
void update_c2b  (c2_block_t *c2b);

/**********************************************************************************************
 * Refcounts. 
 */
static inline void get_c2b(c2_block_t *c2b)
{
    atomic_inc(&c2b->count);
}

static inline void put_c2b(c2_block_t *c2b)
{
    BUG_ON(atomic_read(&c2b->count) == 0);
    atomic_dec(&c2b->count);
}

/**********************************************************************************************
 * Advising the cache. 
 */
typedef uint32_t c2b_advise_t;
#define C2B_PREFETCH_FRWD    ((c2b_advise_t)0x00000001)
#define C2B_PREFETCH_BACK    ((c2b_advise_t)0x00000002)
int castle_cache_block_advise (c2_block_t *c2b, c2b_advise_t advise);
/** @FIXME make these advise targets */
void castle_cache_prefetch_extent_lock (c_ext_id_t ext_id);
void castle_cache_prefetch_extent_unlock (c_ext_id_t ext_id);

/**********************************************************************************************
 * Misc. 
 */
#define c2b_buffer(_c2b)    ((_c2b)->buffer)

/**********************************************************************************************
 * The 'interesting' cache interface functions 
 */
int         submit_c2b                (int rw, c2_block_t *c2b);
int         submit_c2b_sync           (int rw, c2_block_t *c2b);
#define     castle_cache_page_block_get(_cep) \
            castle_cache_block_get    (_cep, 1)
c2_block_t* castle_cache_block_get    (c_ext_pos_t  cep, int nr_pages);
void        castle_cache_flush_wakeup (void);
int         castle_cache_extent_flush (c_ext_id_t ext_id, uint64_t start, uint64_t size);
int         castle_cache_extent_flush_schedule (c_ext_id_t ext_id, uint64_t start, uint64_t size);


/**********************************************************************************************
 * MStore related functions 
 */ 
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

int                        castle_checkpoint_init          (void);
void                       castle_checkpoint_fini          (void);
int                        castle_checkpoint_version_inc   (void);
int                        castle_chk_disk                 (void);

void                       castle_cache_stats_print        (int verbose);

/**********************************************************************************************
 * Cache init/fini. 
 */ 
int  castle_cache_init(void);
void castle_cache_fini(void);

#ifdef CASTLE_DEBUG
void castle_cache_debug(void);
#endif

#endif /* __CASTLE_CACHE_H__ */
