#include "castle_extent.h"

#ifndef __CASTLE_CACHE_H__
#define __CASTLE_CACHE_H__

struct castle_cache_block;
typedef void  (*c2b_end_io_t)(struct castle_cache_block *c2b, int did_io);

struct castle_cache_page;
typedef struct castle_cache_block {
    c_ext_pos_t                cep;
    atomic_t                   remaining;

    int                        nr_pages;        /**< Number of c2ps mapped by the block           */
    struct castle_cache_page **c2ps;            /**< Array of c2ps backing the buffer             */
    void                      *buffer;          /**< Linear mapping of the pages                  */

    struct hlist_node          hlist;           /**< Hash-list node                               */
    union {
        struct list_head       free;            /**< Position on freelist.                        */
        struct list_head       clean;           /**< Position on freelist.                        */
        struct list_head       reserve;         /**< Position on meta-extent reserve freelist.    */
        struct rb_node         rb_dirtytree;    /**< Per-extent dirtytree RB-node.                */
    };
    c_ext_dirtytree_t         *dirtytree;       /**< Dirtytree c2b is a member of.                */

    struct c2b_state {
        unsigned long          bits:56;         /**< State bitfield                               */
        unsigned long          softpin_cnt:8;   /**< Softpin count                                */
    } state;
    atomic_t                   count;           /**< Count of active consumers                    */
    atomic_t                   lock_cnt;
    c2b_end_io_t               end_io;          /**< IO CB handler routine*/
    void                      *private;         /**< Can only be used if c2b is locked            */
    struct work_struct         work;
#ifdef CASTLE_DEBUG
    char                      *file;
    int                        line;
#endif
} c2_block_t;

/**********************************************************************************************
 * Locking.
 */
void __lock_c2b                     (c2_block_t *c2b, int write, int first);
int  __trylock_c2b                  (c2_block_t *c2b, int write);
int  __trylock_node                 (c2_block_t *c2b, int write);
void __downgrade_write_c2b          (c2_block_t *c2b, int first);
void __write_unlock_c2b             (c2_block_t *c2b, int first);
void __read_unlock_c2b              (c2_block_t *c2b, int first);
//int write_trylock_c2b             (c2_block_t *c2b);
//int read_trylock_c2b              (c2_block_t *c2b);
//void write_lock_c2b               (c2_block_t *c2b);
//void read_lock_c2b                (c2_block_t *c2b);
#define downgrade_write_c2b(_c2b)   __downgrade_write_c2b(_c2b, 0)
#define write_unlock_c2b(_c2b)      __write_unlock_c2b(_c2b, 0)
#define read_unlock_c2b(_c2b)       __read_unlock_c2b(_c2b, 0)
//int write_trylock_node            (c2_block_t *c2b);
//int read_trylock_node             (c2_block_t *c2b);
//void write_lock_node              (c2_block_t *c2b);
//void read_lock_node               (c2_block_t *c2b);
#define downgrade_write_node(_c2b)  __downgrade_write_c2b(_c2b, 1)
#define write_unlock_node(_c2b)     __write_unlock_c2b(_c2b, 1)
#define read_unlock_node(_c2b)      __read_unlock_c2b(_c2b, 1)
int  c2b_read_locked                (c2_block_t *c2b);
int  c2b_write_locked               (c2_block_t *c2b);

static inline int write_trylock_c2b(c2_block_t *c2b)
{
    return __trylock_c2b(c2b, 1);
}
static inline int read_trylock_c2b(c2_block_t *c2b)
{
    return __trylock_c2b(c2b, 0);
}

static inline int write_trylock_node(c2_block_t *c2b)
{
    return __trylock_node(c2b, 1 /*write*/);
}
static inline int read_trylock_node(c2_block_t *c2b)
{
    return __trylock_node(c2b, 0 /*write*/);
}

/*
 * c2b locks that span all of the c2b->c2ps.
 */
#ifdef CASTLE_DEBUG
#define write_lock_c2b(_c2b)          \
{                                     \
    might_sleep();                    \
    __lock_c2b(_c2b, 1, 0);           \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#define read_lock_c2b(_c2b)           \
{                                     \
    might_sleep();                    \
    __lock_c2b(_c2b, 0, 0);           \
}
#else /* CASTLE_DEBUG */
#define write_lock_c2b(_c2b)          \
    __lock_c2b(_c2b, 1, 0);
#define read_lock_c2b(_c2b)           \
    __lock_c2b(_c2b, 0, 0);
#endif /* CASTLE_DEBUG */

/*
 * c2b locks that lock just c2b->c2ps[0] (e.g. first c2p).
 */
#ifdef CASTLE_DEBUG
#define write_lock_node(_c2b)         \
{                                     \
    might_sleep();                    \
    __lock_c2b(_c2b, 1, 1);           \
    (_c2b)->file = __FILE__;          \
    (_c2b)->line = __LINE__;          \
}
#define read_lock_node(_c2b)          \
{                                     \
    might_sleep();                    \
    __lock_c2b(_c2b, 0, 1);           \
}
#else /* CASTLE_DEBUG */
#define write_lock_node(_c2b)         \
    __lock_c2b(_c2b, 1, 1);
#define read_lock_node(_c2b)          \
    __lock_c2b(_c2b, 0, 1);
#endif /* CASTLE_DEBUG */

/**********************************************************************************************
 * Dirtying & up-to-date.
 */
int  c2b_dirty              (c2_block_t *c2b);
void dirty_c2b              (c2_block_t *c2b);
void clean_c2b              (c2_block_t *c2b);
int  c2b_uptodate           (c2_block_t *c2b);
void update_c2b             (c2_block_t *c2b);
int  c2b_bio_error          (c2_block_t *c2b);
void set_c2b_no_resubmit    (c2_block_t *c2b);
void clear_c2b_no_resubmit  (c2_block_t *c2b);
int  c2b_remap              (c2_block_t *c2b);
void set_c2b_remap          (c2_block_t *c2b);
void clear_c2b_remap        (c2_block_t *c2b);
void set_c2b_in_flight      (c2_block_t *c2b);
void set_c2b_eio            (c2_block_t *c2b);
void clear_c2b_eio          (c2_block_t *c2b);
int  c2b_eio                (c2_block_t *c2b);
void castle_cache_extent_dirtytree_remove(c_ext_dirtytree_t *dirtytree);

/**********************************************************************************************
 * Refcounts.
 */
static inline void get_c2b(c2_block_t *c2b)
{
    atomic_inc(&c2b->count);
}

static inline void put_c2b(c2_block_t *c2b)
{
#ifdef DEBUG
    BUG_ON(c2b_write_locked(c2b));
#endif
    BUG_ON(atomic_read(&c2b->count) == 0);
    atomic_dec(&c2b->count);
}

#define check_and_put_c2b(_c2b)                                                     \
do {                                                                                \
    if (_c2b)                                                                       \
        put_c2b(_c2b);                                                              \
} while(0)

extern void put_c2b_and_demote(c2_block_t *c2b);


/**********************************************************************************************
 * Advising the cache.
 */
enum c2_advise_bits {
    C2_ADV_cep,
    C2_ADV_extent,  /** @FIXME needs to be folded into C2_ADV_cep */
    C2_ADV_prefetch,
    C2_ADV_hardpin,
    C2_ADV_softpin,
    C2_ADV_static,
    C2_ADV_adaptive,
};


typedef uint32_t c2_advise_t;
#define C2_ADV_CEP          ((c2_advise_t) (1<<C2_ADV_cep))
#define C2_ADV_EXTENT       ((c2_advise_t) (1<<C2_ADV_extent))

#define C2_ADV_PREFETCH     ((c2_advise_t) (1<<C2_ADV_prefetch))
#define C2_ADV_HARDPIN      ((c2_advise_t) (1<<C2_ADV_hardpin))
#define C2_ADV_SOFTPIN      ((c2_advise_t) (1<<C2_ADV_softpin))

#define C2_ADV_STATIC       ((c2_advise_t) (1<<C2_ADV_static))
#define C2_ADV_ADAPTIVE     ((c2_advise_t) (1<<C2_ADV_adaptive))

int castle_cache_advise (c_ext_pos_t s_cep, c2_advise_t advise, int chunks,
                         int priority, int debug);
int castle_cache_advise_clear (c_ext_pos_t s_cep, c2_advise_t advise, int chunks,
                               int priority, int debug);
void castle_cache_prefetch_pin(c_ext_pos_t cep, int chunks, c2_advise_t advise);
void castle_cache_extent_flush(c_ext_id_t ext_id,
                               uint64_t start,
                               uint64_t size,
                               unsigned int ratelimit);
void castle_cache_extent_evict(c_ext_dirtytree_t *dirtytree, c_chk_cnt_t start, c_chk_cnt_t count);
void castle_cache_prefetches_wait(void);

/**********************************************************************************************
 * Misc.
 */
#define c2b_buffer(_c2b)    ((_c2b)->buffer)

int                        castle_stats_read               (void);

/**********************************************************************************************
 * The 'interesting' cache interface functions
 */
int         submit_c2b                (int rw, c2_block_t *c2b);
int         submit_c2b_sync           (int rw, c2_block_t *c2b);
int         submit_c2b_sync_barrier   (int rw, c2_block_t *c2b);
int         submit_c2b_rda            (int rw, c2_block_t *c2b);
int         submit_c2b_remap_rda      (c2_block_t *c2b, c_disk_chk_t *remap_chunks, int nr_remaps);
int         submit_direct_io          (int rw, struct block_device *bdev, sector_t sector,
                                       struct page **iopages, int nr_pages);

int         c2b_has_clean_pages       (c2_block_t *c2b);

int         castle_cache_block_read   (c2_block_t *c2b, c2b_end_io_t end_io, void *private);
int         castle_cache_block_sync_read(c2_block_t *c2b);
#define     castle_cache_page_block_reserve() \
            castle_cache_block_get    ((c_ext_pos_t){RESERVE_EXT_ID, 0}, 1)
c2_block_t* castle_cache_block_get    (c_ext_pos_t  cep, int nr_pages);
void        castle_cache_block_hardpin  (c2_block_t *c2b);
void        castle_cache_block_unhardpin(c2_block_t *c2b);
void        castle_cache_block_softpin  (c2_block_t *c2b);
int         castle_cache_block_unsoftpin(c2_block_t *c2b);
void        castle_cache_page_block_unreserve(c2_block_t *c2b);
int         castle_cache_extent_flush_schedule (c_ext_id_t ext_id, uint64_t start, uint64_t size);


int                        castle_checkpoint_init          (void);
void                       castle_checkpoint_fini          (void);
int                        castle_checkpoint_version_inc   (void);
void                       castle_checkpoint_ratelimit_set (unsigned long ratelimit);
void                       castle_checkpoint_wait          (void);
int                        castle_chk_disk                 (void);

void                       castle_cache_stats_print        (int verbose);
int                        castle_cache_size_get           (void);
int                        castle_cache_block_destroy      (c2_block_t *c2b);
void                       castle_cache_dirtytree_demote   (c_ext_dirtytree_t *dirtytree);
/**********************************************************************************************
 * Cache init/fini.
 */
int  castle_cache_init(void);
void castle_cache_fini(void);

#ifdef CASTLE_DEBUG
void castle_cache_debug(void);
#endif

#define MIN_CHECKPOINT_PERIOD 5
#define MAX_CHECKPOINT_PERIOD 3600

#endif /* __CASTLE_CACHE_H__ */
