#ifndef __CASTLE_EXTENT_H__
#define __CASTLE_EXTENT_H__

#include "castle.h"

typedef enum {
    DEAD_EXT_FLUSH_PRIO,
    LARGE_OBJS_FLUSH_PRIO,
    DEFAULT_FLUSH_PRIO,
    LARGE_CT_FLUSH_PRIO,
    MEDIUM_CT_FLUSH_PRIO,
    SMALL_CT_FLUSH_PRIO,
    META_FLUSH_PRIO,
} c_ext_flush_prio_t;
#define NR_EXTENT_FLUSH_PRIOS   16

/**
 * Extent dirtytree structure.
 *
 * ref_cnt: 1 reference held by the extent
 *          1 reference per dirty c2b
 */
typedef struct castle_extent_dirtytree {
    c_ext_id_t          ext_id;     /**< Extent ID this dirtylist describes.          */
    spinlock_t          lock;       /**< Protects count, rb_root.                     */
    atomic_t            ref_cnt;    /**< References to this dirtylist.                */
    struct rb_root      rb_root;    /**< RB-tree of dirty c2bs.                       */
    struct list_head    list;       /**< Position in a castle_cache_extent_dirtylist. */
    uint8_t             flush_prio; /**< Decides which dirtylist to use (low #, is
                                         higher priority.                             */
    int                 nr_pages;   /**< Sum of c2b->nr_pages for c2bs in tree.
                                         Protected by lock.                           */
#ifdef CASTLE_PERF_DEBUG
    c_chk_cnt_t         ext_size;   /**< Size of extent when created (in chunks).     */
    c_ext_type_t        ext_type;   /**< Extent type when created.                    */
#endif
} c_ext_dirtytree_t;

typedef struct castle_extent {
    c_ext_id_t          ext_id;         /* Unique extent ID                             */
    c_chk_cnt_t         size;           /* Number of chunks                             */
    c_rda_type_t        type;           /* RDA type                                     */
    uint32_t            k_factor;       /* K factor in K-RDA                            */
    c_ext_pos_t         maps_cep;       /* Offset of chunk mapping in logical extent    */
    struct list_head    hash_list;
    struct list_head    process_list;   /* List of extents for rebuild, rebalance etc.  */
    struct list_head    verify_list;    /* Used for testing.                            */
    c_ext_mask_id_t     rebuild_mask_id;/* Stores reference taken by rebuild.           */
    /* TODO: Move rebuild data to a private state structure. */
    uint32_t            curr_rebuild_seqno;
    uint32_t            remap_seqno;
    spinlock_t          shadow_map_lock;
    c_disk_chk_t        *shadow_map;
    c_ext_mask_range_t  shadow_map_range; /* Range of chunks covered by shadow map. */
    int                 use_shadow_map; /* Extent is currently being remapped           */
    atomic_t            link_cnt;
    /* This global mask gets updated after freeing resources. Checkpoint has to commit
     * this to mstore. */
    c_ext_mask_range_t  global_mask;
    struct list_head    mask_list;      /* List of all valid masks - latest first.      */
    struct list_head    schks_list;     /* List of partially used superchunks.          */
    c_res_pool_t       *pool;           /* Reservation pool that this extent tied to.*/
    uint8_t             alive;
    c_ext_dirtytree_t  *dirtytree;      /**< RB-tree of dirty c2bs.                     */
    c_ext_type_t        ext_type;       /**< Type of extent.                            */
    c_da_t              da_id;          /**< DA that extent corresponds to.             */
#ifdef CASTLE_PERF_DEBUG
    atomic_t            pref_chunks_up2date;    /**< Chunks no prefetch required for.   */
    atomic_t            pref_chunks_not_up2date;/**< Chunks prefetched.                 */
#endif
} c_ext_t;

typedef struct meta_pool_entry {
    struct list_head    list;
    c_byte_off_t        offset;
} meta_pool_entry_t;

void                castle_extent_transaction_start         (void);
void                castle_extent_transaction_end           (void);
int                 castle_extent_in_transaction            (void);
c_ext_id_t          castle_extent_alloc                     (c_rda_type_t           rda_type,
                                                             c_da_t                 da_id,
                                                             c_ext_type_t           ext_type,
                                                             c_chk_cnt_t            chk_cnt,
                                                             int                    in_tran,
                                                             void                  *data,
                                                             c_ext_event_callback_t callback);

c_ext_id_t          castle_extent_alloc_sparse              (c_rda_type_t           rda_type,
                                                             c_da_t                 da_id,
                                                             c_ext_type_t           ext_type,
                                                             c_chk_cnt_t            ext_size,
                                                             c_chk_cnt_t            alloc_size,
                                                             int                    in_tran,
                                                             void                  *data,
                                                             c_ext_event_callback_t callback);

int                 castle_extent_grow                      (c_ext_id_t             ext_id,
                                                             c_chk_cnt_t            count);

int                 castle_extent_shrink                    (c_ext_id_t             ext_id,
                                                             c_chk_cnt_t            count);

int                 castle_extent_truncate                  (c_ext_id_t             ext_id,
                                                             c_chk_cnt_t            count);

c_chk_cnt_t         castle_extent_free_chunks_count         (c_ext_t               *ext,
                                                             uint32_t               slave_id);

void                castle_extent_lfs_victims_wakeup        (void);
int                 castle_extent_exists                    (c_ext_id_t     ext_id);
void                castle_extent_mark_live                 (c_ext_id_t     ext_id,
                                                             c_da_t         da_id);
void                castle_extent_mask_put                  (c_ext_mask_id_t mask_id);
int                 castle_extent_free                      (c_ext_id_t     ext_id);
c_ext_mask_id_t     castle_extent_get                       (c_ext_id_t     ext_id);
void                castle_extent_put                       (c_ext_mask_id_t mask_id);
c_ext_mask_id_t     castle_extent_get_all                   (c_ext_id_t     ext_id);
void                castle_extent_put_all                   (c_ext_mask_id_t mask_id);
#if 0
void                castle_extent_current_mask              (c_ext_id_t     ext_id,
                                                             c_chk_cnt_t   *start,
                                                             c_chk_cnt_t   *end);
#endif
void                castle_extent_mask_read_all             (c_ext_id_t     ext_id,
                                                             c_chk_cnt_t   *start,
                                                             c_chk_cnt_t   *end);
int                 castle_extent_link                      (c_ext_id_t     ext_id);
int                 castle_extent_unlink                    (c_ext_id_t     ext_id);
uint32_t            castle_extent_kfactor_get               (c_ext_id_t     ext_id);
c_chk_cnt_t         castle_extent_size_get                  (c_ext_id_t     ext_id);
/* Sets @chunks to all physical chunks holding the logical chunks from offset */
uint32_t            castle_extent_map_get                   (c_ext_id_t     ext_id,
                                                             c_chk_t        offset,
                                                             c_disk_chk_t  *chk_maps,
                                                             int            rw, c_byte_off_t boff);
#ifdef CASTLE_PERF_DEBUG
void                castle_extent_not_up2date_inc           (c_ext_id_t         ext_id);
void                castle_extent_up2date_inc               (c_ext_id_t         ext_id);
int                 castle_extent_not_up2date_get_reset     (c_ext_id_t         ext_id);
int                 castle_extent_up2date_get_reset         (c_ext_id_t         ext_id);
#endif
c_ext_dirtytree_t  *castle_extent_dirtytree_by_id_get       (c_ext_id_t         ext_id);
void                castle_extent_dirtytree_get             (c_ext_dirtytree_t *dirtytree);
void                castle_extent_dirtytree_put             (c_ext_dirtytree_t *dirtytree);


struct castle_extents_superblock* castle_extents_super_block_get (void);
c_ext_id_t                        castle_extent_sup_ext_init     (struct castle_slave *cs);
void                              castle_extent_sup_ext_close    (struct castle_slave *cs);

void                castle_extents_stats_writeback (c_mstore_t *stats_mstore);
void                castle_extents_stat_read       (struct castle_slist_entry *mstore_entry);

int                 castle_extents_create                   (void);
int                 castle_extents_read                     (void);
int                 castle_extents_read_complete            (int *sync_checkpoint);
void                castle_extents_start                    (void);
int                 castle_extents_writeback                (void);
int                 castle_extents_restore                  (void);
int                 castle_extents_init                     (void);
void                castle_extents_fini                     (void);
int                 castle_extents_process_init             (void);
void                castle_extents_process_fini             (void);
void                castle_extents_rebuild_wake             (void);
void                castle_extents_rebuild_startup_check    (int need_rebuild);
int                 castle_extents_slave_scan               (uint32_t uuid);
void                castle_extent_micro_ext_update          (struct castle_slave *cs);
signed int          castle_extent_link_count_get            (c_ext_id_t);
c_ext_type_t        castle_extent_type_get                  (c_ext_id_t);
void                castle_extents_remap_writeback_setstate  (void);
void                castle_extents_remap_writeback           (void);
void                castle_extents_process_syncpoint         (void);
void                castle_extents_meta_pool_init            (void);
meta_pool_entry_t * castle_extent_meta_pool_get              (c_byte_off_t * offset);
void                castle_extent_meta_pool_freeze           (void);
void                castle_extent_meta_pool_free             (void);


extern atomic_t             wi_in_flight;
extern atomic_t             castle_extents_presyncvar;
extern atomic_t             castle_extents_postsyncvar;
extern wait_queue_head_t    process_syncpoint_waitq;
extern int                  castle_checkpoint_syncing;

void                castle_res_pools_post_checkpoint         (void);
c_chk_cnt_t         castle_res_pool_available_space          (c_res_pool_t        *pool,
                                                              struct castle_slave *cs);
c_res_pool_id_t     castle_res_pool_create                   (c_rda_type_t         rda_type,
                                                              c_chk_cnt_t          logical_chk_cnt);
int                 castle_extent_space_reserve              (c_rda_type_t         rda_type,
                                                              c_chk_cnt_t          logical_chk_cnt,
                                                              c_res_pool_id_t      pool_id);
void                castle_res_pool_extent_attach            (c_res_pool_id_t      pool_id,
                                                              c_ext_id_t           ext_id);
void                castle_res_pool_extent_detach            (c_ext_id_t           ext_id);
void                castle_res_pool_destroy                  (c_res_pool_id_t      pool_id);
int                 castle_res_pool_is_alive                 (c_res_pool_id_t      pool_id);
int                 castle_extent_get_min_rda_level          (void);

#define castle_res_pool_counter_check(_pool, _id)                                           \
do {                                                                                        \
    BUG_ON(((_pool)->reserved_schks[_id] < 0) && (_pool)->freed_schks[_id]);                \
} while(0)
#endif /* __CASTLE_EXTENT_H__ */
