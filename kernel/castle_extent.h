#ifndef __CASTLE_EXTENT_H__
#define __CASTLE_EXTENT_H__

#include "castle.h"

/**
 * Extent dirtytree structure.
 *
 * ref_cnt: 1 reference held by the extent
 *          1 reference per dirty c2b
 */
typedef struct castle_extent_dirtytree {
    c_ext_id_t          ext_id;     /**< Extent ID this dirtylist describes.        */
    spinlock_t          lock;       /**< Protects count, rb_root.                   */
    atomic_t            ref_cnt;    /**< References to this dirtylist.              */
    struct rb_root      rb_root;    /**< RB-tree of dirty c2bs.                     */
    struct list_head    list;       /**< Position on castle_cache_extent_dirtylist. */
} c_ext_dirtytree_t;

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
void                castle_extent_lfs_victims_wakeup        (void);
void                castle_extent_free                      (c_ext_id_t     ext_id);
int                 castle_extent_exists                    (c_ext_id_t     ext_id);
void                castle_extent_mark_live                 (c_ext_id_t     ext_id,
                                                             c_da_t         da_id);
void*               castle_extent_get                       (c_ext_id_t     ext_id);
void                castle_extent_put                       (c_ext_id_t     ext_id);
uint32_t            castle_extent_kfactor_get               (c_ext_id_t     ext_id);
c_chk_cnt_t         castle_extent_size_get                  (c_ext_id_t     ext_id);
/* Sets @chunks to all physical chunks holding the logical chunks from offset */
uint32_t            castle_extent_map_get                   (void*          ext_p,
                                                             c_chk_t        offset,
                                                             c_disk_chk_t  *chk_maps,
                                                             int            rw);
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
int                 castle_extents_read_complete            (void);
int                 castle_extents_writeback                (void);
int                 castle_extents_restore                  (void);
int                 castle_extents_init                     (void);
void                castle_extents_fini                     (void);
int                 castle_extents_rebuild_init             (void);
void                castle_extents_rebuild_fini             (void);
void                castle_extents_rebuild_wake             (void);
void                castle_extents_rebuild_startup_check    (int need_rebuild);
int                 castle_extents_slave_scan               (uint32_t uuid);
void                castle_extent_micro_ext_update          (struct castle_slave *cs);
signed int          castle_extent_ref_cnt_get               (c_ext_id_t);
c_ext_type_t        castle_extent_type_get                  (c_ext_id_t);

#endif /* __CASTLE_EXTENT_H__ */
