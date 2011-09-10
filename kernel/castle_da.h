#ifndef __CASTLE_DA_H__
#define __CASTLE_DA_H__

#include "castle_cache.h"

#define NR_CASTLE_DA_WQS 1

struct castle_da_merge {
    c_merge_id_t                  id;
    struct list_head              hash_list;
    struct kobject                kobj;

    struct castle_double_array   *da;
    struct castle_btree_type     *out_btree;
    int                           level;
    int                           nr_trees;     /**< num of component trees being merged */
    struct castle_component_tree **in_trees;    /**< array of component trees to be merged */

    /* partition update copies extent boundaries from immut_iter_t into ... */
    c_ext_pos_t                  *in_tree_shrink_activatable_cep;
    /* partition activate copies the above into... */
    c_ext_pos_t                  *in_tree_shrinkable_cep;

    struct castle_component_tree *out_tree;
    void                         **iters;       /**< iterators for component trees */
    c_merged_iter_t              *merged_iter;
    int                           root_depth;
    c2_block_t                   *last_leaf_node_c2b; /**< Previous node c2b at depth 0. */
    void                         *last_key;           /**< last_key added to
                                                           out tree at depth 0. */
    struct castle_key_ptr_t       new_redirection_partition;
    int                           completing;
    uint64_t                      nr_entries;
    uint64_t                      large_chunks;
    int                           is_new_key;      /**< Is the current key different
                                                        from last key added to out_tree. */
    struct castle_da_merge_level {
        /* Node we are currently generating, and book-keeping variables about the node. */
        c2_block_t               *node_c2b;
        void                     *last_key;
        int                       next_idx;
        int                       valid_end_idx;
        c_ver_t                   valid_version;
    } levels[MAX_BTREE_DEPTH];

    /* Deamortization variables */
    struct work_struct            work;
    int                           budget_cons_rate;
    int                           budget_cons_units;
    int                           leafs_on_ssds;        /**< Are leaf btree nodes stored on SSD.*/
    int                           internals_on_ssds;    /**< Are internal nodes stored on SSD.  */
    struct list_head              new_large_objs;       /**< Large objects added since last
                                                             checkpoint (for merge serdes).     */
    struct castle_version_states  version_states;       /**< Merged version states.             */
    struct castle_version_delete_state snapshot_delete; /**< Snapshot delete state.             */

#ifdef CASTLE_PERF_DEBUG
    u64                           get_c2b_ns;           /**< ns in castle_cache_block_get_for_merge()     */
    u64                           merged_iter_next_ns;
    u64                           da_medium_obj_copy_ns;
    u64                           nodes_complete_ns;
    u64                           budget_consume_ns;
    u64                           progress_update_ns;
    u64                           merged_iter_next_hasnext_ns;
    u64                           merged_iter_next_compare_ns;
#endif
#ifdef CASTLE_DEBUG
    uint8_t                       is_recursion;
#endif
    uint32_t                      skipped_count;        /**< Count of entries from deleted
                                                             versions.                          */

    struct growth_control_t {
        uint32_t tree_ext_nodes_capacity;
        uint32_t tree_ext_nodes_occupancy;
        //TODO@tr data extent
    } growth_control;
    int aborting; /* TODO@tr unhack this... this hack was put specifically to deal with low
                             freespace leading to failure to grow extents, until exit_cond. */
};

extern struct workqueue_struct *castle_da_wqs[NR_CASTLE_DA_WQS];

struct castle_component_tree*
     castle_component_tree_get (tree_seq_t seq);
void castle_ct_get             (struct castle_component_tree *ct, int write, c_ct_ext_ref_t *refs);
void castle_ct_put             (struct castle_component_tree *ct, int write, c_ct_ext_ref_t *refs);
void castle_da_ct_next         (c_bvec_t *c_bvec);

void castle_da_rq_iter_init    (c_da_rq_iter_t *iter,
                                c_ver_t version,
                                c_da_t da_id,
                                void *start_key,
                                void *end_key);
extern struct castle_iterator_type castle_da_rq_iter;

int  castle_da_compacting      (struct castle_double_array *da);
int  castle_double_array_key_cpu_index(c_vl_bkey_t *key, uint32_t key_len);
int  castle_double_array_request_cpu   (int cpu_index);
int  castle_double_array_request_cpus  (void);

void castle_double_array_queue    (c_bvec_t *c_bvec);
void castle_double_array_unreserve(c_bvec_t *c_bvec);
void castle_double_array_submit   (c_bvec_t *c_bvec);

int  castle_double_array_make     (c_da_t da_id, c_ver_t root_version);

int  castle_double_array_read  (void);
int  castle_double_array_create(void);
int  castle_double_array_start (void);

int  castle_double_array_init  (void);
void castle_double_array_fini  (void);

int  castle_double_array_alive          (c_da_t da_id);
int  castle_double_array_get            (c_da_t da_id);
void castle_double_array_put            (c_da_t da_id);
int  castle_double_array_destroy        (c_da_t da_id);
int  castle_double_array_compact        (c_da_t da_id);
int  castle_double_array_prefetch       (c_da_t da_id);
void castle_double_arrays_writeback     (void);
void castle_double_arrays_pre_writeback (void);
void castle_double_array_merges_fini    (void);

int  castle_ct_large_obj_add    (c_ext_id_t              ext_id,
                                 uint64_t                length,
                                 struct list_head       *head,
                                 struct mutex           *mutex);
int  castle_ct_large_obj_remove (c_ext_id_t              ext_id,
                                 struct list_head       *head,
                                 struct mutex           *mutex);
void castle_da_version_delete   (c_da_t da_id);

uint32_t castle_da_count(void);
void castle_da_threads_priority_set(int nice_value);

struct castle_double_array * castle_da_get_ptr(c_da_t da_id);

void castle_merge_thread_create         (c_thread_id_t *thread_id, int *ret);
void castle_merge_thread_destroy        (c_thread_id_t thread_id, int *ret);
void castle_merge_start                 (c_merge_cfg_t *merge_cfg, c_merge_id_t *merge_id, int *ret);
void castle_merge_do_work               (c_merge_id_t   merge_id,
                                         c_work_size_t  size,
                                         c_work_id_t   *work_id,
                                         int           *ret);
void castle_merge_stop                  (c_merge_id_t merge_id, int *ret);
void castle_merge_thread_attach         (c_merge_id_t merge_id, c_thread_id_t thread_id, int *ret);

#endif /* __CASTLE_DA_H__ */
