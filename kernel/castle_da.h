#ifndef __CASTLE_DA_H__
#define __CASTLE_DA_H__

#include "castle_cache.h"
#include "castle_timestamps.h"
#include "castle_public.h"

#define NR_CASTLE_DA_WQS 1

#define FOR_EACH_MERGE_TREE(_i, _merge) for((_i)=0; (_i)<(_merge)->nr_trees; (_i)++)

struct castle_dfs_resolver;

/* A package of all the material needed to checkpoint a merge; i.e. merge_state packed structure
   that contains the state of the castle_da_merge struct and the output tree, and an array of
   packed structures for each of the input trees. */
struct castle_da_merge_mstore_package {
    struct castle_dmserlist_entry           *merge_state;
    struct castle_in_tree_merge_state_entry *in_tree_state_arr;
    atomic_t                                state;
};
void castle_da_merge_mstore_package_deep_copy(struct castle_da_merge_mstore_package *dest,
                                              struct castle_da_merge_mstore_package *source);
void castle_da_merge_mstore_package_check_free(struct castle_da_merge_mstore_package *m);
int castle_da_merge_mstore_package_alloc(struct castle_da_merge_mstore_package *m,
                                         unsigned int nr_in_trees);

struct castle_immut_tree_construct;
typedef void (*c_immut_tree_node_complete_cb_t)(struct castle_immut_tree_construct *tree_constr,
                                                c2_block_t                         *node_c2b,
                                                int                                 depth,
                                                int                                 completing);
struct castle_da_merge {
    c_merge_id_t                  id;
    struct list_head              hash_list;
    struct kobject                kobj;
    c_thread_id_t                 thread_id;
    c_res_pool_id_t               pool_id;

    struct castle_double_array   *da;
    int                           level;
    int                           nr_trees;     /**< num of component trees being merged        */
    struct castle_component_tree **in_trees;    /**< array of component trees to be merged      */
    c_ext_id_t                   *drain_exts;   /**< List of data extents that are to be drained*/
    int                           nr_drain_exts;/**< # of data extents that are to be drained.  */

    void                         **iters;       /**< Component Tree iterators.                  */
    c_merged_iter_t              *merged_iter;
    c2_block_t                   *last_leaf_node_c2b; /**< Last node c2b at depth 0.            */
    uint64_t                      total_nr_bytes;
    uint64_t                      nr_bytes;

    struct castle_immut_tree_construct {
        struct castle_double_array   *da;
        struct castle_component_tree *tree;
        struct castle_btree_type     *btree;

        struct castle_immut_tree_level {
            /* Node we are currently generating, and book-keeping variables about the node. */
            c2_block_t               *node_c2b;
            void                     *last_key;
            int                       next_idx;
            int                       valid_end_idx;
            c_ver_t                   valid_version;
        } levels[MAX_BTREE_DEPTH];

        c_immut_tree_node_complete_cb_t node_complete;

        int                           leafs_on_ssds;     /**< Are leaf btree nodes stored on SSD.*/
        int                           internals_on_ssds; /**< Are internal nodes stored on SSD.  */

        int                           is_new_key;        /**< Is the current key different from
                                                              the last key added to out_tree.    */
        void                         *last_key;          /**< Last key added to out tree, depth
                                                              0. */
        void                         *private;
#ifdef CASTLE_DEBUG
        uint8_t                       is_recursion;
#endif
    } *out_tree_constr;

    /* Deamortisation variables */
    struct work_struct            work;
    struct list_head              new_large_objs;       /**< Large objects added since last
                                                             checkpoint (for merge serdes).     */
    struct castle_version_states  version_states;       /**< Merged version states.             */
    struct castle_version_delete_state snapshot_delete; /**< Snapshot delete state.             */

    uint32_t                      skipped_count;        /**< Count of entries from deleted
                                                             versions.                          */

    /* ----- extent shrink pipeline ----- */
    /* iterators */
    c_ext_pos_t                      *latest_mo_cep;
    struct {
        /* drainable MO extents: */
        c_ext_pos_t                  *data; /* this holds a snapshot of latest_mo_cep */
        c_ext_pos_t                  *tree;
    } shrinkable_extent_boundaries;

    /* partition update copies extent boundaries from immut_iter into ... */
    c_ext_pos_t                  *in_tree_shrink_activatable_cep;
    /* partition activate copies the above into... */
    c_ext_pos_t                  *in_tree_shrinkable_cep;

    /* partition key update pipeline */
    struct castle_key_ptr_t       redirection_partition; /**< The key used to decide if a query
                                                              should be redirected to output ct */



    /* Merge serialisation/deserialisation */
    struct {
        /* Design note: On large_obj handling.

           Before merge checkpointing, we could assume that a cct only contained/owned a
           valid non-zero large_objs list if it was "complete" (i.e. not being produced
           through a merge operation). While a merge was underway, we would produce a
           large objects list to hold results of the ongoing merge. This list was owned by
           the merge, and populated from da_entry_add.  When the merge was complete, the
           merge passes ownership of the large_objs list to the cct through a list_replace
           operation in da_merge_package.

           There are a couple of issues here w.r.t. merge checkpointing. Firstly, on the
           serialisation side, we would need to maintain a list of large_objs corresponding
           to the serialised state of the tree. This list of large_objs would be written
           back during checkpoint. This by itself is not an issue - we simply need to
           maintain a list that is accessible to the checkpoint thread, i.e. right here in
           the double_array structure. That list would have to be deallocated at rmmod
           time so we don't violate any ref_cnt sanity checks on the large_objects, since
           it is currently assumed that each LO would only have 1 reference to it.

           Secondly, we would need to deserialise this list of large_objs. In order to
           reuse the current deserialisation scheme (as in castle_da_read), we would have
           to create a large_obj list onto the deserialising tree. The alternative is to
           handle deserialisation of the incomplete output tree outside the standard path,
           but that will require changes to the standard deserialisation path anyway since
           at least one sanity check will fail (i.e. it will find large_objs linked to
           ccts that it cannot find). Furthermore, we would have to mark the LO extents
           live so they are not removed prematurely.

           Therefore, while a merge is ongoing, by design, the output tree under merge has
           a list of large_obj that corresponds to it's serialised state. When the merge is
           completed this list is completed. If a merge is aborted, this list must be
           dropped (after it has been checkpointed) in order to avoid a bad ref count
           sanity check. After deserialising, the tree once again has a list of large_obj
           that corresponds to the serialised state - therefore symmetry is maintained and
           a deserialised tree would be indistinguishable from a newly created one in mid-
           merge.

           (This symmetry could also have been maintained by allowing the output cct
           to always hold it's "live" state (since at deserialisation time, serialised
           state == live state), but that would have then required maintenance of 3 lists:
           a "live list", a "serialised list", and a "new list" which is the diff between
           the live list and the serialised list. In practice we only need the serialised
           list and the new list, since the live list is worthless until the merge
           completes anyway.)

           For this reason we need to maintain a pointer to the output tree in this struct,
           and in the case of an aborted merge, the output tree must persist beyond
           merge_dealloc so that it can be written out by the final checkpoint before being
           dropped by da_dealloc.
         */
        struct castle_da_merge_mstore_package live;           /* merge thread updates this */
        struct castle_da_merge_mstore_package checkpointable; /* checkpoint write this out */
        unsigned int     des; /* for init to notify merge thread to resume merge, and
                                 to notify checkpoint not to writeback state because
                                 deserialisation still running. */
        c_ext_pos_t     *shrinkable_cep;
    } serdes;

    struct castle_dfs_resolver *tv_resolver; /* A buffering DFS walker to resolve timestamp-version
                                                disputes, and/or for tombstone discard. */
    uint32_t current_key_stream_v_count; /* A running count of the number of versions seen of the
                                            current key stream in _castle_da_entry_add; used to set
                                            out_tree->max_versions_per_key. */

};

extern struct workqueue_struct *castle_da_wqs[NR_CASTLE_DA_WQS];

struct castle_component_tree*
     castle_component_tree_get (tree_seq_t seq);
void castle_ct_get             (struct castle_component_tree *ct, int write, c_ct_ext_ref_t *refs);
void castle_ct_put             (struct castle_component_tree *ct, int write, c_ct_ext_ref_t *refs);
void castle_da_cts_proxy_put   (struct castle_da_cts_proxy *proxy);
void castle_da_next_ct_read    (c_bvec_t *c_bvec);

void castle_da_rq_iter_init    (c_da_rq_iter_t *iter,
                                c_ver_t version,
                                c_da_t da_id,
                                void *start_key,
                                void *end_key,
                                castle_da_rq_iter_init_cb_t init_cb,
                                void *private);
extern struct castle_iterator_type castle_da_rq_iter;

int  castle_double_array_key_cpu_index(c_vl_bkey_t *key);
int  castle_double_array_request_cpu   (int cpu_index);
int  castle_double_array_request_cpus  (void);

struct castle_btree_type
    *castle_double_array_btree_type_get(struct castle_attachment *att);
uint8_t
    castle_da_user_timestamping_check(struct castle_double_array *da);
uint8_t
    castle_attachment_user_timestamping_check(struct castle_attachment *att);
void castle_double_array_queue    (c_bvec_t *c_bvec);
void castle_double_array_unreserve(c_bvec_t *c_bvec);
void castle_double_array_submit   (c_bvec_t *c_bvec);

int  castle_double_array_make     (c_da_t da_id, c_ver_t root_version, c_da_opts_t opts);

int  castle_double_array_read  (void);
int  castle_double_array_start (void);

int  castle_double_array_init  (void);
void castle_double_array_fini  (void);

int  castle_double_array_alive          (c_da_t da_id);
struct castle_double_array
    *castle_double_array_get            (c_da_t da_id);
void castle_double_array_put            (struct castle_double_array *da);
int  castle_double_array_prefetch       (struct castle_double_array *da);
int  castle_double_array_destroy        (c_da_t da_id);
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

uint32_t castle_da_count(void);
void castle_da_threads_priority_set(int nice_value);

int  castle_merge_start                 (c_merge_cfg_t *merge_cfg, c_merge_id_t *merge_id, int level);
int  castle_merge_do_work               (c_merge_id_t   merge_id,
                                         c_work_size_t  size,
                                         c_work_id_t   *work_id);
int  castle_merge_stop                  (c_merge_id_t merge_id);

int  castle_da_vertree_tdp_set          (c_da_t da_id, uint64_t seconds);
int  castle_da_insert_rate_set          (c_da_t da_id, uint32_t insert_rate);
int  castle_da_read_rate_set            (c_da_t da_id, uint32_t read_rate);
void castle_da_write_rate_check         (struct castle_double_array *da, uint32_t length);
int  castle_data_ext_add                (c_ext_id_t ext_id,
                                         uint64_t   nr_entries,
                                         uint64_t   nr_bytes,
                                         uint64_t   nr_drain_bytes);
void castle_ct_data_ext_link            (c_ext_id_t ext_id,
                                         struct castle_component_tree *ct);
struct castle_component_tree* castle_ct_alloc(struct castle_double_array *da,
                                              int level, tree_seq_t seq,
                                              uint32_t nr_data_exts,
                                              uint64_t nr_rwcts);
void castle_ct_dealloc(struct castle_component_tree *ct);
void castle_data_extent_update          (c_ext_id_t     ext_id,
                                         uint64_t       length,
                                         int            to_add);
struct castle_data_extent * castle_data_extent_get(c_ext_id_t ext_id);
int  castle_tree_size_stats_update      (void                            *key,
                                         c_val_tup_t                     *cvt_p,
                                         struct castle_component_tree    *ct,
                                         int                              op);
uint16_t castle_da_merge_node_size_get(struct castle_da_merge *merge,
                                              uint8_t level);
castle_user_timestamp_t castle_da_min_ts_cts_exclude_this_merge_get(struct castle_da_merge *merge);

void castle_double_array_inserts_enable(void);
#endif /* __CASTLE_DA_H__ */
