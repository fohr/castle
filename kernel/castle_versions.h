#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

#define CASTLE_VERSIONS_MAX (200) /**< Maximum number of live versions per-DA.*/

#define CV_INITED_BIT             (0)
#define CV_INITED_MASK            (1 << CV_INITED_BIT)
#define CV_ATTACHED_BIT           (1)
#define CV_ATTACHED_MASK          (1 << CV_ATTACHED_BIT)
#define CV_DELETED_BIT            (2)
#define CV_DELETED_MASK           (1 << CV_DELETED_BIT)
/* If a version has no children or if all children are marked as deleted, then
 * it is marked as leaf. */
#define CV_LEAF_BIT               (3)
#define CV_LEAF_MASK              (1 << CV_LEAF_BIT)
#define CV_IN_SYSFS_BIT           (4)
#define CV_IN_SYSFS_MASK          (1 << CV_IN_SYSFS_BIT)

struct castle_version {
    /* Various tree links */
    c_ver_t                    version;     /**< Version ID, unique across all Doubling Arrays. */
    struct kobject             kobj;        /**< Kobject for sysfs directory.                   */
    union {
        c_ver_t                parent_v;    /**< Valid if !initialised.                         */
        struct castle_version *parent;      /**< Valid if  initialised.                         */
    };
    struct castle_version     *first_child;
    struct castle_version     *next_sybling;

    /* Aux data */
    c_ver_t          o_order;
    c_ver_t          r_order;
    c_da_t           da_id;             /**< Doubling Array ID this version exists within.      */
    c_byte_off_t     size;

    /* We keep two sets of version stats: live and delayed.
     *
     * The live stats are updated during inserts, merges, deletes and provide
     * an insight into the current state of the DA.  These live stats are
     * exposed to userland consumers via sysfs.
     *
     * The delayed stats are updated in a crash-consistent manner as merges
     * get 'snapshotted', see castle_da_merge_serialise(). */
    struct castle_version_stats stats;  /**< Stats associated with version (crash consistent).  */

    struct list_head hash_list;         /**< List for hash table, protected by hash lock.       */
    unsigned long    flags;
    union {                             /**< All lists in this union are protected by the
                                             ctrl mutex.                                        */
        struct list_head init_list;     /**< Used when the version is being initialised.        */
        struct list_head free_list;     /**< Used when the version is being removed.            */
    };
    struct list_head del_list;

    /* Misc info about the version. */
    struct timeval creation_timestamp;
    struct timeval immute_timestamp; /* the time the version was made immutable */
};

int         castle_version_is_ancestor              (c_ver_t candidate, c_ver_t version);
int         castle_version_compare                  (c_ver_t version1,  c_ver_t version2);
void        castle_version_is_ancestor_and_compare  (c_ver_t version1,
                                                     c_ver_t version2,
                                                     int *ver1_is_anc_of_ver2,
                                                     int *cmp);
int         castle_version_attach                   (c_ver_t version);
void        castle_version_detach                   (c_ver_t version);
int         castle_version_read                     (c_ver_t version,
                                                     c_da_t *da,
                                                     c_ver_t *parent,
                                                     c_ver_t *live_parent,
                                                     c_byte_off_t *size,
                                                     int *leaf);
struct timeval
            castle_version_creation_timestamp_get   (c_ver_t version);
struct timeval
            castle_version_immute_timestamp_get     (c_ver_t version);

c_da_t      castle_version_da_id_get                (c_ver_t version);

/**
 * Castle version health.
 */
typedef enum castle_version_health {
    CVH_LIVE = 0,   /**< Live versions.                         */
    CVH_DEAD,       /**< Deleted versions.                      */
    CVH_DELETED,    /**< Dead versions (no further keys in DA). */
    CVH_TOTAL,      /**< Total versions (sum of above).         */
} cv_health_t;

typedef enum castle_version_stats_discard {
    CVS_VERSION_DISCARD,
    CVS_TIMESTAMP_DISCARD,
} cvs_discard_t;

int         castle_versions_count_adjust            (c_da_t da_id, cv_health_t health, int add);
int         castle_versions_count_get               (c_da_t da_id, cv_health_t health);

int         castle_version_states_alloc             (cv_states_t *states, int max_versions);
void        castle_version_states_commit            (cv_states_t *states);
int         castle_version_states_free              (cv_states_t *states);

void        castle_version_stats_entry_replace      (c_ver_t version,
                                                     c_val_tup_t old_tup,
                                                     c_val_tup_t new_tup,
                                                     cv_states_t *private);
void        castle_version_stats_entry_discard      (c_ver_t version,
                                                     c_val_tup_t cvt,
                                                     cvs_discard_t reason,
                                                     cv_states_t *private);
void        castle_version_stats_entry_add          (c_ver_t version,
                                                     c_val_tup_t cvt,
                                                     cv_states_t *private);

cv_nonatomic_stats_t
            castle_version_consistent_stats_get     (c_ver_t version);

int         castle_versions_zero_init               (void);
int         castle_version_new                      (int snap_or_clone,
                                                     c_ver_t parent,
                                                     c_da_t da_id,
                                                     c_byte_off_t size,
                                                     c_ver_t *version);
int         castle_version_free                     (c_ver_t version);
int         castle_version_tree_delete              (c_ver_t version);
int         castle_version_delete                   (c_ver_t version);
int         castle_version_deleted                  (c_ver_t version);
int         castle_version_attached                 (c_ver_t version);
int         castle_version_is_deletable             (struct castle_version_delete_state *state,
                                                     c_ver_t version,
                                                     int is_new_key);
int         castle_version_is_leaf                  (c_ver_t version);
int         castle_version_is_mutable               (c_ver_t version);

int         castle_versions_read                    (void);
int         castle_versions_init                    (void);
void        castle_versions_fini                    (void);

c_ver_t     castle_version_max_get                  (void);
int         castle_versions_writeback               (int is_fini);
void        castle_versions_orphans_check           (void);

#endif /*__CASTLE_VERSIONS_H__ */
