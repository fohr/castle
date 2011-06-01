#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int         castle_version_is_ancestor              (c_ver_t candidate, c_ver_t version);
int         castle_version_compare                  (c_ver_t version1,  c_ver_t version2);
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

int         castle_versions_count_adjust            (c_da_t da_id, cv_health_t health, int add);
int         castle_versions_count_get               (c_da_t da_id, cv_health_t health);

inline void         castle_version_states_hash_add         (cv_states_t *states, cv_state_t *state);
inline cv_state_t*  castle_version_states_hash_get_alloc   (cv_states_t *states, c_ver_t version);
void        castle_version_states_commit            (cv_states_t *states);
int         castle_version_states_free              (cv_states_t *states);
int         castle_version_states_alloc             (cv_states_t *states, int max_versions);
void        castle_version_live_stats_adjust        (c_ver_t version, cv_nonatomic_stats_t adjust);
void        castle_version_consistent_stats_adjust  (c_ver_t version, cv_nonatomic_stats_t adjust);
void        castle_version_private_stats_adjust     (c_ver_t version, cv_nonatomic_stats_t adjust,
                                                     cv_states_t *private);
cv_nonatomic_stats_t castle_version_live_stats_get  (c_ver_t version);
int         castle_versions_zero_init               (void);
c_ver_t     castle_version_new                      (int snap_or_clone,
                                                     c_ver_t parent,
                                                     c_da_t da,
                                                     c_byte_off_t size);
int         castle_version_free                     (c_ver_t version);
int         castle_version_tree_delete              (c_ver_t version);
int         castle_version_delete                   (c_ver_t version);
int         castle_version_deleted                  (c_ver_t version);
int         castle_version_attached                 (c_ver_t version);
int         castle_version_is_deletable             (struct castle_version_delete_state *state,
                                                     c_ver_t version);
int         castle_version_is_leaf                  (c_ver_t version);

int         castle_versions_read                    (void);
int         castle_versions_init                    (void);
void        castle_versions_fini                    (void);

c_ver_t     castle_version_max_get                  (void);
int         castle_versions_writeback               (int is_fini);

#endif /*__CASTLE_VERSIONS_H__ */
