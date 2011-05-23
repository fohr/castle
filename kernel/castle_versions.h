#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int         castle_version_is_ancestor              (version_t candidate, version_t version);
int         castle_version_compare                  (version_t version1,  version_t version2);
int         castle_version_attach                   (version_t version);
void        castle_version_detach                   (version_t version);
int         castle_version_read                     (version_t version,
                                                     da_id_t *da,
                                                     version_t *parent,
                                                     version_t *live_parent,
                                                     c_byte_off_t *size,
                                                     int *leaf);

da_id_t     castle_version_da_id_get                (version_t version);

/**
 * Castle version health.
 */
typedef enum castle_version_health {
    CVH_LIVE = 0,   /**< Live versions.                         */
    CVH_DEAD,       /**< Deleted versions.                      */
    CVH_DELETED,    /**< Dead versions (no further keys in DA). */
    CVH_TOTAL,      /**< Total versions (sum of above).         */
} cv_health_t;

int         castle_versions_count_adjust            (da_id_t da_id, cv_health_t health, int add);
int         castle_versions_count_get               (da_id_t da_id, cv_health_t health);

inline void         castle_version_states_hash_add         (cv_states_t *states, cv_state_t *state);
inline cv_state_t*  castle_version_states_hash_get_alloc   (cv_states_t *states, version_t version);
void        castle_version_states_commit            (cv_states_t *states);
void        castle_version_states_free              (cv_states_t *states);
int         castle_version_states_alloc             (cv_states_t *states, int max_versions);
void        castle_version_live_stats_adjust        (version_t version, cv_nonatomic_stats_t adjust);
void        castle_version_consistent_stats_adjust  (version_t version, cv_nonatomic_stats_t adjust);
void        castle_version_private_stats_adjust     (version_t version, cv_nonatomic_stats_t adjust,
                                                     cv_states_t *private);
cv_nonatomic_stats_t castle_version_live_stats_get  (version_t version);
int         castle_versions_zero_init               (void);
version_t   castle_version_new                      (int snap_or_clone,
                                                     version_t parent,
                                                     da_id_t da,
                                                     c_byte_off_t size);
int         castle_version_tree_delete              (version_t version);
int         castle_version_delete                   (version_t version);
int         castle_version_deleted                  (version_t version);
int         castle_version_attached                 (version_t version);
int         castle_version_is_deletable             (struct castle_version_delete_state *state,
                                                     version_t version);

int         castle_versions_read                    (void);
int         castle_versions_init                    (void);
void        castle_versions_fini                    (void);

version_t   castle_version_max_get                  (void);
int         castle_versions_writeback               (void);

#endif /*__CASTLE_VERSIONS_H__ */
