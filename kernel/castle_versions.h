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

long        castle_version_keys_get                 (version_t version);
void        castle_version_keys_inc                 (version_t version);
void        castle_version_keys_dec                 (version_t version);
long        castle_version_tombstones_get           (version_t version);
void        castle_version_tombstones_inc           (version_t version);
void        castle_version_tombstones_dec           (version_t version);
long        castle_version_tombstone_deletes_get    (version_t version);
void        castle_version_tombstone_deletes_inc    (version_t version);
long        castle_version_version_deletes_get      (version_t version);
void        castle_version_version_deletes_inc      (version_t version);
long        castle_version_key_replaces_get         (version_t version);
void        castle_version_key_replaces_inc         (version_t version);

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
