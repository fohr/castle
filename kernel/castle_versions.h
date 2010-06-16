#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int          castle_version_is_ancestor (version_t candidate, version_t version);
int          castle_version_snap_get    (version_t version, 
                                         version_t *parent,
                                         uint32_t *size,
                                         int *leaf);
void         castle_version_snap_put    (version_t version);
void         castle_version_ftree_update(version_t version, c_disk_blk_t cdb);
c_disk_blk_t castle_version_ftree_lock  (version_t version);
void         castle_version_ftree_unlock(version_t version);

int          castle_versions_root_init  (c_disk_blk_t ftree_root);
version_t    castle_version_new         (int snap_or_clone, version_t parent, uint32_t size);

int          castle_versions_read       (void);
int          castle_versions_init       (void);
void         castle_versions_fini       (void);

#endif /*__CASTLE_VERSIONS_H__ */
