#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int          castle_version_is_ancestor (version_t candidate, version_t version);
int          castle_version_snap_get    (version_t version,
                                         uint32_t *size);
int          castle_version_ftree_update(version_t version, c_disk_blk_t cdb);
c_disk_blk_t castle_version_ftree_lock  (version_t version);
void         castle_version_ftree_unlock(version_t version);
int          castle_version_add         (c_disk_blk_t cdb,
                                         version_t version, 
                                         version_t parent, 
                                         c_disk_blk_t ftree_root,
                                         uint32_t size);
int          castle_versions_list_init  (c_disk_blk_t list_cdb, c_disk_blk_t ftree_root);
void         castle_versions_process    (void);
int          castle_versions_read       (c_disk_blk_t list_cdb);
int          castle_versions_init       (void);
void         castle_versions_fini       (void);

#endif /*__CASTLE_VERSIONS_H__ */
