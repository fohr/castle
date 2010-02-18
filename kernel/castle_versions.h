#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int  castle_version_is_ancestor (version_t candidate, version_t version);
int  castle_version_snap_get    (version_t version,
                                 c_disk_blk_t *ftree_root,
                                 uint32_t *size);
int  castle_version_add         (version_t version, 
                                 version_t parent, 
                                 c_disk_blk_t ftree_root,
                                 uint32_t size);
void castle_versions_process    (void);
int  castle_versions_read       (c_disk_blk_t list_cdb);
int  castle_versions_init       (void);
void castle_versions_fini       (void);

#endif /*__CASTLE_VERSIONS_H__ */
