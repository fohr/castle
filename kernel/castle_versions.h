#ifndef __CASTLE_VERSIONS_H__
#define __CASTLE_VERSIONS_H__

int          castle_version_is_ancestor (version_t candidate, version_t version);
int          castle_version_attach      (version_t version); 
void         castle_version_detach      (version_t version);
int          castle_version_read        (version_t version, 
                                         da_id_t *da,
                                         version_t *parent,
                                         uint32_t *size,
                                         int *leaf);
c_disk_blk_t castle_version_root_get    (version_t version,
                                         tree_seq_t tree);
void         castle_version_root_next   (tree_seq_t tree,
                                         version_t *next_version,
                                         c_disk_blk_t *btree_root);
int          castle_version_root_update (version_t version, 
                                         tree_seq_t tree_id, 
                                         c_disk_blk_t cdb);
void         castle_version_lock        (version_t version);
void         castle_version_unlock      (version_t version);

int          castle_versions_zero_init  (c_disk_blk_t ftree_root);
version_t    castle_version_new         (int snap_or_clone, 
                                         version_t parent, 
                                         da_id_t da, 
                                         uint32_t size);

int          castle_versions_read       (void);
int          castle_versions_init       (void);
void         castle_versions_fini       (void);

#endif /*__CASTLE_VERSIONS_H__ */
