#ifndef __CASTLE_CTRL_H__
#define __CASTLE_CTRL_H__

// TBD Expose these function for RxRPC - remove (and re-static) them when RxRPC has gone
void castle_control_lock_up(void);
void castle_control_lock_down(void);

void castle_control_claim           (uint32_t dev, int *ret, slave_uuid_t *id);
void castle_control_release         (slave_uuid_t id, int *ret);
void castle_control_attach          (version_t version, int *ret, uint32_t *dev);
void castle_control_detach          (uint32_t dev, int *ret);
void castle_control_create          (uint64_t size, int *ret, version_t *id);
void castle_control_clone           (version_t version, int *ret, version_t *clone);
void castle_control_snapshot        (uint32_t dev, int *ret, version_t *version);
void castle_control_fs_init         (int *ret);
void castle_control_transfer_create (version_t      version,
                                     uint32_t       direction,
                                     int           *ret,
                                     transfer_id_t *id);
void castle_control_transfer_destroy(transfer_id_t id, int *ret);
void castle_control_collection_attach(version_t version,
                                      char *name,
                                      int *ret,
                                      collection_id_t *collection);
void castle_control_collection_detach(collection_id_t collection, int *ret);
void castle_control_collection_snapshot(collection_id_t collection,
                                        int *ret,
                                        version_t *version);
void castle_control_set_target      (slave_uuid_t slave_uuid, int value, int *ret);                               

int  castle_control_ioctl           (struct file *filp,
                                     unsigned int cmd, 
                                     unsigned long arg);
int  castle_control_init            (void);
void castle_control_fini            (void);
int  castle_attachments_store_init  (int first);
void castle_attachments_store_fini  (void);

#endif /* __CASTLE_CTRL_H__ */
