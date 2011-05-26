#ifndef __CASTLE_CTRL_H__
#define __CASTLE_CTRL_H__

void castle_control_claim           (uint32_t dev, int *ret, c_slave_uuid_t *id);
void castle_control_release         (c_slave_uuid_t id, int *ret);
void castle_control_attach          (c_ver_t version, int *ret, uint32_t *dev);
void castle_control_detach          (uint32_t dev, int *ret);
void castle_control_create          (uint64_t size, int *ret, c_ver_t *id);
void castle_control_clone           (c_ver_t version, int *ret, c_ver_t *clone);
void castle_control_snapshot        (uint32_t dev, int *ret, c_ver_t *version);
void castle_control_fs_init         (int *ret);
void castle_control_transfer_create (c_ver_t          version,
                                     uint32_t         direction,
                                     int             *ret,
                                     c_transfer_id_t *id);
void castle_control_transfer_destroy(c_transfer_id_t id, int *ret);
void castle_control_collection_attach(c_ver_t version,
                                      char *name,
                                      int *ret,
                                      c_collection_id_t *collection);
void castle_control_collection_detach(c_collection_id_t collection, int *ret);
void castle_control_collection_snapshot(c_collection_id_t collection,
                                        int *ret,
                                        c_ver_t *version);
void castle_control_set_target      (c_slave_uuid_t slave_uuid, int value, int *ret);

int  castle_control_ioctl           (struct file *filp,
                                     unsigned int cmd,
                                     unsigned long arg);
int  castle_control_init            (void);
void castle_control_fini            (void);
int  castle_attachments_read        (void);
int  castle_attachments_writeback   (void);
void castle_wq_priority_set         (struct workqueue_struct *wq);

#endif /* __CASTLE_CTRL_H__ */
