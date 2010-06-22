#ifndef __CASTLE_EVENTS_H__
#define __CASTLE_EVENTS_H__

void castle_uevent4(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
void castle_uevent3(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3);
void castle_uevent2(uint16_t cmd, uint64_t arg1, uint64_t arg2);
void castle_uevent1(uint16_t cmd, uint64_t arg1);

/* Events which do not correspond to any particular command. Defined in 0x80+ range not
   to overlap with IOCTL command ids. */
#define CASTLE_EVENT_SPINUP            (128) 
#define CASTLE_EVENT_SPINDOWN          (129)
#define CASTLE_EVENT_TRANFSER_FINISHED (130)

#define CASTLE_EVENTS_SUCCESS (0)

#define castle_events_slave_claim(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_REQ_CLAIM, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_slave_changed(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_REQ_CLAIM, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_slave_release(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_REQ_RELEASE, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_device_attach(_maj, _min, _version_id) \
    castle_uevent3(CASTLE_CTRL_REQ_ATTACH, CASTLE_EVENTS_SUCCESS, new_encode_dev(MKDEV(_maj, _min)), _version_id)
    
#define castle_events_device_detach(_maj, _min) \
    castle_uevent2(CASTLE_CTRL_REQ_DETACH, CASTLE_EVENTS_SUCCESS, new_encode_dev(MKDEV(_maj, _min)))

#define castle_events_collection_attach(_id, _version_id) \
    castle_uevent3(CASTLE_CTRL_REQ_COLLECTION_ATTACH, CASTLE_EVENTS_SUCCESS, _id, _version_id)

#define castle_events_collection_detach(_id) \
    castle_uevent2(CASTLE_CTRL_REQ_COLLECTION_DETACH, CASTLE_EVENTS_SUCCESS, _id)
 
#define castle_events_version_create(_version_id) \
    castle_uevent2(CASTLE_CTRL_REQ_CREATE, CASTLE_EVENTS_SUCCESS, _version_id)

#define castle_events_version_clone(_version_id) \
    castle_uevent2(CASTLE_CTRL_REQ_CLONE, CASTLE_EVENTS_SUCCESS, _version_id)

#define castle_events_device_snapshot(_version_id, _maj, _min) \
    castle_uevent3(CASTLE_CTRL_REQ_SNAPSHOT, CASTLE_EVENTS_SUCCESS, _version_id, new_encode_dev(MKDEV(_maj, _min)))

#define castle_events_collection_snapshot(_version_id, _id) \
    castle_uevent3(CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT, CASTLE_EVENTS_SUCCESS, _version_id, _id)

#define castle_events_init() \
    castle_uevent1(CASTLE_CTRL_REQ_INIT, CASTLE_EVENTS_SUCCESS)

#define castle_events_region_create(_region_id) \
    castle_uevent2(CASTLE_CTRL_REQ_REGION_CREATE, CASTLE_EVENTS_SUCCESS, _region_id)

#define castle_events_region_destroy(_region_id) \
    castle_uevent2(CASTLE_CTRL_REQ_REGION_DESTROY, CASTLE_EVENTS_SUCCESS, _region_id)

#define castle_events_transfer_create(_transfer_id) \
    castle_uevent2(CASTLE_CTRL_REQ_TRANSFER_CREATE, CASTLE_EVENTS_SUCCESS, _transfer_id)

#define castle_events_transfer_finished(_transfer_id, _err) \
    castle_uevent3(CASTLE_EVENT_TRANFSER_FINISHED, CASTLE_EVENTS_SUCCESS, _transfer_id, _err)

#define castle_events_transfer_destroy(_transfer_id) \
    castle_uevent2(CASTLE_CTRL_REQ_TRANSFER_DESTROY, CASTLE_EVENTS_SUCCESS, _transfer_id)

#define castle_events_spinup(_slave_uuid) \
    castle_uevent2(CASTLE_EVENT_SPINUP, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_spindown(_slave_uuid) \
    castle_uevent2(CASTLE_EVENT_SPINDOWN, CASTLE_EVENTS_SUCCESS, _slave_uuid)


#endif /* __CASTLE_EVENTS_H__ */
