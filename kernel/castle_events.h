#ifndef __CASTLE_EVENTS_H__
#define __CASTLE_EVENTS_H__

void castle_uevent4(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3, uint64_t arg4);
void castle_uevent3(uint16_t cmd, uint64_t arg1, uint64_t arg2, uint64_t arg3);
void castle_uevent2(uint16_t cmd, uint64_t arg1, uint64_t arg2);
void castle_uevent1(uint16_t cmd, uint64_t arg1);
void castle_events_slave_rebuild_notify(void);

/* Events which do not correspond to any particular command. Defined in 0x80+ range not
   to overlap with IOCTL command ids. */
#define CASTLE_EVENT_SPINUP            (128)
#define CASTLE_EVENT_SPINDOWN          (129)
#define CASTLE_EVENT_TRANFSER_FINISHED (130)

#define CASTLE_EVENTS_SUCCESS (0)

#define castle_events_slave_claim(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_CLAIM, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_slave_changed(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_CLAIM, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_slave_rebuild(_slave_uuid) \
    castle_uevent2(CASTLE_CTRL_SLAVE_EVACUATE, CASTLE_EVENTS_SUCCESS, _slave_uuid)

#define castle_events_device_attach(_maj, _min, _version_id) \
    castle_uevent3(CASTLE_CTRL_ATTACH, CASTLE_EVENTS_SUCCESS, new_encode_dev(MKDEV(_maj, _min)), _version_id)

#define castle_events_device_detach(_maj, _min) \
    castle_uevent2(CASTLE_CTRL_DETACH, CASTLE_EVENTS_SUCCESS, new_encode_dev(MKDEV(_maj, _min)))

#define castle_events_collection_attach(_id, _version_id) \
    castle_uevent3(CASTLE_CTRL_COLLECTION_ATTACH, CASTLE_EVENTS_SUCCESS, _id, _version_id)

#define castle_events_collection_detach(_id) \
    castle_uevent2(CASTLE_CTRL_COLLECTION_DETACH, CASTLE_EVENTS_SUCCESS, _id)

#define castle_events_version_create(_version_id) \
    castle_uevent2(CASTLE_CTRL_CREATE, CASTLE_EVENTS_SUCCESS, _version_id)

/* Version changed event piggybacks on CREATE id. */
#define castle_events_version_changed(_version_id) \
    castle_uevent2(CASTLE_CTRL_CREATE, CASTLE_EVENTS_SUCCESS, _version_id)

#define castle_events_version_delete_version(_version_id) \
    castle_uevent2(CASTLE_CTRL_DELETE_VERSION, CASTLE_EVENTS_SUCCESS, _version_id)

#define castle_events_version_clone(_version_id) \
    castle_uevent2(CASTLE_CTRL_CLONE, CASTLE_EVENTS_SUCCESS, _version_id)

#define castle_events_device_snapshot(_version_id, _maj, _min) \
    castle_uevent3(CASTLE_CTRL_SNAPSHOT, CASTLE_EVENTS_SUCCESS, _version_id, new_encode_dev(MKDEV(_maj, _min)))

#define castle_events_collection_snapshot(_version_id, _id) \
    castle_uevent3(CASTLE_CTRL_COLLECTION_SNAPSHOT, CASTLE_EVENTS_SUCCESS, _version_id, _id)

#define castle_events_init() \
    castle_uevent1(CASTLE_CTRL_INIT, CASTLE_EVENTS_SUCCESS)


#endif /* __CASTLE_EVENTS_H__ */
