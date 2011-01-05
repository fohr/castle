#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

#include <linux/types.h>
#include <asm/ioctl.h>

#define CASTLE_PROTOCOL_VERSION 4

#define PACKED               __attribute__((packed))

#ifndef __KERNEL__
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
/* These must be the same as castle.h in fs.hg */
enum {
    CVT_TYPE_INLINE          = 0x10,
    CVT_TYPE_ONDISK          = 0x20,
    CVT_TYPE_INVALID         = 0x30,
};
#endif

typedef enum {
    NO_FAULT,           /* 0 */
    MERGE_FAULT,        /* 1 */
    EXTENT_FAULT,       /* 2 */ 
    FREESPACE_FAULT,    /* 3 */
    REPLACE_FAULT,      /* 4 */
    GET_FAULT,          /* 5 */
    BIG_PUT_FAULT,      /* 6 */
    BIG_GET_FAULT,      /* 7 */
    CHECKPOINT_FAULT,   /* 8 */
    CLAIM_FAULT,        /* 9 */
    FS_INIT_FAULT,      /*10 */
    FS_RESTORE_FAULT,   /*11 */
    FINI_FAULT,         /*12 */
} c_fault_t;

typedef enum {
    BUILD_ID            = 0,
    LAST_ENV_VAR_ID,
} c_env_var_t; 

typedef enum {
    TRACE_CACHE_ID,
    TRACE_MERGE_ID,
    TRACE_MERGE_UNIT_ID,
    TRACE_MERGE_UNIT_STAT_ID,
} c_trace_id_t;

typedef enum {
    TRACE_CACHE_DIRTY_PGS_ID,
    TRACE_CACHE_CLEAN_PGS_ID,
    TRACE_CACHE_FREE_PGS_ID,
    TRACE_CACHE_FREE_BLKS_ID,
    TRACE_CACHE_CLEAN_BLKS_ID,
    TRACE_CACHE_SOFTPIN_BLKS_ID,
    TRACE_CACHE_BLOCK_VICTIMS_ID,
    TRACE_CACHE_SOFTPIN_VICTIMS_ID,
    TRACE_CACHE_READS_ID,
    TRACE_CACHE_WRITES_ID,
} c_trc_cache_var_id_t;

typedef enum {
    TRACE_MERGE_UNIT_C2B_SYNC_WAIT_BT_NS,
    TRACE_MERGE_UNIT_C2B_SYNC_WAIT_DATA_NS,
    TRACE_MERGE_UNIT_GET_C2B_NS,
    TRACE_MERGE_UNIT_DA_MEDIUM_OBJ_COPY_NS,
} c_trc_merge_var_id_t;

typedef struct castle_trace_cache_event {
    c_trc_cache_var_id_t var_id;
    uint32_t             var_val;
} PACKED c_trc_cache_evt_t;

#define MERGE_START_FLAG    (1U<<0)
#define MERGE_END_FLAG      (1U<<1)
typedef struct castle_trace_merge_event {
    uint32_t da;
    uint8_t  level;
    uint8_t  flags;
    uint32_t tree_id1;
    uint32_t tree_id2;
} PACKED c_trc_mrg_evt_t;

typedef struct castle_trace_merge_unit_event {
    uint32_t da;
    uint8_t  level;
    uint8_t  flags;
    uint64_t unit;
} PACKED c_trc_mrg_unit_evt_t;

typedef struct castle_trace_merge_unit_stat {
    uint32_t da;
    uint8_t  level;
    uint64_t unit;
    c_trc_merge_var_id_t var_id;
    uint32_t val;
} PACKED c_trc_mrg_unit_stat_t;

/* Bump the magic version byte (LSB) when c_trc_evt_t changes. */
#define CASTLE_TRACE_MAGIC          0xCAE5E101
typedef struct castle_trace_event {
    uint32_t                    magic;
    struct timeval              timestamp;
    c_trace_id_t                id;
    int                         cpu;
    union {
        c_trc_cache_evt_t       cache;
        c_trc_mrg_evt_t         merge;
        c_trc_mrg_unit_evt_t    merge_unit;
        c_trc_mrg_unit_stat_t   merge_unit_stat;
    };
} PACKED c_trc_evt_t;

typedef uint32_t transfer_id_t;
typedef uint32_t slave_uuid_t;
typedef uint32_t collection_id_t;
typedef uint32_t version_t;
#define INVAL_VERSION       ((version_t)-1)
#define VERSION_INVAL(_v)   ((_v) == INVAL_VERSION)

/* And our IOCTL code is: */
#define CASTLE_CTRL_IOCTL_TYPE                  (0xCA)

/* Subtypes for CASTLE_CTRL_ used for IOCTLs */
#define CASTLE_CTRL_CLAIM                    1
#define CASTLE_CTRL_RELEASE                  2
#define CASTLE_CTRL_ATTACH                   3
#define CASTLE_CTRL_DETACH                   4
#define CASTLE_CTRL_CREATE                   5
#define CASTLE_CTRL_CLONE                    6
#define CASTLE_CTRL_SNAPSHOT                 7
#define CASTLE_CTRL_INIT                     8
#define CASTLE_CTRL_TRANSFER_CREATE          11
#define CASTLE_CTRL_TRANSFER_DESTROY         12
#define CASTLE_CTRL_COLLECTION_ATTACH        13
#define CASTLE_CTRL_COLLECTION_DETACH        14
#define CASTLE_CTRL_COLLECTION_SNAPSHOT      15
#define CASTLE_CTRL_RESERVE_FOR_TRANSFER     16
#define CASTLE_CTRL_VALID_STATS              17
#define CASTLE_CTRL_INVALID_STATS            18
#define CASTLE_CTRL_SET_TARGET               19
#define CASTLE_CTRL_DESTROY                  20
#define CASTLE_CTRL_PROTOCOL_VERSION         21
#define CASTLE_CTRL_FAULT                    22
#define CASTLE_CTRL_ENVIRONMENT_SET          23
#define CASTLE_CTRL_TRACE_SETUP              24
#define CASTLE_CTRL_TRACE_START              25
#define CASTLE_CTRL_TRACE_STOP               26
#define CASTLE_CTRL_TRACE_TEARDOWN           27

typedef struct castle_control_cmd_claim {
    uint32_t     dev;          /* IN  */
    int          ret;          /* OUT */
    slave_uuid_t id;           /* OUT */
} PACKED cctrl_cmd_claim_t;

typedef struct castle_control_cmd_release {
    slave_uuid_t id;           /* IN  */
    int          ret;          /* OUT */
} PACKED cctrl_cmd_release_t;

typedef struct castle_control_cmd_attach {
    version_t version;         /* IN  */
    int       ret;             /* OUT */
    uint32_t  dev;             /* OUT */
} PACKED cctrl_cmd_attach_t;

typedef struct castle_control_cmd_detach {
    uint32_t dev;              /* IN  */
    int      ret;              /* OUT */
} PACKED cctrl_cmd_detach_t;

typedef struct castle_control_cmd_snapshot {
    uint32_t  dev;             /* IN  */
    int       ret;             /* OUT */
    version_t version;         /* OUT */
} PACKED cctrl_cmd_snapshot_t;

typedef struct castle_control_cmd_collection_attach {
    version_t           version;         /* IN  */
    const char         *name;            /* IN  */
    size_t              name_length;     /* IN  */
    int                 ret;             /* OUT */
    collection_id_t     collection;      /* OUT */
} PACKED cctrl_cmd_collection_attach_t;

typedef struct castle_control_cmd_collection_detach {
    collection_id_t collection;          /* IN  */
    int             ret;                 /* OUT */
} PACKED cctrl_cmd_collection_detach_t;

typedef struct castle_control_cmd_collection_snapshot {
    collection_id_t collection; /* IN  */
    int       ret;             /* OUT */
    version_t version;         /* OUT */
} PACKED cctrl_cmd_collection_snapshot_t;

typedef struct castle_control_cmd_create {
    uint64_t  size;            /* IN  */
    int       ret;             /* OUT */
    version_t id;              /* OUT */
} PACKED cctrl_cmd_create_t;

typedef struct castle_control_cmd_destroy {
    version_t version;         /* IN */
    int       ret;             /* OUT */
} cctrl_cmd_destroy_t;

typedef struct castle_control_cmd_clone {
    version_t version;         /* IN  */
    int       ret;             /* OUT */
    version_t clone;           /* OUT */
} PACKED cctrl_cmd_clone_t;

typedef struct castle_control_cmd_init {
    int ret;                   /* OUT */
} PACKED cctrl_cmd_init_t;

typedef struct castle_control_cmd_transfer_create {
    version_t     version;     /* IN  */
    uint32_t      direction;   /* IN  */
    int           ret;         /* OUT */
    transfer_id_t id;          /* OUT */
} PACKED cctrl_cmd_transfer_create_t;

typedef struct castle_control_cmd_transfer_destroy {
    transfer_id_t id;          /* IN  */
    int           ret;         /* OUT */
} PACKED cctrl_cmd_transfer_destroy_t;

typedef struct castle_control_cmd_protocol_version {
    int ret;                   /* OUT */
    uint32_t version;          /* OUT */
} PACKED cctrl_cmd_protocol_version_t;

typedef struct castle_control_cmd_environment_set {
    c_env_var_t var_id;        /* IN */
    const char *var_str;       /* IN  */
    size_t      var_len;       /* IN  */
    int         ret;           /* OUT */
} PACKED cctrl_cmd_environment_set_t;

typedef struct castle_control_cmd_fault {
    c_fault_t fault_id;        /* IN  */
    int       ret;             /* OUT */
} PACKED cctrl_cmd_fault_t;

typedef struct castle_control_cmd_trace_setup {
    const char *dir_str;       /* IN  */
    size_t      dir_len;       /* IN  */
    int         ret;           /* OUT */
} PACKED cctrl_cmd_trace_setup_t;

typedef struct castle_control_cmd_trace_start {
    int         ret;           /* OUT */
} PACKED cctrl_cmd_trace_start_t;

typedef struct castle_control_cmd_trace_stop {
    int         ret;           /* OUT */
} PACKED cctrl_cmd_trace_stop_t;

typedef struct castle_control_cmd_trace_teardown {
    int         ret;           /* OUT */
} PACKED cctrl_cmd_trace_teardown_t;

typedef struct castle_control_ioctl {
    uint16_t cmd;
    union {
        cctrl_cmd_claim_t               claim;
        cctrl_cmd_release_t             release;
        cctrl_cmd_init_t                init;

        cctrl_cmd_attach_t              attach;
        cctrl_cmd_detach_t              detach;
        cctrl_cmd_snapshot_t            snapshot;

        cctrl_cmd_collection_attach_t   collection_attach;
        cctrl_cmd_collection_detach_t   collection_detach;
        cctrl_cmd_collection_snapshot_t collection_snapshot;

        cctrl_cmd_create_t              create;
        cctrl_cmd_destroy_t             destroy;
        cctrl_cmd_clone_t               clone;

        cctrl_cmd_transfer_create_t     transfer_create;
        cctrl_cmd_transfer_destroy_t    transfer_destroy;

        cctrl_cmd_protocol_version_t    protocol_version;
        cctrl_cmd_environment_set_t     environment_set;

        cctrl_cmd_fault_t               fault;

        cctrl_cmd_trace_setup_t         trace_setup;
        cctrl_cmd_trace_start_t         trace_start;
        cctrl_cmd_trace_stop_t          trace_stop;
        cctrl_cmd_trace_teardown_t      trace_teardown;

    };
} PACKED cctrl_ioctl_t;

/* IOCTL definitions. */
enum {
    CASTLE_CTRL_CLAIM_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CLAIM, cctrl_ioctl_t),
    CASTLE_CTRL_RELEASE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_RELEASE, cctrl_ioctl_t),
    CASTLE_CTRL_ATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_ATTACH, cctrl_ioctl_t),
    CASTLE_CTRL_DETACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_DETACH, cctrl_ioctl_t),
    CASTLE_CTRL_CREATE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CREATE, cctrl_ioctl_t),
    CASTLE_CTRL_CLONE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CLONE, cctrl_ioctl_t),
    CASTLE_CTRL_SNAPSHOT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_SNAPSHOT, cctrl_ioctl_t),
    CASTLE_CTRL_INIT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_INIT, cctrl_ioctl_t),
    CASTLE_CTRL_TRANSFER_CREATE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRANSFER_CREATE, cctrl_ioctl_t),
    CASTLE_CTRL_TRANSFER_DESTROY_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRANSFER_DESTROY, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_ATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_ATTACH, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_DETACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_DETACH, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_SNAPSHOT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_SNAPSHOT, cctrl_ioctl_t),
    CASTLE_CTRL_RESERVE_FOR_TRANSFER_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_RESERVE_FOR_TRANSFER, cctrl_ioctl_t),
    CASTLE_CTRL_VALID_STATS_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_VALID_STATS, cctrl_ioctl_t),
    CASTLE_CTRL_INVALID_STATS_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_INVALID_STATS, cctrl_ioctl_t),
    CASTLE_CTRL_SET_TARGET_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_SET_TARGET, cctrl_ioctl_t),
    CASTLE_CTRL_DESTROY_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_DESTROY, cctrl_ioctl_t),
    CASTLE_CTRL_PROTOCOL_VERSION_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_PROTOCOL_VERSION, cctrl_ioctl_t),
    CASTLE_CTRL_ENVIRONMENT_SET_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_ENVIRONMENT_SET, cctrl_ioctl_t),
    CASTLE_CTRL_FAULT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_FAULT, cctrl_ioctl_t),
    CASTLE_CTRL_TRACE_SETUP_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRACE_SETUP, cctrl_ioctl_t),
    CASTLE_CTRL_TRACE_START_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRACE_START, cctrl_ioctl_t),
    CASTLE_CTRL_TRACE_STOP_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRACE_STOP, cctrl_ioctl_t),
    CASTLE_CTRL_TRACE_TEARDOWN_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_TRACE_TEARDOWN, cctrl_ioctl_t),
};

/*
 * Variable length key, for example used by the btree
 */

typedef struct castle_var_length_key {
    uint32_t length;
    uint8_t key[];
} PACKED c_vl_key_t;

typedef struct castle_var_length_object_key {
    uint32_t nr_dims;
    c_vl_key_t *dims[];
} PACKED c_vl_okey_t;

#define CASTLE_RING_PAGES (2)
/* CASTLE_RING_SIZE must be a power of 2, or code will silently break */
#define CASTLE_RING_SIZE (CASTLE_RING_PAGES << PAGE_SHIFT)

#define CASTLE_IOCTL_POKE_RING 2
#define CASTLE_IOCTL_WAIT 3

#define CASTLE_RING_REPLACE 1
#define CASTLE_RING_BIG_PUT 2
#define CASTLE_RING_PUT_CHUNK 3
#define CASTLE_RING_GET 4
#define CASTLE_RING_BIG_GET 5
#define CASTLE_RING_GET_CHUNK 6
#define CASTLE_RING_ITER_START 7
#define CASTLE_RING_ITER_NEXT 8
#define CASTLE_RING_ITER_FINISH 9
#define CASTLE_RING_ITER_SKIP 10
#define CASTLE_RING_REMOVE 11

typedef uint32_t castle_interface_token_t;

typedef struct castle_request_replace {
    collection_id_t       collection_id;
    c_vl_okey_t          *key_ptr;
    uint32_t              key_len;
    void                 *value_ptr;
    uint32_t              value_len;
} castle_request_replace_t;

typedef struct castle_request_remove {
    collection_id_t       collection_id;
    c_vl_okey_t          *key_ptr;
    uint32_t              key_len;
} castle_request_remove_t;

typedef struct castle_request_get {
    collection_id_t      collection_id;
    c_vl_okey_t         *key_ptr;
    uint32_t             key_len;
    void                *value_ptr; /* where to put the result */
    uint32_t             value_len;
} castle_request_get_t;

typedef struct castle_request_iter_start {
    collection_id_t      collection_id;
    c_vl_okey_t         *start_key_ptr;
    uint32_t             start_key_len;
    c_vl_okey_t         *end_key_ptr;
    uint32_t             end_key_len;
    uint64_t             flags;
} castle_request_iter_start_t;

#define CASTLE_RING_ITER_FLAG_NONE      0x0
#define CASTLE_RING_ITER_FLAG_NO_VALUES 0x1

typedef struct castle_request_iter_next {
    castle_interface_token_t  token;
    void                     *buffer_ptr;
    uint32_t                  buffer_len;
} castle_request_iter_next_t;

typedef struct castle_request_iter_finish {
    castle_interface_token_t token;
} castle_request_iter_finish_t;

typedef struct castle_request_big_get {
    collection_id_t  collection_id;
    c_vl_okey_t     *key_ptr;
    uint32_t         key_len;
} castle_request_big_get_t;

typedef struct castle_request_get_chunk {
    castle_interface_token_t  token;
    void                     *buffer_ptr;
    uint32_t                  buffer_len;
} castle_request_get_chunk_t;

typedef struct castle_request_big_put {
    collection_id_t  collection_id;
    c_vl_okey_t     *key_ptr;
    uint32_t         key_len;
    uint64_t         value_len;
} castle_request_big_put_t;

typedef struct castle_request_put_chunk {
    castle_interface_token_t  token;
    void                     *buffer_ptr;
    uint32_t                  buffer_len;
} castle_request_put_chunk_t;

typedef struct castle_request {
    uint32_t call_id;
    uint32_t tag;
    union {
        castle_request_replace_t     replace;
        castle_request_remove_t      remove;
        castle_request_get_t         get;

        castle_request_big_get_t     big_get;
        castle_request_get_chunk_t   get_chunk;
        castle_request_big_put_t     big_put;
        castle_request_put_chunk_t   put_chunk;

        castle_request_iter_start_t  iter_start;
        castle_request_iter_next_t   iter_next;
        castle_request_iter_finish_t iter_finish;
    };
} castle_request_t;

typedef struct castle_response {
    uint32_t                 call_id;
    uint32_t                 err;
    uint64_t                 length;
    castle_interface_token_t token;
} castle_response_t;

struct castle_iter_val {
    uint8_t              type;
    uint64_t             length;
    union {
        uint8_t         *val;
        collection_id_t  collection_id;
    };
} PACKED;

struct castle_key_value_list {
    struct castle_key_value_list *next;
    c_vl_okey_t                  *key;
    struct castle_iter_val       *val;
} PACKED;


#define CASTLE_SLAVE_MAGIC1     (0x02061985)
#define CASTLE_SLAVE_MAGIC2     (0x16071983)
#define CASTLE_SLAVE_MAGIC3     (0x16061981)
#define CASTLE_SLAVE_VERSION    (1)

#define CASTLE_SLAVE_TARGET     (0x00000001)
#define CASTLE_SLAVE_SPINNING   (0x00000002)
#define CASTLE_SLAVE_NEWDEV     (0x00000004)

struct castle_slave_superblock_public {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t version;   /* Super chunk format version */
    uint32_t uuid;
    uint32_t used;
    uint64_t size;      /* In blocks. */
	uint32_t flags;
    uint32_t checksum;
} PACKED;

#define CASTLE_FS_MAGIC1        (0x19731121)
#define CASTLE_FS_MAGIC2        (0x19880624)
#define CASTLE_FS_MAGIC3        (0x19821120)
#define CASTLE_FS_VERSION       (1)

struct castle_fs_superblock_public {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t uuid;
    uint32_t version;   /* Super chunk format version */
    uint32_t salt;
    uint32_t peper;
    uint32_t checksum;
} PACKED;

#endif /* __CASTLE_PUBLIC_H__ */
