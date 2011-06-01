#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

#include <linux/types.h>
#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/time.h>
#endif

#define CASTLE_PROTOCOL_VERSION 10

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
    SLAVE_OOS_ERR,      /*13 */
    REBUILD_FAULT1,     /*14 Fault between extent remaps*/
    REBUILD_FAULT2,     /*15 Fault in mid extent remap*/
} c_fault_t;

typedef enum {
    BUILD_ID            = 0,
    LAST_ENV_VAR_ID,
} c_env_var_t;

/**
 * Trace providers.
 */
typedef enum {
    TRACE_CACHE,            /**< Cache events       */
    TRACE_DA,               /**< DA events          */
    TRACE_DA_MERGE,         /**< Merge events       */
    TRACE_DA_MERGE_UNIT,    /**< Merge unit events  */
} c_trc_prov_t;

/**
 * Event types.
 */
typedef enum {
    TRACE_VALUE,        /**< Value being reported   */
    TRACE_MARK,         /**< Event has occurred     */
    TRACE_START,        /**< Event has started      */
    TRACE_END,          /**< Event has ended        */
} c_trc_type_t;

/**
 * Cache trace variables.
 */
typedef enum {
    TRACE_CACHE_CHECKPOINT_ID,          /**< Checkpoint running.                                */
    TRACE_CACHE_DIRTY_PGS_ID,           /**< Number of c2ps on the dirtylist.                   */
    TRACE_CACHE_CLEAN_PGS_ID,           /**< Number of c2ps on the cleanlist.                   */
    TRACE_CACHE_FREE_PGS_ID,            /**< Number of c2ps on the freelist.                    */
    TRACE_CACHE_RESERVE_PGS_ID,         /**< Number of c2ps on the reserve freelist.            */
    TRACE_CACHE_CLEAN_BLKS_ID,          /**< Number of c2bs on the cleanlist.                   */
    TRACE_CACHE_FREE_BLKS_ID,           /**< Number of c2bs on the freelist.                    */
    TRACE_CACHE_RESERVE_BLKS_ID,        /**< Number of c2bs on the reserve freelist.            */
    TRACE_CACHE_SOFTPIN_BLKS_ID,        /**< Number of softpin c2bs in the cache.               */
    TRACE_CACHE_BLOCK_VICTIMS_ID,       /**< Number of c2bs evicted from the cache.             */
    TRACE_CACHE_SOFTPIN_VICTIMS_ID,     /**< Number of softpinned c2bs evicted from the cache.  */
    TRACE_CACHE_READS_ID,               /**< Number of reads this tick.                         */
    TRACE_CACHE_WRITES_ID,              /**< Number of writes this tick.                        */
    TRACE_CACHE_RESERVE_PGS_USED_ID,    /**< Number of c2ps from reserve freelist in use.       */
    TRACE_CACHE_RESERVE_BLKS_USED_ID,   /**< Number of c2bs from reserve freelist in use.       */
} c_trc_cache_var_t;

/**
 * DA trace variables.
 */
typedef enum {
    TRACE_DA_INSERTS_DISABLED_ID,                   /**< Whether inserts are enabled or not.    */
    TRACE_DA_MERGE_ID,                              /**< Merge                                  */
    TRACE_DA_MERGE_MODLIST_ITER_INIT_ID,            /**< Modlist iter init                      */
    TRACE_DA_MERGE_UNIT_ID,                         /**< Merge unit                             */
    TRACE_DA_MERGE_UNIT_C2B_SYNC_WAIT_BT_NS_ID,
    TRACE_DA_MERGE_UNIT_C2B_SYNC_WAIT_DATA_NS_ID,
    TRACE_DA_MERGE_UNIT_GET_C2B_NS_ID,
    TRACE_DA_MERGE_UNIT_MOBJ_COPY_NS_ID,
} c_trc_da_var_t;

#define MERGE_START_FLAG    (1U<<0)
#define MERGE_END_FLAG      (1U<<1)

/* Bump the magic version byte (LSB) when c_trc_evt_t changes. */
#define CASTLE_TRACE_MAGIC          0xCAE5E10D
typedef struct castle_trace_event {
    uint32_t                    magic;
    struct timeval              timestamp;
    int                         cpu;        /**< CPU ID that allocated structure.       */
    c_trc_prov_t                provider;   /**< Event provider                         */
    c_trc_type_t                type;       /**< Event type                             */
    int                         var;        /**< Event variable                         */
    uint64_t                    v1;
    uint64_t                    v2;
    uint64_t                    v3;
    uint64_t                    v4;
    uint64_t                    v5;
} c_trc_evt_t;

typedef uint32_t c_transfer_id_t;
typedef uint32_t c_slave_uuid_t;
typedef uint32_t c_collection_id_t;
typedef uint32_t c_ver_t;           /**< Version ID type, unique across all Doubling Arrays.    */
typedef uint32_t c_da_t;
#define INVAL_VERSION       ((c_ver_t)-1)
#define VERSION_INVAL(_v)   ((_v) == INVAL_VERSION)

/* And our IOCTL code is: */
#define CASTLE_CTRL_IOCTL_TYPE                  (0xCA)

/* Subtypes for CASTLE_CTRL_ used for IOCTLs */
#define CASTLE_CTRL_CLAIM                    1
#define CASTLE_CTRL_ATTACH                   3
#define CASTLE_CTRL_DETACH                   4
#define CASTLE_CTRL_CREATE                   5
#define CASTLE_CTRL_CLONE                    6
#define CASTLE_CTRL_SNAPSHOT                 7
#define CASTLE_CTRL_INIT                     8
#define CASTLE_CTRL_COLLECTION_ATTACH        13
#define CASTLE_CTRL_COLLECTION_DETACH        14
#define CASTLE_CTRL_COLLECTION_SNAPSHOT      15
#define CASTLE_CTRL_VALID_STATS              17
#define CASTLE_CTRL_INVALID_STATS            18
#define CASTLE_CTRL_DESTROY_VERTREE          20
#define CASTLE_CTRL_PROTOCOL_VERSION         21
#define CASTLE_CTRL_FAULT                    22
#define CASTLE_CTRL_ENVIRONMENT_SET          23
#define CASTLE_CTRL_TRACE_SETUP              24
#define CASTLE_CTRL_TRACE_START              25
#define CASTLE_CTRL_TRACE_STOP               26
#define CASTLE_CTRL_TRACE_TEARDOWN           27
#define CASTLE_CTRL_SLAVE_EVACUATE           28
#define CASTLE_CTRL_THREAD_PRIORITY          29
#define CASTLE_CTRL_SLAVE_SCAN               30
#define CASTLE_CTRL_DELETE_VERSION           31
#define CASTLE_CTRL_VERTREE_COMPACT          32

typedef struct castle_control_cmd_claim {
    uint32_t       dev;          /* IN  */
    int            ret;          /* OUT */
    c_slave_uuid_t id;           /* OUT */
} cctrl_cmd_claim_t;

typedef struct castle_control_cmd_release {
    c_slave_uuid_t id;           /* IN  */
    int            ret;          /* OUT */
} cctrl_cmd_release_t;

typedef struct castle_control_cmd_attach {
    c_ver_t  version;         /* IN  */
    int      ret;             /* OUT */
    uint32_t dev;             /* OUT */
} cctrl_cmd_attach_t;

typedef struct castle_control_cmd_detach {
    uint32_t dev;              /* IN  */
    int      ret;              /* OUT */
} cctrl_cmd_detach_t;

typedef struct castle_control_cmd_snapshot {
    uint32_t dev;             /* IN  */
    int      ret;             /* OUT */
    c_ver_t  version;         /* OUT */
} cctrl_cmd_snapshot_t;

typedef struct castle_control_cmd_collection_attach {
    c_ver_t            version;         /* IN  */
    const char        *name;            /* IN  */
    size_t             name_length;     /* IN  */
    int                ret;             /* OUT */
    c_collection_id_t  collection;      /* OUT */
} cctrl_cmd_collection_attach_t;

typedef struct castle_control_cmd_collection_detach {
    c_collection_id_t collection;       /* IN  */
    int               ret;              /* OUT */
} cctrl_cmd_collection_detach_t;

typedef struct castle_control_cmd_collection_snapshot {
    c_collection_id_t collection;      /* IN  */
    int               ret;             /* OUT */
    c_ver_t           version;         /* OUT */
} cctrl_cmd_collection_snapshot_t;

typedef struct castle_control_cmd_create {
    uint64_t size;            /* IN  */
    int      ret;             /* OUT */
    c_ver_t  id;              /* OUT */
} cctrl_cmd_create_t;

typedef struct castle_control_cmd_destroy_vertree {
    c_da_t vertree_id;      /* IN */
    int    ret;             /* OUT */
} cctrl_cmd_destroy_vertree_t;

typedef struct castle_control_cmd_vertree_compact {
    c_da_t vertree_id;      /* IN */
    int    ret;             /* OUT */
} cctrl_cmd_vertree_compact_t;

typedef struct castle_control_cmd_delete_version {
    c_ver_t version;         /* IN */
    int     ret;             /* OUT */
} cctrl_cmd_delete_version_t;

typedef struct castle_control_cmd_clone {
    c_ver_t version;         /* IN  */
    int     ret;             /* OUT */
    c_ver_t clone;           /* OUT */
} cctrl_cmd_clone_t;

typedef struct castle_control_cmd_init {
    int ret;                   /* OUT */
} cctrl_cmd_init_t;

typedef struct castle_control_cmd_transfer_create {
    c_ver_t         version;     /* IN  */
    uint32_t        direction;   /* IN  */
    int             ret;         /* OUT */
    c_transfer_id_t id;          /* OUT */
} cctrl_cmd_transfer_create_t;

typedef struct castle_control_cmd_transfer_destroy {
    c_transfer_id_t id;          /* IN  */
    int             ret;         /* OUT */
} cctrl_cmd_transfer_destroy_t;

typedef struct castle_control_cmd_protocol_version {
    int      ret;              /* OUT */
    uint32_t version;          /* OUT */
} cctrl_cmd_protocol_version_t;

typedef struct castle_control_cmd_environment_set {
    c_env_var_t var_id;        /* IN */
    const char *var_str;       /* IN  */
    size_t      var_len;       /* IN  */
    int         ret;           /* OUT */
} cctrl_cmd_environment_set_t;

typedef struct castle_control_cmd_fault {
    c_fault_t fault_id;        /* IN  */
    uint32_t  fault_arg;       /* IN  */
    int       ret;             /* OUT */
} cctrl_cmd_fault_t;

typedef struct castle_control_cmd_trace_setup {
    const char *dir_str;       /* IN  */
    size_t      dir_len;       /* IN  */
    int         ret;           /* OUT */
} cctrl_cmd_trace_setup_t;

typedef struct castle_control_cmd_trace_start {
    int         ret;           /* OUT */
} cctrl_cmd_trace_start_t;

typedef struct castle_control_cmd_trace_stop {
    int         ret;           /* OUT */
} cctrl_cmd_trace_stop_t;

typedef struct castle_control_cmd_trace_teardown {
    int         ret;           /* OUT */
} cctrl_cmd_trace_teardown_t;

typedef struct castle_control_slave_evacuate {
    c_slave_uuid_t id;           /* IN  */
    uint32_t       force;        /* IN  */
    int            ret;          /* OUT */
} PACKED cctrl_cmd_slave_evacuate_t;

typedef struct castle_control_slave_scan {
    c_slave_uuid_t id;           /* IN  */
    int            ret;          /* OUT */
} PACKED cctrl_cmd_slave_scan_t;

typedef struct castle_control_cmd_thread_priority {
    int       nice_value;       /* IN */
    int       ret;             /* OUT */
} cctrl_cmd_thread_priority_t;

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
        cctrl_cmd_destroy_vertree_t     destroy_vertree;
        cctrl_cmd_delete_version_t      delete_version;
        cctrl_cmd_vertree_compact_t     vertree_compact;
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

        cctrl_cmd_slave_evacuate_t      slave_evacuate;
        cctrl_cmd_slave_scan_t          slave_scan;

        cctrl_cmd_thread_priority_t     thread_priority;
    };
} cctrl_ioctl_t;

/* IOCTL definitions. */
enum {
    CASTLE_CTRL_CLAIM_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CLAIM, cctrl_ioctl_t),
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
    CASTLE_CTRL_COLLECTION_ATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_ATTACH, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_DETACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_DETACH, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_SNAPSHOT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_SNAPSHOT, cctrl_ioctl_t),
    CASTLE_CTRL_VALID_STATS_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_VALID_STATS, cctrl_ioctl_t),
    CASTLE_CTRL_INVALID_STATS_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_INVALID_STATS, cctrl_ioctl_t),
    CASTLE_CTRL_DESTROY_VERTREE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_DESTROY_VERTREE, cctrl_ioctl_t),
    CASTLE_CTRL_DELETE_VERSION_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_DELETE_VERSION, cctrl_ioctl_t),
    CASTLE_CTRL_VERTREE_COMPACT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_VERTREE_COMPACT, cctrl_ioctl_t),
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
    CASTLE_CTRL_SLAVE_EVACUATE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_SLAVE_EVACUATE, cctrl_ioctl_t),
    CASTLE_CTRL_THREAD_PRIORITY_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_THREAD_PRIORITY, cctrl_ioctl_t),
    CASTLE_CTRL_SLAVE_SCAN_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_SLAVE_SCAN, cctrl_ioctl_t),
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

#define CASTLE_RING_PAGES (16)                              /**< 64 requests/page.                */
#define CASTLE_RING_SIZE (CASTLE_RING_PAGES << PAGE_SHIFT)  /**< Must be ^2 or things break.      */

#define CASTLE_STATEFUL_OPS 512

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
    c_collection_id_t     collection_id;
    c_vl_okey_t          *key_ptr;
    uint32_t              key_len;
    void                 *value_ptr;
    uint32_t              value_len;
} castle_request_replace_t;

typedef struct castle_request_remove {
    c_collection_id_t     collection_id;
    c_vl_okey_t          *key_ptr;
    uint32_t              key_len;
} castle_request_remove_t;

typedef struct castle_request_get {
    c_collection_id_t    collection_id;
    c_vl_okey_t         *key_ptr;
    uint32_t             key_len;
    void                *value_ptr; /* where to put the result */
    uint32_t             value_len;
} castle_request_get_t;

typedef struct castle_request_iter_start {
    c_collection_id_t    collection_id;
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
    c_collection_id_t  collection_id;
    c_vl_okey_t       *key_ptr;
    uint32_t           key_len;
} castle_request_big_get_t;

typedef struct castle_request_get_chunk {
    castle_interface_token_t  token;
    void                     *buffer_ptr;
    uint32_t                  buffer_len;
} castle_request_get_chunk_t;

typedef struct castle_request_big_put {
    c_collection_id_t  collection_id;
    c_vl_okey_t       *key_ptr;
    uint32_t           key_len;
    uint64_t           value_len;
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
    uint64_t               length;
    uint8_t                type;
    union {
        uint8_t           *val;
        c_collection_id_t  collection_id;
    };
};

struct castle_key_value_list {
    struct castle_key_value_list *next;
    c_vl_okey_t                  *key;
    struct castle_iter_val       *val;
};


#define CASTLE_SLAVE_MAGIC1     (0x02061985)
#define CASTLE_SLAVE_MAGIC2     (0x16071983)
#define CASTLE_SLAVE_MAGIC3     (0x16061981)
#define CASTLE_SLAVE_VERSION    (14)

#define CASTLE_SLAVE_NEWDEV     (0x00000004)
#define CASTLE_SLAVE_SSD        (0x00000008)
#define CASTLE_SLAVE_SB_INVALID (0x00000010)

struct castle_slave_superblock_public {
    /* align:   8 */
    /* offset:  0 */ uint32_t magic1;
    /*          4 */ uint32_t magic2;
    /*          8 */ uint32_t magic3;
    /*         12 */ uint32_t version;   /* Super chunk format version */
    /*         16 */ uint32_t uuid;
    /*         20 */ uint32_t used;
    /*         24 */ uint64_t size;      /* In 4K blocks. */
    /*         32 */ uint32_t flags;
    /*         36 */ uint32_t checksum;
    /*         40 */ uint8_t  _unused[88];
    /*        128 */
} PACKED;

#define CASTLE_FS_MAGIC1        (0x19731121)
#define CASTLE_FS_MAGIC2        (0x19880624)
#define CASTLE_FS_MAGIC3        (0x19821120)
#define CASTLE_FS_VERSION       (1)

struct castle_fs_superblock_public {
    /* align:   4 */
    /* offset:  0 */ uint32_t magic1;
    /*          4 */ uint32_t magic2;
    /*          8 */ uint32_t magic3;
    /*         12 */ uint32_t uuid;
    /*         16 */ uint32_t version;   /* Super chunk format version */
    /*         20 */ uint32_t salt;
    /*         24 */ uint32_t peper;
    /*         28 */ uint32_t checksum;
    /*         32 */ uint8_t  _unused[96];
    /*        128 */
} PACKED;

#endif /* __CASTLE_PUBLIC_H__ */
