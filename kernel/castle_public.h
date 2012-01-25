#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

#include <linux/types.h>
#include <asm/ioctl.h>
#ifndef __KERNEL__
#include <sys/time.h>
#include <sys/types.h>
#else
#include <linux/time.h>
#endif

#ifdef __cplusplus
extern "C" {
#endif

#define CASTLE_PROTOCOL_VERSION 33 /* last updated by GM */

#ifdef SWIG
#define PACKED               //overide gcc intrinsics for SWIG
#else
#define PACKED               __attribute__((packed))
#endif

#ifndef __KERNEL__
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
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
    TRACE_CACHE,            /**< Cache events        */
    TRACE_DA,               /**< DA events           */
    TRACE_DA_MERGE,         /**< Merge events        */
    TRACE_DA_MERGE_UNIT,    /**< Merge unit events   */
    TRACE_IO_SCHED,         /**< IO scheduler events */
} c_trc_prov_t;

/**
 * Event types.
 */
typedef enum {
    TRACE_PERCENTAGE,   /**< Percentage value       */
    TRACE_VALUE,        /**< Value being reported   */
    TRACE_MARK,         /**< Event has occurred     */
    TRACE_START,        /**< Event has started      */
    TRACE_END,          /**< Event has ended        */
} c_trc_type_t;

/**
 * Cache trace variables.
 */
typedef enum {
    TRACE_CACHE_CHECKPOINT_ID,            /**< Checkpoint running.                                */
    TRACE_CACHE_DIRTY_PGS_ID,             /**< Number of c2ps on the dirtylist.                   */
    TRACE_CACHE_CLEAN_PGS_ID,             /**< Number of c2ps on the cleanlist.                   */
    TRACE_CACHE_FREE_PGS_ID,              /**< Number of c2ps on the freelist.                    */
    TRACE_CACHE_RESERVE_PGS_ID,           /**< Number of c2ps on the reserve freelist.            */
    TRACE_CACHE_CLEAN_BLKS_ID,            /**< Number of c2bs on the cleanlist.                   */
    TRACE_CACHE_FREE_BLKS_ID,             /**< Number of c2bs on the freelist.                    */
    TRACE_CACHE_RESERVE_BLKS_ID,          /**< Number of c2bs on the reserve freelist.            */
    TRACE_CACHE_SOFTPIN_BLKS_ID,          /**< Number of softpin c2bs in the cache.               */
    TRACE_CACHE_BLOCK_VICTIMS_ID,         /**< Number of c2bs evicted from the cache.             */
    TRACE_CACHE_SOFTPIN_VICTIMS_ID,       /**< Number of softpinned c2bs evicted from the cache.  */
    TRACE_CACHE_READS_ID,                 /**< Number of reads this tick.                         */
    TRACE_CACHE_WRITES_ID,                /**< Number of writes this tick.                        */
    TRACE_CACHE_RESERVE_PGS_USED_ID,      /**< Number of c2ps from reserve freelist in use.       */
    TRACE_CACHE_RESERVE_BLKS_USED_ID,     /**< Number of c2bs from reserve freelist in use.       */
    TRACE_CACHE_META_DATA_IOS_ID,         /**< IOs to meta extent                                 */
    TRACE_CACHE_GLOBAL_BTREE_IOS_ID,      /**< IOs to global btree extent                         */
    TRACE_CACHE_BLOCK_DEV_IOS_ID,         /**< IOs to device mapper blocks                        */
    TRACE_CACHE_INTERNAL_NODES_IOS_ID,    /**< IOs to non T0 internal btree nodes                 */
    TRACE_CACHE_LEAF_NODES_IOS_ID,        /**< IOs to non T0 leaf btree nodes                     */
    TRACE_CACHE_MEDIUM_OBJECTS_IOS_ID,    /**< IOs to non T0 medium objects                       */
    TRACE_CACHE_T0_INTERNAL_NODES_IOS_ID, /**< IOs to T0 internal btree nodes                     */
    TRACE_CACHE_T0_LEAF_NODES_IOS_ID,     /**< IOs to T0 leaf btree nodes                         */
    TRACE_CACHE_T0_MEDIUM_OBJECTS_IOS_ID, /**< IOs to T0 medium objects                           */
    TRACE_CACHE_LARGE_OBJECT_IOS_ID,      /**< IOs to large objects                               */
    TRACE_CACHE_BLOOM_FILTER_IOS_ID,      /**< IOs to bloom filters                               */
    TRACE_CACHE_BLK_T0_INT_HIT_MISS_ID,   /**< Hits, misses T0 internal nodes                     */
    TRACE_CACHE_BLK_T0_INT_HITS_ID,       /**< Hits  T0 internal nodes                            */
    TRACE_CACHE_BLK_T0_INT_MISSES_ID,     /**< Misses T0 internal nodes                           */
    TRACE_CACHE_BLK_T0_INT_HITS_PCT_ID,   /**< %Hits  T0 internal nodes                           */
    TRACE_CACHE_BLK_T0_INT_MISSES_PCT_ID, /**< %Misses T0 internal nodes                          */
    TRACE_CACHE_BLK_T0_LEAF_HIT_MISS_ID,  /**< Hits, misses T0 leaf nodes                         */
    TRACE_CACHE_BLK_T0_LEAF_HITS_ID,      /**< Hits  T0 leaf nodes                                */
    TRACE_CACHE_BLK_T0_LEAF_MISSES_ID,    /**< Misses T0 leaf nodes                               */
    TRACE_CACHE_BLK_T0_LEAF_HITS_PCT_ID,  /**< %Hits  T0 leaf nodes                               */
    TRACE_CACHE_BLK_T0_LEAF_MISSES_PCT_ID,/**< %Misses T0 leaf nodes                              */
    TRACE_CACHE_BLK_INT_HIT_MISS_ID,      /**< Hits, misses ROCT internal nodes                   */
    TRACE_CACHE_BLK_INT_HITS_ID,          /**< Hits  ROCT internal nodes                          */
    TRACE_CACHE_BLK_INT_MISSES_ID,        /**< Misses ROCT internal nodes                         */
    TRACE_CACHE_BLK_INT_HITS_PCT_ID,      /**< %Hits  ROCT internal nodes                         */
    TRACE_CACHE_BLK_INT_MISSES_PCT_ID,    /**< %Misses ROCT internal nodes                        */
    TRACE_CACHE_BLK_LEAF_HIT_MISS_ID,     /**< Hits, misses ROCT leaf nodes                       */
    TRACE_CACHE_BLK_LEAF_HITS_ID,         /**< Hits ROCT leaf nodes                               */
    TRACE_CACHE_BLK_LEAF_MISSES_ID,       /**< Misses ROCT leaf nodes                             */
    TRACE_CACHE_BLK_LEAF_HITS_PCT_ID,     /**< %Hits  ROCT leaf nodes                             */
    TRACE_CACHE_BLK_LEAF_MISSES_PCT_ID,   /**< %Misses ROCT leaf nodes                            */
    TRACE_CACHE_BLK_GET_HIT_MISS_ID,      /**< Hits, misses within the cache                      */
    TRACE_CACHE_BLK_GET_HITS_ID,          /**< Block hits within the cache                        */
    TRACE_CACHE_BLK_GET_MISSES_ID,        /**< Block misses within the cache                      */
    TRACE_CACHE_BLK_GET_HITS_PCT_ID,      /**< % of block hits within the cache                   */
    TRACE_CACHE_BLK_GET_MISSES_PCT_ID,    /**< % of block misses within the cache                 */
    TRACE_CACHE_BLK_MERGE_HIT_MISS_ID,    /**< Hits, misses  of merges within the cache           */
    TRACE_CACHE_BLK_MERGE_HITS_ID,        /**< Merge hits within the cache                        */
    TRACE_CACHE_BLK_MERGE_MISSES_ID,      /**< Merge misses within the cache                      */
    TRACE_CACHE_BLK_MERGE_HITS_PCT_ID,    /**< % of merge hits within the cache                   */
    TRACE_CACHE_BLK_MERGE_MISSES_PCT_ID,  /**< % of merge misses within the cache                 */
    TRACE_CACHE_BLK_NON_MERGE_HIT_MISS_ID,/**< Hits, misses  of merges within the cache           */
    TRACE_CACHE_BLK_NON_MERGE_HITS_ID,    /**< Merge hits within the cache                        */
    TRACE_CACHE_BLK_NON_MERGE_MISSES_ID,  /**< Merge misses within the cache                      */
    TRACE_CACHE_BLK_NON_MERGE_HITS_PCT_ID,/**< % of merge hits within the cache                   */
    TRACE_CACHE_BLK_NON_MERGE_MISSES_PCT_ID,/**< % of merge misses within the cache               */
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
    TRACE_DA_MERGE_UNIT_CACHE_BTREE_EFFICIENCY_ID,  /**< % of up2date btree chunk-c2bs.         */
    TRACE_DA_MERGE_UNIT_CACHE_DATA_EFFICIENCY_ID,   /**< % of up2date data chunk-c2bs.          */
} c_trc_da_var_t;
#define MERGE_START_FLAG    (1U<<0)
#define MERGE_END_FLAG      (1U<<1)

/**
 * IO scheduler trace variables.
 */
typedef enum {
    TRACE_IO_SCHED_NUM_READ_IOS_ID,          /**< Number of IOs done due to reads               */
    TRACE_IO_SCHED_NUM_MERGE_IOS_ID,         /**< Number of IOs done due to merges (and writes) */
    TRACE_IO_SCHED_NUM_CHECKPOINT_IOS_ID,    /**< Number of IOs done due to checkpoints         */
    TRACE_IO_SCHED_BYTES_READ_IOS_ID,        /**< Amount of IO data due to reads                */
    TRACE_IO_SCHED_BYTES_MERGE_IOS_ID,       /**< Amount of IO data due to merges (and writes)  */
    TRACE_IO_SCHED_BYTES_CHECKPOINT_IOS_ID,  /**< Amount of IO data due to checkpoints          */
} c_trc_io_sched_var_t;

/* Bump the magic version byte (LSB) when c_trc_evt_t changes. */
#define CASTLE_TRACE_MAGIC          0xCAE5E110
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

typedef uint64_t c_da_opts_t;       /**< Options bitmask for DA options that must be set at
                                         creation time. */
enum {
    CASTLE_DA_OPTS_NONE                  = (0),             /**< No options (all defaults). */
    CASTLE_DA_OPTS_NO_USER_TIMESTAMPING  = (1 << 0),        /**< Disable user timestamping. */
};

/* Golden Nugget - Types */
typedef uint64_t c_array_id_t;
typedef uint32_t c_merge_id_t;
typedef uint32_t c_thread_id_t;
typedef uint32_t c_work_id_t;
typedef uint64_t c_work_size_t;
typedef uint64_t c_data_ext_id_t;

#define INVAL_ARRAY_ID      ((c_array_id_t)-1)
#define ARRAY_ID_INVAL(_a)  ((_a) == INVAL_ARRAY_ID)
#define INVAL_MERGE_ID      ((c_merge_id_t)-1)
#define MERGE_ID_INVAL(_m)  ((_m) == INVAL_MERGE_ID)
#define INVAL_THREAD_ID     ((c_thread_id_t)-1)
#define THREAD_ID_INVAL(_t) ((_t) == INVAL_THREAD_ID)
#define INVAL_WORK_ID       ((c_work_id_t)-1)
#define WORK_ID_INVAL(_t)   ((_t) == INVAL_WORK_ID)

#define MERGE_ALL_DATA_EXTS ((uint32_t)(~0U))

typedef enum {
    RDA_1,
    RDA_2,
    SSD_RDA_2,
    SSD_RDA_3,
    META_EXT,
    MICRO_EXT,
    SUPER_EXT,
    SSD_ONLY_EXT,
    NR_RDA_SPECS
} c_rda_type_t;

typedef struct castle_merge_config {
    uint32_t                nr_arrays;          /**< # of arrays to be merged.                  */
    c_array_id_t           *arrays;             /**< List of arrays.                            */
    uint32_t                nr_data_exts;       /**< Number of medium extents in this array.    */
    c_data_ext_id_t        *data_exts;          /**< List of medium extents.                    */
    c_rda_type_t            metadata_ext_type;  /**< Type of the extent that the output metdata *
                                                  *< to go. (SSD_RDA/DEFAULT_RDA/SSD_ONLY_EXT)  */
    c_rda_type_t            data_ext_type;      /**< Type of the extent that medium objects     *
                                                  *< to go. (SSD_RDA/DEFAULT_RDA/SSD_ONLY_EXT)  */
    uint32_t                bandwidth;
} c_merge_cfg_t;

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
#define CASTLE_CTRL_COLLECTION_REATTACH      33

#define CASTLE_CTRL_MERGE_THREAD_CREATE      34
#define CASTLE_CTRL_MERGE_THREAD_DESTROY     35
#define CASTLE_CTRL_MERGE_START              36
#define CASTLE_CTRL_MERGE_DO_WORK            37
#define CASTLE_CTRL_MERGE_STOP               38
#define CASTLE_CTRL_MERGE_THREAD_ATTACH      39
#define CASTLE_CTRL_INSERT_RATE_SET          40
#define CASTLE_CTRL_READ_RATE_SET            41
#define CASTLE_CTRL_PROG_REGISTER            42
#define CASTLE_CTRL_PROG_DEREGISTER          43
#define CASTLE_CTRL_PROG_HEARTBEAT           44

#define CASTLE_CTRL_CREATE_WITH_OPTS         45
#define CASTLE_CTRL_VERTREE_TDP_SET          46
#define CASTLE_CTRL_STATE_QUERY              47



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

typedef struct castle_control_cmd_collection_reattach {
    c_collection_id_t  collection;      /* IN */
    c_ver_t            new_version;     /* IN  */
    int                ret;             /* OUT */
} cctrl_cmd_collection_reattach_t;

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

typedef struct castle_control_cmd_create_with_opts {
    uint64_t    size;         /* IN  */
    c_da_opts_t opts;         /* IN */
    int         ret;          /* OUT */
    c_ver_t     id;           /* OUT */
} cctrl_cmd_create_with_opts_t;

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

/* Golden Nugget - Interface structures. */
typedef struct castle_control_cmd_merge_thread_create {
    c_thread_id_t   thread_id;      /* OUT */
    int             ret;            /* OUT */
} cctrl_cmd_merge_thread_create_t;

typedef struct castle_control_cmd_merge_thread_destroy {
    c_thread_id_t   thread_id;      /* IN  */
    int             ret;            /* OUT */
} cctrl_cmd_merge_thread_destroy_t;

typedef struct castle_control_cmd_merge_start {
    c_merge_cfg_t   merge_cfg;      /* IN  */
    c_merge_id_t    merge_id;       /* OUT */
    int             ret;            /* OUT */
} cctrl_cmd_merge_start_t;

typedef struct castle_control_cmd_merge_do_work {
    c_merge_id_t    merge_id;       /* IN  */
    c_work_size_t   work_size;      /* IN  */
    c_work_id_t     work_id;        /* OUT */
    int             ret;            /* OUT */
} cctrl_cmd_merge_do_work_t;

typedef struct castle_control_cmd_merge_stop {
    c_merge_id_t    merge_id;       /* IN  */
    int             ret;            /* OUT */
} cctrl_cmd_merge_stop_t;

typedef struct castle_control_cmd_merge_thread_attach {
    c_merge_id_t    merge_id;       /* IN  */
    c_thread_id_t   thread_id;      /* IN  */
    int             ret;            /* OUT */
} cctrl_cmd_merge_thread_attach_t;

typedef struct castle_control_cmd_insert_rate_set {
    c_da_t          vertree_id;     /* IN  */
    uint32_t        insert_rate;    /* IN  */
    int             ret;            /* OUT */
} cctrl_cmd_insert_rate_set_t;

typedef struct castle_control_cmd_read_rate_set {
    c_da_t          vertree_id;     /* IN  */
    uint32_t        read_rate;      /* IN  */
    int             ret;            /* OUT */
} cctrl_cmd_read_rate_set_t;

typedef struct castle_control_cmd_prog_register {
    int             ret;            /* OUT */
} cctrl_cmd_prog_register_t;

typedef struct castle_control_cmd_prog_deregister {
    uint8_t         shutdown;       /* IN  */
    pid_t           pid;            /* OUT  */
    int             ret;            /* OUT */
} cctrl_cmd_prog_deregister_t;

typedef struct castle_control_cmd_prog_heartbeat {
    int             ret;            /* OUT */
} cctrl_cmd_prog_heartbeat_t;

typedef struct castle_control_cmd_vertree_tdp_set {
    c_da_t          vertree_id;     /* IN */
    uint64_t        seconds;        /* IN */
    int             ret;            /* OUT */
} cctrl_cmd_vertree_tdp_set_t;

typedef enum {
    CASTLE_STATE_LOADING = 0,
    CASTLE_STATE_UNINITED,
    CASTLE_STATE_INITED,
} c_state_t;

typedef struct castle_control_cmd_state_query {
    c_state_t       state;          /* OUT */
    int             ret;            /* OUT */
} cctrl_cmd_state_query_t;

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
        cctrl_cmd_collection_reattach_t collection_reattach;
        cctrl_cmd_collection_detach_t   collection_detach;
        cctrl_cmd_collection_snapshot_t collection_snapshot;

        cctrl_cmd_create_t              create;
        cctrl_cmd_create_with_opts_t    create_with_opts;
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
        cctrl_cmd_merge_thread_create_t merge_thread_create;
        cctrl_cmd_merge_thread_destroy_t merge_thread_destroy;
        cctrl_cmd_merge_start_t         merge_start;
        cctrl_cmd_merge_do_work_t       merge_do_work;
        cctrl_cmd_merge_stop_t          merge_stop;
        cctrl_cmd_merge_thread_attach_t merge_thread_attach;
        cctrl_cmd_insert_rate_set_t     insert_rate_set;
        cctrl_cmd_read_rate_set_t       read_rate_set;
        cctrl_cmd_prog_register_t       ctrl_prog_register;
        cctrl_cmd_prog_deregister_t     ctrl_prog_deregister;
        cctrl_cmd_prog_heartbeat_t      ctrl_prog_heartbeat;

        cctrl_cmd_vertree_tdp_set_t     vertree_tdp_set;
        cctrl_cmd_state_query_t         state_query;
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
    CASTLE_CTRL_CREATE_WITH_OPTS_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CREATE_WITH_OPTS, cctrl_ioctl_t),
    CASTLE_CTRL_CLONE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_CLONE, cctrl_ioctl_t),
    CASTLE_CTRL_SNAPSHOT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_SNAPSHOT, cctrl_ioctl_t),
    CASTLE_CTRL_INIT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_INIT, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_ATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_ATTACH, cctrl_ioctl_t),
    CASTLE_CTRL_COLLECTION_REATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_COLLECTION_REATTACH, cctrl_ioctl_t),
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
    CASTLE_CTRL_MERGE_THREAD_CREATE_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_THREAD_CREATE, cctrl_ioctl_t),
    CASTLE_CTRL_MERGE_THREAD_DESTROY_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_THREAD_DESTROY, cctrl_ioctl_t),
    CASTLE_CTRL_MERGE_START_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_START, cctrl_ioctl_t),
    CASTLE_CTRL_MERGE_DO_WORK_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_DO_WORK, cctrl_ioctl_t),
    CASTLE_CTRL_MERGE_STOP_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_STOP, cctrl_ioctl_t),
    CASTLE_CTRL_MERGE_THREAD_ATTACH_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_MERGE_THREAD_ATTACH, cctrl_ioctl_t),
    CASTLE_CTRL_INSERT_RATE_SET_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_INSERT_RATE_SET, cctrl_ioctl_t),
    CASTLE_CTRL_READ_RATE_SET_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_READ_RATE_SET, cctrl_ioctl_t),
    CASTLE_CTRL_PROG_REGISTER_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_PROG_REGISTER, cctrl_ioctl_t),
    CASTLE_CTRL_PROG_DEREGISTER_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_PROG_DEREGISTER, cctrl_ioctl_t),
    CASTLE_CTRL_PROG_HEARTBEAT_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_PROG_HEARTBEAT, cctrl_ioctl_t),
    CASTLE_CTRL_VERTREE_TDP_SET_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_VERTREE_TDP_SET, cctrl_ioctl_t),
    CASTLE_CTRL_STATE_QUERY_IOCTL =
        _IOWR(CASTLE_CTRL_IOCTL_TYPE, CASTLE_CTRL_STATE_QUERY, cctrl_ioctl_t),
};

/*
 * Castle B-tree key definitions. The key structure defined here is also, in fact, the key
 * structure which is exported to userspace.
 */

/**
 * Castle B-Tree key. No pointers.
 *
 * Each dim_head(one per dimension) contains 8-bits for flags(lower bits) and remaining
 * 24 bits for offset of the payload. Payloads continue immediatly after dim_head array.
 */
typedef struct castle_var_length_btree_key {
    /* align:   4 */
    /* offset:  0 */ uint32_t length;
    /*          4 */ uint32_t nr_dims;
    /*          8 */ uint8_t  _unused[8];
    /*         16 */ uint32_t dim_head[0];
    /*         16 */
    /* Dimension header is followed by individual dimensions. */
} PACKED c_vl_bkey_t;

#define KEY_DIMENSION_NEXT_FLAG             (1 << 0)
#define KEY_DIMENSION_MINUS_INFINITY_FLAG   (1 << 1)
#define KEY_DIMENSION_PLUS_INFINITY_FLAG    (1 << 2)
#define KEY_DIMENSION_UNUSED3_FLAG          (1 << 3)
#define KEY_DIMENSION_UNUSED4_FLAG          (1 << 4)
#define KEY_DIMENSION_UNUSED5_FLAG          (1 << 5)
#define KEY_DIMENSION_UNUSED6_FLAG          (1 << 6)
#define KEY_DIMENSION_UNUSED7_FLAG          (1 << 7)
#define KEY_DIMENSION_FLAGS_SHIFT           (8)
#define KEY_DIMENSION_FLAGS_MASK           ((1 << KEY_DIMENSION_FLAGS_SHIFT) - 1)
#define KEY_DIMENSION_INFINITY_FLAGS_MASK   (KEY_DIMENSION_MINUS_INFINITY_FLAG |          \
                                             KEY_DIMENSION_PLUS_INFINITY_FLAG)
#define KEY_DIMENSION_FLAGS(_dim_head)      ((_dim_head) &  KEY_DIMENSION_FLAGS_MASK)
#define KEY_DIMENSION_OFFSET(_dim_head)     ((_dim_head) >> KEY_DIMENSION_FLAGS_SHIFT)
#define KEY_DIMENSION_HEADER(_off, _flags)  (((_off)  << KEY_DIMENSION_FLAGS_SHIFT) |     \
                                             ((_flags) & KEY_DIMENSION_FLAGS_MASK))

#define castle_object_btree_key_header_size(_nr_dims)                                     \
        ( sizeof(c_vl_bkey_t) + ((_nr_dims) * 4) )

#define castle_object_btree_key_length(_key)                                              \
        ( (_key) ? ((_key)->length + 4) : 0 )

#define castle_object_btree_key_dim_length(key, dim)                                      \
({                                                                                        \
    uint32_t end_offset;                                                                  \
                                                                                          \
    end_offset = (dim+1 < key->nr_dims) ? KEY_DIMENSION_OFFSET(key->dim_head[dim+1]) :    \
                                          key->length + 4;                                \
    (end_offset - KEY_DIMENSION_OFFSET(key->dim_head[dim]));                              \
})

#define castle_object_btree_key_dim_get(key, dim)                                         \
({                                                                                        \
    ((char *)key + KEY_DIMENSION_OFFSET(key->dim_head[dim]));                             \
})

#define castle_object_btree_key_dim_flags_get(key, dim)                                   \
({                                                                                        \
    (KEY_DIMENSION_FLAGS(key->dim_head[dim]));                                            \
})

/*
 * Castle request interface definitions.
 *
 * CASTLE_RING_SIZE (and hence CASTLE_RING_PAGES) must be a power of two or code
 * will silently break.
 *
 * The __RING_SIZE macro determines how many requests can be present on the ring
 * at a time.  This macro allocates some space for the ring structures before
 * rounding down the remaining space to the next power of two.  Hence the Bytes
 * available for requests tends to be CASTLE_RING_SIZE/2 (which should be a
 * power of two).
 *
 * Requests on the ring are represented as castle_back_op structures.  As such
 * there are (CASTLE_RING_SIZE/2)/sizeof(castle_back_op) slots on the ring.
 *
 * CASTLE_STATEFUL_OPS determines the maximum number of stateful_ops.  In the
 * frontend code (libcastle) CASTLE_STATEFUL_OPS slots are reserved on the ring.
 * These slots cannot be used except by ongoing stateful_ops.  Therefore there
 * can be at most
 * (CASTLE_RING_SIZE/2)/sizeof(castle_back_request)-CASTLE_STATEFUL_OPS requests
 * on the ring that are not ongoing stateful ops.  Furthermore, the total ring
 * capacity must not exactly match CASTLE_STATEFUL_OPS or no requests may be
 * queued.
 */
#define CASTLE_RING_PAGES   (32)                                /**< Must be a power of 2.  */
#define CASTLE_RING_SIZE    (CASTLE_RING_PAGES << PAGE_SHIFT)
#define CASTLE_STATEFUL_OPS 512                                 /**< Must be < total slots. */


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
#define CASTLE_RING_ITER_SKIP 9
#define CASTLE_RING_ITER_FINISH 10
#define CASTLE_RING_REMOVE 11
#define CASTLE_RING_COUNTER_REPLACE 12
#define CASTLE_RING_TIMESTAMPED_REPLACE 13
#define CASTLE_RING_TIMESTAMPED_REMOVE 14
#define CASTLE_RING_TIMESTAMPED_BIG_PUT 15

typedef uint32_t castle_interface_token_t;

typedef uint64_t castle_user_timestamp_t;

typedef struct castle_request_replace {
    c_collection_id_t     collection_id;
    uint32_t              key_len;
    c_vl_bkey_t          *key_ptr;
    void                 *value_ptr;
    uint32_t              value_len;
} castle_request_replace_t;

typedef struct castle_request_timestamped_replace {
    c_collection_id_t        collection_id;
    uint32_t                 key_len;
    c_vl_bkey_t             *key_ptr;
    void                    *value_ptr;
    uint32_t                 value_len;
    castle_user_timestamp_t  user_timestamp;
} castle_request_timestamped_replace_t;

enum{
    CASTLE_COUNTER_TYPE_SET=0,
    CASTLE_COUNTER_TYPE_ADD,
};

typedef struct castle_request_counter_replace {
    c_collection_id_t     collection_id;
    uint32_t              key_len;
    c_vl_bkey_t          *key_ptr;
    void                 *value_ptr;
    uint32_t              value_len;
    uint8_t               add;              /**< Op type: CASTLE_COUNTER_TYPE_{SET|ADD}.    */
} castle_request_counter_replace_t;

typedef struct castle_request_remove {
    c_collection_id_t     collection_id;
    uint32_t              key_len;
    c_vl_bkey_t          *key_ptr;
} castle_request_remove_t;

typedef struct castle_request_timestamped_remove {
    c_collection_id_t        collection_id;
    uint32_t                 key_len;
    c_vl_bkey_t             *key_ptr;
    castle_user_timestamp_t  user_timestamp;
} castle_request_timestamped_remove_t;

typedef struct castle_request_get {
    c_collection_id_t    collection_id;
    uint32_t             key_len;
    c_vl_bkey_t         *key_ptr;
    void                *value_ptr;         /**< Output buffer for result.                  */
    uint32_t             value_len;
} castle_request_get_t;

typedef struct castle_request_iter_start {
    c_collection_id_t    collection_id;
    uint32_t             start_key_len;
    c_vl_bkey_t         *start_key_ptr;
    c_vl_bkey_t         *end_key_ptr;
    uint32_t             end_key_len;
    void                *buffer_ptr;        /**< Resulting kvps from iterator.              */
    uint32_t             buffer_len;        /**< Size of buffer_ptr buffer.                 */
} castle_request_iter_start_t;

typedef struct castle_request_iter_next {
    castle_interface_token_t  token;
    uint32_t                  buffer_len;
    void                     *buffer_ptr;
} castle_request_iter_next_t;

typedef struct castle_request_iter_finish {
    castle_interface_token_t token;
} castle_request_iter_finish_t;

typedef struct castle_request_big_get {
    c_collection_id_t  collection_id;
    uint32_t           key_len;
    c_vl_bkey_t       *key_ptr;
} castle_request_big_get_t;

typedef struct castle_request_get_chunk {
    castle_interface_token_t  token;
    uint32_t                  buffer_len;
    void                     *buffer_ptr;
} castle_request_get_chunk_t;

typedef struct castle_request_big_put {
    c_collection_id_t  collection_id;
    uint32_t           key_len;
    c_vl_bkey_t       *key_ptr;
    uint64_t           value_len;
} castle_request_big_put_t;

typedef struct castle_request_timestamped_big_put {
    c_collection_id_t         collection_id;
    uint32_t                  key_len;
    c_vl_bkey_t              *key_ptr;
    uint64_t                  value_len;
    castle_user_timestamp_t   user_timestamp;
} castle_request_timestamped_big_put_t;

typedef struct castle_request_put_chunk {
    castle_interface_token_t  token;
    uint32_t                  buffer_len;
    void                     *buffer_ptr;
} castle_request_put_chunk_t;

typedef struct castle_request {
    uint32_t    call_id;
    uint32_t    tag;
    union {
        castle_request_timestamped_replace_t     timestamped_replace;
        castle_request_timestamped_remove_t      timestamped_remove;
        castle_request_timestamped_big_put_t     timestamped_big_put;

        castle_request_replace_t            replace;
        castle_request_remove_t             remove;
        castle_request_get_t                get;

        castle_request_counter_replace_t    counter_replace;

        castle_request_big_get_t            big_get;
        castle_request_get_chunk_t          get_chunk;
        castle_request_big_put_t            big_put;
        castle_request_put_chunk_t          put_chunk;

        castle_request_iter_start_t         iter_start;
        castle_request_iter_next_t          iter_next;
        castle_request_iter_finish_t        iter_finish;
    };
    uint8_t     flags;                      /**< Flags affecting op, see CASTLE_RING_FLAGs.     */
} castle_request_t;

/**
 * Value types used in struct castle_request.flags field, which is a uint8_t.
 */
enum {
    CASTLE_RING_FLAG_NONE             = (1 << 0),        /**< No flags specified.                            */
    CASTLE_RING_FLAG_NO_PREFETCH      = (1 << 1),        /**< Don't prefetch as part of this request.        */
    CASTLE_RING_FLAG_NO_CACHE         = (1 << 2),        /**< Don't evict other data to cache this request.  */
    CASTLE_RING_FLAG_ITER_NO_VALUES   = (1 << 3),        /**< Iterator to return only keys, not values.      */
    CASTLE_RING_FLAG_ITER_GET_OOL     = (1 << 4),        /**< Return out-of-line values inline.              */
    CASTLE_RING_FLAG_RET_TIMESTAMP    = (1 << 5),
};

typedef struct castle_response {
    uint32_t                 call_id;
    uint32_t                 err;
    uint64_t                 length;
    castle_interface_token_t token;
    castle_user_timestamp_t  user_timestamp;   /** For non-timestamped collections, this will be
                                                   undefined. If the request flag did not specify
                                                   CASTLE_RING_FLAG_RET_TIMESTAMP, this is
                                                   undefined. Undefined on non-get ops.       */
} castle_response_t;

/* Value types used in struct castle_iter_val. */
enum {
    CASTLE_VALUE_TYPE_INVALID         = 0,
    CASTLE_VALUE_TYPE_INLINE          = 1,
    CASTLE_VALUE_TYPE_OUT_OF_LINE     = 2,
    CASTLE_VALUE_TYPE_INLINE_COUNTER  = 3
};

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
    c_vl_bkey_t                  *key;
    struct castle_iter_val       *val;
    castle_user_timestamp_t       user_timestamp;
};


#define CASTLE_SLAVE_MAGIC1     (0x02061985)
#define CASTLE_SLAVE_MAGIC2     (0x16071983)
#define CASTLE_SLAVE_MAGIC3     (0x16061981)
#define CASTLE_SLAVE_VERSION    (24)            /* Last changed by: GM */

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
#define CASTLE_FS_VERSION       (2)

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

/**
 * 0                            - Success.
 * 1    -   100                 - Generic errors.
 * 101  -   200                 - Userspace controlled merge errors.
 * 201  -   300                 - Control command errors.
 * 500                          - CASTLE_ERROR_MAX - don't increase is too much. Error string
 *                                array will take more space.
 */
#define CASTLE_ERROR_MAX_NUM 500
#define CASTLE_ERRORS                                                                           \
    CASTLE_ERROR_CODE(0, C_ERR_SUCCESS, "Operation Succeeded.")                                 \
    CASTLE_ERROR_CODE(1, C_ERR_NOSPC, "Not enough space available on disk.")                    \
    CASTLE_ERROR_CODE(2, C_ERR_NOMEM, "Not enough memory available.")                           \
    CASTLE_ERROR_CODE(3, C_ERR_FAIL, "Operation Failed.")                                       \
    CASTLE_ERROR_CODE(4, C_ERR_RUNNING, "Operation already running.")                           \
    CASTLE_ERROR_CODE(5, C_ERR_NODISK, "No disk available.")                                    \
    CASTLE_ERROR_CODE(6, C_ERR_FS_VERSION, "FS version on slaves is not matching.")             \
    CASTLE_ERROR_CODE(7, C_ERR_INTERNAL, "Castle FS internal failure.")                         \
    CASTLE_ERROR_CODE(8, C_ERR_INVAL_PARAM, "Couldn't find associated structure in kernel.")    \
    CASTLE_ERROR_CODE(9, C_ERR_NODEV, "No device available.")                                   \
    CASTLE_ERROR_CODE(10, C_ERR_INVAL_VER, "Invalid version.")                                  \
    CASTLE_ERROR_CODE(11, C_ERR_MEM_FAULT, "Can't access memory.")                              \
    CASTLE_ERROR_CODE(12, C_ERR_EXISTS, "Already exists.")                                      \
    CASTLE_ERROR_CODE(13, C_ERR_INVAL, "Invalid operation.")                                    \
    CASTLE_ERROR_CODE(14, C_ERR_PERM, "Permission denied.")                                     \
                                                                                                \
    CASTLE_ERROR_CODE(101, C_ERR_MERGE_0TREES, "Merge can't be done on zero trees.")            \
    CASTLE_ERROR_CODE(102, C_ERR_MERGE_THREAD, "Merge failed to create thread.")                \
    CASTLE_ERROR_CODE(103, C_ERR_MERGE_INVAL_DA, "Arrays belong to invalid version tree.")      \
    CASTLE_ERROR_CODE(104, C_ERR_MERGE_INVAL_EXT, "Arrays belong to invalid data extent.")      \
    CASTLE_ERROR_CODE(105, C_ERR_MERGE_ORPHAN_EXT, "Data extent doesn't belong to any array.")  \
    CASTLE_ERROR_CODE(106, C_ERR_MERGE_INIT, "Merge initialization failed.")                    \
    CASTLE_ERROR_CODE(107, C_ERR_MERGE_INVAL_ARRAY, "Array is invalid.")                        \
    CASTLE_ERROR_CODE(108, C_ERR_MERGE_ARRAY_BUSY, "Array is already merging.")                 \
    CASTLE_ERROR_CODE(109, C_ERR_MERGE_ARRAY_KERNEL, "Array is owned by kernel. Can't do merge.") \
    CASTLE_ERROR_CODE(110, C_ERR_MERGE_ARRAYS_OOO, "Arrays are not in order.")                  \
    CASTLE_ERROR_CODE(111, C_ERR_MERGE_ERROR, "Internal error in merges.")                      \
    CASTLE_ERROR_CODE(112, C_ERR_MERGE_INVAL_ID, "Invalid merge ID.")                           \
    CASTLE_ERROR_CODE(113, C_ERR_MERGE_RUNNING, "Merge is already running.")                    \
                                                                                                \
    CASTLE_ERROR_CODE(201, C_ERR_INVAL_DA, "Invalid version tree.")                             \
                                                                                                \
    CASTLE_ERROR_CODE(CASTLE_ERROR_MAX_NUM, CASTLE_ERROR_MAX, "Invalid error code from kernel.") \



#undef CASTLE_ERROR_CODE
#define CASTLE_ERROR_CODE(err_no, err_code, err_str)  err_code = err_no,
enum castle_error_codes
{
    CASTLE_ERRORS
};

/* castle_slave flags bits */
#define CASTLE_SLAVE_OOS_BIT             0 /* Slave is out-of-service */
#define CASTLE_SLAVE_EVACUATE_BIT        1 /* Slave is being, or has been, evacuated */
#define CASTLE_SLAVE_GHOST_BIT           2 /* Slave is missing or invalid (on reboot) */
#define CASTLE_SLAVE_REMAPPED_BIT        3 /* Slave has been remapped */
#define CASTLE_SLAVE_CLAIMING_BIT        4 /* Slave is not yet available for use (in castle_claim) */
#define CASTLE_SLAVE_BDCLAIMED_BIT       5 /* Slave has been bd_claim'ed. */
#define CASTLE_SLAVE_ORDERED_SUPP_BIT    6 /* Slave supports ordered writes. */
#define CASTLE_SLAVE_SYSFS_BIT           7 /* Slave has sysfs entry. */

#ifdef __cplusplus
}
#endif

#endif /* __CASTLE_PUBLIC_H__ */
