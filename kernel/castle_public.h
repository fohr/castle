#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

#include <linux/types.h>
#include "ring.h"

typedef uint32_t transfer_id_t;
typedef uint32_t slave_uuid_t;
typedef uint32_t collection_id_t;
typedef uint32_t version_t;
#define INVAL_VERSION       ((version_t)-1) 
#define VERSION_INVAL(_v)   ((_v) == INVAL_VERSION) 

/* Subtypes for CASTLE_CTRL_REQ, also used for IOCTLs */
#define CASTLE_CTRL_REQ_CLAIM                    1
#define CASTLE_CTRL_REQ_RELEASE                  2
#define CASTLE_CTRL_REQ_ATTACH                   3
#define CASTLE_CTRL_REQ_DETACH                   4
#define CASTLE_CTRL_REQ_CREATE                   5
#define CASTLE_CTRL_REQ_CLONE                    6
#define CASTLE_CTRL_REQ_SNAPSHOT                 7
#define CASTLE_CTRL_REQ_INIT                     8
//#define CASTLE_CTRL_REQ_REGION_CREATE            9
//#define CASTLE_CTRL_REQ_REGION_DESTROY           10
#define CASTLE_CTRL_REQ_TRANSFER_CREATE          11
#define CASTLE_CTRL_REQ_TRANSFER_DESTROY         12
#define CASTLE_CTRL_REQ_COLLECTION_ATTACH        13
#define CASTLE_CTRL_REQ_COLLECTION_DETACH        14
#define CASTLE_CTRL_REQ_COLLECTION_SNAPSHOT      15
#define CASTLE_CTRL_REQ_RESERVE_FOR_TRANSFER     16

#define CASTLE_CTRL_REQ_VALID_STATS              17
#define CASTLE_CTRL_REQ_INVALID_STATS            18

#define CASTLE_CTRL_REQ_SET_TARGET               19

/* Subtypes for CASTLE_CTRL_REPLY */
#define CASTLE_CTRL_REPLY_FAIL                   0
#define CASTLE_CTRL_REPLY_VOID                   1
#define CASTLE_CTRL_REPLY_NEW_SLAVE              2
#define CASTLE_CTRL_REPLY_NEW_VERSION            3
#define CASTLE_CTRL_REPLY_NEW_DEVICE             4
//#define CASTLE_CTRL_REPLY_NEW_REGION             5
#define CASTLE_CTRL_REPLY_NEW_TRANSFER           6
#define CASTLE_CTRL_REPLY_NEW_COLLECTION         7
//EXCEPTIONS 8
#define CASTLE_CTRL_REPLY_VALID_COUNTS           9
#define CASTLE_CTRL_REPLY_INVALID_COUNTS         10

/* Definitions for IOCTLs */
#define CASTLE_CTRL_IOCTL                        1     /* Only 1 ioctl at the moment */

/* Transfer directions */
#define CASTLE_TRANSFER_TO_TARGET                0
#define CASTLE_TRANSFER_TO_REGION                1

typedef struct castle_control_cmd_claim {
    uint32_t     dev;          /* IN  */
    int          ret;          /* OUT */
    slave_uuid_t id;           /* OUT */
} cctrl_cmd_claim_t;

typedef struct castle_control_cmd_release {
    slave_uuid_t id;           /* IN  */
    int          ret;          /* OUT */
} cctrl_cmd_release_t;

typedef struct castle_control_cmd_attach {
    version_t version;         /* IN  */
    int       ret;             /* OUT */
    uint32_t  dev;             /* OUT */
} cctrl_cmd_attach_t;

typedef struct castle_control_cmd_detach {
    uint32_t dev;              /* IN  */
    int      ret;              /* OUT */
} cctrl_cmd_detach_t;

typedef struct castle_control_cmd_snapshot {
    uint32_t  dev;             /* IN  */
    int       ret;             /* OUT */
    version_t version;         /* OUT */
} cctrl_cmd_snapshot_t;

typedef struct castle_control_cmd_collection_attach {
    version_t           version;         /* IN  */
    const char         *name;            /* IN  */
    size_t              name_length;     /* IN  */ 
    int                 ret;             /* OUT */
    collection_id_t     collection;      /* OUT */
} cctrl_cmd_collection_attach_t;

typedef struct castle_control_cmd_collection_detach {
    collection_id_t collection;          /* IN  */
    int             ret;                 /* OUT */
} cctrl_cmd_collection_detach_t;

typedef struct castle_control_cmd_collection_snapshot {
    collection_id_t collection; /* IN  */
    int       ret;             /* OUT */
    version_t version;         /* OUT */
} cctrl_cmd_collection_snapshot_t;

typedef struct castle_control_cmd_create {
    uint64_t  size;            /* IN  */
    int       ret;             /* OUT */
    version_t id;              /* OUT */
} cctrl_cmd_create_t;

typedef struct castle_control_cmd_clone {
    version_t version;         /* IN  */
    int       ret;             /* OUT */
    version_t clone;           /* OUT */
} cctrl_cmd_clone_t;

typedef struct castle_control_cmd_init {
    int ret;                   /* OUT */
} cctrl_cmd_init_t;

typedef struct castle_control_cmd_transfer_create {
    version_t     version;     /* IN  */
    uint32_t      direction;   /* IN  */
    int           ret;         /* OUT */
    transfer_id_t id;          /* OUT */
} cctrl_cmd_transfer_create_t;

typedef struct castle_control_cmd_transfer_destroy {
    transfer_id_t id;          /* IN  */
    int           ret;         /* OUT */
} cctrl_cmd_transfer_destroy_t;

typedef struct castle_control_ioctl {
    uint16_t cmd;
    union {
        cctrl_cmd_claim_t            claim;
        cctrl_cmd_release_t          release;
        cctrl_cmd_init_t             init;
        
        cctrl_cmd_attach_t           attach;
        cctrl_cmd_detach_t           detach;
        cctrl_cmd_snapshot_t         snapshot;

        cctrl_cmd_collection_attach_t           collection_attach;
        cctrl_cmd_collection_detach_t           collection_detach;
        cctrl_cmd_collection_snapshot_t         collection_snapshot;        

        cctrl_cmd_create_t           create;
        cctrl_cmd_clone_t            clone;

        cctrl_cmd_transfer_create_t  transfer_create;
        cctrl_cmd_transfer_destroy_t transfer_destroy;
    };
} cctrl_ioctl_t;

#ifndef __KERNEL__
#define PAGE_SIZE 4096
#define PAGE_SHIFT 12
// TODO: should link to castle.h
enum {
    CVT_TYPE_INLINE          = 0x10,
    CVT_TYPE_ONDISK          = 0x20,
    CVT_TYPE_INVALID         = 0x30,
};
#else

#endif

/*
 * BIG TODO - do we need to consider how these structures might work for 32bit
 * userspace are 64bit kernel?
 */

/* 
 * Variable length key, for example used by the btree 
 */
#define PACKED               __attribute__((packed))
 
typedef struct castle_var_length_key {
    uint32_t length;
    uint8_t key[0];
} PACKED c_vl_key_t;

typedef struct castle_var_length_object_key {
    uint32_t nr_dims;
    c_vl_key_t *dims[0];
} PACKED c_vl_okey_t;

#define CASTLE_RING_PAGES (2)
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
    size_t                key_len;
    void                 *value_ptr;
    size_t                value_len;
} castle_request_replace_t;

typedef struct castle_request_remove {
    collection_id_t       collection_id;
    c_vl_okey_t          *key_ptr;
    size_t                key_len;
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
    size_t               start_key_len;
    c_vl_okey_t         *end_key_ptr;
    size_t               end_key_len;
    uint64_t             flags;
} castle_request_iter_start_t;

#define CASTLE_RING_ITER_FLAG_NONE      0x0
#define CASTLE_RING_ITER_FLAG_NO_VALUES 0x1

typedef struct castle_request_iter_next {
    castle_interface_token_t token;
    void   *buffer_ptr;
    size_t  buffer_len;
} castle_request_iter_next_t;

typedef struct castle_request_iter_finish {
    castle_interface_token_t token;
} castle_request_iter_finish_t;

typedef struct castle_request {
    uint32_t call_id;
    uint32_t tag;
    union {
        castle_request_replace_t replace;
        castle_request_remove_t remove;
        castle_request_get_t get;
        
        castle_request_iter_start_t iter_start;
        castle_request_iter_next_t iter_next;
        castle_request_iter_finish_t iter_finish;
    };
} castle_request_t;

typedef struct castle_response {
    uint32_t call_id;
    uint32_t err;
    size_t   length;
    castle_interface_token_t token;
} castle_response_t;

struct castle_iter_val {
    uint8_t           type;
    uint32_t          length;
    uint8_t          *val;
};

struct castle_key_value_list {
    struct castle_key_value_list *next;
    c_vl_okey_t                  *key;
    struct castle_iter_val       *val;
} PACKED;

DEFINE_RING_TYPES(castle, castle_request_t, castle_response_t);

#endif /* __CASTLE_PUBLIC_H__ */
