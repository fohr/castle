#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

#include <linux/types.h>

typedef uint32_t transfer_id_t;
typedef uint32_t slave_uuid_t;
typedef uint32_t collection_id_t;
typedef uint32_t version_t;
#define INVAL_VERSION       ((version_t)-1) 
#define VERSION_INVAL(_v)   ((_v) == INVAL_VERSION) 

/* Definitions for RxRPC/XDR marshalling */
#define CASTLE_OBJ_REQ_GET                       0
#define CASTLE_OBJ_REQ_REPLACE                   1
#define CASTLE_OBJ_REQ_SLICE                     5
#define CASTLE_CTRL_REQ                          7

#define CASTLE_OBJ_REPLY_REPLACE                 2
#define CASTLE_OBJ_REPLY_GET                     3
#define CASTLE_OBJ_REPLY_ERROR                   4
#define CASTLE_OBJ_REPLY_GET_SLICE               6
#define CASTLE_CTRL_REPLY                        8

/* Subtypes for CASTLE_REPLACE_REQ */
#define CASTLE_OBJ_TOMBSTONE                     0
#define CASTLE_OBJ_VALUE                         1

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

typedef struct castle_control_cmd_snapshot {
    uint32_t  dev;             /* IN  */
    int       ret;             /* OUT */
    version_t version;         /* OUT */
} cctrl_cmd_snapshot_t;

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
        cctrl_cmd_attach_t           attach;
        cctrl_cmd_detach_t           detach;
        cctrl_cmd_create_t           create;
        cctrl_cmd_clone_t            clone;
        cctrl_cmd_snapshot_t         snapshot;
        cctrl_cmd_init_t             init;
        cctrl_cmd_transfer_create_t  transfer_create;
        cctrl_cmd_transfer_destroy_t transfer_destroy;
    };
} cctrl_ioctl_t;

#endif /* __CASTLE_PUBLIC_H__ */
