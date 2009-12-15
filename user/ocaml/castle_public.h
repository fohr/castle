#ifndef __CASTLE_PUBLIC_H__
#define __CASTLE_PUBLIC_H__

typedef uint64_t snap_id_t;


/* Control ioctls */
#define CASTLE_CTRL_IOCTL              1     /* Only 1 ioctl at the moment */
                                       
#define CASTLE_CTRL_CMD_CLAIM          1     /* Claim physical device      */
#define CASTLE_CTRL_CMD_RELEASE        2     /* Release physical device    */ 
#define CASTLE_CTRL_CMD_ATTACH         3     /* Create /dev file for vol   */
#define CASTLE_CTRL_CMD_DETACH         4     /* Release /dev file          */
#define CASTLE_CTRL_CMD_CREATE         5     /* New vol                    */
#define CASTLE_CTRL_CMD_CLONE          6     /* Writable vol from snapshot */
#define CASTLE_CTRL_CMD_SNAPSHOT       7     /* Snapshot /dev file         */
#define CASTLE_CTRL_CMD_INIT           8     /* Init the file sytem        */

#define CASTLE_CTRL_CMD_RET          117     /* TEMPORARY       */
                                       
typedef struct castle_control_cmd_claim {
    uint32_t dev;               /* IN  */
    int      ret;               /* OUT */
} cctrl_cmd_claim_t;    

typedef struct castle_control_cmd_release {
    uint32_t dev;              /* IN  */
    int      ret;              /* OUT */
} cctrl_cmd_release_t;    

typedef struct castle_control_cmd_attach {
    snap_id_t snap;            /* IN  */
    int       ret;             /* OUT */
} cctrl_cmd_attach_t;    

typedef struct castle_control_cmd_detach {
    uint32_t dev;              /* IN  */
    int      ret;              /* OUT */
} cctrl_cmd_detach_t;    

typedef struct castle_control_cmd_create {
    uint64_t  size;            /* IN  */
    snap_id_t id;              /* OUT */
} cctrl_cmd_create_t;    

typedef struct castle_control_cmd_clone {
    snap_id_t snap;            /* IN  */
    snap_id_t clone;           /* OUT */
} cctrl_cmd_clone_t;    

typedef struct castle_control_cmd_snapshot {
    uint32_t  dev;             /* IN  */
    snap_id_t snap_id;         /* OUT */
} cctrl_cmd_snapshot_t;    

typedef struct castle_control_cmd_init {
    int ret;                   /* OUT */
} cctrl_cmd_init_t;    




typedef struct castle_control_cmd_ret {
    uint64_t   ret_val;
} cctrl_cmd_ret_t;    


typedef struct castle_control_ioctl {
    uint16_t cmd;
    union {
        cctrl_cmd_claim_t     claim;    
        cctrl_cmd_release_t   release;    
        cctrl_cmd_attach_t    attach;    
        cctrl_cmd_detach_t    detach;    
        cctrl_cmd_create_t    create;    
        cctrl_cmd_clone_t     clone;    
        cctrl_cmd_snapshot_t  snapshot;    
        cctrl_cmd_init_t      init;    

        cctrl_cmd_ret_t       ret;    
    };
} cctrl_ioctl_t;

#endif /* __CASTLE_PUBLIC_H__ */
