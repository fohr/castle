#ifndef __CASTLE_H__
#define __CASTLE_H__

typedef uint32_t version_t;
/* Disk layout related structures */
struct castle_disk_block {
    uint32_t disk;
    uint32_t block;
};
typedef struct castle_disk_block c_disk_blk_t;
#define INVAL_DISK_BLK          ((c_disk_blk_t){0,0})
#define DISK_BLK_INVAL(_blk)    (((_blk).block == 0) && ((_blk).disk == 0))
#define DISK_BLK_EQUAL(_blk1, _blk2) (((_blk1).disk == (_blk2).disk) && \
                                      ((_blk1).block == (_blk2).block)) 

struct castle_slave_superblock {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t uuid;
    uint32_t used;
    uint32_t size; /* In blocks */
};

struct castle_fs_superblock {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t salt;
    uint32_t peper;
    uint32_t fwd_tree_disk1;
    uint32_t fwd_tree_block1;
    uint32_t fwd_tree_disk2;
    uint32_t fwd_tree_block2;
    uint32_t rev_tree_disk1;
    uint32_t rev_tree_block1;
    uint32_t rev_tree_disk2;
    uint32_t rev_tree_block2;
};

#define NODE_HEADER        0x180

#define FTREE_SLOT_LEAF       0x1
#define FTREE_SLOT_NODE       0x2
#define FTREE_SLOT_NODE_LAST  0x3
#define FTREE_SLOT_IS_NODE(_slot)       (((_slot)->type == FTREE_SLOT_NODE) || \
                                         ((_slot)->type == FTREE_SLOT_NODE_LAST))
#define FTREE_SLOT_IS_NODE_LAST(_slot)   ((_slot)->type == FTREE_SLOT_NODE_LAST)
#define FTREE_SLOT_IS_LEAF(_slot)        ((_slot)->type == FTREE_SLOT_LEAF) 

#define FTREE_NODE_IS_LEAF(_node)        ((_node)->is_leaf)

#define INVAL_BLK          ((uint32_t)-1)
#define MAX_BLK            ((uint32_t)-2)
#define BLK_INVAL(_blk)    ((_blk) == INVAL_BLK)

struct castle_ftree_slot {
    uint32_t     type;
    uint32_t     block;
    uint32_t     version;
    c_disk_blk_t cdb;
};

#define FTREE_NODE_MAGIC  0x0000cdab
#define FTREE_NODE_SLOTS  ((PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_ftree_slot))
struct castle_ftree_node {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t used;
    uint8_t  __pad[NODE_HEADER - 16 /* for the 4 u32s above */ - 1 /* for is_leaf */];
    /* The following bits of data are computed dynamically, and don't need to be
       saved to the disk (even though they probably will */
    uint8_t  is_leaf;
    struct castle_ftree_slot slots[FTREE_NODE_SLOTS];
};


struct castle_vlist_slot {
    uint32_t     version_nr;
    uint32_t     parent;
    uint32_t     size;
    c_disk_blk_t cdb;
};

#define VLIST_SLOTS  ((PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_vlist_slot))
struct castle_vlist_node {
    uint32_t magic;
    uint32_t version; 
    uint32_t capacity;
    uint32_t used;
    c_disk_blk_t next; /* 8 bytes */
    c_disk_blk_t prev; /* 8 bytes */
    uint8_t __pad[NODE_HEADER - 32];
    struct castle_vlist_slot slots[VLIST_SLOTS];
};

/* IO related structures */
struct castle_bio_vec;
typedef struct castle_bio {
    struct bio            *bio;
    struct castle_bio_vec *c_bvecs; 
    atomic_t               remaining;
    int                    err;
} c_bio_t;


struct castle_cache_page;
typedef struct castle_bio_vec {
    /* Where did this IO originate from */
    c_bio_t            *c_bio;
    /* What (block,version) do we want to read */
    sector_t            block;
    uint32_t            version;
    /* Used to walk the B-Tree, and return the final cdb */
    union {
        /* Used when walking B-Tree. When writing, B-Tree node and
           its parent have to be locked concurrently. */
        struct {
            struct castle_cache_page *btree_node;
            struct castle_cache_page *btree_parent_node;
        };
        /* Location of the data on a slave disk. Set when B-Tree walk 
           is finished */
        c_disk_blk_t cdb;
    };
    /* Used to thread this bvec onto a workqueue */
    struct work_struct  work;
} c_bvec_t;
#define c_bvec_data_dir(_c_bvec)    bio_data_dir((_c_bvec)->c_bio->bio)
#define c_bvec_bnode(_c_bvec)       pfn_to_kaddr(page_to_pfn((_c_bvec)->btree_node->page))
#define c_bvec_bpnode(_c_bvec)      pfn_to_kaddr(page_to_pfn((_c_bvec)->btree_parent_node->page))
#define c_bvec_bio_iovec(_c_bvec)   bio_iovec_idx((_c_bvec)->c_bio->bio, c_bvec - c_bvec->c_bio->c_bvecs)

/* First class structures */
struct castle {
    struct kobject kobj;
};

struct castle_volumes {
    struct kobject kobj;
};

struct castle_slave {
    uint32_t                        id;
    uint32_t                        uuid; /* Copy of the uuid from the superblock
                                             needed here, because we cannot cache
                                             the superblock without being able to
                                             _find_by_uuid */
    struct kobject                  kobj;
    struct list_head                list;
    struct block_device            *bdev;
    struct castle_cache_page       *sblk;
    struct castle_cache_page       *fs_sblk;
};

struct castle_slaves {
    struct kobject   kobj;
    struct list_head slaves;
};

struct castle_device {
    struct kobject    kobj;
    spinlock_t        lock;
    struct list_head  list;
    struct gendisk   *gd;
    int               users;
    int               sysfs_registered;

    version_t         version;
};

struct castle_devices { 
    struct kobject kobj;
    int major;
    struct list_head devices;
};

extern struct castle             castle;
extern struct castle_volumes     castle_volumes;
extern struct castle_slaves      castle_slaves;
extern struct castle_devices     castle_devices;

extern struct workqueue_struct  *castle_wq;

/* Various utilities */
#define C_BLK_SHIFT                    (12) 
#define C_BLK_SIZE                     (1 << C_BLK_SHIFT)
#define disk_blk_to_offset(_cdb)     ((_cdb).block * C_BLK_SIZE)

void castle_bio_data_io_end(c_bvec_t *c_bvec, int err);
void castle_bio_data_io(c_bvec_t *c_bvec);

struct castle_device* castle_device_init       (version_t version);
void                  castle_device_free       (struct castle_device *cd);
struct castle_device* castle_device_find       (dev_t dev);
struct castle_slave*  castle_claim             (uint32_t new_dev);
struct castle_slave*  castle_slave_find_by_id  (uint32_t id);
struct castle_slave*  castle_slave_find_by_uuid(uint32_t uuid);
struct castle_slave*  castle_slave_find_by_block(c_disk_blk_t cdb);
c_disk_blk_t          castle_slaves_disk_block_get(void);
void                  castle_release           (struct castle_slave *cs);
int                   castle_fs_init           (void);

#endif /* __CASTLE_H__ */
