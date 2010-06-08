#ifndef __CASTLE_H__
#define __CASTLE_H__

#define USED                 __attribute__((used))
#define PACKED               __attribute__((packed))

#define STATIC_BUG_ON_HELPER(expr) \
        (!!sizeof (struct { unsigned int static_assertion_error: (expr) ? -1 : 1; }))
#define STATIC_BUG_ON(expr) \
        extern int (*assert_function__(void)) [STATIC_BUG_ON_HELPER(expr)]

typedef uint32_t block_t;
#define INVAL_BLOCK         ((block_t)-1) 
#define BLOCK_INVAL(_b)     ((_b) == INVAL_BLOCK) 
/* Disk layout related structures */
struct castle_disk_block {
    uint32_t disk;
    block_t block;
} PACKED;
typedef struct castle_disk_block c_disk_blk_t;
#define INVAL_DISK_BLK          ((c_disk_blk_t){0,0})
#define DISK_BLK_INVAL(_blk)    (((_blk).block == 0) && ((_blk).disk == 0))
#define DISK_BLK_EQUAL(_blk1, _blk2) (((_blk1).disk == (_blk2).disk) && \
                                      ((_blk1).block == (_blk2).block)) 
#define blkfmt                  "(0x%x, 0x%x)"
#define blk2str(_blk)           (_blk).disk, (_blk).block

#define CASTLE_SLAVE_TARGET     (0x00000001)
#define CASTLE_SLAVE_SPINNING   (0x00000002)

#define CASTLE_SLAVE_MAGIC1     (0x02061985)
#define CASTLE_SLAVE_MAGIC2     (0x16071983)
#define CASTLE_SLAVE_MAGIC3     (0x16061981)
struct castle_slave_superblock {
    uint32_t     magic1;
    uint32_t     magic2;
    uint32_t     magic3;
    uint32_t     uuid;
    uint32_t     used;
    uint32_t     size; /* In blocks */
	uint32_t     flags; 
    c_disk_blk_t flist_next;
    c_disk_blk_t flist_prev;
} PACKED;

#define CASTLE_FS_MAGIC1        (0x19731121)
#define CASTLE_FS_MAGIC2        (0x19880624)
#define CASTLE_FS_MAGIC3        (0x19821120)
struct castle_fs_superblock {
    uint32_t     magic1;
    uint32_t     magic2;
    uint32_t     magic3;
    uint32_t     salt;
    uint32_t     peper;
    c_disk_blk_t fwd_tree1;
    c_disk_blk_t fwd_tree2;
    c_disk_blk_t rev_tree1;
    c_disk_blk_t rev_tree2;
} PACKED;


#define MAX_BTREE_DEPTH       (10)

#define NODE_HEADER           0x180

#define FTREE_SLOT_LEAF_VAL   0x1
#define FTREE_SLOT_LEAF_PTR   0x2
#define FTREE_SLOT_NODE       0x3
#define FTREE_SLOT_IS_NODE(_slot)        ((_slot)->type == FTREE_SLOT_NODE)
#define FTREE_SLOT_IS_LEAF_VAL(_slot)    ((_slot)->type == FTREE_SLOT_LEAF_VAL) 
#define FTREE_SLOT_IS_LEAF_PTR(_slot)    ((_slot)->type == FTREE_SLOT_LEAF_PTR) 
#define FTREE_SLOT_IS_ANY_LEAF(_slot)   (((_slot)->type == FTREE_SLOT_LEAF_VAL) ||  \
                                         ((_slot)->type == FTREE_SLOT_LEAF_PTR))
#define FTREE_NODE_IS_LEAF(_node)        ((_node)->is_leaf)

#define INVAL_BLK          ((uint32_t)-1)
#define MAX_BLK            ((uint32_t)-2)
#define BLK_INVAL(_blk)    ((_blk) == INVAL_BLK)

struct castle_ftree_slot {
    uint8_t      type;
    uint32_t     block;
    uint32_t     version;
    c_disk_blk_t cdb;
} PACKED;

#define FTREE_NODE_SIZE   (10) /* In blocks */
#define FTREE_NODE_MAGIC  0x0000cdab
#define FTREE_NODE_SLOTS  ((FTREE_NODE_SIZE * PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_ftree_slot))
struct castle_ftree_node {
    uint32_t magic;
    uint32_t version;
    uint32_t capacity;
    uint32_t used;
    uint8_t  __pad[NODE_HEADER - 16 /* for the 4 u32s above */ - 1 /* for is_leaf */];
    /* The following bits of data are computed dynamically, and don't need to be
       saved to the disk (even though they probably will) */
    uint8_t  is_leaf;
    struct castle_ftree_slot slots[FTREE_NODE_SLOTS];
} PACKED;


struct castle_vlist_slot {
    uint32_t     version_nr;
    uint32_t     parent;
    uint32_t     size;
    c_disk_blk_t cdb;
} PACKED;

#define VLIST_NODE_MAGIC  0x0000baca
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
} PACKED;

struct castle_flist_slot {
    version_t    version;
    block_t      blocks;
} PACKED;

#define FLIST_NODE_MAGIC  0x0000faca
#define FLIST_SLOTS  ((PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_flist_slot))
struct castle_flist_node {
    uint32_t magic;
    uint32_t version; 
    uint32_t capacity;
    uint32_t used;
    c_disk_blk_t next; /* 8 bytes */
    c_disk_blk_t prev; /* 8 bytes */
    uint8_t __pad[NODE_HEADER - 32];
    struct castle_flist_slot slots[FLIST_SLOTS];
} PACKED;

/* IO related structures */
struct castle_bio_vec;
typedef struct castle_bio {
    struct castle_device  *c_dev;
    struct bio            *bio;
    struct castle_bio_vec *c_bvecs; 
    atomic_t               count;
    int                    err;
#ifdef CASTLE_DEBUG    
    int                    stuck;
    int                    id;
    int                    nr_bvecs;
    struct list_head       list;
#endif
} c_bio_t;


struct castle_cache_block;
#define CBV_ONE2ONE_BIT         (0) 
#define CBV_ROOT_LOCKED_BIT     (1) 
typedef struct castle_bio_vec {
    /* Where did this IO originate from */
    c_bio_t            *c_bio;
    /* What (block,version) do we want to read */
    sector_t            block;
    uint32_t            version;
    /* Flags */
    unsigned long       flags;
    /* Used to walk the B-Tree, and return the final cdb */
    union {
        struct {
            int                        btree_depth;
            /* Block key in the parent node under which we found
               btree_node */
            sector_t                   key_block;
            /* When writing, B-Tree node and its parent have to be 
               locked concurrently. */
            struct castle_cache_block *btree_node;
            struct castle_cache_block *btree_parent_node;
        };
        /* Location of the data on a slave disk. Set when B-Tree walk 
           is finished */
        c_disk_blk_t cdb;
    };
    /* Used to thread this bvec onto a workqueue */
    struct work_struct         work;
#ifdef CASTLE_DEBUG    
    unsigned long              state;
    struct castle_cache_block *locking;
#endif
} c_bvec_t;
#define c_bvec_data_dir(_c_bvec)    bio_data_dir((_c_bvec)->c_bio->bio)
#define c2b_bnode(_c2b)           ((struct castle_ftree_node *)c2b_buffer(_c2b))
#define c_bvec_bnode(_c_bvec)       c2b_bnode((_c_bvec)->btree_node)
#define c_bvec_bpnode(_c_bvec)      c2b_buffer((_c_bvec)->btree_parent_node)

/* Used for iterating through the tree */
typedef struct castle_iterator {
    version_t                  version;
    void                     (*node_start)(struct castle_iterator *c_iter);
    void                     (*each)      (struct castle_iterator *c_iter, int index, c_disk_blk_t cdb);
    void                     (*node_end)  (struct castle_iterator *c_iter);
    void                     (*end)       (struct castle_iterator *c_iter, int err);
    void                      *private;
                             
    block_t                    parent_vblk; /* The v_blk followed to get to the block 
                                               on the top of the path/stack */
    block_t                    next_vblk;   /* The next v_blk to look for in the interation 
                                               (typically parent_vblk + 1 when at leafs) */

    struct castle_cache_block *path[MAX_BTREE_DEPTH];
    struct {
        union {
            struct {
                struct castle_cache_block *c2b;      /* Cache page for an 'indirect' node */
            };
            struct {
                c_disk_blk_t               cdb;      /* CDB from leaf pointer  */
                uint8_t                    f_idx;    /* Index in the orig node */
            };                             
        };                                 
        struct {                 
            uint8_t                        r_idx;    /* Index in indirect_nodes array */
            uint8_t                        node_idx; /* Inder in the indirect node */ 
        };
    }                         indirect_nodes[FTREE_NODE_SLOTS];
    int                       depth;
                              
    int                       cancelled;
    int                       err;
    struct work_struct        work;
} c_iter_t;

#define BLOCKS_HASH_SIZE        (100)
struct castle_slave_block_cnt
{
    version_t version;
    block_t cnt;
    struct list_head list;
};

struct castle_slave_block_cnts 
{
    struct list_head hash[BLOCKS_HASH_SIZE];
    struct castle_slave_block_cnt metadata_cnt;  /* Count for version 0 (metadata) */
    struct castle_cache_block *last_flist_c2b;   /* Buffer for the last flist node.
                                             `      One ref, unlocked. */
    uint32_t flist_capacity;
    uint32_t flist_used;
};

/* First class structures */
struct castle {
    struct kobject kobj;
};

struct castle_slave {
    uint32_t                        id;
    uint32_t                        uuid; /* Copy of the uuid from the superblock
                                             needed here, because we cannot cache
                                             the superblock without being able to
                                             _find_by_uuid */
    int                             new_dev;
    struct kobject                  kobj;
    struct list_head                list;
    struct block_device            *bdev;
    struct castle_cache_block      *sblk;
    struct castle_cache_block      *fs_sblk;
    block_t                         free_blk;
    struct castle_slave_block_cnts  block_cnts;
    unsigned long                   last_access;
};

struct castle_slaves {
    struct kobject   kobj;
    struct list_head slaves;
};

struct castle_device {
    struct kobject      kobj;
    struct rw_semaphore lock;
    struct list_head    list;
    struct gendisk     *gd;
    int                 users;
    int                 sysfs_registered;
                       
    version_t           version;
};

struct castle_devices { 
    struct kobject kobj;
    int major;
    struct list_head devices;
};

struct castle_region {
	region_id_t          id;
	struct kobject       kobj;
	struct list_head     list;
	
	struct castle_slave *slave;
	version_t            version;
	int                  start;
	int                  length;
};

struct castle_regions {
    struct kobject   kobj;
    struct list_head regions;
};

struct castle_transfer {
    transfer_id_t           id;
    version_t               version;
    int                     direction;
    atomic_t                progress;
    int                     finished;
    int                     error;

    struct castle_region  **regions;
    int                     regions_count;
    
    struct kobject          kobj;
    struct list_head        list;
    
    c_iter_t                c_iter;
    atomic_t                phase;
    struct completion       completion;
};

struct castle_transfers {
    struct kobject   kobj;
    struct list_head transfers;
};

extern struct castle             castle;
extern struct castle_slaves      castle_slaves;
extern struct castle_devices     castle_devices;
extern struct castle_regions     castle_regions;
extern struct castle_transfers   castle_transfers;

extern struct workqueue_struct *castle_wqs[2*MAX_BTREE_DEPTH+1];
#define castle_wq              (castle_wqs[0])

/* Various utilities */
#define C_BLK_SHIFT                    (12) 
#define C_BLK_SIZE                     (1 << C_BLK_SHIFT)
#define disk_blk_to_offset(_cdb)     ((_cdb).block * C_BLK_SIZE)

void                  castle_bio_data_io_end   (c_bvec_t *c_bvec, int err);
void                  castle_bio_data_io       (c_bvec_t *c_bvec);

struct castle_device* castle_device_init       (version_t version);
void                  castle_device_free       (struct castle_device *cd);
struct castle_device* castle_device_find       (dev_t dev);

struct castle_slave*  castle_claim             (uint32_t new_dev);
void                  castle_release           (struct castle_slave *cs);

struct castle_region* castle_region_find       (region_id_t id);
struct castle_region* castle_region_create     (uint32_t slave_id, version_t version, uint32_t start, uint32_t length);
int                   castle_region_destroy    (struct castle_region *region);

void                  castle_slave_access      (uint32_t uuid);

struct castle_slave*  castle_slave_find_by_id  (uint32_t id);
struct castle_slave*  castle_slave_find_by_uuid(uint32_t uuid);
struct castle_slave*  castle_slave_find_by_block(c_disk_blk_t cdb);

struct castle_slave_superblock* 
                      castle_slave_superblock_get(struct castle_slave *cs);
void                  castle_slave_superblock_put(struct castle_slave *cs, int dirty);
struct castle_fs_superblock* 
                      castle_fs_superblocks_get(void);
void                  castle_fs_superblocks_put(struct castle_fs_superblock *sb, int dirty);

int                   castle_fs_init           (void);


#endif /* __CASTLE_H__ */
