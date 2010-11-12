/* TODO: when castle disk mounted, and then castle-fs-test run, later bd_claims on
         disk devices fail (multiple castle_fs_cli 'claim' cause problems?) */
#include <linux/bio.h>
#include <linux/kobject.h>
#include <linux/blkdev.h>
#include <linux/random.h>
#include <linux/crc32.h>
#include <linux/skbuff.h>
#include <linux/hardirq.h>
#include <linux/buffer_head.h>

#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_utils.h"
#include "castle_da.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_versions.h"
#include "castle_ctrl.h"
#include "castle_sysfs.h"
#include "castle_time.h"
#include "castle_debug.h"
#include "castle_events.h"
#include "castle_back.h"
#include "castle_extent.h"
#include "castle_freespace.h"

struct castle                castle;
struct castle_slaves         castle_slaves;
struct castle_attachments    castle_attachments;
struct castle_component_tree castle_global_tree = {.seq             = GLOBAL_TREE,
                                                   .ref_count       = {1},
                                                   .write_ref_count = {1},
                                                   .item_count      = {0ULL},
                                                   .btree_type      = MTREE_TYPE, 
                                                   .dynamic         = 1,
                                                   .da              = INVAL_DA,
                                                   .level           = -1, 
                                                   .tree_depth      = -1,
                                                   .root_node       = INVAL_EXT_POS,
                                                   .first_node      = INVAL_EXT_POS,
                                                   .last_node       = INVAL_EXT_POS,
                                                   .node_count      = {0ULL},
                                                   .da_list         = {NULL, NULL},
                                                   .hash_list       = {NULL, NULL},
                                                   .mstore_key      = INVAL_MSTORE_KEY,
                                                   .tree_ext_fs     = {INVAL_EXT_ID, (1024 * C_CHK_SIZE), 0, {0ULL}, {0ULL}},
                                                   .data_ext_fs     = {INVAL_EXT_ID, (20480ULL * C_CHK_SIZE), 0, {0ULL}, {0ULL}},
                                                  }; 
struct workqueue_struct     *castle_wqs[2*MAX_BTREE_DEPTH+1];
int                          castle_fs_inited = 0;

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif


static void USED castle_fs_superblock_print(struct castle_fs_superblock *fs_sb)
{
    printk("Magic1: %.8x\n"
           "Magic2: %.8x\n"
           "Magic3: %.8x\n"
           "UUID: %x\n"
           "Version: %d\n"
           "Salt:   %x\n"
           "Pepper: %x\n",
           fs_sb->pub.magic1,
           fs_sb->pub.magic2,
           fs_sb->pub.magic3,
           fs_sb->pub.uuid,
           fs_sb->pub.version,
           fs_sb->pub.salt,
           fs_sb->pub.peper);
}

static int castle_fs_superblock_validate(struct castle_fs_superblock *fs_sb)
{
    if(fs_sb->pub.magic1 != CASTLE_FS_MAGIC1) return -1;
    if(fs_sb->pub.magic2 != CASTLE_FS_MAGIC2) return -2;
    if(fs_sb->pub.magic3 != CASTLE_FS_MAGIC3) return -3;
    if(fs_sb->pub.version != CASTLE_FS_VERSION) return -4;

    return 0;
}

static void castle_fs_superblock_init(struct castle_fs_superblock *fs_sb)
{   
    int i;
    struct list_head *lh;
    struct castle_slave *cs;

    fs_sb->pub.magic1 = CASTLE_FS_MAGIC1;
    fs_sb->pub.magic2 = CASTLE_FS_MAGIC2;
    fs_sb->pub.magic3 = CASTLE_FS_MAGIC3;
    do {
        get_random_bytes(&fs_sb->pub.uuid,  sizeof(fs_sb->pub.uuid));
    } while (fs_sb->pub.uuid == 0);
    fs_sb->pub.version = CASTLE_FS_VERSION;
    get_random_bytes(&fs_sb->pub.salt,  sizeof(fs_sb->pub.salt));
    get_random_bytes(&fs_sb->pub.peper, sizeof(fs_sb->pub.peper));
    for(i=0; i<sizeof(fs_sb->mstore) / sizeof(c_ext_pos_t ); i++)
        fs_sb->mstore[i] = INVAL_EXT_POS;

    i = 0;
    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        fs_sb->slaves[i++] = cs->uuid;
    }
    fs_sb->nr_slaves = i;
}

static void castle_fs_superblocks_init(void)
{
    struct castle_fs_superblock *fs_sb;

    fs_sb = castle_fs_superblocks_get();
    castle_fs_superblock_init(fs_sb);
    castle_fs_superblocks_put(fs_sb, 1);
}

static inline struct castle_fs_superblock* castle_fs_superblock_get(struct castle_slave *cs)
{
    write_lock_c2b(cs->fs_sblk);
    BUG_ON(!c2b_uptodate(cs->fs_sblk));

    return ((struct castle_fs_superblock*) c2b_buffer(cs->fs_sblk));
}

static inline void castle_fs_superblock_put(struct castle_slave *cs, int dirty)
{
    if(dirty) dirty_c2b(cs->fs_sblk);
    write_unlock_c2b(cs->fs_sblk);
}

/* Get all superblocks */
struct castle_fs_superblock* castle_fs_superblocks_get(void)
{
    struct list_head *l;
    struct castle_slave *cs;
    struct castle_fs_superblock *sb = NULL;

    list_for_each(l, &castle_slaves.slaves)
    {
        cs = list_entry(l, struct castle_slave, list);
        sb = castle_fs_superblock_get(cs);
    }

    return sb;
}

/* Put all superblocks */
void castle_fs_superblocks_put(struct castle_fs_superblock *sb, int dirty)
{
    struct list_head *l;
    struct castle_slave *cs;
    struct castle_fs_superblock *curr_sb;

    list_for_each(l, &castle_slaves.slaves)
    {
        cs = list_entry(l, struct castle_slave, list);
        /* The buffer should be locked */
        BUG_ON(!c2b_write_locked(cs->fs_sblk));
        /* If superblock has been dirtied, copy it, and dirty the buffer */
        if(dirty)
        {
            curr_sb = c2b_buffer(cs->fs_sblk);
            /* Note, we can be possibly copying from ourselves, memmove is safer */
            memmove(curr_sb, sb, sizeof(struct castle_fs_superblock)); 
            dirty_c2b(cs->fs_sblk);
        }
        /* Finally, unlock the buffer */
        write_unlock_c2b(cs->fs_sblk);
    }
}

int castle_ext_fs_init(c_ext_fs_t       *ext_fs, 
                       da_id_t           da_id, 
                       c_byte_off_t      size,
                       uint32_t          align)
{
    uint32_t nr_chunks = ((size  - 1) / C_CHK_SIZE) + 1;

    ext_fs->ext_id      = castle_extent_alloc(DEFAULT, da_id, nr_chunks);
    ext_fs->ext_size    = size;
    ext_fs->align       = align;
    atomic64_set(&ext_fs->used, 0);
    atomic64_set(&ext_fs->blocked, 0);

    if (EXT_ID_INVAL(ext_fs->ext_id))
        return -ENOSPC;
    return 0;
}

void castle_ext_fs_fini(c_ext_fs_t      *ext_fs)
{
    castle_extent_free(ext_fs->ext_id);
    ext_fs->ext_id      = INVAL_EXT_ID;
    ext_fs->ext_size    = 0;
    ext_fs->align       = 0;
    atomic64_set(&ext_fs->used, 0);
    atomic64_set(&ext_fs->blocked, 0);
}

int castle_ext_fs_pre_alloc(c_ext_fs_t       *ext_fs,
                            c_byte_off_t      size)
{
    uint64_t ret;
    uint64_t used;
    uint64_t blocked;

    used = atomic64_read(&ext_fs->used);
    barrier();
    blocked = atomic64_read(&ext_fs->blocked);

    BUG_ON(used % ext_fs->align);
    BUG_ON(blocked % ext_fs->align);
    BUG_ON(blocked < used);
    BUG_ON(used > ext_fs->ext_size);

    ret = atomic64_add_return(size, &ext_fs->blocked);
    barrier();
    if (ret > ext_fs->ext_size)
    {
        atomic64_sub(size, &ext_fs->blocked);
        barrier();
        return -1;
    }

    return 0;
}

int castle_ext_fs_free(c_ext_fs_t       *ext_fs,
                       int64_t           size)
{
    BUG_ON(atomic64_read(&ext_fs->used) % ext_fs->align);
    BUG_ON(atomic64_read(&ext_fs->blocked) % ext_fs->align);

    atomic64_sub(size, &ext_fs->blocked);
    barrier();

    return 0;
}

int castle_ext_fs_get(c_ext_fs_t      *ext_fs,
                      c_byte_off_t     size,
                      int              alloc_done,
                      c_ext_pos_t     *cep)
{
    uint64_t used;
    uint64_t blocked;

    used = atomic64_read(&ext_fs->used);
    barrier();
    blocked = atomic64_read(&ext_fs->blocked);

    BUG_ON(used % ext_fs->align);
    BUG_ON(blocked % ext_fs->align);
    BUG_ON(blocked < used);
    BUG_ON(used > ext_fs->ext_size);

    if (!alloc_done)
    {
        int ret;

        ret = castle_ext_fs_pre_alloc(ext_fs, size);
        if (ret < 0)
            return ret;
    }
    
    cep->ext_id = ext_fs->ext_id;
    cep->offset = atomic64_add_return(size, &ext_fs->used) - size;
    barrier();
    BUG_ON(EXT_ID_INVAL(cep->ext_id));
    
    used = atomic64_read(&ext_fs->used);
    barrier();
    blocked = atomic64_read(&ext_fs->blocked);

    if (blocked < used)
    {
        atomic64_sub(size, &ext_fs->used);
        barrier();
        return -2;
    }

    return 0;
}

void castle_ext_fs_marshall(c_ext_fs_t *ext_fs, c_ext_fs_bs_t *ext_fs_bs)
{
    ext_fs_bs->ext_id    = ext_fs->ext_id;
    ext_fs_bs->ext_size  = ext_fs->ext_size;
    ext_fs_bs->align     = ext_fs->align;
    ext_fs_bs->used      = atomic64_read(&ext_fs->used);
    ext_fs_bs->blocked   = atomic64_read(&ext_fs->blocked);
}

void castle_ext_fs_unmarshall(c_ext_fs_t *ext_fs, c_ext_fs_bs_t *ext_fs_bs)
{
    ext_fs->ext_id       = ext_fs_bs->ext_id;
    ext_fs->ext_size     = ext_fs_bs->ext_size;
    ext_fs->align        = ext_fs_bs->align;
    atomic64_set(&ext_fs->used, ext_fs_bs->used);
    atomic64_set(&ext_fs->blocked, ext_fs_bs->blocked);
}

c_byte_off_t castle_ext_fs_summary_get(c_ext_fs_t *ext_fs)
{
    return (ext_fs->ext_size - atomic64_read(&ext_fs->used));
}

int castle_fs_init(void)
{
    struct list_head *lh;
    struct castle_slave *cs;
    struct castle_fs_superblock fs_sb, *cs_fs_sb;
    int ret, first, prev_new_dev = -1;
    uint32_t i, nr_fs_slaves = 0, slave_count = 0;

    if(castle_fs_inited)
        return -EEXIST;

    if(list_empty(&castle_slaves.slaves))
        return -ENOENT;

    first = 1;
    /* Make sure that superblocks of the all non-new devices are
       the same, save the results */
    list_for_each(lh, &castle_slaves.slaves)
    {
        cs = list_entry(lh, struct castle_slave, list);
        slave_count++;

        /* Either all disks should be new or none. */
        if (prev_new_dev < 0)
            prev_new_dev = cs->new_dev;
        if (cs->new_dev != prev_new_dev)
        {
            printk("Few disks are marked new and few are not\n");
            return -EINVAL;
        }

        if(cs->new_dev)
            continue;

        cs_fs_sb = castle_fs_superblock_get(cs);
        BUG_ON(!c2b_uptodate(cs->fs_sblk));

        /* Save fs superblock if the first slave. */
        if(first)
        {
            memcpy(&fs_sb, cs_fs_sb, sizeof(struct castle_fs_superblock));
            first = 0;
        }
        else
        /* Check if fs superblock the same as the one we already know about */
        {
            if(memcmp(&fs_sb, cs_fs_sb, 
                      sizeof(struct castle_fs_superblock)) != 0)
            {
                printk("Castle fs supreblocks do not match!\n");
                castle_fs_superblock_put(cs, 0);
                return -EINVAL;
            }
        }

        /* Check whether the slave is already in FS slaves list. */
        for (i=0; i<fs_sb.nr_slaves; i++)
        {
            if (fs_sb.slaves[i] == cs->uuid)
            {
                nr_fs_slaves++;
                break;
            }
        }

        if (i == fs_sb.nr_slaves)
        {
            printk("Slave %u doesn't belong to this File system.\n", cs->uuid);
            return -EINVAL;
        }
        castle_fs_superblock_put(cs, 0);
    }

    if (slave_count < 2)
    {
        printk("Need minimum two disks.\n");
        return -EINVAL;
    }

    if (!first && (nr_fs_slaves != fs_sb.nr_slaves))
    {
        printk("Couldn't find all slaves of the filesystem.\n");
        return -EINVAL;
    }

    /* Load extent structures into memory */
    if ((ret = castle_extents_load(first)))
        return ret;

    /* Init the fs superblock */
    if (first) castle_fs_superblocks_init();

    /* Read mstore meta data in. */
    ret = first ? castle_mstores_create() : castle_mstores_read(); 
    if(ret) return -EINVAL;

    /* If first is still true, we've not found a single non-new cs.
       Init the fs superblock. */
    if(first) {
        c2_block_t *c2b;
        struct castle_btree_type *btree =
                                castle_btree_type_get(castle_global_tree.btree_type);

        /* Init the root btree node */
        atomic64_set(&(castle_global_tree.node_count), 0);
        init_rwsem(&castle_global_tree.lock);

        if ((ret = castle_ext_fs_init(&castle_global_tree.tree_ext_fs,
                                      castle_global_tree.da,
                                      castle_global_tree.tree_ext_fs.ext_size,
                                      btree->node_size * C_BLK_SIZE)) < 0)
        {
            printk("Failed to allocate space for Global Tree.\n");
            return ret;
        }
            
        if ((ret = castle_ext_fs_init(&castle_global_tree.data_ext_fs,
                                      castle_global_tree.da,
                                      castle_global_tree.data_ext_fs.ext_size,
                                      C_BLK_SIZE)) < 0)
        {
            printk("Failed to allocate space for Global Tree Medium Objects.\n");
            return ret;
        }

        c2b = castle_btree_node_create(0 /* version */, 1 /* is_leaf */, &castle_global_tree, 0);
        castle_btree_node_save_prepare(&castle_global_tree, c2b->cep);
        /* Save the root node in the global tree */
        castle_global_tree.root_node = c2b->cep; 
        /* We know that the tree is 1 level deep at the moment */
        castle_global_tree.tree_depth = 1;
        /* Release btree node c2b */
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        /* Init version list */
        ret = castle_versions_zero_init();
        if(ret) return ret;
        /* Make sure that fs_sb is up-to-date */
        cs_fs_sb = castle_fs_superblocks_get();
        memcpy(&fs_sb, cs_fs_sb, sizeof(struct castle_fs_superblock));
        castle_fs_superblocks_put(cs_fs_sb, 0);
    }
    cs_fs_sb = castle_fs_superblocks_get();
    BUG_ON(!cs_fs_sb);
    /* This will initialise the fs superblock of all the new devices */
    memcpy(cs_fs_sb, &fs_sb, sizeof(struct castle_fs_superblock));
    castle_fs_superblocks_put(cs_fs_sb, 1);

    /* Read doubling arrays and component trees in. */
    ret = first ? castle_double_array_create() : castle_double_array_read(); 
    if(ret) return -EINVAL;

    /* Read versions in. This requires component trees. */
    ret = castle_versions_read();
    if(ret) return -EINVAL;

    /* Init mstore for Collection Attachments. */
    ret = castle_attachments_store_init(first);
    if (ret) return -EINVAL;

    castle_events_init();
    
    printk("Castle FS inited.\n");
    castle_fs_inited = 1;

    return 0;
}

static void castle_slave_superblock_print(struct castle_slave_superblock *cs_sb)
{
    printk("Magic1: %.8x\n"
           "Magic2: %.8x\n"
           "Magic3: %.8x\n"
           "Version:%x\n"
           "Uuid:   %x\n"
           "Used:   %x\n"
           "Size:   %x\n",
           cs_sb->magic1,
           cs_sb->magic2,
           cs_sb->magic3,
           cs_sb->version,
           cs_sb->uuid,
           cs_sb->used,
           cs_sb->size);
}

static int castle_slave_superblock_validate(struct castle_slave_superblock *cs_sb)
{
    if(cs_sb->magic1 != CASTLE_SLAVE_MAGIC1) return -1;
    if(cs_sb->magic2 != CASTLE_SLAVE_MAGIC2) return -2;
    if(cs_sb->magic3 != CASTLE_SLAVE_MAGIC3) return -3;
    if(cs_sb->version != CASTLE_SLAVE_VERSION) return -4;

    return 0;
}

static int castle_block_read(struct block_device *bdev, sector_t sector, 
                                                        uint32_t size, char *buffer)
{
    int block_size;
    struct buffer_head *bh;
    sector_t block;
    
    if (!bdev)
        return -1;

    block_size = bdev->bd_block_size;
    block = sector / (block_size / 512);

    if (size > block_size)
    {
        printk("Block size: %u too small. Not supported\n", block_size);
        return -1;
    }

    debug("Reading %u bytes from block %llu.\n", block_size, block);
    if (!(bh = __bread(bdev, block, block_size)))
        return -1;

    memcpy(buffer, bh->b_data, size);

    bforget(bh);

    return 0;

}

static int castle_slave_superblock_read(struct castle_slave *cs) 
{
    struct castle_slave_superblock cs_sb;
    struct castle_fs_superblock fs_sb;
    int err = -EINVAL;

    if ((err = castle_block_read(cs->bdev, 0, sizeof(cs_sb), (char *)&cs_sb)) < 0)
        goto error_out;

    if ((err = castle_slave_superblock_validate(&cs_sb)) < 0)
    {
        printk("%d\n", err);
        goto error_out;
    }

    if ((err = castle_block_read(cs->bdev, 8, sizeof(fs_sb), (char *)&fs_sb)) < 0)
        goto error_out;

    if (((err = castle_fs_superblock_validate(&fs_sb)) < 0) && 
                        !(cs_sb.flags & CASTLE_SLAVE_NEWDEV))
    {
        printk("%d\n", err);
        goto error_out;
    }

    printk("Disk superblock found.\n");

    /* Save the uuid and exit */
    cs->uuid = cs_sb.uuid;
    cs->new_dev = cs_sb.flags & CASTLE_SLAVE_NEWDEV;
    return 0;

error_out:
    return err;
}

struct castle_slave_superblock* castle_slave_superblock_get(struct castle_slave *cs)
{
    write_lock_c2b(cs->sblk);
    BUG_ON(!c2b_uptodate(cs->sblk));
    
    return ((struct castle_slave_superblock*) c2b_buffer(cs->sblk));
}

void castle_slave_superblock_put(struct castle_slave *cs, int dirty)
{
    if(dirty) dirty_c2b(cs->sblk);
    write_unlock_c2b(cs->sblk);
}

static int castle_slave_superblocks_cache(struct castle_slave *cs)
/* NOTE: This function leaves superblocks locked. This prevents init races */
{
    c2_block_t *c2b, **c2bp[2];
    c_ext_pos_t  cep;
    block_t i, j;

    /* We want to read the first two 4K blocks of the slave device
       Frist is the slave superblock, the second is the fs superblock */
    c2bp[0] = &cs->sblk;
    c2bp[1] = &cs->fs_sblk;

    for(i=0; i<2; i++)
    {
        /* Read the superblock */
        cep.ext_id = cs->sup_ext;
        cep.offset = i * C_BLK_SIZE;
        c2b = castle_cache_page_block_get(cep);
        *(c2bp[i]) = c2b;
        /* We expecting the buffer not to be up to date. 
           We check if it got updated later */
        BUG_ON(c2b_uptodate(c2b));
        write_lock_c2b(c2b);
        submit_c2b_sync(READ, c2b);
        if(!c2b_uptodate(c2b))
        {
            for(j=0; j<=i; i++)
                write_unlock_c2b(*(c2bp[i]));
            printk("Disk super block already exists in disk\n");
            return -EIO;
        }
    }

    return 0;
}

sector_t get_bd_capacity(struct block_device *bd)
{
    return bd->bd_contains == bd ? get_capacity(bd->bd_disk) : bd->bd_part->nr_sects;
}

static int castle_slave_superblocks_init(struct castle_slave *cs)
{
    struct castle_slave_superblock *cs_sb;
    struct castle_fs_superblock *fs_sb;
    int ret = castle_slave_superblocks_cache(cs);

    if(ret) return ret;

    /* If both superblock have been read correctly. Validate or write. 
       *_superblock_get() functions are not used, because superblocks are
       already locked for us by superblocks_cache function. */
    BUG_ON(!c2b_uptodate(cs->sblk));
    cs_sb = ((struct castle_slave_superblock*) c2b_buffer(cs->sblk)); 
    BUG_ON(!c2b_uptodate(cs->fs_sblk));
    fs_sb = ((struct castle_fs_superblock*) c2b_buffer(cs->fs_sblk));

    debug("In superblocks_init: in_atomic()=%d\n", in_atomic());
    if(!cs->new_dev)
    {
        ret = castle_slave_superblock_validate(cs_sb);
        if (ret)
        {
            printk("Invalid Slave Superblock\n");
            BUG();
        }
        else 
        {
            ret = castle_fs_superblock_validate(fs_sb);
            if (ret)
            {
                printk("Invalid FS Superblock\n");
                BUG();
            }
        }
    } else
    {
        printk("Initing slave superblock.\n");
        cs_sb->magic1 = CASTLE_SLAVE_MAGIC1;
        cs_sb->magic2 = CASTLE_SLAVE_MAGIC2;
        cs_sb->magic3 = CASTLE_SLAVE_MAGIC3;
        cs_sb->version= CASTLE_SLAVE_VERSION;
        cs_sb->used   = 2; /* Two blocks used for the superblocks */
        cs_sb->uuid   = cs->uuid;
        cs_sb->size   = get_bd_capacity(cs->bdev) >> (C_BLK_SHIFT - 9);
        cs_sb->flags  = CASTLE_SLAVE_TARGET | CASTLE_SLAVE_SPINNING;
        castle_slave_superblock_print(cs_sb);
        printk("Done.\n");
    }
    debug("Before slave init: in_atomic()=%d\n", in_atomic());
    castle_freespace_slave_init(cs, cs->new_dev);

    castle_slave_superblock_put(cs, cs->new_dev);
    castle_fs_superblock_put(cs, 0);
    return ret;
}

struct castle_slave* castle_slave_find_by_id(uint32_t id)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        if(slave->id == id)
            return slave;
    }

    return NULL;
}

struct castle_slave* castle_slave_find_by_uuid(uint32_t uuid)
{
    struct list_head *lh;
    struct castle_slave *slave;

    list_for_each(lh, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list);
        if(slave->uuid == uuid)
            return slave;
    }

    return NULL;
}

struct castle_slave* castle_slave_find_by_block(c_ext_pos_t  cep)
{
    return castle_slave_find_by_uuid(cep.ext_id);
}

static int castle_slave_add(struct castle_slave *cs)
{
    struct list_head *l;
    struct castle_slave *s;

    list_for_each(l, &castle_slaves.slaves)
    {
        s = list_entry(l, struct castle_slave, list);
        if(s->uuid == cs->uuid)
        {
            printk("Uuid of two slaves match (uuid=0x%x, id1=%d, id2=%d)\n", 
                    cs->uuid, s->id, cs->id);
            return -EINVAL;
        }
    }
    /* If no UUID collision, add to the list */
    list_add(&cs->list, &castle_slaves.slaves);
    return 0;
}

struct castle_slave* castle_claim(uint32_t new_dev)
{
    dev_t dev;
    struct block_device *bdev = NULL;
    int bdev_claimed = 0, cs_added = 0;
    int err;
    char b[BDEVNAME_SIZE];
    struct castle_slave *cs = NULL;
    static int slave_id = 0;
    static int nr_slaves = 0;

    debug("Claiming: in_atomic=%d.\n", in_atomic());
    if(!(cs = castle_zalloc(sizeof(struct castle_slave), GFP_KERNEL)))
        goto err_out;
    cs->id          = slave_id++;
    cs->last_access = jiffies;
    cs->sup_ext     = INVAL_EXT_ID;

    dev = new_decode_dev(new_dev);
    bdev = open_by_devnum(dev, FMODE_READ|FMODE_WRITE);
    if (IS_ERR(bdev)) 
    {
        printk("Could not open %s.\n", __bdevname(dev, b));
        bdev = NULL;
        goto err_out;
    }
    cs->bdev = bdev;

    if(castle_slave_superblock_read(cs))
	{
        printk("Invalid superblock.\n");
        goto err_out;
	}

    err = bd_claim(bdev, &castle);
    if (err) 
    {
        printk("Could not bd_claim %s, err=%d.\n", bdevname(bdev, b), err);
        goto err_out;
    }
    bdev_claimed = 1;

    cs->sup_ext = castle_extent_sup_ext_init(cs);
    if (cs->sup_ext == INVAL_EXT_ID)
    {
        printk("Could not initialize super extent for slave 0x%x\n", cs->uuid);
        goto err_out;
    }

    err = castle_rda_slave_add(DEFAULT, cs);
    if (err)
    {
        printk("Could not add slave to DEFAULT RDA.\n");
        goto err_out;
    }
    err = castle_slave_add(cs);
    if(err)
    {
        printk("Could not add slave to the list.\n");
        goto err_out;
    }
    cs_added = 1;
    nr_slaves++;
    
    err = castle_sysfs_slave_add(cs);
    if(err)
    {
        printk("Could not add slave to sysfs.\n");
        goto err_out;
    }
    
    castle_events_slave_claim(cs->uuid);

    debug("Initing superblocks: in_atomic=%d.\n", in_atomic());
    err = castle_slave_superblocks_init(cs);
    if(err)
    {
        printk("Could not cache the superblocks.\n");
        goto err_out;
    }

    return cs;
err_out:
    if (!EXT_ID_INVAL(cs->sup_ext))
        castle_extent_sup_ext_close(cs);
    castle_rda_slave_remove(DEFAULT, cs);
    if(cs_added)     list_del(&cs->list);
    if(cs->sblk)     put_c2b(cs->sblk);
    if(cs->fs_sblk)  put_c2b(cs->fs_sblk);
    if(bdev_claimed) bd_release(bdev);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    if(bdev) blkdev_put(bdev);
#else
    if(bdev) blkdev_put(bdev, FMODE_READ|FMODE_WRITE);
#endif
    if(cs)           castle_free(cs);
    return NULL;    
}

void castle_release(struct castle_slave *cs)
{
    castle_rda_slave_remove(DEFAULT, cs);
    castle_events_slave_release(cs->uuid);
    castle_sysfs_slave_del(cs);
    bd_release(cs->bdev);
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
    blkdev_put(cs->bdev);
#else
    blkdev_put(cs->bdev, FMODE_READ|FMODE_WRITE);
#endif
    list_del(&cs->list);
    castle_free(cs);
}

static int castle_open(struct castle_attachment *dev)
{
    spin_lock(&castle_attachments.lock);
    dev->ref_cnt++;
    spin_unlock(&castle_attachments.lock);

	return 0;
}

static int castle_close(struct castle_attachment *dev)
{
    spin_lock(&castle_attachments.lock);
    dev->ref_cnt++;
    spin_unlock(&castle_attachments.lock);

    // TODO should call put, potentially free it?

	return 0;
}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
static int castle_old_open(struct inode *inode, struct file *filp)
{
    return castle_open(inode->i_bdev->bd_disk->private_data);
}

static int castle_old_close(struct inode *inode, struct file *filp)
{
    return castle_close(inode->i_bdev->bd_disk->private_data);
}

static struct block_device_operations castle_bd_ops = {
	.owner           = THIS_MODULE,
	.open 	         = castle_old_open,
	.release 	     = castle_old_close,
	.media_changed   = NULL,
	.revalidate_disk = NULL,
};
#else
static int castle_new_open(struct block_device *bdev, fmode_t mode)
{
    return castle_open(bdev->bd_disk->private_data);
}

static int castle_new_close(struct gendisk *gendisk, fmode_t mode)
{
    return castle_close(gendisk->private_data);
}

static struct block_device_operations castle_bd_ops = {
	.owner           = THIS_MODULE,
	.open 	         = castle_new_open,
	.release 	     = castle_new_close,
	.media_changed   = NULL,
	.revalidate_disk = NULL,
};
#endif

void castle_bio_get(c_bio_t *c_bio)
{
    /* This should never called in race with the last _put */
    BUG_ON(atomic_read(&c_bio->count) == 0);
    atomic_inc(&c_bio->count);
}

/* Do not declare this as static because castle_debug calls this directly. 
   But this is the only external reference */
void castle_bio_put(c_bio_t *c_bio)
{
    struct bio *bio = c_bio->bio;
    int finished, err = c_bio->err;

    finished = atomic_dec_and_test(&c_bio->count);
    if(!finished)
        return;

    castle_debug_bio_deregister(c_bio);

    castle_utils_bio_free(c_bio);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    bio_endio(bio, bio->bi_size, err);
#else
    bio_endio(bio, err);
#endif
}
   

static void castle_bio_data_copy(c_bvec_t *c_bvec, c2_block_t *c2b)
{
    int write = (c_bvec_data_dir(c_bvec) == WRITE);
    struct bio *bio = c_bvec->c_bio->bio;
    sector_t sector = bio->bi_sector;
    struct bio_vec *bvec;
    char *bvec_buf, *buf;
    int i;

    /* Find bvec(s) to IO to/from */
    bio_for_each_segment(bvec, bio, i)
    {
        sector_t bv_first_sec   = sector;
        sector_t bv_last_sec    = sector + (bvec->bv_len >> 9);
        sector_t cbv_first_sec  =  MTREE_BVEC_BLOCK(c_bvec)      << (C_BLK_SHIFT - 9);
        sector_t cbv_last_sec   = (MTREE_BVEC_BLOCK(c_bvec) + 1) << (C_BLK_SHIFT - 9);
        sector_t first_sec, last_sec;

        /* Exit if we've already gone too far */
        if(cbv_last_sec < sector)
            break;

        /* Ignore bvecs which touch different sectors than those in c_bvec */
        if((cbv_first_sec >= bv_last_sec) ||
           (cbv_last_sec  <= bv_first_sec))
        {
            sector += (bvec->bv_len >> 9);
            continue;
        }

        /* Work out which sectors to copy */
        first_sec = (bv_first_sec < cbv_first_sec ? cbv_first_sec : bv_first_sec);
        last_sec  = (bv_last_sec  < cbv_last_sec  ? bv_last_sec   : cbv_last_sec);
        
#ifdef CASTLE_DEBUG        
        /* Some sanity checks */
        BUG_ON(last_sec <= first_sec);
        BUG_ON(last_sec > bv_last_sec);
        BUG_ON(last_sec > cbv_last_sec);
        BUG_ON(first_sec < bv_first_sec);
        BUG_ON(first_sec < cbv_first_sec);
#endif        
        
        bvec_buf  = pfn_to_kaddr(page_to_pfn(bvec->bv_page));
        bvec_buf += bvec->bv_offset + ((first_sec - sector) << 9);
        /* If invalid block, we are handling non-allocated block read */
        if(c2b)
        {
            /* TODO use better macros than page_to_pfn etc */
            buf  = c2b_buffer(c2b); 
            buf += (first_sec - cbv_first_sec) << 9;

            memcpy( write ? buf : bvec_buf,
                    write ? bvec_buf : buf,
                   (last_sec - first_sec) << 9);
        } else
            memset(bvec_buf, 0, (last_sec - first_sec) << 9);

        sector += (bvec->bv_len >> 9);
    }

    /* Dirty buffers on writes */
    if(write) 
    {
        BUG_ON(!c2b);
        dirty_c2b(c2b);
    }

    /* Unlock buffers */
    if(c2b)
    {
        write_unlock_c2b(c2b);
        put_c2b(c2b);
    }
    
    castle_bio_put(c_bvec->c_bio);
}

static void castle_bio_data_io_error(c_bvec_t *c_bvec, int err)
{
    BUG_ON(!err);

    castle_debug_bvec_update(c_bvec, C_BVEC_IO_END_ERR);
    c_bvec->c_bio->err = err;
    castle_bio_put(c_bvec->c_bio);
}

static void castle_bio_c2b_update(c2_block_t *c2b)
{
    /* TODO: comment when it gets called */
    c_bvec_t *c_bvec = c2b->private;

    if(c2b_uptodate(c2b))
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2B_UPTODATE);
        castle_bio_data_copy(c_bvec, c2b);
    } else
    {
        /* Just drop the lock, if we failed to update */
        write_unlock_c2b(c2b);
        put_c2b(c2b);
        castle_bio_data_io_error(c_bvec, -EIO);
    }
}

static void castle_bio_data_io_do(c_bvec_t *c_bvec, c_ext_pos_t cep)
{
    c2_block_t *c2b;
    int write = (c_bvec_data_dir(c_bvec) == WRITE);

    /* 
     * Invalid pointer to on slave data means that it's never been written before.
     * Memset BIO buffer page to zero.
     * This should not happen on writes, since btree handling code should have 
     * allocated a new block (TODO: what if we've just run out of capacity ...)
     */
    if(EXT_POS_INVAL(cep))
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_IO_NO_BLK);
        BUG_ON(write);
        castle_bio_data_copy(c_bvec, NULL);
        return;
    }

    c2b = castle_cache_page_block_get(cep);
    castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2B_GOT);
#ifdef CASTLE_DEBUG
    c_bvec->locking = c2b;
#endif
    write_lock_c2b(c2b);
    castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2B_LOCKED);

    /* We don't need to update the c2b if it's already uptodate
       or if we are doing entire page write, in which case we'll
       overwrite previous content anyway */
    if(c2b_uptodate(c2b) || (write && test_bit(CBV_ONE2ONE_BIT, &c_bvec->flags)))
    {
        update_c2b(c2b);
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2B_UPTODATE);
        castle_bio_data_copy(c_bvec, c2b);
    } else
    {
        castle_debug_bvec_update(c_bvec, C_BVEC_DATA_C2B_OUTOFDATE);
        c2b->private = c_bvec;
        c2b->end_io = castle_bio_c2b_update;
        submit_c2b(READ, c2b);
    }
}

static int castle_bio_data_cvt_get(c_bvec_t    *c_bvec,
                                   c_val_tup_t  prev_cvt,
                                   c_val_tup_t *cvt)
{
    c_ext_pos_t cep;
    int ret;

    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 

    /* If the block has already been allocated, override it */
    if (!CVT_INVALID(prev_cvt))
    {
        BUG_ON(!CVT_ONE_BLK(prev_cvt));
        *cvt = prev_cvt;
        return 0;
    }

    /* Otherwise, allocate a new out-of-line block */
    ret = castle_ext_fs_get(&c_bvec->tree->data_ext_fs, 
                             C_BLK_SIZE,
                             0, &cep);
    if (ret < 0)
    {
        printk("Pre-alloc: %lu, Alloc: %lu\n",
               atomic64_read(&c_bvec->tree->data_ext_fs.blocked)/4096,
               atomic64_read(&c_bvec->tree->data_ext_fs.used)/4096);
        BUG();
    }
    CVT_MEDIUM_OBJECT_SET(*cvt, C_BLK_SIZE, cep);

    return 0;
}

static void castle_bio_data_io_end(c_bvec_t     *c_bvec, 
                                   int           err, 
                                   c_val_tup_t   cvt)
{
    debug("Finished the IO.\n");
    castle_debug_bvec_update(c_bvec, C_BVEC_IO_END);
   
    if(err) 
        castle_bio_data_io_error(c_bvec, err);
    else
    {
        if (!CVT_INVALID(cvt) && !CVT_MEDIUM_OBJECT(cvt))
        {
            printk("%u:%llu:"cep_fmt_str_nl, cvt.type, cvt.length, cep2str(cvt.cep));
            BUG();
        }
        if (CVT_MEDIUM_OBJECT(cvt) && 
               (cvt.cep.ext_id != c_bvec->tree->data_ext_fs.ext_id))
        {
            printk("%u:%llu:%llu:"cep_fmt_str_nl, cvt.type, cvt.length,
                    c_bvec->tree->data_ext_fs.ext_id, cep2str(cvt.cep));
            BUG();
        }
        castle_bio_data_io_do(c_bvec, cvt.cep);
    }
}
 
static int castle_bio_validate(struct bio *bio)
{
    struct bio_vec *bvec;
    int i;
        
    bio_for_each_segment(bvec, bio, i)
    {
        if(((bvec->bv_offset % (1<<9)) != 0) ||  
           ((bvec->bv_len    % (1<<9)) != 0)) 
        {
            printk("Got non aligned IO: len=0x%x, offset=0x%x\n", 
                    bvec->bv_len, bvec->bv_offset);
            return -EINVAL;
        }
    }

    return 0;
}

static void castle_device_c_bvec_make(c_bio_t *c_bio, 
                                      int idx, 
                                      sector_t block,
                                      int one2one_bvec)
{
    /* Create an appropriate c_bvec */
    c_bvec_t *c_bvec = c_bio->c_bvecs + idx;
                                
    /* Get a reference */
    castle_bio_get(c_bio);

    /* Init the c_bvec */
    c_bvec->key         = (void *)block; 
    c_bvec->version     = INVAL_VERSION; 
    c_bvec->flags       = 0; 
    c_bvec->tree        = &castle_global_tree;
    c_bvec->cvt_get     = castle_bio_data_cvt_get;
    c_bvec->endfind     = castle_bio_data_io_end;
    c_bvec->da_endfind  = NULL;
    atomic_set(&c_bvec->reserv_nodes, 0);
    if(one2one_bvec)
        set_bit(CBV_ONE2ONE_BIT, &c_bvec->flags);
    castle_debug_bvec_update(c_bvec, C_BVEC_INITIALISED);

    /* Submit the c_bvec for processing */
    castle_btree_find(c_bvec); 
}
 
static int castle_device_make_request(struct request_queue *rq, struct bio *bio)
{ 
    c_bio_t *c_bio = NULL;
    struct castle_attachment *dev = rq->queuedata;
    struct bio_vec *bvec;
    sector_t sector, last_block;
    int i, j;

    debug("Request on dev=0x%x\n", MKDEV(dev->dev.gd->major, dev->dev.gd->first_minor));
    /* Check if we can handle this bio */
    if(castle_bio_validate(bio))
        goto fail_bio;

    /* We'll generate at most bi_vcnt + 1 castle_bio_vecs (for full page, 
       unaligned bvecs) */
    c_bio = castle_utils_bio_alloc(bio->bi_vcnt + 1);
    if(!c_bio) 
        goto fail_bio;
    
    c_bio->attachment = dev;
    c_bio->bio        = bio;
    c_bio->data_dir   = bio_data_dir(bio);

    sector     = bio->bi_sector;
    last_block = -1;
    j          = 0;
    bio_for_each_segment(bvec, bio, i)
    {
        sector_t block   = sector >> (C_BLK_SHIFT - 9);
        sector_t bv_secs = (bvec->bv_len >> 9);
        int aligned = !(sector % (1 << (C_BLK_SHIFT - 9)));
        int one2one = aligned && (bvec->bv_len == C_BLK_SIZE);

        /* Check if block number is different to the previous one.
           If so, init and submit a new c_bvec. */
        if(block != last_block)
            castle_device_c_bvec_make(c_bio, j++, block, one2one);
        last_block = block;

        /* Check this bvec shouldn't be split into two c_bvecs now. */
        block = (sector + bv_secs - 1) >> (C_BLK_SHIFT - 9);
        if(block != last_block)
        {
            /* We should have only advanced by one block */
            BUG_ON(block != last_block + 1);
            /* Make sure we never try to use too many c_bvecs 
               (we've got bi_vcnt + 1) */
            BUG_ON(j > bio->bi_vcnt);
            /* Block cannot possibly correspond to one bvec exactly */
            BUG_ON(one2one);
            /* Submit the request */
            castle_device_c_bvec_make(c_bio, j++, block, one2one);
        }
        last_block = block;

        /* Advance the sector counter */
        sector += bv_secs;
    }
    castle_debug_bio_register(c_bio, dev->version, j);
    castle_bio_put(c_bio);

    return 0;

fail_bio:
    if(c_bio) castle_utils_bio_free(c_bio);
 
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    bio_endio(bio, 0, -EIO);
#else
    bio_endio(bio, -EIO);
#endif



    return 0;
}

struct castle_attachment* castle_device_find(dev_t dev)
{
    struct castle_attachment *cd;
    struct list_head *lh;

    list_for_each(lh, &castle_attachments.attachments)
    {
        cd = list_entry(lh, struct castle_attachment, list);
        if(!cd->device)
            continue;
        if((cd->dev.gd->major == MAJOR(dev)) &&
           (cd->dev.gd->first_minor == MINOR(dev)))
            return cd;
    }
    return NULL;
}

struct castle_attachment* castle_attachment_get(collection_id_t col_id)
{
    struct castle_attachment *ca, *result = NULL;
    struct list_head *lh;

    spin_lock(&castle_attachments.lock);

    list_for_each(lh, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list);
        if(ca->device)
            continue;
        if(ca->col.id == col_id)
        {
            result = ca;
            ca->ref_cnt++;
            break;
        }
    }
    
    spin_unlock(&castle_attachments.lock);
    
    return result;
}

void castle_attachment_put(struct castle_attachment *ca)
{
    int to_free = 0;
    
    BUG_ON(in_atomic());
    spin_lock(&castle_attachments.lock);

    ca->ref_cnt--;
    
    BUG_ON(ca->ref_cnt < 0);
    
    if (ca->ref_cnt == 0)
    {
        to_free = 1;
        list_del(&ca->list);
    }

    spin_unlock(&castle_attachments.lock);

    if (to_free)
    {
        version_t version = ca->version;
        da_id_t da_id = castle_version_da_id_get(version);
        collection_id_t ca_id = ca->col.id;
        
        castle_events_collection_detach(ca->col.id);
        castle_sysfs_collection_del(ca);

        castle_free(ca->col.name);
        castle_free(ca);
        castle_version_detach(version);
        castle_double_array_put(da_id);
        printk("Attachment %u is completly removed\n", ca_id);
    }
}

EXPORT_SYMBOL(castle_attachment_get);
EXPORT_SYMBOL(castle_attachment_put);

struct castle_attachment* castle_attachment_init(int device, /* _or_object_collection */
                                                 version_t version,
                                                 da_id_t *da_id,
                                                 uint32_t *size,
                                                 int *leaf)
{
    struct castle_attachment *attachment = NULL;

    if(castle_version_attach(version))
        return NULL;
    BUG_ON(castle_version_read(version, da_id, NULL, size, leaf));

    attachment = castle_malloc(sizeof(struct castle_attachment), GFP_KERNEL); 
    if(!attachment)
        return NULL;
	init_rwsem(&attachment->lock);
    attachment->ref_cnt = 1; // Use double put on detach
    attachment->device  = device;
    attachment->version = version;
    attachment->key = INVAL_MSTORE_KEY;

    return attachment; 
}

void castle_device_free(struct castle_attachment *cd)
{
    version_t version = cd->version;
    
    castle_events_device_detach(cd->dev.gd->major, cd->dev.gd->first_minor);

    printk("===> When freeing the number of cd users is: %d\n", cd->ref_cnt);
    castle_sysfs_device_del(cd);
    /* TODO: Should this be done? blk_cleanup_queue(cd->dev.gd->rq); */ 
    del_gendisk(cd->dev.gd);
    put_disk(cd->dev.gd);
    list_del(&cd->list);
    castle_free(cd);
    castle_version_detach(version);
}

struct castle_attachment* castle_device_init(version_t version)
{
    struct castle_attachment *dev = NULL;
    struct request_queue *rq      = NULL;
    struct gendisk *gd            = NULL;
    static int minor = 0;
    uint32_t size;
    int leaf;
    int err;

    dev = castle_attachment_init(1, version, NULL, &size, &leaf); 
    if(!dev)
        goto error_out;
    gd = alloc_disk(1);
    if(!gd)
        goto error_out;

    sprintf(gd->disk_name, "castle-fs-%d", minor);
    gd->major        = castle_attachments.major;
    gd->first_minor  = minor++;
	gd->fops         = &castle_bd_ops;
    gd->private_data = dev;

	rq = blk_alloc_queue(GFP_KERNEL);
    if (!rq)
        goto error_out;
	blk_queue_make_request(rq, castle_device_make_request);
	rq->queuedata    = dev;
    gd->queue        = rq;
    if(!leaf) 
        set_disk_ro(gd, 1);

    list_add(&dev->list, &castle_attachments.attachments);
    dev->dev.gd = gd;
    
    set_capacity(gd, (size << (C_BLK_SHIFT - 9)));
    add_disk(gd);

    bdget(MKDEV(gd->major, gd->first_minor));
    err = castle_sysfs_device_add(dev);
    if(err) 
    {
        /* TODO: this doesn't do bdput. device_free doesn't 
                 do this neither, and it works ... */
        del_gendisk(gd);
        list_del(&dev->list);
        goto error_out;
    }

    castle_events_device_attach(gd->major, gd->first_minor, version);

    return dev;

error_out:
    if(gd)  put_disk(gd); 
    if(rq)  blk_cleanup_queue(rq); 
    if(dev) castle_free(dev);
    printk("Failed to init device.\n");
    return NULL;    
}

struct castle_attachment* castle_collection_init(version_t version, char *name)
{
    struct castle_attachment *collection = NULL;
    static collection_id_t collection_id = 0;
    da_id_t da_id;
    int err;
    int da_get = 0;

    BUG_ON(strlen(name) > MAX_NAME_SIZE);

    collection = castle_attachment_init(0, version, &da_id, NULL, NULL); 
    if(!collection)
        goto error_out;
    
    if(DA_INVAL(da_id))
    {
        printk("Could not attach collection: %s, version: %d, because no DA found.\n",
                name, version);
        castle_version_detach(version);
        goto error_out;
    }
    if (castle_double_array_get(da_id) < 0)
        goto error_out;
    da_get = 1;

    collection->col.id   = collection_id++;
    collection->col.name = name;
    spin_lock(&castle_attachments.lock);
    list_add(&collection->list, &castle_attachments.attachments);
    spin_unlock(&castle_attachments.lock);

    err = castle_sysfs_collection_add(collection);
    if(err) 
    {
        spin_lock(&castle_attachments.lock);
        list_del(&collection->list);
        spin_unlock(&castle_attachments.lock);
        goto error_out;
    }

    castle_events_collection_attach(collection->col.id, version);

    return collection;

error_out:
    castle_free(name);
    if(collection) castle_free(collection);
    if(da_get) castle_double_array_put(da_id);
    printk("Failed to init collection.\n");
    return NULL;    
}

void castle_slave_access(uint32_t uuid)
{
    struct castle_slave_superblock *sb;
    struct castle_slave *cs;

    cs = castle_slave_find_by_uuid(uuid);
    BUG_ON(!cs);
    cs->last_access = jiffies; 
        
    sb = castle_slave_superblock_get(cs);
    if(!(sb->flags & CASTLE_SLAVE_SPINNING))
    {
        sb->flags |= CASTLE_SLAVE_SPINNING;
        castle_slave_superblock_put(cs, 1);
        castle_events_spinup(cs->uuid);
    } else
        castle_slave_superblock_put(cs, 0);
}

static void castle_slaves_spindown(struct work_struct *work)
{
    struct castle_slave_superblock *sb;
    struct list_head *l;

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        sb = castle_slave_superblock_get(cs);
        if(!(sb->flags & CASTLE_SLAVE_SPINNING))
        {
            castle_slave_superblock_put(cs, 0);
            continue;
        }
#ifdef CASTLE_SPINDOWN_DISKS
        /* This slave is spinning, check if there was an access to it within
           the spindown period */
        if((cs->last_access + 5 * HZ < jiffies) &&
           !(sb->flags & CASTLE_SLAVE_TARGET))
        {
            sb->flags &= ~CASTLE_SLAVE_SPINNING; 
            castle_slave_superblock_put(cs, 1);
            castle_events_spindown(cs->uuid);
        } else
            castle_slave_superblock_put(cs, 0);
#else
            castle_slave_superblock_put(cs, 0);
#endif
    }
}
    
static struct timer_list spindown_timer; 
static struct work_struct spindown_work_item;
static void castle_slaves_spindowns_check(unsigned long first)
{
    unsigned long sleep = 5*HZ;

    /* NOTE: This should really check if we've got waitqueues initialised
       at the moment we assume 10s is enough for that */
    if(first)
    {
        CASTLE_INIT_WORK(&spindown_work_item, castle_slaves_spindown);
        sleep = 10*HZ;
    }
    else
        queue_work(castle_wq, &spindown_work_item); 

    /* Reschedule ourselves */
    setup_timer(&spindown_timer, castle_slaves_spindowns_check, 0);
    mod_timer(&spindown_timer, jiffies + sleep);
}

static void castle_slaves_unlock(void)
{
    struct list_head *lh, *th;
    struct castle_slave *slave;

    del_singleshot_timer_sync(&spindown_timer);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
    cancel_delayed_work(&spindown_work_item);
    flush_scheduled_work();
#else
    cancel_work_sync(&spindown_work_item);
#endif

    list_for_each_safe(lh, th, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list); 
        put_c2b(slave->sblk);
        put_c2b(slave->fs_sblk);
        put_c2b(slave->freespace_sblk);
        slave->freespace_sblk = NULL;
    }
}

static char *wq_names[2*MAX_BTREE_DEPTH+1];
static void castle_wqs_fini(void)
{
    int i;

    for(i=0; i<=2*MAX_BTREE_DEPTH; i++)
    {
        if(wq_names[i])
            castle_free(wq_names[i]); 
        if(castle_wqs[i]) 
            destroy_workqueue(castle_wqs[i]);
    }
}

static int castle_wqs_init(void)
{
    int i;

    /* Init the castle workqueues */
    memset(wq_names  , 0, sizeof(char *) * (2*MAX_BTREE_DEPTH+1));
    memset(castle_wqs, 0, sizeof(struct workqueue_struct *) * (2*MAX_BTREE_DEPTH+1));
    for(i=0; i<=2*MAX_BTREE_DEPTH; i++)
    {
        /* At most two characters for the number */
        BUG_ON(i > 99);
        wq_names[i] = castle_malloc(strlen("castle_wq")+3, GFP_KERNEL);
        if(!wq_names[i])
            goto err_out;
        sprintf(wq_names[i], "castle_wq%d", i);
        castle_wqs[i] = create_workqueue(wq_names[i]);
        if(!castle_wqs[i])
            goto err_out;
    }

    return 0;

err_out:
    printk("Could not create workqueues.\n");

    return -ENOMEM;
}

static void castle_slaves_free(void)
{
    struct list_head *lh, *th;
    struct castle_slave *slave;

    list_for_each_safe(lh, th, &castle_slaves.slaves)
    {
        slave = list_entry(lh, struct castle_slave, list); 
        castle_release(slave);
    }
}

static int castle_slaves_init(void)
{
    /* Init the slaves structures */
    memset(&castle_slaves, 0, sizeof(struct castle_slaves));
    INIT_LIST_HEAD(&castle_slaves.slaves);

    castle_slaves_spindowns_check(1);

    return 0;
}

static int castle_attachments_init(void)
{
    int major;

    memset(&castle_attachments, 0, sizeof(struct castle_attachments));
    INIT_LIST_HEAD(&castle_attachments.attachments);

    /* Allocate a major for this device */
    if((major = register_blkdev(0, "castle-fs")) < 0) 
    {
        printk("Couldn't register castle device\n");
        return -ENOMEM;
    }
    spin_lock_init(&castle_attachments.lock);
        
    castle_attachments.major = major;

    return 0;
}

static void castle_attachments_free(void)
{
    struct list_head *lh, *th;
    struct castle_attachment *ca;

    castle_attachments_store_fini();
    list_for_each_safe(lh, th, &castle_attachments.attachments)
    {
        ca = list_entry(lh, struct castle_attachment, list); 
        if(ca->device)
            castle_device_free(ca);
        else
            castle_attachment_put(ca);
    }

    if (castle_attachments.major)
        unregister_blkdev(castle_attachments.major, "castle-fs");
}

void __castle_extents_fini(void);

static int __init castle_init(void)
{
    int ret;

    printk("Castle FS init (build: %s) ... ", CASTLE_COMPILE_CHANGESET);

    castle_fs_inited = 0;
              castle_debug_init();
              castle_time_init();
    if((ret = castle_wqs_init()))          goto err_out0;
    if((ret = castle_slaves_init()))       goto err_out1;
    if((ret = castle_extents_init()))      goto err_out2;
    if((ret = castle_cache_init()))        goto err_out3;
    if((ret = castle_versions_init()))     goto err_out4;
    if((ret = castle_btree_init()))        goto err_out5;
    if((ret = castle_double_array_init())) goto err_out6;
    if((ret = castle_attachments_init()))  goto err_out7;
    if((ret = castle_control_init()))      goto err_out8;
    if((ret = castle_sysfs_init()))        goto err_out9;
    if((ret = castle_back_init()))         goto err_out10;

    printk("OK.\n");

    return 0;

    castle_back_fini(); /* Unreachable */
err_out10:
    castle_sysfs_fini();
err_out9:
    castle_control_fini();
err_out8:
    castle_attachments_free();
err_out7:
    castle_double_array_fini();
err_out6:
    castle_btree_free();
err_out5:
    castle_versions_fini();
err_out4:
    BUG_ON(!list_empty(&castle_slaves.slaves));
    castle_slaves_unlock();
    castle_cache_fini();
err_out3:
    castle_extents_fini();
err_out2:
    castle_slaves_free();
err_out1:
    castle_wqs_fini();
err_out0:
    castle_time_fini();
    castle_debug_fini();
    
    /* TODO: check if kernel will accept any non-zero return value to mean: we want to exit */
    return ret;
}

void castle_rda_slaves_free(void);

static void __exit castle_exit(void)
{
    printk("Castle FS exit ... ");

    /* Remove externaly visible interfaces */
    castle_back_fini();
    castle_control_fini();
    castle_sysfs_fini();
    /* Now, make sure no more IO can be made, internally or externally generated */
    castle_attachments_free();
    /* Cleanup/writeout all metadata */ 
    castle_double_array_fini();
    castle_btree_free();
    castle_versions_fini();
    castle_mstores_fini();
    /* Drop all cache references (superblocks), flush the cache, free the slaves. */ 
    castle_slaves_unlock();
    __castle_extents_fini();
    castle_cache_fini();
    castle_extents_fini();
    castle_slaves_free();
    castle_wqs_fini();
    /* All finished, stop the debuggers */
    castle_time_fini();
    castle_debug_fini();

    printk("done.\n\n\n");
}

module_init(castle_init);
module_exit(castle_exit);

MODULE_LICENSE("GPL");

