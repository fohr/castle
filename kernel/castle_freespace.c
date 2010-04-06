#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/fs.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif


#define blk_to_bitmap_blk(_blk) (((_blk) >> (C_BLK_SHIFT + 3)) + 2)
#define bitmap_blk_to_blk(_blk) (((_blk) - 2) << (C_BLK_SHIFT + 3))

#define cdb_to_bitmap_cdb(_cdb) ((c_disk_blk_t){(_cdb).disk, blk_to_bitmap_blk((_cdb).block)})
#define bitmap_cdb_to_cdb(_cdb) ((c_disk_blk_t){(_cdb).disk, bitmap_blk_to_blk((_cdb).block)})

#define blk_to_bitmap_off(_blk) ((_blk) & (8 * C_BLK_SIZE - 1))
#define cdb_to_bitmap_off(_cdb) (blk_to_bitmap_off((_cdb).block))

#define HASH_MOD_INC     (1)
#define HASH_MOD_DEC     (2)
#define HASH_MOD_ADD     (3)
#define HASH_MOD_REM     (4)
static int castle_freespace_hash_mod(struct castle_slave *cs,
                                     version_t version,
                                     int mod)
{
    int hash_idx = (version % BLOCKS_HASH_SIZE);
    struct list_head *i, *h = &cs->block_cnts.hash[hash_idx];
    struct castle_slave_blocks_cnt *cnt = NULL;

    if((mod == HASH_MOD_INC) ||
       (mod == HASH_MOD_DEC) ||
       (mod == HASH_MOD_REM))
    {
        list_for_each(i, h)
        {
            cnt = list_entry(i, struct castle_slave_blocks_cnt, list);
            if(cnt->version == version)
                break;
        }
        BUG_ON(!cnt);
    }

    switch(mod)
    {
        case HASH_MOD_INC:
            cnt->cnt++;
            break;
        case HASH_MOD_DEC:
            cnt->cnt--;
            break;
        case HASH_MOD_ADD:
            if(version == 0)
                cnt = &cs->block_cnts.metadata_cnt;
            else 
            {
                cnt = kmalloc(sizeof(struct castle_slave_blocks_cnt), GFP_KERNEL);
                if(!cnt) return -ENOMEM;
            }
            cnt->version = version;
            cnt->cnt = 0;
            INIT_LIST_HEAD(&cnt->list);
            list_add(&cnt->list, h);
            break;
        case HASH_MOD_REM:
            list_del(&cnt->list);
            if(cnt->version != 0)
                kfree(cnt);
            break;
        default:
            printk("Unknown hash mod: %d\n", mod);
            BUG();
            break;
    }

    return 0;
}

ssize_t castle_freespace_summary_get(struct castle_slave *cs, char *buf)
{
    struct castle_slave_blocks_cnt *cnt;
    struct list_head *l;
    ssize_t offset = 0;
    int i;

    for(i=0; i<BLOCKS_HASH_SIZE; i++)
    {
        list_for_each(l, &cs->block_cnts.hash[i])
        {
            cnt = list_entry(l, struct castle_slave_blocks_cnt, list);
            offset += sprintf((buf + offset), "%d\t%d\n", cnt->version, cnt->cnt); 
        }
    }

    return offset;
}

ssize_t castle_freespace_blks_for_version_get(struct castle_slave *cs, version_t version)
{
    int hash_idx = (version % BLOCKS_HASH_SIZE);
    struct list_head *i, *h = &cs->block_cnts.hash[hash_idx];
    struct castle_slave_blocks_cnt *cnt = NULL;

    list_for_each(i, h)
    {
        cnt = list_entry(i, struct castle_slave_blocks_cnt, list);
        if(cnt->version == version)
            break;
    }
    BUG_ON(!cnt);
    
    return cnt->cnt;
}

int castle_freespace_version_add(version_t version)
{
    struct list_head *l;

    /* That has already been done */
    if(version == 0)
        return 0;

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);
        int ret = castle_freespace_hash_mod(cs, version, HASH_MOD_ADD);

        if(ret) return ret;
    }

    return 0;
}

void castle_freespace_slave_init(struct castle_slave *cs, struct castle_slave_superblock *cs_sb)
{
    c_disk_blk_t freespace_cdb, last_cdb, bitmap_cdb;
    c2_page_t *bitmap_c2p;
    void * bitmap_buf;
    uint8_t *bitmap;
    int i;

    /* Initialise the hashtable to store version->blk_cnt map */
    for(i=0; i<BLOCKS_HASH_SIZE; i++)
        INIT_LIST_HEAD(&cs->block_cnts.hash[i]);
    BUG_ON(castle_freespace_hash_mod(cs, 0, HASH_MOD_ADD)); 
    /* TODO: other versions may already exist. We need to ask versions.c for them
       ATM we don't support adding disks after initing the FS */

    freespace_cdb.disk  = cs->uuid;
    freespace_cdb.block = cs_sb->used;
    for(i=0; i<cs_sb->used; i++)
        BUG_ON(castle_freespace_hash_mod(cs, 0, HASH_MOD_INC));
    last_cdb.disk  = cs->uuid;
    last_cdb.block = 0;
    bitmap_cdb = INVAL_DISK_BLK;

    while(last_cdb.block < cs_sb->size)
    {
        c2_page_t *c2p = castle_cache_page_get(freespace_cdb);

        lock_c2p(c2p);
        /* We'll overwrite entire block */
        set_c2p_uptodate(c2p);
        bitmap = c2p_buffer(c2p);
        for(i=0; i<C_BLK_SIZE; i++)
            bitmap[i] = (uint8_t)-1;

        /* c2p has been changed */
        dirty_c2p(c2p);
        unlock_c2p(c2p);
        put_c2p(c2p);

        /* Make sure that the blocks used for freespace bitmap is set as used */
        if(memcmp(&bitmap_cdb, &cdb_to_bitmap_cdb(freespace_cdb), sizeof(c_disk_blk_t)) != 0)
        {
            if(!DISK_BLK_INVAL(bitmap_cdb))
            {
                dirty_c2p(bitmap_c2p);
                unlock_c2p(bitmap_c2p);
                put_c2p(bitmap_c2p);
            }
            bitmap_cdb = cdb_to_bitmap_cdb(freespace_cdb);
            bitmap_c2p = castle_cache_page_get(bitmap_cdb);
            lock_c2p(bitmap_c2p);
            if(!c2p_uptodate(bitmap_c2p))
                BUG_ON(submit_c2p_sync(READ, bitmap_c2p));
            bitmap_buf = c2p_buffer(bitmap_c2p);
        }
        clear_bit(cdb_to_bitmap_off(freespace_cdb), bitmap_buf);
        /* Superblocks use up 2 blocks */
        if(last_cdb.block == 0)
        {
            clear_bit(0, bitmap_buf);
            clear_bit(1, bitmap_buf);
        }

        freespace_cdb.block += 1;
        last_cdb.block      += C_BLK_SIZE * 8;
        cs_sb->used++;
        BUG_ON(castle_freespace_hash_mod(cs, 0, HASH_MOD_INC));
    }

    /* Release the last bitmap */
    dirty_c2p(bitmap_c2p);
    unlock_c2p(bitmap_c2p);
    put_c2p(bitmap_c2p);
}

c_disk_blk_t castle_freespace_slave_block_get(struct castle_slave *slave, version_t version)
{
    struct castle_slave_superblock *sb = NULL;
    c_disk_blk_t free_cdb, bitmap_cdb, first_bitmap_cdb;
    uint64_t *bitmap_buf, word, complement_word;
    c2_page_t *bitmap_c2p;
    block_t slave_size;
    int i, i_max = (C_BLK_SIZE / sizeof(uint64_t));

    // TODO: slave locks!
    /* We've selected a disk to search for a new block on. Select bitmap block. */
    sb = castle_slave_superblock_get(slave);
    slave_size = sb->size;
    if(!(sb->flags & CASTLE_SLAVE_TARGET))
    {
        castle_slave_superblock_put(slave, 0);
        return INVAL_DISK_BLK;
    }

    debug("Slave size=0x%x\n", slave_size);

    free_cdb = (c_disk_blk_t){slave->uuid, slave->free_blk+1};
    debug("Free block on the slave is: 0x%x\n", free_cdb.block);
    i = cdb_to_bitmap_off(free_cdb) / (sizeof(uint64_t) * 8);
    debug("uint64_t offset is: 0x%x\n", i);
    first_bitmap_cdb = bitmap_cdb = cdb_to_bitmap_cdb(free_cdb);
    debug("first bitmap block: 0x%x\n", first_bitmap_cdb.block);
    goto process_bitmap_cdb;

next_bitmap_cdb:
    debug("==> Selecting next bitmap block.\n");
    debug("0x%x -> ", bitmap_cdb.block);
    unlock_c2p(bitmap_c2p);
    put_c2p(bitmap_c2p);
    bitmap_cdb.block++;
    if(bitmap_cdb.block > blk_to_bitmap_blk(slave_size-1))
        bitmap_cdb.block = 2;
    debug("0x%x\n", bitmap_cdb.block);
    if(bitmap_cdb.block == first_bitmap_cdb.block)
    {
        debug("Checked all bitmap blocks. Going to the next slave.\n");
        castle_slave_superblock_put(slave, 0);
        return INVAL_DISK_BLK;
    }

process_bitmap_cdb:
    /* Find first non-zero uint64_t in the bitmap */
    bitmap_c2p = castle_cache_page_get(bitmap_cdb);
    lock_c2p(bitmap_c2p);
    if(!c2p_uptodate(bitmap_c2p))
        BUG_ON(submit_c2p_sync(READ, bitmap_c2p));
    bitmap_buf = c2p_buffer(bitmap_c2p);
    for(; i < i_max; i++)
        if(bitmap_buf[i] != 0)
            break;
    debug("First non-zero bitmap block word is at i=%d (i_max=%d)\n",
        i, i_max);

    /* If none of the words were non-zero in the bitmap, goto next bitmap
       block straight away */
    if(i == i_max) goto next_bitmap_cdb;

    /* Find the first set bit in the first non-zero bitmap word */
    /* We are assuming little endian here */
    word = bitmap_buf[i];
    debug("The non-zero bitmap block word is 0x%.16llx\n", word);
    complement_word = (~word) + 1UL;
    debug("2's completement is               0x%.16llx\n", complement_word);
    word = word & complement_word;
    debug("And is                            0x%.16llx\n", word);
    debug("The set bit is at position        %d\n", fls64(word)-1);
    i = i * sizeof(uint64_t) * 8 + fls64(word) - 1;
    debug("Found set bit at offset=%d\n", i);
    BUG_ON(test_bit(i, bitmap_buf) == 0);
    /* This might be past the end of the block device, check for that */
    free_cdb.block = bitmap_cdb_to_cdb(bitmap_cdb).block + i;
    debug("Free block corresponding to this bit is: 0x%x (slave_size=0x%x)\n", free_cdb.block, slave_size);
    if(free_cdb.block >= slave_size)
        goto next_bitmap_cdb;
    /* If we got here we found a non-set bit, < size of the slave device */
    clear_bit(i, bitmap_buf);
    dirty_c2p(bitmap_c2p);
    unlock_c2p(bitmap_c2p);
    put_c2p(bitmap_c2p);
    /* Book-keeping stuff */
    debug("Free_block is (0x%x, 0x%x), bookkeeping that\n", free_cdb.disk, free_cdb.block);
    slave->free_blk = free_cdb.block;
    castle_freespace_hash_mod(slave, version, HASH_MOD_INC);
    sb->used++;
    castle_slave_superblock_put(slave, 1);

    return free_cdb;
}

c_disk_blk_t castle_freespace_block_get(version_t version)
{
    static struct castle_slave *last_slave = NULL;
    struct castle_slave *slave, *first_slave = NULL;
    struct list_head *l;
    c_disk_blk_t free_cdb;

    debug("\nAllocating a new block.\n");

    /* Will happen only once. The first time the allocator is called */
    if(!last_slave)
    {
        BUG_ON(list_empty(&castle_slaves.slaves));
        l = castle_slaves.slaves.next;
        last_slave = list_entry(l, struct castle_slave, list);
    }

next_disk:
    l = &last_slave->list;
    if(list_is_last(l, &castle_slaves.slaves))
        l = &castle_slaves.slaves;
    l = l->next;
    slave = list_entry(l, struct castle_slave, list);

    /* We've selected the next slave, check if we've tried it already */
    if(slave == first_slave)
    {
        printk("Could not find a single free block, on any of the disks!\n");
        BUG();
        return INVAL_DISK_BLK;
    }

    /* Remember what slave we've tried last */
    last_slave = slave;
    if(!first_slave) first_slave = slave;

    debug("Selected slave=0x%x\n", slave->uuid);
    free_cdb = castle_freespace_slave_block_get(slave, version);
    if(DISK_BLK_INVAL(free_cdb))
        goto next_disk;

    return free_cdb;
}

void castle_freespace_block_free(c_disk_blk_t cdb, version_t version)
{
    struct castle_slave *slave = castle_slave_find_by_uuid(cdb.disk);
    c_disk_blk_t bitmap_cdb;
    c2_page_t *bitmap_c2p;
    void *bitmap_buf;

    BUG_ON(!slave);
    bitmap_cdb = cdb_to_bitmap_cdb(cdb);
    bitmap_c2p = castle_cache_page_get(bitmap_cdb);
    lock_c2p(bitmap_c2p);
    if(!c2p_uptodate(bitmap_c2p))
        BUG_ON(submit_c2p_sync(READ, bitmap_c2p));
    bitmap_buf = c2p_buffer(bitmap_c2p);
    set_bit(blk_to_bitmap_off(cdb.block), bitmap_buf);
    dirty_c2p(bitmap_c2p);
    unlock_c2p(bitmap_c2p);
    put_c2p(bitmap_c2p);
    
    castle_freespace_hash_mod(slave, version, HASH_MOD_DEC);
}

