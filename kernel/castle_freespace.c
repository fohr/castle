#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define FREESPACE_START_BLK     2
c_disk_blk_t castle_freespace_slave_block_get(struct castle_slave *cs, version_t v, int size);

#define blk_to_bitmap_blk(_blk) (((_blk) >> (C_BLK_SHIFT + 3)) + FREESPACE_START_BLK)
#define bitmap_blk_to_blk(_blk) (((_blk) - FREESPACE_START_BLK) << (C_BLK_SHIFT + 3))

#define cdb_to_bitmap_cdb(_cdb) ((c_disk_blk_t){(_cdb).disk, blk_to_bitmap_blk((_cdb).block)})
#define bitmap_cdb_to_cdb(_cdb) ((c_disk_blk_t){(_cdb).disk, bitmap_blk_to_blk((_cdb).block)})

#define blk_to_bitmap_off(_blk) ((_blk) & (8 * C_BLK_SIZE - 1))
#define cdb_to_bitmap_off(_cdb) (blk_to_bitmap_off((_cdb).block))

#define HASH_MOD_INC     (1)
#define HASH_MOD_DEC     (2)
#define HASH_MOD_SET     (3)
#define HASH_MOD_ADD     (4)
#define HASH_MOD_REM     (5)
static int castle_freespace_hash_mod(struct castle_slave *cs,
                                     version_t version,
                                     int mod, ...)
{
    int hash_idx = (version % BLOCKS_HASH_SIZE);
    struct list_head *i, *h = &cs->block_cnts.hash[hash_idx];
    struct castle_slave_block_cnt *cnt = NULL;
    va_list vl;

    va_start(vl, mod);
    if((mod == HASH_MOD_INC) ||
       (mod == HASH_MOD_DEC) ||
       (mod == HASH_MOD_SET) ||
       (mod == HASH_MOD_REM) ||
       (mod == HASH_MOD_ADD))
    {
        list_for_each(i, h)
        {
            cnt = list_entry(i, struct castle_slave_block_cnt, list);
            if(cnt->version == version)
                break;
        }
        if(cnt && (cnt->version != version)) cnt = NULL;
        BUG_ON((mod != HASH_MOD_ADD) && (!cnt));
    }

    switch(mod)
    {
        case HASH_MOD_INC:
            cnt->cnt++;
            break;
        case HASH_MOD_DEC:
            cnt->cnt--;
            break;
        case HASH_MOD_SET:
            cnt->cnt = va_arg(vl, block_t);
            break;
        case HASH_MOD_ADD:
            /* Check if there is an entry for this version already */ 
            if(cnt)
            {
                va_end(vl);
                return -EEXIST;
            }

            /* Allocate hash entry for this version, unless it's version 0 */
            if(version == 0)
                cnt = &cs->block_cnts.metadata_cnt;
            else 
            {
                cnt = kmalloc(sizeof(struct castle_slave_block_cnt), GFP_KERNEL);
                if(!cnt) 
                {
                    va_end(vl);
                    return -ENOMEM;
                }
            }
            /* Init and insert */
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
    va_end(vl);

    return 0;
}

ssize_t castle_freespace_summary_get(struct castle_slave *cs, char *buf, int version_offset, int number)
{
    struct castle_slave_block_cnt *cnt;
    struct list_head *l;
    ssize_t offset = 0;
    int i;

    // TODO we currently assume here we never do delete! version numbers must be contig

    for(i=0; i<BLOCKS_HASH_SIZE; i++)
    {
        list_for_each(l, &cs->block_cnts.hash[i])
        {
            cnt = list_entry(l, struct castle_slave_block_cnt, list);
            
            if (cnt->version >= version_offset + number)
                continue;
                
            if (cnt->version < version_offset)
                continue;
            
            offset += sprintf((buf + offset), "0x%x: %d\n", cnt->version, cnt->cnt); 
        }
    }

    return offset;
}

ssize_t castle_freespace_version_slave_blocks_get(struct castle_slave *cs, version_t version)
{
    int hash_idx = (version % BLOCKS_HASH_SIZE);
    struct list_head *i, *h = &cs->block_cnts.hash[hash_idx];
    struct castle_slave_block_cnt *cnt = NULL;
    
    list_for_each(i, h)
    {
        cnt = list_entry(i, struct castle_slave_block_cnt, list);
        if(cnt->version == version)
            break;
    }
    BUG_ON(!cnt || (cnt->version != version));
    
    return cnt->cnt;
}

ssize_t castle_freespace_version_blocks_get(version_t version)
{
    struct list_head *l;
    ssize_t cnt = 0;

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        cnt += castle_freespace_version_slave_blocks_get(cs, version);
    }

    return cnt;
}

static c2_block_t* castle_freespace_flist_alloc(struct castle_slave *cs,
                                               c_disk_blk_t prev_flist_cdb)
{
    struct castle_flist_node *flist_node;
    c_disk_blk_t cdb;
    c2_block_t *c2b;

    debug("\nAllocating a new block for flist.\n");
    cdb = castle_freespace_slave_block_get(cs, 0, 1);
    debug("Allocated (0x%x, 0x%x)\n", cdb.disk, cdb.block);
    if(DISK_BLK_INVAL(cdb))
        return NULL;

    c2b = castle_cache_page_block_get(cdb);
    lock_c2b(c2b);
    set_c2b_uptodate(c2b);
    flist_node = c2b_buffer(c2b);
    flist_node->magic    = FLIST_NODE_MAGIC;
    flist_node->version  = 0;
    flist_node->capacity = FLIST_SLOTS;
    flist_node->used     = -1;
    flist_node->next     = INVAL_DISK_BLK;
    flist_node->prev     = prev_flist_cdb;
    dirty_c2b(c2b);
    unlock_c2b(c2b);

    return c2b;
}

static int castle_freespace_flist_extend(struct castle_slave *cs, version_t version)
{
    // TODO: locks?
    struct castle_flist_node *flist_node;
    struct castle_slave_superblock *sb;
    c2_block_t *prev_c2b, *c2b; 

    debug("Extending flist for version %d. Capacity=%d, used=%d\n", version,
            cs->block_cnts.flist_capacity, cs->block_cnts.flist_used);
    if(cs->block_cnts.flist_used >=
       cs->block_cnts.flist_capacity - 1)
    {
        debug("====> Allocating a new node for flist.\n");
        /* We are running out of space on the flist. */
        prev_c2b = cs->block_cnts.last_flist_c2b;
        /* Allocate a new node */
        c2b = castle_freespace_flist_alloc(cs, prev_c2b->cdb);
        /* Return early if could not allocate the block */
        if(!c2b) return -EFBIG;
        /* Update the existing last flist node */
        lock_c2b(prev_c2b);
        BUG_ON(!c2b_uptodate(prev_c2b));
        flist_node = c2b_buffer(prev_c2b); 
        flist_node->next = c2b->cdb;
        dirty_c2b(prev_c2b);
        unlock_c2b(prev_c2b);
        put_c2b(prev_c2b);
        /* Update the prev pointer in the superblock */
        sb = castle_slave_superblock_get(cs);
        sb->flist_prev = c2b->cdb;
        /* Make the new node the last node */ 
        cs->block_cnts.last_flist_c2b = c2b;
        cs->block_cnts.flist_capacity += FLIST_SLOTS;
        castle_slave_superblock_put(cs, 1);
    }

    cs->block_cnts.flist_used++;
    BUG_ON(cs->block_cnts.flist_used > 
           cs->block_cnts.flist_capacity);

    return 0;
}

int castle_freespace_version_add(version_t version)
{
    struct list_head *l;
    int ret;

    /* That has already been done */
    if(version == 0)
        return 0;

    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        ret = castle_freespace_hash_mod(cs, version, HASH_MOD_ADD);
        if(ret == -EEXIST)
            continue;
        if(ret) return ret;
        ret = castle_freespace_flist_extend(cs, version);
        if(ret) return ret;
    }

    return 0;
}

static void castle_freespace_new_slave_init(struct castle_slave *cs)
{
    struct castle_slave_superblock *cs_sb;
    c_disk_blk_t freespace_cdb, last_cdb, bitmap_cdb;
    c2_block_t *bitmap_c2b, *flist_c2b;
    void * bitmap_buf;
    uint8_t *bitmap;
    int i;

    /* TODO: fail the initialisation of the slave if less than certain number of blocks 
             available */

    /* TODO: other versions may already exist. We need to ask versions.c for them
       ATM we don't support adding disks after initing the FS */
    BUG_ON(castle_freespace_hash_mod(cs, 0, HASH_MOD_ADD)); 

    cs_sb = castle_slave_superblock_get(cs);
    BUG_ON(cs_sb->used != FREESPACE_START_BLK);
    freespace_cdb.disk  = cs->uuid;
    freespace_cdb.block = cs_sb->used;
    for(i=0; i<cs_sb->used; i++)
        BUG_ON(castle_freespace_hash_mod(cs, 0, HASH_MOD_INC));
    last_cdb.disk  = cs->uuid;
    last_cdb.block = 0;
    bitmap_cdb = INVAL_DISK_BLK;

    /* Note, the bitmap will extend beyond the last block of the device.
       The next block will be marked as allocated, which simplifies allocation
       algorithms below. */
    while(last_cdb.block <= cs_sb->size)
    {
        c2_block_t *c2b = castle_cache_page_block_get(freespace_cdb);

        lock_c2b(c2b);
        /* We'll overwrite entire block */
        set_c2b_uptodate(c2b);
        bitmap = c2b_buffer(c2b);
        for(i=0; i<C_BLK_SIZE; i++)
            bitmap[i] = (uint8_t)-1;

        /* Check if the end of device is in this page */
        if(last_cdb.block + C_BLK_SIZE * 8 >= cs_sb->size)
        {
            i = blk_to_bitmap_off(cs_sb->size);
            debug("Marking end of device in freespace map.\n"
                  "Freespace_cdb=(0x%x, 0x%x), @offset: %d\n",
                  freespace_cdb.disk, freespace_cdb.block, i);
            
            while(i < C_BLK_SIZE * 8) 
            {
                if(i % 8 != 0)
                {
                    clear_bit(i, bitmap);
                    i++;
                    continue;
                }
                bitmap[i/8] = 0;
                i += 8;
            }
        }

        /* c2b has been changed */
        dirty_c2b(c2b);
        unlock_c2b(c2b);
        put_c2b(c2b);

        /* Make sure that the blocks used for freespace bitmap is set as used */
        if(memcmp(&bitmap_cdb, &cdb_to_bitmap_cdb(freespace_cdb), sizeof(c_disk_blk_t)) != 0)
        {
            if(!DISK_BLK_INVAL(bitmap_cdb))
            {
                dirty_c2b(bitmap_c2b);
                unlock_c2b(bitmap_c2b);
                put_c2b(bitmap_c2b);
            }
            bitmap_cdb = cdb_to_bitmap_cdb(freespace_cdb);
            bitmap_c2b = castle_cache_page_block_get(bitmap_cdb);
            lock_c2b(bitmap_c2b);
            if(!c2b_uptodate(bitmap_c2b))
                BUG_ON(submit_c2b_sync(READ, bitmap_c2b));
            bitmap_buf = c2b_buffer(bitmap_c2b);
        }
        clear_bit(cdb_to_bitmap_off(freespace_cdb), bitmap_buf);
        /* Superblocks use up 2 blocks. */
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
    castle_slave_superblock_put(cs, 1);

    /* Release the last bitmap */
    dirty_c2b(bitmap_c2b);
    unlock_c2b(bitmap_c2b);
    put_c2b(bitmap_c2b);

    /* Initialise the flist */
    flist_c2b = castle_freespace_flist_alloc(cs, INVAL_DISK_BLK);
    BUG_ON(!flist_c2b);
    cs_sb = castle_slave_superblock_get(cs);
    cs_sb->flist_next = flist_c2b->cdb;
    cs_sb->flist_prev = flist_c2b->cdb;
    castle_slave_superblock_put(cs, 1);
    cs->block_cnts.last_flist_c2b = flist_c2b; 
    cs->block_cnts.flist_capacity = FLIST_SLOTS;
    cs->block_cnts.flist_used     = 1; /* One entry used for version 0 */
}

static void castle_freespace_old_slave_init(struct castle_slave *cs)
{
    struct castle_slave_superblock *cs_sb;
    c_disk_blk_t flist_cdb, last_flist_cdb;
    c2_block_t *flist_c2b;
    struct castle_flist_node *flist_node;
    int i;
    
    /* If the slave is an 'old' slave, the bitmap has already been
       initialised. Also, the flist also exists. We need to read it */
    cs_sb = castle_slave_superblock_get(cs);
    flist_cdb = cs_sb->flist_next; 
    last_flist_cdb = cs_sb->flist_prev;
    castle_slave_superblock_put(cs, 0);
        
    cs->block_cnts.flist_used     = 0;
    cs->block_cnts.flist_capacity = 0;

    debug("First flist cdb=(0x%x, 0x%x)\n", flist_cdb.disk, flist_cdb.block);
    while(!DISK_BLK_INVAL(flist_cdb))
    {
        flist_c2b = castle_cache_page_block_get(flist_cdb);
        lock_c2b(flist_c2b);
         // TODO proper error handling
        if(!c2b_uptodate(flist_c2b))
            BUG_ON(submit_c2b_sync(READ, flist_c2b));
        flist_node = c2b_buffer(flist_c2b);
        flist_cdb = flist_node->next;
        if(flist_node->used > flist_node->capacity)
        {
            debug("Found flist_node with used=%x\n", flist_node->used);
            flist_node->used = 0;
        }
        for(i=0; i<flist_node->used; i++)
        {
            version_t version = flist_node->slots[i].version;
            block_t   blocks  = flist_node->slots[i].blocks;
            debug("Reading: v->cnt = %d->%d\n", version, blocks);
            // TODO proper error handling
            BUG_ON(castle_freespace_hash_mod(cs, version, HASH_MOD_ADD));
            BUG_ON(castle_freespace_hash_mod(cs, version, HASH_MOD_SET, blocks));
        } 
        cs->block_cnts.flist_used     += flist_node->used;
        cs->block_cnts.flist_capacity += flist_node->capacity;
        unlock_c2b(flist_c2b);

        if(DISK_BLK_INVAL(flist_cdb))
            cs->block_cnts.last_flist_c2b = flist_c2b;
        else
            put_c2b(flist_c2b);
    }

}

void castle_freespace_slave_init(struct castle_slave *cs, int fresh)
{
    int i;

    /* Initialise the hashtable to store version->blk_cnt map */
    for(i=0; i<BLOCKS_HASH_SIZE; i++)
        INIT_LIST_HEAD(&cs->block_cnts.hash[i]);

    /* If we've got a new device we need to initialise the freemap
       and flist */
    if(fresh)  castle_freespace_new_slave_init(cs);
    /* If not a new device, read the flist */
    if(!fresh) castle_freespace_old_slave_init(cs);
}

static int castle_freespace_bitmap_block_get(c2_block_t *bitmap_c2b, 
                                             int bit_idx, 
                                             version_t version, 
                                             int size)
{
    /* Search for contiguous run of set bits of size 'size' starting with bit_idx */
    uint64_t *bitmap_buf;
    int i;

    /* TODO: This can be optimised with the use of the following snipet of code:
        word = bitmap_buf[word_idx];
        debug("The non-zero bitmap block word is 0x%.16llx\n", word);
        complement_word = (~word) + 1UL;
        debug("2's completement is               0x%.16llx\n", complement_word);
        word = word & complement_word;
        debug("And is                            0x%.16llx\n", word);
        debug("The set bit is at position        %d\n", fls64(word)-1);
        bit_idx = word_idx * sizeof(uint64_t) * 8 + fls64(word) - 1;
        debug("Found set bit at offset=%d\n", bit_idx);
        BUG_ON(test_bit(bit_idx, bitmap_buf) == 0);

        For the time being the dumbest code that works below.
     */
    debug("=> Searching bitmap, with bit_idx=%d\n", bit_idx);
    bitmap_buf = c2b_buffer(bitmap_c2b);
    for(;bit_idx + size < C_BLK_SIZE * 8; bit_idx++)
    {
        /* Check if bit_idx is set (=> free block), and start searching for 'size' from there. */
        for(i=0; test_bit(bit_idx+i, bitmap_buf) && (i < size); i++);
        //debug("=> Check for bit_idx=%d, i=%d, size=%d\n", bit_idx, i, size);
        /* Consider the 3 cases: i < size, i==size, i > size */
        BUG_ON(i > size);
        if(i == size)
        {
            /* Got it! Clear all the bits, and return */
            for(i=0; i<size; i++)
            {
#ifdef CASTLE_DEBUG            
                BUG_ON(!test_bit(bit_idx + i, bitmap_buf));
#endif                
                clear_bit(bit_idx + i, bitmap_buf);
            }
            dirty_c2b(bitmap_c2b);
            return bit_idx;
        }
        bit_idx += i;
#ifdef CASTLE_DEBUG            
        BUG_ON((bit_idx < C_BLK_SIZE * 8) && test_bit(bit_idx, bitmap_buf));
#endif                
    }
    debug("=> Bitmap exhausted, bit_idx=%d.\n", bit_idx);
 
    return -1; 
}

c_disk_blk_t castle_freespace_slave_block_get(struct castle_slave *slave, version_t version, int size)
{
    c_disk_blk_t first_bitmap_cdb, bitmap_cdb, free_cdb;
    struct castle_slave_superblock *sb = NULL;
    c2_block_t *bitmap_c2b;
    block_t slave_size;
    int bit_idx, bitmap_offset;

    /* Lock the slave, read of the slave related info. 
       Especially the next candidate block to look at. */
    sb = castle_slave_superblock_get(slave);
    slave_size = sb->size;
    debug("Slave size=0x%x\n", slave_size);
   
    first_bitmap_cdb = bitmap_cdb = 
        (c_disk_blk_t){slave->uuid, blk_to_bitmap_blk(slave->free_blk)};
    debug("First bitmap block: 0x%x\n", first_bitmap_cdb.block);
    bit_idx = blk_to_bitmap_off(slave->free_blk);
    debug("Bit_idx: 0x%x\n", bit_idx);
                
    free_cdb = INVAL_DISK_BLK;
    /* Check the bitmap blocks until we get back to the first_bitmap_cdb again */
    do {
        bitmap_c2b = castle_cache_page_block_get(bitmap_cdb);
        lock_c2b(bitmap_c2b);
        if(!c2b_uptodate(bitmap_c2b))
            BUG_ON(submit_c2b_sync(READ, bitmap_c2b));
         
        /* NOTE: This will not find free blocks crossing the bitmap page
           boundries. If this is a problem it might be worth mapping more
           than a page at a time */
        bitmap_offset = castle_freespace_bitmap_block_get(bitmap_c2b, bit_idx, version, size);
        /* bitmap_offset >= 0 if contiguous block of freespace of size 'size'
           was found. Check if not beyond the end of device, and return. */
        debug("Got bitmap_offest=%d\n", bitmap_offset);
        if(bitmap_offset >= 0)
        {
            free_cdb.block = bitmap_cdb_to_cdb(bitmap_cdb).block + bitmap_offset;
            BUG_ON(free_cdb.block + size > slave_size);
        }
        unlock_c2b(bitmap_c2b);
        put_c2b(bitmap_c2b);
        /* Check if we found free block, if so exit. */
        if(!DISK_BLK_INVAL(free_cdb))
        {
            /* Book-keeping stuff */
            free_cdb.disk = slave->uuid;
            debug("Free block is (0x%x, 0x%x), size=%d, bookkeeping that\n", 
                    free_cdb.disk, free_cdb.block, size);
            slave->free_blk = free_cdb.block + size;
            if(slave->free_blk > slave_size)
                slave->free_blk = 0; /* Obviously 0 isn't free, but that's fine. */
            castle_freespace_hash_mod(slave, version, HASH_MOD_INC);
            sb->used += size;
            castle_slave_superblock_put(slave, 1);
            
            return free_cdb;
        }
        /* Haven't found appropriate free block in this bitmap. Check the next page. */
        bit_idx = 0;
        bitmap_cdb.block++;
        if(bitmap_cdb.block > blk_to_bitmap_blk(slave_size-1))
            bitmap_cdb.block = FREESPACE_START_BLK;
        debug("Selected next bitmap block, 0x%x.\n", bitmap_cdb.block);
    } 
    while(bitmap_cdb.block != first_bitmap_cdb.block);

    /* We dropped out of the bottom of the while loop => free block not found */
    castle_slave_superblock_put(slave, 0);
    printk("Warning: Could not find a free block on slave(%d, 0x%x), used=%d\n",
            slave->id, slave->uuid, sb->used);

    return INVAL_DISK_BLK;
}

#if 0
c_disk_blk_t castle_freespace_slave_block_get(struct castle_slave *slave, version_t version, int size)
{
    struct castle_slave_superblock *sb = NULL;
    c_disk_blk_t free_cdb, bitmap_cdb, first_bitmap_cdb;
    volatile uint64_t *bitmap_buf, word, complement_word;
    c2_block_t *bitmap_c2b;
    block_t slave_size;
    int idx, bit_idx, word_idx, word_max = (C_BLK_SIZE / sizeof(uint64_t));

    // TODO: slave locks!
    /* We've selected a disk to search for a new block on. Select bitmap block. */
    sb = castle_slave_superblock_get(slave);
    slave_size = sb->size;
    
    debug("Slave size=0x%x\n", slave_size);

    free_cdb = (c_disk_blk_t){slave->uuid, slave->free_blk+1};
    debug("Free block on the slave is: 0x%x\n", free_cdb.block);
    word_idx = cdb_to_bitmap_off(free_cdb) / (sizeof(uint64_t) * 8);
    debug("uint64_t offset is: 0x%x\n", i);
    first_bitmap_cdb = bitmap_cdb = cdb_to_bitmap_cdb(free_cdb);
    debug("first bitmap block: 0x%x\n", first_bitmap_cdb.block);
    goto process_bitmap_cdb;

next_bitmap_cdb:
    debug("==> Selecting next bitmap block.\n");
    debug("0x%x -> ", bitmap_cdb.block);
    unlock_c2b(bitmap_c2b);
    put_c2b(bitmap_c2b);
    bitmap_cdb.block++;
    if(bitmap_cdb.block > blk_to_bitmap_blk(slave_size-1))
        bitmap_cdb.block = FREESPACE_START_BLK;
    debug("0x%x\n", bitmap_cdb.block);
    if(bitmap_cdb.block == first_bitmap_cdb.block)
    {
        debug("Checked all bitmap blocks. Going to the next slave.\n");
        printk("Warning: Could not find a free block on slave(%d, 0x%x), used=%d\n",
                slave->id, slave->uuid, sb->used);
        castle_slave_superblock_put(slave, 0);
        return INVAL_DISK_BLK;
    }
    word_idx=0;

process_bitmap_cdb:
    /* Find first non-zero uint64_t in the bitmap */
    bitmap_c2b = castle_cache_page_block_get(bitmap_cdb);
    lock_c2b(bitmap_c2b);
    if(!c2b_uptodate(bitmap_c2b))
        BUG_ON(submit_c2b_sync(READ, bitmap_c2b));
    bitmap_buf = c2b_buffer(bitmap_c2b);

    for(; word_idx < word_max; word_idx++)
        if(bitmap_buf[word_idx] != 0)
            break;
    debug("First non-zero bitmap block word is at word_idx=%d (word_max=%d)\n",
        word_idx, word_max);

    /* If none of the words were non-zero in the bitmap, goto next bitmap
       block straight away */
    if(word >= word_max) 
        goto next_bitmap_cdb;

    /* Find the first set bit in the first non-zero bitmap word */
    /* We are assuming little endian here */
    word = bitmap_buf[word_idx];
    debug("The non-zero bitmap block word is 0x%.16llx\n", word);
    complement_word = (~word) + 1UL;
    debug("2's completement is               0x%.16llx\n", complement_word);
    word = word & complement_word;
    debug("And is                            0x%.16llx\n", word);
    debug("The set bit is at position        %d\n", fls64(word)-1);
    bit_idx = word_idx * sizeof(uint64_t) * 8 + fls64(word) - 1;
    debug("Found set bit at offset=%d\n", bit_idx);
    BUG_ON(test_bit(bit_idx, bitmap_buf) == 0);
    /* Check if we have at least 'size' set bits after 'bit_idx' */
    /* We might be looking beyond the end of this page */
    if((bit_idx + size > max_word * sizeof(uint64_t) * 8) ||                /* End of bitmap page */
       (bitmap_cdb_to_cdb(bitmap_cdb).block + bit_idx + size > slave_size)) /* End of device      */
        goto next_bitmap_cdb;
    for(idx = 0; idx < size; idx++)
    {
        if(!test_bit(bit_idx + idx, bitmap_buff))
        {
            bit_idx += idx + 1;
            goto TODO;
        }
    
            /* This might be past the end of the block device, check for that */
    free_cdb.block = bitmap_cdb_to_cdb(bitmap_cdb).block + i;
    debug("Free block corresponding to this bit is: 0x%x (slave_size=0x%x)\n", free_cdb.block, slave_size);
    if(free_cdb.block >= slave_size)
        goto next_bitmap_cdb;
    /* If we got here we found a non-set bit, < size of the slave device */
    clear_bit(i, bitmap_buf);
    dirty_c2b(bitmap_c2b);
    unlock_c2b(bitmap_c2b);
    put_c2b(bitmap_c2b);
    /* Book-keeping stuff */
    debug("Free_block is (0x%x, 0x%x), bookkeeping that\n", free_cdb.disk, free_cdb.block);
    slave->free_blk = free_cdb.block;
    castle_freespace_hash_mod(slave, version, HASH_MOD_INC);
    sb->used++;
    castle_slave_superblock_put(slave, 1);

    return free_cdb;
}

#endif

c_disk_blk_t castle_freespace_block_get(version_t version, int size)
{
    static struct castle_slave *last_slave = NULL;
    struct castle_slave *slave, *first_slave = NULL;
    struct list_head *l;
    struct castle_slave_superblock *sb = NULL;
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

    /* Only allocate onto target disks */
    sb = castle_slave_superblock_get(slave);
    if(!(sb->flags & CASTLE_SLAVE_TARGET))
    {
        castle_slave_superblock_put(slave, 0);
        goto next_disk;
    }
    castle_slave_superblock_put(slave, 0);

    debug("Selected slave=0x%x\n", slave->uuid);
    free_cdb = castle_freespace_slave_block_get(slave, version, size);
    if(DISK_BLK_INVAL(free_cdb))
        goto next_disk;

    return free_cdb;
}

void castle_freespace_block_free(c_disk_blk_t cdb, version_t version, int size)
{
    struct castle_slave *slave = castle_slave_find_by_uuid(cdb.disk);
    struct castle_slave_superblock *cs_sb;
    c_disk_blk_t bitmap_cdb;
    c2_block_t *bitmap_c2b;
    volatile uint64_t *bitmap_buf;
    int i, position;

    BUG_ON(!slave);
    bitmap_cdb = cdb_to_bitmap_cdb(cdb);
    bitmap_c2b = castle_cache_page_block_get(bitmap_cdb);
    lock_c2b(bitmap_c2b);
    if(!c2b_uptodate(bitmap_c2b))
        BUG_ON(submit_c2b_sync(READ, bitmap_c2b));
    bitmap_buf = c2b_buffer(bitmap_c2b);
    position = blk_to_bitmap_off(cdb.block);
    debug("Freeing cdb=(0x%x, 0x%x), in freespace_cdb=(0x%x, 0x%x), position=%d, size=%d\n",
            cdb.disk, cdb.block, bitmap_cdb.disk, bitmap_cdb.block, position, size);
    for(i=0; i<size; i++)
    {
        /* Bug if we need to cross page boundry */
        BUG_ON(position + i > C_BLK_SIZE * 8);
        
        if(test_bit(position + i, bitmap_buf))
        {
            printk("Found a set bit @i=%d\n", i);
            continue;
        }
        BUG_ON(test_bit(position + i, bitmap_buf));
        set_bit(position + i, bitmap_buf);
    }
    dirty_c2b(bitmap_c2b);
    unlock_c2b(bitmap_c2b);
    put_c2b(bitmap_c2b);
    
    cs_sb = castle_slave_superblock_get(slave);
    castle_freespace_hash_mod(slave, version, HASH_MOD_DEC);
    cs_sb->used--;
    castle_slave_superblock_put(slave, 1);
}

int castle_freespace_init(void)
{
    /* Initialisation is done when sleves are initialised */
    return 0; 
}

void castle_freespace_fini(void)
{
    struct castle_slave_superblock *cs_sb;
    struct castle_slave_block_cnt *cnt;
    struct castle_flist_node *flist_node;
    struct list_head *l, *h, *ht;
    c_disk_blk_t cdb;
    c2_block_t *c2b;
    int i;

    /* Write the version->count maps for each slave */
    list_for_each(l, &castle_slaves.slaves)
    {
        struct castle_slave *cs = list_entry(l, struct castle_slave, list);

        /* Drop the buffer for last_flist_c2b */
        put_c2b(cs->block_cnts.last_flist_c2b);

        cs_sb = castle_slave_superblock_get(cs);
        cdb = cs_sb->flist_next;
        castle_slave_superblock_put(cs, 0);

        debug("Writing version->cnts map for slave=%d, cdb=(0x%x, 0x%x)\n",
                cs->id, cdb.disk, cdb.block);
        c2b = castle_cache_page_block_get(cdb);
        lock_c2b(c2b);
        if(!c2b_uptodate(c2b))
            BUG_ON(submit_c2b_sync(READ, c2b));
        flist_node = c2b_buffer(c2b);
        flist_node->used = 0;
        for(i=0; i<BLOCKS_HASH_SIZE; i++)
        {
            list_for_each_safe(h, ht, &cs->block_cnts.hash[i])
            {
                cnt = list_entry(h, struct castle_slave_block_cnt, list);
                list_del(h);
                if(flist_node->used >= flist_node->capacity)
                {
                    /* Move on to the next node */
                    cdb = flist_node->next;
                    dirty_c2b(c2b);
                    unlock_c2b(c2b);
                    put_c2b(c2b);

                    c2b = castle_cache_page_block_get(cdb);
                    debug("Next flist block (0x%x, 0x%x).\n", cdb.disk, cdb.block);
                    lock_c2b(c2b);
                    if(!c2b_uptodate(c2b))
                        BUG_ON(submit_c2b_sync(READ, c2b));
                    flist_node = c2b_buffer(c2b);
                    flist_node->used = 0;
                }
                debug("Writing out (version=%d, blocks=%d)\n", cnt->version, cnt->cnt);
                debug("Idx=%d\n", flist_node->used);
                flist_node->slots[flist_node->used].version = cnt->version; 
                flist_node->slots[flist_node->used].blocks  = cnt->cnt; 
                flist_node->used++;
                if(cnt->version != 0) 
                    kfree(cnt); 
            } 
        } 
        dirty_c2b(c2b);
        unlock_c2b(c2b);
        put_c2b(c2b);
    }    
}

#if 0
void castle_freespace_tests(void)
{
    c_disk_blk_t cdb;
    struct castle_slave *cs;
    int i=0;
    static c_disk_blk_t big_blocks[256];
    static c_disk_blk_t mid_blocks[256];
    static c_disk_blk_t sml_blocks[256];

    /* Allocate a single page to get the slave uuid. */
    printk("\n\nAllocating a single page to find out the block id.\n");
    cdb = castle_freespace_block_get(0, 1);
    printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
    cs = castle_slave_find_by_uuid(cdb.disk);
    BUG_ON(!cs);

    for(i=0; i<256; i++)
    {
        printk("\n\nLoop: %d\n", i);
        cdb = big_blocks[i] = castle_freespace_slave_block_get(cs, 0, 256);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
        cdb = mid_blocks[i] = castle_freespace_slave_block_get(cs, 0, 4);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
        cdb = sml_blocks[i] = castle_freespace_slave_block_get(cs, 0, 1);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
    }
    printk("\n\n\nFreeing some blocks.\n");
    for(i=0; i<(256-3); i+=3)
    {
        castle_freespace_block_free(big_blocks[i], 0, 256);
        castle_freespace_block_free(mid_blocks[i+1], 0, 4);
        castle_freespace_block_free(sml_blocks[i+2], 0, 1);
    }
    for(i=0; i<256; i++)
    {
        printk("\n\nLoop: %d\n", i);
        cdb = castle_freespace_slave_block_get(cs, 0, 256);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
        cdb = castle_freespace_slave_block_get(cs, 0, 4);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
        cdb = castle_freespace_slave_block_get(cs, 0, 1);
        printk("Got: (0x%x, 0x%x)\n", cdb.disk, cdb.block);
    }
}
#endif
