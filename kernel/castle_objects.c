#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_rxrpc.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#else
#define debug(_f, _a...)        (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

   
static const uint32_t OBJ_TOMBSTONE = ((uint32_t)-1);
extern struct castle_attachment *global_attachment_hack;


void castle_object_replace_complete(struct castle_bio_vec *c_bvec, int err, c_disk_blk_t cdb)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b;

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Deal with error case first */
    if(err)
    {
        castle_rxrpc_replace_complete(call, err);
        return;
    }

    /* Otherwise, write the entry out to the cache */
    BUG_ON(DISK_BLK_INVAL(cdb));
    c2b = castle_cache_page_block_get(cdb);
    lock_c2b(c2b);
    set_c2b_uptodate(c2b);
    if(c_bvec_data_del(c_bvec))
        memcpy(c2b_buffer(c2b), &OBJ_TOMBSTONE, 4); 
    else
        castle_rxrpc_str_copy(call, c2b_buffer(c2b), PAGE_SIZE);
    dirty_c2b(c2b);
    unlock_c2b(c2b);
    put_c2b(c2b);
        
    castle_rxrpc_replace_complete(call, 0);
    castle_utils_bio_free(c_bio);
}

int castle_object_replace(struct castle_rxrpc_call *call, uint8_t **key, int tombstone)
{
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    uint64_t noddy_key;
    int i;

    memcpy(&noddy_key, key[0], 8);
    for(i=0; key[i]; i++)
    {
#if 0
        printk(" key[%d]         : ", i);
        print_hex_dump_bytes("", DUMP_PREFIX_NONE, key[i], strlen(key[i]));
#endif    
        kfree(key[i]);
    }
    kfree(key);
    //printk(" value          : %s\n", tombstone ? "tombstone" : "object");
    //printk(" Noddy key=%llx\n", noddy_key);

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM;
    BUG_ON(!global_attachment_hack);
    c_bio->attachment    = global_attachment_hack;
    c_bio->rxrpc_call    = call;
    /* Tombstone & object replace both require a write */
    c_bio->data_dir      = WRITE;
    if(tombstone)
        c_bio->data_dir |= REMOVE;

    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = (void *)noddy_key; 
    c_bvec->endfind    = castle_object_replace_complete;
    c_bvec->da_endfind = NULL; 
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}

void __castle_object_get_complete(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c2_block_t *c2b = c_bvec->data_c2b;
    uint32_t *buffer = c2b_buffer(c2b);

    debug("Completed reading buffer for object get.\n"); 
    debug("First word: 0x%x.\n", buffer[0]); 

    BUG_ON(buffer[0] > PAGE_SIZE - 4);
    if(buffer[0] == OBJ_TOMBSTONE)
    { 
        castle_rxrpc_get_complete(call, 0, NULL, 0);
    } else
    {
        castle_rxrpc_get_complete(call, 0, buffer+1, buffer[0]);
    }
    unlock_c2b(c2b);
    put_c2b(c2b);
    castle_utils_bio_free(c_bvec->c_bio);
}

void castle_object_get_io_end(c2_block_t *c2b, int uptodate)
{
    c_bvec_t *c_bvec = c2b->private;

    if(uptodate)
        set_c2b_uptodate(c2b);

    INIT_WORK(&c_bvec->work, __castle_object_get_complete);
    queue_work(castle_wq, &c_bvec->work); 
}

void castle_object_get_complete(struct castle_bio_vec *c_bvec, int err, c_disk_blk_t cdb)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b;

    debug("Returned from btree walk with cdb=(0x%x, 0x%x)\n", cdb.disk, cdb.block);
    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != READ); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Deal with error case first */
    if(err)
    {
        castle_rxrpc_get_complete(call, err, NULL, 0);
        return;
    }

    /* Otherwise, read the relevant disk block */
    if(DISK_BLK_INVAL(cdb))
    {
        castle_rxrpc_get_complete(call, 0, NULL, 0);
        return;
    }
    c2b = castle_cache_page_block_get(cdb);
    c_bvec->data_c2b = c2b;
    lock_c2b(c2b);
    
    if(!c2b_uptodate(c2b))
    {
        /* If the buffer doesn't contain up to date data, schedule the IO */
        c2b->private = c_bvec;
        c2b->end_io = castle_object_get_io_end;
        BUG_ON(submit_c2b(READ, c2b));
    } else
    {
        __castle_object_get_complete(&c_bvec->work);
    }
}

int castle_object_get(struct castle_rxrpc_call *call, uint8_t **key)
{
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    uint64_t noddy_key;
    int i;

    memcpy(&noddy_key, key[0], 8);
    for(i=0; key[i]; i++)
    {
#if 0        
        printk(" key[%d]         : ", i);
        print_hex_dump_bytes("", DUMP_PREFIX_NONE, key[i], strlen(key[i]));
#endif
        kfree(key[i]);
    }
    kfree(key);
#if 0
    printk(" Noddy key=%llx\n", noddy_key);
#endif

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM;
    BUG_ON(!global_attachment_hack);
    c_bio->attachment    = global_attachment_hack;
    c_bio->rxrpc_call    = call;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = (void *)noddy_key; 
    c_bvec->endfind    = castle_object_get_complete;
    c_bvec->da_endfind = NULL; 
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}
