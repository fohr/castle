#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_btree.h"
#include "castle_cache.h"
#include "castle_freespace.h"
#include "castle_rxrpc.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)          ((void)0)
#else
#define debug(_f, _a...)        (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

   
static const uint32_t OBJ_TOMBSTONE = ((uint32_t)-1);
extern struct castle_attachment *global_attachment_hack;

/* Converts 'object key' (i.e. multidimensional key) to btree key (single dimensional) */
static c_vl_key_t* castle_object_key_convert(c_vl_key_t **obj_key)
{
    c_vl_key_t *btree_key;
    uint32_t max_len = 0;
    int i, nr_keys = 0;

    /* Work out the maximum length of the keys, and number of keys in the array */
    while(obj_key[nr_keys])
    {
        max_len = max_len < obj_key[nr_keys]->length ? obj_key[nr_keys]->length : max_len;
        nr_keys++;
    }

    /* Allocate the single-dimensional key */
    btree_key = kzalloc(sizeof(c_vl_key_t) + max_len * nr_keys, GFP_KERNEL);
    if(!btree_key)
        return NULL;

    /* Construct interleaved key */
    btree_key->length = max_len * nr_keys;
    for(i=0; i<btree_key->length; i++)
        if(i / nr_keys < obj_key[i % nr_keys]->length)
            btree_key->key[i] = obj_key[i % nr_keys]->key[i / nr_keys];

    return btree_key;
}

static void castle_object_key_free(c_vl_key_t **obj_key)
{
    int i;

    for(i=0; obj_key[i]; i++)
        kfree(obj_key[i]);
    kfree(obj_key);
}

static void castle_object_replace_cvt_get(c_bvec_t    *c_bvec,
                                          c_val_tup_t  prev_cvt,
                                          c_val_tup_t *cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    int tombstone = c_bvec_data_del(c_bvec); 
    int nr_blocks;

    /* We should be handling a write (possibly a tombstone write). */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 
    /* Some sanity checks */
    BUG_ON(CVT_TOMB_STONE(prev_cvt) && (prev_cvt.length != 0));

    /* Allocate space for new value, in or out of line */ 
    if(!tombstone)
    {
        /* The packet will now contain the length of the data payload */
        cvt->length = castle_rxrpc_uint32_get(call);
        /* Decide whether to use inline, or out-of-line value on the 
           basis of this length. */
        if (cvt->length <= MAX_INLINE_VAL_SIZE)
        {
            cvt->type = CVT_TYPE_INLINE;
            cvt->val  = kmalloc(cvt->length, GFP_NOIO);
            /* TODO: Work out how to handle this */
            BUG_ON(!cvt->val);
            /* We should not inline values which do not fit in a packet */
            BUG_ON(castle_rxrpc_packet_length(call) < cvt->length);
            castle_rxrpc_str_copy(call, cvt->val, cvt->length, 0 /* not partial */); 
        }
        else
        {
            nr_blocks = (cvt->length - 1) / C_BLK_SIZE + 1; 
            /* Arbitrary limits on the size of the objets (freespace code cannot handle
               huge objects ATM) */
            BUG_ON(nr_blocks > 100); 
            cvt->type   = CVT_TYPE_ONDISK;
            cvt->cdb    = castle_freespace_block_get(c_bvec->version, nr_blocks); 
            /* TODO: Again, work out how to handle failed allocations */ 
            BUG_ON(DISK_BLK_INVAL(cvt->cdb));
         }

    } else
    /* For tombstones, construct the cvt and exit. */
    {
        CVT_TOMB_STONE_SET(*cvt);
    }

    /* If there was an out-of-line object stored under this key, release it. */
    if (CVT_ONDISK(prev_cvt))
    {
        nr_blocks = (prev_cvt.length - 1) / C_BLK_SIZE + 1; 
        castle_freespace_block_free(prev_cvt.cdb,
                                    c_bvec->version,
                                    nr_blocks);
    }
    BUG_ON(CVT_INVALID(*cvt));
}

#define OBJ_IO_MAX_BUFFER_SIZE      (10)    /* In C_BLK_SIZE blocks */

static c_disk_blk_t castle_object_write_next_cdb(struct castle_rxrpc_call *call,
                                                 c_disk_blk_t old_cdb,
                                                 uint32_t data_length)
{
    uint32_t data_c2b_length;
    c_disk_blk_t new_data_cdb;
    int nr_blocks;

    /* Work out how large buffer to allocate */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1; 
    debug("Allocating new buffer of size %d blocks, for data_length=%d\n",
        nr_blocks, data_length);
    new_data_cdb.disk  = old_cdb.disk; 
    new_data_cdb.block = old_cdb.block + nr_blocks; 

    return new_data_cdb;
}

static c2_block_t* castle_object_write_buffer_alloc(struct castle_rxrpc_call *call,
                                                    c_disk_blk_t new_data_cdb,
                                                    uint32_t data_length)
{
    uint32_t data_c2b_length;
    c2_block_t *new_data_c2b;
    int nr_blocks;

    /* Work out how large the buffer is */
    data_c2b_length = data_length > OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE ?
                                    OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE :
                                    data_length;
    nr_blocks = (data_c2b_length - 1) / C_BLK_SIZE + 1; 
    new_data_c2b = castle_cache_block_get(new_data_cdb, nr_blocks);
    lock_c2b(new_data_c2b);
    set_c2b_uptodate(new_data_c2b);
#ifdef CASTLE_DEBUG        
    /* Poison the data block */
    memset(c2b_buffer(new_data_c2b), 0xf4, nr_blocks * C_BLK_SIZE);
#endif
 
    return new_data_c2b;
}

static int castle_object_data_write(struct castle_rxrpc_call *call)
{
    c2_block_t *data_c2b;
    uint32_t data_c2b_offset, data_c2b_length, data_length, packet_length;
    c2_block_t *new_data_c2b;
    c_disk_blk_t new_data_cdb;

    /* Work out how much data we've got, and how far we've got so far */
    castle_rxrpc_replace_call_get(call, &data_c2b, &data_c2b_offset, &data_length);
    debug("Data write. call=%p, data_c2b=%p, data_c2b_offset=%d, data_length=%d\n",
        call, data_c2b, data_c2b_offset, data_length);
    data_c2b_length = data_c2b->nr_pages * C_BLK_SIZE;
    packet_length = castle_rxrpc_packet_length(call);

    debug("Packet length=%d, data_length=%d\n", packet_length, data_length);
    BUG_ON(packet_length <= 0);
    do {
        char *data_c2b_buffer;
        int copy_length;
        int last_copy;

        BUG_ON(data_c2b_offset >= data_c2b_length);
        data_c2b_buffer = (char *)c2b_buffer(data_c2b) + data_c2b_offset; 
        copy_length = data_c2b_length - data_c2b_offset >= packet_length ? 
                                           packet_length :
                                           data_c2b_length - data_c2b_offset;
        debug("Could copy %d bytes.\n", copy_length);
        last_copy = 0;
        if(copy_length >= data_length)
        {
            debug("data_length=%d is smaller than copy_length=%d, resetting copy_length.\n", 
                    data_length, copy_length);
            last_copy = 1;
            copy_length = data_length;
        }
        castle_rxrpc_str_copy(call, 
                              data_c2b_buffer,
                              copy_length,
                              last_copy ? 0 : 1);

        data_length     -= copy_length;
        data_c2b_offset += copy_length;
        /* For last copy more bytes might have been pulled, work out how many */
        if(last_copy)
            copy_length += (copy_length % 4 == 0 ? 0 : 4 - copy_length % 4);
        debug("Read %d bytes from the packet.\n", copy_length);
        packet_length   -= copy_length;


        /* Allocate a new buffer if there will be more data (either in the current
           packet, or in future packets). */
        if((data_c2b_offset == data_c2b_length) && (data_length > 0))
        {
            debug("Run out of buffer space, allocating a new one.\n");
            new_data_cdb = castle_object_write_next_cdb(call, data_c2b->cdb, data_length); 
            new_data_c2b = castle_object_write_buffer_alloc(call, new_data_cdb, data_length); 
            data_c2b_length = new_data_c2b->nr_pages * C_BLK_SIZE;
            data_c2b_offset = 0;
            /* Release the (old) buffer */
            dirty_c2b(data_c2b);
            unlock_c2b(data_c2b);
            put_c2b(data_c2b);
            /* Swap the new buffer in, if one was initialised. */
            data_c2b = new_data_c2b;
        } 
    }
    while((packet_length > 0) && (data_length > 0));

    debug("Exiting data_write with data_c2b_offset=%d, data_length=%d, data_c2b=%p\n", 
            data_c2b_offset, data_length, data_c2b);
    castle_rxrpc_replace_call_set(call, data_c2b, data_c2b_offset, data_length);

    return (data_length == 0);
}
                                     

void castle_object_replace_complete(struct castle_bio_vec *c_bvec,
                                    int err,
                                    c_val_tup_t cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b = NULL;
    int complete_write;

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Free the key */
    kfree(c_bvec->key);

    /* Deal with error case first */
    if(err)
    {
        castle_rxrpc_replace_complete(call, err);
        castle_utils_bio_free(c_bio);
        return;
    }

    /* Otherwise, write the entry out. */
    BUG_ON(CVT_INVALID(cvt));
    if(CVT_ONDISK(cvt))
    {
        BUG_ON(c_bvec_data_del(c_bvec));
        c2b = castle_object_write_buffer_alloc(call, cvt.cdb, cvt.length); 
        castle_rxrpc_replace_call_set(call, c2b, 0, cvt.length); 
        complete_write = castle_object_data_write(call);
    }
    else 
    if(CVT_INLINE(cvt))
    {
        complete_write = 1;
        kfree(cvt.val);
    }
        
        
    /* Unlock buffers, and complete the call if we are done already */
    if(complete_write)
    {
        debug("Completing the write. c2b=%p\n", c2b);
        if(c2b)
        {
            dirty_c2b(c2b);
            unlock_c2b(c2b);
            put_c2b(c2b);
        }
 
        castle_rxrpc_replace_complete(call, 0);
    } else
    /* Complete the packet, so that the client sends us more. */
    {
        debug("Completing the packet, continuing the rest of the write.\n");
        castle_rxrpc_replace_continue(call);
    }

    castle_utils_bio_free(c_bio);
}

int castle_object_replace_continue(struct castle_rxrpc_call *call, int last)
{
    int copy_end;

    debug("Replace continue.\n");
    copy_end = castle_object_data_write(call);
    if(copy_end != last)
        printk("Warning packet for completed replace!!.\n");
    if(last)
    {
        c2_block_t *data_c2b;
        uint32_t data_c2b_offset, data_length;

        castle_rxrpc_replace_call_get(call, &data_c2b, &data_c2b_offset, &data_length);
        BUG_ON(data_length != 0);
        dirty_c2b(data_c2b);
        unlock_c2b(data_c2b);
        put_c2b(data_c2b);
        castle_rxrpc_replace_complete(call, 0);
    } else
    {
        castle_rxrpc_replace_continue(call);
    }

    return 0;
}

int castle_object_replace(struct castle_rxrpc_call *call, c_vl_key_t **key, int tombstone)
{
    c_vl_key_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;

    btree_key = castle_object_key_convert(key);
    castle_object_key_free(key);
    
    //printk(" value          : %s\n", tombstone ? "tombstone" : "object");
    //printk("Btree key is:");
    //vl_key_print(btree_key);

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM;
    BUG_ON(!global_attachment_hack);
    c_bio->attachment    = global_attachment_hack;
    c_bio->rxrpc_call    = call;
    c_bio->data_dir      = WRITE;
    /* Tombstone & object replace both require a write */
    if(tombstone) 
        c_bio->data_dir |= REMOVE;
    
    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = btree_key; 
    c_bvec->cvt_get    = castle_object_replace_cvt_get;
    c_bvec->endfind    = castle_object_replace_complete;
    c_bvec->da_endfind = NULL; 
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}

void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_rxrpc_call *call,
                                c_disk_blk_t data_cdb,
                                uint32_t data_length);
void __castle_object_get_complete(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c2_block_t *c2b;
    uint32_t data_c2b_length, data_length;
    c_disk_blk_t cdb;
    int first, last;

    castle_rxrpc_get_call_get(call, &c2b, &data_c2b_length, &data_length, &first);
    debug("Get complete for call %p, first=%d, c2b->cdb=(0x%x, 0x%x), "
           "data_c2b_length=%d, data_length=%d\n", 
        call, first, c2b->cdb.disk, c2b->cdb.block, data_c2b_length, data_length);
    /* Deal with error case first */
    if(!c2b_uptodate(c2b))
    {
        debug("Not up to date.\n");
        if(first)
            castle_rxrpc_get_reply_start(call, -EIO, 0, NULL, 0);
        else
            castle_rxrpc_get_reply_continue(call, -EIO, NULL, 0, 1 /* last */);
        goto out;
    }
    
    /* If data_length is zero, it means we are supposed to finish this get call */
    last = (data_length == 0);
    debug("Last=%d\n", last);
    if(first)
        castle_rxrpc_get_reply_start(call, 
                                     0,
                                     data_c2b_length + data_length,
                                     c2b_buffer(c2b), 
                                     data_c2b_length);
    else
        castle_rxrpc_get_reply_continue(call, 
                                        0, 
                                        c2b_buffer(c2b), 
                                        data_c2b_length,
                                        last);

    if(last)
        goto out;
        
    BUG_ON(data_c2b_length != OBJ_IO_MAX_BUFFER_SIZE * C_BLK_SIZE);
    cdb.disk  = c2b->cdb.disk;
    cdb.block = c2b->cdb.block + OBJ_IO_MAX_BUFFER_SIZE;
    debug("Continuing for cdb=(0x%x, 0x%x)\n", cdb.disk, cdb.block);   
    /* TODO: Work out if we don't go into unbound recursion here */
    castle_rxrpc_get_call_set(call, c2b, data_c2b_length, data_length, 0 /* not first any more */);
    castle_object_get_continue(c_bvec,
                               call,
                               cdb,
                               data_length);
    return;

out:    
    debug("Finishing with call %p, putting c2b->cdb=(0x%x, 0x%x)\n",
        call, c2b->cdb.disk, c2b->cdb.block);
    unlock_c2b(c2b);
    put_c2b(c2b);

    castle_utils_bio_free(c_bvec->c_bio);
}

void castle_object_get_io_end(c2_block_t *c2b, int uptodate)
{
    c_bvec_t *c_bvec = c2b->private;
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
#ifdef CASTLE_DEBUG    
    c2_block_t *data_c2b;
    uint32_t data_length, data_c2b_length;
    int first;

    castle_rxrpc_get_call_get(call, &data_c2b, &data_c2b_length, &data_length, &first); 
    BUG_ON(c2b != data_c2b);
#endif
    debug("IO end for cdb (0x%x, 0x%x), uptodate=%d\n", 
            c2b->cdb.disk, c2b->cdb.block, uptodate);
    if(uptodate)
        set_c2b_uptodate(c2b);

    INIT_WORK(&c_bvec->work, __castle_object_get_complete);
    queue_work(castle_wq, &c_bvec->work); 
}

void castle_object_get_continue(struct castle_bio_vec *c_bvec,
                                struct castle_rxrpc_call *call,
                                c_disk_blk_t data_cdb,
                                uint32_t data_length)
{
    c2_block_t *c2b, *old_c2b;
    int nr_blocks, first;
    uint32_t data_c2b_length, old_data_length;
    
    BUG_ON(c_bvec->c_bio->rxrpc_call != call);
    castle_rxrpc_get_call_get(call, &old_c2b, &data_c2b_length, &old_data_length, &first);
    debug("get_continue for call %p, data_c2b_length=%d, "
           "old_data_length=%d, data_length=%d, first=%d\n", 
        call, data_c2b_length, old_data_length, data_length, first);
    BUG_ON(data_length != old_data_length);
    /* If old_c2b exists, we must have completed a MAX chunk */
    BUG_ON( old_c2b &&
           (old_c2b->cdb.disk != data_cdb.disk) &&
           (old_c2b->cdb.block + OBJ_IO_MAX_BUFFER_SIZE != data_cdb.block));

    nr_blocks = (data_length - 1) / C_BLK_SIZE + 1; 
    debug("Nr blocks required for entire data: %d\n", nr_blocks);
    /* Work out if we can read the (remaining part of the) object in full,
       or if we are going to be reading just a part of it */
    if(nr_blocks > OBJ_IO_MAX_BUFFER_SIZE)
    {
        nr_blocks = OBJ_IO_MAX_BUFFER_SIZE;
        data_c2b_length = nr_blocks * C_BLK_SIZE;
        debug("Too many blocks required, reducing to %d\n", nr_blocks);
    } else
    {
        data_c2b_length = data_length;
    }
    debug("data_c2b_length=%d, data_length=%d\n", data_c2b_length, data_length);
    data_length -= data_c2b_length; 
    
    debug("Locking cdb (0x%x, 0x%x)\n", data_cdb.disk, data_cdb.block);
    c2b = castle_cache_block_get(data_cdb, nr_blocks);
    lock_c2b(c2b);
    castle_rxrpc_get_call_set(call, c2b, data_c2b_length, data_length, first);
    /* Unlock the old c2b if we had one */
    if(old_c2b)
    {
        debug("Unlocking old_cdb (0x%x, 0x%x)\n", old_c2b->cdb.disk, old_c2b->cdb.block);
        unlock_c2b(old_c2b);
        put_c2b(old_c2b);
    }

    debug("c2b uptodate: %d\n", c2b_uptodate(c2b));
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

void castle_object_get_complete(struct castle_bio_vec *c_bvec, 
                                int err,
                                c_val_tup_t cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;

    debug("Returned from btree walk with value of type 0x%x and length %u\n", 
          cvt.type, cvt.length);
    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != READ); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Free the key */
    kfree(c_bvec->key);

    /* Deal with error case, or non-existant value. */
    if(err || CVT_INVALID(cvt) || CVT_TOMB_STONE(cvt))
    {
        debug("Error, invalid or tombstone.\n");
        castle_rxrpc_get_reply_start(call, err, 0, NULL, 0);
        castle_utils_bio_free(c_bvec->c_bio);
        return;
    }

    /* Next, handle inline values, since we already have them in memory */
    if(CVT_INLINE(cvt))
    {
        debug("Inline.\n");
        castle_rxrpc_get_reply_start(call, 0, cvt.length, cvt.val, cvt.length);
        kfree(cvt.val);
        castle_utils_bio_free(c_bvec->c_bio);
        return;
    }

    debug("Out of line.\n");
    /* Finally, out of line values */
    BUG_ON(!CVT_ONDISK(cvt));
    /* Init the variables stored in the call correctly, so that _continue() doesn't
       get confused */
    castle_rxrpc_get_call_set(call, NULL, 0, cvt.length, 1 /* first */);
    castle_object_get_continue(c_bvec, call, cvt.cdb, cvt.length);
}

int castle_object_get(struct castle_rxrpc_call *call, c_vl_key_t **key)
{
    c_vl_key_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;

    btree_key = castle_object_key_convert(key);
    castle_object_key_free(key);

    /* Single c_bvec for the bio */
    c_bio = castle_utils_bio_alloc(1);
    if(!c_bio)
        return -ENOMEM;
    BUG_ON(!global_attachment_hack);
    c_bio->attachment    = global_attachment_hack;
    c_bio->rxrpc_call    = call;
    c_bio->data_dir      = READ;

    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = btree_key; 
    /* Callback cvt_get() is not required for READ */
    c_bvec->cvt_get    = NULL;
    c_bvec->endfind    = castle_object_get_complete;
    c_bvec->da_endfind = NULL; 
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}
