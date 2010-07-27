#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_da.h"
#include "castle_utils.h"
#include "castle_btree.h"
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
    c_val_tup_t new_cvt = c_bvec->cvt;

    /* TODO: Add support for inline values and larger objects */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE && c_bvec_data_dir(c_bvec) != REMOVE); 
    BUG_ON(c_bvec_data_dir(c_bvec) == REMOVE && (!CVT_TOMB_STONE(new_cvt) ||
           new_cvt.length != 0));
    BUG_ON(CVT_INVALID(new_cvt));

    BUG_ON(CVT_TOMB_STONE(prev_cvt) &&  prev_cvt.length != 0);

    BUG_ON(CVT_ONDISK(new_cvt) && (new_cvt.length % C_BLK_SIZE != 0));
    BUG_ON(CVT_ONDISK(prev_cvt) && (prev_cvt.length % C_BLK_SIZE != 0));

    /* Set cvt with the new value references. Allocate space for new value 
     * on-disk, if required */
    if (CVT_ONDISK(new_cvt) && (new_cvt.length != prev_cvt.length))
    {
        new_cvt.cdb =
            castle_freespace_block_get(c_bvec->version, 
                                       new_cvt.length / C_BLK_SIZE);
        BUG_ON(DISK_BLK_INVAL(cvt->cdb));
    }

    /* Free resources */
    if (CVT_ONDISK(prev_cvt) && (!CVT_ONDISK(new_cvt) ||
                                 !DISK_BLK_EQUAL(prev_cvt.cdb, new_cvt.cdb)))
        castle_freespace_block_free(prev_cvt.cdb,
                                    c_bvec->version,
                                    prev_cvt.length / C_BLK_SIZE);
        
    *cvt = new_cvt;
}

void castle_object_replace_complete(struct castle_bio_vec *c_bvec, int err, 
                                    c_val_tup_t cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b;

    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != WRITE && c_bvec_data_dir(c_bvec) != REMOVE); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Free the key */
    kfree(c_bvec->key);

    /* Deal with error case first */
    if(err)
    {
        castle_rxrpc_replace_complete(call, err);
        return;
    }

    /* Otherwise, write the entry out to the cache */
    BUG_ON(CVT_INVALID(cvt));
    if (CVT_ONDISK(cvt))
    {
        BUG_ON(!DISK_BLK_EQUAL(c_bvec->cvt.cdb, cvt.cdb));
        BUG_ON(c_bvec_data_del(c_bvec));
        c2b = castle_cache_page_block_get(cvt.cdb);
        lock_c2b(c2b);
        set_c2b_uptodate(c2b);
        *((uint32_t *) c2b_buffer(c2b)) = cvt.length - sizeof(uint32_t);
        castle_rxrpc_str_copy(call, ((uint32_t *) c2b_buffer(c2b)) + 1, 
                              cvt.length - sizeof(uint32_t));
        dirty_c2b(c2b);
        unlock_c2b(c2b);
        put_c2b(c2b);
    }
    else if (CVT_INLINE(c_bvec->cvt))
    {
        BUG_ON(c_bvec->cvt.length != cvt.length);
        BUG_ON(c_bvec->cvt.val != cvt.val);
        kfree(c_bvec->cvt.val);
    }
    castle_rxrpc_replace_complete(call, 0);
    castle_utils_bio_free(c_bio);
}

int castle_object_replace(struct castle_rxrpc_call *call, c_vl_key_t **key, int tombstone)
{
    c_vl_key_t *btree_key;
    c_bvec_t *c_bvec;
    c_bio_t *c_bio;
    c_val_tup_t cvt;

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
    CVT_INVALID_SET(cvt);
    /* Tombstone & object replace both require a write */
    if(tombstone) 
    {
        c_bio->data_dir |= REMOVE;
        cvt.type = CVT_TYPE_TOMB_STONE;
    }
    else 
    {
        cvt.length = castle_rxrpc_uint32_get(call) + sizeof(uint32_t);
        if (cvt.length <= MAX_INLINE_VAL_SIZE)
        {
            cvt.type   = CVT_TYPE_INLINE;
            cvt.val    = kmalloc(cvt.length, GFP_NOIO);
            BUG_ON(!cvt.val);
            *((uint32_t *)cvt.val) = cvt.length - sizeof(uint32_t);
            castle_rxrpc_str_copy(call, ((uint32_t *)cvt.val) + 1, 
                                  cvt.length - sizeof(uint32_t));
        }
        else
        {
            cvt.type    = CVT_TYPE_ONDISK;
            cvt.length += C_BLK_SIZE - (cvt.length % C_BLK_SIZE);
        }
    }
    
    c_bvec = c_bio->c_bvecs; 
    c_bvec->key        = btree_key; 
    c_bvec->cvt_get    = castle_object_replace_cvt_get;
    c_bvec->endfind    = castle_object_replace_complete;
    c_bvec->da_endfind = NULL; 
    c_bvec->cvt = cvt;
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}

void __castle_object_get_complete(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c2_block_t *c2b = c_bvec->data_c2b;
    uint32_t *buffer;
    c_val_tup_t cvt = c_bvec->cvt;

    buffer = CVT_ONDISK(cvt)?c2b_buffer(c2b):cvt.val;
    debug("Completed reading buffer for object get.\n"); 
    if (CVT_TOMB_STONE(cvt))
        debug("Value is tomb-stone\n");
    else 
        debug("First word: 0x%x.\n", buffer[0]); 

    BUG_ON(CVT_INLINE(cvt) && (cvt.length != buffer[0] + sizeof(uint32_t)));
    BUG_ON(CVT_ONDISK(cvt) && (cvt.length - buffer[0] == 
                               C_BLK_SIZE - (buffer[0] %  C_BLK_SIZE)));
    if(CVT_TOMB_STONE(cvt))
    { 
        castle_rxrpc_get_complete(call, 0, NULL, 0);
    } 
    else
    {
        castle_rxrpc_get_complete(call, 0, buffer+1, buffer[0]);
    }

    if (CVT_ONDISK(cvt))
    {
        unlock_c2b(c2b);
        put_c2b(c2b);
    }

    if (CVT_INLINE(cvt))
        kfree(cvt.val);

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

void castle_object_get_complete(struct castle_bio_vec *c_bvec, int err,
                                c_val_tup_t cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b;

    debug("Returned from btree walk with value of type 0x%x and length %u\n", 
          (uint32_t)cvt.type, cvt.length );
    /* Sanity checks on the bio */
    BUG_ON(c_bvec_data_dir(c_bvec) != READ); 
    BUG_ON(atomic_read(&c_bio->count) != 1);
    BUG_ON(c_bio->err != 0);

    /* Free the key */
    kfree(c_bvec->key);

    /* Deal with error case first */
    if(err)
    {
        castle_rxrpc_get_complete(call, err, NULL, 0);
        return;
    }

    /* Otherwise, read the relevant disk block */
    if(CVT_INVALID(cvt))
    {
        castle_rxrpc_get_complete(call, 0, NULL, 0);
        return;
    }

    c_bvec->cvt = cvt;
    /* TODO: Handle inline values */
    if (CVT_ONDISK(cvt)) 
    {
        BUG_ON(cvt.length % C_BLK_SIZE);
        c2b = castle_cache_block_get(cvt.cdb, cvt.length / C_BLK_SIZE);
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
    else 
        __castle_object_get_complete(&c_bvec->work);
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
    CVT_INVALID_SET(c_bvec->cvt);
    
    /* TODO: add bios to the debugger! */ 

    castle_double_array_find(c_bvec);

    return 0;
}
