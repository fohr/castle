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
        if ((cvt->length <= MAX_INLINE_VAL_SIZE) && (0 == 1)) /* DISABLE INLINE VALUES TEMPORARILY */
        {
            cvt->type = CVT_TYPE_INLINE;
            cvt->val  = kmalloc(cvt->length, GFP_NOIO);
            /* TODO: Work out how to handle this */
            BUG_ON(!cvt->val);
            castle_rxrpc_str_copy(call, cvt->val, cvt->length); 
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

void castle_object_replace_complete(struct castle_bio_vec *c_bvec,
                                    int err,
                                    c_val_tup_t cvt)
{
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c_bio_t *c_bio = c_bvec->c_bio;
    c2_block_t *c2b;

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
        return;
    }

    /* Otherwise, write the entry out. */
    BUG_ON(CVT_INVALID(cvt));
    if(CVT_ONDISK(cvt))
    {
        BUG_ON(cvt.length > C_BLK_SIZE);
        BUG_ON(c_bvec_data_del(c_bvec));
        c2b = castle_cache_page_block_get(cvt.cdb);
        lock_c2b(c2b);
        set_c2b_uptodate(c2b);
#ifdef CASTLE_DEBUG        
        /* Poison the data block */
        memset(c2b_buffer(c2b), 0xf4, C_BLK_SIZE);
#endif
        castle_rxrpc_str_copy(call, c2b_buffer(c2b), cvt.length); 
        dirty_c2b(c2b);
        unlock_c2b(c2b);
        put_c2b(c2b);
    }
    else 
    if(CVT_INLINE(cvt))
    {
        kfree(cvt.val);
    }
    castle_rxrpc_replace_complete(call, 0);
    castle_utils_bio_free(c_bio);
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

void __castle_object_get_complete(struct work_struct *work)
{
    c_bvec_t *c_bvec = container_of(work, c_bvec_t, work);
    struct castle_rxrpc_call *call = c_bvec->c_bio->rxrpc_call;
    c2_block_t *c2b;
    c_val_tup_t cvt;

    castle_rxrpc_call_c2b_cvt_get(call, &c2b, &cvt); 

    BUG_ON(!CVT_ONDISK(cvt));
    BUG_ON(cvt.length > C_BLK_SIZE);

    if(c2b_uptodate(c2b))
        castle_rxrpc_get_complete(call, 0, c2b_buffer(c2b), cvt.length);
    else
        castle_rxrpc_get_complete(call, -EIO, NULL, 0);
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
    c_val_tup_t data_cvt;

    castle_rxrpc_call_c2b_cvt_get(call, &data_c2b, &data_cvt); 
    BUG_ON(c2b != data_c2b);
#endif
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
    int nr_blocks;

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
        castle_rxrpc_get_complete(call, err, NULL, 0);
        castle_utils_bio_free(c_bvec->c_bio);
        return;
    }

    /* Next, handle inline values, since we already have them in memory */
    if(CVT_INLINE(cvt))
    {
        castle_rxrpc_get_complete(call, 0, cvt.val, cvt.length);
        kfree(cvt.val);
        castle_utils_bio_free(c_bvec->c_bio);
        return;
    }

    /* Finally, out of line values */
    BUG_ON(!CVT_ONDISK(cvt));
    nr_blocks = (cvt.length - 1) / C_BLK_SIZE + 1; 
    c2b = castle_cache_block_get(cvt.cdb, nr_blocks);
    castle_rxrpc_call_c2b_cvt_set(call, c2b, cvt);
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
