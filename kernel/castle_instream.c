#include "castle_instream.h"

void castle_instream_batch_proc_construct(c_instream_batch_proc *batch_proc,
                                         char* buf,
                                         size_t buf_len_bytes)
{
    BUG_ON(!batch_proc); /* caller must alloc! */
    BUG_ON(!buf);
    batch_proc->batch_buf = buf;
    batch_proc->batch_buf_len_bytes = buf_len_bytes;

    batch_proc->cursor = batch_proc->batch_buf;
    batch_proc->bytes_consumed = 0;
}

/* return -ESPIPE when cursor reaches or moves beyond buffer bound */
static int _castle_insteam_cursor_forward_bound_check(c_instream_batch_proc *batch_proc, size_t bytes)
{
    if (batch_proc->bytes_consumed + bytes >= batch_proc->batch_buf_len_bytes)
        return -ESPIPE;
    return 0;
}

/* move cursor forward (subject to buffer bounds) */
static int castle_instream_batch_proc_cursor_advance(c_instream_batch_proc *batch_proc, size_t bytes)
{
    int ret;
    if((ret = _castle_insteam_cursor_forward_bound_check(batch_proc, bytes)))
        return ret;
    batch_proc->cursor += bytes;
    batch_proc->bytes_consumed += bytes;
    return 0;
}

/* memcpy then advance cursor */
static int castle_instream_batch_consume(char *dst, c_instream_batch_proc *batch_proc, size_t bytes)
{
    int ret;
    BUG_ON(!dst); /* caller provides buffer */
    if((ret = _castle_insteam_cursor_forward_bound_check(batch_proc, bytes)))
        return ret;
    memcpy(dst, batch_proc->cursor, bytes);
    BUG_ON(castle_instream_batch_proc_cursor_advance(batch_proc, bytes));
    return 0;
}

/* return ENOSR when batch buffer processing complete */
int castle_instream_batch_proc_next(c_instream_batch_proc *batch_proc, void ** raw_key, c_val_tup_t *cvt)
{
    c_stream_entry_hdr entry_hdr;
    void *val;

    BUG_ON(!batch_proc);

    /* caller must provide these containers: */
    BUG_ON(!raw_key);
    BUG_ON(!cvt);

    /* It is assumed that the cursor is now pointing at the start of a new key/val/timestamp tupe */

    /* Get the entry header... */
    if (castle_instream_batch_consume((char *)&entry_hdr, batch_proc, sizeof(entry_hdr)))
    {
        /* Failed to glob a new entry header... is it EOF? */

        unsigned char hdr_type;
        if (castle_instream_batch_consume(&hdr_type, batch_proc, sizeof(unsigned char)))
            return ENOSR; /* can't even get one more byte; must be EOF. */

        /* Got another byte, it must be a header type field with the NULL flag */
        BUG_ON(hdr_type != CASTLE_STREAMING_ENTRY_HEADER_TYPE_NULL);
        return ENOSR;
    }
    //castle_printk(LOG_UNLIMITED, "%s::entry_hdr, type:%u, timestamp: %llu, key_length:%u, val_length: %llu\n",
    //    __FUNCTION__, entry_hdr.type, entry_hdr.timestamp, entry_hdr.key_length, entry_hdr.val_length);

    if (entry_hdr.key_length > VLBA_TREE_MAX_KEY_SIZE) /* This is a bad bug! Userspace corruption? */
    {
        castle_printk(LOG_ERROR, "%s::got key_length %lu; userspace corruption?\n",
            __FUNCTION__, entry_hdr.key_length);
        return -E2BIG;
    }
    if (entry_hdr.val_length > MAX_INLINE_VAL_SIZE) /* This is probably user error. */
    {
        castle_printk(LOG_ERROR, "%s::got val_length %llu; user error?\n",
            __FUNCTION__, entry_hdr.val_length);
        return -ENOSPC;
    }

    if (entry_hdr.type == CASTLE_STREAMING_ENTRY_HEADER_TYPE_NULL)
        return ENOSR; /* EOF */

    *raw_key = batch_proc->cursor; /* Key follows the header */
    /* New raw key pointer obtained (caller does key packing). */

    if (castle_instream_batch_proc_cursor_advance(batch_proc, entry_hdr.key_length))
    {
        castle_printk(LOG_ERROR, "%s::something screwy is going on, entry_hdr: %p batch_proc: %p\n",
            __FUNCTION__, &entry_hdr, batch_proc);
        BUG();
    }
    val = batch_proc->cursor; /* Value follows the key */

    /* Build up the cvt */
    cvt->user_timestamp = entry_hdr.timestamp;

    switch (entry_hdr.type)
    {
        case CASTLE_STREAMING_ENTRY_HEADER_TYPE_NULL:
            BUG();
            break; /* ;-) */
        case CASTLE_STREAMING_ENTRY_HEADER_TYPE_VALUE:
            CVT_INLINE_INIT(*cvt, entry_hdr.val_length, val);
            break;
        default:
            castle_printk(LOG_UNLIMITED, "%s::TODO\n", __FUNCTION__);
            BUG(); /* all other cvt types not yet implemented */
            break;
    }

    if (castle_instream_batch_proc_cursor_advance(batch_proc, entry_hdr.val_length))
    {
        /* Hmmm, we failed to move ahead of the value segment... is this the end? */
        if (castle_instream_batch_proc_cursor_advance(batch_proc, entry_hdr.val_length-1))
            BUG(); /* can't even seek to the expected end of the val */
        else
            return ENOSR; /* Nothing beyond this value; assume it's EOF */
    }

    return 0;
}

void castle_instream_batch_proc_destroy(c_instream_batch_proc *batch_proc)
{
    /* NoOp... for now... but please use it anyway!!! */
    BUG_ON(0);
}

static int castle_instream_batch_proc_2_entries_unit_test(void)
{
    char input_batch[1024] = {0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x05, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x61, 0x68, 0x65, 0x6c, 0x6c, 0x6f,
                              0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x15, 0x00, 0x00, 0x00, 0x05, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x11, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                              0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x62, 0x77, 0x6f, 0x72, 0x6c, 0x64, 0x00};
    c_instream_batch_proc proc;
    struct castle_btree_type *btree = castle_btree_type_get(SLIM_TREE_TYPE);
    void * raw_key = NULL;
    void * key = NULL;
    c_val_tup_t cvt;
    int err;
    int entries_found = 0;

    castle_instream_batch_proc_construct(&proc, input_batch, 1020);
    while(!(err = castle_instream_batch_proc_next(&proc, &raw_key, &cvt)))
    {
        char val_buf[6];
        memset(val_buf, 0, 6);

        key = btree->key_pack(raw_key, NULL, NULL);
        BUG_ON(!CVT_INLINE(cvt));
        BUG_ON(cvt.length != 5);
        memcpy(val_buf, cvt.val_p, cvt.length);

        castle_printk(LOG_DEVEL, "%s::key: \n", __FUNCTION__);
        btree->key_print(LOG_DEVEL, key);
        castle_printk(LOG_DEVEL, "%s::val: %s\n", __FUNCTION__, val_buf);

        entries_found++;
        castle_free(key);
    }
    BUG_ON(err != ENOSR);
    BUG_ON(entries_found != 2);
    castle_instream_batch_proc_destroy(&proc);
    return 0;
}

int castle_instream_unit_tests_do(void)
{
    int test_seq_id = 0;
    int err = 0;

    test_seq_id++; if (0 != (err = castle_instream_batch_proc_2_entries_unit_test()) ) goto fail;

    BUG_ON(err);
    castle_printk(LOG_INIT, "%s::%d tests passed.\n", __FUNCTION__, test_seq_id);
    return 0;
fail:
    castle_printk(LOG_ERROR, "%s::test %d failed with return code %d.\n",
            __FUNCTION__, test_seq_id, err);
    return err;
}

