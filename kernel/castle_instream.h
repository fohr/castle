#ifndef __CASTLE_INSTREAM_H__
#define __CASTLE_INSTREAM_H__

#include "castle.h"
#include "castle_defines.h"
#include "castle_utils.h"
#include "castle_btree.h"

typedef struct castle_instream_batch_processor
{
    char * batch_buf;
    size_t batch_buf_len_bytes;
    char * cursor;
    size_t bytes_consumed;
} c_instream_batch_proc;

//////// TODO: copy this to libcastle and make streaming.hg use it
#define CASTLE_STREAMING_ENTRY_HEADER_TYPE_NULL        (0)
#define CASTLE_STREAMING_ENTRY_HEADER_TYPE_VALUE       (1)
#define CASTLE_STREAMING_ENTRY_HEADER_TYPE_COUNTER_SET (2)
#define CASTLE_STREAMING_ENTRY_HEADER_TYPE_COUNTER_ADD (3)
#define CASTLE_STREAMING_ENTRY_HEADER_TYPE_TOMBSTONE   (4)

struct castle_streaming_entry_header
{
    unsigned char type;
    castle_user_timestamp_t timestamp;
    uint32_t key_length;
    uint64_t val_length;
} PACKED;
typedef struct castle_streaming_entry_header c_stream_entry_hdr;
////////////////////////////////////////////////////////////////////////

void castle_instream_batch_proc_construct(c_instream_batch_proc *batch_proc,
                                          char* buf,
                                          size_t buf_len_bytes);
int castle_instream_batch_proc_next(c_instream_batch_proc *batch_proc, void ** raw_key, c_val_tup_t *cvt);

void castle_instream_batch_proc_destroy(c_instream_batch_proc *batch_proc);

#endif
