#ifndef __CASTLE_RXRPC_H__
#define __CASTLE_RXRPC_H__

/* Definitions for RxRPC/XDR marshalling */
#define CASTLE_OBJ_REQ_GET                       0
#define CASTLE_OBJ_REQ_REPLACE                   1
#define CASTLE_OBJ_REQ_SLICE                     5
#define CASTLE_CTRL_REQ                          7

#define CASTLE_OBJ_REPLY_REPLACE                 2
#define CASTLE_OBJ_REPLY_GET                     3
#define CASTLE_OBJ_REPLY_ERROR                   4
#define CASTLE_OBJ_REPLY_GET_SLICE               6
#define CASTLE_CTRL_REPLY                        8
#define CASTLE_OBJ_REQ_REPLACE_MULTI             15

/* Subtypes for CASTLE_REPLACE_REQ */
#define CASTLE_OBJ_TOMBSTONE                     0
#define CASTLE_OBJ_VALUE                         1

uint32_t castle_rxrpc_packet_length      (struct castle_rxrpc_call *call);
void     castle_rxrpc_str_copy           (struct castle_rxrpc_call *call, 
                                          void *buffer, 
                                          int str_length, 
                                          int partial);

uint32_t castle_rxrpc_uint32_get_buf     (struct castle_rxrpc_call *call);
void     castle_rxrpc_str_copy_buf       (struct castle_rxrpc_call *call,
                                          void *buffer,
                                          int str_length,
                                          int partial);
                                         
void     castle_rxrpc_replace_multi_continue
                                         (struct castle_rxrpc_call *call);
void     castle_rxrpc_replace_multi_complete
                                         (struct castle_rxrpc_call *call, int err);
void     castle_rxrpc_replace_multi_next_process
                                         (struct castle_rxrpc_call *call, int err);
int      castle_rxrpc_get_slice_reply_marshall
                                         (struct castle_rxrpc_call *call,
                                          c_vl_okey_t *k,
                                          char *value,
                                          uint32_t value_len,
                                          char *buffer,
                                          uint32_t buffer_len,
                                          uint32_t *buffer_used);
void     castle_rxrpc_get_slice_reply_start
                                         (struct castle_rxrpc_call *call,
                                          int err,
                                          int nr_vals,
                                          char *buffer,
                                          uint32_t buffer_len,
                                          int last);
void     castle_rxrpc_get_slice_reply_continue
                                         (struct castle_rxrpc_call *call,
                                          char *buffer,
                                          uint32_t buffer_len,
                                          int last);

void     castle_rxrpc_get_complete     (struct castle_rxrpc_call *call, int err, void *d, size_t len);

int      castle_rxrpc_init             (void);
void     castle_rxrpc_fini             (void);

#endif /* __CASTLE_RXRPC_H__ */
