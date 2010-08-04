#ifndef __CASTLE_RXRPC_H__
#define __CASTLE_RXRPC_H__

uint32_t castle_rxrpc_packet_length      (struct castle_rxrpc_call *call);
uint32_t castle_rxrpc_uint32_get         (struct castle_rxrpc_call *call);
void     castle_rxrpc_str_copy           (struct castle_rxrpc_call *call, 
                                          void *buffer, 
                                          int str_length, 
                                          int partial);
                                         
void     castle_rxrpc_get_call_get       (struct castle_rxrpc_call *call, 
                                          c2_block_t **data_c2b, 
                                          uint32_t *data_c2b_length,
                                          uint32_t *data_length,
                                          int *first);
void     castle_rxrpc_get_call_set       (struct castle_rxrpc_call *call, 
                                          c2_block_t *data_c2b, 
                                          uint32_t data_c2b_length,
                                          uint32_t data_length,
                                          int first);
void     castle_rxrpc_replace_call_get   (struct castle_rxrpc_call *call, 
                                          c2_block_t **data_c2b, 
                                          uint32_t *data_c2b_offset,
                                          uint32_t *data_length);
void     castle_rxrpc_replace_call_set   (struct castle_rxrpc_call *call, 
                                          c2_block_t *data_c2b, 
                                          uint32_t data_c2b_offset,
                                          uint32_t data_length);
                                         
void     castle_rxrpc_replace_continue   (struct castle_rxrpc_call *call);
void     castle_rxrpc_replace_complete   (struct castle_rxrpc_call *call, int err);
int      castle_rxrpc_get_slice_reply_marshall
                                         (struct castle_rxrpc_call *call,
                                          c_vl_okey_t *k,
                                          char *value,
                                          uint32_t value_len,
                                          char *buffer,
                                          uint32_t buffer_len,
                                          uint32_t *buffer_used);
void     castle_rxrpc_get_slice_reply    (struct castle_rxrpc_call *call,
                                          int err,
                                          int nr_vals,
                                          char *buffer,
                                          uint32_t buffer_len);
void     castle_rxrpc_get_reply_start    (struct castle_rxrpc_call *call, 
                                          int err, 
                                          uint32_t data_length,
                                          void *buffer, 
                                          uint32_t buffer_length);
void     castle_rxrpc_get_reply_continue (struct castle_rxrpc_call *call,
                                          int err,
                                          void *buffer,
                                          uint32_t buffer_length,
                                          int last);

void     castle_rxrpc_get_complete     (struct castle_rxrpc_call *call, int err, void *d, size_t len);

int      castle_rxrpc_init             (void);
void     castle_rxrpc_fini             (void);

#endif /* __CASTLE_RXRPC_H__ */
