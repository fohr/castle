#ifndef __CASTLE_RXRPC_H__
#define __CASTLE_RXRPC_H__

uint32_t castle_rxrpc_uint32_get       (struct castle_rxrpc_call *call);
void     castle_rxrpc_str_copy         (struct castle_rxrpc_call *call, void *buffer, int max_length);
                                      
void     castle_rxrpc_call_c2b_cvt_get (struct castle_rxrpc_call *call, 
                                        c2_block_t **data_c2b, 
                                        c_val_tup_t *data_cvt);
void     castle_rxrpc_call_c2b_cvt_set (struct castle_rxrpc_call *call, 
                                        c2_block_t *data_c2b, 
                                        c_val_tup_t data_cvt);

void     castle_rxrpc_replace_complete (struct castle_rxrpc_call *call, int err);
void     castle_rxrpc_get_complete     (struct castle_rxrpc_call *call, int err, void *d, size_t len);

int      castle_rxrpc_init             (void);
void     castle_rxrpc_fini             (void);

#endif /* __CASTLE_RXRPC_H__ */
