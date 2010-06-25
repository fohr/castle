#ifndef __CASTLE_RXRPC_H__
#define __CASTLE_RXRPC_H__

void castle_rxrpc_str_copy         (struct castle_rxrpc_call *call, void *buffer, int max_length);
void castle_rxrpc_replace_complete (struct castle_rxrpc_call *call, int err);
void castle_rxrpc_get_complete     (struct castle_rxrpc_call *call, int err, void *d, size_t len);

int  castle_rxrpc_init          (void);
void castle_rxrpc_fini          (void);

#endif /* __CASTLE_RXRPC_H__ */
