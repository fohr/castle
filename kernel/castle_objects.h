#ifndef __CASTLE_OBJECTS_H__
#define __CASTLE_OBJECTS_H__

int castle_object_get    (struct castle_rxrpc_call *call, uint8_t **key);
int castle_object_replace(struct castle_rxrpc_call *call, uint8_t **key, int tombstone);

#endif /* __CASTLE_OBJECTS_H__ */
