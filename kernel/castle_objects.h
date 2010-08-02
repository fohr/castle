#ifndef __CASTLE_OBJECTS_H__
#define __CASTLE_OBJECTS_H__

int   castle_object_btree_key_compare (c_vl_bkey_t *key1, c_vl_bkey_t *key2);
void *castle_object_btree_key_next    (c_vl_bkey_t *key);

int   castle_object_get               (struct castle_rxrpc_call *call, 
                                       c_vl_key_t **key);
int   castle_object_replace           (struct castle_rxrpc_call *call, 
                                       c_vl_key_t **key, 
                                       int tombstone);
int   castle_object_replace_continue  (struct castle_rxrpc_call *call, 
                                       int last);

#endif /* __CASTLE_OBJECTS_H__ */
