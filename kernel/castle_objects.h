#ifndef __CASTLE_OBJECTS_H__
#define __CASTLE_OBJECTS_H__

c_vl_bkey_t* castle_object_key_convert       (c_vl_okey_t *obj_key);
c_vl_okey_t* castle_object_btree_key_convert (c_vl_bkey_t *btree_key);
void         castle_object_key_free          (c_vl_okey_t *obj_key);
            
int          castle_object_btree_key_compare (c_vl_bkey_t *key1, c_vl_bkey_t *key2);
void        *castle_object_btree_key_next    (c_vl_bkey_t *key);
            
int          castle_object_get               (struct castle_object_get *get, 
                                              struct castle_attachment *attachment, 
                                              c_vl_okey_t *key);
int          castle_object_slice_get         (struct castle_rxrpc_call *call, 
                                              struct castle_attachment *attachment, 
                                              c_vl_okey_t *start_key, 
                                              c_vl_okey_t *end_key,
                                              uint32_t max_entries);
int          castle_object_replace           (struct castle_object_replace *replace, 
                                              struct castle_attachment *attachment, 
                                              c_vl_okey_t *key, 
                                              int tombstone);
int          castle_object_replace_multi     (struct castle_rxrpc_call *call,
                                              struct castle_attachment *attachment,
                                              c_vl_okey_t *key,
                                              int tombstone);
int          castle_object_replace_continue  (struct castle_object_replace *replace, 
                                              int last);

#endif /* __CASTLE_OBJECTS_H__ */
