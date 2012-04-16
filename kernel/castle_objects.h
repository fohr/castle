#ifndef __CASTLE_OBJECTS_H__
#define __CASTLE_OBJECTS_H__

#if 0
c_vl_bkey_t* castle_object_key_convert       (c_vl_okey_t *obj_key);
c_vl_bkey_t* castle_object_key_convert_to_buf(c_vl_okey_t *obj_key,
                                              c_vl_bkey_t *btree_key,
                                              uint32_t     buf_len);
c_vl_okey_t* castle_object_btree_key_convert (c_vl_bkey_t *btree_key);
void         castle_object_okey_free         (c_vl_okey_t *obj_key);
c_vl_okey_t *castle_object_okey_copy         (c_vl_okey_t *obj_key);
#endif

int          castle_object_get               (struct castle_object_get *get,
                                              struct castle_attachment *attachment,
                                              int cpu_index);
int          castle_object_iter_init         (struct castle_attachment *attachment,
                                              c_vl_bkey_t *start_key,
                                              c_vl_bkey_t *end_key,
                                              castle_object_iterator_t **iter,
                                              int seq_id,
                                              castle_object_iter_start_cb_t start_cb,
                                              void *private);
int          castle_object_iter_next         (castle_object_iterator_t *iterator,
                                              castle_object_iter_next_available_t callback,
                                              void *data);
int          castle_object_iter_finish       (castle_object_iterator_t *iter);
int          castle_object_replace           (struct castle_object_replace *replace,
                                              struct castle_attachment *attachment,
                                              int cpu_index,
                                              int tombstone);
int          castle_object_replace_continue  (struct castle_object_replace *replace);
int          castle_object_replace_cancel    (struct castle_object_replace *replace);
void         castle_object_pull_finish       (struct castle_object_pull *pull);
int          castle_object_pull              (struct castle_object_pull *pull,
                                              struct castle_attachment *attachment,
                                              int cpu_index);
void         castle_object_chunk_pull        (struct castle_object_pull *pull,
                                              void *buf, size_t len);

enum{
    CASTLE_OBJECT_NOT_COUNTER = 0,
    CASTLE_OBJECT_COUNTER_SET,
    CASTLE_OBJECT_COUNTER_ADD
};
#endif /* __CASTLE_OBJECTS_H__ */
