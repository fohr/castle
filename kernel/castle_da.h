#ifndef __CASTLE_DA_H__
#define __CASTLE_DA_H__

#define NR_CASTLE_DA_WQS 1
extern struct workqueue_struct *castle_da_wqs[NR_CASTLE_DA_WQS];

struct castle_component_tree*
     castle_component_tree_get (tree_seq_t seq);
void castle_ct_get             (struct castle_component_tree *ct, int write);
void castle_ct_put             (struct castle_component_tree *ct, int write);
struct castle_component_tree*
     castle_da_ct_next         (struct castle_component_tree *ct);

void castle_da_rq_iter_init    (c_da_rq_iter_t *iter,
                                version_t version,
                                da_id_t da_id,
                                void *start_key,
                                void *end_key);
extern struct castle_iterator_type castle_da_rq_iter;

int  castle_double_array_okey_cpu_index(c_vl_okey_t *okey, uint32_t key_len);
int  castle_double_array_request_cpu(int cpu_index);
int  castle_double_array_request_cpus(void);

void castle_double_array_submit(c_bvec_t *c_bvec);
int  castle_double_array_make  (da_id_t da_id, version_t root_version);

int  castle_double_array_read  (void);
int  castle_double_array_create(void);
int  castle_double_array_start (void);

int  castle_double_array_init  (void);
void castle_double_array_fini  (void);

int  castle_double_array_get   (da_id_t da_id);
void castle_double_array_put   (da_id_t da_id);
int  castle_double_array_destroy (da_id_t da_id);
int  castle_double_array_size_get (da_id_t da_id, c_byte_off_t *size);
void castle_double_arrays_writeback (void);
void castle_double_array_merges_fini(void);

int  castle_ct_large_obj_add    (c_ext_id_t              ext_id, 
                                 uint64_t                length, 
                                 struct list_head       *head,
                                 struct mutex           *mutex);
int castle_double_arrays_unfreeze(void);
void castle_da_version_delete   (da_id_t da_id);

uint32_t castle_da_count(void);
void castle_da_threads_priority_set(int nice_value);
#endif /* __CASTLE_DA_H__ */
