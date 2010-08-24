#ifndef __CASTLE_DA_H__
#define __CASTLE_DA_H__

struct castle_component_tree*
     castle_component_tree_get (tree_seq_t seq);
void castle_ct_get             (struct castle_component_tree *ct, int write);
void castle_ct_put             (struct castle_component_tree *ct, int write);

void castle_da_rq_iter_init    (c_da_rq_iter_t *iter,
                                version_t version,
                                da_id_t da_id,
                                void *start_key,
                                void *end_key);
extern struct castle_iterator_type castle_da_rq_iter;

void castle_double_array_find  (c_bvec_t *c_bvec);
int  castle_double_array_make  (da_id_t da_id, version_t root_version);

int  castle_double_array_read  (void);
int  castle_double_array_create(void);

int  castle_double_array_init  (void);
void castle_double_array_fini  (void);

#endif /* __CASTLE_DA_H__ */
