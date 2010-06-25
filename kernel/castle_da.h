#ifndef __CASTLE_DA_H__
#define __CASTLE_DA_H__

void castle_double_array_find  (c_bvec_t *c_bvec);
int  castle_double_array_make  (da_id_t da_id, version_t root_version);

int  castle_double_array_read  (void);
int  castle_double_array_create(void);

int  castle_double_array_init  (void);
void castle_double_array_fini  (void);


#endif /* __CASTLE_DA_H__ */
