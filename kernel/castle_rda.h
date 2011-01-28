#ifndef __CASTLE_RDA_H__
#define __CASTLE_RDA_H__

/* Get a slave to allocate next chunk.
 *
 * rda_type - RDA spec to be used to allocate the chunk
 * slave_id - Retruns the slave to be used
 * state    - State to be passed b/w multiple calls. NULL for first call.
 */
typedef int  (*c_next_slave_get_t)(struct castle_slave **cs,
                                   void                 *state,
                                   c_chk_t               chk_num,
                                   c_rda_type_t          rda_type);

typedef void* (*c_extent_init_t)(c_ext_id_t   ext_id, 
                                 c_chk_cnt_t  size,
                                 c_rda_type_t rda_type);

typedef void (*c_extent_fini_t)(c_ext_id_t  ext_id, 
                                void       *state);
typedef struct {
    c_rda_type_t                type;           /* RDA type */
    uint32_t                    k_factor;       /* K in K-RDA. [in order of 2] */
    c_next_slave_get_t          next_slave_get; /* fn() to get sequence of
                                                 * slaves to allocate freespace */
    c_extent_init_t             extent_init;
    c_extent_fini_t             extent_fini;
} c_rda_spec_t;

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type);



#endif /* __CASTLE_RDA_H__ */

