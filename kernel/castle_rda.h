#ifndef __CASTLE_RDA_H__
#define __CASTLE_RDA_H__

#include "castle_freespace.h"

/**
 * Get a slave to allocate next chunk. Slave array determines which slave should be used
 * for the allocation, superchunk ids determine whether to allocate multiple superchunks
 * from a given slave, and which one to use.
 *
 * @param cs                  Array of slave pointers to be filled in.
 * @param seq_ids             Array of superchunk ids. Ids are never greater than k_factor.
 * @param reservation_token   Pointer to the reservation token pointer.
 * @param state               RDA state structure obtained from @see c_extent_init_t().
 * @param chk_num             Logical chunk number for which we are allocating space.
 */
typedef int  (*c_next_slave_get_t)(struct castle_slave                 **cs,
                                   int                                  *schk_ids,
                                   struct castle_freespace_reservation **reservation_token,
                                   void                                 *state,
                                   c_chk_t                               chk_num);

typedef void* (*c_extent_init_t)  (c_ext_id_t   ext_id,
                                   c_chk_cnt_t  size,
                                   c_rda_type_t rda_type);

typedef void (*c_extent_fini_t)   (c_ext_id_t  ext_id,
                                   void       *state);

typedef struct c_rda_spec {
    c_rda_type_t                type;           /* RDA type */
    uint32_t                    k_factor;       /* K in K-RDA. [in order of 2] */
    c_next_slave_get_t          next_slave_get; /* fn() to get sequence of
                                                 * slaves to allocate freespace */
    c_extent_init_t             extent_init;
    c_extent_fini_t             extent_fini;
} c_rda_spec_t;

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type);



#endif /* __CASTLE_RDA_H__ */

