#ifndef __CASTLE_EXTENT_H__
#define __CASTLE_EXTENT_H__

#include "castle.h"

#define INV_EXT_ID 0

typedef enum {
    DEFAULT,
    JOURNAL,
    FS_META,
    LOG_FREEZER,
    NR_RDA_SPEC
} c_rda_type_t;

#if 0
static char *rda_type_str[] = {
    "DEFAULT",
    "JOURNAL",
    "FS_META",
    "LOG_FREEZER",
    "NR_RDA_SPEC"
};
#endif

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

typedef void* (*c_extent_init_t)(c_ext_id_t         ext_id, 
                                 c_chk_cnt_t        size,
                                 c_rda_type_t       rda_type);

typedef void (*c_extent_free_t)(c_ext_id_t         ext_id, 
                                void              *state);
typedef struct {
    c_rda_type_t                type;           /* RDA type */
    uint32_t                    k_factor;       /* K factor in K-RDA */
    c_next_slave_get_t          next_slave_get; /* fn() to get sequence of
                                                 * slaves to allocate freespace */
    c_extent_init_t             extent_init;
    c_extent_free_t             extent_free;
} c_rda_spec_t;


int 
castle_rda_slave_add(c_rda_type_t            rda_type,
                     struct castle_slave    *slave);

struct castle_slave* castle_slave_find_by_id(uint32_t id);
struct castle_slave* castle_slave_find_by_uuid(uint32_t uuid);

c_rda_spec_t * 
castle_rda_spec_get(c_rda_type_t rda_type);

int
castle_extents_init(void);

void
castle_extents_fini(void);

c_ext_id_t 
castle_extent_alloc(c_rda_type_t            rda_type,
                    da_id_t                 da_id,
                    c_chk_cnt_t             chk_cnt);

void 
castle_extent_free(c_rda_type_t             rda_type,
                   da_id_t                 da_id,
                   c_ext_id_t               ext_id);

/* Sets @chunks to all physical chunks holding the logical chunks from offset */
c_disk_chk_t * 
castle_extent_map_get(c_ext_id_t             ext_id,
                      c_chk_t                offset,
                      uint32_t              *k_factor);

#endif //__CASTLE_EXTENT_H__
