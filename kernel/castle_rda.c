#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

#include "castle.h"
#include "castle_rda.h"
#include "castle_debug.h"
#include "castle_extent.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

typedef struct {
    c_ext_id_t             ext_id;
    c_chk_t                prev_chk;
    c_chk_cnt_t            size;
    int                    nr_slaves;
    struct castle_slave   *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                permut_idx;
} c_def_rda_state_t;

typedef struct {
    c_def_rda_state_t     *def_state;
    int                    nr_slaves;
    struct castle_slave   *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                permut_idx;
} c_ssd_rda_state_t;

/**
 * (Re)permute the array of castle_slave pointers, used to contruct the extent. Uses Fisher-Yates 
 * shuffle.
 *
 * @param slaves_array Array of castle_slave pointers to permute. 
 * @param nr_slaves    Length of slaves array.
 */
static void castle_rda_slaves_shuffle(struct castle_slave **slaves_array, int nr_slaves)
{
    struct castle_slave *tmp_slave;
    uint16_t i, j;

    /* Be careful with comparisons to zero, i&j are unsigned. */ 
    for(i=nr_slaves-1; i>=1; i--)
    {
        /* Initialise j to a random number in inclusive range [0, i] */
        get_random_bytes(&j, 2);
        /* Very slight non-uniformity due to %. Safely ignorable. */
        j = j % (i+1); 
        /* Swap. */
        tmp_slave = slaves_array[i];
        slaves_array[i] = slaves_array[j];
        slaves_array[j] = tmp_slave;
    }
    debug("Permuation:\n\t");
    for(i=0; i<nr_slaves; i++)
        debug("%u ", slaves_array[i]->uuid);
    debug("\n");
}

/**
 * Determines whether a slave should be used by given rda_spec.
 *
 * @param rda_type Type of the rda spec.
 * @param slave    Slave to be tested.
 */
static int castle_rda_slave_usable(c_rda_type_t rda_type, struct castle_slave *slave)
{
    /* Any extra tests (e.g. disk dead) should go here. */

    switch(rda_type)
    {
        case DEFAULT_RDA:
            /* Default RDA doesn't use SSD disks. */
            if(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                return 0;
            break;
        case SSD_RDA:
            if(!(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD))
                return 0;
            break;
        /* No special tests for other RDA types. */
        default:
            break;
    }

    /* By default, use the disk. */
    return 1;
}

void* castle_def_rda_extent_init(c_ext_id_t ext_id, 
                                 c_chk_cnt_t size, 
                                 c_rda_type_t rda_type)
{
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_slave *slave;
    c_def_rda_state_t *state;
    struct list_head *l;

    /* Allocate memory for the state structure. */
    state = castle_malloc(sizeof(c_def_rda_state_t), GFP_KERNEL);
    if (!state)
    {
        printk("Failed to allocate memory for RDA state.\n");
        goto err_out;
    }
    
    /* Initialise state structure. */
    state->ext_id     = ext_id;
    state->prev_chk   = -1;
    state->size       = size;
    state->nr_slaves  = 0;
    memset(&state->permuted_slaves, 0, sizeof(struct castle_slave *) * MAX_NR_SLAVES);
    state->permut_idx = 0;

    /* Initialise the slaves array. */
    list_for_each(l, &castle_slaves.slaves)
    {
        slave = list_entry(l, struct castle_slave, list);
        if(castle_rda_slave_usable(rda_type, slave))
            state->permuted_slaves[state->nr_slaves++] = slave;
    }
    /* Check whether we've got enough slaves to make this extent. */
    if (state->nr_slaves < rda_spec->k_factor)
    {
        printk("Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        goto err_out;
    }
    /* Permute the list of slaves the first time around. */
    castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);

    return state;

err_out:
    if (state)
        castle_free(state);

    return NULL;
}

void castle_def_rda_extent_fini(c_ext_id_t ext_id, void *state)
{
    castle_free(state);
}

int castle_def_rda_next_slave_get(struct castle_slave *cs[],
                                  void                *state_p,
                                  c_chk_t              chk_num,
                                  c_rda_type_t         rda_type)
{
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    c_def_rda_state_t *state = state_p;
    int i;

    if (state == NULL)
        return -1;

    BUG_ON(state->size <= chk_num);
    if (chk_num == state->prev_chk)
    {
        /* Findout the victim slave and segregate it */
        printk("Not yet ready for extent manager errors\n");
        BUG();
    }

    /* Repermute, if permut_idx is greater than the number of slaves we are using. */
    if(state->permut_idx >= state->nr_slaves)
    {
        castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);
        state->permut_idx = 0;
    }

    /* Fill the cs array. Use current permutation slave pointer for the first slave,
       and simple modulo shift for the other ones. */
    for (i=0; i<rda_spec->k_factor; i++)
        cs[i] = state->permuted_slaves[(state->permut_idx + i) % state->nr_slaves];

    /* Advance the permutation index. */
    state->permut_idx++;

    /* Remeber what chunk we've just dealt with. */
    state->prev_chk = chk_num;

    return 0;
}

/**
 * Initialise RDA state structure for SSD_RDA rda spec type. Piggybacks on DEFAULT_RDA,
 * to generate most of the extent map, and only adds an extra on SSD copy. 
 * 
 * @param ext_id   Extent id this RDA spec will be generating. 
 * @param size     Size of the extent.
 * @param rda_type Must be set to SSD_RDA.  
 */
void* castle_ssd_rda_extent_init(c_ext_id_t ext_id, 
                                 c_chk_cnt_t size, 
                                 c_rda_type_t rda_type)
{
    struct castle_slave *slave;
    c_ssd_rda_state_t *state;
    struct list_head *l;

    /* This function is only expected to be invoked for SSD_RDA spec type. */
    BUG_ON(rda_type != SSD_RDA);
    /* Allocate state structure, and corresponding default RDA spec state. */
    state = castle_zalloc(sizeof(c_ssd_rda_state_t), GFP_KERNEL);
    if(!state)
        goto err_out;
    state->def_state = castle_def_rda_extent_init(ext_id, size, DEFAULT_RDA);
    if(!state->def_state)
        goto err_out;
    /* Initialise the slave list. */ 
    list_for_each(l, &castle_slaves.slaves)
    {
        slave = list_entry(l, struct castle_slave, list);
        if(castle_rda_slave_usable(rda_type, slave))
            state->permuted_slaves[state->nr_slaves++] = slave;
    }
    castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);

    return state;
 
err_out:
    if(state)
    {
        if(state->def_state)
            castle_def_rda_extent_fini(ext_id, state->def_state);
        castle_free(state);
    }
    return NULL;
}

void castle_ssd_rda_extent_fini(c_ext_id_t ext_id, void *state_v)
{
    c_ssd_rda_state_t *state = state_v; 
    
    castle_def_rda_extent_fini(ext_id, state->def_state);
    castle_free(state);
}

int castle_ssd_rda_next_slave_get(struct castle_slave *cs[],
                                  void                *state_v,
                                  c_chk_t              chk_num,
                                  c_rda_type_t         rda_type)
{
    c_ssd_rda_state_t *state = state_v;
    int ret;

    /* Fill the non-ssd slaves first. */
    ret = castle_def_rda_next_slave_get(&cs[1], state->def_state, chk_num, DEFAULT_RDA);
    if(ret)
        return ret;

    /* Repermute, if permut_idx is greater than the number of slaves we are using. */
    if(state->permut_idx >= state->nr_slaves)
    {
        castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);
        state->permut_idx = 0;
    }
    /* Use SSD for the 0th copy. */
    cs[0] = state->permuted_slaves[state->permut_idx];
    state->permut_idx++;

    return 0;
}


/* RDA specs. */
static c_rda_spec_t castle_default_rda = {
    .type               = DEFAULT_RDA,
    .k_factor           = 2,
    .extent_init        = castle_def_rda_extent_init,
    .next_slave_get     = castle_def_rda_next_slave_get,
    .extent_fini        = castle_def_rda_extent_fini,
};

static c_rda_spec_t castle_ssd_rda = {
    .type               = SSD_RDA, 
    .k_factor           = 3,
    .extent_init        = castle_ssd_rda_extent_init,
    .next_slave_get     = castle_ssd_rda_next_slave_get,
    .extent_fini        = castle_ssd_rda_extent_fini,
};

static c_rda_spec_t castle_super_ext_rda = {
    .type               = SUPER_EXT,
    .k_factor           = 2,
    .extent_init        = NULL, 
    .next_slave_get     = NULL, 
    .extent_fini        = NULL, 
};

static c_rda_spec_t castle_meta_ext_rda = {
    .type               = META_EXT,
    .k_factor           = 2,
    .extent_init        = castle_def_rda_extent_init,
    .next_slave_get     = castle_def_rda_next_slave_get,
    .extent_fini        = castle_def_rda_extent_fini,
};

c_rda_spec_t *castle_rda_specs[] = {
    [DEFAULT_RDA]       = &castle_default_rda,
    [SSD_RDA]           = &castle_ssd_rda,
    [SUPER_EXT]         = &castle_super_ext_rda,
    [META_EXT]          = &castle_meta_ext_rda,
    [MICRO_EXT]         = NULL,
};

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type)
{
    BUG_ON((rda_type < 0) || (rda_type >= NR_RDA_SPECS));
    return castle_rda_specs[rda_type];
}
