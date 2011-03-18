#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

#include "castle.h"
#include "castle_rda.h"
#include "castle_debug.h"
#include "castle_extent.h"
#include "castle_freespace.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

typedef struct c_def_rda_state {
    c_rda_spec_t                        *rda_spec;
    c_ext_id_t                           ext_id;
    c_chk_t                              prev_chk;
    c_chk_cnt_t                          size;
    uint32_t                             nr_slaves;
    struct castle_slave                 *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                              permut_idx;
    struct castle_freespace_reservation  freespace_reservation; 
} c_def_rda_state_t;

typedef struct c_ssd_rda_state {
    c_rda_spec_t                        *rda_spec;
    c_def_rda_state_t                   *def_state;
    uint32_t                             nr_slaves;
    struct castle_slave                 *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                              permut_idx;
    struct castle_freespace_reservation  freespace_reservation; 
} c_ssd_rda_state_t;

static c_rda_spec_t castle_default_rda;

/**
 * (Re)permute the array of castle_slave pointers, used to contruct the extent. Uses Fisher-Yates 
 * shuffle.
 *
 * Correctness experimentally validated as of 4c488c2459d8
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
 * @param rda_spec RDA spec used to allocate disks. 
 * @param slave    Slave to be tested.
 */
static int castle_rda_slave_usable(c_rda_spec_t *rda_spec, struct castle_slave *slave)
{
    /* Any extra tests should go here. */

    if ((test_bit(CASTLE_SLAVE_OOS_BIT, &slave->flags)) ||
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &slave->flags)))
        return 0;

    switch(rda_spec->type)
    {
        case DEFAULT_RDA:
            /* Default RDA doesn't use SSD disks. */
            if(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                return 0;
            break;
        case SSD_RDA:
        case SSD_ONLY_EXT:
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

/**
 * Calculates the number of superchunks needed for each of the slaves, in order to
 * create specified size extent, with given k_factor for given number of slaves.
 *
 * @param ext_size  Size of the extent to be created.
 * @param k_factor  K factor for the RDA spec.
 * @param nr_slaves What the size of the slave set. 
 */
static c_chk_cnt_t castle_rda_reservation_size_get(c_chk_cnt_t ext_size, 
                                                   uint32_t k_factor,
                                                   uint32_t nr_slaves)
{
    uint32_t nr_permutations;
    c_chk_cnt_t nr_schks;

    /* Work out how many separate, nr_slaves big, permutations are needed. */ 
    BUG_ON(ext_size == 0);
    BUG_ON(nr_slaves == 0);
    nr_permutations = (ext_size - 1) / nr_slaves + 1;
    /* Each permutation allocates one chunk, work out how many superchunks
       does that correspond to. */
    BUG_ON(nr_permutations == 0);
    nr_schks = (nr_permutations - 1) / CHKS_PER_SLOT + 1; 
    /* Total number of superchunks from each slave is k_factor times greater than that. */
    return nr_schks * k_factor;
}

/**
 * Tries to reserve specified number of superchunks from each of the slaves supplied.
 * All reservations are stored in a single reservation structure, also provided as a parameter.
 *
 * @param slaves            Array of slaves to allocate superchunks from.
 * @param nr_slaves         Size of the slaves array.
 * @param reservation_size  Number of superchunks to reserve from each slave.
 * @param token             Reservation structure to store the reservations in.
 *
 * @return -ENOSPC:    At least one reservation failed.
 * @return       0:    All reservations succeede.
 */
static int castle_rda_reserve(struct castle_slave **slaves, 
                              int nr_slaves,
                              c_chk_cnt_t reservation_size,
                              struct castle_freespace_reservation *token)
{
    int i, ret;

    for(i=0; i<nr_slaves; i++)
    {
        ret = castle_freespace_slave_superchunks_reserve(slaves[i], reservation_size, token);
        if(ret)
            return ret;
    }
    
    return 0; 
}

/**
 * Frees freespace reservation for the specified array of slaves.
 *
 * @param slaves            Array of slaves to free the reservation for.
 * @param nr_slaves         Size of the slaves array.
 * @param token             Reservation structure with the reservations.
 */
static void castle_rda_unreserve(struct castle_slave **slaves,
                                 int nr_slaves,
                                 struct castle_freespace_reservation *token)
{
    int i;

    for(i=0; i<nr_slaves; i++)
        castle_freespace_slave_superchunks_unreserve(slaves[i], token);
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
    state = castle_zalloc(sizeof(c_def_rda_state_t), GFP_KERNEL);
    if (!state)
    {
        printk("Failed to allocate memory for RDA state.\n");
        goto err_out;
    }
    
    /* Initialise state structure. */
    state->rda_spec   = rda_spec;
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
        if(castle_rda_slave_usable(rda_spec, slave))
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

    /* When allocating small extents, limit the number of disks, which reduces the wasted space. */
    BUG_ON(state->size == 0);
    state->nr_slaves = min(state->nr_slaves, SUPER_CHUNK(state->size - 1) + 1);
    state->nr_slaves = max(state->nr_slaves, rda_spec->k_factor);

    /* Reserve space from each of the disks. */
    if(castle_rda_reserve(state->permuted_slaves, 
                          state->nr_slaves, 
                          castle_rda_reservation_size_get(size, 
                                                          rda_spec->k_factor, 
                                                          state->nr_slaves),
                          &state->freespace_reservation))
        goto unreserve_err_out;

    /* Success. Return the state structure. */
    return state;

unreserve_err_out:
    castle_rda_unreserve(state->permuted_slaves, state->nr_slaves, &state->freespace_reservation);
err_out:
    if (state)
        castle_free(state);

    return NULL;
}

void castle_def_rda_extent_fini(c_ext_id_t ext_id, void *state_p)
{
    c_def_rda_state_t *state = (c_def_rda_state_t *)state_p;

    castle_rda_unreserve(state->permuted_slaves, state->nr_slaves, &state->freespace_reservation);
    castle_free(state);
}

int castle_def_rda_next_slave_get(struct castle_slave **cs,
                                  int *schk_ids, 
                                  struct castle_freespace_reservation **reservation_token, 
                                  void *state_p,
                                  c_chk_t chk_num)
{
    c_def_rda_state_t *state = state_p;
    c_rda_spec_t *rda_spec = state->rda_spec; 
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
    {
        cs[i] = state->permuted_slaves[(state->permut_idx + i) % state->nr_slaves];
        schk_ids[i] = i;
    }
    *reservation_token = &state->freespace_reservation;

    /* Advance the permutation index. */
    state->permut_idx++;

    /* Remeber what chunk we've just dealt with. */
    state->prev_chk = chk_num;

    return 0;
}

/**
 * Gets the appropriate freespace reservation structure (either from ssd rda state structure
 * or from the def rda state structure, depending whether we the ssd spec is SSD_ONLY_EXT or
 * SSD_RDA). 
 *
 * @param state RDA state structure. 
 */
static struct castle_freespace_reservation *castle_ssd_rda_reservation_token_get(
                                                                        c_ssd_rda_state_t *state)
{
    if(state->rda_spec->type == SSD_ONLY_EXT)
        return &state->freespace_reservation;

    if(state->rda_spec->type == SSD_RDA)
        return &state->def_state->freespace_reservation;

    /* Unknown RDA type. */ 
    BUG();
}

/**
 * Initialise RDA state structure for SSD_RDA or SSD_ONLY_RDA rda spec type. 
 * For SSD_RDA it piggybacks on DEFAULT_RDA, to generate most of the extent map, 
 * and only adds an extra on SSD copy. 
 * 
 * @param ext_id   Extent id this RDA spec will be generating. 
 * @param size     Size of the extent.
 * @param rda_type Must be set to SSD_RDA or SSD_ONLY_EXT. 
 */
void* castle_ssd_rda_extent_init(c_ext_id_t ext_id, 
                                 c_chk_cnt_t size, 
                                 c_rda_type_t rda_type)
{
    struct castle_slave *slave;
    c_ssd_rda_state_t *state;
    c_rda_spec_t *rda_spec;
    struct list_head *l;

    /* This function is only expected to be invoked for SSD_RDA or SSD_ONLY_EXT spec type. */
    BUG_ON((rda_type != SSD_RDA) && (rda_type != SSD_ONLY_EXT));
    rda_spec = castle_rda_spec_get(rda_type);
    /* Make sure that the k_factor is correct. */
    BUG_ON((rda_type == SSD_RDA)      && (rda_spec->k_factor != 1 + castle_default_rda.k_factor));
    BUG_ON((rda_type == SSD_ONLY_EXT) && (rda_spec->k_factor != 1));
    /* Allocate state structure, and corresponding default RDA spec state. */
    state = castle_zalloc(sizeof(c_ssd_rda_state_t), GFP_KERNEL);
    if(!state)
        goto err_out;
    state->rda_spec = rda_spec;
    if(rda_type != SSD_ONLY_EXT)
    {
        state->def_state = castle_def_rda_extent_init(ext_id, size, DEFAULT_RDA);
        if(!state->def_state)
            goto err_out;
    }
    /* Initialise the slave list. */ 
    list_for_each(l, &castle_slaves.slaves)
    {
        slave = list_entry(l, struct castle_slave, list);
        if(castle_rda_slave_usable(rda_spec, slave))
            state->permuted_slaves[state->nr_slaves++] = slave;
    }
    if(state->nr_slaves == 0)
    {
        debug("Could not allocate SSD extent size: %d. No SSDs found.\n", size);
        goto unreserve_err_out;
    }
    castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);
    /* Reserve space from each of the disks. */
    if(castle_rda_reserve(state->permuted_slaves, 
                          state->nr_slaves, 
                          castle_rda_reservation_size_get(size, 
                                                          1,
                                                          state->nr_slaves),
                          castle_ssd_rda_reservation_token_get(state)))
        goto unreserve_err_out;

    /* Success. Return. */
    return state;
 
unreserve_err_out:
    castle_rda_unreserve(state->permuted_slaves, 
                         state->nr_slaves, 
                         castle_ssd_rda_reservation_token_get(state));
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
    
    /* Free SSD reservations _before_ calling def_rda_extent_fini() because that
       destroys the def state structure, which contains the reservation token. */
    castle_rda_unreserve(state->permuted_slaves, 
                         state->nr_slaves, 
                         castle_ssd_rda_reservation_token_get(state));
    if(state->def_state)
        castle_def_rda_extent_fini(ext_id, state->def_state);
    castle_free(state);
}

int castle_ssd_rda_next_slave_get(struct castle_slave **cs,
                                  int *schk_ids,
                                  struct castle_freespace_reservation **reservation_token, 
                                  void *state_v,
                                  c_chk_t chk_num)
{
    c_ssd_rda_state_t *state = state_v;
    int ret;

    /* Fill the non-ssd slaves first, if we are handling non-SSD_ONLY_EXT */
    if(state->rda_spec->type != SSD_ONLY_EXT)
    {
        BUG_ON(!state->def_state);
        ret = castle_def_rda_next_slave_get(&cs[1], 
                                            &schk_ids[1], 
                                            reservation_token,
                                            state->def_state, 
                                            chk_num);
        if(ret)
            return ret;
    }

    /* Repermute, if permut_idx is greater than the number of slaves we are using. */
    if(state->permut_idx >= state->nr_slaves)
    {
        castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);
        state->permut_idx = 0;
    }
    /* Use SSD for the 0th copy. */
    cs[0] = state->permuted_slaves[state->permut_idx];
    schk_ids[0] = 0;
    *reservation_token = castle_ssd_rda_reservation_token_get(state);
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

static c_rda_spec_t castle_ssd_only_rda = {
    .type               = SSD_ONLY_EXT, 
    .k_factor           = 1,
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
    [SSD_ONLY_EXT]      = &castle_ssd_only_rda,
    [SUPER_EXT]         = &castle_super_ext_rda,
    [META_EXT]          = &castle_meta_ext_rda,
    [MICRO_EXT]         = NULL,
};

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type)
{
    BUG_ON((rda_type < 0) || (rda_type >= NR_RDA_SPECS));
    return castle_rda_specs[rda_type];
}
