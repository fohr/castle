#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

#include "castle.h"
#include "castle_rda.h"
#include "castle_utils.h"
#include "castle_debug.h"
#include "castle_extent.h"
#include "castle_freespace.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (castle_printk(LOG_DEBUG, _f, ##_a))
#define debug_res_pools(_f, _a...)  (castle_printk(LOG_DEBUG, _f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#define debug_res_pools(_f, _a...)  ((void)0)
#endif

typedef struct c_def_rda_state {
    c_rda_spec_t                        *rda_spec;
    c_ext_id_t                           ext_id;
    c_chk_t                              prev_chk;
    c_chk_cnt_t                          size;
    uint32_t                             nr_slaves;
    struct castle_slave                 *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                              permut_idx;
} c_def_rda_state_t;

typedef struct c_ssd_rda_state {
    c_rda_spec_t                        *rda_spec;
    c_def_rda_state_t                   *def_state;
    uint32_t                             nr_slaves;
    struct castle_slave                 *permuted_slaves[MAX_NR_SLAVES];
    uint8_t                              permut_idx;
} c_ssd_rda_state_t;

static c_rda_spec_t castle_rda_1, castle_rda_2;

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
        (test_bit(CASTLE_SLAVE_EVACUATE_BIT, &slave->flags)) ||
        (test_bit(CASTLE_SLAVE_CLAIMING_BIT, &slave->flags)))
        return 0;

    switch(rda_spec->type)
    {
        case RDA_1:
        case RDA_2:
            /* N_RDA doesn't use SSD disks. */
            if(slave->cs_superblock.pub.flags & CASTLE_SLAVE_SSD)
                return 0;
            break;
        case SSD_RDA_2:
        case SSD_RDA_3:
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
 * Calculates the number of super chunks needed for each of the slaves, in order to
 * create specified size extent, for each copy.
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
 * Reserves space for the pool, based on RDA_TYPE provided.
 *
 * @param [in]      rda_type        Type of the RDA that should be used to pick slaves and layout.
 * @param [in]      logical_chk_cnt Number of logical chunks client is looking for, RDA decides
 *                                  how many physical chunks to be used from each slave.
 * @param [inout]   pool            Reservation pool that reserved chunks to be added to.
 *
 * @return 0 SUCCESS  Reservation succeeded.
 *        -1 FAILURE  Couldn't find space on slaves.
 */
int castle_rda_space_reserve(c_rda_type_t            rda_type,
                             c_chk_cnt_t             logical_chk_cnt,
                             c_res_pool_t           *pool)
{
    struct castle_slave *slaves[MAX_NR_SLAVES];
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct list_head *l;
    uint32_t nr_slaves = 0, reservation_size;
    int i;

    /* Space reserve can be done only for DEFAULT_RDA and SSD_ONLY_EXT. For SSD_RDA call
     * this fucntion twice with both the RDA types. Before adding new RDA type verify this
     * function. */
    BUG_ON((rda_type != RDA_1) && (rda_type != RDA_2) && (rda_type != SSD_ONLY_EXT));

    /* Initialise the slaves array. */
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
    {
        struct castle_slave *slave;

        slave = list_entry(l, struct castle_slave, list);
        if (castle_rda_slave_usable(rda_spec, slave))
            slaves[nr_slaves++] = slave;
    }
    rcu_read_unlock();

    /* Check whether we've got enough slaves. */
    if (nr_slaves < rda_spec->k_factor)
    {
        //castle_printk(LOG_ERROR, "Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        debug("Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        return -EINVAL;
    }

    /* We used to do the optimiztion "when allocating small extents, limit the number of disks, which
     * reduce the wasted space". Not doing this optimization for reservations anymore as it is fine to
     * over-reserve, as we reservations get destroyed after completing the task(ex: merge). */

    /* Find the number of chunks to be reserved from each slave. */
    reservation_size = castle_rda_reservation_size_get(logical_chk_cnt,
                                                       rda_spec->k_factor,
                                                       nr_slaves);

    /* Reserve space from all slaves. If failed to allocate space from any single slave, skip. */
    for(i=0; i<nr_slaves; i++)
    {
        int ret;

        ret = castle_freespace_slave_superchunks_reserve(slaves[i], reservation_size, pool);
        if(ret)
        {
            castle_printk(LOG_DEBUG, "Failed to reserve space on slave: 0x%x\n", slaves[i]->uuid);
            /* Fail to reserve space. Unreserve space from slaves. */
            for (i=i-1; i>=0; i--)
                castle_freespace_slave_superchunks_unreserve(slaves[i], reservation_size, pool);

            return -ENOSPC;
        }
    }

    /* Return Success. */
    return 0;
}

void* castle_def_rda_extent_init(c_ext_t *ext,
                                 c_chk_cnt_t ext_size,
                                 c_chk_cnt_t alloc_size,
                                 c_rda_type_t rda_type)
{
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_slave *slave;
    c_def_rda_state_t *state;
    struct list_head *l;
    uint32_t nr_slaves;

    /* Allocate memory for the state structure. */
    state = castle_zalloc(sizeof(c_def_rda_state_t));
    if (!state)
    {
        castle_printk(LOG_ERROR, "Failed to allocate memory for RDA state.\n");
        goto err_out;
    }

    /* Initialise state structure. */
    state->rda_spec   = rda_spec;
    state->ext_id     = ext->ext_id;
    state->prev_chk   = -1;
    state->size       = alloc_size;
    state->nr_slaves  = 0;
    memset(&state->permuted_slaves, 0, sizeof(struct castle_slave *) * MAX_NR_SLAVES);
    state->permut_idx = 0;

    /* Initialise the slaves array. */
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
    {
        slave = list_entry(l, struct castle_slave, list);
        if(castle_rda_slave_usable(rda_spec, slave))
            state->permuted_slaves[state->nr_slaves++] = slave;
    }
    rcu_read_unlock();
    /* Check whether we've got enough slaves to make this extent. */
    if (state->nr_slaves < rda_spec->k_factor)
    {
        castle_printk(LOG_ERROR, "Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        goto err_out;
    }
    /* Permute the list of slaves the first time around. */
    castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);

    BUG_ON(state->size == 0);

    nr_slaves = state->nr_slaves;

    /* If the allocation size is not same as extent size, treat it as extent grow, and use all slaves.
     * Other wise, for small extent, limit the number of disks, which reduces the wasted space. */
    if (ext_size == alloc_size)
    {
        nr_slaves = min(nr_slaves, SUPER_CHUNK(ext_size - 1) + 1);
        nr_slaves = max(nr_slaves, rda_spec->k_factor);
    }

#if 0
    /* TODO: For the sake cleanness, implemented bruteforce. Improvize this code. */
    /* If we are not using all the slaves, then use the slaves for which we got reservations. */
    if (nr_slaves != state->nr_slaves && ext->pool)
    {
        int i, j;
        struct castle_slave **slaves;

        BUG_ON(nr_slaves > state->nr_slaves);

        slaves = castle_zalloc(sizeof(struct castle_slave *) * nr_slaves);
        if (!slaves)
            goto err_out;

        /* Take slaves for which, we got reservations. */
        for (i=0, j=0; i<state->nr_slaves && j<nr_slaves; i++)
        {
            /* Note: not really checking for whether reserved space is enough or not. If not
             * enough, we would over allocate. */
            if (castle_res_pool_available_space(ext->pool, state->permuted_slaves[i]))
            {
                slaves[j++] = state->permuted_slaves[i];
                state->permuted_slaves[i] = NULL;
            }
        }

        /* If those slaves are not enough, get more, even if no space is reserved. */
        for (i=0; i<state->nr_slaves && j<nr_slaves; i++)
        {
            if (state->permuted_slaves[i])
                slaves[j++] = state->permuted_slaves[i];
        }

        /* Copy the newly set slaves to state. */
        memset(&state->permuted_slaves, 0, sizeof(struct castle_slave *) * MAX_NR_SLAVES);
        memcpy(&state->permuted_slaves, slaves, sizeof(struct castle_slave *) * nr_slaves);

        castle_free(slaves);
    }
#endif

    state->nr_slaves = nr_slaves;

    /* Success. Return the state structure. */
    return state;

err_out:
    castle_check_free(state);

    return NULL;
}

void castle_def_rda_extent_fini(void *state_p)
{
    c_def_rda_state_t *state = (c_def_rda_state_t *)state_p;

    castle_free(state);
}

int castle_def_rda_next_slave_get(struct castle_slave **cs,
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
        castle_printk(LOG_ERROR, "Not yet ready for extent manager errors\n");
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
 * Initialise RDA state structure for SSD_RDA or SSD_ONLY_RDA rda spec type.
 * For SSD_RDA it piggybacks on DEFAULT_RDA, to generate most of the extent map,
 * and only adds an extra on SSD copy.
 *
 * @param ext_id   Extent id this RDA spec will be generating.
 * @param size     Size of the extent.
 * @param rda_type Must be set to SSD_RDA or SSD_ONLY_EXT.
 */
void* castle_ssd_rda_extent_init(c_ext_t *ext,
                                 c_chk_cnt_t ext_size,
                                 c_chk_cnt_t alloc_size,
                                 c_rda_type_t rda_type)
{
    struct castle_slave *slave;
    c_ssd_rda_state_t *state;
    c_rda_spec_t *rda_spec;
    struct list_head *l;

    /* This function is only expected to be invoked for SSD_RDA or SSD_ONLY_EXT spec type. */
    BUG_ON((rda_type != SSD_RDA_2) && (rda_type != SSD_RDA_3) &&(rda_type != SSD_ONLY_EXT));
    rda_spec = castle_rda_spec_get(rda_type);
    /* Make sure that the k_factor is correct. */
    BUG_ON((rda_type == SSD_RDA_2) && (rda_spec->k_factor != 1 + castle_rda_1.k_factor));
    BUG_ON((rda_type == SSD_RDA_3) && (rda_spec->k_factor != 1 + castle_rda_2.k_factor));
    BUG_ON((rda_type == SSD_ONLY_EXT) && (rda_spec->k_factor != 1));
    /* Allocate state structure, and corresponding default RDA spec state. */
    state = castle_zalloc(sizeof(c_ssd_rda_state_t));
    if(!state)
        goto err_out;
    state->rda_spec = rda_spec;
    if(rda_type != SSD_ONLY_EXT)
    {
        state->def_state = castle_def_rda_extent_init(ext, ext_size, alloc_size,
                                                      castle_ssdrda_to_rda(rda_type));
        if(!state->def_state)
            goto err_out;
    }
    /* Initialise the slave list. */
    rcu_read_lock();
    list_for_each_rcu(l, &castle_slaves.slaves)
    {
        slave = list_entry(l, struct castle_slave, list);
        if(castle_rda_slave_usable(rda_spec, slave))
            state->permuted_slaves[state->nr_slaves++] = slave;
    }
    rcu_read_unlock();
    if(state->nr_slaves == 0)
    {
        debug("Could not allocate SSD extent size: %d. No SSDs found.\n", alloc_size);
        goto err_out;
    }
    castle_rda_slaves_shuffle(state->permuted_slaves, state->nr_slaves);

    /* Success. Return. */
    return state;

err_out:
    if(state)
    {
        if(state->def_state)
            castle_def_rda_extent_fini(state->def_state);
        castle_free(state);
    }
    return NULL;
}

void castle_ssd_rda_extent_fini(void *state_v)
{
    c_ssd_rda_state_t *state = state_v;

    if(state->def_state)
        castle_def_rda_extent_fini(state->def_state);
    castle_free(state);
}

int castle_ssd_rda_next_slave_get(struct castle_slave **cs,
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
    state->permut_idx++;

    return 0;
}

/* RDA specs. */
static c_rda_spec_t castle_rda_1 = {
    .type               = RDA_1,
    .k_factor           = 1,
    .extent_init        = castle_def_rda_extent_init,
    .next_slave_get     = castle_def_rda_next_slave_get,
    .extent_fini        = castle_def_rda_extent_fini,
};

static c_rda_spec_t castle_rda_2 = {
    .type               = RDA_2,
    .k_factor           = 2,
    .extent_init        = castle_def_rda_extent_init,
    .next_slave_get     = castle_def_rda_next_slave_get,
    .extent_fini        = castle_def_rda_extent_fini,
};

static c_rda_spec_t castle_ssd_rda_2 = {
    .type               = SSD_RDA_2,
    .k_factor           = 2,
    .extent_init        = castle_ssd_rda_extent_init,
    .next_slave_get     = castle_ssd_rda_next_slave_get,
    .extent_fini        = castle_ssd_rda_extent_fini,
};

static c_rda_spec_t castle_ssd_rda_3 = {
    .type               = SSD_RDA_3,
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

/* BM: Just to avoid confusion, commenting it. Talk to GM and re-enable if needed. */
#if 0
static c_rda_spec_t castle_meta_ext_rda = {
    .type               = META_EXT,
    .k_factor           = 2,
    .extent_init        = castle_def_rda_extent_init,
    .next_slave_get     = castle_def_rda_next_slave_get,
    .extent_fini        = castle_def_rda_extent_fini,
};
#endif

c_rda_spec_t *castle_rda_specs[] = {
    [RDA_1]             = &castle_rda_1,
    [RDA_2]             = &castle_rda_2,
    [SSD_RDA_2]         = &castle_ssd_rda_2,
    [SSD_RDA_3]         = &castle_ssd_rda_3,
    [SSD_ONLY_EXT]      = &castle_ssd_only_rda,
    [SUPER_EXT]         = &castle_super_ext_rda,
    [META_EXT]          = &castle_rda_2,
    [MICRO_EXT]         = NULL,
};

/* Default is 2-RDA */
unsigned int castle_rda_lvl = 2;
module_param(castle_rda_lvl, uint, S_IRUSR | S_IWUSR | S_IRGRP | S_IWGRP);
MODULE_PARM_DESC(castle_rda_lvl, "RDA level");

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type)
{
    BUG_ON((rda_type < 0) || (rda_type >= NR_RDA_SPECS));
    return castle_rda_specs[rda_type];
}

/* Convert castle_rda_lvl module param to corresponding RDA_N rda_type */
c_rda_type_t castle_get_rda_lvl(void)
{
    if (castle_rda_lvl == 1)
        return RDA_1;
    else
    {
        castle_rda_lvl = 2;
        return RDA_2; /* If set to 2, or anything else, then it's 2-RDA. */
    }
}

/* Convert castle_rda_lvl module param to corresponding SSD_RDA_N rda_type */
c_rda_type_t castle_get_ssd_rda_lvl(void)
{
    return (castle_get_rda_lvl() + (SSD_RDA_2 - RDA_1));
}

/* Convert SSD_RDA_N rda_type to equivalent RDA_N rda_type */
c_rda_type_t castle_ssdrda_to_rda(c_rda_type_t rda_type)
{
    switch (rda_type)
    {
        case SSD_RDA_2:
            return RDA_1;
            break;
        case SSD_RDA_3:
            return RDA_2;
            break;
        default:
            BUG();
    }
}
