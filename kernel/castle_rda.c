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
} c_rda_state_t;

/**
 * (Re)permute the array of castle_slave pointers, used to contruct the extent. Uses Fisher-Yates 
 * shuffle.
 *
 * @param state Current state for onginig extent construction. 
 */
static void castle_rda_slaves_shuffle(c_rda_state_t *state)
{
    struct castle_slave *tmp_slave;
    uint16_t i, j;

    /* Be careful with comparisons to zero, i&j are unsigned. */ 
    for(i=state->nr_slaves-1; i>=1; i--)
    {
        /* Initialise j to a random number in inclusive range [0, i] */
        get_random_bytes(&j, 2);
        /* Very slight non-uniformity due to %. Safely ignorable. */
        j = j % (i+1); 
        /* Swap. */
        tmp_slave = state->permuted_slaves[i];
        state->permuted_slaves[i] = state->permuted_slaves[j];
        state->permuted_slaves[j] = tmp_slave;
    }
    state->permut_idx = 0;
    debug("Permuation:\n\t");
    for(i=0; i<state->nr_slaves; i++)
        debug("%u ", state->permuted_slaves[i]->uuid);
    debug("\n");
}

void* castle_rda_extent_init(c_ext_id_t   ext_id, 
                             c_chk_cnt_t  size, 
                             c_rda_type_t rda_type)
{
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    struct castle_slave *slave;
    c_rda_state_t *state;
    struct list_head *l;

    /* Allocate memory for the state structure. */
    state = castle_malloc(sizeof(c_rda_state_t), GFP_KERNEL);
    if (!state)
    {
        printk("Failed to allocate memory for RDA state\n");
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
        /* Here go any test which could prevent us using this disk (e.g. disk being dead). */
        state->permuted_slaves[state->nr_slaves++] = slave;
    }
    /* Check whether we've got enough slaves to make this extent. */
    if (state->nr_slaves < rda_spec->k_factor)
    {
        printk("Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        goto err_out;
    }
    /* Permute the list of slaves the first time around. */
    castle_rda_slaves_shuffle(state);

    return state;

err_out:
    if (state)
        castle_free(state);

    return NULL;
}

void castle_rda_extent_fini(c_ext_id_t ext_id, void *state)
{
    castle_free(state);
}

int castle_rda_next_slave_get(struct castle_slave *cs[],
                              void                *state_p,
                              c_chk_t              chk_num,
                              c_rda_type_t         rda_type)
{
    c_rda_spec_t *rda_spec = castle_rda_spec_get(rda_type);
    c_rda_state_t *state = state_p;
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
        castle_rda_slaves_shuffle(state);

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

/* RDA specs. */
static c_rda_spec_t castle_default_rda = {
    .type               = DEFAULT_RDA,
    .k_factor           = 2,
    .next_slave_get     = castle_rda_next_slave_get,
    .extent_init        = castle_rda_extent_init,
    .extent_fini        = castle_rda_extent_fini,
};

static c_rda_spec_t castle_super_ext_rda = {
    .type               = SUPER_EXT,
    .k_factor           = 2,
    .next_slave_get     = NULL, 
    .extent_init        = NULL, 
    .extent_fini        = NULL, 
};

static c_rda_spec_t castle_meta_ext_rda = {
    .type               = META_EXT,
    .k_factor           = 2,
    .next_slave_get     = castle_rda_next_slave_get,
    .extent_init        = castle_rda_extent_init,
    .extent_fini        = castle_rda_extent_fini,
};

c_rda_spec_t *castle_rda_specs[] = {
    [DEFAULT_RDA]       = &castle_default_rda,
    [SUPER_EXT]         = &castle_super_ext_rda,
    [META_EXT]          = &castle_meta_ext_rda,
    [MICRO_EXT]         = NULL,
};

c_rda_spec_t *castle_rda_spec_get(c_rda_type_t rda_type)
{
    BUG_ON((rda_type < 0) || (rda_type >= NR_RDA_SPECS));
    return castle_rda_specs[rda_type];
}
