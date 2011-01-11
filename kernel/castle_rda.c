#include <linux/mm.h>
#include <linux/vmalloc.h>
#include <linux/random.h>

#include "castle.h"
#include "castle_debug.h"
#include "castle_extent.h"

//#define DEBUG
#ifdef DEBUG
#define debug(_f, _a...)        (printk(_f, ##_a))
#else
#define debug(_f, ...)          ((void)0)
#endif

typedef struct {
    uint32_t                nr_slaves;                  /* Total # of slaves */
    uint32_t                nr_act_slaves;              /* # of active slaves */
    struct castle_slave    *slaves[MAX_NR_SLAVES];      /* List of slaves */
    struct castle_slave    *act_slaves[MAX_NR_SLAVES];  /* List of active slaves */
} c_rda_spec_ext_t;

static c_rda_spec_ext_t def_rda_spec;

typedef struct {
    c_ext_id_t              ext_id;
    c_chk_t                 prev_chk;
    c_chk_cnt_t             size;
    uint8_t                 permut1[MAX_NR_SLAVES];
    uint8_t                 permut2[MAX_NR_SLAVES];
    uint8_t                *permut;
    uint8_t                 permut_idx;
    struct castle_slave    *prev_set[0];
} c_rda_state_t;

void knuth_shuffle(uint8_t *a, int n)
{
    uint32_t i, j;

    a[0] = 0;
    for (i=1; i<=(n-1); i++)
    {
        get_random_bytes(&j, 4);
        j = j % (i+1);
        a[i] = a[j];
        a[j] = i;
    }
    debug("Permuation:\n\t");
    for (i=0; i<n; i++)
        debug("%u ", (uint32_t)a[i]);
    debug("\n");
}

void* castle_rda_extent_init(c_ext_id_t             ext_id, 
                             c_chk_cnt_t            size, 
                             c_rda_type_t           rda_type)
{
    c_rda_state_t   *state;
    c_rda_spec_t    *rda_spec = castle_rda_spec_get(rda_type);

    if (def_rda_spec.nr_act_slaves < rda_spec->k_factor)
    {
        printk("Do not have enough disks to support %d-RDA\n", rda_spec->k_factor);
        return NULL;
    }

    state = castle_malloc(sizeof(c_rda_state_t) + 
                          sizeof(struct castle_slave *) * rda_spec->k_factor, 
                          GFP_KERNEL);
    if (!state)
    {
        printk("Failed to allocate memory for RDA state\n");
        goto __hell;
    }

    state->ext_id       = ext_id;
    state->prev_chk     = -1;
    state->size         = size;
    state->permut_idx   = 0;
    knuth_shuffle(&state->permut1[0], def_rda_spec.nr_act_slaves);
    state->permut       = &state->permut1[0];

    return state;

__hell:
    if (state)
        castle_free(state);

    return NULL;
}

void castle_rda_extent_fini(c_ext_id_t    ext_id,
                            void         *_state)
{
    c_rda_state_t   *state = _state;

    castle_free(state);
}

int castle_rda_next_slave_get(struct castle_slave  *cs[],
                              void                 *_state,
                              c_chk_t               chk_num,
                              c_rda_type_t          rda_type)
{
    c_rda_state_t *state    = _state;
    c_rda_spec_t  *rda_spec = castle_rda_spec_get(rda_type);
    uint32_t       nr_act_slaves = def_rda_spec.nr_act_slaves;
    uint32_t       n;
    int i;

    if (state == NULL)
        goto __hell;

    BUG_ON(state->size <= chk_num);
    if (chk_num == state->prev_chk)
    {
        /* Findout the victim slave and segregate it */
        printk("Not yet ready for extent manager errors\n");
        BUG();
    }

    if(state->permut_idx >= nr_act_slaves)
    {
        /* Repermute. */
        knuth_shuffle(state->permut, nr_act_slaves);
        state->permut_idx=0;
    }
    for (i=0; i<rda_spec->k_factor; i++)
    {
        n = (state->permut[state->permut_idx] + i) % nr_act_slaves;
        cs[i] = def_rda_spec.act_slaves[n];
    }

    state->permut_idx++;

    return 0;

__hell:
    return -1;
}

int castle_rda_slave_add(c_rda_type_t rda_type, struct castle_slave *cs)
{
    def_rda_spec.slaves[def_rda_spec.nr_slaves]          = cs;
    def_rda_spec.act_slaves[def_rda_spec.nr_act_slaves]  = cs;
    BUG_ON(def_rda_spec.nr_slaves != def_rda_spec.nr_act_slaves);
    BUG_ON(def_rda_spec.nr_slaves != cs->id);

    def_rda_spec.nr_slaves++;
    def_rda_spec.nr_act_slaves++;
    debug("Added another slave to \"default\" rda spec\n");
    debug("     # of active disks: %d/%d\n", def_rda_spec.nr_slaves,
                            def_rda_spec.nr_act_slaves);
    return 0;
}

void castle_rda_slave_remove(c_rda_type_t rda_type, struct castle_slave *cs)
{
    if (!cs)
        return;

    /* Check if slave is already added to the RDA list. */
    if (cs->id != (def_rda_spec.nr_slaves - 1))
        return;

    def_rda_spec.nr_slaves--;
    def_rda_spec.nr_act_slaves--;

    return;
}
