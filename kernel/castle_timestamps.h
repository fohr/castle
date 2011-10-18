#ifndef __CASTLE_TIMESTAMPS_H__
#define __CASTLE_TIMESTAMPS_H__

#include "castle_utils.h"
#include "castle.h"
#include "castle_public.h"
#include "castle_da.h"

/* to compare same k entries */
struct castle_da_entry_candidate_t{
    //TODO@tr clean this up... we started using a full btree node to hold candidates, so only need
    //        this struct to hold the inclusion bits.
    /* no key, because this was designed for timestamp-version violation resolution, where we
       always have the same key. */
    //c_val_tup_t              cvt;
    //c_ver_t                  version;
    //castle_user_timestamp_t  u_ts;
    int                      included;
};

typedef enum {
    DFS_RESOLVER_NULL = 0,
    DFS_RESOLVER_ENTRY_ADD,
    DFS_RESOLVER_BUFFER_PROCESS,
    DFS_RESOLVER_ENTRY_POP
} c_dfs_resolver_mode_t;

/**
 * Timestamp/tombstone-version key stream resolver.
 *
 * The dfs_resolver object is a drop-in mechanism to do timestamp-version resolution for DA merges.
 * The stream of same keys out of the merge iterator is fed into the dfs_resolver, which buffers up
 * all the entries (it is up to the caller to make sure only same ks enter the dfs_resolver through
 * the entry_add method).
 *
 * Once the caller is satisfied that there are no more entries for that k (using the new_key_check
 * method), it calls the process method, which does a DFS walk over the buffered entries, tagging
 * which entries should be included in the output stream.
 *
 * Once the process method returns, the caller uses the entry_pop method to stream results out of
 * the dfs_resolver's buffer.
 *
 * There are 4 operation modes (see the enum c_dfs_resolver_mode_t):
 * 1) null: just inited, or just finished a pop cycle
 * 2) entry add: fill up the buffer with same k entries
 * 3) buffer process: do the dfs walk, and mark the include flags
 * 4) entry pop: return included entries
 *
 * Mode flow is as follows: null->add->process->pop->null, and the user can make repeated calls
 * to add and pop.
 */
typedef struct castle_dfs_resolver
{
    //void                   *key;
    struct castle_da_merge *merge; /* for btree->key_copy */

    unsigned int top_index;   /* where to add entries; only change during entry add stage (now
                                 that we are using a btree node as a buffer, node->used should
                                 be the same). */
    unsigned int curr_index;  /* iterator used for pop */
    unsigned int _buffer_max; /* max entries; never change this after ctor! */

    struct castle_da_entry_candidate_t           *inclusion_buffer;
    c_uint32_stack                               *stack; /* for DFS walk */
    c_dfs_resolver_mode_t  mode;

    struct castle_btree_node *buffer_node;
} c_dfs_resolver;

int castle_dfs_resolver_construct(c_dfs_resolver *dfs_resolver, struct castle_da_merge *merge);
void castle_dfs_resolver_destroy(c_dfs_resolver *dfs_resolver);
int castle_dfs_resolver_entry_add(c_dfs_resolver *dfs_resolver,
                                  void *key,
                                  c_val_tup_t cvt,
                                  c_ver_t version,
                                  castle_user_timestamp_t u_ts);
int castle_dfs_resolver_entry_pop(c_dfs_resolver *dfs_resolver,
                                  void **key_p,
                                  c_val_tup_t *cvt_p,
                                  c_ver_t *version_p,
                                  castle_user_timestamp_t *u_ts_p);
uint32_t castle_dfs_resolver_process(c_dfs_resolver *dfs_resolver);
int castle_dfs_resolver_is_new_key_check(c_dfs_resolver *dfs_resolver, void *key);

#endif
