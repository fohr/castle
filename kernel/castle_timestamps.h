#ifndef __CASTLE_TIMESTAMPS_H__
#define __CASTLE_TIMESTAMPS_H__

#include "castle_utils.h"
#include "castle.h"
#include "castle_public.h"
#include "castle_da.h"

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
 * There are 5 operation modes (see the enum c_dfs_resolver_mode_t):
 * 0) ctor_incomplete: only partially inited, construct_complete not called yet
 * 1) new_key: just inited, or just finished a pop cycle
 * 2) entry add: fill up the buffer with same k entries
 * 3) buffer process: do the dfs walk, and mark the include flags
 * 4) entry pop: return included entries
 */

typedef enum {
    DFS_RESOLVER_CTOR_INCOMPLETE = 1,
    DFS_RESOLVER_NEW_KEY,
    DFS_RESOLVER_ENTRY_ADD,
    DFS_RESOLVER_BUFFER_PROCESS,
    DFS_RESOLVER_ENTRY_POP
} c_dfs_resolver_mode_t;

/* each entry must be a power of 2 */
typedef enum {
    DFS_RESOLVE_NOTHING =    (1<<0),
    DFS_RESOLVE_TOMBSTONES = (1<<1),
    DFS_RESOLVE_TIMESTAMPS = (1<<2),
} c_dfs_resolver_functions_t;

typedef struct castle_dfs_resolver
{
    struct castle_da_merge *merge; /* for btree->key_copy */

    unsigned int    top_index;   /* where to add entries; only change during entry add stage (now
                                 that we are using a btree node as a buffer, node->used should
                                 be the same). */
    unsigned int    curr_index;  /* iterator used for pop */
    unsigned int    _buffer_max; /* max entries; never change this after ctor! */

    int            *inclusion_flag;   /* bool array to flag which entries to include in output */
    c_uint32_stack *stack;            /* for DFS walk */

    c_dfs_resolver_mode_t       mode;      /* current resolver cycle/state */
    c_dfs_resolver_functions_t  functions; /* what functions the resolver provides */

    struct castle_btree_node *buffer_node;

    struct timeval now; /* For tombstone delete; init with gettimeofday, which is too expensive
                           to do for every tombstone, so do it once on init. */
    castle_user_timestamp_t min_u_ts_excluded_cts;

} c_dfs_resolver;

int castle_dfs_resolver_preconstruct(c_dfs_resolver *dfs_resolver, struct castle_da_merge *merge,
                                     c_dfs_resolver_functions_t function_flags);
void castle_dfs_resolver_construct_complete(c_dfs_resolver *dfs_resolver);
void castle_dfs_resolver_destroy(c_dfs_resolver *dfs_resolver);
int castle_dfs_resolver_entry_add(c_dfs_resolver *dfs_resolver,
                                  void *key,
                                  c_val_tup_t cvt,
                                  c_ver_t version);
int castle_dfs_resolver_entry_pop(c_dfs_resolver *dfs_resolver,
                                  void **key_p,
                                  c_val_tup_t *cvt_p,
                                  c_ver_t *version_p);
uint32_t castle_dfs_resolver_process(c_dfs_resolver *dfs_resolver);
int castle_dfs_resolver_is_new_key_check(c_dfs_resolver *dfs_resolver, void *key);

#endif
