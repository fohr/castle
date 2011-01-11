#ifndef __CASTLE_TRACE_H__
#define __CASTLE_TRACE_H__

#include <linux/tracepoint.h>

#define CASTLE_DEFINE_TRACE(name, proto, args)                                \
    DEFINE_TRACE(castle_##name, TPPROTO(proto), TPARGS(args))                 \
    static inline void castle_trace_##name(proto)                             \
    {                                                                         \
        trace_castle_##name(args);                                            \
    }                                                                         \
    static inline int castle_trace_##name##_register(void (*probe)(proto))    \
    {                                                                         \
        return register_trace_castle_##name((void *)probe);                   \
    }                                                                         \
    static inline int castle_trace_##name##_unregister(void (*probe)(proto))  \
    {                                                                         \
        return unregister_trace_castle_##name((void *)probe);                 \
    } 

/*
 * Consumer trace function definitions.
 *
 * Definitions below result in functions named castle_trace_XXX().  As a general
 * rule functions should use the name of the logical unit they are tracing, e.g.
 *
 * castle_trace_merge()
 *
 * For start/stop events define a function with _start and _stop, e.g.
 *
 * castle_trace_merge_start()
 * castle_trace_merge_stop()
 *
 * A castle_trace_XXX() function that does not have the _start()/_stop() suffix
 * is generally expected to pass a point in time statistic, e.g. number of dirty
 * pages or number of outstanding IO operations.
 */
CASTLE_DEFINE_TRACE(cache,              /* castle_trace_cache() */
                    TPPROTO(c_trc_cache_var_t var_id, uint32_t var_val),
                    TPARGS(var_id, var_val));
CASTLE_DEFINE_TRACE(merge_start,        /* castle_trace_merge_start() */
                    TPPROTO(da_id_t da, uint8_t level, tree_seq_t in_tree1, tree_seq_t in_tree2),
                    TPARGS(da, level, in_tree1, in_tree2));
CASTLE_DEFINE_TRACE(merge_stop,         /* castle_trace_merge_stop() */
                    TPPROTO(da_id_t da, uint8_t level, tree_seq_t out_tree),
                    TPARGS(da, level, out_tree));
CASTLE_DEFINE_TRACE(merge_unit_start,   /* castle_trace_merge_unit_start() */
                    TPPROTO(da_id_t da, uint8_t level, uint64_t unit),
                    TPARGS(da, level, unit));
CASTLE_DEFINE_TRACE(merge_unit_stop,    /* castle_trace_merge_unit_stop() */
                    TPPROTO(da_id_t da, uint8_t level, uint64_t unit),
                    TPARGS(da, level, unit));
CASTLE_DEFINE_TRACE(merge_unit,         /* castle_trace_merge_unit() */
                    TPPROTO(da_id_t da, uint8_t level, uint64_t unit,
                        c_trc_merge_var_t var_id, uint32_t val),
                    TPARGS(da, level, unit, var_id, val));

int castle_trace_setup   (char *dir);
int castle_trace_start   (void);
int castle_trace_stop    (void);
int castle_trace_teardown(void);

int  castle_trace_init(void);
void castle_trace_fini(void);

#endif /* __CASTLE_TRACE_H__ */
