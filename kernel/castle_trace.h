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

/* castle_trace_cache() */
CASTLE_DEFINE_TRACE(cache,
                    TPPROTO(c_trc_type_t type, c_trc_cache_var_t var, uint64_t v1, uint64_t v2),
                    TPARGS(type, var, v1, v2));

/* castle_trace_da() */
CASTLE_DEFINE_TRACE(da,
                    TPPROTO(c_trc_type_t type, c_trc_cache_var_t var,
                        c_da_t da, uint64_t v2),
                    TPARGS(type, var, da, v2));

/* castle_trace_da_merge() */
CASTLE_DEFINE_TRACE(da_merge,
                    TPPROTO(c_trc_type_t type, c_trc_cache_var_t var,
                        c_da_t da, uint8_t level, uint64_t v4, uint64_t v5),
                    TPARGS(type, var, da, level, v4, v5));

/* castle_trace_da_merge_unit() */
CASTLE_DEFINE_TRACE(da_merge_unit,
                    TPPROTO(c_trc_type_t type, c_trc_cache_var_t var,
                        c_da_t da, uint8_t level, uint64_t unit, uint64_t v4),
                    TPARGS(type, var, da, level, unit, v4));

/* castle_trace_io_sched() */
CASTLE_DEFINE_TRACE(io_sched,
                    TPPROTO(c_trc_type_t type, c_trc_io_sched_var_t var, uint64_t val),
                    TPARGS(type, var, val));


int castle_trace_setup   (char *dir);
int castle_trace_start   (void);
int castle_trace_stop    (void);
int castle_trace_teardown(void);

int  castle_trace_init(void);
void castle_trace_fini(void);

#endif /* __CASTLE_TRACE_H__ */
