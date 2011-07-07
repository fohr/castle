#ifndef __CASTLE_TIME_H__
#define __CASTLE_TIME_H__

#ifdef CASTLE_PERF_DEBUG
#include <linux/time.h>

#define MAX_CHECK_POINTS    173
typedef struct castle_request_timeline {
    uint32_t         seq;
    /* Time when the request timeline was created */
    struct timespec  create_tm;
    struct timespec  destroy_tm;
    /* Stats about timing check points */
    int              active_checkpoint;
    struct castle_checkpoint {
        int              active;
        struct timespec  start_tm;
        uint32_t         cnts;
        struct timespec  aggregate_tm;
        struct timespec  max_tm;
        struct timespec  min_tm;
        char            *desc;              /**< User-defined checkpoint description.           */
        char            *file;              /**< File checkpoint_start() called from.           */
        int              line;              /**< Line in file checkpoint_start() called from.   */
    } checkpoints[MAX_CHECK_POINTS+1];      /**< +1 for stats on inactive duration.             */

    struct list_head list;
} c_req_time_t;

/* These should not be used directly */
extern c_req_time_t* _castle_request_timeline_create        (char *desc, char *file, int line);
extern void          _castle_request_timeline_checkpoint    (c_req_time_t *timeline,
                                                             char *desc,
                                                             char *file,
                                                             int line);
/* External functions */

/**
 * Allocate and start a timeline (arguments as per castle_request_timeline_checkpoint()).
 *
 * @also castle_request_timeline_checkpoint()
 */
#define castle_request_timeline_create(_ptr, _desc)                                 \
            (_ptr) = _castle_request_timeline_create(_desc, __FILE__, __LINE__)

/**
 * Checkpoint the current position.
 *
 * @param   _ptr    Timeline pointer
 * @param   _desc   Describes checkpoint start
 */
#define castle_request_timeline_checkpoint(_ptr, _desc)                             \
            _castle_request_timeline_checkpoint(_ptr, _desc, __FILE__, __LINE__)

/**
 * Stop and destroy timeline.
 */
void    castle_request_timeline_destroy(c_req_time_t *timeline);

int            castle_time_init(void);
void           castle_time_fini(void);

#else /* !CASTLE_PERF_DEBUG */

#define castle_request_timeline_create(_a, _desc)       ((void)0)
#define castle_request_timeline_checkpoint(_a, _desc)   ((void)0)
#define castle_request_timeline_destroy(_a)             ((void)0)

#define castle_time_init()                            (0)
#define castle_time_fini()                            ((void)0)

#endif /* CASTLE_PERF_DEBUG */

#endif /* __CASTLE_TIME_H__ */
