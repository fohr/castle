#ifndef __CASTLE_TIME_H__
#define __CASTLE_TIME_H__

#ifdef CASTLE_PERF_DEBUG
#include <linux/time.h>

#define MAX_CHECK_POINTS    23
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
        char            *file;
        int              line;
    } checkpoints[MAX_CHECK_POINTS];

    struct list_head list; 
} c_req_time_t;

/* These should not be used directly */
extern c_req_time_t* _castle_request_timeline_create           (void); 
extern void          _castle_request_timeline_checkpoint_start (c_req_time_t *timeline,
                                                                char *file,
                                                                int line);
/* External functions */
#define        castle_request_timeline_create(_ptr)                             \
    (_ptr) = _castle_request_timeline_create()
void           castle_request_timeline_destroy(c_req_time_t *timeline);
#define        castle_request_timeline_checkpoint_start(_ptr)                   \
    _castle_request_timeline_checkpoint_start(_ptr, __FILE__, __LINE__)
void           castle_request_timeline_checkpoint_stop(c_req_time_t *timeline);

int            castle_time_init(void);
void           castle_time_fini(void);

#else /* !CASTLE_PERF_DEBUG */

#define castle_request_timeline_create(_a)            ((void)0)
#define castle_request_timeline_destroy(_a)           ((void)0)
#define castle_request_timeline_checkpoint_start(_a)  ((void)0)
#define castle_request_timeline_checkpoint_stop(_a)   ((void)0)

#define castle_time_init()                            (0)
#define castle_time_fini()                            ((void)0)

#endif /* CASTLE_PERF_DEBUG */

#endif /* __CASTLE_TIME_H__ */
