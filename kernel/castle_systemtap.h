#include <linux/tracepoint.h>

/****************************
 * castle_back
 ***************************/
struct castle_back_conn;

DEFINE_TRACE(back_work_do,
        TPPROTO(struct castle_back_conn *conn, int items),
        TPARGS(conn, items));

DEFINE_TRACE(CASTLE_PRINTK,
             TPPROTO(int level,         /**< Log-level for current message.         */
                     void *msg),        /**< Formatted printk message.              */
             TPARGS(level, msg));
