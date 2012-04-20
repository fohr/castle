#ifndef __CASTLE_SYSTEMTAP_H__
#define __CASTLE_SYSTEMTAP_H__

#include <linux/tracepoint.h>

/***************
 * BACK EVENTS *
 ***************/
struct castle_back_conn;

/** Kernel has removed items from the ring. */
DEFINE_TRACE(CASTLE_BACK_WORK_DO,
        TPPROTO(struct castle_back_conn *conn,  /**< castle_back_conn processed                 */
                int items),             /**< Number of items removed from ring                  */
        TPARGS(conn, items));

/** Request completed. */
DEFINE_TRACE(CASTLE_REQUEST_END,
        TPPROTO(int seq_id),            /**< Unique sequence ID for completed request           */
        TPARGS(seq_id));

/** Request running on CPU again. */
DEFINE_TRACE(CASTLE_REQUEST_CLAIM,
        TPPROTO(int seq_id),            /**< Unique sequence ID for request                     */
        TPARGS(seq_id));

/** Request releasing CPU. */
DEFINE_TRACE(CASTLE_REQUEST_RELEASE,
        TPPROTO(int seq_id),            /**< Unique sequence ID for request                     */
        TPARGS(seq_id));

/** New request started. */
DEFINE_TRACE(CASTLE_REQUEST_BEGIN,
        TPPROTO(int seq_id,             /**< Unique sequence ID for this request                */
                uint32_t tag),          /**< Type of request                                    */
        TPARGS(seq_id, tag));

/****************
 * CACHE EVENTS *
 ****************/

/** Somebody requested an uptodate block. */
DEFINE_TRACE(CASTLE_CACHE_BLOCK_READ,
        TPPROTO(int submitted_c2ps,     /**< Number of c2ps submitted for read I/O (0 => hit)   */
                uint64_t ext_id,        /**< c2b->cep.ext_id                                    */
                int ext_type,           /**< Extent type for c2b                                */
                uint64_t offset,        /**< c2b->cep.offset                                    */
                int nr_pages,           /**< c2b->nr_pages                                      */
                int async),             /**< Asynchronous or synchronous read                   */
        TPARGS(submitted_c2ps, ext_id, ext_type, offset, nr_pages, async));

/*****************
 * PRINTK EVENTS *
 *****************/

DEFINE_TRACE(CASTLE_PRINTK,
             TPPROTO(int level,         /**< Log-level for current message                      */
                     void *msg),        /**< Formatted printk message                           */
             TPARGS(level, msg));

#endif /* __CASTLE_SYSTEMTAP_H__ */
