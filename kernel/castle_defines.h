#ifndef __CASTLE_DEFINES_H__
#define __CASTLE_DEFINES_H__

/*
 * Key and value size limits.
 */
#define VLBA_TREE_MAX_KEY_SIZE         512      /* In bytes */
#define SLIM_TREE_MAX_KEY_SIZE         512      /* In bytes */
#define MAX_INLINE_VAL_SIZE            512      /* In bytes */
#define MEDIUM_OBJECT_LIMIT (20 * C_CHK_SIZE)
#define is_medium(_size)    (((_size) > MAX_INLINE_VAL_SIZE) && ((_size) <= MEDIUM_OBJECT_LIMIT))

#endif  /* !defined(__CASTLE_DEFINES_H__) */
