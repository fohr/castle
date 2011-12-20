#ifndef __CASTLE_DEBUG_H__
#define __CASTLE_DEBUG_H__

#ifdef CASTLE_DEBUG
#include "castle.h"

/* castle_bio_vec state debugging bits */
#define C_BVEC_INITIALISED          (0x1)
#define C_BVEC_VERSION_FOUND        (0x2)
#define C_BVEC_IO_END               (0x4)
#define C_BVEC_IO_END_ERR           (0x8)
#define C_BVEC_DATA_IO              (0x10)
#define C_BVEC_DATA_IO_NO_BLK       (0x20)
#define C_BVEC_DATA_C2B_UPTODATE    (0x40)
#define C_BVEC_DATA_C2B_OUTOFDATE   (0x80)
#define C_BVEC_DATA_C2B_GOT         (0x100)
#define C_BVEC_DATA_C2B_LOCKED      (0x200)

#define C_BVEC_BTREE_MASK           (0xFFFF0000)
#define C_BVEC_BTREE_GOT_NODE       (0x00010000)
#define C_BVEC_BTREE_LOCKED_NODE    (0x00020000)
#define C_BVEC_BTREE_NODE_UPTODATE  (0x00040000)
#define C_BVEC_BTREE_NODE_OUTOFDATE (0x00080000)
#define C_BVEC_BTREE_NODE_RPROCESS  (0x00100000)
#define C_BVEC_BTREE_NODE_WPROCESS  (0x00200000)
#define C_BVEC_BTREE_NODE_IO_END    (0x00400000)

#define castle_alloc(_s)             castle_debug_alloc_func(_s, __FILE__, __LINE__)
#define castle_alloc_atomic(_s)      castle_debug_malloc(_s, GFP_ATOMIC, __FILE__, __LINE__)
#define castle_zalloc(_s)            castle_debug_zalloc_func(_s, __FILE__, __LINE__)
#define castle_free(_p)              castle_debug_free_func(_p)
#define castle_alloc_maybe(_l, _d, _dl) castle_debug_alloc_maybe_func(_l, _d, _dl, __FILE__, __LINE__)
#define castle_dup_or_copy(_s, _sl, _d, _dl) castle_debug_dup_or_copy_func(_s, _sl, _d, _dl, __FILE__, __LINE__)
#define castle_vmalloc(_s)           castle_debug_vmalloc(_s, __FILE__, __LINE__)
#define castle_vfree(_p)             castle_debug_vfree(_p)

void* castle_debug_alloc_func(size_t size, char *file, int line);
void* castle_debug_zalloc_func(size_t size, char *file, int line);
void  castle_debug_free_func(void *ptr);
void *castle_debug_alloc_maybe_func(size_t len, void *dst, size_t *dst_len, char *file, int line);
void *castle_debug_dup_or_copy_func(const void *src, size_t src_len, void *dst, size_t *dst_len,
                                    char *file, int line);
void* castle_debug_malloc(size_t size, gfp_t flags, char *file, int line);
void* castle_debug_zalloc(size_t size, gfp_t flags, char *file, int line);
void  castle_debug_free(void *obj);
void* castle_debug_vmalloc(unsigned long size, char *file, int line);
void  castle_debug_vfree(void *obj);
void  castle_debug_bvec_update(c_bvec_t *c_bvec, unsigned long state_flag);
void  castle_debug_bvec_btree_walk(c_bvec_t *c_bvec);
void  castle_debug_bio_register(c_bio_t *c_bio, uint32_t version, int nr_cbvecs);
void  castle_debug_bio_deregister(c_bio_t *c_bio);
int   castle_debug_init(void);
void  castle_debug_fini(void);

#else /* !CASTLE_DEBUG */
/* NO-OP debugging statements */
#define castle_debug_bvec_update(_a, _b)      ((void)0)
#define castle_debug_bvec_btree_walk(_a)      ((void)0)
#define castle_debug_bio_register(_a, _b, _c) ((void)0)
#define castle_debug_bio_deregister(_a)       ((void)0)
#define castle_debug_init()                   (0)
#define castle_debug_fini()                   ((void)0)
#define castle_alloc(_s)                      castle_alloc_func(_s)
#define castle_alloc_atomic(_s)               kmalloc(_s, GFP_ATOMIC)
#define castle_zalloc(_s)                     castle_zalloc_func(_s)
#define castle_free(_p)                       castle_free_func(_p)
#define castle_alloc_maybe(_l, _d, _dl)       castle_alloc_maybe_func(_l, _d, _dl)
#define castle_dup_or_copy(_s, _sl, _d, _dl)  castle_dup_or_copy_func(_s, _sl, _d, _dl)
#define castle_vmalloc(_s)                    vmalloc(_s)
#define castle_vfree(_p)                      vfree(_p)

#endif /* CASTLE_DEBUG */

#define castle_check_free(_p)   {   if (_p) {   castle_free(_p); (_p) = NULL;  }   }
#endif /* __CASTLE_DEBUG_H__ */
