#ifndef __CASTLE_DEBUG_H__
#define __CASTLE_DEBUG_H__

#ifdef CASTLE_DEBUG

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

#define castle_malloc(_s, _f)        castle_debug_malloc(_s, _f, __FILE__, __LINE__)
#define castle_zalloc(_s, _f)        castle_debug_zalloc(_s, _f, __FILE__, __LINE__)
#define castle_free(_p)              do {castle_debug_free(_p); (_p) = NULL;} while(0)

void* castle_debug_malloc(size_t size, gfp_t flags, char *file, int line);
void* castle_debug_zalloc(size_t size, gfp_t flags, char *file, int line);
void  castle_debug_free(void *obj);
void  castle_debug_bvec_update(c_bvec_t *c_bvec, unsigned long state_flag);
void  castle_debug_bvec_btree_walk(c_bvec_t *c_bvec);
void  castle_debug_bio_register(c_bio_t *c_bio, uint32_t version, int nr_cbvecs);
void  castle_debug_bio_deregister(c_bio_t *c_bio);
void  castle_debug_init(void);
void  castle_debug_fini(void);

#else /* !CASTLE_DEBUG */
/* NO-OP debugging statements */
#define castle_debug_bvec_update(_a, _b)  ((void)0)
#define castle_debug_bvec_btree_walk(_a)  ((void)0) 
#define castle_debug_bio_register(_a, _b, _c)  ((void)0)
#define castle_debug_bio_deregister(_a)          ((void)0)
#define castle_debug_init()               ((void)0)
#define castle_debug_fini()               ((void)0)
#define castle_malloc(_s, _f)             kmalloc(_s, _f)
#define castle_zalloc(_s, _f)             kzalloc(_s, _f)
#define castle_free(_p)                   kfree(_p)

#endif /* CASTLE_DEBUG */


#endif /* __CASTLE_DEBUG_H__ */
