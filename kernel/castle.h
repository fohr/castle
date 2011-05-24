#ifndef __CASTLE_H__
#define __CASTLE_H__

#include <asm/byteorder.h>
#include <linux/module.h>
#include <linux/version.h>
#include <linux/workqueue.h>
#include <linux/completion.h>
#include <linux/fs.h>
#include <linux/net.h>
#include <linux/socket.h>
#include <net/sock.h>
#include <linux/rcupdate.h>
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif


#include "castle_public.h"

/* BUG and BUG_ON redefined to cause reliable crash-dumpable crashes. */
#undef BUG
#undef BUG_ON

/* Enable additional sanity checking to debug merge serialisation/deserialisation */
//#define DEBUG_MERGE_SERDES
extern int castle_merges_checkpoint; /* 0 or 1, default=enabled */

static inline ATTRIB_NORET void bug_fn(char *file, unsigned long line)
{
    panic("Castle BUG, from: %s:%ld\n", file, line);
#if 0
    /* Write the line number into R15, but push it onto the stack first. */
    __asm__ __volatile__ ("pushq %%r15\n\t"
                          "movq %0, %%r15;\n\t"
                          "movq $0x0,0xca511e\n\t"
                            : : "i" (line) : "%r15" );
    /* Will never get here. */
    while(1){};
#endif
}
#define BUG()            do { bug_fn(__FILE__, __LINE__); } while(0)
#define BUG_ON(_cond)    do { if(_cond) BUG(); } while(0)

/* Printk implementation used in the entire filesystem. */
#define PRINTKS_PER_SEC_STEADY_STATE    5
#define PRINTKS_IN_BURST                100
#define PRINTK_BUFFER_MBS               10          /**< Size of printk ring buffer (in MB).    */
#define PRINTK_BUFFER_SIZE              PRINTK_BUFFER_MBS*1024*1024 /**< Size of printk buffer. */
/*#define castle_printk(_f, _a...)    do { if(__printk_ratelimit(                     \
                                                HZ/PRINTKS_PER_SEC_STEADY_STATE,    \
                                                PRINTKS_IN_BURST))                  \
                                            printk(_f, ##_a); } while(0)*/
#define FLE strrchr(__FILE__, '/') ? strrchr(__FILE__, '/') + 1 : __FILE__

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,18)
#define CASTLE_INIT_WORK(_work, _func) INIT_WORK((_work), (void (*)(void *)) (_func), (void *) (_work))
#define CASTLE_DECLARE_WORK(_name, _func) DECLARE_WORK((_name), (void (*)(void *)) _func, &(_name))
#define CASTLE_PREPARE_WORK(_work, _func) PREPARE_WORK((_work), (void (*)(void *)) (_func), (void *) (_work))
#else
#define CASTLE_INIT_WORK(_work, _func) INIT_WORK((_work), (_func))
#define CASTLE_DECLARE_WORK(_name, _func) DECLARE_WORK((_name), (_func))
#define CASTLE_PREPARE_WORK(_work, _func) PREPARE_WORK((_work), (_func))
#endif

#define USED                 __attribute__((used))
#define EXIT_SUCCESS         (0)

#define STATIC_BUG_ON_HELPER(expr) \
        (!!sizeof (struct { unsigned int static_assertion_error: (expr) ? -1 : 1; }))
#define STATIC_BUG_ON(expr) \
        extern int (*assert_function__(void)) [STATIC_BUG_ON_HELPER(expr)]

#define NR_ENV_VARS          8
#define MAX_ENV_LEN          128
STATIC_BUG_ON(LAST_ENV_VAR_ID >= NR_ENV_VARS);
extern char *castle_environment[NR_ENV_VARS];
extern int   castle_fs_inited;
extern int   castle_fs_exiting;

typedef uint32_t tree_seq_t;
#define GLOBAL_TREE         ((tree_seq_t)0)
#define INVAL_TREE          ((tree_seq_t)-1)
#define TREE_GLOBAL(_t)     ((_t) == GLOBAL_TREE)
#define TREE_INVAL(_t)      ((_t) == INVAL_TREE)
#define TREE_SEQ_SHIFT      (24)                    /**< Shift for RWCTs (at levels 0,1)        */

#define INVAL_DA            ((da_id_t)-1)
#define DA_INVAL(_da)       ((_da) == INVAL_DA)

typedef uint32_t block_t;
#define INVAL_BLOCK         ((block_t)-1)
#define BLOCK_INVAL(_b)     ((_b) == INVAL_BLOCK)

/* New Free space structures */

/*
 * WARNING: be careful about changing MAX_NR_SLAVES. It's used to define various on-disk
 * datastructures.
 */
#define MAX_NR_SLAVES   64
/*
 * The minimum number of live slaves we can safely run with. For N-rda this is N.
 * This is hard coded for 2-rda at the moment.
 */
#define MIN_LIVE_SLAVES 2

#define C_CHK_SHIFT                    (20)
#define C_CHK_SIZE                     (1ULL << C_CHK_SHIFT)   /**< Bytes per chunk.             */

#define CHUNK_OFFSET(offset)  ((offset) & (C_CHK_SIZE - 1))
#define BLOCK_OFFSET(offset)  ((offset) & (C_BLK_SIZE - 1))
#define SECTOR_OFFSET(offset) ((offset) & ((1 << 9)-1))
#define CHUNK(offset)         ((offset) >> C_CHK_SHIFT)
#define BLOCK(offset)         ((offset) >> C_BLK_SHIFT)
#define BLK_IN_CHK(offset)    (BLOCK(CHUNK_OFFSET(offset)))
#define BLKS_PER_CHK          (C_CHK_SIZE / C_BLK_SIZE)         /**< Blocks(/pages) per chunk.    */
#define MASK_BLK_OFFSET(offset) (((offset) >> C_BLK_SHIFT) << C_BLK_SHIFT)
#define MASK_CHK_OFFSET(offset) (((offset) >> C_CHK_SHIFT) << C_CHK_SHIFT)

#define POWOF2(_n)            (((_n) & ((_n) - 1)) == 0)
/*  Chunk #                     Description
 *  =======                     ===========
 *   0 - 29                     Super Extent
 *   0                          Super block (Only first 8k)
 *   1                          Reserved
 *   2                          Freespace structures
 *   3 - 29                     Reserved
 *
 *           Leave double the space (Super Extent is 2-RDA)
 *
 *   60                         Micro Extent (Maps of meta extent)
 *
 *   61 - 63                    Reserved
 *
 *   64 - 563 (on each disk)    Meta extent (Spans across multiple disks)
 *                              would occupy 1024 logical chunks
 *    0 -  99                   Extent Structures
 *  100 - 1023                  Extent maps
 */

#define SUP_EXT_ID                     (10)
#define MICRO_EXT_ID                   (332)
#define META_EXT_ID                    (333)
#define MSTORE_EXT_ID                  (444) /* Two extents use 444 and 445. */
#define EXT_SEQ_START                  (1000)

/* Size of special(or logical) extents [in chunks] */
#define SUP_EXT_SIZE                   (30)  /* 2-RDA. Occupies double the space */
#define MICRO_EXT_START                (60)
#define MICRO_EXT_SIZE                 (1)   /* Don't change this */
#define META_SPACE_SIZE                (100)
#define MSTORE_SPACE_SIZE              (50)
#define FREE_SPACE_START               (100)
#define FREESPACE_OFFSET               (2 * C_CHK_SIZE)
#define FREESPACE_SIZE                 (20 * C_CHK_SIZE)

#define sup_ext_to_slave_id(_id)       ((_id) - SUP_EXT_ID)
#define slave_id_to_sup_ext(_id)       ((_id) + SUP_EXT_ID)

/* Logical extent structures are stored seperatly from normal extents. They are
 * stored in extent superblock itself. */
#define LOGICAL_EXTENT(_ext_id)        ((_ext_id) < EXT_SEQ_START && !EXT_ID_INVAL(_ext_id))
#define SUPER_EXTENT(_ext_id)          (((_ext_id) >= SUP_EXT_ID) && ((_ext_id) < slave_id_to_sup_ext(MAX_NR_SLAVES)))
#define EVICTABLE_EXTENT(_ext_id)      ((_ext_id) >= EXT_SEQ_START || (_ext_id) == META_EXT_ID  \
                                            || EXT_ID_INVAL(_ext_id))

typedef uint32_t c_chk_cnt_t;
typedef uint32_t c_chk_t;
typedef uint64_t c_ext_id_t;
typedef uint32_t c_uuid_t;

#define INVAL_CHK                       ((c_chk_t)-1)
#define CHK_INVAL(_chk)                 ((_chk) == INVAL_CHK)

#define INVAL_EXT_ID                    (-1)
#define EXT_ID_INVAL(_id)               ((_id) == INVAL_EXT_ID)
#define RESERVE_EXT_ID                  (-2)        /**< See castle_cache_page_block_unreserve(). */
#define EXT_ID_RESERVE(_id)             ((_id) == RESERVE_EXT_ID)
#define INVAL_SLAVE_ID                  (0)

struct castle_chunk_sequence {
    /* align:   4 */
    /* offset:  0 */ c_chk_t         first_chk;
    /*          4 */ c_chk_cnt_t     count;
    /*          8 */
} PACKED;
typedef struct castle_chunk_sequence c_chk_seq_t;
#define INVAL_CHK_SEQ                ((c_chk_seq_t){0,0})
#define CHK_SEQ_INVAL(_seq)          ((_seq).count == 0)
#define CHK_SEQ_EQUAL(_seq1, _seq2)  (((_seq1).first_chk == (_seq2).first_chk) && \
                                      ((_seq1).count == (_seq2).count))
#define chk_seq_fmt                  "(0x%llx, 0x%llx)"
#define chk_seq2str(_seq)            (_seq).first_chk, (_seq).count

struct castle_disk_chunk {
    /* align:   4 */
    /* offset:  0 */ c_uuid_t        slave_id;
    /*          4 */ c_chk_t         offset;
    /*          8 */
} PACKED;
typedef struct castle_disk_chunk c_disk_chk_t;
#define INVAL_DISK_CHK               ((c_disk_chk_t){INVAL_SLAVE_ID,0})
#define DISK_CHK_INVAL(_chk)         (((_chk).slave_id == INVAL_SLAVE_ID) &&    \
                                      ((_chk).offset == 0))
#define DISK_CHK_EQUAL(_chk1, _chk2) (((_chk1).slave_id == (_chk2).slave_id) && \
                                      ((_chk1).offset == (_chk2).offset))
#define disk_chk_fmt                  "(0x%x, 0x%x)"
#define disk_chk_fmt_nl               "(0x%x, 0x%x)\n"
#define disk_chk2str(_chk)            (_chk).slave_id, (_chk).offset

typedef uint64_t c_byte_off_t;

/* Disk layout related structures (extent based) */
struct castle_extent_position {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t      ext_id;
    /*          8 */ c_byte_off_t    offset;
    /*         16 */
} PACKED;
typedef struct castle_extent_position c_ext_pos_t;
#define __INVAL_EXT_POS             {INVAL_EXT_ID,0}
#define INVAL_EXT_POS               ((c_ext_pos_t) __INVAL_EXT_POS)
#define EXT_POS_INVAL(_off)         ((_off).ext_id == INVAL_EXT_ID)
#define EXT_POS_EQUAL(_off1, _off2) (((_off1).ext_id == (_off2).ext_id) && \
                                      ((_off1).offset == (_off2).offset))
/**
 * Compare cep1 against cep2.
 *
 * @param cep1	cep to compare
 * @param cep2	cep to compare against
 *
 * @return -1	cep1 is prior to cep2
 * @return  0	cep1 is the same as cep2
 * @return  1	cep1 is after cep2
 */
static inline int EXT_POS_COMP(c_ext_pos_t cep1, c_ext_pos_t cep2)
{
    if(cep1.ext_id < cep2.ext_id)
        return -1;

    if(cep1.ext_id > cep2.ext_id)
        return 1;

    if(cep1.offset < cep2.offset)
        return -1;

    if(cep1.offset > cep2.offset)
        return 1;

	return 0;
}
#define cep_fmt_str                  "(%llu, 0x%llx (chunk %lld chunk_off 0x%llx))"
#define cep_fmt_str_nl               "(%llu, 0x%llx (chunk %lld chunk_off 0x%llx)).\n"
#define cep2str(_off)                (_off).ext_id, BLOCK((_off).offset), CHUNK((_off).offset), CHUNK_OFFSET((_off).offset)
#define __cep2str(_off)              (_off).ext_id, ((_off).offset), CHUNK((_off).offset), CHUNK_OFFSET((_off).offset)

typedef enum {
    DEFAULT_RDA,
    SSD_RDA,
    META_EXT,
    MICRO_EXT,
    SUPER_EXT,
    SSD_ONLY_EXT,
    NR_RDA_SPECS
} c_rda_type_t;

/* Type of data stored within extent. */
typedef enum {
    EXT_T_META_DATA,
    EXT_T_BTREE_NODES,
    EXT_T_INTERNAL_NODES,
    EXT_T_LEAF_NODES,
    EXT_T_MEDIUM_OBJECTS,
    EXT_T_LARGE_OBJECT,
    EXT_T_BLOOM_FILTER,
    EXT_T_INVALID,
} c_ext_type_t;

static USED char *castle_ext_type_str[] = { 
    "EXT_T_META_DATA",
    "EXT_T_BTREE_NODES",
    "EXT_T_INTERNAL_NODES",
    "EXT_T_LEAF_NODES",
    "EXT_T_MEDIUM_OBJECTS",
    "EXT_T_LARGE_OBJECT",
    "EXT_T_BLOOM_FILTER",
    "EXT_T_INVALID"
};

/* This type determines the way, this extent has to be handled in case of Low Free-Space (LFS) 
 * situation. */
typedef enum {
    LFS_VCT_T_T0_GRP,
    LFS_VCT_T_T0,
    LFS_VCT_T_MERGE,
    LFS_VCT_T_INVALID
} c_lfs_vct_type_t;

#define LFS_VCT_T_MAX_TYPE LFS_VCT_T_INVALID

static USED char *castle_lfs_vct_type_str[] = {
    "LFS_VCT_T_T0_GRP",
    "LFS_VCT_T_T0",
    "LFS_VCT_T_MERGE",
    "LFS_VCT_T_INVALID"
};

typedef int       (*c_ext_event_callback_t)                (void *data);

typedef struct castle_extent_freespace {
    c_ext_id_t      ext_id;
    c_byte_off_t    ext_size;
    atomic64_t      used;
    atomic64_t      blocked;
} c_ext_free_t;

typedef struct castle_extent_freespace_byte_stream {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t      ext_id;
    /*          8 */ c_byte_off_t    ext_size;
    /*         16 */ uint64_t        used;
    /*         24 */ uint64_t        blocked;
    /*         32 */ uint8_t         _unused[32];
    /*         64 */
} PACKED c_ext_free_bs_t;

typedef struct castle_freespace {
    /* align:   4 */
    /* offset:  0 */ uint32_t        max_entries;
    /*          4 */ uint32_t        nr_entries;
    /*          8 */ uint32_t        prod;
    /*         12 */ uint32_t        cons;
    /*         16 */ c_chk_cnt_t     free_chk_cnt;
    /*         20 */ c_chk_cnt_t     disk_size;
    /*         24 */ uint8_t         _unused[40];
    /*         64 */
} PACKED castle_freespace_t;

struct castle_elist_entry {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t      ext_id;
    /*          8 */ c_chk_cnt_t     size;
    /*         12 */ c_rda_type_t    type;
    /*         16 */ uint32_t        k_factor;
    /*         20 */ uint32_t        obj_refs;
    /*         24 */ c_ext_pos_t     maps_cep;
    /*         40 */ uint32_t        curr_rebuild_seqno;
    /*         44 */ uint32_t        da_id;
    /*         48 */ uint32_t        ext_type;
    /*         52 */ uint8_t         _unused[12];
    /*         64 */
} PACKED;

struct castle_extents_superblock {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t                 ext_id_seq;
    /*          8 */ uint64_t                   nr_exts;
    /*         16 */ struct castle_elist_entry  micro_ext;
    /*         80 */ struct castle_elist_entry  meta_ext;
    /*        144 */ struct castle_elist_entry  mstore_ext[2];
    /*        272 */ c_ext_free_bs_t            meta_ext_free_bs;
    /*        336 */ c_disk_chk_t               micro_maps[MAX_NR_SLAVES];
    /*        848 */ uint32_t                   current_rebuild_seqno;
    /*        852 */ uint8_t                    _unused[172];
    /*       1024 */
} PACKED;

struct castle_slave_superblock {
    /* align:   8 */
    /* offset:  0 */ struct castle_slave_superblock_public pub;
    /*        128 */ uint32_t                              fs_version;
    /*        132 */ castle_freespace_t                    freespace;
    /*        196 */ uint8_t                               _unused[60];
    /*        256 */
} PACKED;

struct castle_fs_superblock {
    /* align:   8 */
    /* offset:  0 */ struct castle_fs_superblock_public      pub;
    /*        128 */ uint32_t                                fs_version;
    /*        132 */ uint32_t                                nr_slaves;
    /*        136 */ uint32_t                                slaves[MAX_NR_SLAVES];
    /*        392 */ uint8_t                                 slaves_flags[MAX_NR_SLAVES];
    /*        456 */ struct castle_extents_superblock        extents_sb;
    /*       1480 */ c_ext_pos_t                             mstore[16];
    /*       1736 */ int                                     fs_in_rebuild;
    /*       1740 */ uint8_t                                 _unused[308];
    /*       2048 */
} PACKED;

enum {
    CVT_TYPE_LEAF_VAL        = 0x01,
    CVT_TYPE_LEAF_PTR        = 0x02,
    CVT_TYPE_NODE            = 0x04,
    /* TOMB_STONE points to NULL value (no value). */
    CVT_TYPE_TOMB_STONE      = 0x08,
    /* Value length is small enough to keep in B-tree node itself. */
    CVT_TYPE_INLINE          = 0x10,
    /* Set to 1 for both Large and Medium Objects */
    CVT_TYPE_ONDISK          = 0x20,
    /* Valid only when CVT_TYPE_ONDISK is set.
     * 1 - Large objects
     * 0 - Medium objects */
    CVT_TYPE_LARGE_OBJECT    = 0x40,
    CVT_TYPE_INVALID         = 0x00,
};

#define MAX_INLINE_VAL_SIZE            512      /* In bytes */
#define VLBA_TREE_MAX_KEY_SIZE         512      /* In bytes */
#define MEDIUM_OBJECT_LIMIT (20 * C_CHK_SIZE)
#define is_medium(_size)    (((_size) > MAX_INLINE_VAL_SIZE) && ((_size) <= MEDIUM_OBJECT_LIMIT))

struct castle_value_tuple {
    /* align:   8 */
    /* offset:  0 */ struct {
    /*          0 */     uint64_t      type:8;
    /*          1 */     uint64_t      length:56;
    /*          8 */ };
    /*          8 */ union {
    /*          8 */     c_ext_pos_t   cep;
    /*          8 */     uint8_t      *val;
    /*         24 */ };
    /*         24 */
} PACKED;
typedef struct castle_value_tuple c_val_tup_t;

#define INVAL_VAL_TUP        ((c_val_tup_t){{CVT_TYPE_INVALID, 0}, {.cep = INVAL_EXT_POS}})

#define CVT_LEAF_VAL(_cvt)      ((_cvt).type & CVT_TYPE_LEAF_VAL)
#define CVT_LEAF_PTR(_cvt)      ((_cvt).type & CVT_TYPE_LEAF_PTR)
#define CVT_NODE(_cvt)          ((_cvt).type & CVT_TYPE_NODE)
#define CVT_TOMB_STONE(_cvt)    (CVT_LEAF_VAL(_cvt) && ((_cvt).type & CVT_TYPE_TOMB_STONE))
#define CVT_INLINE(_cvt)        (CVT_LEAF_VAL(_cvt) && ((_cvt).type & CVT_TYPE_INLINE))
#define CVT_ONDISK(_cvt)        (CVT_LEAF_VAL(_cvt) && ((_cvt).type & CVT_TYPE_ONDISK))
#define CVT_MEDIUM_OBJECT(_cvt) (CVT_ONDISK(_cvt) && !((_cvt).type & CVT_TYPE_LARGE_OBJECT))
#define CVT_LARGE_OBJECT(_cvt)  (CVT_ONDISK(_cvt) && ((_cvt).type & CVT_TYPE_LARGE_OBJECT))
#define CVT_INVALID(_cvt)       ((_cvt).type == CVT_TYPE_INVALID)
#define CVT_ONE_BLK(_cvt)       (CVT_ONDISK(_cvt) &&  (_cvt).length == C_BLK_SIZE)
#define CVT_INVALID_SET(_cvt)                                               \
{                                                                           \
   (_cvt).type   = CVT_TYPE_INVALID;                                        \
   (_cvt).length = 0;                                                       \
   (_cvt).cep    = INVAL_EXT_POS;                                           \
}
#define CVT_LEAF_PTR_SET(_cvt, _length, _cep)                               \
{                                                                           \
   (_cvt).type   = CVT_TYPE_LEAF_PTR;                                       \
   (_cvt).length = _length;                                                 \
   (_cvt).cep    = _cep;                                                    \
}
#define CVT_NODE_SET(_cvt, _length, _cep)                                   \
{                                                                           \
   (_cvt).type   = CVT_TYPE_NODE;                                           \
   (_cvt).length = _length;                                                 \
   (_cvt).cep    = _cep;                                                    \
}
#define CVT_TOMB_STONE_SET(_cvt)                                            \
{                                                                           \
   (_cvt).type   = (CVT_TYPE_LEAF_VAL | CVT_TYPE_TOMB_STONE);               \
   (_cvt).length = 0;                                                       \
   (_cvt).cep    = INVAL_EXT_POS;                                           \
}
#define CVT_INLINE_SET(_cvt, _length, _ptr)                                 \
{                                                                           \
   (_cvt).type   = (CVT_TYPE_LEAF_VAL | CVT_TYPE_INLINE);                   \
   (_cvt).length = _length;                                                 \
   (_cvt).val    = _ptr;                                                    \
}
#define CVT_MEDIUM_OBJECT_SET(_cvt, _length, _cep)                          \
{                                                                           \
    (_cvt).type  = (CVT_TYPE_LEAF_VAL | CVT_TYPE_ONDISK);                   \
    (_cvt).length= _length;                                                 \
    (_cvt).cep   = _cep;                                                    \
}
#define CVT_LARGE_OBJECT_SET(_cvt, _length, _cep)                           \
{                                                                           \
    (_cvt).type  = (CVT_TYPE_LEAF_VAL | CVT_TYPE_ONDISK | CVT_TYPE_LARGE_OBJECT); \
    (_cvt).length= _length;                                                 \
    (_cvt).cep   = _cep;                                                    \
}
#define CVT_INLINE_VAL_LENGTH(_cvt)                                             \
                             (CVT_INLINE(_cvt)?((_cvt).length):0)

#define CVT_EQUAL(_cvt1, _cvt2)                                                 \
                             ((_cvt1).type      == (_cvt2).type &&              \
                              (_cvt1).length    == (_cvt2).length &&            \
                              (!CVT_ONDISK(_cvt1) ||                            \
                               EXT_POS_EQUAL((_cvt1).cep, (_cvt2).cep)))
#if 0
#define CEP_TO_CVT(_cvt, _cep, _blks, _type)                                    \
                                {                                               \
                                    (_cvt).type     = _type;                    \
                                    (_cvt).length   = (_blks) * C_BLK_SIZE;     \
                                    (_cvt).cep      = _cep;                     \
                                }
#endif


typedef uint8_t c_mstore_id_t;

typedef struct castle_mstore_key {
    c_ext_pos_t  cep;
    int          idx;
} c_mstore_key_t;

#define INVAL_MSTORE_KEY           ((c_mstore_key_t){.cep = __INVAL_EXT_POS, .idx = 0})
#define MSTORE_KEY_INVAL(_k)       (EXT_POS_INVAL(_k.cep) && ((_k).idx == 0))
#define MSTORE_KEY_EQUAL(_k1, _k2) (EXT_POS_EQUAL(_k1.cep, _k2.cep)  &&         \
                                    ((_k1).idx == (_k2).idx))
typedef struct castle_mstore {
    c_mstore_id_t              store_id;             /* Id of the store, ptr in fs_sb    */
    size_t                     entry_size;           /* Size of the entries stored       */
    struct semaphore           mutex;                /* Mutex which protects the         */
                                                     /*  last_node_* variables           */
    c_ext_pos_t                last_node_cep;        /* Tail of the list, has at least   */
                                                     /* one unused entry in it           */
    int                        last_node_unused;     /* Number of unused entries in the  */
                                                     /* last node                        */
} c_mstore_t;

typedef struct castle_mstore_iter {
    struct castle_mstore      *store;                /* Store we are iterating over      */
    struct castle_cache_block *node_c2b;             /* Currently accessed node (locked) */
    int                        node_idx;             /* Next entry index in current node */
} c_mstore_iter_t;

enum {
    MSTORE_VERSIONS_ID,
    MSTORE_BLOCK_CNTS,
    MSTORE_DOUBLE_ARRAYS,
    MSTORE_COMPONENT_TREES,
    MSTORE_ATTACHMENTS_TAG,
    MSTORE_EXTENTS,
    MSTORE_LARGE_OBJECTS,
    MSTORE_DA_MERGE,
    MSTORE_STATS,
};


#define MTREE_TYPE                 0x33
#define MTREE_BVEC_BLOCK(_bvec)   ((sector_t)(_bvec)->key)
#define BATREE_TYPE                0x44
#define RW_VLBA_TREE_TYPE          0x55
#define RO_VLBA_TREE_TYPE          0x66

#define MAX_BTREE_DEPTH           (10)               /**< Maximum depth of btrees.
                                                          This is used in on-disk datastructures.
                                                          For example castle_clist_entry.
                                                          If modified, those need to be reviewed.
                                                      */
#define VLBA_HDD_RO_TREE_NODE_SIZE      (64)  /**< Size of the default RO tree node size. */
#define VLBA_SSD_RO_TREE_NODE_SIZE      (2)   /**< Size of the RO tree node size on SSDs. */

typedef uint8_t btree_t;

#define BTREE_NODE_MAGIC  0x0100cdab
struct castle_btree_node {
    /* align:   8 */
    /* offset:  0 */ uint32_t        magic;
    /*          4 */ uint32_t        version;
    /*          8 */ uint32_t        used;
    /*         12 */ btree_t         type;
    /*         13 */ uint8_t         is_leaf;
    /*         14 */ uint16_t        size;           /**< Size of this btree node in pages.     */
                     /* Payload (i.e. btree entries) depend on the B-tree type */
    /*         16 */ uint8_t         _unused[48];
    /*         64 */ uint8_t         payload[0];
    /*         64 */
} PACKED;

#define BTREE_NODE_PAYLOAD(_node)   ((void *)&(_node)->payload)

#define PLUS_INFINITY_DIM_LENGTH 0xFFFFFFFF

typedef struct castle_var_length_btree_key {
    /* align:   4 */
    /* offset:  0 */ uint32_t length;
    /*          4 */ uint32_t nr_dims;
    /*          8 */ uint8_t  _unused[8];
    /*         16 */ uint32_t dim_head[0];
    /*         16 */
    /* Dimension header is followed by individual dimensions. */
} PACKED c_vl_bkey_t;

/* Below encapsulates the internal btree node structure, different type of
   nodes may be used for different trees */
struct castle_component_tree;
struct castle_btree_type {
    btree_t    magic;         /* Also used as an index to castle_btrees
                                 array.                                 */
    void      *min_key;       /* Minimum key                            */
    void      *max_key;       /* Maximum used as the end of node marker */
    void      *inv_key;       /* An invalid key, comparison with it
                                 should always return a negative number
                                 except if also compared to invalid key
                                 in which case cmp should return zero   */
    uint16_t (*node_size)     (struct castle_component_tree *ct,
                               uint8_t level);
                              /**< Gives btree node size at the given
                                   level. Levels are counted in reverse
                                   order. I.e. leaf level is 0, etc.
                                   This makes it possible to grow the tree
                                   without renumbering all the existing
                                   levels. */
    int      (*need_split)    (struct castle_btree_node *node,
                               int                       version_or_key);
                              /* 0 - version split, 1 - key split       */
    int      (*key_compare)   (void *key1, void *key2);
                              /* Returns negative if key1 < key2, zero
                                 if equal, positive otherwise           */
    void*    (*key_duplicate) (void *key);
                              /* Returns duplicate of key. Need to call
                               * a dealloc later to free resources      */
    void*    (*key_next)      (void *key);
                              /* Successor key, succ(MAX) = INVAL,
                                 succ(INVAL) = INVAL                    */
    void     (*key_dealloc)   (void *key);
                              /* Destroys the key, frees resources
                                 associated with it                     */
    uint32_t (*key_hash)      (void *key, uint32_t seed);
                              /* Get hash of key with seed              */
    int      (*entry_get)     (struct castle_btree_node *node,
                               int                       idx,
                               void                    **key_p,
                               version_t                *version_p,
                               c_val_tup_t              *cvt_p);
    void     (*entry_add)     (struct castle_btree_node *node,
                               int                       idx,
                               void                     *key,
                               version_t                 version,
                               c_val_tup_t               cvt);
    void     (*entry_replace) (struct castle_btree_node *node,
                               int                       idx,
                               void                     *key,
                               version_t                 version,
                               c_val_tup_t               cvt);
    void     (*entry_disable) (struct castle_btree_node *node,
                               int                       idx);
    void     (*entries_drop)  (struct castle_btree_node *node,
                               int                       idx_start,
                               int                       idx_end);
                              /* Drop all entries between idx_start and
                                 idx_stop. Inclusive                    */
    void     (*node_print)    (struct castle_btree_node *node);
#ifdef CASTLE_DEBUG
    void     (*node_validate) (struct castle_btree_node *node);
#endif
};

#define MTREE_NODE_SIZE     (10) /* In blocks */

typedef struct castle_bloom_filter {
    uint8_t                   num_hashes;
    uint32_t                  block_size_pages;
    uint32_t                  num_chunks;
    uint32_t                  num_blocks_last_chunk;
    uint64_t                  chunks_offset;
    uint32_t                  num_btree_nodes;
    struct castle_btree_type *btree;
    c_ext_id_t                ext_id;
    void                     *private; /* used for builds */
#ifdef CASTLE_BLOOM_FP_STATS
    atomic64_t                queries;
    atomic64_t                false_positives;
#endif
} castle_bloom_t;

struct castle_bbp_entry
{
    /* align:   8 */
    /* offset:  0 */ uint64_t    expected_num_elements;
    /*          8 */ uint64_t    elements_inserted;
    /*         16 */ uint32_t    chunks_complete;
    /*         20 */ uint32_t    cur_node_cur_chunk_id;
    /*         24 */ uint32_t    cur_chunk_num_blocks;
    /*         28 */ uint32_t    nodes_complete;
    /*         32 */ c_ext_pos_t node_cep;
    /*         48 */ c_ext_pos_t chunk_cep;
    /*         64 */ uint32_t    node_used;   /* for entries_drop */
    /*         68 */ uint8_t     node_avail;  /* flag to indicate if we should recover node */
    /*         69 */ uint8_t     chunk_avail; /* flag to indicate if we should recover chunk */
    /*         70 */
} PACKED;

struct castle_component_tree {
    tree_seq_t          seq;               /**< Unique ID identifying this tree.                */
    atomic_t            ref_count;
    atomic_t            write_ref_count;
    atomic64_t          item_count;        /**< Number of items in the tree.                    */
    btree_t             btree_type;
    uint8_t             dynamic;           /**< 1 - dynamic modlist btree, 0 - merge result.    */
    da_id_t             da;
    uint8_t             level;             /**< Level in the doubling array.                    */
    uint16_t            node_sizes[MAX_BTREE_DEPTH];
                                           /**< Size of nodes in each level in the b-tree,
                                                in pages. Only used for !dynamic (i.e. RO)
                                                trees. Stored in reverse order,
                                                i.e. node_sizes[0] is the size of leaf level,
                                                node_sizes[tree_depth-1] is the size of the
                                                root node. */
    uint8_t             new_ct;            /**< Marked for cts which are not yet flushed onto
                                                the disk.                                       */
    uint8_t             compacting;        /**< compaction is going on this CT.                 */
    struct rw_semaphore lock;              /**< Protects root_node, tree depth & last_node.     */
    uint8_t             tree_depth;
    c_ext_pos_t         root_node;
    struct list_head    da_list;
    struct list_head    hash_list;
    struct list_head    large_objs;
    struct mutex        lo_mutex;          /**< Protects Large Object List. When working with
                                                the output CT of a serialisable merge, never
                                                take this lock before serdes.mutex or there will
                                                be deadlock against checkpoint thread. */
    c_ext_free_t        internal_ext_free;
    c_ext_free_t        tree_ext_free;
    c_ext_free_t        data_ext_free;
    atomic64_t          large_ext_chk_cnt;
    uint8_t             bloom_exists;
    castle_bloom_t      bloom;
#ifdef CASTLE_PERF_DEBUG
    u64                 bt_c2bsync_ns;
    u64                 data_c2bsync_ns;
    u64                 get_c2b_ns;
#endif
};
extern struct castle_component_tree castle_global_tree;

struct castle_large_obj_entry {
    c_ext_id_t          ext_id;
    uint64_t            length;
    struct list_head    list;
};

struct castle_dlist_entry {
    /* align:   4 */
    /* offset:  0 */ da_id_t     id;
    /*          4 */ version_t   root_version;
    /*          8 */ uint8_t     _unused[248];
    /*        256 */
} PACKED;

struct castle_clist_entry {
    /* align:   8 */
    /* offset:  0 */ da_id_t         da_id;
    /*          4 */ btree_t         btree_type;
    /*          5 */ uint8_t         dynamic;
    /*          6 */ uint8_t         level;
    /*          7 */ uint8_t         tree_depth;
    /*          8 */ uint64_t        item_count;
    /*         16 */ c_ext_pos_t     root_node;
    /*         32 */ c_ext_free_bs_t internal_ext_free_bs;
    /*         96 */ c_ext_free_bs_t tree_ext_free_bs;
    /*        160 */ c_ext_free_bs_t data_ext_free_bs;
    /*        224 */ uint64_t        large_ext_chk_cnt;
    /*        232 */ uint32_t        bloom_num_chunks;
    /*        236 */ uint32_t        bloom_num_blocks_last_chunk;
    /*        240 */ uint64_t        bloom_chunks_offset;
    /*        248 */ c_ext_id_t      bloom_ext_id;
    /*        256 */ uint32_t        bloom_num_btree_nodes;
    /*        260 */ uint32_t        bloom_block_size_pages;
    /*        264 */ tree_seq_t      seq;
    /*        268 */ uint8_t         bloom_exists;
    /*        269 */ uint8_t         bloom_num_hashes;
    /*        270 */ uint16_t        node_sizes[MAX_BTREE_DEPTH];
    /*        290 */ uint8_t         _unused[222];
    /*        512 */
} PACKED;

/** DA merge SERDES on-disk structure.
 *
 *  @note Assumes 2 input trees, both c_immut_iter_t, and max of 10 DA levels
 */
struct castle_dmserlist_entry {
    /* align:   8 */
    /* offset:  0 */ da_id_t                     da_id;
    /*          4 */ int32_t                     level;
    /* On in_trees... each in_tree can identify which DA and level it belongs to, so it is up to
       the trees to find their DA, not the DA to find it's trees. On any given level there can
       be more than 2 trees (but no more than 4? don't quote me on that); the choice of which 2
       trees to merge is dictated by their age (oldest trees first), which is implicit in their
       location in the level ("left-most" first?). But just in case something goes wrong, lets
       check the tree sequence numbers as well. */
    /*          8 */ tree_seq_t                  in_tree_0;
    /*         12 */ tree_seq_t                  in_tree_1;
    /*         16 */ struct castle_clist_entry   out_tree;
    /*        528 */ btree_t                     btree_type;
    /*        529 */ int32_t                     root_depth;
    /*        533 */ int8_t                      is_new_key;
    /*        534 */ c_ext_pos_t                 last_leaf_node_cep;
    /*        550 */ int8_t                      completing;
    /*        551 */ uint64_t                    nr_entries;
    /*        559 */ uint64_t                    large_chunks;
    /*        567 */ int8_t                      leafs_on_ssds;
    /*        568 */ int8_t                      internals_on_ssds;
    /*        569 */ uint32_t                    skipped_count;
    /*        573 */

                   /* next few entries assume MAX_BTREE_DEPTH=10 */
                   /* TODO@tr change SoA to Aos */
    /*        573 */ c_ext_pos_t                 node_c2b_cep[MAX_BTREE_DEPTH];
    /*        733 */ int32_t                     next_idx[MAX_BTREE_DEPTH];
    /*        773 */ int32_t                     node_used[MAX_BTREE_DEPTH]; /* uncertain if this
                                                                                is needed... might
                                                                                get rid of it */
    /*        813 */ int32_t                     valid_end_idx[MAX_BTREE_DEPTH];
    /*        853 */ version_t                   valid_version[MAX_BTREE_DEPTH];
    /*        893 */ uint8_t                     pad_to_iters[3]; /* beyond here entries are
                                                                     frequently marshalled, so
                                                                     alignment is important */

                    /* iterators, assuming we always have 2 immut_iters per merge */
    /*        896 */ int32_t                     iter_err;
    /*        900 */ int64_t                     iter_non_empty_cnt;
    /*        908 */ uint64_t                    iter_src_items_completed;
    /*        916 */
                          /* 2 immutable iterators */
                          /* TODO@tr change SoA to AoS */
    /*        916 */ int32_t                     iter_component_completed[2];
    /*        924 */ int32_t                     iter_component_cached[2];
    /*        932 */ int32_t                     iter_immut_curr_idx[2];
    /*        940 */ int32_t                     iter_immut_cached_idx[2];
    /*        948 */ int32_t                     iter_immut_next_idx[2];
    /*        956 */ c_ext_pos_t                 iter_immut_curr_c2b_cep[2];
    /*        988 */ c_ext_pos_t                 iter_immut_next_c2b_cep[2];

    /*       1020 */ uint8_t                     pad_to_bloom_build_params[4];
    /*       1024 */

    /*       1024 */ struct castle_bbp_entry     out_tree_bbp;
    /*       1094 */ uint8_t                     have_bbp;
    /*       1095 */ uint8_t                     pad[441];
    /*       1536 */

} PACKED;
#define SIZEOF_CASTLE_DMSERLIST_ENTRY (1536)

/**
 * Ondisk Serialized structure for castle versions.
 */
struct castle_vlist_entry {
    /* align:   8 */
    /* offset:  0 */ version_t    version_nr;
    /*          4 */ version_t    parent;
    /*          8 */ da_id_t      da_id;
    /*         12 */ uint8_t      _pad[4];
    /*         16 */ uint64_t     size;
    /*         24 */ uint64_t     flags;                /**< Flags for version LEAF & DELETED.  */
    /*         32 */ uint64_t     keys;                 /**< stats.keys                         */
    /*         40 */ uint64_t     tombstones;           /**< stats.tombstones                   */
    /*         48 */ uint64_t     tombstone_deletes;    /**< stats.tombstone_deletes            */
    /*         56 */ uint64_t     version_deletes;      /**< stats.version_deletes              */
    /*         64 */ uint64_t     key_replaces;         /**< stats.key_replaces                 */
    /*         72 */ uint8_t      _unused[184];
    /*        256 */
} PACKED;

#define MAX_NAME_SIZE 128
struct castle_alist_entry {
    /* align:   4 */
    /* offset:  0 */ version_t   version;
    /*          4 */ char        name[MAX_NAME_SIZE];
    /*        132 */ uint8_t     _unused[124];
    /*        256 */
} PACKED;

#define MLIST_NODE_MAGIC  0x0000baca
struct castle_mlist_node {
    /* align:   8 */
    /* offset:  0 */ uint32_t    magic;
    /*          4 */ uint16_t    capacity;
    /*          6 */ uint16_t    used;
    /*          8 */ c_ext_pos_t next;
    /*         24 */ uint8_t     _unused[40];
    /*         64 */ uint8_t     payload[0];
    /*         64 */
} PACKED;

struct castle_lolist_entry {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t  ext_id;
    /*          8 */ uint64_t    length;
    /*         16 */ tree_seq_t  ct_seq;
    /*         20 */ uint8_t     _unused[12];
    /*         32 */
} PACKED;

enum {
    STATS_MSTORE_REBUILD_PROGRESS,
};

struct castle_slist_entry {
    /* align:  8 */
    /* offset: 0 */ uint16_t    stat_type;
    /*         2 */ uint8_t     _pad[6];
    /*         8 */ uint64_t    key;
    /*        16 */ uint64_t    val;
    /*        24 */ uint8_t     _unused[40];
    /*        64 */
} PACKED;

/* IO related structures */
struct castle_bio_vec;
struct castle_object_replace;
struct castle_object_get;

typedef struct castle_bio {
    struct castle_attachment         *attachment;
    /* castle_bio is created to handle a bio, or an rxrpc call (never both) */
    int                               data_dir;
    /* Pointer to the op that created this c_bio. */
    union {
        struct bio                   *bio;
        struct castle_object_replace *replace;
        struct castle_object_get     *get;
        struct castle_object_pull    *pull;
    };
    struct castle_bio_vec            *c_bvecs;
    atomic_t                          count;
    int                               err;
#ifdef CASTLE_DEBUG
    int                               stuck;
    int                               id;
    int                               nr_bvecs;
    struct list_head                  list;
#endif
} c_bio_t;


struct castle_cache_block;
struct castle_request_timeline;
#define CBV_ONE2ONE_BIT               (0)
#define CBV_ROOT_LOCKED_BIT           (1)
#define CBV_PARENT_WRITE_LOCKED       (3)
#define CBV_CHILD_WRITE_LOCKED        (4)
/* Temporary variable used to set the above correctly, at the right point in time */
#define CBV_C2B_WRITE_LOCKED          (5)

typedef struct castle_bio_vec {
    c_bio_t                      *c_bio;        /**< Where this IO originated                   */

    void                         *key;          /**< Key we want to read                        */
    version_t                     version;      /**< Version of key we want to read             */
    int                           cpu;          /**< CPU id for this request                    */
    int                           cpu_index;    /**< CPU index (for determining correct CT)     */
    struct castle_component_tree *tree;         /**< CT to search                               */

    /* Btree walk variables. */
    unsigned long                 flags;        /**< Flags                                      */
    int                           btree_depth;  /**< How far down the btree we've gone so far   */
    int                           btree_levels; /**< Levels in the tree (private copy in case
                                                     someone splits root node while we are
                                                     lower down in the tree                     */
    void                         *parent_key;   /**< Key in parent node btree_node is from      */
    /* When writing, B-Tree node and its parent have to be locked concurrently. */
    struct castle_cache_block    *btree_node;
    struct castle_cache_block    *btree_parent_node;

    /* Bloom filters. */
    struct castle_cache_block *bloom_c2b;
#ifdef CASTLE_BLOOM_FP_STATS
    int bloom_positive;
#endif

    struct work_struct               work;      /**< Used to thread this bvec onto a workqueue  */
    union {
        /* Castle Value Tuple allocation callback for writes */
        int                        (*cvt_get)    (struct castle_bio_vec *,
                                                  c_val_tup_t,
                                                  c_val_tup_t *);
        /* Get reference on objects for reads */
        int                        (*ref_get)    (struct castle_bio_vec *,
                                                  c_val_tup_t);
    };
    /* Completion callback */
    union {
        void                       (*queue_complete)  (struct castle_bio_vec *, int);
        void                       (*submit_complete) (struct castle_bio_vec *, int, c_val_tup_t);
    };
    void                           (*orig_complete)   (struct castle_bio_vec *, int, c_val_tup_t);
    atomic_t                         reserv_nodes;
    struct list_head                 io_list;
#ifdef CASTLE_DEBUG
    unsigned long                    state;
    struct castle_cache_block       *locking;
#endif
#ifdef CASTLE_PERF_DEBUG
    struct castle_request_timeline  *timeline;
#endif
} c_bvec_t;

#define REMOVE                        (2)

#define c_bvec_data_dir(_c_bvec)      ((_c_bvec)->c_bio->data_dir & RW_MASK)
#define c_bvec_data_del(_c_bvec)      ((_c_bvec)->c_bio->data_dir & REMOVE)
#define c2b_bnode(_c2b)               ((struct castle_btree_node *)c2b_buffer(_c2b))
#define c_bvec_bnode(_c_bvec)           c2b_bnode((_c_bvec)->btree_node)
#define c_bvec_bpnode(_c_bvec)          c2b_buffer((_c_bvec)->btree_parent_node)
#define c_bvec_btree_fn(_c_bvec, _fn) ((_c_bvec)->c_bio->btree->(_fn))

/* Iterface implemented by various iterators in the module. Skip function is optional. */
/*
 * Sequence of iterator functions to be called
 *      -> prep_next()
 *          <- end_io()
 *      -> has_next()
 *      -> next()
 */
/* end_io - gets called after completing the lower level iterator. Call
 *          prep_next() to make sure buffer is not empty, If so prep_next would
 *          schedule lower level iterator again. If prep_next() returns 1, then
 *          call upper level iterator's callback. */
typedef void (*castle_iterator_end_io_t)(void *iter,
                                         int err);
/* register_cb - sets the calback function to be called after preparing buffer */
typedef void (*castle_iterator_register_cb_t)(void *iter,
                                              castle_iterator_end_io_t cb,
                                              void *data);

/* prep_next - Returns
 *         1 - if the iterator has content ready in buffers to respond to next()
 *         0 - if the iterator needs to get contents schedule lower level
 *             iterator; this leads to a call to iterator's end_io() after
 *             completion of lower level iterator */
typedef int  (*castle_iterator_prep_next_t)(void *iter);
/* has_next -  Returns
          1 -  if the iterator buffer is not empty
          0 -  if the buffer is empty */
typedef int  (*castle_iterator_has_next_t)(void *iter);
/* next - gets called only if buffer is not empty */
typedef void (*castle_iterator_next_t)    (void *iter,
                                           void **key_p,
                                           version_t *version_p,
                                           c_val_tup_t *cvt_p);
/* skip - set the low level iterator to skip to the key, but don't run lower
 *        level iterator. It shouldn't block */
typedef void (*castle_iterator_skip_t)    (void *iter,
                                           void *key);
typedef void (*castle_iterator_cancel_t)  (void *iter);
struct castle_iterator_type {
    castle_iterator_register_cb_t register_cb;
    castle_iterator_prep_next_t   prep_next;
    castle_iterator_has_next_t    has_next;
    castle_iterator_next_t        next;
    castle_iterator_skip_t        skip;
    castle_iterator_cancel_t      cancel;
 };

/* Used to lock nodes pointed to by leaf pointers (refered to as 'indirect nodes') */
struct castle_indirect_node {
    /* Will form array of c2b/{cep, f_idx} for the indirect nodes. Sorted by
       cep. May contain holes, if multiple entries in the original node
       point to the same indirect node. Will span at most orig_node->used
       entries. */
    union {
        /* Used before entries are locked */
        struct {
            c_ext_pos_t                cep;      /* CEP from leaf pointer  */
            uint16_t                   f_idx;    /* Index in the orig node */
        };
        /* Used after entries are locked */
        struct {
            struct castle_cache_block *c2b;      /* Cache page for an 'indirect' node */
        };
    };
    /* Will form array indexed by the entry # from the orginal node. Used to find
       the right indirect node/entry in the array above. Again spans at most
       node->used entries. */
    struct {
        uint16_t                       r_idx;    /* Index in indirect_nodes array */
        uint16_t                       node_idx; /* Index in the indirect node */
    };
};

enum {
    C_ITER_ALL_ENTRIES,
    C_ITER_MATCHING_VERSIONS,
    C_ITER_ANCESTRAL_VERSIONS
};

/* Used for iterating through the tree */
typedef struct castle_iterator {
    /* Fields below should be filled in before iterator is registered with the btree
       code with btree_iter_init() and start() */
    int                         (*need_visit)(struct castle_iterator *c_iter,
                                              c_ext_pos_t node_cep);
    void                        (*node_start)(struct castle_iterator *c_iter);
    void                        (*each)      (struct castle_iterator *c_iter,
                                              int index,
                                              void *key,
                                              version_t version,
                                              c_val_tup_t cvt);
    void                        (*node_end)  (struct castle_iterator *c_iter);
    void                        (*end)       (struct castle_iterator *c_iter, int err);
    void                         *private;
    struct castle_component_tree *tree;

    /* Fields below are used by the iterator to conduct the walk */
    int                           type;       /* C_ITER_XXX */
    version_t                     version;
    void                         *parent_key; /* The key we followed to get to the block
                                                 on the top of the path/stack */
    union {
        /* Used by C_ITER_ALL_ENTRIES       */
        int                       node_idx[MAX_BTREE_DEPTH];
        /* Used by C_ITER_MATCHING_VERSIONS & C_ITER_ANCESTORAL_VERSIONS */
        struct {
            void                 *key;          /* The next key to look for in the iteration
                                                   (typically parent_key + 1 when at leafs) */
            int                   need_destroy; /* True if allocated by the iterator
                                                   (and needs destroying at the end) */
        } next_key;

    };
    int                           cancelled;
    int                           err;

    struct castle_cache_block    *path[MAX_BTREE_DEPTH];
    int                           depth;
    int                           btree_levels;   /**< Private copy of ct->tree_depth, recorded
                                                       at the time when the walk started.
                                                       Used to prevent races with root node
                                                       splits. */

    struct castle_indirect_node  *indirect_nodes; /* If allocated, MAX_BTREE_ENTRIES */

    struct work_struct            work;
} c_iter_t;

/* Enumerates all entries in a modlist btree */
typedef struct castle_enumerator {
    struct castle_component_tree *tree;
    int                           err;
    struct castle_iterator        iterator;
    wait_queue_head_t             iterator_wq;
    volatile int                  iterator_outs;
    int                           iter_completed;
    /* Variables used to buffer up entries from the iterator */
    int                           prod_idx;
    int                           cons_idx;
    struct castle_btree_node     *buffer;       /* Two buffers are actually allocated (buffer1/2) */
    struct castle_btree_node     *buffer1;      /* buffer points to the one currently used to     */
    struct castle_btree_node     *buffer2;      /* read in a node, second is used to preserve     */
                                                /* key pointer validity. TODO: fix, waseful.      */

    /* Set to decide whether to visit nodes, implemented as hash table */
    struct {
        spinlock_t                visited_lock;
        struct list_head         *visited_hash;
        int                       next_visited;
        int                       max_visited;
        struct castle_visited {
            c_ext_pos_t           cep;
            struct list_head      list;
        } *visited;
    };
} c_enum_t;

struct node_buf_t;
struct node_buf_t {
    struct castle_btree_node *node;
    struct list_head          list;
};

/**
 * Non-atomic statistics specific to a given version.
 *
 * @also castle_version_stats
 */
typedef struct castle_version_nonatomic_stats {
    long        keys;               /**< castle_version_stats.keys                          */
    long        tombstones;         /**< castle_version_stats.tombstones                    */
    long        tombstone_deletes;  /**< castle_version_stats.tombstone_deletes             */
    long        version_deletes;    /**< castle_version_stats.version_deletes               */
    long        key_replaces;       /**< castle_version_stats.key_replaces                  */
} cv_nonatomic_stats_t;

/* Enumerates latest version value for all entries */
typedef struct castle_rq_enumerator {
    struct castle_component_tree *tree;
    int                           err;
    version_t                     version;
    struct castle_iterator        iterator;
    volatile int                  iter_completed;
    wait_queue_head_t             iter_wq;
    volatile int                  iter_running;
    struct node_buf_t            *prod_buf;
    int                           prod_idx;
    struct node_buf_t            *cons_buf;
    int                           cons_idx;
    struct node_buf_t            *buf_head;
    int                           buf_count;
    void                         *cur_key;
    void                         *start_key;
    void                         *end_key;
    void                         *last_key;  /* Last key returned by next(). */
    int                           in_range;
    castle_iterator_end_io_t      end_io;
    void                         *private;
    int                           sync_call; /* TODO: Cleanup, not requried */
} c_rq_enum_t;

struct castle_merged_iterator;
struct component_iterator;

typedef void (*castle_merged_iterator_each_skip) (struct castle_merged_iterator *,
                                                  struct component_iterator *,
                                                  struct component_iterator *);

typedef struct castle_merged_iterator {
    int nr_iters;
    struct castle_btree_type *btree;
    int err;
    int64_t non_empty_cnt;
    uint64_t src_items_completed;
    struct component_iterator {
        int                          completed;
        void                        *iterator;
        struct castle_iterator_type *iterator_type;
        int                          cached;
        struct {
            void                    *k;
            version_t                v;
            c_val_tup_t              cvt;
        } cached_entry;
        struct rb_node               rb_node;
    } *iterators;
    struct rb_root                   rb_root;
    cv_nonatomic_stats_t             stats;         /**< Stat changes during last _next().  */
    castle_merged_iterator_each_skip each_skip;
    castle_iterator_end_io_t         end_io;
    void                            *private;
} c_merged_iter_t;

typedef struct castle_da_rq_iterator {
    int                       nr_cts;
    int                       err;
    c_merged_iter_t           merged_iter;

    struct ct_rq {
        struct castle_component_tree *ct;
        c_rq_enum_t                   ct_rq_iter;
    } *ct_rqs;
    castle_iterator_end_io_t  end_io;
    void                     *private;
} c_da_rq_iter_t;


#define BLOCKS_HASH_SIZE        (100)
struct castle_slave_block_cnt
{
    version_t        version;
    block_t          cnt;
    struct list_head list;
    c_mstore_key_t   mstore_key;
};

struct castle_slave_block_cnts
{
    struct list_head hash[BLOCKS_HASH_SIZE];     /* The hashtable is protected by
                                                    castle_slave superblock lock   */
    struct castle_slave_block_cnt metadata_cnt;  /* Count for version 0 (metadata) */
};

/**
 * Structure describing the printk ring buffer.
 */
struct castle_printk_buffer {
    char           *buf;    /**< Ring buffer.           */
    c_byte_off_t    off;    /**< Write pointer.         */
    c_byte_off_t    size;   /**< Size of ring buffer.   */
    int             wraps;  /**< Times buf has wrapped. */
    spinlock_t      lock;   /**< Protects structure.    */
};

/* First class structures */
struct castle {
    struct kobject kobj;
};

struct castle_slave {
    uint32_t                        id;
    uint32_t                        uuid; /* Copy of the uuid from the superblock
                                             needed here, because we cannot cache
                                             the superblock without being able to
                                             _find_by_uuid */
    unsigned long                   flags;
    int                             new_dev;
    struct kobject                  kobj;
    struct list_head                list;
    struct rcu_head                 rcu;
    struct block_device            *bdev;
    c_ext_id_t                      sup_ext;
    c_disk_chk_t                   *sup_ext_maps;
    struct mutex                    freespace_lock;
    castle_freespace_t              freespace;
    c_chk_cnt_t                     prev_prod;
    c_chk_cnt_t                     frozen_prod;
    struct castle_slave_block_cnts  block_cnts;
    unsigned long                   last_access;
    struct castle_slave_superblock  cs_superblock;
    struct castle_fs_superblock     fs_superblock;
    uint32_t                        fs_versions[2]; /* The fs versions for this slave. */
    struct mutex                    sblk_lock;
    c_chk_cnt_t                     disk_size; /* in chunks; max_chk_num + 1 */
    c_chk_cnt_t                     reserved_schks;
    atomic_t                        free_chk_cnt;
    atomic_t                        io_in_flight;
    char                            bdev_name[BDEVNAME_SIZE];
    struct work_struct              work;
};
/* castle_slave flags bits */
#define CASTLE_SLAVE_OOS_BIT        0 /* Slave is out-of-service */
#define CASTLE_SLAVE_EVACUATE_BIT   1 /* Slave is being, or has been, evacuated */
#define CASTLE_SLAVE_GHOST_BIT      2 /* Slave is missing or invalid (on reboot) */
#define CASTLE_SLAVE_REMAPPED_BIT   3 /* Slave has been remapped */
#define CASTLE_SLAVE_CLAIMING_BIT   4 /* Slave is not yet available for use (in castle_claim) */
#define CASTLE_SLAVE_BDCLAIMED_BIT  5 /* Slave has been bd_claim'ed. */

struct castle_slaves {
    struct kobject   kobj;
    struct list_head slaves;
};

/* Castle attachment represents a block device or an attached object collection */
struct castle_attachment {
    version_t           version;
    int                 ref_cnt; /* protected by castle_attachments.lock */
    struct rw_semaphore lock;
    int                 device; /* !=0 if block device, == 0 if object collection */
    union {
        struct {
            struct gendisk  *gd;
        } dev; /* Only valid for block devices */
        struct {
            collection_id_t  id;
            char            *name;
        } col; /* Only valid for object collections */
    };

    /* Stats for attachment. */
    struct {
        atomic64_t      ios;
        atomic64_t      bytes;
    } get, put, big_get, big_put, rq;
    atomic64_t          rq_nr_keys;

    struct kobject      kobj;
    int                 sysfs_registered;
    struct list_head    list;
};

struct castle_attachments {
    struct kobject          collections_kobj;
    struct kobject          devices_kobj;
    int                     major;
    struct list_head        attachments;
    spinlock_t              lock;
};

extern struct castle              castle;
extern struct castle_slaves       castle_slaves;
extern struct castle_attachments  castle_attachments;
extern da_id_t                    castle_next_da_id;

extern struct workqueue_struct *castle_wqs[2*MAX_BTREE_DEPTH+1];
#define castle_wq              (castle_wqs[0])

/* Various utilities */
#define C_BLK_SHIFT                    (12)
#define C_BLK_SIZE                     (1 << C_BLK_SHIFT)
//#define disk_blk_to_offset(_cdb)     ((_cdb).block * C_BLK_SIZE)

struct castle_attachment*
                      castle_device_init           (version_t version);
void                  castle_device_free           (struct castle_attachment *cd);
struct castle_attachment*
                      castle_device_find           (dev_t dev);

struct castle_attachment*
                      castle_collection_init       (version_t version, char *name);

struct castle_attachment *
                      castle_attachment_get        (collection_id_t collection);
void                  castle_attachment_put        (struct castle_attachment *ca);
void                  castle_attachment_free       (struct castle_attachment *ca);
void                  castle_attachment_free_complete(struct castle_attachment *ca);

struct castle_slave*  castle_claim                 (uint32_t new_dev);
void                  castle_release               (struct castle_slave *cs);
void                  castle_release_device        (struct castle_slave *cs);

void                  castle_slave_access          (uint32_t uuid);

struct castle_slave*  castle_slave_find_by_id      (uint32_t id);
struct castle_slave*  castle_slave_find_by_uuid    (uint32_t uuid);
struct castle_slave*  castle_slave_find_by_bdev    (struct block_device *bdev);
struct castle_slave*  castle_slave_find_by_block   (c_ext_pos_t cep);

struct castle_slave_superblock*
                      castle_slave_superblock_get  (struct castle_slave *cs);
void                  castle_slave_superblock_put  (struct castle_slave *cs, int dirty);
struct castle_fs_superblock*
                      castle_fs_superblocks_get    (void);
void                  castle_fs_superblocks_put    (struct castle_fs_superblock *sb, int dirty);
void                  castle_fs_superblock_slaves_update
                                                   (struct castle_fs_superblock *fs_sb);

int                   castle_fs_init               (void);

void                  castle_ext_freespace_init    (c_ext_free_t     *ext_free,
                                                    c_ext_id_t        ext_id);

int                   castle_new_ext_freespace_init(c_ext_free_t     *ext_free,
                                                    da_id_t           da_id,
                                                    c_ext_type_t      ext_type,
                                                    c_byte_off_t      size, 
                                                    int               in_tran,
                                                    void              *data,
                                                    c_ext_event_callback_t callback);

int                   castle_ext_freespace_consistent
                                                   (c_ext_free_t     *ext_frees);

void                  castle_ext_freespace_fini    (c_ext_free_t     *ext_free);

int                   castle_ext_freespace_prealloc(c_ext_free_t     *ext_free,
                                                    c_byte_off_t      size);
int                   castle_ext_freespace_can_alloc
                                                   (c_ext_free_t *ext_free,
                                                    c_byte_off_t size);
int                   castle_ext_freespace_get     (c_ext_free_t     *ext_free,
                                                    c_byte_off_t      size,
                                                    int               alloc_done,
                                                    c_ext_pos_t      *cep);

int                   castle_ext_freespace_free    (c_ext_free_t     *ext_free,
                                                    int64_t           size);

void                  castle_ext_freespace_marshall(c_ext_free_t     *ext_free,
                                                    c_ext_free_bs_t  *ext_free_bs);

void                  castle_ext_freespace_unmarshall
                                                   (c_ext_free_t     *ext_free,
                                                    c_ext_free_bs_t  *ext_free_bs);

c_byte_off_t          castle_ext_freespace_summary_get
                                                   (c_ext_free_t     *ext_free);
void                  castle_release_oos_slave     (struct work_struct *work) ;

struct castle_cache_block;

struct castle_object_replace {
    uint64_t                      value_len;        /**< Length of the value being written out. */
    c_val_tup_t                   cvt;              /**< CVT allocated for the value.           */
    c_bvec_t                     *c_bvec;           /**< bvec to be submitted to DA.            */

    /* Variables used when copying the value into the CVT. */
    struct castle_cache_block    *data_c2b;         /**< Current cache block used to copy the
                                                         data out.                              */
    uint64_t                      data_c2b_offset;  /**< Offset in the data_c2b at which future
                                                         writes should start from (everything
                                                         up to data_c2b_offset has already been
                                                         used up).                              */
    uint64_t                      data_length;      /**< Amount of data still to be written out
                                                         initialy equals value_len.             */

    /* Call on completion of big_put. */
    void        (*complete)        (struct castle_object_replace *op,
                                    int                           err);
    /* Call on completion of copy of a chunk for put_chunk(). */
    void        (*replace_continue)(struct castle_object_replace *op);

    /* Length of current put_chunk. */
    uint32_t    (*data_length_get) (struct castle_object_replace *op);

    /* Copy data from interface buffers into cache buffers(C2B). */
    void        (*data_copy)       (struct castle_object_replace *op,
                                    void                         *buffer,
                                    uint32_t                      str_length,
                                    int                           partial);
};

struct castle_object_get {
    struct castle_component_tree *ct;
    struct castle_cache_block *data_c2b;
    uint64_t    data_c2b_length;
    uint64_t    data_length;
    int         first;
    c_val_tup_t cvt;

    void      (*reply_start)     (struct castle_object_get *get,
                                  int err,
                                  uint64_t data_length,
                                  void *buffer,
                                  uint32_t buffer_length);
    void      (*reply_continue)  (struct castle_object_get *get,
                                  int err,
                                  void *buffer,
                                  uint32_t buffer_length,
                                  int last);
};

struct castle_object_pull {
    uint64_t                    remaining;
    uint64_t                    offset;

    int                         is_inline;
    union {
        c_ext_pos_t             cep;
        char                   *inline_val;
    };
    c_val_tup_t                 cvt;
    struct castle_component_tree *ct;
    struct castle_cache_block  *curr_c2b;

    void                       *buf;
    uint32_t                    to_copy;

    struct work_struct          work;

    void (*pull_continue)      (struct castle_object_pull *pull,
                                int err, uint64_t length, int done);
};
/*
 * This is the callback to notify when the iterator has the
 * next key available. The callback should return non-zero if
 * it wants the next value without calling castle_object_iter_next
 * again.
 */
struct castle_object_iterator;
typedef int (*castle_object_iter_next_available_t)
        (struct castle_object_iterator *iter,
         c_vl_okey_t *key,
         c_val_tup_t *val,
         int err,
         void *data);

typedef struct castle_object_iterator {
    /* Filled in by the client */
    da_id_t             da_id;
    version_t           version;
    c_vl_okey_t        *start_okey;
    c_vl_okey_t        *end_okey;

    /* Rest */
    int                 err;
    c_vl_bkey_t        *start_bkey;
    c_vl_bkey_t        *end_bkey;
    int                 completed;
    c_vl_bkey_t        *last_next_key;
    c_da_rq_iter_t      da_rq_iter;
    /* Cached entry, guaranteed to fall in the hypercube */
    int                 cached;
    void               *cached_k;
    version_t           cached_v;
    c_val_tup_t         cached_cvt;
    castle_iterator_end_io_t end_io;
    castle_object_iter_next_available_t next_available;
    void               *next_available_data;
    void               *data;
    struct work_struct  work;
} castle_object_iterator_t;

int castle_superblocks_writeback(uint32_t version);

void castle_ctrl_lock               (void);
void castle_ctrl_unlock             (void);
int  castle_ctrl_is_locked          (void);

#define CASTLE_TRANSACTION_BEGIN    castle_ctrl_lock()
#define CASTLE_TRANSACTION_END      castle_ctrl_unlock()
#define CASTLE_IN_TRANSACTION       castle_ctrl_is_locked()

#define FAULT(_fault)                                           \
    if (castle_fault == _fault)                                 \
    {                                                           \
        castle_printk(LOG_ERROR, "User asked for fault\n");     \
        BUG();                                                  \
    }

#define INJECT_ERR(_fault)          (castle_fault == _fault)

#define INJECT_FAULT                FAULT(FAULT_CODE)

extern c_fault_t castle_fault;
extern uint32_t  castle_fault_arg;

/* Ref: This code is taken from wikipedia. */
static uint32_t __attribute__((used)) fletcher32( uint16_t *data, size_t len )
{
        uint32_t sum1 = 0xffff, sum2 = 0xffff;

        /* Length should be in terms if 16-bit words. */
        if (len % 2) *((size_t *)(uint64_t)(sum1 - sum2)) = len;
        len = (len / 2);

        while (len) {
                unsigned tlen = len > 360 ? 360 : len;
                len -= tlen;
                do {
                        sum1 += *data++;
                        sum2 += sum1;
                } while (--tlen);
                sum1 = (sum1 & 0xffff) + (sum1 >> 16);
                sum2 = (sum2 & 0xffff) + (sum2 >> 16);
        }
        /* Second reduction step to reduce sums to 16 bits */
        sum1 = (sum1 & 0xffff) + (sum1 >> 16);
        sum2 = (sum2 & 0xffff) + (sum2 >> 16);
        return sum2 << 16 | sum1;
}

struct castle_merge_token {
    int driver_level;
    int ref_cnt;
    struct list_head list;
};

/* Low free space structure being used by each merge in DA. */
struct castle_da_lfs_ct_t {
    uint8_t             space_reserved;     /**< Reserved space from low space handler  */
    struct castle_double_array *da;         /**< Double-array */
    struct {
        c_chk_cnt_t     size;               /**< Size of the extent to be reserved      */
        c_ext_id_t      ext_id;             /**< ID to be set after space is reserved   */
    } internal_ext, tree_ext, data_ext;
    int                 leafs_on_ssds;
    int                 internals_on_ssds;
};

/* Possible states of merge serialisation control atomics in da->levels[].merge.serdes,
   which indicate the state of the serialised state (struct dmserlist_entry) mstore_entry */
typedef enum {
    /* DO NOT REORDER */
    NULL_DAM_SERDES=0,          /* not yet alloc'd, or undergoing deserialisation */
    INVALID_DAM_SERDES,         /* alloc'd but not yet checkpointable */
    VALID_AND_FRESH_DAM_SERDES, /* checkpointable and has changed since last checkpoint */
    VALID_AND_STALE_DAM_SERDES, /* checkpointable, but not changed since last checkpoint */
    MAX_DAM_SERDES /* must be last entry */
} c_merge_serdes_state_t;

#define MAX_DA_LEVEL                        (20)
#define DOUBLE_ARRAY_GROWING_RW_TREE_BIT    (0)
#define DOUBLE_ARRAY_DELETED_BIT            (1)
#define DOUBLE_ARRAY_NEED_COMPACTION_BIT    (2)
#define DOUBLE_ARRAY_COMPACTING_BIT         (3)
#define MIN_DA_SERDES_LEVEL                 (2) /* merges below this level won't be serialised */
struct castle_double_array {
    da_id_t                     id;
    version_t                   root_version;
    rwlock_t                    lock;               /**< Protects levels[].trees lists          */
    struct kobject              kobj;
    unsigned long               flags;
    int                         nr_trees;           /**< Total number of CTs in the da          */
    struct {
        int                     nr_trees;           /**< Number of CTs at level                 */
        int                     nr_compac_trees;    /**< #trees that need to be merged          */
        struct list_head        trees;              /**< List of (nr_trees) at level            */
        /* Merge related variables. */
        struct {
            struct list_head    merge_tokens;
            struct castle_merge_token
                               *active_token;
            struct castle_merge_token
                               *driver_token;
            uint32_t            units_commited;
            struct task_struct *thread;
            int                 deamortize;
            /* Merge serialisation/deserialisation */
            struct {
#ifdef DEBUG_MERGE_SERDES
                int                            merge_completed;
#endif
                struct castle_component_tree  *out_tree; /* points to merge->out_tree, which holds
                                                            list of serialised large_objs */
                /* Design note: On large_obj handling.

                   Before merge checkpointing, we could assume that a cct only contained/owned a
                   valid non-zero large_objs list if it was "complete" (i.e. not being produced
                   through a merge operation). While a merge was underway, we would produce a
                   large objects list to hold results of the ongoing merge. This list was owned by
                   the merge, and populated from da_entry_add.  When the merge was complete, the
                   merge passes ownership of the large_objs list to the cct through a list_replace
                   operation in da_merge_package.

                   There are a couple of issues here w.r.t. merge checkpointing. Firstly, on the
                   serialisation side, we would need to maintain a list of large_objs corresponding
                   to the serialised state of the tree. This list of large_objs would be written
                   back during checkpoint. This by itself is not an issue - we simply need to
                   maintain a list that is accessible to the checkpoint thread, i.e. right here in
                   the double_array structure. That list would have to be deallocated at rmmod
                   time so we don't violate any ref_cnt sanity checks on the large_objects, since
                   it is currently assumed that each LO would only have 1 reference to it.

                   Secondly, we would need to deserialise this list of large_objs. In order to
                   reuse the current deserialisation scheme (as in castle_da_read), we would have
                   to create a large_obj list onto the deserialising tree. The alternative is to
                   handle deserialisation of the incomplete output tree outside the standard path,
                   but that will require changes to the standard deserialisation path anyway since
                   at least one sanity check will fail (i.e. it will find large_objs linked to
                   ccts that it cannot find). Furthermore, we would have to mark the LO extents
                   live so they are not removed prematurely.

                   Therefore, while a merge is ongoing, by design, the output tree under merge has
                   a list of large_obj that corresponds to it's serialised state. When the merge is
                   completed this list is completed. If a merge is aborted, this list must be
                   dropped (after it has been checkpointed) in order to avoid a bad ref count
                   sanity check. After deserialising, the tree once again has a list of large_obj
                   that corresponds to the serialised state - therefore symmetry is maintained and
                   a deserialised tree would be indistinguishable from a newly created one in mid-
                   merge.

                   (This symmetry could also have been maintained by allowing the output cct
                   to always hold it's "live" state (since at deserialisation time, serialised
                   state == live state), but that would have then required maintenance of 3 lists:
                   a "live list", a "serialised list", and a "new list" which is the diff btwn
                   the live list and the serialised list. In practice we only need the serialised
                   list and the new list, since the live list is worthless until the merge
                   completes anyway.)

                   For this reason we need to maintain a pointer to the output tree in this struct,
                   and in the case of an aborted merge, the output tree must persist beyond
                   merge_dealloc so that it can be written out by the final checkpoint before being
                   dropped by da_dealloc.
                 */
                struct castle_dmserlist_entry *mstore_entry;
                struct mutex     mutex; /* because we might lock while using mstore, spinlock
                                           may be a bad idea. might need a "double buffering"
                                           solution with round robin selection over 2
                                           mstore_entry structures to get around it? */
                atomic_t         valid; /* for merge thread to notify checkpoint when state is
                                           checkpointable; see c_merge_serdes_state_t */
                unsigned int     des; /* for init to notify merge thread to resume merge, and
                                         to notify checkpoint not to writeback state because
                                         deserialisation still running. */
            } serdes;
        } merge;
        struct castle_da_lfs_ct_t lfs;              /**< Low Free-Space handler for merge       */
    } levels[MAX_DA_LEVEL];
    atomic_t                    lfs_victim_count;   /**< Number of components of DA, that are
                                                         blocked due to Low Free-Space.         */
    struct castle_da_lfs_ct_t  *t0_lfs;             /**< Low Free-Space handler for T0s.        */
    struct castle_merge_token   merge_tokens_array[MAX_DA_LEVEL];
    struct list_head            merge_tokens;
    struct list_head            hash_list;
    int                         driver_merge;
    atomic_t                    ongoing_merges;     /**< Number of ongoing merges.              */
    atomic_t                    ref_cnt;
    uint32_t                    attachment_cnt;

    /* Write IO wait queue members */
    struct castle_da_io_wait_queue {
        spinlock_t              lock;               /**< Protects list,cnt (accessed by 1 CPU so
                                                         should be no need for rwlock)          */
        int                     cnt;                /**< Number of pending write IOs            */
        struct list_head        list;               /**< List of pending write IOs              */
        struct castle_double_array *da;             /**< Back pointer to parent DA              */
        struct work_struct      work;               /**< For queue kicks                        */
    } *ios_waiting;                                 /**< Array of pending write IO queues,
                                                         1 queue per request-handling CPU       */
    atomic_t                    ios_waiting_cnt;    /**< Total number of pending write IOs      */
    atomic_t                    ios_budget;         /**< Remaining number of write IOs that can
                                                         hit T0 before they get queued          */
    int                         ios_rate;           /**< ios_budget initialiser; for throttling
                                                         writes to the btrees                   */

    wait_queue_head_t           merge_waitq;        /**< Merge deamortisation wait queue        */
    /* Merge throttling. DISABLED ATM. */
    atomic_t                    epoch_ios;
    atomic_t                    merge_budget;
    wait_queue_head_t           merge_budget_waitq;
    /* Compaction (Big-merge) */
    int                         top_level;          /**< Levels in the doubling array.          */
    atomic_t                    nr_del_versions;    /**< Versions deleted since last compaction.*/

    /* General purpose structure for placing DA on a workqueue.
     * @TODO Currently used only by castle_da_levle0_modified_promote(), hence
     * there is no locking. */
    struct work_struct          work;               /**< General purpose work structure.        */
    void                       *private;            /**< Work private data.                     */
};

extern int castle_latest_key;

/**
 * Snapshot delete state.
 *
 * Gets reset for each new key on the merge stream.
 */
struct castle_version_delete_state {
    char               *occupied;       /**< v'th bit set if key exists for version v.      */
    char               *need_parent;    /**< v'th bit set if version v depends on parent
                                             for the current key.                           */
    struct list_head   *next_deleted;   /**< Next version in list of reverse DFS order of
                                             deleted versions.                              */
    int                 last_version;   /**< Last version that is created before starting
                                             the merge.                                     */
};

/**
 * Various statistics stored on a per-version basis.
 *
 * @also castle_version_stats
 */
typedef enum castle_version_stat_id {
    CV_KEYS_ID = 0,                 /**< castle_version_stats.keys                          */
    CV_TOMBSTONES_ID,               /**< castle_version_stats.tombstones                    */
    CV_TOMBSTONE_DELETES_ID,        /**< castle_version_stats.tombstone_deletes             */
    CV_VERSION_DELETES_ID,          /**< castle_version_stats.version_deletes               */
    CV_KEY_REPLACES_ID,             /**< castle_version_stats.key_replaces                  */
} cv_stat_id_t;

/**
 * Statistics specific to a given version.
 *
 * @also castle_version_stat_id
 * @also castle_version_nonatomic_stats
 */
typedef struct castle_version_stats {
    atomic64_t  keys;               /**< Number of live keys.  May be inaccurate until all
                                         merges complete and duplicates are handled.        */
    atomic64_t  tombstones;         /**< Number of tombstones.                              */
    atomic64_t  tombstone_deletes;  /**< Number of keys deleted by tombstones (does not
                                         include tombstones deleted by tombstones).         */
    atomic64_t  version_deletes;    /**< Number of entries deleted due to version delete.   */
    atomic64_t  key_replaces;       /**< Number of keys replaced by newer keys (excludes
                                         tombstones).                                       */
} cv_stats_t;

/**
 * Version-specific state.
 *
 * Maintain statistics about a given version.  Used by merge output.
 */
typedef struct castle_version_state {
    version_t                   version;        /**< Version ID.                            */
    struct castle_version_delete_state2 {
        uint8_t                 occupied:1;     /**< Whether keys exist in this version.    */
        uint8_t                 need_parent:7;  /**< Whether this version depends on parent
                                                     for the current key.                   */
    } delete_state;
    cv_nonatomic_stats_t        stats;          /**< Per-version stats.                     */
    struct list_head            hash_list;      /**< Hash-bucket list position.             */
} cv_state_t;

/**
 * Hash of per-version states.
 *
 * castle_version_state array allocated dynamically.
 *
 * @also castle_da_merge
 */
typedef struct castle_version_states {
#define CASTLE_VERSION_STATES_HASH_SIZE (1000)  /**< Hash buckets to allocate.              */
    struct castle_version_state    *array;      /**< Array of free version_state structs.   */
    int                             free_idx;   /**< Index of next free version_state.      */
    int                             max_idx;    /**< Max possible elements in array.        */
    struct list_head               *hash;       /**< Array of hash buckets.                 */
} cv_states_t;

/**
 * Describe changes to per-version stats.
 */
typedef struct castle_version_stats_adjust {
    version_t               version;        /**< Version to adjust stats for.                   */

    int                     live;           /**< Whether to update live version stats.          */
    cv_states_t            *private;        /**< Whether to update private per-version stats.   */
    int                     consistent;     /**< Whether to update crash consistent stats.      */

    cv_nonatomic_stats_t    stats;          /**< Stat changes.                                  */
} cv_stats_adjust_t;

extern int castle_nice_value;

extern int checkpoint_frequency;
#endif /* __CASTLE_H__ */
