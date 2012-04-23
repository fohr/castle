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
#include <linux/reboot.h>

#include "castle_public.h"

/* BUG and BUG_ON redefined to cause reliable crash-dumpable crashes. */
#undef BUG
#undef BUG_ON

/* Enable additional sanity checking to debug merge serialisation/deserialisation */
//#define DEBUG_MERGE_SERDES

/* moved to castle_utils.c for now */
void ATTRIB_NORET bug_fn(char *file, unsigned long line);

#define BUG()            do { bug_fn(__FILE__, __LINE__); } while(0)
#define BUG_ON(_cond)    do { if(unlikely(_cond)) BUG(); } while(0)

#define MAX_KMALLOC_PAGES   32                                  /**< Maximum pages we can kmalloc */
#define MAX_KMALLOC_SIZE    MAX_KMALLOC_PAGES << PAGE_SHIFT     /**< Maximum Bytes we can kmalloc */

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

#define CASTLE_INIT_WORK_AND_TRACE(_work, _func, _data) INIT_WORK((_work), (void (*)(void *)) (__trace_##_func), _data)

#define DEFINE_WQ_TRACE_FN(_func, _struct)                                          \
static void __trace_##_func(void *data)                                              \
{                                                                                   \
    int seq_id = ((_struct *)data)->seq_id;                                         \
                                                                                    \
    trace_CASTLE_REQUEST_CLAIM(seq_id);                                             \
    _func(data);                                                                    \
    trace_CASTLE_REQUEST_RELEASE(seq_id);                                           \
}

#define USED                 __attribute__((used))
#define EXIT_SUCCESS         (0)

#define STATIC_BUG_ON_HELPER(expr) \
        (!!sizeof (struct { unsigned int static_assertion_error: (expr) ? -1 : 1; }))
#define STATIC_BUG_ON(expr) \
        extern int (*assert_function__(void)) [STATIC_BUG_ON_HELPER(expr)]

#define NR_ENV_VARS          8
#define MAX_ENV_LEN          128
STATIC_BUG_ON(LAST_ENV_VAR_ID >= NR_ENV_VARS);
extern char     *castle_environment[NR_ENV_VARS];
extern int       castle_fs_inited;
extern int       castle_fs_exiting;
extern c_state_t castle_fs_state;

typedef c_array_id_t tree_seq_t;
#define GLOBAL_TREE         ((tree_seq_t)0)
#define INVAL_TREE          ((tree_seq_t)-1)
#define TREE_GLOBAL(_t)     ((_t) == GLOBAL_TREE)
#define TREE_INVAL(_t)      ((_t) == INVAL_TREE)
#define TREE_SEQ_SHIFT      (56)                    /**< Shift for RWCTs (at levels 0,1)        */

#define INVAL_DA            ((c_da_t)-1)
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
#define USED_CHUNK(offset)    (offset ? CHUNK(offset-1) : CHUNK(0))
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
 *   61 - 99                    Reserved
 *
 *   100                        Freespace to be used by extents (including meta extent and
 *                              mstore extent)
 *
 *   Meta Extent
 *   ==== ======
 *
 *   Keeps the maps for all extents (Maps for this extent would be stored in micro extent).
 *   Size of this extent depends on MAX number of slaves. We take META_SPACE_SIZE chunks from
 *   each slave for this extent. Freespace allocation is done just like any other extent, but
 *   as this extent gets allocated before any other extent it usually gets space at the
 *   front of freespace(this is not mandatory, no assumptions made on this).
 *
 *   Mstore Extents
 *   ====== =======
 *
 *   Keeps the serialised meta data for all entities in the file system(including extent
 *   structures). From extent manager point of view this is just like any other extent,
 *   except when serialising the extents, as this extent can't be reserialised into itself.
 *   We keep 2 extents for mstore to alternate checkpoints. We take MSTORE_SPACE_SIZE chunks
 *   from each slave to form this extent.
 *
 *   Extent dependency flow
 *   ====== ========== ====
 *
 *   Normal extents - BTree extents, Large object extents etc
 *                             | (depends on Meta extent to store maps)
 *                             | (depends on Mstore to serialise extent structure)
 *                             V
 *                       Mstore extents
 *                             | (depends on Meta extent to store maps
 *                             | (depends on Superextents to serialise extent structure)
 *                             V
 *                        Meta extent
 *                             | (depends on Micro extent to store maps)
 *                             | (depends on Superextents to serialise extent structure)
 *                             V
 *                        Micro extent
 *                             | (Maps are static gets created every time filesystem loads)
 *                             | (depends on Superextents to serialise extent structure)
 *                             V
 *                       Super extents
 *                             | (Maps are static gets created every time filesystem loads)
 *                             | (Extent structure is static created when FS loads)
 *                            ===
 *                             =
 *
 *
 * So, minimum size of the slave should be
 *
 * 100 + (META_SPACE_SIZE * MAX_NR_SLAVES / # of slaves) + (MSTORE_SPACE_SIZE * 2) + (global tree size * 2 / nr of slaves)
 *
 * Note: global tree size could be found in castle_global_tree, all other definitions should be
 * found in castle.h
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

/* Logical extent structures are stored separately from normal extents. They are
 * stored in extent superblock itself. */
#define LOGICAL_EXTENT(_ext_id)        ((_ext_id) < EXT_SEQ_START && !EXT_ID_INVAL(_ext_id))
#define SUPER_EXTENT(_ext_id)          (((_ext_id) >= SUP_EXT_ID) && ((_ext_id) < slave_id_to_sup_ext(MAX_NR_SLAVES)))
#define EVICTABLE_EXTENT(_ext_id)      ((_ext_id) >= EXT_SEQ_START || (_ext_id) == META_EXT_ID  \
                                            || EXT_ID_INVAL(_ext_id))

typedef uint32_t c_chk_cnt_t;
/* Signed chunk count is used by reservation pool counters. So, it
 * supports upto 2**31 chunks which is 2 PB, too big for reservation pool buffers(is it!!). */
typedef int32_t  c_signed_chk_cnt_t;
typedef uint32_t c_chk_t;
typedef uint64_t c_ext_id_t;
typedef uint32_t c_uuid_t;
typedef uint32_t c_ext_mask_id_t;
typedef uint32_t c_res_pool_id_t;

#define INVAL_RES_POOL                  ((c_res_pool_id_t) -1)
#define RES_POOL_INVAL(_pool)           ((_pool) == INVAL_RES_POOL)

/**
 * Reservation pools contain reservation from all the slaves, together. Reservation pool IDs are
 * persistent across reboots.
 */
typedef struct castle_reservation_pool {
    c_res_pool_id_t     id;
    struct list_head    hash_list;
    atomic_t            ref_count;
    c_signed_chk_cnt_t  reserved_schks[MAX_NR_SLAVES];
    c_chk_cnt_t         frozen_freed_schks[MAX_NR_SLAVES];
    c_chk_cnt_t         freed_schks[MAX_NR_SLAVES];    /* Superchunks freed, but not yet
                                                          checkpointed. Couldn't allocate
                                                          these yet. */
} c_res_pool_t;

/* Extent mask represents the view of an extent. We always make changes to extents to ends.
 * Any point of time, extent view corresponds to one contiguous range. */
typedef struct castle_extent_mask_range {
    c_chk_cnt_t         start;
    c_chk_cnt_t         end;
} c_ext_mask_range_t;

#define EMPTY_MASK_RANGE            ((c_ext_mask_range_t){0, 0})
#define MASK_RANGE_EMPTY(_r)        ((_r).start == (_r).end)
#define MASK_RANGE(_start, _end)    ((c_ext_mask_range_t) {_start, _end})
#define CHECK_MASK_RANGE(_r)        BUG_ON((_r).start > (_r).end)

#define INVAL_MASK_ID                   (-1)
#define MASK_ID_INVAL(_id)              ((_id) == INVAL_MASK_ID)

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
STATIC_BUG_ON(sizeof(struct castle_chunk_sequence) != 8);
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
STATIC_BUG_ON(sizeof(struct castle_disk_chunk) != 8);
#define INVAL_DISK_CHK               ((c_disk_chk_t){INVAL_SLAVE_ID,0})
#define DISK_CHK_INVAL(_chk)         (((_chk).slave_id == INVAL_SLAVE_ID) &&    \
                                      ((_chk).offset == 0))
#define DISK_CHK_EQUAL(_chk1, _chk2) (((_chk1).slave_id == (_chk2).slave_id) && \
                                      ((_chk1).offset == (_chk2).offset))
#define disk_chk_fmt                  "(0x%x, 0x%x)"
#define disk_chk_fmt_nl               "(0x%x, 0x%x)\n"
#define disk_chk2str(_chk)            (_chk).slave_id, (_chk).offset

typedef uint64_t c_byte_off_t;
#define INVAL_BYTE_OFF               ((c_byte_off_t)-1)
#define BYTE_OFF_INVAL(_off)         ((_off) == INVAL_BYTE_OFF)

/* Disk layout related structures (extent based) */
struct castle_extent_position {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t      ext_id;
    /*          8 */ c_byte_off_t    offset;
    /*         16 */
} PACKED;
typedef struct castle_extent_position c_ext_pos_t;
STATIC_BUG_ON(sizeof(struct castle_extent_position) != 16);
#define __INVAL_EXT_POS             {INVAL_EXT_ID,0}
#define INVAL_EXT_POS               ((c_ext_pos_t) __INVAL_EXT_POS)
#define EXT_POS_INVAL(_off)         ((_off).ext_id == INVAL_EXT_ID)
#define EXT_POS_EQUAL(_off1, _off2) (((_off1).ext_id == (_off2).ext_id) && \
                                      ((_off1).offset == (_off2).offset))
/**
 * Compare cep1 against cep2.
 *
 * @param cep1 cep to compare
 * @param cep2 cep to compare against
 *
 * @return -1  cep1 is prior to cep2
 * @return  0  cep1 is the same as cep2
 * @return  1  cep1 is after cep2
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
#define PG_ALIGN_CEP(_cep)           (c_ext_pos_t){(_cep).ext_id, MASK_BLK_OFFSET((_cep).offset)}

static USED char *castle_rda_type_str[] = {
    "RDA_1",
    "RDA_2",
    "SSD_RDA_2",
    "SSD_RDA_3",
    "META_EXT",
    "MICRO_EXT",
    "SUPER_EXT",
    "SSD_ONLY_EXT",
    "NR_RDA_SPECS"
};

/* Type of data stored within extent.
   NOTE: all extent types must be dealt with in castle_ext_flush_prio_get(), please modify
         that function if adding any types.
 */
typedef enum {
    EXT_T_META_DATA,
    EXT_T_GLOBAL_BTREE,
    EXT_T_BLOCK_DEV,
    EXT_T_INTERNAL_NODES,
    EXT_T_LEAF_NODES,
    EXT_T_MEDIUM_OBJECTS,
    EXT_T_T0_INTERNAL_NODES,
    EXT_T_T0_LEAF_NODES,
    EXT_T_T0_MEDIUM_OBJECTS,
    EXT_T_LARGE_OBJECT,
    EXT_T_BLOOM_FILTER,
    EXT_T_INVALID,
} c_ext_type_t;

static USED char *castle_ext_type_str[] = {
    "EXT_T_META_DATA",
    "EXT_T_GLOBAL_BTREE",
    "EXT_T_BLOCK_DEV",
    "EXT_T_INTERNAL_NODES",
    "EXT_T_LEAF_NODES",
    "EXT_T_MEDIUM_OBJECTS",
    "EXT_T_T0_INTERNAL_NODES",
    "EXT_T_T0_LEAF_NODES",
    "EXT_T_T0_MEDIUM_OBJECTS",
    "EXT_T_LARGE_OBJECT",
    "EXT_T_BLOOM_FILTER",
    "EXT_T_INVALID"
};

/* This type determines the way, this extent has to be handled in case of Low Free-Space (LFS)
 * situation. */
typedef enum {
    LFS_VCT_T_T0_GRP,       /**< Intent to allocate freespace for many T0s.                 */
    LFS_VCT_T_T0,           /**< Intent to allocate freespace for a single T0.              */
    LFS_VCT_T_MERGE,        /**< Intent to allocate freespace for a merge.                  */
    LFS_VCT_T_INVALID       /**< Intent to allocate freespace for unspecified use.          */
} c_lfs_vct_type_t;

#define LFS_VCT_T_MAX_TYPE LFS_VCT_T_INVALID

static USED char *castle_lfs_vct_type_str[] = {
    "LFS_VCT_T_T0_GRP",
    "LFS_VCT_T_T0",
    "LFS_VCT_T_MERGE",
    "LFS_VCT_T_INVALID"
};

typedef void (*c_ext_event_callback_t) (void *data);

typedef struct castle_extent_freespace {
    c_ext_id_t      ext_id;
    c_byte_off_t    ext_size;
    atomic64_t      used;
    atomic64_t      blocked;
} c_ext_free_t;

typedef struct castle_extent_freespace_byte_stream {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t      ext_id;
    /*          8 */ uint8_t         __unused[8];
    /*         16 */ uint64_t        used;
    /*         24 */ uint64_t        blocked;
    /*         32 */ uint8_t         _unused[32];
    /*         64 */
} PACKED c_ext_free_bs_t;
STATIC_BUG_ON(sizeof(struct castle_extent_freespace_byte_stream) != 64);

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
STATIC_BUG_ON(sizeof(struct castle_freespace) != 64);

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
    /*         52 */ c_ext_mask_range_t cur_mask;   /**< Current valid mask. All structures in FS
                                                         should depend on this part of extent only.
                                                         */
    /*         60 */ c_ext_mask_range_t prev_mask;  /**< Freespace held by the extent, compare
                                                         this with current valid mask and free extra
                                                         space on reboot. */
    /*         68 */ uint8_t         _unused[60];
    /*        128 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_elist_entry) != 128);

struct castle_plist_entry {
    /* align:   4 */
    /* offset:  0 */ c_ext_id_t       ext_id;
    /*          8 */ c_uuid_t         slave_uuid;
    /*         12 */ c_chk_t          first_chk;
    /*         16 */ c_chk_cnt_t      count;
    /*         20 */ uint8_t          _unused[12];
    /*         32 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_plist_entry) != 32);

struct castle_rlist_entry {
    /* align:   4 */
    /* offset:  0 */ c_res_pool_id_t    id;
    /*          4 */ struct {
       /*          0 */ c_uuid_t               uuid;
                        /* Reserved superchunks for a given slave could be -ve, if it
                         * has over allocated chunks. */
       /*          4 */ c_signed_chk_cnt_t     reserved_schks;
       /*          8 */
                     } slaves[MAX_NR_SLAVES];
    /*        516 */ uint8_t            _unused[508];
    /*       1024 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_rlist_entry) != 1024);

struct castle_extents_superblock {
    /* align:     */
    /* offset:  0 */ c_ext_id_t                 ext_id_seq;
    /*          8 */ uint64_t                   nr_exts;
    /*         16 */ struct castle_elist_entry  micro_ext;
    /*        144 */ struct castle_elist_entry  meta_ext;
    /*        272 */ struct castle_elist_entry  mstore_ext[2];
    /*        528 */ c_ext_free_bs_t            meta_ext_free_bs;
    /*        592 */ c_disk_chk_t               micro_maps[MAX_NR_SLAVES];
    /*       1104 */ uint32_t                   current_rebuild_seqno;
    /*       1108 */ uint8_t                    _unused[940];
    /*       2048 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_extents_superblock) != 2048);

struct castle_slave_superblock {
    /* align:   8 */
    /* offset:  0 */ struct castle_slave_superblock_public pub;
    /*        128 */ uint32_t                              fs_version;
    /*        132 */ castle_freespace_t                    freespace;
    /*        196 */ uint8_t                               _unused[60];
    /*        256 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_slave_superblock) != 256);

struct castle_fs_superblock {
    /* align:   8 */
    /* offset:  0 */ struct castle_fs_superblock_public      pub;
    /*        128 */ uint32_t                                fs_version;
    /*        132 */ uint32_t                                nr_slaves;
    /*        136 */ uint32_t                                slaves[MAX_NR_SLAVES];
    /*        392 */ uint8_t                                 slaves_flags[MAX_NR_SLAVES];
    /*        456 */ struct castle_extents_superblock        extents_sb;
    /*       2504 */ c_ext_pos_t                             mstore[16];
    /*       2760 */ int                                     fs_in_rebuild;
    /*       2764 */ uint8_t                                 _unused[308];
    /*       3072 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_fs_superblock) != 3072);

/* Different CVT types. These are stored in btree nodes, so changes to those should be
   made in a backwards compatible way. */

enum {
    CVT_TYPE_INVALID               = 0x00,
    CVT_TYPE_NODE                  = 0x04,
    CVT_TYPE_TOMBSTONE             = 0x09,
    CVT_TYPE_INLINE                = 0x11,
    CVT_TYPE_MEDIUM_OBJECT         = 0x21,
    CVT_TYPE_LARGE_OBJECT          = 0x61,

    CVT_TYPE_COUNTER_SET           = 0x01, /**< Counter set, c_val_tup_t.val points to the data.  */
    CVT_TYPE_COUNTER_ADD           = 0x03, /**< Counter add, c_val_tup_t.val points to the data.  */
    CVT_TYPE_COUNTER_LOCAL_SET     = 0x05, /**< Counter set, only used for returning the response
                                              to the user. Counter stored in c_val_tup_t.counter. */
    CVT_TYPE_COUNTER_LOCAL_ADD     = 0x06, /**< Counter add. Counter stored in cvt.counter.       */
    CVT_TYPE_COUNTER_ACCUM_SET_SET = 0x07, /**< Composite counter, first counter stores count
                                              for one version (specified in the btree entry)
                                              the second, stores accumulation over ancestral
                                              versions. In this particular cvt type both
                                              subcounters are sets. */
    CVT_TYPE_COUNTER_ACCUM_ADD_SET = 0x08, /**< Composite counter, first is an add, second a set. */
    CVT_TYPE_COUNTER_ACCUM_ADD_ADD = 0x0a, /**< Composite counter, both are adds.                 */
};

struct castle_value_tuple {
    /* align:   8 */
    /* offset:  0 */ struct {
    /*          0 */     uint64_t      type:8;
    /*          1 */     uint64_t      length:56;
    /*          8 */ };
    /*          8 */ union {
    /*          8 */     c_ext_pos_t   cep;
    /*          8 */     uint8_t      *val_p;
    /*          8 */     int64_t       counter;
    /*         24 */ };
    /*         24 */ castle_user_timestamp_t user_timestamp;
    /*         32 */
} PACKED;
typedef struct castle_value_tuple c_val_tup_t;
STATIC_BUG_ON(sizeof(struct castle_value_tuple) != 32);

#define INVAL_VAL_TUP        ((c_val_tup_t){{CVT_TYPE_INVALID, 0}, {.cep = INVAL_EXT_POS}})


#define CVT_INVALID(_cvt)           ((_cvt).type == CVT_TYPE_INVALID)

/* CVT_LEAF_VAL checks for any value type (directly usable entry from leaf btree nodes).
   In particular pointers to btree nodes aren't CVT_LEAF_VAL, neither are leaf ptrs. */
#define CVT_LEAF_VAL(_cvt)              (((_cvt).type == CVT_TYPE_TOMBSTONE) ||               \
                                         ((_cvt).type == CVT_TYPE_INLINE) ||                  \
                                         ((_cvt).type == CVT_TYPE_MEDIUM_OBJECT) ||           \
                                         ((_cvt).type == CVT_TYPE_LARGE_OBJECT) ||            \
                                         ((_cvt).type == CVT_TYPE_COUNTER_SET) ||             \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ADD) ||             \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_SET_SET) ||   \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_SET) ||   \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_ADD))

#define CVT_NODE(_cvt)                   ((_cvt).type == CVT_TYPE_NODE)

#define CVT_TOMBSTONE(_cvt)              ((_cvt).type == CVT_TYPE_TOMBSTONE)

/* CVT_INLINE() is true for _any_ inline values, including counters. */
#define CVT_INLINE(_cvt)                (((_cvt).type == CVT_TYPE_INLINE) ||                  \
                                         ((_cvt).type == CVT_TYPE_COUNTER_SET) ||             \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ADD) ||             \
                                         ((_cvt).type == CVT_TYPE_COUNTER_LOCAL_SET) ||       \
                                         ((_cvt).type == CVT_TYPE_COUNTER_LOCAL_ADD) ||       \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_SET_SET) ||   \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_SET) ||   \
                                         ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_ADD))

/* Only medium and large objects are stored out of line, i.e. 'on disk' .*/
#define CVT_ON_DISK(_cvt)               (((_cvt).type == CVT_TYPE_MEDIUM_OBJECT) ||           \
                                         ((_cvt).type == CVT_TYPE_LARGE_OBJECT))

#define CVT_MEDIUM_OBJECT(_cvt)          ((_cvt).type == CVT_TYPE_MEDIUM_OBJECT)

#define CVT_LARGE_OBJECT(_cvt)           ((_cvt).type == CVT_TYPE_LARGE_OBJECT)

#define CVT_COUNTER_SET(_cvt)            ((_cvt).type == CVT_TYPE_COUNTER_SET)

#define CVT_COUNTER_ADD(_cvt)            ((_cvt).type == CVT_TYPE_COUNTER_ADD)

#define CVT_COUNTER_LOCAL_SET(_cvt)      ((_cvt).type == CVT_TYPE_COUNTER_LOCAL_SET)

#define CVT_COUNTER_LOCAL_ADD(_cvt)      ((_cvt).type == CVT_TYPE_COUNTER_LOCAL_ADD)

#define CVT_COUNTER_ACCUM_SET_SET(_cvt)  ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_SET_SET)

#define CVT_COUNTER_ACCUM_ADD_SET(_cvt)  ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_SET)

#define CVT_COUNTER_ACCUM_ADD_ADD(_cvt)  ((_cvt).type == CVT_TYPE_COUNTER_ACCUM_ADD_ADD)


/* Derivative types. */
#define CVT_ONE_BLK(_cvt)           (CVT_ON_DISK(_cvt) && ((_cvt).length == C_BLK_SIZE))
#define CVT_LOCAL_COUNTER(_cvt)     (CVT_COUNTER_LOCAL_SET(_cvt) ||            \
                                     CVT_COUNTER_LOCAL_ADD(_cvt))
#define CVT_ACCUM_COUNTER(_cvt)     (CVT_COUNTER_ACCUM_SET_SET(_cvt) ||        \
                                     CVT_COUNTER_ACCUM_ADD_SET(_cvt) ||        \
                                     CVT_COUNTER_ACCUM_ADD_ADD(_cvt))
#define CVT_INLINE_COUNTER(_cvt)    (CVT_COUNTER_SET(_cvt) ||                  \
                                     CVT_COUNTER_ADD(_cvt) ||                  \
                                     CVT_COUNTER_ACCUM_SET_SET(_cvt) ||        \
                                     CVT_COUNTER_ACCUM_ADD_SET(_cvt) ||        \
                                     CVT_COUNTER_ACCUM_ADD_ADD(_cvt))
/* True if the counter is a 'simple' add, or for composite counters, if the
   all-versions sub-counter is an add. */
#define CVT_ADD_ALLV_COUNTER(_cvt)  (CVT_COUNTER_ADD(_cvt) ||                  \
                                     CVT_COUNTER_ACCUM_ADD_ADD(_cvt) ||        \
                                     CVT_COUNTER_LOCAL_ADD(_cvt))
/* Should only be used for non-composite CVTs. True if its an add counter. */
#define CVT_ADD_COUNTER(_cvt)                                                 \
({                                                                            \
    int _ret;                                                                 \
    /* Cannot decide which sub-counter to check for accum counters. */        \
    BUG_ON(CVT_ACCUM_COUNTER(_cvt));                                          \
    _ret = CVT_ADD_ALLV_COUNTER(_cvt);                                        \
    _ret;                                                                     \
})
#define CVT_SET_COUNTER(_cvt)    (!CVT_ADD_COUNTER(_cvt))
#define CVT_ANY_COUNTER(_cvt)    (CVT_INLINE_COUNTER(_cvt) ||                 \
                                  CVT_LOCAL_COUNTER(_cvt))

#define CVT_INVALID_INIT(_cvt)                                                \
{                                                                             \
   (_cvt).type   = CVT_TYPE_INVALID;                                          \
   (_cvt).length = 0;                                                         \
   (_cvt).cep    = INVAL_EXT_POS;                                             \
   (_cvt).user_timestamp = 0;                                                 \
}
#define CVT_NODE_INIT(_cvt, _length, _cep)                                    \
{                                                                             \
   (_cvt).type   = CVT_TYPE_NODE;                                             \
   (_cvt).length = _length;                                                   \
   (_cvt).cep    = _cep;                                                      \
}
#define CVT_TOMBSTONE_INIT(_cvt)                                              \
{                                                                             \
   (_cvt).type   = CVT_TYPE_TOMBSTONE;                                        \
   (_cvt).length = 0;                                                         \
   (_cvt).cep    = INVAL_EXT_POS;                                             \
}
#define CVT_INLINE_INIT(_cvt, _length, _ptr)                                  \
{                                                                             \
   (_cvt).type   = CVT_TYPE_INLINE;                                           \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_SET_INIT(_cvt, _length, _ptr)                             \
{                                                                             \
   BUG_ON((_length) != 8);                                                    \
   (_cvt).type   = CVT_TYPE_COUNTER_SET;                                      \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_ADD_INIT(_cvt, _length, _ptr)                             \
{                                                                             \
   BUG_ON((_length) != 8);                                                    \
   (_cvt).type   = CVT_TYPE_COUNTER_ADD;                                      \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_ACCUM_SET_SET_INIT(_cvt, _length, _ptr)                   \
{                                                                             \
   BUG_ON((_length) != 16);                                                   \
   (_cvt).type   = CVT_TYPE_COUNTER_ACCUM_SET_SET;                            \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_ACCUM_ADD_SET_INIT(_cvt, _length, _ptr)                   \
{                                                                             \
   BUG_ON((_length) != 16);                                                   \
   (_cvt).type   = CVT_TYPE_COUNTER_ACCUM_ADD_SET;                            \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_ACCUM_ADD_ADD_INIT(_cvt, _length, _ptr)                   \
{                                                                             \
   BUG_ON((_length) != 16);                                                   \
   (_cvt).type   = CVT_TYPE_COUNTER_ACCUM_ADD_ADD;                            \
   (_cvt).length = _length;                                                   \
   (_cvt).val_p  = _ptr;                                                      \
}
#define CVT_COUNTER_LOCAL_SET_INIT(_cvt, _counter)                            \
{                                                                             \
   (_cvt).type    = CVT_TYPE_COUNTER_LOCAL_SET;                               \
   (_cvt).length  = 8;                                                        \
   (_cvt).counter = (_counter);                                               \
}
#define CVT_COUNTER_LOCAL_ADD_INIT(_cvt, _counter)                            \
{                                                                             \
   (_cvt).type    = CVT_TYPE_COUNTER_LOCAL_ADD;                               \
   (_cvt).length  = 8;                                                        \
   (_cvt).counter = (_counter);                                               \
}
#define CVT_MEDIUM_OBJECT_INIT(_cvt, _length, _cep)                           \
{                                                                             \
    (_cvt).type  = CVT_TYPE_MEDIUM_OBJECT;                                    \
    (_cvt).length= _length;                                                   \
    (_cvt).cep   = _cep;                                                      \
}
#define CVT_LARGE_OBJECT_INIT(_cvt, _length, _cep)                            \
{                                                                             \
    (_cvt).type  = CVT_TYPE_LARGE_OBJECT;                                     \
    (_cvt).length= _length;                                                   \
    (_cvt).cep   = _cep;                                                      \
}
#define CVT_INLINE_VAL_LENGTH(_cvt)                                           \
                             (CVT_INLINE(_cvt)?((_cvt).length):0)
/* Helper macro, don't use outside of the CVT macros. */
#define _CVT_COUNTER_INLINE_TO_LOCAL(_local_cvt, _inline_cvt, _offset, _set)  \
{                                                                             \
    int64_t count;                                                            \
    memcpy(&count, (_inline_cvt).val_p+(_offset), 8);                         \
    if(_set)                                                                  \
        CVT_COUNTER_LOCAL_SET_INIT(_local_cvt, count)                         \
    else                                                                      \
        CVT_COUNTER_LOCAL_ADD_INIT(_local_cvt, count)                         \
}
/* Converts an accumulating counter to a local counter, extracting the
   all-versions sub-counter. */
#define CVT_COUNTER_ACCUM_ALLV_TO_LOCAL(_local_cvt, _accum_cvt)               \
{                                                                             \
    if(CVT_COUNTER_ACCUM_ADD_ADD(_accum_cvt))                                 \
        _CVT_COUNTER_INLINE_TO_LOCAL(_local_cvt, _accum_cvt, 8, 0)            \
    else                                                                      \
        _CVT_COUNTER_INLINE_TO_LOCAL(_local_cvt, _accum_cvt, 8, 1)            \
}
/* Converts an accumulating counter to a local counter, extracting the
   one-version sub-counter. */
#define CVT_COUNTER_ACCUM_ONEV_TO_LOCAL(_local_cvt, _accum_cvt)               \
{                                                                             \
    if(CVT_COUNTER_ACCUM_ADD_ADD(_accum_cvt) ||                               \
       CVT_COUNTER_ACCUM_ADD_SET(_accum_cvt))                                 \
        _CVT_COUNTER_INLINE_TO_LOCAL(_local_cvt, _accum_cvt, 0, 0)            \
    else                                                                      \
        _CVT_COUNTER_INLINE_TO_LOCAL(_local_cvt, _accum_cvt, 0, 1)            \
}
/* Returns pointer to the an inlined value (deals with local counters too). */
#define CVT_INLINE_VAL_PTR(_cvt)                                              \
({                                                                            \
    void *_ptr;                                                               \
    BUG_ON(!CVT_INLINE(_cvt));                                                \
    if(CVT_LOCAL_COUNTER(_cvt))                                               \
        _ptr = &(_cvt).counter;                                               \
    else                                                                      \
        _ptr = (_cvt).val_p;                                                  \
    _ptr;                                                                     \
})
#define CVT_TOMBSTONE_VAL_PTR(_cvt)                                           \
({                                                                            \
    void *_ptr;                                                               \
    BUG_ON(!CVT_TOMBSTONE(_cvt));                                             \
    _ptr = (_cvt).val_p;                                                      \
    _ptr;                                                                     \
})
#define CVT_INLINE_FREE(_cvt)                                                 \
{                                                                             \
    if(CVT_INLINE(_cvt) && !CVT_LOCAL_COUNTER(_cvt))                          \
    {                                                                         \
        BUG_ON(!(_cvt).val_p);                                                \
        castle_free((_cvt).val_p);                                            \
        (_cvt).val_p = NULL;                                                  \
    }                                                                         \
}
#define CVT_EQUAL(_cvt1, _cvt2)                                               \
                             ((_cvt1).type      == (_cvt2).type &&            \
                              (_cvt1).length    == (_cvt2).length &&          \
                              (!CVT_ON_DISK(_cvt1) ||                         \
                               EXT_POS_EQUAL((_cvt1).cep, (_cvt2).cep)))


typedef uint8_t c_mstore_id_t;

typedef struct castle_mstore {
    c_mstore_id_t              store_id;                    /* Id of the store, ptr in fs_sb    */
    int                        rw;                          /* Whether the store is being read  */
                                                            /* or written.                      */
    struct semaphore           mutex;                       /* Mutex which protects the         */
                                                            /*  last_node_* variables           */
    c_ext_pos_t                last_node_cep;               /* Tail of the list, has at least   */
                                                            /* one unused entry in it           */
    c_byte_off_t               last_node_last_entry_offset; /* Points to the start of the last  */
                                                            /* entry inserted into the last     */
                                                            /* node.                            */
    c_byte_off_t               last_node_next_entry_offset; /* Points to the start of where the */
                                                            /* next entry should be inserted    */
                                                            /* into the last node.              */
} c_mstore_t;

typedef struct castle_mstore_iter {
    struct castle_mstore       store;                /* Store we are iterating over      */
    struct castle_cache_block *node_c2b;             /* Currently accessed node (locked) */
    int                        next_entry_idx;       /* Entry # in node_c2b to be        */
                                                     /* returned next.                   */
} c_mstore_iter_t;

enum {
    MSTORE_VERSIONS_ID,
    MSTORE_BLOCK_CNTS,
    MSTORE_DOUBLE_ARRAYS,
    MSTORE_COMPONENT_TREES,
    MSTORE_ATTACHMENTS_TAG,
    MSTORE_EXTENTS,
    MSTORE_LARGE_OBJECTS,
    MSTORE_DA_MERGE,                  /* state of merge structure and output tree */
    MSTORE_DA_MERGE_IN_TREE,          /* state of input trees in a merge, mainly iterator state */
    MSTORE_PART_SCHKS,
    MSTORE_STATS,
    MSTORE_DATA_EXTENTS,
    MSTORE_CT_DATA_EXTENTS,
    MSTORE_RES_POOLS,
};


#define MTREE_TYPE                 0x33
#define MTREE_BVEC_BLOCK(_bvec)   ((sector_t)(_bvec)->key)
#define VLBA_TREE_TYPE             0x66
#define SLIM_TREE_TYPE             0x77

#define MAX_BTREE_DEPTH           (10)               /**< Maximum depth of btrees.
                                                          This is used in on-disk datastructures.
                                                          For example castle_clist_entry.
                                                          If modified, those need to be reviewed.
                                                      */

#define MTREE_NODE_SIZE         10      /**< Size of the mtree nodes, in blocks.  */
#define RW_TREE_NODE_SIZE        2      /**< Size of the RW tree nodes, in blocks.
                                             Constant independent of the level.   */
#define HDD_RO_TREE_NODE_SIZE   64      /**< Size of the RO tree nodes on HDDs, in blocks. */
#define SSD_RO_TREE_NODE_SIZE    2      /**< Size of the RO tree nodes on SSDs, in blocks. */

typedef uint8_t btree_t;

#define BTREE_NODE_MAGIC  0x0100cdab
enum {
    BTREE_NODE_IS_LEAF_FLAG        = 1,
    BTREE_NODE_HAS_TIMESTAMPS_FLAG = 2
};

struct castle_btree_node {
    /* align:   8 */
    /* offset:  0 */ uint32_t        magic;
    /*          4 */ uint32_t        version;
    /*          8 */ uint32_t        used;
    /*         12 */ btree_t         type;
    /*         13 */ uint8_t         flags;
    /*         14 */ uint16_t        size;           /**< Size of this btree node in pages.     */
                     /* Payload (i.e. btree entries) depend on the B-tree type */
    /*         16 */ uint8_t         _unused[48];
    /*         64 */ uint8_t         payload[0];
    /*         64 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_btree_node) != 64);

#define BTREE_NODE_IS_LEAF(_node)        ((_node)->flags & BTREE_NODE_IS_LEAF_FLAG)
#define BTREE_NODE_HAS_TIMESTAMPS(_node) ((_node)->flags & BTREE_NODE_HAS_TIMESTAMPS_FLAG)
#define BTREE_NODE_PAYLOAD(_node)        ((void *)&(_node)->payload)

/**
 * CT states to handle key ranges with partial merge redirection.
 */
#define HASH_STRIPPED_DIMS      2   /**< Number of significant dimensions in stripped key.      */
typedef enum {
    HASH_WHOLE_KEY = 0,             /**< Hash whole key.                                        */
    HASH_STRIPPED_KEYS              /**< Hash just stripped key dimensions in key.              */
} c_btree_hash_enum_t;

struct castle_component_tree;

/**
 * Generic btree node functions.
 */
struct castle_btree_type {
    btree_t    magic;         /* Also used as an index to castle_btrees
                                 array.                                 */
    void      *min_key;       /* Minimum key                            */
    void      *max_key;       /* Maximum used as the end of node marker */
    void      *inv_key;       /* An invalid key, comparison with it
                                 should always return a negative number
                                 except if also compared to invalid key
                                 in which case cmp should return zero   */
    size_t   (*max_entries)   (size_t size);
                              /* Returns a conservative estimate of the
                                 max number of entries which can fit in
                                 a node of the given size (in blocks).  */
    size_t   (*min_size)      (size_t entries);
                              /* Returns a conservative estimate of the
                                 min node size into which the given number
                                 of entries may fit. */
    int      (*need_split)    (struct castle_btree_node *node,
                               int                       version_or_key);
                              /* 0 - version split, 1 - key split       */
    int      (*mid_entry)     (struct castle_btree_node *node);
                              /* Returns index of an entry which splits the
                                 node into equal halfs (as much as possible)
                                 taking the variable length of keys & values
                                 into account.
                                 The halfs are entries [0 - (mid_entry-1)] &
                                 [mid_entry - (nr_entries-1)].
                               */
    void    *(*key_pack)      (const c_vl_bkey_t *src, void *dst, size_t *dst_len);
                              /* Packs a standard backend key into the
                                 tree's native key format. Uses its
                                 arguments exactly like key_copy().     */
    c_vl_bkey_t *(*key_unpack)(const void *src, c_vl_bkey_t *dst, size_t *dst_len);
                              /* Unpacks a native key into the standard
                                 backend format. Uses its arguments
                                 exactly like key_copy().               */
    int      (*key_compare)   (const void *key1, const void *key2);
                              /* Returns negative if key1 < key2, zero
                                 if equal, positive otherwise           */
    size_t   (*key_size)      (const void *key);
                              /* Returns the amount of space needed to
                                 store the key, in bytes.               */
    void    *(*key_copy)      (const void *src, void *dst, size_t *dst_len);
                              /* Copies a key from src to dst. If dst
                                 is NULL, the key is copied into a
                                 freshly alloc'ed buffer which needs to
                                 be dealloc'ed later by the caller.     */
    void    *(*key_next)      (const void *src, void *dst, size_t *dst_len);
                              /* Successor key, succ(MAX) = INVAL,
                                 succ(MIN) / succ(INVAL) -> BUG(). Uses
                                 its arguments exactly like key_copy(). */
    void    *(*key_hc_next)   (const void *key, const void *low, const void *high);
                              /* Returns the next key to fall inside
                                 the hypercube defined by low and high;
                                 key itself if it is already inside the
                                 hypercube; high if no such key exists. */
    void     (*key_dealloc)   (void *key);
                              /* Destroys the key, frees resources
                                 associated with it                     */
    int      (*nr_dims)       (const void *key);
                              /**< Get number of key dimensions.        */
    void    *(*key_strip)     (const void *src, void *dst, size_t *dst_len, int nr_dims);
                              /**< Build key with first nr_dims dimensions, remaining
                                   dimensions set to -inf.                              */
    uint32_t (*key_hash)      (const void *key, c_btree_hash_enum_t type, uint32_t seed);
                              /**< Hash key using seed.                 */
    void     (*key_print)     (int level, const void *key);
                              /* Print the key with log level           */
    int      (*entry_get)     (struct castle_btree_node *node,
                               int                       idx,
                               void                    **key_p,
                               c_ver_t                  *version_p,
                               c_val_tup_t              *cvt_p);
    void     (*entry_add)     (struct castle_btree_node *node,
                               int                       idx,
                               void                     *key,
                               c_ver_t                   version,
                               c_val_tup_t               cvt);
    void     (*entry_replace) (struct castle_btree_node *node,
                               int                       idx,
                               void                     *key,
                               c_ver_t                   version,
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

/**
 * Structure used during creation and query of bloom filter.
 *
 * Bloom filter extent is laid out such that the btree nodes are at the start
 * of the extent and the bloom filter chunks (part that contains key hashes) are
 * following the btree nodes (at chunks_offset).  Chunks and btree nodes are not
 * guaranteed to be totally contiguous as during construction we may have
 * overestimated the number of btree nodes required hence some extent space goes
 * unused.
 *
 * @also castle_bloom_create()
 * @also castle_bloom_add()
 */
typedef struct castle_bloom_filter {
    uint8_t                   num_hashes;           /**< Hashes per key in the bloom block.     */
    uint32_t                  block_size_pages;     /**< Pages per bloom block in bloom chunks. */
    uint32_t                  num_chunks;           /**< Number of bloom chunks in filter.      */
    uint64_t                  chunks_offset;        /**< Offset of first chunk in bloom extent. */
    atomic_t                  num_btree_nodes;      /**< Non-empty btree nodes in bloom filter. */
    struct castle_btree_type *btree;                /**< Bloom index btree type.                */
    c_ext_id_t                ext_id;               /**< Bloom filter extent id.                */
    void                     *private;              /**< Construction only; pointer to
                                                         castle_bloom_build_params structure.   */
#ifdef CASTLE_BLOOM_FP_STATS
    atomic64_t                queries;              /**< Queries handled.                       */
    atomic64_t                false_positives;      /**< False positive count.                  */
#endif
} castle_bloom_t;

struct castle_bbp_entry
{
    /* align:   8 */
    /* offset:  0 */ uint64_t    max_num_elements;
    /*          8 */ uint64_t    elements_inserted;
    /*         16 */ uint32_t    chunks_complete;
    /*         20 */ uint32_t    cur_node_cur_chunk_id;
    /*         24 */ uint32_t    nodes_complete;
    /*         28 */ c_ext_pos_t node_cep;
    /*         44 */ c_ext_pos_t chunk_cep;
    /*         60 */ uint32_t    node_used;   /* for entries_drop */
    /*         64 */ uint8_t     node_avail;  /* flag to indicate if we should recover node */
    /*         65 */ uint8_t     chunk_avail; /* flag to indicate if we should recover chunk */
    /*         66 */ uint32_t    last_stripped_hash;
    /*         70 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_bbp_entry) != 70);

/* Component tree flags bits. */
#define CASTLE_CT_DYNAMIC_BIT           0   /* CT is dynamic. RW Tree.                          */
#define CASTLE_CT_NEW_TREE_BIT          1   /* CT is not yet committed to disk.                 */
#define CASTLE_CT_BLOOM_EXISTS_BIT      2   /* CT has bloom filter.                             */
#define CASTLE_CT_MERGE_OUTPUT_BIT      3   /* CT is being created by a merge.                  */
#define CASTLE_CT_MERGE_INPUT_BIT       4   /* CT is being merged.                              */
#define CASTLE_CT_PARTIAL_TREE_BIT      5   /* CT tree is partial could be intree/outtree.      */

#define CASTLE_CT_ON_DISK_FLAGS_MASK    ((1UL << CASTLE_CT_DYNAMIC_BIT))

#define CT_DYNAMIC(_ct)  (test_bit(CASTLE_CT_DYNAMIC_BIT, &(_ct)->flags))
/**
 * Is CT queriable.
 */
#define CASTLE_CT_QUERIABLE(_ct)                                            \
    (test_bit(CASTLE_CT_PARTIAL_TREE_BIT, &((_ct)->flags))                  \
        || !test_bit(CASTLE_CT_MERGE_OUTPUT_BIT, &((_ct)->flags)))

/**
 * Total number of extents associated with a CT.
 */
#define CASTLE_CT_EXTENTS(_ct)                                                      \
    (((_ct)->bloom_exists) ? 3 + (_ct)->nr_data_exts : 2 + (_ct)->nr_data_exts)

struct castle_component_tree {
    tree_seq_t          seq;               /**< Unique ID identifying this tree.                */
    tree_seq_t          data_age;          /**< Denotes the age of data.                        */
    unsigned long       flags;

    atomic_t            ref_count;
    atomic_t            write_ref_count;
    atomic64_t          item_count;        /**< Number of items in the tree.                    */
    atomic64_t          nr_bytes;          /**< Size of B-Tree - includes keys and inline values
                                                but not B-Tree overhead and empty space in Tree.
                                                So, it doesn't add upto space occupied by all
                                                B-Tree nodes. This would be good/more accurate
                                                way to report B-Tree size that GN cares.        */
    uint64_t            nr_drained_bytes;  /**< Number of bytes drained from the tree, during
                                                merge. Measurement units are same as nr_bytes.
                                                This counter is accessed in serialised fashion
                                                by a single merge thread, atomic not needed.    */
    uint64_t            chkpt_nr_bytes;
    uint64_t            chkpt_nr_drained_bytes;
    btree_t             btree_type;
    struct castle_double_array *da;        /**< DA that this CT belongs to.                     */
    uint8_t             level;             /**< Level in the doubling array.                    */
    uint16_t            node_sizes[MAX_BTREE_DEPTH];
                                           /**< Size of nodes in each level in the b-tree,
                                                in pages. Only used for !dynamic (i.e. RO)
                                                trees. Stored in reverse order,
                                                i.e. node_sizes[0] is the size of leaf level,
                                                node_sizes[tree_depth-1] is the size of the
                                                root node. */
    struct rw_semaphore lock;              /**< Protects root_node, tree depth & last_node.     */
    atomic_t            tree_depth;
    c_ext_pos_t         root_node;
    struct list_head    da_list;
    struct list_head    hash_list;
    struct list_head    large_objs;
    struct mutex        lo_mutex;           /**< Protects Large Object List. When working with
                                                 the output CT of a serialisable merge, never
                                                 take this lock before serdes.mutex or there
                                                 will be deadlock against checkpoint thread.    */
    c_ext_free_t        internal_ext_free;  /**< Extent for internal btree nodes.               */
    c_ext_free_t        tree_ext_free;      /**< Extent for leaf btree nodes.                   */
    c_ext_free_t        data_ext_free;      /**< Medium-object data extent.                     */
    c_ext_id_t         *data_exts;          /**< Array of data extent IDs.                      */
    uint32_t            nr_data_exts;       /**< Number of data extents in in this CT.          */
    uint64_t            nr_rwcts;           /**< How many RWCTs were merged to produce this CT. */
    /* FIXME: Just for debugging sake. get rid of data_exts_count later. */
    uint32_t            data_exts_count;
    atomic64_t          large_ext_chk_cnt;
    uint8_t             bloom_exists;
    castle_bloom_t      bloom;
    struct kobject      kobj;
    struct kobject      data_extents_kobj;
    struct castle_da_merge  *merge;         /**< Contains mreg structure if the tree involved
                                                 in a merge. */
    c_merge_id_t        merge_id;

    atomic64_t          max_user_timestamp; /**< To terminate point gets early */
    atomic64_t          min_user_timestamp; /**< For tombstone discard */

    uint32_t            max_versions_per_key; /**< For a merge to correctly size the tv_resolver (see
                                                   trac #4749) */
};
extern struct castle_component_tree *castle_global_tree;

struct castle_large_obj_entry {
    c_ext_id_t          ext_id;
    uint64_t            length;
    struct list_head    list;
};

struct castle_data_extent {
    c_ext_id_t          ext_id;
    atomic_t            ref_cnt;
    atomic64_t          nr_entries;
    atomic64_t          nr_bytes;
    atomic64_t          nr_drain_bytes;
    uint64_t            chkpt_nr_entries;
    uint64_t            chkpt_nr_bytes;
    uint64_t            chkpt_nr_drain_bytes;
    struct list_head    hash_list;
    struct kobject      kobj;
};

struct castle_dlist_entry {
    /* align:   4 */
    /* offset:  0 */ c_da_t      id;
    /*          4 */ c_ver_t     root_version;
    /*          8 */ btree_t     btree_type;
    /*          9 */ uint64_t    creation_opts;
    /*         17 */ uint64_t    tombstone_discard_threshold_time_s;
    /*         25 */ uint8_t     _unused[231];
    /*        256 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_dlist_entry) != 256);

struct castle_clist_entry {
    /* align:   8 */
    /* offset:  0 */ c_da_t          da_id;
    /*          4 */ btree_t         btree_type;
    /*          5 */ uint8_t         level;
    /*          6 */ uint64_t        item_count;
    /*         14 */ c_ext_pos_t     root_node;
    /*         30 */ c_ext_free_bs_t internal_ext_free_bs;
    /*         94 */ c_ext_free_bs_t tree_ext_free_bs;
    /*        158 */ c_ext_free_bs_t data_ext_free_bs;
    /*        222 */ uint64_t        large_ext_chk_cnt;
    /*        230 */ uint32_t        bloom_num_chunks;
    /*        234 */ uint32_t        bloom_num_blocks_last_chunk;
    /*        238 */ uint64_t        bloom_chunks_offset;
    /*        246 */ c_ext_id_t      bloom_ext_id;
    /*        254 */ uint32_t        bloom_num_btree_nodes;
    /*        258 */ uint32_t        bloom_block_size_pages;
    /*        262 */ tree_seq_t      seq;
    /*        270 */ uint8_t         bloom_exists;
    /*        271 */ uint8_t         bloom_num_hashes;
    /*        272 */ uint16_t        node_sizes[MAX_BTREE_DEPTH];
    /*        292 */ tree_seq_t      data_age;
    /*        300 */ uint32_t        nr_data_exts;
    /*        304 */ uint64_t        nr_rwcts;
    /*        312 */ uint64_t        nr_bytes;
    /*        320 */ uint64_t        nr_drained_bytes;
    /*        328 */ uint64_t        max_user_timestamp;
    /*        336 */ uint64_t        min_user_timestamp;
    /*        344 */ int32_t         tree_depth;
    /*        348 */ uint32_t        max_versions_per_key;
    /*        352 */ uint64_t        flags;
    /*        360 */ uint8_t         _unused[152];
    /*        512 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_clist_entry) != 512);

/* A "convenience" struct to temporarily (for a short period) maintain a pointer to
   a key in some component tree */
struct castle_key_ptr_t {
    void                      *key;        /* points to the key we want to keep */
    struct castle_cache_block *node_c2b;   /* points to the c2b we need to get/put
                                              to keep the key pointer alive */
    unsigned int               node_size;  /* btree level */
};

/** DA merge SERDES input tree iter on-disk structure.
 */
struct castle_in_tree_merge_state_entry {
    /* align:  16 */
    /* offset:  0 */ tree_seq_t                    seq;
    /*          4 */
                     struct {
                         /* stuff in here is accessed very often - align carefully! */
                         /*   0 */ int32_t         component_completed;
                         /*   4 */ int32_t         component_cached;
                         /*   8 */ int32_t         immut_curr_idx;
                         /*  12 */ int32_t         immut_cached_idx;
                         /*  16 */ int32_t         immut_next_idx;
                         /*  20 */ c_ext_pos_t     immut_curr_c2b_cep;
                         /*  36 */ c_ext_pos_t     immut_next_c2b_cep;
                         /*  52 */
                     } iter PACKED; /* 52 * 1 = 52 */
                     /* at des time, each c_intree_merge_state uses the da_id and level
                        to find the corresponding merge state */
    /*         56 */ c_da_t                        da_id;
    /*         60 */ c_merge_id_t                  merge_id;
    /*         64 */ int32_t                       pos_in_merge_struct; /* cld use seq to infer this? */
    /*         68 */ uint8_t                       alignment_pad[8];
    /*         80 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_in_tree_merge_state_entry) != 80);

/** DA merge SERDES on-disk structure.
 *
 *  @note Assumes 2 input trees, both c_immut_iter_t, and max of 10 DA levels
 */
struct castle_dmserlist_entry {
    /* align:  16 */
    /*************************** misc stuff: marshalled once per merge ***************************/
    /* offset:  0 */ c_da_t                           da_id;
    /*          4 */ int32_t                          level;
    /*          8 */ int8_t                           leafs_on_ssds;
    /*          9 */ int8_t                           internals_on_ssds;
    /*         10 */ int32_t                          nr_trees;
    /*         14 */ uint8_t                          pad_to_outct[2];
    /*         16 */

    /**************** partially complete output ct: marshalled once per checkpoint ****************/
                    /* sizing/alignment of the overall struct assumes MAX_BTREE_DEPTH=10 */
    /*         16 */ struct castle_clist_entry        out_tree;
    /*        528 */
                     struct {
                         /*   0 */ c_ext_pos_t                 node_c2b_cep;
                         /*  16 */ int32_t                     next_idx;
                         /*  20 */ int32_t                     node_used;
                         /*  24 */ int32_t                     valid_end_idx;
                         /*  28 */ c_ver_t                     valid_version;
                         /*  32 */
                     } levels[MAX_BTREE_DEPTH]; /* 32 * 10 = 320 */
    /*        848 */
    /*        848 */ c_ext_pos_t                      last_leaf_node_cep;
    /*        864 */ struct castle_bbp_entry          out_tree_bbp;
    /*        934 */ uint8_t                          have_bbp;
    /*        935 */ btree_t                          btree_type;
    /*        936 */ int8_t                           is_new_key;
    /*        937 */ uint32_t                         skipped_count;
                     /* Although the redirection partition is contained by the castle_double_array
                        struct, SERDES is left to merge because the partition is tightly linked to
                        merge SERDES state. */
    /*        941 */ c_ext_pos_t                      redirection_partition_node_cep;
    /*        957 */ int32_t                          redirection_partition_node_size;
    /*        961 */ uint8_t                          pad_to_iters[7];  /**< beyond here entries
                                                                              are frequently
                                                                              marshalled, so
                                                                              alignment is
                                                                              important */
    /*         */

    /**************** input ct seq and iters: iters potentially marshalled often *****************/
    /*        968 */ int32_t                          iter_err;
    /*        972 */ int64_t                          iter_non_empty_cnt;
    /*        980 */ uint64_t                         iter_src_items_completed;
    /*        988 */ c_merge_id_t                     merge_id;
    /*        992 */ uint32_t                         nr_drain_exts;
    /*        996 */ uint32_t                         pool_id;
    /*       1000 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_dmserlist_entry) != 1000);

/**
 * Ondisk Serialized structure for castle versions.
 */
struct castle_vlist_entry {
    /* align:   8 */
    /* offset:  0 */ c_ver_t      version_nr;
    /*          4 */ c_ver_t      parent;
    /*          8 */ c_da_t       da_id;
    /*         12 */ uint8_t      _pad[4];
    /*         16 */ uint64_t     size;
    /*         24 */ uint64_t     flags;                /**< Flags for version LEAF & DELETED.  */
    /*         32 */ uint64_t     keys;                 /**< stats.keys                         */
    /*         40 */ uint64_t     tombstones;           /**< stats.tombstones                   */
    /*         48 */ uint64_t     tombstone_deletes;    /**< stats.tombstone_deletes            */
    /*         56 */ uint64_t     version_deletes;      /**< stats.version_deletes              */
    /*         64 */ uint64_t     key_replaces;         /**< stats.key_replaces                 */
    /*         72 */ uint64_t     timestamp_rejects;    /**< stats.timestamp_rejects            */
    /*         80 */ uint64_t     creation_time_s;      /**< seconds of the creation timestamp  */
    /*         88 */ uint64_t     creation_time_us;     /**< useconds of the creation timestamp */
    /*         96 */ uint64_t     immute_time_s;        /**< seconds of the immute timestamp  */
    /*        104 */ uint64_t     immute_time_us;       /**< useconds of the immute timestamp */
    /*        112 */ uint8_t      _unused[144];
    /*        256 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_vlist_entry) != 256);

#define MAX_NAME_SIZE 128
struct castle_alist_entry {
    /* align:   4 */
    /* offset:  0 */ c_ver_t     version;
    /*          4 */ uint32_t    flags;
    /*          8 */ char        name[MAX_NAME_SIZE];
    /*        136 */ uint8_t     _unused[120];
    /*        256 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_alist_entry) != 256);

#define MLIST_NODE_MAGIC  0x0000baca
struct castle_mlist_node {
    /* align:   8 */
    /* offset:  0 */ uint32_t    magic;
    /*          4 */ uint32_t    used;
    /*          8 */ c_ext_pos_t next;
    /*         24 */ uint8_t     _unused[40];
    /*         64 */ uint8_t     payload[0];
    /*         64 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_mlist_node) != 64);

struct castle_lolist_entry {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t  ext_id;
    /*          8 */ uint64_t    length;
    /*         16 */ tree_seq_t  ct_seq;
    /*         24 */ uint8_t     _unused[8];
    /*         32 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_lolist_entry) != 32);

struct castle_dext_list_entry {
    /* align:   8 */
    /* offset:  0 */ c_ext_id_t  ext_id;
    /*          8 */ uint64_t    nr_entries;
    /*         16 */ uint64_t    nr_bytes;
    /*         24 */ uint64_t    nr_drain_bytes;
    /*         32 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_dext_list_entry) != 32);

struct castle_dext_map_list_entry {
    /* align:   8 */
    /* offset:  0 */ union {
                        tree_seq_t      ct_seq;
                        c_merge_id_t    merge_id;
                     };
    /*          8 */ c_ext_id_t  ext_id;
    /*         16 */ uint8_t     is_merge;
    /*         17 */ uint8_t     _unused[15];
    /*         32 */
} PACKED;
STATIC_BUG_ON(sizeof(struct castle_dext_map_list_entry) != 32);

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
STATIC_BUG_ON(sizeof(struct castle_slist_entry) != 64);

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
#define CBV_PARENT_WRITE_LOCKED       (2)
#define CBV_CHILD_WRITE_LOCKED        (3)
/* Temporary variable used to set the above correctly, at the right point in time */
#define CBV_C2B_WRITE_LOCKED          (4)

/**
 * Bloom lookup request structure.
 */
typedef void (*castle_bloom_lookup_async_cb_t)(void *private, int key_exists);
typedef struct castle_bloom_lookup
{
    castle_bloom_t                 *bf;         /**< Bloom filter.                  */

    void                           *key;        /**< Key to search for.             */
    c_btree_hash_enum_t             hash_type;  /**< Key hash to use.               */

    struct castle_cache_block      *block_c2b;  /**< c2b for relevant filter block. */

    struct work_struct              work;       /**< Asynchronous work handler.     */
    castle_bloom_lookup_async_cb_t  async_cb;   /**< Asynchronous CB handler.       */
    void                           *private;    /**< Caller-provided private data.  */
} c_bloom_lookup_t;

struct castle_bloom_lookup;
typedef struct castle_bio_vec {
    c_bio_t                        *c_bio;        /**< Where this IO originated                 */

    void                           *key;          /**< Key we want to read                      */
    c_ver_t                         version;      /**< Version of key we want to read           */
    int                             cpu;          /**< CPU id for this request                  */
    int                             cpu_index;    /**< CPU index (for determining correct CT)   */
    struct castle_component_tree   *tree;         /**< CT to search/insert into.                */
    struct castle_da_cts_proxy     *cts_proxy;    /**< Reference-taking snapshot of CTs in DA.  */
    int                             cts_index;    /**< Current index into cts_proxy->cts[].     */

    /* Btree walk variables. */
    unsigned long                   flags;        /**< Flags                                    */
    int                             btree_depth;  /**< How far down the btree we've gone so far */
    int                             btree_levels; /**< Levels in the tree (private copy in case
                                                       someone splits root node while we are
                                                       lower down in the tree                   */
    void                           *parent_key;   /**< Key in parent node btree_node is from    */
    /* When writing, B-Tree node and its parent have to be locked concurrently. */
    struct castle_cache_block      *btree_node;
    struct castle_cache_block      *btree_parent_node;

    /* Bloom filters. */
    c_bloom_lookup_t                bloom_lookup;   /**< Bloom lookup request structure.        */
    uint8_t                         bloom_skip;     /**< Whether bloom filter advised skipping
                                                         tree. @also castle_bloom_debug         */
#ifdef CASTLE_BLOOM_FP_STATS
    int bloom_positive;
#endif

    c_val_tup_t accum; /**< Accumulates a return value candidate; used to sort
                            out counters and timestamps.    */

    struct work_struct              work;      /**< Used to thread this bvec onto a workqueue    */
    union {
        /* Castle Value Tuple allocation callback for writes */
        int                       (*cvt_get)    (struct castle_bio_vec *,
                                                 c_val_tup_t,  /**< CVT being replaced.          */
                                                 c_val_tup_t,  /**< Ancestral CVT, if there
                                                                    isn't precise (k,v) match,
                                                                    and if one exists.           */
                                                 c_val_tup_t *);
        struct {
            /* Acquire the necessary value resources for reads. */
            void                  (*val_get)    (c_val_tup_t *);
            /* Release the value resources previously acquired for reads. */
            void                  (*val_put)    (c_val_tup_t *);
        };
    };
    /* Completion callback */
    union {
        void                      (*queue_complete)  (struct castle_bio_vec *, int);
        void                      (*submit_complete) (struct castle_bio_vec *, int, c_val_tup_t);
    };
    void                          (*orig_complete)   (struct castle_bio_vec *, int, c_val_tup_t);
    atomic_t                        reserv_nodes;
    struct list_head                io_list;
#ifdef CASTLE_DEBUG
    unsigned long                   state;
    struct castle_cache_block      *locking;
    atomic_t                        read_passes;
#endif
#ifdef CASTLE_PERF_DEBUG
    struct castle_request_timeline *timeline;
#endif
    int                             seq_id;
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
/* register_cb - sets the callback function to be called after preparing buffer */
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
typedef void (*castle_iterator_next_t)    (void        *iter,
                                           void       **key_p,
                                           c_ver_t     *version_p,
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

int castle_iterator_has_next_sync(struct castle_iterator_type *iter_type, void *iter);

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
    /* Will form array indexed by the entry # from the original node. Used to find
       the right indirect node/entry in the array above. Again spans at most
       node->used entries. */
    struct {
        uint16_t                       r_idx;    /* Index in indirect_nodes array */
        uint16_t                       node_idx; /* Index in the indirect node */
    };
};

enum {
    C_ITER_MATCHING_VERSIONS,
    C_ITER_ANCESTRAL_VERSIONS
};

/* Used for iterating through the tree */
typedef struct castle_iterator {
    /* Fields below should be filled in before iterator is registered with the btree
       code with btree_iter_init() and start() */
    int                         (*need_visit)(struct castle_iterator *c_iter,
                                              c_ext_pos_t node_cep);
    int                         (*node_start)(struct castle_iterator *c_iter);
                                    /**< Returns index within node the iterator should begin
                                         iterating from, or 0 to start from the beginning.      */
    int                         (*each)      (struct castle_iterator *c_iter,
                                              int                     index,
                                              void                   *key,
                                              c_ver_t                 version,
                                              c_val_tup_t             cvt);
                                    /**< Returns a positive value to indicate the iterator
                                         should terminate, or 0 to continue.                    */
    int                         (*node_end)  (struct castle_iterator *c_iter, int async);
                                    /**< Returns a positive value to indicate the callback
                                         has restarted this (e.g. castle_iterator) iterator
                                         asynchronously.                                        */
    void                        (*end)       (struct castle_iterator *c_iter, int err, int async);
    void                         *private;
    struct castle_component_tree *tree;

    /* Fields below are used by the iterator to conduct the walk */
    int                           type;       /* C_ITER_XXX */
    c_ver_t                       version;
    void                         *parent_key; /* The key we followed to get to the block
                                                 on the top of the path/stack */
    union {
        /* Used by C_ITER_MATCHING_VERSIONS & C_ITER_ANCESTRAL_VERSIONS */
        struct {
            void                 *key;          /* The next key to look for in the iteration
                                                   (typically parent_key + 1 when at leafs) */
            int                   need_destroy; /* True if allocated by the iterator
                                                   (and needs destroying at the end) */
        } next_key;

    };
    int                           cancelled;
    int                           err;
    int                           seq_id;           /**< Unique ID for tracing                  */
    int                           running_async;    /**< Has the iterator requeued and gone
                                                         asynchronous since it started, e.g. to
                                                         do I/O or avoid a stack overflow.      */
    struct castle_cache_block    *path[MAX_BTREE_DEPTH];
    int                           depth;
    int                           btree_levels;     /**< Private copy of ct->tree_depth, recorded
                                                         at the time when the walk started.
                                                         Used to prevent races with root node
                                                         splits.                                */

    struct work_struct            work;
} c_iter_t;

struct node_buf_t;
struct node_buf_t {
    struct castle_btree_node *node;
    struct list_head          list;
};

/**
 * Non-atomic statistics specific to a given version.
 * This structure is used to store the stats, but also to do adjustments. This is why
 * signed integers are used.
 *
 * @also castle_version_stats
 */
typedef struct castle_version_nonatomic_stats {
    /* Item counts. */
    long        keys;               /**< @see castle_version_stats.keys                 */
    long        tombstones;         /**< @see castle_version_stats.tombstones           */

    /* Operation counts. */
    long        tombstone_deletes;  /**< @see castle_version_stats.tombstone_deletes    */
    long        version_deletes;    /**< @see castle_version_stats.version_deletes      */
    long        key_replaces;       /**< @see castle_version_stats.key_replaces         */
    long        timestamp_rejects;  /**< @see castle_version_stats.timestamp_rejects    */
} cv_nonatomic_stats_t;

typedef struct castle_async_iterator {
    castle_iterator_end_io_t        end_io;
    struct castle_iterator_type    *iter_type;
    void                           *private;
} c_async_iterator_t;

/* Enumerates latest version value for all entries */
typedef struct castle_rq_iterator {
    c_async_iterator_t            async_iter;
    struct castle_component_tree *tree;
    int                           err;
    int                           seq_id;               /**< Sequence ID for tracing.       */
    c_ver_t                       version;
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

    /* Variables used for counter accumulation. */
    c_val_tup_t                   counter_accumulator; /**< Accumulator for the current key. */
    void                         *counter_key;         /**< Key being accumulated.           */
    struct node_buf_t            *counter_buf;         /**< Buffer in which counter key is
                                                            stored. Value updated after
                                                            accumulation.                    */
    int                           counter_idx;         /**< Index in the buffer node under
                                                            which the counter is stored.     */
} c_rq_iter_t;

struct castle_merged_iterator;
struct component_iterator;

typedef void (*castle_merged_iterator_each_skip) (struct castle_merged_iterator *,
                                                  c_ver_t version,
                                                  c_val_tup_t dup_cvt,
                                                  c_val_tup_t new_cvt);

typedef struct castle_merged_iterator {
    c_async_iterator_t              async_iter;
    int                             iter_running;
    int                             nr_iters;
    struct castle_btree_type       *btree;
    int                             err;
    int64_t                         non_empty_cnt;
    uint64_t                        src_items_completed;
    struct component_iterator {
        int                          completed;
        void                        *iterator;
        struct castle_iterator_type *iterator_type;
        int                          cached;
        struct {
            void                    *k;
            c_ver_t                  v;
            c_val_tup_t              cvt;
            castle_user_timestamp_t  u_ts;
        } cached_entry;
        struct list_head             same_kv_head;
        union {
            struct rb_node           rb_node;       /**< Used to put the iterator onto rb tree
                                                         rooted in the merged_iterator.rb_root
                                                         (or temporarily when sorting same_kv
                                                          list on local rb tree) */
            struct list_head         same_kv_list;  /**< Used to add iterator to the list of
                                                         iterators with the same (k,v), rooted
                                                         at same_kv_head above. */
        };
    } *iterators;
    struct rb_root                   rb_root;
    castle_merged_iterator_each_skip each_skip;
    struct castle_da_merge          *merge;
    struct castle_double_array      *da;
} c_merged_iter_t;

typedef struct castle_da_rq_iterator c_da_rq_iter_t;

/**
 * Structure that stores individual CT relevance to a range query.
 *
 * castle_da_rq_iter_init() calls castle_da_rq_iterator_relevant_cts_get() to
 * get a list of which of its proxy_ct->cts[] are relevant to the range query.
 * The results are stored in an array of proxy_ct->nr_cts of these structures.
 *
 * A structure is required because a bloom filter lookup may go asynchronous.
 *
 * @also castle_da_rq_iterator_relevant_cts_get()
 * @also _castle_da_rq_iter_init()
 */
typedef struct castle_da_rq_iterator_ct_relevant {
    c_da_rq_iter_t             *rq_iter;            /**< Range query iterator backpointer.  */
    c_bloom_lookup_t            bloom_lookup;       /**< Bloom lookup structure.            */
    int                         relevant;           /**< Is CT relevant for range query?    */
} c_da_rq_iter_ct_relevant_t;

typedef struct castle_object_iterator castle_object_iterator_t;

/**
 * Range query iterator structure.
 */
typedef void (*castle_da_rq_iter_init_cb_t)(void *private);
struct castle_da_rq_iterator
{
    c_merged_iter_t             merged_iter;        /**< Merged iterator for rq_iters.          */

    struct castle_da_cts_proxy *cts_proxy;          /**< Reference-taking snapshot of CTs in DA.*/
    c_rq_iter_t                *ct_iters;           /**< nr_iters RQ iterators.                 */
    int                         nr_iters;           /**< Number of ct_iters[].                  */

    struct castle_double_array *da;
    c_ver_t                     version;
    void                       *start_key;
    void                       *end_key;
    void                       *start_stripped;     /**< Stripped start key.                    */
    void                       *end_stripped;       /**< Stripped end key.                      */

    c_da_rq_iter_ct_relevant_t *relevant_cts;       /**< CT range query relevance.              */
    atomic_t                    pending_lookups;    /**< Number of pending CT relevance checks. */

    c_async_iterator_t          async_iter;         /**< Async iterator callback.               */

    castle_da_rq_iter_init_cb_t init_cb;            /**< Initialisation complete callback.      */
    void                       *private;            /**< Passed to init_cb().                   */

    int                         seq_id;             /**< Unique ID for tracing.                 */
    int                         err;
};

#define BLOCKS_HASH_SIZE        (100)
struct castle_slave_block_cnt
{
    c_ver_t          version;
    block_t          cnt;
    struct list_head list;
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
    char           *buf;    /**< Ring buffer.                                               */
    c_byte_off_t    off;    /**< Write pointer (points to \0 from last castle_printk().     */
    c_byte_off_t    size;   /**< Size of ring buffer.                                       */
    int             wraps;  /**< Times buf has wrapped.                                     */
    spinlock_t      lock;   /**< Protects structure.                                        */
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
    c_chk_cnt_t                     reserved_schks;     /**< # of super chunks reserved in this
                                                             slave. */
    atomic_t                        free_chk_cnt;
    atomic_t                        io_in_flight;
    char                            bdev_name[BDEVNAME_SIZE];
    struct work_struct              work;
};

struct castle_slaves {
    struct kobject   kobj;
    struct list_head slaves;
};

/* Castle attachment represents a block device or an attached object collection */
struct castle_attachment {
    c_ver_t             version;
    int                 ref_cnt; /* protected by castle_attachments.lock */
    struct rw_semaphore lock;
    int                 device; /* !=0 if block device, == 0 if object collection */
    union {
        struct {
            struct gendisk             *gd;
        } dev; /* Only valid for block devices */
        struct {
            c_collection_id_t           id;
            uint32_t                    flags;
            char                       *name;
            struct castle_double_array *da;
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
extern c_da_t                     castle_next_da_id;

extern struct workqueue_struct *castle_wqs[2*MAX_BTREE_DEPTH+1];
#define castle_wq              (castle_wqs[0])

/* Various utilities */
#define C_BLK_SHIFT                    (12)
#define C_BLK_SIZE                     (1ULL << C_BLK_SHIFT)
#define NR_BLOCKS(_bytes)              (((_bytes) - 1) / C_BLK_SIZE + 1)
//#define disk_blk_to_offset(_cdb)     ((_cdb).block * C_BLK_SIZE)

#define CASTLE_ATTACH_RDONLY           (0)
#define CASTLE_ATTACH_DEAD             (1)  /* Set, when attachment resources are good to be
                                               freed. */

struct castle_attachment*
                      castle_device_init           (c_ver_t version);
void                  castle_device_free           (struct castle_attachment *cd);
struct castle_attachment*
                      castle_device_find           (dev_t dev);

int                   castle_collection_is_rdonly  (struct castle_attachment *ca);

struct castle_attachment*
                      castle_collection_init       (c_ver_t version, uint32_t flags, char *name);

struct castle_attachment *
                      castle_attachment_get        (c_collection_id_t collection, int rw);
void                  castle_attachment_put        (struct castle_attachment *ca);
void                  castle_attachment_free       (struct castle_attachment *ca);
void                  castle_attachment_free_complete(struct castle_attachment *ca);

struct castle_slave*  castle_claim                 (uint32_t new_dev);
void                  castle_release               (struct castle_slave *cs);
void                  castle_release_device        (struct castle_slave *cs);

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
                                                    c_da_t            da_id,
                                                    c_ext_type_t      ext_type,
                                                    c_byte_off_t      size,
                                                    int               in_tran,
                                                    void              *data,
                                                    c_ext_event_callback_t callback);
void                  castle_ext_freespace_size_update
                                                   (c_ext_free_t *ext_free,
                                                    int           do_checks);

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

c_byte_off_t          castle_ext_freespace_available
                                                   (c_ext_free_t     *ext_free);

castle_freespace_t *  freespace_sblk_get           (struct castle_slave *cs);
void                  freespace_sblk_put           (struct castle_slave *cs);

void                  castle_release_oos_slave     (struct work_struct *work);

c_rda_type_t          castle_get_rda_lvl           (void);
c_rda_type_t          castle_get_ssd_rda_lvl       (void);
c_rda_type_t          castle_ssdrda_to_rda         (c_rda_type_t rda_type);

struct castle_cache_block;

struct castle_object_replace {
    uint64_t                      value_len;        /**< Length of the value being written out. */
    c_val_tup_t                   cvt;              /**< CVT allocated for the value.           */
    c_bvec_t                     *c_bvec;           /**< bvec to be submitted to DA.            */
    c_vl_bkey_t                  *key;              /**< Key of the value to be replaced.       */

    /* Variables used when copying the value into the CVT. */
    struct castle_cache_block    *data_c2b;         /**< Current cache block used to copy the
                                                         data out.                              */
    uint64_t                      data_c2b_offset;  /**< Offset in the data_c2b at which future
                                                         writes should start from (everything
                                                         up to data_c2b_offset has already been
                                                         used up).                              */
    uint64_t                      data_length;      /**< Amount of data still to be written out
                                                         initially equals value_len.             */

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
    /*0: not a counter, 1: counter SET, 2: counter ADD */
    uint8_t                       counter_type;

    uint8_t                       has_user_timestamp;
    castle_user_timestamp_t       user_timestamp;
};

struct castle_object_get {
    c_val_tup_t                   cvt;              /**< Describes value (e.g. disk offset).    */

    struct castle_cache_block    *data_c2b;
    uint64_t                      data_c2b_length;
    uint64_t                      data_length;
    int                           first;            /**< First call of _object_iter_continue()? */
    c_vl_bkey_t                  *key;              /**< Requested key.                         */
    uint8_t                       flags;            /**< From userland request                  */



    int       (*reply_start)     (struct castle_object_get *get,
                                  int err,
                                  uint64_t data_length,
                                  void *buffer,
                                  uint32_t buffer_length);
    int       (*reply_continue)  (struct castle_object_get *get,
                                  int err,
                                  void *buffer,
                                  uint32_t buffer_length,
                                  int last);
};

struct castle_object_pull {
    int                           seq_id;       /**< Unique ID for tracing.                     */
    c_val_tup_t                   cvt;

    struct castle_da_cts_proxy   *cts_proxy;    /**< Reference-taking snapshot of CTs in DA.    */
    uint64_t                      remaining;
    uint64_t                      offset;

    c_vl_bkey_t                  *key;          /**< Key of the value to be replaced.           */

    struct castle_cache_block    *curr_c2b;

    void                         *buf;
    uint32_t                      to_copy;

    struct work_struct            work;

    void (*pull_continue)        (struct castle_object_pull *pull,
                                  int err, uint64_t length, int done);
};
/*
 * This is the callback to notify when the iterator has the
 * next key available. The callback should return non-zero if
 * it wants the next value without calling castle_object_iter_next
 * again.
 */
typedef int (*castle_object_iter_next_available_t)
        (struct castle_object_iterator *iter,
         c_vl_bkey_t *key,
         c_val_tup_t *val,
         int err,
         void *data);

typedef void (*castle_object_iter_start_cb_t)(void *private, int err);
typedef void (*castle_object_iter_init_cb_t)(castle_object_iterator_t *iterator);
struct castle_object_iterator
{
    c_async_iterator_t                  async_iter;
    /* Filled in by the client */
    c_da_t                              da_id;
    c_ver_t                             version;
    struct castle_btree_type           *btree;
    void                               *start_key;
    void                               *end_key;

    /* Rest */
    int                                 seq_id;                 /**< Unique ID for tracing.     */
    int                                 err;
    int                                 completed;
    void                               *last_next_key;
    c_da_rq_iter_t                      da_rq_iter;
    /* Cached entry, guaranteed to fall in the hypercube */
    int                                 cached;
    void                               *cached_k;
    c_ver_t                             cached_v;
    c_val_tup_t                         cached_cvt;
    castle_object_iter_next_available_t next_available;
    void                               *next_available_data;
    struct work_struct                  work;

    castle_object_iter_start_cb_t       start_cb;               /**< Iterator start callback.   */
    void                               *start_private;          /**< Passed to start_cb().      */

    castle_object_iter_init_cb_t        init_cb;                /**< Iterator init callback.    */
};

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
        emergency_restart();                                                  \
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

/**
 * Structure to store extent references for CT.
 */
typedef struct castle_ct_extent_reference_set_t
{
    /* align:  4 */
    /* offset: 0 */ uint32_t        nr_refs;    /**< Number of extents handled by structure.    */
    /*         4 */ c_ext_mask_id_t refs[0];    /**< Array of nr_refs extent references.        */
    /*         4 */
} c_ct_ext_ref_t;
STATIC_BUG_ON((sizeof(c_ct_ext_ref_t) + sizeof(c_ext_mask_id_t)) % 4);

/**
 * CT states to handle key ranges with partial merge redirection.
 */
typedef enum {
    NO_REDIR = 0,   /**< No redirection for this CT.    */
    REDIR_INTREE,   /**< CT is an input tree.           */
    REDIR_OUTTREE   /**< CT is an output tree.          */
} c_ct_redir_state_enum_t;

/**
 * Snapshot with references of CTs in DA.
 *
 * Necessary to amortise the cost of many CT reference gets/puts.
 *
 * LOCKING/REFERENCE COUNTING NOTES:
 *
 * castle_da_cts_proxy_create() creates a CT's proxy structure under a DA write
 * lock and takes out two references - one for the DA (it sets da->cts_proxy to
 * point to itself) and another for the caller who requested the DA CT's proxy.
 *
 * Subsequent requests take a further reference.  When the reference count drops
 * to 0 the proxy is freed and references are dropped.  The first reference (for
 * the DA) must be dropped after a da->cts_proxy pointer has been updated to
 * NULL (under DA write lock).
 *
 * When creating a DA CT's proxy structure we set CASTLE_DA_CTS_PROXY_CREATE_BIT
 * in da->flags to ensure creation is serialised.  If the bit is already set we
 * sleep and then retry.
 */
struct castle_da_cts_proxy {
    struct castle_da_cts_proxy_ct {
        struct castle_component_tree   *ct;         /**< Pointer to CT.                         */
        c_ct_ext_ref_t                 *ext_refs;   /**< References held on CT extents.         */
        void                           *pk;         /**< Partition key for CT.                  */
        void                           *pk_next;    /**< Next key of partition key.
                                                         Set for REDIR_INTREE only.             */
        c_ct_redir_state_enum_t         state;      /**< Redirection state.                     */
    } *cts;
    int                         nr_cts;     /**< Number of CTs in cts[].                        */
    void                       *keys;       /**< Buffer of partition keys.                      */
    void                       *ext_refs;   /**< Buffer of per-CT extent references.            */
    btree_t                     btree_type; /**< Tree type used for the CTs.                    */
    atomic_t                    ref_cnt;    /**< References held on proxy structure.            */
    struct castle_double_array *da;         /**< Backpointer to DA (for DEBUG).                 */
    c_chk_cnt_t                 da_size;    /**< Amount of freespace used by the DA at          */
                                            /**< the time of proxy creation.                    */
    struct work_struct          work;       /**< For asynchronous castle_da_cts_proxy_drop().   */
};

/**
 * State structure for use by castle_da_cts_proxy_all_invalidate().
 *
 * @also castle_da_cts_proxy_all_invalidate().
 */
struct castle_da_cts_proxy_all_invalidate {
    struct castle_da_cts_proxy    **proxies;        /**< Array of proxy CTs proxy pointers.     */
    int                             proxy;          /**< Number of elements in proxies[].       */
};

/* Low free space structure being used by each merge in DA. */
struct castle_da_lfs_ct_t {
    struct castle_double_array *da;                 /**< Doubling array.                        */
    uint8_t                     space_reserved;     /**< Reserved space from low space handler. */
    uint8_t                     rwct;               /**< Whether allocating RWCT or not.        */

    /* Following members for use by LFS_VCT_T_MERGE only. */
    struct {
        c_chk_cnt_t     size;               /**< Size of the extent to be reserved.     */
        c_ext_id_t      ext_id;             /**< ID to be set after space is reserved.  */
    } internal_ext, tree_ext, data_ext;
    int                         leafs_on_ssds;
    int                         internals_on_ssds;
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
#define CASTLE_DA_CTS_PROXY_CREATE_BIT      (2)     /**< Serialises creation of da->cts_proxy.  */
#define CASTLE_DA_INSERTS_DISABLED          (3)     /**< Set when inserts are disabled.         */
#define CASTLE_DA_INSERTS_BLOCKED_ON_MERGE  (4)
#define CASTLE_TOMBSTONE_DISCARD_TD_DEFAULT (0)

#define PARTIAL_MERGES_QUERY_REDIRECTION_BTREE_NODE_LEVEL (0)
#if PARTIAL_MERGES_QUERY_REDIRECTION_BTREE_NODE_LEVEL > MAX_BTREE_DEPTH
#error "PARTIAL_MERGES_QUERY_REDIRECTION_BTREE_NODE_LEVEL > MAX_BTREE_DEPTH"
#endif

/* rate at which output tree leaf nodes extent is grown; in chunks at a time. */
#define MERGE_OUTPUT_TREE_GROWTH_RATE (10) /* BM said don't make this < 10 */
/* rate at which output tree medium objects extent is grown; in chunks at a time. */
#define MERGE_OUTPUT_DATA_GROWTH_RATE (10) /* BM said don't make this < 10 */

#define MIN_DA_SERDES_LEVEL                 (2) /* merges below this level won't be serialised;
                                                   and therefore won't use partial merges       */
struct castle_double_array {
    c_da_t                      id;
    c_ver_t                     root_version;
    rwlock_t                    lock;               /**< Protects levels[].trees lists          */
    struct kobject              kobj;
    struct kobject              arrays_kobj;        /**< Sysfs entry for list of arrays         */
    struct kobject              merges_kobj;        /**< Sysfs entry for list of merges         */
    unsigned long               flags;
    btree_t                     btree_type;         /**< Tree type used for the CTs             */
    int                         nr_trees;           /**< Total number of CTs in the DA, including
                                                         input, output, not-merging, queriable
                                                         and non-queriable CTs.                 */
    struct {
        int                     nr_trees;           /**< Number of queriable CTs at level.      */
        int                     nr_output_trees;    /**< Number of output trees at level.       */
        struct list_head        trees;              /**< List of (nr_trees) at level            */
    } levels[MAX_DA_LEVEL];

    struct task_struct         *l1_merge_thread;    /**< Level-1 merge thread.                  */
    struct castle_da_cts_proxy *cts_proxy;          /**< Reference-taking snapshot of CTs in DA.
                                                         Protected by da->lock.                 */
    atomic_t                    lfs_victim_count;   /**< Number of queued LFS callbacks.
                                                         Non-zero value implies DA is in LFS.   */
    struct castle_da_lfs_ct_t   l1_merge_lfs;       /**< LFS structure for level 1 merge.       */
    struct list_head            hash_list;
    atomic_t                    ref_cnt;
    atomic_t                    attachment_cnt;

    /* Write IO wait queue members */
    struct castle_da_io_wait_queue {
        spinlock_t              lock;               /**< Protects list,cnt (accessed by 1 CPU so
                                                         should be no need for rwlock)          */
        atomic_t                cnt;                /**< Number of pending write IOs            */
        struct list_head        list;               /**< List of pending write IOs              */
        struct castle_double_array *da;             /**< Back pointer to parent DA              */
        struct work_struct      work;               /**< For queue kicks                        */
    } *ios_waiting;                                 /**< Array of pending write IO queues,
                                                         1 queue per request-handling CPU       */
    atomic_t                    ios_waiting_cnt;    /**< Total number of pending write IOs      */

    wait_queue_head_t           merge_waitq;        /**< Merge deamortisation wait queue        */
    /* Compaction (Big-merge) */
    int                         top_level;          /**< Levels in the doubling array.          */

    /* General purpose work structure for placing DA on a workqueue.
     * Currently used by just castle_da_level0_modified_promote() so no locking
     * is done.  If this changes in the future, this will need to be revisited. */
    struct work_struct          work;               /**< General purpose work structure.        */
    void                       *private;            /**< Work private data.                     */

    /* Rate control parameters. */
    atomic64_t                  write_key_bytes;    /**< # of key bytes written since FS start. */
    atomic64_t                  write_data_bytes;   /**< # of data bytes written since FS start.*/
    atomic64_t                  read_key_bytes;     /**< # of key bytes read since FS start.    */
    atomic64_t                  read_data_bytes;    /**< # of data bytes read since FS start.   */

    struct timeval              prev_time;          /**< Last sample time.                      */
    uint64_t                    write_rate;         /**< Max write rate set. (in bytes/usecs).  */
    uint64_t                    read_rate;          /**< Max read rate set. (in bytes/usecs).   */
    struct timer_list           write_throttle_timer;
                                                    /**< Timer to check write rate and throttle
                                                     **< if required.                           */
    uint64_t                    sample_rate;
    uint64_t                    sample_data_bytes;
    spinlock_t                  rate_ctrl_lock;
    c_da_opts_t                 creation_opts;
    atomic64_t                  tombstone_discard_threshold_time_s;

    struct {
        struct{
            atomic64_t partition_updates;
            atomic64_t extent_shrinks;
        } partial_merges;
        struct{
            atomic64_t tombstone_inserts;
            atomic64_t tombstone_discards;
        } tombstone_discard;
        struct{
            atomic64_t t0_discards;
            atomic64_t merge_discards;
            atomic64_t ct_max_uts_negatives;
            atomic64_t ct_max_uts_false_positives;
        } user_timestamps;
    } stats;
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
    /* Item counts. */
    atomic64_t  keys;               /**< Number of live keys.  May be inaccurate until all
                                         merges complete and duplicates are handled.        */
    atomic64_t  tombstones;         /**< Number of tombstones.                              */


    /* Operation counts. */
    atomic64_t  tombstone_deletes;  /**< Number of keys deleted by tombstones (does not
                                         include tombstones deleted by tombstones).         */
    atomic64_t  version_deletes;    /**< Number of entries deleted due to version delete.   */
    atomic64_t  key_replaces;       /**< Number of keys replaced by newer keys (excludes
                                         tombstones).                                       */
    atomic64_t  timestamp_rejects;  /**< Number of keys discarded due to out of timestamp
                                         order writes.                                      */
} cv_stats_t;

/**
 * Version-specific state.
 *
 * Maintain statistics about a given version.  Used by merge output.
 */
typedef struct castle_version_state {
    c_ver_t                     version;        /**< Version ID.                            */
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
    c_ver_t                 version;        /**< Version to adjust stats for.                   */

    int                     live;           /**< Whether to update live version stats.          */
    cv_states_t            *private;        /**< Whether to update private per-version stats.   */
    int                     consistent;     /**< Whether to update crash consistent stats.      */

    cv_nonatomic_stats_t    stats;          /**< Stat changes.                                  */
} cv_stats_adjust_t;

extern int castle_nice_value;

extern int castle_checkpoint_period;

extern int castle_meta_ext_compact_pct;

extern int castle_last_checkpoint_ongoing;

struct castle_merge_thread {
    c_thread_id_t               id;
    struct task_struct         *thread;
    c_merge_id_t                merge_id;
    c_work_id_t                 work_id;
    uint64_t                    cur_work_size;
    struct list_head            hash_list;
    struct castle_double_array *da;
};

extern uint32_t castle_merge_threads_count;

extern int castle_extents_process_ratelimit;

extern int castle_rebuild_freespace_threshold;

extern unsigned int castle_rda_lvl;

extern const char *castle_error_strings[];

enum {
    MERGE_NOT_COMPLETED = 0,
    MERGE_COMPLETED = 1,
    MERGE_COMPLETED_NO_OP_TREE = 2,
};
extern atomic_t castle_req_seq_id; /**< Unique ID for tracing */

#endif /* __CASTLE_H__ */
