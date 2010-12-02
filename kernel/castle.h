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
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2,6,24)
#include <asm/semaphore.h>
#else
#include <linux/semaphore.h>
#endif

#include "castle_public.h"

#undef BUG
#undef BUG_ON

#define BUG()                                                           \
            do {                                                        \
                    WARN_ON(1);                                         \
                    panic("castle panic %s:%d\n", __FILE__, __LINE__);  \
            } while(0)
#define BUG_ON(_cond)    do{if(_cond) BUG();} while(0)

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
//#define PACKED               __attribute__((packed))
#define EXIT_SUCCESS         (0)

#define STATIC_BUG_ON_HELPER(expr) \
        (!!sizeof (struct { unsigned int static_assertion_error: (expr) ? -1 : 1; }))
#define STATIC_BUG_ON(expr) \
        extern int (*assert_function__(void)) [STATIC_BUG_ON_HELPER(expr)]

extern int castle_fs_inited;

typedef uint32_t tree_seq_t;                   
#define GLOBAL_TREE         ((tree_seq_t)0)
#define INVAL_TREE          ((tree_seq_t)-1)
#define TREE_GLOBAL(_t)     ((_t) == GLOBAL_TREE)
#define TREE_INVAL(_t)      ((_t) == INVAL_TREE)

typedef uint32_t da_id_t;                   
#define INVAL_DA            ((da_id_t)-1)
#define DA_INVAL(_da)       ((_da) == INVAL_DA)

typedef uint32_t block_t;
#define INVAL_BLOCK         ((block_t)-1) 
#define BLOCK_INVAL(_b)     ((_b) == INVAL_BLOCK) 

/* New Free space structures */

#define MAX_NR_SLAVES 20

#define C_CHK_SHIFT                    (20) 
#define C_CHK_SIZE                     (1 << C_CHK_SHIFT)

#define CHUNK_OFFSET(offset)  ((offset) & (C_CHK_SIZE - 1))
#define BLOCK_OFFSET(offset)  ((offset) & (C_BLK_SIZE - 1))
#define SECTOR_OFFSET(offset) ((offset) & ((1 << 9)-1))
#define CHUNK(offset)         ((offset) >> C_CHK_SHIFT)
#define BLOCK(offset)         ((offset) >> C_BLK_SHIFT)
#define BLK_IN_CHK(offset)    (BLOCK(CHUNK_OFFSET(offset)))
#define BLKS_PER_CHK          (C_CHK_SIZE / C_BLK_SIZE)
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
#define MICRO_EXT_SIZE                 (1)   /* Dont change this */
#define META_SPACE_START               (64)
#define META_SPACE_SIZE                (300)
#define MSTORE_SPACE_SIZE              (50)
#define FREE_SPACE_START               (400) /* This must be >= to META_EXT_STRAT + METAEXT_SIZE. */
#define FREESPACE_OFFSET               (2 * C_CHK_SIZE)
#define FREESPACE_SIZE                 (20 * C_CHK_SIZE)

#define sup_ext_to_slave_id(_id)       ((_id) - SUP_EXT_ID)
#define slave_id_to_sup_ext(_id)       ((_id) + SUP_EXT_ID)

/* Logical extent structures are stored seperatly from normal extents. They are 
 * stored in extent superblock itself. */
#define LOGICAL_EXTENT(_ext_id)        ((_ext_id) < EXT_SEQ_START && !EXT_ID_INVAL(_ext_id))
#define SUPER_EXTENT(_ext_id)          (((_ext_id) >= SUP_EXT_ID) && ((_ext_id) < slave_id_to_sup_ext(MAX_NR_SLAVES)))

typedef enum {
    DEFAULT,
    JOURNAL,
    FS_META,
    LOG_FREEZER,
    META_EXT,
    MICRO_EXT,
    SUPER_EXT,
    NR_RDA_SPEC
} c_rda_type_t;

typedef uint32_t c_chk_cnt_t;
typedef uint32_t c_chk_t;
typedef uint64_t c_ext_id_t;
typedef uint32_t c_uuid_t;

#define INVAL_CHK                       ((c_chk_t)-1)
#define CHK_INVAL(_chk)                 ((_chk) == INVAL_CHK)

#define INVAL_EXT_ID                    (-1)
#define EXT_ID_INVAL(_id)               ((_id) == INVAL_EXT_ID)
#define INVAL_SLAVE_ID                  (0)

struct castle_chunk_sequence {
    c_chk_t         first_chk;
    c_chk_cnt_t     count;
} PACKED;
typedef struct castle_chunk_sequence c_chk_seq_t;
#define INVAL_CHK_SEQ                ((c_chk_seq_t){0,0})
#define CHK_SEQ_INVAL(_seq)          ((_seq).count == 0)
#define CHK_SEQ_EQUAL(_seq1, _seq2)  (((_seq1).first_chk == (_seq2).first_chk) && \
                                      ((_seq1).count == (_seq2).count)) 
#define chk_seq_fmt                  "(0x%llx, 0x%llx)"
#define chk_seq2str(_seq)            (_seq).first_chk, (_seq).count

struct castle_disk_chunk {
    c_uuid_t        slave_id;
    c_chk_t         offset;
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
    c_ext_id_t      ext_id;
    c_byte_off_t    offset;
} PACKED;
typedef struct castle_extent_position c_ext_pos_t;
#define __INVAL_EXT_POS             {INVAL_EXT_ID,0}
#define INVAL_EXT_POS               ((c_ext_pos_t) __INVAL_EXT_POS) 
#define EXT_POS_INVAL(_off)         ((_off).ext_id == INVAL_EXT_ID)
#define EXT_POS_EQUAL(_off1, _off2) (((_off1).ext_id == (_off2).ext_id) && \
                                      ((_off1).offset == (_off2).offset)) 
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
#define cep_fmt_str                  "(%llu, 0x%llx)"
#define cep_fmt_str_nl               "(%llu, 0x%llx). \n"
#define cep2str(_off)                (_off).ext_id, BLOCK((_off).offset)
#define __cep2str(_off)              (_off).ext_id, ((_off).offset)

typedef struct castle_extent_freespace {
    c_ext_id_t      ext_id;
    c_byte_off_t    ext_size;
    uint32_t        align;
    atomic64_t      used;
    atomic64_t      blocked;
} c_ext_fs_t;

typedef struct castle_extent_freespace_byte_stream {
    c_ext_id_t      ext_id;
    c_byte_off_t    ext_size;
    uint32_t        align;
    uint64_t        used;
    uint64_t        blocked;
} c_ext_fs_bs_t;

typedef struct {
    uint32_t        max_entries;
    uint32_t        nr_entries;
    uint32_t        prod;
    uint32_t        cons;
    c_chk_cnt_t     free_chk_cnt;
    c_chk_cnt_t     disk_size;
} castle_freespace_t;

struct castle_elist_entry {
    c_ext_id_t      ext_id;
    c_chk_cnt_t     size;
    c_rda_type_t    type;
    uint32_t        k_factor;
    c_ext_pos_t     maps_cep;
    uint32_t        obj_refs;
} PACKED;

struct castle_extents_sb_t {
    c_ext_id_t                              ext_id_seq;
    uint64_t                                nr_exts;
    c_byte_off_t                            next_free_byte;
    c_disk_chk_t                            micro_maps[MAX_NR_SLAVES];
    struct castle_elist_entry               micro_ext;
    struct castle_elist_entry               meta_ext;
    struct castle_elist_entry               mstore_ext[2];
};

struct castle_slave_superblock {
    struct castle_slave_superblock_public   pub;
    uint32_t                                fs_version;
    castle_freespace_t                      freespace;
} PACKED;

struct castle_fs_superblock {
    struct castle_fs_superblock_public      pub;
    uint32_t                                nr_slaves;
    uint32_t                                slaves[MAX_NR_SLAVES];
    struct castle_extents_sb_t              extents_sb;
    uint32_t                                fs_version;
    c_ext_pos_t                             mstore[16];
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

struct castle_value_tuple {
    uint8_t           type;
    uint64_t          length;
    union {
        uint8_t      *val;
        c_ext_pos_t   cep;
    };
} PACKED;
typedef struct castle_value_tuple c_val_tup_t;

#define INVAL_VAL_TUP        ((c_val_tup_t){CVT_TYPE_INVALID, 0, {.cep = INVAL_EXT_POS}})

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
}; 


#define MTREE_TYPE                 0x33
#define MTREE_BVEC_BLOCK(_bvec)   ((sector_t)(_bvec)->key)
#define BATREE_TYPE                0x44
#define RW_VLBA_TREE_TYPE          0x55
#define RO_VLBA_TREE_TYPE          0x66
                                  
#define MAX_BTREE_DEPTH           (10)
#define MAX_BTREE_ENTRIES         (2500)

typedef uint8_t btree_t;

#define BTREE_NODE_MAGIC  0x0000cdab
struct castle_btree_node {
    uint32_t        magic;
    uint32_t        version;
    uint32_t        used;
    uint8_t         is_leaf;
    /* Payload (i.e. btree entries) depend on the B-tree type */
    btree_t         type;
    c_ext_pos_t     next_node;
    uint8_t         payload[0];
} PACKED;

#define BTREE_NODE_PAYLOAD(_node)   ((void *)&(_node)->payload)

#define PLUS_INFINITY_DIM_LENGTH 0xFFFFFFFF

typedef struct castle_var_length_btree_key {
    uint32_t length;
    uint32_t nr_dims;
    uint32_t dim_head[0];
    /* uint8_t dims[][] */
} PACKED c_vl_bkey_t;

/* Below encapsulates the internal btree node structure, different type of
   nodes may be used for different trees */
struct castle_btree_type {
    btree_t   magic;         /* Also used as an index to castle_btrees
                                array.                                 */
    int       node_size;     /* in C_BLK_SIZE                          */
    void     *min_key;       /* Minimum key                            */
    void     *max_key;       /* Maximum used as the end of node marker */
    void     *inv_key;       /* An invalid key, comparison with it 
                                should always return a negative number
                                except if also compared to invalid key
                                in which case cmp should return zero   */
    int     (*need_split)    (struct castle_btree_node *node,
                              int                       version_or_key);
                             /* 0 - version split, 1 - key split       */
    int     (*key_compare)   (void *key1, void *key2);
                             /* Returns negative if key1 < key2, zero 
                                if equal, positive otherwise           */
    void*   (*key_duplicate) (void *key);
                             /* Returns duplicate of key. Need to call 
                              * a dealloc later to free resources      */
    void*   (*key_next)      (void *key);
                             /* Successor key, succ(MAX) = INVAL,
                                succ(INVAL) = INVAL                    */
    void    (*key_dealloc)   (void *key);
                             /* Destroys the key, frees resources
                                associated with it                     */
    int     (*entry_get)     (struct castle_btree_node *node,
                              int                       idx,
                              void                    **key_p,            
                              version_t                *version_p,
                              c_val_tup_t              *cvt_p);
    void    (*entry_add)     (struct castle_btree_node *node,
                              int                       idx,
                              void                     *key,            
                              version_t                 version,
                              c_val_tup_t               cvt);
    void    (*entry_replace) (struct castle_btree_node *node,
                              int                       idx,
                              void                     *key,            
                              version_t                 version,
                              c_val_tup_t               cvt);
    void    (*entry_disable) (struct castle_btree_node *node,
                              int                       idx);
    void    (*entries_drop)  (struct castle_btree_node *node,
                              int                       idx_start,
                              int                       idx_end);
                             /* Drop all entries between idx_start and
                                idx_stop. Inclusive                    */ 
    void    (*node_print)    (struct castle_btree_node *node);
#ifdef CASTLE_DEBUG    
    void    (*node_validate) (struct castle_btree_node *node);
#endif        
};

struct castle_component_tree {
    tree_seq_t          seq;
    atomic_t            ref_count;
    atomic_t            write_ref_count;
    atomic64_t          item_count;
    btree_t             btree_type;
    uint8_t             dynamic;           /* 1 - dynamic modlist btree, 0 - merge result */ 
    da_id_t             da;
    uint8_t             level;
    uint8_t             new_ct;            /* Marked for cts which are not yet
                                            * flushed onto disk. */
    struct rw_semaphore lock;              /* Protects root_node, tree depth & last_node  */
    uint8_t             tree_depth;
    c_ext_pos_t         root_node;
    c_ext_pos_t         first_node;
    c_ext_pos_t         last_node;
    atomic64_t          node_count;
    struct list_head    da_list;
    struct list_head    hash_list;
    struct list_head    large_objs;
    struct mutex        lo_mutex;          /* Protects Large Object List. */
    c_ext_fs_t          tree_ext_fs;
    c_ext_fs_t          data_ext_fs;
    atomic64_t          large_ext_chk_cnt;
};
extern struct castle_component_tree castle_global_tree;

struct castle_large_obj_entry {
    c_ext_id_t          ext_id;
    uint64_t            length;
    struct list_head    list;
};

struct castle_dlist_entry {
    da_id_t     id;
    version_t   root_version;
} PACKED;

struct castle_clist_entry {
    da_id_t      da_id;
    uint64_t     item_count;
    btree_t      btree_type;
    uint8_t      dynamic;
    tree_seq_t   seq;
    uint8_t      level;
    uint8_t      tree_depth;
    c_ext_pos_t  root_node;
    c_ext_pos_t  first_node;
    c_ext_pos_t  last_node;
    uint64_t     node_count;
    c_ext_fs_bs_t tree_ext_fs_bs;
    c_ext_fs_bs_t data_ext_fs_bs;
    uint64_t	 large_ext_chk_cnt;
} PACKED;

struct castle_vlist_entry {
    version_t    version_nr;
    version_t    parent;
    da_id_t      da_id;
    uint64_t     size;
} PACKED;

#define MAX_NAME_SIZE 128
struct castle_alist_entry {
    version_t   version;
    char        name[MAX_NAME_SIZE];
} PACKED;

#define MLIST_NODE_MAGIC  0x0000baca
struct castle_mlist_node {
    uint32_t     magic;
    uint16_t     capacity;
    uint16_t     used;
    c_ext_pos_t  next;
    uint8_t      payload[0];
} PACKED;

struct castle_flist_entry {
    uint32_t        slave_uuid;
    version_t       version;
    block_t         blocks;
} PACKED;

struct castle_lolist_entry {
    c_ext_id_t      ext_id;
    uint64_t        length;
    tree_seq_t      ct_seq;
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
#define CBV_DOING_SPLITS              (2) 
#define CBV_PARENT_WRITE_LOCKED       (3) 
#define CBV_CHILD_WRITE_LOCKED        (4) 
/* Temporary variable used to set the above correctly, at the right point in time */ 
#define CBV_C2B_WRITE_LOCKED          (5) 

typedef struct castle_bio_vec {
    /* Where did this IO originate from */
    c_bio_t                      *c_bio;
    
    /* What (key, version) do we want to read */
    void                         *key;
    version_t                     version;
    /* Component tree in which to perform the search */
    struct castle_component_tree *tree;
    /* Flags */
    unsigned long                 flags;
    /* Used to walk the B-Tree */
    union {
        struct {
            /* How far down the tree we've gone so far */
            int                        btree_depth;
            int                        split_depth;
            /* What's the number of levels in the tree, private copy needed in case
               someone splits the root node while we are lower down in the tree */
            int                        btree_levels;
            /* Key in the parent node under which we found btree_node */
            void                      *parent_key;
            /* When writing, B-Tree node and its parent have to be 
               locked concurrently. */
            struct castle_cache_block *btree_node;
            struct castle_cache_block *btree_parent_node;
        };
    };
    /* Used to thread this bvec onto a workqueue */
    struct work_struct               work;
    /* Value tuple allocation callback */
    int                            (*cvt_get)    (struct castle_bio_vec *, 
                                                  c_val_tup_t,
                                                  c_val_tup_t *);
    /* Completion callback */
    void                           (*endfind)    (struct castle_bio_vec *, int, c_val_tup_t);
    void                           (*da_endfind) (struct castle_bio_vec *, int, c_val_tup_t);
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
/* skip - set the low level iterator to skip to the key, but dont run lower
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

    struct castle_indirect_node *indirect_nodes; /* If allocated, MAX_BTREE_ENTRIES */
                                
    struct work_struct           work;
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
    int                           in_range;
    castle_iterator_end_io_t      end_io;
    void                         *private;
    int                           sync_call; /* TODO: Cleanup, not requried */
} c_rq_enum_t;

struct castle_merged_iterator;
struct component_iterator;

typedef void (*castle_merged_iterator_each_skip) (struct castle_merged_iterator *,
                                                  struct component_iterator *);

typedef struct castle_merged_iterator {
    int nr_iters;
    struct castle_btree_type *btree;
    int err;
    int non_empty_cnt;
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
    } *iterators;
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
    int                             new_dev;
    struct kobject                  kobj;
    struct list_head                list;
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
    struct mutex                    sblk_lock;
    c_chk_cnt_t                     disk_size; /* in chunks; max_chk_num + 1 */
    atomic_t                        free_chk_cnt;
};

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

    struct kobject      kobj;
    int                 sysfs_registered;
    struct list_head    list;
};

struct castle_attachments { 
    struct kobject collections_kobj;
    struct kobject devices_kobj;
    int major;
    struct list_head attachments;
    spinlock_t     lock;
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

struct castle_slave*  castle_claim                 (uint32_t new_dev);
void                  castle_release               (struct castle_slave *cs);
                                                   
void                  castle_slave_access          (uint32_t uuid);
                                                   
struct castle_slave*  castle_slave_find_by_id      (uint32_t id);
struct castle_slave*  castle_slave_find_by_uuid    (uint32_t uuid);
struct castle_slave*  castle_slave_find_by_block   (c_ext_pos_t cep);

struct castle_slave_superblock* 
                      castle_slave_superblock_get  (struct castle_slave *cs);
void                  castle_slave_superblock_put  (struct castle_slave *cs, int dirty);
struct castle_fs_superblock* 
                      castle_fs_superblocks_get    (void);
void                  castle_fs_superblocks_put    (struct castle_fs_superblock *sb, int dirty);

int                   castle_fs_init               (void);

int                   castle_ext_fs_init           (c_ext_fs_t       *ext_fs, 
                                                    da_id_t           da_id, 
                                                    c_byte_off_t      size,
                                                    uint32_t          align);

int                   castle_ext_fs_consistent     (c_ext_fs_t       *ext_fs);

int                  _castle_ext_fs_init           (c_ext_fs_t       *ext_fs, 
                                                    da_id_t           da_id, 
                                                    c_byte_off_t      size,
                                                    uint32_t          align,
                                                    c_ext_id_t        ext_id);

void                  castle_ext_fs_fini           (c_ext_fs_t       *ext_fs);

int                   castle_ext_fs_pre_alloc      (c_ext_fs_t       *ext_fs,
                                                    c_byte_off_t      size);

int                   castle_ext_fs_get            (c_ext_fs_t       *ext_fs,
                                                    c_byte_off_t      size,
                                                    int               alloc_done,
                                                    c_ext_pos_t      *cep);

int                   castle_ext_fs_free           (c_ext_fs_t       *ext_fs,
                                                    int64_t           size);

void                  castle_ext_fs_marshall       (c_ext_fs_t       *ext_fs, 
                                                    c_ext_fs_bs_t    *ext_fs_bs);

void                  castle_ext_fs_unmarshall     (c_ext_fs_t       *ext_fs, 
                                                    c_ext_fs_bs_t    *ext_fs_bs);

c_byte_off_t          castle_ext_fs_summary_get    (c_ext_fs_t *ext_fs);

struct castle_cache_block;

struct castle_object_replace {
    uint64_t    value_len; // total value length

    void        (*complete)        (struct castle_object_replace *op,
                                    int                           err);
    void        (*replace_continue)(struct castle_object_replace *op);
    uint32_t    (*data_length_get) (struct castle_object_replace *op);
    void        (*data_copy)       (struct castle_object_replace *op, 
                                    void                         *buffer, 
                                    uint32_t                      str_length,
                                    int                           partial);

    struct castle_component_tree *ct;
    struct castle_cache_block *data_c2b;
    uint64_t    data_c2b_offset;
    uint64_t    data_length;
};

struct castle_object_get {
    struct castle_component_tree *ct;
    struct castle_cache_block *data_c2b;
    uint64_t    data_c2b_length;
    uint64_t    data_length;
    int         first;
    
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

extern int low_disk_space;

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
        printk("User asked for fault\n");                       \
        BUG();                                                  \
    }

#define INJECT_FAULT                FAULT(FAULT_CODE)

extern c_fault_t castle_fault;

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
#endif /* __CASTLE_H__ */
