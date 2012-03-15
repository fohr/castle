#include "castle.h"
#include "castle_utils.h"

/**********************************************************************************************/
/* Block mapper btree (mtree) definitions */

#define MTREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define MTREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define MTREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define MTREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)))

#define MTREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMBSTONE(*(_slot))
#define MTREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define MTREE_ENTRY_IS_COUNTER_SET(_slot)   CVT_COUNTER_SET(*(_slot))
#define MTREE_ENTRY_IS_COUNTER_ADD(_slot)   CVT_COUNTER_ADD(*(_slot))
#define MTREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define MTREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define MTREE_ENTRY_IS_ONDISK(_slot)        CVT_ON_DISK(*(_slot))
#define MTREE_INVAL_BLK          ((block_t)-1)
#define MTREE_MAX_BLK            ((block_t)-2)
#define MTREE_BLK_INVAL(_blk)    ((_blk) == MTREE_INVAL_BLK)

struct castle_mtree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t     type;
    /*          1 */ uint8_t     _pad[3];
    /*          4 */ block_t     block;
    /*          8 */ c_ver_t     version;
    /*         12 */ uint32_t    val_len;
    /*         16 */ c_ext_pos_t cep;
    /*         32 */
} PACKED;

#define MTREE_MAX_ENTRIES(_size) (((_size) * C_BLK_SIZE - sizeof(struct castle_btree_node)) \
                                  / sizeof(struct castle_mtree_entry))
#define MTREE_NODE_ENTRIES       MTREE_MAX_ENTRIES(MTREE_NODE_SIZE)

static size_t castle_mtree_max_entries(size_t size)
{
    return MTREE_MAX_ENTRIES(size);
}

static size_t castle_mtree_min_size(size_t entries)
{
    castle_printk(LOG_ERROR, "%s::not implemented!\n", __FUNCTION__);
    BUG();
}

static int castle_mtree_need_split(struct castle_btree_node *node, int ver_or_key_split)
{
    switch(ver_or_key_split)
    {
        case 0:
            return ((BTREE_NODE_IS_LEAF(node) &&  (node->used == MTREE_NODE_ENTRIES)) ||
                    (!BTREE_NODE_IS_LEAF(node) && (MTREE_NODE_ENTRIES - node->used < 2)));
        case 1:
            return (node->used > 2 * MTREE_NODE_ENTRIES / 3);
        default:
            BUG();
    }

    return -1;
}

static int castle_mtree_mid_entry(struct castle_btree_node *node)
{
    return (node->used / 2);
}

static int castle_mtree_key_compare(const void *key1, const void *key2)
{
    block_t blk1 = (block_t)(unsigned long)key1;
    block_t blk2 = (block_t)(unsigned long)key2;

    if(unlikely(MTREE_BLK_INVAL(blk1) && MTREE_BLK_INVAL(blk2)))
        return 0;

    if(unlikely(MTREE_BLK_INVAL(blk1)))
        return -1;

    if(unlikely(MTREE_BLK_INVAL(blk2)))
        return 1;

    if(blk1 < blk2)
        return -1;

    if(blk1 > blk2)
        return 1;

    return 0;
}

static size_t castle_mtree_key_size(const void *key)
{
    return sizeof(unsigned long);
}

static void *castle_mtree_key_copy(const void *src, void *dst, size_t *dst_len)
{
    /* No need to do anything in mtree keys, because they are ints (cast to void *). */
    return (void *) src;
}

static void *castle_mtree_key_next(const void *src, void *dst, size_t *dst_len)
{
    block_t blk = (block_t)(unsigned long)src;

    /* No successor to invalid block */
    if(MTREE_BLK_INVAL(blk))
        return (void *)(unsigned long)MTREE_INVAL_BLK;

    /* MTREE_INVAL_BLK is the successor of MTREE_MAX_BLK, conveniently */
    return (void *)(unsigned long)(blk+1);
}

static void castle_mtree_key_dealloc(void *key)
{
    /* No need to do anything in mtree keys, because they are ints (cast to void *). */
}

static int castle_mtree_key_nr_dims(const void *key)
{
    BUG();
}

static void *castle_mtree_key_strip(const void *src, void *dst, size_t *dst_len, int nr_dims)
{
    BUG();
}

static uint32_t castle_mtree_key_hash(const void *key, c_btree_hash_enum_t type, uint32_t seed)
{
    BUG();
}

static int castle_mtree_entry_get(struct castle_btree_node *node,
                                  int                       idx,
                                  void                    **key_p,
                                  c_ver_t                  *version_p,
                                  c_val_tup_t              *cvt_p)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)(unsigned long)entry->block;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        *cvt_p = convert_to_cvt(entry->type, entry->val_len, entry->cep, NULL, 0);
        BUG_ON(!CVT_MEDIUM_OBJECT(*cvt_p) && !CVT_NODE(*cvt_p));
    }

    return 0;
}

static void castle_mtree_entry_add(struct castle_btree_node *node,
                                   int                       idx,
                                   void                     *key,
                                   c_ver_t                   version,
                                   c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) >
                                                MTREE_NODE_SIZE * C_BLK_SIZE);
    BUG_ON(BTREE_NODE_IS_LEAF(node) && CVT_NODE(cvt));

    /* Make space for the new entry, no-op if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    BUG_ON(!CVT_MEDIUM_OBJECT(cvt) && !CVT_NODE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}

static void castle_mtree_entry_replace(struct castle_btree_node *node,
                                       int                       idx,
                                       void                     *key,
                                       c_ver_t                   version,
                                       c_val_tup_t               cvt)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(BTREE_NODE_IS_LEAF(node) && CVT_NODE(cvt));

    entry->block   = (block_t)(unsigned long)key;
    entry->version = version;
    BUG_ON(!CVT_MEDIUM_OBJECT(cvt) && !CVT_NODE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;
}

static void castle_mtree_entry_disable(struct castle_btree_node *node,
                                       int                       idx)
{
    /* This does nothing, which means that we cannot merge MTrees,
       that's fine ATM */
}

static void castle_mtree_entries_drop(struct castle_btree_node *node,
                                      int                       idx_start,
                                      int                       idx_end)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_mtree_entry *entry_start = entries + idx_start;
    struct castle_mtree_entry *entry_end   = entries + idx_end;

    BUG_ON(idx_start < 0 || idx_start > node->used);
    BUG_ON(idx_end   < 0 || idx_end   > node->used);
    BUG_ON(idx_start > idx_end);

    /* Move the node entries forward */
    memmove(entry_start,
            entry_end + 1,
            sizeof(*entry_start) * (node->used - idx_end - 1));
    /* Decrement the node used count */
    node->used -= (idx_end - idx_start + 1);
}

#ifdef CASTLE_DEBUG
static void castle_mtree_node_validate(struct castle_btree_node *node)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->used     > MTREE_NODE_ENTRIES) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        castle_printk(LOG_ERROR, "Invalid mtree node used=%d and/or node version=%d\n",
               node->used, node->version);
        BUG();
    }

    for(i=0; i < node->used; i++)
    {
        struct castle_mtree_entry *entry = entries + i;
        /* Fail if node IS_LEAF doesn't match with the slot. ! needed
           to guarantee canonical value for boolean true */
        BUG_ON(!(BTREE_NODE_IS_LEAF(node)) != !(MTREE_ENTRY_IS_ANY_LEAF(entry)));
    }
}
#endif

static void castle_mtree_node_print(struct castle_btree_node *node)
{
    struct castle_mtree_entry *entries =
                (struct castle_mtree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    castle_printk(LOG_DEBUG, "Node: used=%d, version=%d, flags=%d\n",
                  node->used, node->version, node->flags);
    for(i=0; i<node->used; i++)
        castle_printk(LOG_DEBUG, "[%d] (0x%x, 0x%x) -> "cep_fmt_str_nl,
            i,
            entries[i].block,
            entries[i].version,
            cep2str(entries[i].cep));
    castle_printk(LOG_DEBUG, "\n");
}


struct castle_btree_type castle_mtree = {
    .magic          = MTREE_TYPE,
    .min_key        = (void *)0,
    .max_key        = (void *)MTREE_MAX_BLK,
    .inv_key        = (void *)MTREE_INVAL_BLK,
    .max_entries    = castle_mtree_max_entries,
    .min_size       = castle_mtree_min_size,
    .need_split     = castle_mtree_need_split,
    .mid_entry      = castle_mtree_mid_entry,
    .key_compare    = castle_mtree_key_compare,
    .key_size       = castle_mtree_key_size,
    .key_copy       = castle_mtree_key_copy,
    .key_next       = castle_mtree_key_next,
    .key_dealloc    = castle_mtree_key_dealloc,
    .nr_dims        = castle_mtree_key_nr_dims,
    .key_strip      = castle_mtree_key_strip,
    .key_hash       = castle_mtree_key_hash,
    .entry_get      = castle_mtree_entry_get,
    .entry_add      = castle_mtree_entry_add,
    .entry_replace  = castle_mtree_entry_replace,
    .entry_disable  = castle_mtree_entry_disable,
    .entries_drop   = castle_mtree_entries_drop,
    .node_print     = castle_mtree_node_print,
#ifdef CASTLE_DEBUG
    .node_validate  = castle_mtree_node_validate,
#endif
};
