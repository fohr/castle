#include "castle.h"
#include "castle_utils.h"
#include "castle_btree_batree.h"

/**********************************************************************************************/
/* Fixed size byte array key btree (batree) definitions */

#define BATREE_ENTRY_IS_NODE(_slot)          CVT_NODE(*(_slot))
#define BATREE_ENTRY_IS_LEAF_VAL(_slot)      CVT_LEAF_VAL(*(_slot))
#define BATREE_ENTRY_IS_LEAF_PTR(_slot)      CVT_LEAF_PTR(*(_slot))
#define BATREE_ENTRY_IS_ANY_LEAF(_slot)      (CVT_LEAF_VAL(*(_slot)) || CVT_LEAF_PTR(*(_slot)))

#define BATREE_ENTRY_IS_TOMB_STONE(_slot)    CVT_TOMBSTONE(*(_slot))
#define BATREE_ENTRY_IS_INLINE(_slot)        CVT_INLINE(*(_slot))
#define BATREE_ENTRY_IS_COUNTER_SET(_slot)   CVT_COUNTER_SET(*(_slot))
#define BATREE_ENTRY_IS_COUNTER_ADD(_slot)   CVT_COUNTER_ADD(*(_slot))
#define BATREE_ENTRY_IS_LARGE_OBJECT(_slot)  CVT_LARGE_OBJECT(*(_slot))
#define BATREE_ENTRY_IS_MEDIUM_OBJECT(_slot) CVT_MEDIUM_OBJECT(*(_slot))
#define BATREE_ENTRY_IS_ONDISK(_slot)        CVT_ON_DISK(*(_slot))

#define BATREE_KEY_SIZE         128      /* In bytes */
typedef struct bakey {
    /* align:   1 */
    /* offset:  0 */ uint8_t _key[BATREE_KEY_SIZE];
    /*        128 */
} PACKED bakey_t;

static const bakey_t BATREE_INVAL_KEY = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0xFF}};
static const bakey_t BATREE_MIN_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-1)] = 0x00}};
static const bakey_t BATREE_MAX_KEY   = (bakey_t){._key = {[0 ... (BATREE_KEY_SIZE-2)] = 0xFF,
                                                           [      (BATREE_KEY_SIZE-1)] = 0xFE}};
#define BATREE_KEY_INVAL(_key)          ((_key) == &BATREE_INVAL_KEY)
#define BATREE_KEY_MIN(_key)            ((_key) == &BATREE_MIN_KEY)
#define BATREE_KEY_MAX(_key)            ((_key) == &BATREE_MAX_KEY)

struct castle_batree_entry {
    /* align:   8 */
    /* offset:  0 */ uint8_t      type;
    /*          1 */ uint8_t      _pad1[3];
    /*          4 */ bakey_t      key;
    /*        132 */ c_ver_t      version;
    /*        136 */ uint32_t     val_len;
    /*        140 */ uint8_t      _pad2[4];
    /*        144 */ c_ext_pos_t  cep;
    /*        160 */
} PACKED;

#define BATREE_NODE_SIZE     (20) /* In blocks */

const size_t BATREE_NODE_ENTRIES = (BATREE_NODE_SIZE * PAGE_SIZE - sizeof(struct castle_btree_node))
    / sizeof(struct castle_batree_entry);

static inline void castle_batree_key_print(bakey_t *key)
{
    int i;

    for(i=0; i<BATREE_KEY_SIZE; i++)
        castle_printk(LOG_DEBUG, "%.2x", key->_key[i]);
}

/**
 * Size of batree btree nodes equals BATREE_NODE_SIZE (20 pages).
 */
static uint16_t castle_batree_node_size(struct castle_component_tree *ct, uint8_t level)
{
    return BATREE_NODE_SIZE;
}

static int castle_batree_need_split(struct castle_btree_node *node, int ver_or_key_split)
{
    switch(ver_or_key_split)
    {
        case 0:
            return ((node->is_leaf &&  (node->used == BATREE_NODE_ENTRIES)) ||
                    (!node->is_leaf && (BATREE_NODE_ENTRIES - node->used < 2)));
        case 1:
            return (node->used > 2 * BATREE_NODE_ENTRIES / 3);
        default:
            BUG();
    }

    return -1;
}

static int castle_batree_key_compare(void *keyv1, void *keyv2)
{
    bakey_t *key1 = (bakey_t *)keyv1;
    bakey_t *key2 = (bakey_t *)keyv2;
    int ret;

    if(unlikely(BATREE_KEY_INVAL(key1) && BATREE_KEY_INVAL(key2)))
        return 0;

    if(unlikely(BATREE_KEY_INVAL(key1)))
        return -1;

    if(unlikely(BATREE_KEY_INVAL(key2)))
        return 1;

    ret = memcmp(key1, key2, sizeof(bakey_t));

    return ret;
}

static void* castle_batree_key_duplicate(void *keyv)
{
    bakey_t *key = (bakey_t *)keyv;
    bakey_t *new_key;

    if (BATREE_KEY_INVAL(key) || BATREE_KEY_MIN(key) || BATREE_KEY_MAX(key))
        return key;

    new_key = castle_malloc(sizeof(bakey_t), GFP_NOIO);
    BUG_ON(!new_key);
    memcpy(new_key, key, sizeof(bakey_t));

    return new_key;
}

static void* castle_batree_key_next(void *keyv)
{
    bakey_t *key = (bakey_t *)keyv;
    bakey_t *succ;
    int i;

    /* No successor to invalid block */
    if(BATREE_KEY_INVAL(key))
        return (void *)&BATREE_INVAL_KEY;

    /* Successor to max key is the invalid key (return the static copy). */
    if(castle_batree_key_compare((void *)&BATREE_MAX_KEY, key) == 0)
        return (void *)&BATREE_INVAL_KEY;

    /* Finally allocate and return the successor key */
    succ = castle_malloc(sizeof(bakey_t), GFP_NOIO);
    /* @TODO: Should this be handled properly? */
    BUG_ON(!succ);
    memcpy(succ, key, sizeof(bakey_t));
    for (i=sizeof(bakey_t)-1; i >= 0; i--)
        if((++succ->_key[i]) != 0)
            break;

    return succ;
}

static void castle_batree_key_dealloc(void *key)
{
    if (BATREE_KEY_INVAL(key) || BATREE_KEY_MIN(key) || BATREE_KEY_MAX(key))
        return;

    castle_kfree(key);
}

static uint32_t castle_batree_key_hash(void *key, uint32_t seed)
{
    BUG();
}

static int castle_batree_entry_get(struct castle_btree_node *node,
                                   int                       idx,
                                   void                    **key_p,
                                   c_ver_t                  *version_p,
                                   c_val_tup_t              *cvt_p)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);

    if(key_p)         *key_p         = (void *)&entry->key;
    if(version_p)     *version_p     = entry->version;
    if(cvt_p)
    {
        BUG_ON(!BATREE_ENTRY_IS_ONDISK(entry) && !BATREE_ENTRY_IS_NODE(entry));
        *cvt_p = convert_to_cvt(entry->type, entry->val_len, entry->cep, NULL);
    }

    return 0;
}

static void castle_batree_entry_add(struct castle_btree_node *node,
                                    int                       idx,
                                    void                     *key,
                                    c_ver_t                   version,
                                    c_val_tup_t               cvt)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx > node->used);
    BUG_ON(sizeof(*entry) * node->used + sizeof(struct castle_btree_node) >
                                                BATREE_NODE_SIZE * C_BLK_SIZE);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    /* Make space for the new entry, noop if we are adding one at the end
       of the node */
    memmove(entry + 1, entry, sizeof(*entry) * (node->used - idx));

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    BUG_ON(CVT_INVALID(cvt) || CVT_INLINE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;

    /* Increment the node used count */
    node->used++;
}

static void castle_batree_entry_replace(struct castle_btree_node *node,
                                        int                       idx,
                                        void                     *key,
                                        c_ver_t                   version,
                                        c_val_tup_t               cvt)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry = entries + idx;

    BUG_ON(idx < 0 || idx >= node->used);
    BUG_ON(!node->is_leaf && CVT_LEAF_PTR(cvt));
    BUG_ON(node->is_leaf && CVT_NODE(cvt));

    memcpy(&entry->key, key, sizeof(bakey_t));
    entry->version = version;
    BUG_ON(CVT_INVALID(cvt) || CVT_INLINE(cvt));
    entry->type    = cvt.type;
    entry->cep     = cvt.cep;
    entry->val_len = cvt.length;
}

static void castle_batree_entry_disable(struct castle_btree_node *node,
                                        int                       idx)
{
    /* This does nothing, which means that we cannot merge BATrees,
       that's fine ATM */
}

static void castle_batree_entries_drop(struct castle_btree_node *node,
                                       int                       idx_start,
                                       int                       idx_end)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    struct castle_batree_entry *entry_start = entries + idx_start;
    struct castle_batree_entry *entry_end   = entries + idx_end;

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
static void castle_batree_node_validate(struct castle_btree_node *node)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    int i;

    if((node->used     > BATREE_NODE_ENTRIES) ||
      ((node->used     == 0) && (node->version != 0)))
    {
        castle_printk(LOG_DEBUG, "Invalid batree node used=%d and/or node version=%d\n",
               node->used, node->version);
        BUG();
    }

    for(i=0; i < node->used; i++)
    {
        struct castle_batree_entry *entry = entries + i;
        /* Fail if node is_leaf doesn't match with the slot. ! needed
           to guarantee canonical value for boolean true */
        BUG_ON(!(node->is_leaf) != !(BATREE_ENTRY_IS_ANY_LEAF(entry)));
    }
}
#endif

static void castle_batree_node_print(struct castle_btree_node *node)
{
    struct castle_batree_entry *entries =
                (struct castle_batree_entry *) BTREE_NODE_PAYLOAD(node);
    int i, j;

    for(i=0; i<node->used; i++)
    {
        struct castle_batree_entry *entry = entries + i;

        castle_printk(LOG_DEBUG, "[%d] (", i);
        for(j=0; j<BATREE_KEY_SIZE; j++)
            castle_printk(LOG_DEBUG, "%.2x", entry->key._key[j]);
        castle_printk(LOG_DEBUG, ", 0x%x) -> "cep_fmt_str_nl,
            entries[i].version,
            cep2str(entries[i].cep));
    }
    castle_printk(LOG_DEBUG, "\n");
}


struct castle_btree_type castle_batree = {
    .magic          = BATREE_TYPE,
    .min_key        = (void *)&BATREE_MIN_KEY,
    .max_key        = (void *)&BATREE_MAX_KEY,
    .inv_key        = (void *)&BATREE_INVAL_KEY,
    .node_size      = castle_batree_node_size,
    .need_split     = castle_batree_need_split,
    .key_compare    = castle_batree_key_compare,
    .key_duplicate  = castle_batree_key_duplicate,
    .key_next       = castle_batree_key_next,
    .key_dealloc    = castle_batree_key_dealloc,
    .key_hash       = castle_batree_key_hash,
    .entry_get      = castle_batree_entry_get,
    .entry_add      = castle_batree_entry_add,
    .entry_replace  = castle_batree_entry_replace,
    .entry_disable  = castle_batree_entry_disable,
    .entries_drop   = castle_batree_entries_drop,
    .node_print     = castle_batree_node_print,
#ifdef CASTLE_DEBUG
    .node_validate  = castle_batree_node_validate,
#endif
};
