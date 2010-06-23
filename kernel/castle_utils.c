#include <linux/list.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle.h"

struct castle_component_tree {
    tree_seq_t       seq;
    uint8_t          level;
    c_disk_blk_t     first_node;
    struct list_head list;
    c_mstore_key_t   mstore_key;
};


void inline  __list_swap(struct list_head *p,
                         struct list_head *t1,
                         struct list_head *t2,
                         struct list_head *n)
{
    p->next  = t2;
    t2->prev = p;
    t2->next = t1;
    t1->prev = t2;
    t1->next = n;
    n->prev  = t1;
}

void inline list_swap(struct list_head *t1, struct list_head *t2)
{
    __list_swap(t1->prev, t1, t2, t2->next);
}


/* Implements O(n^2) list sort using externally provided comparator */
void list_sort(struct list_head *list, 
               int (*compare)(struct list_head *l1, struct list_head *l2))
{
    struct list_head *t1, *t2;
    int length;
    int i, j;
         
    /* Length of the list */
    for(length=0, t1=list->next; t1 != list; length++, t1=t1->next);
    
    /* 0 & 1 long lists are already sorted */
    if(length <= 1)
        return;

    /* Bubble sort */
    for(i=0; i<length-1; i++)
    {
        t1 = list->next; 
        for(j=length; j>i+1; j--)
        {
            t2 = t1->next;
            /* Potentially swap */
            if(compare(t1, t2) > 0)
                /* t1 should remain unchanged (it's going to be moved forward) */
                list_swap(t1, t2);
            else
                t1 = t2; 
        }
    }
}

void skb_print(struct sk_buff *skb)
{
    uint8_t buffer[128];
    int i;

    BUG_ON(skb->len > 128);
    BUG_ON(skb_copy_bits(skb, 0, buffer, skb->len) < 0);
    printk("\nPacket length=%d\n", skb->len);
    for(i=0; i<skb->len; i++)
    {
        uint8_t byte = *(buffer + i);    
        if((byte >= 32) && (byte <= 126))
            printk(" [%d]=%d (%c)\n", i, byte, byte);
        else
            printk(" [%d]=%d\n", i, byte);
    }
    printk("\n");
}
