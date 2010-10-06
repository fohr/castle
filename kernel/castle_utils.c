#include <linux/list.h>
#include <asm/tlbflush.h>
#include <linux/vmalloc.h>

#include "castle_public.h"
#include "castle_utils.h"
#include "castle_cache.h"
#include "castle_btree.h"
#include "castle_objects.h"
#include "castle.h"

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
    int i;
    uint8_t byte;

    printk("\nPacket length=%d\n", skb->len);
    for(i=0; i<skb->len; i++)
    {
        BUG_ON(skb_copy_bits(skb, i, &byte, 1) < 0);
        if((byte >= 32) && (byte <= 126))
            printk(" [%d]=%d (%c)\n", i, byte, byte);
        else
            printk(" [%d]=%d\n", i, byte);
    }
    printk("\n");
}

void vl_key_print(c_vl_key_t *vl_key)
{
    printk(" key len=%d: ", vl_key->length);
    print_hex_dump_bytes("", DUMP_PREFIX_NONE, vl_key->key, vl_key->length);
}

void vl_okey_print(c_vl_okey_t *key)
{
    int i, j;
#define NR_BYTES_PRINT  15

    printk("# key dimensions: %d, key array=%p\n", key->nr_dims, key);
    for(i=0; i<key->nr_dims; i++)
    {
        printk(" dim[%.2d], %p, length=%.3d, first %d bytes: ", i, key->dims[i], key->dims[i]->length, NR_BYTES_PRINT);
        for(j=0; j<NR_BYTES_PRINT && j<key->dims[i]->length; j++)
            printk("%.2x", key->dims[i]->key[j]);
        printk("\n");
    }
}

void vl_bkey_print(c_vl_bkey_t *key)
{
    c_vl_okey_t *okey;
    
    okey = castle_object_btree_key_convert(key);
    if(!okey)
    {
        printk("Couldn't convert btree key for printing.\n");
        return;
    }
    printk("Btree key, length=%d\n", key->length);
    vl_okey_print(okey);
    castle_object_key_free(okey);
}

/**********************************************************************************************
 * Utilities for vmapping/vunmapping pages. Assumes that virtual address to map/unmap is known.
 * Copied from RHEL mm/vmalloc.c.
 */

void pgd_clear_bad(pgd_t *pgd)
{
    pgd_ERROR(*pgd);
    pgd_clear(pgd);
}

void castle_unmap_vm_area(void *addr_p, int nr_pages)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = (unsigned long) addr_p;
	unsigned long end = addr + nr_pages * PAGE_SIZE; 

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	flush_cache_vunmap(addr, end);
	do {
		next = pgd_addr_end(addr, end);
		if (pgd_none_or_clear_bad(pgd))
			continue;
		vunmap_pud_range(pgd, addr, next);
	} while (pgd++, addr = next, addr != end);
	flush_tlb_kernel_range((unsigned long) addr_p, end);
}

int castle_map_vm_area(void *addr_p, struct page **pages, int nr_pages, pgprot_t prot)
{
	pgd_t *pgd;
	unsigned long next;
	unsigned long addr = (unsigned long) addr_p;
	unsigned long end = addr + nr_pages * PAGE_SIZE;
	int err;

	BUG_ON(addr >= end);
	pgd = pgd_offset_k(addr);
	do {
		next = pgd_addr_end(addr, end);
		err = vmap_pud_range(pgd, addr, next, prot, &pages);
		if (err)
			break;
	} while (pgd++, addr = next, addr != end);
	flush_cache_vmap((unsigned long) addr_p, end);
	return err;
}
