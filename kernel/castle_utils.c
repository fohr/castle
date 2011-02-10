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

void vl_okey_to_buf(c_vl_okey_t *key, char *buf)
{
    int i, j;

    *buf++ = '|';
    for(i=0; i<key->nr_dims; i++)
    {
        for(j=0; j<key->dims[i]->length; j++)
        {
            sprintf(buf, "%.2x", key->dims[i]->key[j]);
            buf += 2;
        }
        *buf++ = '|';
    }
    *buf++ = '\0';
}

void vl_okey_print(c_vl_okey_t *key)
{
#define NR_BYTES_PRINT  15
    int i, j;
    char key_str[2*NR_BYTES_PRINT+1];

    printk("# key dimensions: %d\n", key->nr_dims);
    for(i=0; i<key->nr_dims; i++)
    {
        for(j=0; j<key->dims[i]->length && j<NR_BYTES_PRINT; j++)
            sprintf(key_str + 2*j, "%.2x", key->dims[i]->key[j]);
        printk(" dim[%.2d], len=%.3d, first %d bytes: %s\n", 
            i, 
            key->dims[i]->length, 
            NR_BYTES_PRINT,
            key->dims[i]->length == 0 ? "" : key_str);
    }
}

EXPORT_SYMBOL(vl_okey_print);

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
    castle_object_okey_free(okey);
}

/**
 * Copies a string out of the userspace, performing checks to verify that string
 * isn't too long or malformed.
 *
 * @param from    Userspace string pointer
 * @param len     String length
 * @param max_len Maximum length allowed
 * @param to      Pointer to the return char pointer
 */
int castle_from_user_copy(const char __user *from, int len, int max_len, char **to)
{
    char *out_str;
    int ret;

    ret = 0;
    /* Check that the string isn't too long. */
    if(len > max_len)
        return -E2BIG;
            
    /* Allocate memory for the string. */ 
    out_str = castle_malloc(len, GFP_KERNEL);
    if(!out_str)
        return -ENOMEM;

    /* Copy it from userspace. */
    if(copy_from_user(out_str, from, len)) 
    {
        ret = -EFAULT; 
        goto err_out;
    }
    
    /* Check that the string finishes with '\0'. */
    if (out_str[len-1] != '\0')
    {
        ret = -EINVAL;
        goto err_out;
    }

    /* Succeeded, returning. */
    *to = out_str;
    return 0;

err_out:
    /* Non-zero return code should have been set. */
    BUG_ON(ret == 0);
    castle_free(out_str);
    return ret;
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

/* Murmur hash */

#define _rotl64(n,X) ( ( ( X ) << n ) | ( ( X ) >> ( 64 - n ) ) )

//----------
// Block mix - combine the key bits with the hash bits and scramble everything

#define bmix64(h1, h2, k1, k2, c1, c2)  \
({                                      \
    k1 *= c1;                           \
    k1  = _rotl64(k1,23);               \
    k1 *= c2;                           \
    h1 ^= k1;                           \
    h1 += h2;                           \
                                        \
    h2 = _rotl64(h2,41);                \
                                        \
    k2 *= c2;                           \
    k2  = _rotl64(k2,23);               \
    k2 *= c1;                           \
    h2 ^= k2;                           \
    h2 += h1;                           \
                                        \
    h1 = h1*3+0x52dce729;               \
    h2 = h2*3+0x38495ab5;               \
                                        \
    c1 = c1*5+0x7b7d159c;               \
    c2 = c2*5+0x6bce6396;               \
})

//----------
// Finalization mix - avalanches all bits to within 0.05% bias

static inline uint64_t fmix64(uint64_t k)
{
    k ^= k >> 33;
    k *= 0xff51afd7ed558ccd;
    k ^= k >> 33;
    k *= 0xc4ceb9fe1a85ec53;
    k ^= k >> 33;

    return k;
}

static void MurmurHash3_x64_128(const void *key, const int len, const uint32_t seed, void *out)
{
    const uint8_t * data = (const uint8_t*)key;
    const int nblocks = len / 16;
    const uint8_t *tail;
    uint64_t k1, k2;
    int i;

    uint64_t h1 = 0x9368e53c2f6af274 ^ seed;
    uint64_t h2 = 0x586dcd208f7cd3fd ^ seed;

    uint64_t c1 = 0x87c37b91114253d5;
    uint64_t c2 = 0x4cf5ad432745937f;

    //----------
    // body

    const uint64_t * blocks = (const uint64_t *)(data);

    for(i = 0; i < nblocks; i++)
    {
        uint64_t k1 = blocks[i*2 + 0];
        uint64_t k2 = blocks[i*2 + 1];

        bmix64(h1, h2, k1, k2, c1, c2);
    }

    //----------
    // tail

    tail = (const uint8_t*)(data + nblocks*16);

    k1 = 0;
    k2 = 0;

    switch(len & 15)
    {
    case 15: k2 ^= ((uint64_t) tail[14]) << 48;
    case 14: k2 ^= ((uint64_t) tail[13]) << 40;
    case 13: k2 ^= ((uint64_t) tail[12]) << 32;
    case 12: k2 ^= ((uint64_t) tail[11]) << 24;
    case 11: k2 ^= ((uint64_t) tail[10]) << 16;
    case 10: k2 ^= ((uint64_t) tail[ 9]) << 8;
    case  9: k2 ^= ((uint64_t) tail[ 8]) << 0;

    case  8: k1 ^= ((uint64_t) tail[ 7]) << 56;
    case  7: k1 ^= ((uint64_t) tail[ 6]) << 48;
    case  6: k1 ^= ((uint64_t) tail[ 5]) << 40;
    case  5: k1 ^= ((uint64_t) tail[ 4]) << 32;
    case  4: k1 ^= ((uint64_t) tail[ 3]) << 24;
    case  3: k1 ^= ((uint64_t) tail[ 2]) << 16;
    case  2: k1 ^= ((uint64_t) tail[ 1]) << 8;
    case  1: k1 ^= ((uint64_t) tail[ 0]) << 0;
             bmix64(h1,h2,k1,k2,c1,c2);
    };

    //----------
    // finalization

    h2 ^= len;

    h1 += h2;
    h2 += h1;

    h1 = fmix64(h1);
    h2 = fmix64(h2);

    h1 += h2;
    h2 += h1;

    ((uint64_t*)out)[0] = h1;
    ((uint64_t*)out)[1] = h2;
}

//-----------------------------------------------------------------------------
// If we need a smaller hash value, it's faster to just use a portion of the
// 128-bit hash

uint32_t murmur_hash_32(const void *key, int len, uint32_t seed)
{
    uint32_t temp[4];

    MurmurHash3_x64_128(key, len, seed, temp);

    return temp[0];
}

uint64_t murmur_hash_64(const void *key, int len, uint32_t seed)
{
    uint64_t temp[2];

    MurmurHash3_x64_128(key, len, seed, temp);

    return temp[0];
}
