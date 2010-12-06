#include <linux/sched.h>
#include <linux/list.h>
#include <asm/tlbflush.h>
#include "castle.h"
#include "castle_debug.h"
#include "castle_utils.h"
#include "castle_vmap.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)           ((void)0)
#else
#define debug(_f, _a...)         (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

#define CASTLE_VMAP_FREELIST_INITIAL	2	    /* Iniial number of per-bucket freelist slots */
#define CASTLE_VMAP_FREELIST_MULTI		2	    /* Freelist grow multiplier */

#define CASTLE_SLOT_INVALID 			0xFAFAFAFA

#define SLOT_SIZE(idx)                 (1 << idx) /* Convert slot (order no) to slot size */

#define order_base_2(n) ilog2(roundup_pow_of_two(n))

/* One struct per freelist, multiple freelists per bucket */
typedef struct {
	struct list_head	list;				    /* List of freelists for this bucket */
	uint32_t			*freelist;			    /* The freelist */
	void				*vstart;			    /* Start vaddr */
	void				*vend;				    /* End vaddr */
	int					nr_slots;			    /* No of slots in this freelist */
	int					slots_free;			    /* No of free slots in this freelist */
} castle_vmap_freelist_t;

/* This is the bucket of linked lists of freelists. Array is oversized,
so that we can index by allocation order number, e.g. index 8 = size 256 (2^8) */
struct list_head                    castle_vmap_fast_maps[CASTLE_VMAP_MAX_ORDER+1];

struct semaphore                    castle_vmap_lock[CASTLE_VMAP_MAX_ORDER+1];

static castle_vmap_freelist_t       *castle_vmap_freelist_init(int slot_size, int slots);
static void                         castle_vmap_freelist_delete(castle_vmap_freelist_t
                                                                *castle_vmap_freelist);
static void                         castle_vmap_freelist_add(castle_vmap_freelist_t
                                                             *castle_vmap_freelist, uint32_t id);
static uint32_t                     castle_vmap_freelist_get(castle_vmap_freelist_t
                                                             *castle_vmap_freelist);
static castle_vmap_freelist_t       *castle_vmap_freelist_grow(int freelist_bucket_idx);

int castle_vmap_fast_map_init(void)
{
	int		i, freelist_bucket_idx;


	/* The fast vmap unit sizes are 2^1 through 2^8 */
	for (freelist_bucket_idx=1; freelist_bucket_idx<=CASTLE_VMAP_MAX_ORDER; freelist_bucket_idx++)
	{
		castle_vmap_freelist_t * castle_vmap_freelist;

		castle_vmap_freelist = castle_vmap_freelist_init(SLOT_SIZE(freelist_bucket_idx),
                                                         CASTLE_VMAP_FREELIST_INITIAL);

		if (!castle_vmap_freelist)
		{
	        debug("castle_vmap_fast_map_init freelist vmalloc/vmap failure\n");
			/* Before we error out, delete the freelists sucessfully allocated so far, if any */
			for (i=1; i<freelist_bucket_idx; i++)
				castle_vmap_freelist_delete(list_first_entry(&castle_vmap_fast_maps[i],
                                                             castle_vmap_freelist_t, list));
			return -ENOMEM;
		}

		/* Put at the head of the bucket for this size mapper */
		INIT_LIST_HEAD(&castle_vmap_fast_maps[freelist_bucket_idx]);
		list_add(&castle_vmap_freelist->list, &(castle_vmap_fast_maps[freelist_bucket_idx]));

        /* Init the mutex for this bucket */
        init_MUTEX(&castle_vmap_lock[freelist_bucket_idx]);
	}

	return EXIT_SUCCESS;
}

void castle_vmap_fast_map_fini(void)
{
	int		                freelist_bucket_idx;
	castle_vmap_freelist_t  *castle_vmap_freelist;

	/* Index through each of the freelist buckets. For each bucket, delete the list of freelists */
	for (freelist_bucket_idx=1; freelist_bucket_idx<=CASTLE_VMAP_MAX_ORDER; freelist_bucket_idx++)
    {
        castle_vmap_freelist = list_first_entry(&castle_vmap_fast_maps[freelist_bucket_idx],
                                          castle_vmap_freelist_t, list);
        BUG_ON(!(list_is_singular(&castle_vmap_fast_maps[freelist_bucket_idx])));
		castle_vmap_freelist_delete(castle_vmap_freelist);
		castle_free(castle_vmap_freelist);
    }
}

static castle_vmap_freelist_t *castle_vmap_freelist_init(int slot_size, int slots)
{
	int				        nr_vmap_array_pages;
	struct page		        **pgs_array;
	struct page		        *dummy_page;
	castle_vmap_freelist_t  *castle_vmap_freelist;
	int i;

/* replace vmalloc with kmalloc for small structures */
	castle_vmap_freelist = castle_malloc(sizeof(castle_vmap_freelist_t), GFP_KERNEL);

	if (!castle_vmap_freelist)
		goto errout_1;

	/* Each array is sized to include 'slots' entries, plus a canary page between
	   each entry. For n entries of size p this is (n * p) + n - 1 pages */
	nr_vmap_array_pages = (slots * slot_size + slots - 1);
	pgs_array = castle_vmalloc(nr_vmap_array_pages * sizeof(struct page *));

	if(!pgs_array)
		goto errout_2;

	/* Freelist contains one slot per mapping, plus one extra as an end-of-freelist marker */
	castle_vmap_freelist->freelist = castle_vmalloc((slots + 1) * sizeof(uint32_t)); 

	if(!castle_vmap_freelist->freelist)
		goto errout_3;

	memset(castle_vmap_freelist->freelist, 0xFA, (slots + 1) * sizeof(uint32_t));

    castle_vmap_freelist->slots_free = 0;

	/* Populate the pages in pgs_array. This can be any arbitrary page - they are only used to allow
       vmap() to create us a vm area, and we subsequently unmap them all anyway. */
	dummy_page = alloc_page(GFP_KERNEL);
	if (!dummy_page)
		goto errout_4;
	for (i=0; i<nr_vmap_array_pages; i++)
		pgs_array[i] = dummy_page;

	castle_vmap_freelist->vstart = vmap(pgs_array, nr_vmap_array_pages,
					VM_READ|VM_WRITE, PAGE_KERNEL);

	if (!castle_vmap_freelist->vstart)
		goto errout_5;

	castle_vmap_freelist->vend = castle_vmap_freelist->vstart + nr_vmap_array_pages * PAGE_SIZE;
	castle_vmap_freelist->nr_slots = slots;

    /* This gives as an area in virtual memory in which we'll keep mapping multi-page objects. In
       order for this to work we need to unmap all the pages, but trick the kernel vmalloc code into
       not deallocating the vm_area_struct describing our virtual memory region. */
	castle_unmap_vm_area(castle_vmap_freelist->vstart, nr_vmap_array_pages);

	/* Init the actual freelist. This needs to contain ids which will always put us within the vmap
       area created above. */
	for(i=0; i<slots; i++)
		castle_vmap_freelist_add(castle_vmap_freelist, i);

	castle_vfree(pgs_array);

    __free_page(dummy_page);

	return castle_vmap_freelist;

errout_5:
	__free_page(dummy_page);
errout_4:
	castle_vfree(castle_vmap_freelist->freelist);
errout_3:
	castle_vfree(pgs_array);
errout_2:
	castle_free(castle_vmap_freelist);
errout_1:
	return NULL;
}

static void castle_vmap_freelist_delete(castle_vmap_freelist_t *castle_vmap_freelist)
{
#ifdef CASTLE_DEBUG
{
	/* At this point there should be nothing mapped in the fast vmap areas for this freelist. 
	   When in debug mode, verify that the freelist contains the correct number of items */
    int i = 0;
    while(castle_vmap_freelist->freelist[0] < castle_vmap_freelist->nr_slots)
    {
        castle_vmap_freelist_get(castle_vmap_freelist);
        i++;
    }
    BUG_ON(i != castle_vmap_freelist->nr_slots);
}
#endif 
	castle_vfree(castle_vmap_freelist->freelist);
	/* Let vmalloc.c destroy vm_area_struct by vmunmping it. */
	vunmap(castle_vmap_freelist->vstart);
	BUG_ON(list_empty(&castle_vmap_freelist->list));
}

static void castle_vmap_freelist_add(castle_vmap_freelist_t *castle_vmap_freelist, uint32_t id)
{
    BUG_ON(castle_vmap_freelist->freelist[id+1] != CASTLE_SLOT_INVALID);
    castle_vmap_freelist->freelist[id+1] = castle_vmap_freelist->freelist[0]; 
    castle_vmap_freelist->freelist[0]    = id; 
    castle_vmap_freelist->slots_free++;
}

/* Should be called with the vmap lock held */
static uint32_t castle_vmap_freelist_get(castle_vmap_freelist_t *castle_vmap_freelist)
{
	uint32_t id;

    id = castle_vmap_freelist->freelist[0];
	if (id >= castle_vmap_freelist->nr_slots) {
        /* Last slot has been used. Return CASTLE_SLOT_INVALID. Caller will grow freelist and retry */
        BUG_ON(id != CASTLE_SLOT_INVALID);
		goto out;
	}

    castle_vmap_freelist->freelist[0] = castle_vmap_freelist->freelist[id+1]; 
    /* Invalidate the slot we've just allocated, so that we can test for double frees */ 
    castle_vmap_freelist->freelist[id+1] = CASTLE_SLOT_INVALID;
    castle_vmap_freelist->slots_free--;

out:
	return id;
}

/* This used to require the vmap lock to be held. Now locking is done internally. Caller should
   lock the pages, though. */
void *castle_vmap_fast_map(struct page **pgs, int nr_pages)
{
    uint32_t                vmap_slot;
    void                    *vaddr;
	int                     freelist_bucket_idx=0;
	castle_vmap_freelist_t  *castle_vmap_freelist;

    freelist_bucket_idx = order_base_2(nr_pages);

    down(&castle_vmap_lock[freelist_bucket_idx]);

	/* We always map from the freelist at the head of the bucket */
	castle_vmap_freelist = list_first_entry(&castle_vmap_fast_maps[freelist_bucket_idx],
							castle_vmap_freelist_t, list);
    vmap_slot = castle_vmap_freelist_get(castle_vmap_freelist);
	if (vmap_slot == CASTLE_SLOT_INVALID)
	{
		if ((castle_vmap_freelist = castle_vmap_freelist_grow(freelist_bucket_idx)))
		{
    		vmap_slot = castle_vmap_freelist_get(castle_vmap_freelist);
			BUG_ON(vmap_slot == CASTLE_SLOT_INVALID);
		} else
            BUG();
	}
 
    vaddr = castle_vmap_freelist->vstart + vmap_slot * PAGE_SIZE * (SLOT_SIZE(freelist_bucket_idx)+1);
#ifdef CASTLE_DEBUG    
    BUG_ON((unsigned long)vaddr <  (unsigned long)castle_vmap_freelist->vstart);
    BUG_ON((unsigned long)vaddr >= (unsigned long)castle_vmap_freelist->vend);
#endif
    if(castle_map_vm_area(vaddr, pgs, nr_pages, PAGE_KERNEL))
    {
        debug("ERROR: failed to vmap!\n");
        castle_vmap_freelist_add(castle_vmap_freelist, vmap_slot);
        vaddr = NULL;
    }
    up(&castle_vmap_lock[freelist_bucket_idx]);
    return vaddr;
}

void castle_vmap_fast_unmap(void *vaddr, int nr_pages)
{
	castle_vmap_freelist_t  *castle_vmap_freelist;
	int                     freelist_bucket_idx=0;
    uint32_t                vmap_slot;
	struct list_head        *pos;

    freelist_bucket_idx = order_base_2(nr_pages);

    down(&castle_vmap_lock[freelist_bucket_idx]);

	/* We could be unmapping from any freelist in the bucket */
	list_for_each(pos, &castle_vmap_fast_maps[freelist_bucket_idx])
	{
		castle_vmap_freelist = list_entry(pos, castle_vmap_freelist_t, list);
		/* Is it in this freelist? */
		if ((vaddr >= castle_vmap_freelist->vstart) && (vaddr < castle_vmap_freelist->vend))
		{
    		vmap_slot = (vaddr - castle_vmap_freelist->vstart) /
                        ((SLOT_SIZE(freelist_bucket_idx)+1) * PAGE_SIZE);
    		debug("Releasing fast vmap slot: %d\n", vmap_slot);
    		castle_vmap_freelist_add(castle_vmap_freelist, vmap_slot);

            /* If the add made this freelist completely free, and this freelist is not at the head
               of the bucket (i.e. not active for gets, then delete this freelist. */
            if ((castle_vmap_freelist->slots_free == castle_vmap_freelist->nr_slots) &&
                (castle_vmap_freelist != list_first_entry(
                    &castle_vmap_fast_maps[freelist_bucket_idx], castle_vmap_freelist_t, list)))
            {
                list_del(pos);
                castle_vmap_freelist_delete(castle_vmap_freelist);
                castle_free(castle_vmap_freelist);
            }
			castle_unmap_vm_area(vaddr, nr_pages);

            up(&castle_vmap_lock[freelist_bucket_idx]);

			return;
		}
	}
	debug("Unmap: could not find freelist\n");
	BUG();
}

static castle_vmap_freelist_t *castle_vmap_freelist_grow(int freelist_bucket_idx)
{
	castle_vmap_freelist_t	*castle_vmap_freelist, *new;
	int						cur_nr_slots;

    BUG_ON(down_trylock(&castle_vmap_lock[freelist_bucket_idx]) == 0);

    /* TBD macro to replace 'get first entry in bucket' */
	castle_vmap_freelist = list_first_entry(&castle_vmap_fast_maps[freelist_bucket_idx],
							castle_vmap_freelist_t, list);

	cur_nr_slots = castle_vmap_freelist->nr_slots;

	debug("Adding new freelist of %d slots for bucket size %d\n",
           castle_vmap_freelist->nr_slots * CASTLE_VMAP_FREELIST_MULTI, SLOT_SIZE(freelist_bucket_idx));
	new = castle_vmap_freelist_init(SLOT_SIZE(freelist_bucket_idx),
                                    castle_vmap_freelist->nr_slots * CASTLE_VMAP_FREELIST_MULTI);

	if (!new)
		return NULL;

	list_add(&new->list, &(castle_vmap_fast_maps[freelist_bucket_idx]));

	return new;
}
