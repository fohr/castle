#include <linux/completion.h>
#include <linux/kobject.h>
#include <linux/bio.h>

#include "castle.h"

struct castle_block_io
{
    struct completion io_completed;
    int err;
};

static void castle_block_read_done(struct bio *bio, int err)
{
    struct castle_block_io *cbio = (struct castle_block_io *)bio->bi_private;

    cbio->err = err;
    complete(&cbio->io_completed);
}


int castle_block_read(struct castle_slave *slave, 
                      sector_t block,
                      struct page *page)
{
    struct bio *bio = bio_alloc(GFP_KERNEL, 1);
    struct castle_block_io cbio;

    /* Early checks */
    BUG_ON(slave->bdev->bd_block_size != PAGE_SIZE);
    if(!bio) return -ENOMEM;

    /* Construct bio */    
    bio->bi_bdev    = slave->bdev; 
    bio->bi_sector  = block * 8;   /* 512B sectors on 4K blocks */
    bio->bi_end_io  = castle_block_read_done;
    bio->bi_private = &cbio;
    BUG_ON(bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE);
    BUG_ON(!bio->bi_size);

    /* Construct the token */
    init_completion(&cbio.io_completed);
    cbio.err = 0;
    
    /* Submit */ 
    submit_bio(READ, bio);

    /* Wait till IO completes */
    wait_for_completion(&cbio.io_completed);

    return cbio.err;
}

int castle_sub_block_read(struct castle_slave *cs,
                          void *buffer, 
                          uint64_t offset,
                          uint16_t size)
{
    struct page *page = NULL;
    char *src;
    int err;
    
    if(!(page = alloc_page(GFP_KERNEL)))
        return -ENOMEM;
    
    err = castle_block_read(cs, offset >> PAGE_SHIFT, page);

    src = pfn_to_kaddr(page_to_pfn(page));
    src += (offset & ~PAGE_MASK);

    memcpy(buffer, src, size); 

    __free_page(page);
 
    return 0;
}
