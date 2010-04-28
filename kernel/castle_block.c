#include <linux/completion.h>
#include <linux/kobject.h>
#include <linux/bio.h>
#include <linux/hardirq.h>

#include "castle_public.h"
#include "castle.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

struct castle_block_io
{
    void (* callback)(void *, int err);
    void *arg; 
    struct completion io_completed;
    int *ret;
};

static void castle_block_read_end(struct bio *bio, int err)
{
    struct castle_block_io *cbio = (struct castle_block_io *)bio->bi_private;

    if(!cbio->callback)
    {
        debug("      No callback in block_read_end. Ret=%d\n", err);
        /* If no callback was supplied, wakeup blocked execution */
        *(cbio->ret) = err;
        complete(&cbio->io_completed);
    } else
    {
        debug("      With callback in block_read_end. Ret=%d\n", err);
        cbio->callback(cbio->arg, err);
        debug("      FREEING CBIO\n");
        kfree(cbio);
    }
    /* TODO: Does this need to be done, or will bio get cleaned up by our caller? */
    debug("      NOT PUTTING BIO\n");
    //bio_put(bio);
}

int castle_block_read(struct castle_slave *slave, 
                      sector_t block,
                      struct page *page,
                      void (* callback)(void *, int),
                      void *arg)
{
    struct bio *bio = bio_alloc(GFP_KERNEL, 1);
    struct castle_block_io *cbio;

    /* Early checks */
    if(!bio) return -ENOMEM;

    cbio = kmalloc(sizeof(struct castle_block_io), GFP_KERNEL);
    if(!cbio) {
        /* This will destroy the bio */
        bio_put(bio); 
        return -ENOMEM;
    }

    /* Construct bio */    
    bio->bi_bdev    = slave->bdev; 
    bio->bi_sector  = block * 8;   /* 512B sectors on 4K blocks */
    bio->bi_end_io  = castle_block_read_end;
    bio->bi_private = cbio;
    BUG_ON(bio_add_page(bio, page, PAGE_SIZE, 0) < PAGE_SIZE);
    BUG_ON(!bio->bi_size);
    debug("     BIO for bdev=%p, sector=0x%lx.\n", bio->bi_bdev, bio->bi_sector);

    /* Construct completion struct */
    cbio->callback = callback;
    cbio->arg = arg; 

    /* We make blocking read if there is no callback */ 
    if(!callback)
    {
        int ret = 0;

        debug("     No callback to block_read. Blocking IO.\n");
        cbio->ret = &ret; 
        init_completion(&cbio->io_completed);
        /* Submit IO */
        submit_bio(READ, bio);
        /* Wait till IO completes */
        debug("     Waiting for completion.\n");
        wait_for_completion(&cbio->io_completed);
        debug("     Completion returned, ret=%d\n", ret);
        debug("     FREEING CBIO\n");
        kfree(cbio);
        return ret;
    } else
    {
        debug("     Callback provided. Nonblocking IO.\n");
        /* Just submit */ 
        submit_bio(READ, bio);
        debug("     Exiting from block_read with success.\n");
        return 0;
    }
}

struct castle_sub_block_io {
    void (* callback)(void *, int err);
    void *arg;
    struct page *page;
    void *buffer;
    uint64_t offset;
    uint16_t size;
};

void castle_sub_block_read_end(void *arg, int err)
{
    struct castle_sub_block_io *iop = arg;
    struct castle_sub_block_io io = *iop;
    char *src;

    /* Free the io structure (we've got a local copy) */
    debug("   FREEING SUB BLOCK IO STRUCT.\n");
    kfree(iop);

    /* Callback early if read failed */
    if(err) 
    {
        debug("   FREEING BUFFER PAGE.\n");
        __free_page(io.page);
        if(io.callback) 
        {
            debug("   Callback from sub_block_read, ret=%d.\n", err);
            io.callback(io.arg, err); 
        }
        return;
    }
    debug("   Copying data between buffers, dst=%p!\n", io.buffer);
    /* Read succeeded, copy data to the buffer */
    src = pfn_to_kaddr(page_to_pfn(io.page));
    src += (io.offset & ~PAGE_MASK);

    memcpy(io.buffer, src, io.size); 

    debug("   FREEING BUFFER PAGE.\n");
    __free_page(io.page);

    /* Callback */
    if(io.callback) 
    {
        debug("   Callback from sub_block_read, success.\n");
        io.callback(io.arg, 0);
    }
}

int castle_sub_block_read(struct castle_slave *cs,
                          void *buffer, 
                          uint64_t offset,
                          uint16_t size,
                          void (* callback)(void *, int ret),
                          void *arg)
{
    struct castle_sub_block_io *io;
    struct page *page;
    int err;
    
    io = kmalloc(sizeof(struct castle_sub_block_io), GFP_KERNEL);
    if(!io) return -ENOMEM;

    page = alloc_page(GFP_KERNEL);
    if(!page)
    {
        kfree(io);
        return -ENOMEM;
    }
    
    io->callback = callback;
    io->arg = arg;
    io->page = page;
    io->buffer = buffer;
    io->offset = offset;
    io->size = size;
    /* If no callback was given, we make a blocking read */
    if(!callback)
    {
        debug("  No callback to sub_block_read. Executing block_read without callback.\n");
        err = castle_block_read(cs, offset >> PAGE_SHIFT, page, NULL, NULL);
        debug("  Block_read returned with %d. Calling block_read_end() to cleanup.\n", err);
        castle_sub_block_read_end(io, err);
        debug("  Returning %d\n", err);
        return err;
    }
    else
    {
        debug("  Got callback, executing nonblocking sub block_read.\n");
        /* Non blocking IO */
        err = castle_block_read(cs, offset >> PAGE_SHIFT, page, castle_sub_block_read_end, io);
        debug("  Nonblocking read returned with %d\n", err);
        /* If read failed call the 'callback' manually */
        if(err) 
        {
            debug("  Calling sub_block_read_end manually, without callback.\n");
            io->callback = NULL;
            io->arg = NULL;
            castle_sub_block_read_end(io, err);
        }
        debug("  Returting with %d\n", err);
        return err;
    }
}


