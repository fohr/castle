#include <linux/module.h>
#include <linux/workqueue.h>
#include <linux/sched.h>
#include <linux/fs.h>

#include "castle_public.h"
#include "castle.h"
#include "castle_cache.h"
#include "castle_freespace.h"

//#define DEBUG
#ifndef DEBUG
#define debug(_f, ...)  ((void)0)
#else
#define debug(_f, _a...)  (printk("%s:%.4d: " _f, __FILE__, __LINE__ , ##_a))
#endif

int castle_double_array_init(void)
{
    printk("========= Double Array init ==========\n");
    return 0;
}

void castle_double_array_fini(void)
{
    printk("========= Double Array fini ==========\n");
}
