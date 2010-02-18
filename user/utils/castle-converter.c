#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <inttypes.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/mman.h>

#define PAGE_SIZE 4096

struct castle_disk_block {
    uint32_t disk;
    uint32_t block;
};
typedef struct castle_disk_block c_disk_blk_t;

struct castle_slave_superblock {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t uuid;
    uint32_t used;
    uint32_t size; /* In blocks */
};

struct castle_fs_superblock {
    uint32_t magic1;
    uint32_t magic2;
    uint32_t magic3;
    uint32_t salt;
    uint32_t peper;
    uint32_t fwd_tree_disk1;
    uint32_t fwd_tree_block1;
    uint32_t fwd_tree_disk2;
    uint32_t fwd_tree_block2;
    uint32_t rev_tree_disk1;
    uint32_t rev_tree_block1;
    uint32_t rev_tree_disk2;
    uint32_t rev_tree_block2;
};

struct castle_vtree_node_slot {
    uint32_t     version_nr;
    c_disk_blk_t cdb;
};

struct castle_vtree_leaf_slot {
    uint32_t     version_nr;
    uint32_t     parent;
    uint32_t     size;
    c_disk_blk_t cdb;
};

#define NODE_HEADER        0x180

#define VTREE_SLOT_LEAF       0x1
#define VTREE_SLOT_NODE       0x2
#define VTREE_SLOT_NODE_LAST  0x3
#define VTREE_SLOT_IS_NODE(_slot)       (((_slot)->type == VTREE_SLOT_NODE) || \
                                         ((_slot)->type == VTREE_SLOT_NODE_LAST))
#define VTREE_SLOT_IS_NODE_LAST(_slot)   ((_slot)->type == VTREE_SLOT_NODE_LAST)
#define VTREE_SLOT_IS_LEAF(_slot)        ((_slot)->type == VTREE_SLOT_LEAF) 

struct castle_vtree_slot {
    uint32_t type;
    union {
        struct castle_vtree_node_slot node;
        struct castle_vtree_leaf_slot leaf;
    };
};

#define VTREE_NODE_SLOTS  ((PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_vtree_slot))
struct castle_vtree_node {
    /* On disk representation of the node */
    uint32_t magic;
    uint32_t version; 
    uint32_t capacity;
    uint32_t used;
    uint8_t __pad[NODE_HEADER - 16];
    struct castle_vtree_slot slots[VTREE_NODE_SLOTS]; 
};

#define VTREE_LIST_SLOTS  ((PAGE_SIZE - NODE_HEADER)/sizeof(struct castle_vtree_leaf_slot))
struct castle_vtree_list_node {
    c_disk_blk_t next; /* 8 bytes */
    c_disk_blk_t prev; /* 8 bytes */
    uint8_t __pad[NODE_HEADER - 16];
    struct castle_vtree_leaf_slot slots[VTREE_LIST_SLOTS];
};

#define MAX_FILES         100
#define MAX_BTREE_NODES   5000
#define MAX_VERSIONS      1500000
int fds[MAX_FILES];
char *mmaps[MAX_FILES];
size_t mmaps_size[MAX_FILES];
struct castle_slave_superblock* cs_sbs[MAX_FILES];
struct castle_fs_superblock* fs_sbs[MAX_FILES];
c_disk_blk_t btree_nodes[MAX_BTREE_NODES];
int max_btree_node = 0;
struct castle_vtree_leaf_slot versions[MAX_VERSIONS];
int max_version = 0;
int max_files;

static uint32_t cs_uuid_get(int file)
{
    return cs_sbs[file]->uuid;
}

static void* get_block(c_disk_blk_t cdb)
{
    int i;
    /* Find the disk */
    for(i=0; i<max_files; i++)
        if(cs_uuid_get(i) == cdb.disk)
            return (void *)(mmaps[i] + cdb.block * PAGE_SIZE);

    printf("Could not find cdb=(0x%x, 0x%x)\n", cdb.disk, cdb.block);
    exit(-1);

    return NULL;
}

static void add_version(struct castle_vtree_leaf_slot *slot)
{
    if(max_version >= MAX_VERSIONS)
    {
        printf("Too many versions.\n");
        exit(-3);
    }
    memcpy(&versions[max_version++], slot, sizeof(struct castle_vtree_leaf_slot));
}

static void add_btree_node(c_disk_blk_t cdb)
{
    if(max_btree_node >= MAX_BTREE_NODES)
    {
        printf("Too many btree nodes\n");
        exit(-2);
    }
    btree_nodes[max_btree_node++] = cdb;
}

static void read_btree(c_disk_blk_t cdb)
{
    struct castle_vtree_node *node = get_block(cdb);   
    int i;

    printf("Capacity: 0x%x, used 0x%x\n", node->capacity, node->used);
    add_btree_node(cdb);

    for(i=0; i<node->used; i++)
    {
        struct castle_vtree_slot *slot = &node->slots[i];
        if(VTREE_SLOT_IS_NODE(slot))
            read_btree(slot->node.cdb);
        else
            add_version(&slot->leaf);
    }
}

static int prepare_list_node(int first_version, int btree_node_id)
{
    struct castle_vtree_list_node *np = get_block(btree_nodes[btree_node_id]);
    int version;

    for( version=first_version;
        (version < max_version) && (version - first_version < VTREE_LIST_SLOTS);
         version++)
    {
        struct castle_vtree_leaf_slot *slot = &np->slots[version - first_version];
        memcpy(slot, &versions[version], sizeof(struct castle_vtree_leaf_slot));
        printf("Saving version: %d\n", versions[version].version_nr);
    }  
    if(btree_node_id == 0)
    {
        /* No prev element in the list */
        np->prev.disk  = 0;
        np->prev.block = 0;
    } else
    {
        /* Save previous block */
        np->prev = btree_nodes[btree_node_id - 1];
    }

    if(version >= max_version)
    {
        /* No next element */
        np->next.disk  = 0;
        np->next.block = 0;
    } else
    {
        np->prev = btree_nodes[btree_node_id + 1];
    }

    return (version >= max_version ? -1 : version);
}

static void process()
{
    int i, btree_node_id;
    c_disk_blk_t vtree_root;
    uint32_t *fp, *p;
    printf("Processing: %d\n", max_files);

    vtree_root.disk  = fs_sbs[0]->fwd_tree_disk1;
    vtree_root.block = fs_sbs[0]->fwd_tree_block1;
    read_btree(vtree_root);
    for(i=0; i<max_version; i++)
        printf("Version: %d, parent %d, size %d\n", 
            versions[i].version_nr,
            versions[i].parent,
            versions[i].size);
    i = 0;
    btree_node_id = 0;
    while((i = prepare_list_node(i, btree_node_id)) >= 0)
    {
        printf("Prepared list node slot, now version: %d.\n", i);
        btree_node_id++;
    }
    
    printf("Used %d btree nodes for the list. Had %d. Replacing rest.\n",
        btree_node_id, max_btree_node);
    for(i=btree_node_id+1; i<max_btree_node; i++)
    {
        fp = p = get_block(btree_nodes[i]);
        while(((char *)p - (char*)fp) < PAGE_SIZE)
        {
            *p = 0xde00adde;
            p++;
        }
    }

    /* Go through superblocks and update the pointers */
    for(i=0; i<max_files; i++)
    {
        fs_sbs[i]->fwd_tree_disk1  = btree_nodes[0].disk;
        fs_sbs[i]->fwd_tree_block1 = btree_nodes[0].block;
        fs_sbs[i]->fwd_tree_disk2  = btree_nodes[btree_node_id].disk;
        fs_sbs[i]->fwd_tree_block2 = btree_nodes[btree_node_id].block;
    }
}

static int castle_fs_superblock_validate(struct castle_fs_superblock *fs_sb)
{
    if(fs_sb->magic1 != 0x19731121) return -1;
    if(fs_sb->magic2 != 0x19880624) return -2;
    if(fs_sb->magic3 != 0x19821120) return -3;

    return 0;
}

static int castle_slave_superblock_validate(struct castle_slave_superblock *cs_sb)
{
    if(cs_sb->magic1 != 0x02061985) return -1;
    if(cs_sb->magic2 != 0x16071983) return -2;
    if(cs_sb->magic3 != 0x16061981) return -3;

    return 0;
}

int main(int argc, char* argv[])
{
    int i;
    
    if(argc <= 1)
    {
        printf("Usage castle-converter <disk-image-1> <disk-image-2> ...\n");
        return -1;
    }

    if(argc > MAX_FILES)
    {
        printf("Cannot handle more than %d files. Increase MAX_FILES in source.\n",
                MAX_FILES);
        return -2;
    }

    for(i=1; i<argc; i++)
    {
        int fd = fds[i-1] = open(argv[i], O_RDWR);
        struct stat stat;

        if(fd<0)
        {
            printf("Could not open %s\n", argv[i]);
            return -3;
        }
        if(fstat(fd, &stat) < 0)
        {
            printf("Could not fstat %s\n", argv[i]);
            return -4;
        }
        printf("Opening %s. Size: %ld bytes\n", argv[i], stat.st_size);
        mmaps[i-1] = mmap(NULL, stat.st_size, 
                          PROT_READ | PROT_WRITE, MAP_SHARED,
                          fds[i-1], 0);
        mmaps_size[i-1] = stat.st_size;
        if(mmaps[i-1] == MAP_FAILED)
        {
            printf("Could not mmap %s, %s\n", argv[i], strerror(errno));
            return -5;
        }
        cs_sbs[i-1] = (struct castle_slave_superblock *)mmaps[i-1];
        fs_sbs[i-1] = (struct castle_fs_superblock *)(mmaps[i-1] + PAGE_SIZE);
        if(castle_slave_superblock_validate(cs_sbs[i-1]) ||
           castle_fs_superblock_validate(fs_sbs[i-1]))
        {
            printf("Could not validate a superblock for: %s\n", argv[i]);
            return -6;
        }
        if((i >= 2) && 
           (memcmp(fs_sbs[0], fs_sbs[i-1], sizeof(struct castle_fs_superblock)) != 0))
        {
            printf("Superblocks do not match.\n");
            return -7;
        }
        if((fs_sbs[i-1]->fwd_tree_disk1 != fs_sbs[i-1]->fwd_tree_disk2) || 
           (fs_sbs[i-1]->fwd_tree_block1 != fs_sbs[i-1]->fwd_tree_block2))
        {
            printf("Looks like (at least) the disk image: %s has already been converted.\n",
                    argv[i]);
            return -8;
        }
    }
    /* We have all the disk files mmaped and validated, should not fail any more ... we hape :) */
    max_files = argc - 1;
    process();

    for(i=0; i<max_files; i++)
        munmap(mmaps[i], mmaps_size[i]);

    return 0;
}
