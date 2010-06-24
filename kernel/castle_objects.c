#include "castle_public.h"
#include "castle_compile.h"
#include "castle.h"
#include "castle_btree.h"

void castle_object_replace(c_bio_t *c_bio, uint8_t **key, uint8_t *value)
{
    uint64_t noddy_key;
    c_bvec_t *c_bvec;
    int i;

    memcpy(&noddy_key, key[0], 8);
    for(i=0; key[i]; i++)
    {
        printk(" key[%d]         : ", i);
        print_hex_dump_bytes("", DUMP_PREFIX_NONE, key[i], strlen(key[i]));
        kfree(key[i]);
    }
    kfree(key);
    if(value == NULL)
    {
        printk(" value          : tombstone\n");
    } else
    {
        printk(" value          : ");
        print_hex_dump_bytes("", DUMP_PREFIX_NONE, value, strlen(value));
        kfree(value);
    }
    printk(" Noddy key=%llx\n", noddy_key);

    /* This should go through doubling array, of course */
    BUG_ON(atomic_read(&c_bio->count) != 1);
    c_bvec          = c_bio->c_bvecs;
    c_bvec->key     = (void *)noddy_key; 

    castle_btree_find(&castle_mtree, c_bvec); 
}

