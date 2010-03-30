#ifndef __CASTLE_FREESPACE_H__
#define __CASTLE_FREESPACE_H__

void         castle_freespace_slave_init   (struct castle_slave *cs, 
                                            struct castle_slave_superblock *cs_sb);
c_disk_blk_t castle_freespace_block_get    (void);
void         castle_freespace_block_free   (c_disk_blk_t cdb);

#endif /* __CASTLE_FREESPACE_H__ */
