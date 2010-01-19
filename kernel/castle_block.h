#ifndef __CASTLE_BLOCK_H__
#define __CASTLE_BLOCK_H__

int castle_block_read(struct castle_slave *slave, 
                      sector_t block,
                      struct page *page);

#endif /* __CASTLE_BLOCK_H__ */
