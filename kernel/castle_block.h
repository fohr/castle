#ifndef __CASTLE_BLOCK_H__
#define __CASTLE_BLOCK_H__

int castle_block_read(struct castle_slave *slave, 
                      sector_t block,
                      struct page *page,
                      void (*callback)(void *, int err),
                      void *arg);
int castle_sub_block_read(struct castle_slave *slave,
                          void *buffer, 
                          uint64_t offset,
                          uint16_t size,
                          void (*callback)(void *, int err),
                          void *arg);

#endif /* __CASTLE_BLOCK_H__ */
