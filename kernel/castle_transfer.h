#ifndef __CASTLE_TRANSFERS_H__
#define __CASTLE_TRANSFERS_H__

extern struct castle_transfers castle_transfers;

int castle_transfers_init(void);
void castle_transfers_free(void);

struct castle_transfer* castle_transfer_find    (transfer_id_t id);
struct castle_transfer* castle_transfer_create  (version_t version, int direction, int *ret);
void                    castle_transfer_destroy (struct castle_transfer *transfer);

#endif /* __CASTLE_TRANSFERS_H__ */
