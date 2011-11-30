#ifndef __CASTLE_MSTORE_H__
#define __CASTLE_MSTORE_H__

/**********************************************************************************************
 * MStore related functions (including stats store handler).
 */
int                        castle_mstore_iterator_has_next (struct castle_mstore_iter *iter);
void                       castle_mstore_iterator_next     (struct castle_mstore_iter *iter,
                                                            void *entry_p,
                                                            size_t *size_p);
void                       castle_mstore_iterator_destroy  (struct castle_mstore_iter *iter);
struct castle_mstore_iter* castle_mstore_iterate           (c_mstore_id_t store_id);
int                        castle_mstore_entry_insert      (struct castle_mstore *store,
                                                            void *entry,
                                                            size_t size);
struct castle_mstore*      castle_mstore_init              (c_mstore_id_t store_id);
void                       castle_mstore_fini              (struct castle_mstore *store);

int                        castle_mstores_writeback        (uint32_t version, int is_fini);

#endif /* __CASTLE_MSTORE_H__ */
