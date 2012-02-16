#ifndef __CASTLE_VMAP_H__
#define __CASTLE_VMAP_H__

/* The fast vmapper currently maps pages in the range 2 to 256, in powers of 2 (i.e. 2 to the power 1
through 2 to the power 8. */
#define CASTLE_VMAP_MAX_ORDER           8
#define CASTLE_VMAP_PGS                 (1 << CASTLE_VMAP_MAX_ORDER)

int     castle_vmap_fast_map_init(void);
void    castle_vmap_fast_map_fini(void);
void    *castle_vmap_fast_map(struct page **, int);
void    castle_vmap_fast_unmap(void *, int);

#endif /* __CASTLE_VMAP_H__ */
