#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <string.h>

#include "castle_public.h"

static int castle_slave_superblock_validate(struct castle_slave_superblock_public *cs_sb)
{
    if(cs_sb->magic1 != CASTLE_SLAVE_MAGIC1) return -1;
    if(cs_sb->magic2 != CASTLE_SLAVE_MAGIC2) return -2;
    if(cs_sb->magic3 != CASTLE_SLAVE_MAGIC3) return -3;
    if(cs_sb->version != CASTLE_SLAVE_VERSION) return -4;

    return 0;
}

static int castle_fs_superblock_validate(struct castle_fs_superblock_public *fs_sb)
{
    if(fs_sb->magic1 != CASTLE_FS_MAGIC1) return -1;
    if(fs_sb->magic2 != CASTLE_FS_MAGIC2) return -2;
    if(fs_sb->magic3 != CASTLE_FS_MAGIC3) return -3;
    if(fs_sb->version != CASTLE_FS_VERSION) return -4;

    return 0;
}

#define ROUND_UP_ALIGN(x, align) ((x + align) - 1) & ~(align - 1)

int main(int argc, char *argv[])
{
    int    fd, ret;
    struct castle_slave_superblock_public *cs_sb;
    struct castle_fs_superblock_public *fs_sb;
    size_t cs_sb_alignbuf_size, fs_sb_alignbuf_size;
    unsigned int align;

    if (argc != 2)
    {
      fprintf(stderr, "Usage: %s <device>\n", argv[0]);
      return 2;
    }

    if ((fd = open(argv[1], O_RDONLY | O_NOCTTY | O_DIRECT)) < 0) {
      fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
      return 1;
    }

    /* Find alignment requirements for posix_memalign / O_DIRECT read. */
    align = pathconf(argv[1], _PC_REC_XFER_ALIGN);

    cs_sb_alignbuf_size = ROUND_UP_ALIGN(sizeof(struct castle_slave_superblock_public), align);
    ret = posix_memalign((void *)&cs_sb, align, cs_sb_alignbuf_size);
    if (ret == -1)
    {
      perror("posix_memalign failed\n");
      return 1;
    }

    fs_sb_alignbuf_size = ROUND_UP_ALIGN(sizeof(struct castle_fs_superblock_public), align);
    ret = posix_memalign((void *)&fs_sb, align, fs_sb_alignbuf_size);
    if (ret == -1)
    {
      perror("posix_memalign failed\n");
      return 1;
    }

    /* Note: Use second copy of the cs superblock, as this will be the first to be checkpointed. */
    if (lseek(fd, 8192, SEEK_SET) == -1)
    {
        perror("Failed to seek to cs_sb");
        return 1;
    }

    if (read(fd, cs_sb, cs_sb_alignbuf_size) != cs_sb_alignbuf_size)
    {
        perror("Failed to read cs_sb");
        return 1;
    }

    if ((ret = castle_slave_superblock_validate(cs_sb)) < 0)
    {
        fprintf(stderr, "Invalid disk superblock (at %d)\n", -ret);
        return 1;
    }

    /* Note: Use second copy of the fs superblock, as this will be the first to be checkpointed. */
    if (lseek(fd, 12288, SEEK_SET) == -1)
    {
        perror("Failed to seek to cs_sb");
        return 1;
    }

    if (read(fd, fs_sb, fs_sb_alignbuf_size) != fs_sb_alignbuf_size)
    {
        perror("Failed to read fs_sb");
        return 1;
    }

    if (cs_sb->flags & CASTLE_SLAVE_NEWDEV) {
      fprintf(stdout, "New disk - no filesystem superblock\n");
    }
    else if ((ret = castle_fs_superblock_validate(fs_sb)) < 0)
    {
      fprintf(stderr, "Invalid filesystem superblock (at %d)\n", -ret);
    }
    else {
      fprintf(stdout, "Filesystem uuid: 0x%x\n", fs_sb->uuid);
    }

    fprintf(stdout, "Disk uuid: 0x%x%s\n", cs_sb->uuid,
            (cs_sb->flags & CASTLE_SLAVE_SSD) ? ", SSD" : "");

    free(cs_sb);
    free(fs_sb);

    close(fd);

    return 0;
}
