#include <stdio.h>
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

int main(int argc, char *argv[])
{
    int    fd, ret;
    struct castle_slave_superblock_public cs_sb;
    struct castle_fs_superblock_public fs_sb;

    if (argc != 2)
    {
      fprintf(stderr, "Usage: %s <device>\n", argv[0]);
      return 2;
    }

    if ((fd = open(argv[1], O_RDONLY | O_NOCTTY)) < 0) {
      fprintf(stderr, "Failed to open %s: %s\n", argv[1], strerror(errno));
      return 1;
    }

    if (read(fd, &cs_sb, sizeof(cs_sb)) != sizeof(cs_sb))
    {
        perror("Failed to read cs_sb");
        return 1;
    }

    if ((ret = castle_slave_superblock_validate(&cs_sb)) < 0)
    {
        fprintf(stderr, "Invalid disk superblock (at %d)\n", -ret);
        return 1;
    }

    lseek(fd, 4096, SEEK_SET);
    if (read(fd, &fs_sb, sizeof(fs_sb)) != sizeof(fs_sb))
    {
        perror("Failed to read fs_sb");
        return 1;
    }

    if (cs_sb.flags & CASTLE_SLAVE_NEWDEV) {
      fprintf(stdout, "New disk - no filesystem superblock\n");
    }
    else if ((ret = castle_fs_superblock_validate(&fs_sb)) < 0)
    {
      fprintf(stderr, "Invalid filesystem superblock (at %d)\n", -ret);
    }
    else {
      fprintf(stdout, "Filesystem uuid: 0x%x\n", fs_sb.uuid);
    }

    fprintf(stdout, "Disk uuid: 0x%x%s\n", cs_sb.uuid, (cs_sb.flags & CASTLE_SLAVE_SSD) ? ", SSD" : "");

    close(fd);

    return 0;
}
