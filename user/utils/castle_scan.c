#include <stdio.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>

#include "castle_public.h"

static int castle_slave_superblock_validate(struct castle_slave_superblock *cs_sb)
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
    char   fname[128];
    struct castle_slave_superblock cs_sb;
    struct castle_fs_superblock_public fs_sb;

    if (argc != 2)
    {
        fprintf(stderr, "Usage: castle-scan <device, e.g. sda3>.\n");
        return -1;
    }

    snprintf(fname, 128, "/dev/%s", argv[1]);
    if ((fd = open(fname, O_RDONLY)) < 0)
    {
        perror(fname);
        return -1;
    }

    if (read(fd, &cs_sb, sizeof(cs_sb)) < 0)
    {
        perror("Failed to read");
        return -1;
    }

    if ((ret = castle_slave_superblock_validate(&cs_sb)) < 0)
    {
        fprintf(stderr, "Invalid Disk Superblock: %d\n", ret);
        return -1;
    }

    lseek(fd, 4096, SEEK_SET);
    if (read(fd, &fs_sb, sizeof(fs_sb)) < 0)
    {
        perror("Failed to read");
        return -1;
    }

    if (castle_fs_superblock_validate(&fs_sb) < 0)
    {
        fprintf(stderr, "Invalid File-system Superblock\n");
        return -1;
    }

    printf("0x%x\n", fs_sb.uuid);

    close(fd);

    return 0;
}
