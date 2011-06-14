#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>
#include <errno.h>

#include "castle_public.h"

#define MB (1024 * 1024)

void usage(void)
{
  printf("Usage: mkcastlefs /dev/sdXY\n");
}

uint32_t get_random_uuid()
{
  const int len = sizeof(uint32_t);
  char data[len];
  int fd, bytes;
  uint32_t i;
	
  if((fd = open("/dev/urandom", O_RDONLY)) == -1) {
    fprintf(stderr, "Failed to open /dev/urandom: %s\n", strerror(errno));
    exit(1);
  }
	
  if(read(fd, data, len) != len) {
    fprintf(stderr, "Error reading /dev/urandom: %s\n", strerror(errno));
    exit(1);
  }
  close(fd);
  memcpy(&i, data, sizeof(i));
  return i;
}

void init_superblock(struct castle_slave_superblock_public *super, int is_ssd)
{
  super->magic1 = CASTLE_SLAVE_MAGIC1;
  super->magic2 = CASTLE_SLAVE_MAGIC2;
  super->magic3 = CASTLE_SLAVE_MAGIC3;
  super->version = CASTLE_SLAVE_VERSION;
  super->uuid = get_random_uuid();
  super->used = 1; /* we are responsible for writing JUST the
                      slave's superblock */
  super->flags = CASTLE_SLAVE_NEWDEV | (is_ssd ? CASTLE_SLAVE_SSD : 0);
  super->size = -1;
  super->checksum = 0;
}

int write_superblock(int fd, struct castle_slave_superblock_public *super)
{
  const int max = 4096;
  const int len = sizeof(struct castle_slave_superblock_public);

  if(len > max) {
    fprintf(stderr, "superblock too big to fit in disk block\n");
    return 0;
  }

  if(write(fd, super, len) != len) {
    fprintf(stderr, "Failure writing superblock!\n");
    return 0;
  }

  if (lseek(fd, 8192, SEEK_SET) == -1) {
    fprintf(stderr, "Failure seeking to second superblock!\n");
    return 0;
  }
	
  if(write(fd, super, len) != len) {
    fprintf(stderr, "Failure writing second superblock!\n");
    return 0;
  }

  fsync(fd);

  return 1;

}

static int check_ssd(char *node)
{
#define BUFFER_SIZE     256
#define MODEL_COMMAND   "check-ssd "

  FILE *p = NULL;
  char buffer[BUFFER_SIZE];
  int i, ret;

  ret = 0;
  /* Make sure that the command will fit in the buffer. */
  if(strlen(node) > BUFFER_SIZE - strlen(MODEL_COMMAND) - 10)
    goto out;
  sprintf(buffer, MODEL_COMMAND"%s", node);
  p = popen(buffer, "r");
  if(!p)
    {
      printf("Failed to execute: %s\n", buffer);
      goto out;
    }

  ret = pclose(p);

out:
  return ret;
}

int main(int argc, char *argv[])
{
  int rv, fd, i, is_ssd;
  char *node;
  struct stat st;
  struct castle_slave_superblock_public super;
  char buf[4096];

  /* check args */
  if(argc != 2) {
    usage();
    exit(2);
  }

  node = argv[1];

  if(stat(node, &st)) {
    fprintf(stderr, "%s: failed to stat %s: %s\n", argv[0], node, strerror(errno));
    exit(2);
  }

#if 0
  if(!st.st_rdev) {
    fprintf(stderr, "Warning: %s does not seem to be a device node\n", node);
  }
#endif
    
  is_ssd = check_ssd(node);
  init_superblock(&super, is_ssd);

  /* write */
  if((fd = open(node, O_RDWR|O_LARGEFILE|O_SYNC)) == -1) {
    /* open failed */
    fprintf(stderr, "%s: failed to open %s: %s\n", argv[0], node, strerror(errno));
    exit(1);
  }

  /* Set first MB of the disk to 0. */
  memset(buf, 0 , 4096);
  for(i=0; i<(MB / 4096); i++) {
    if(write(fd, buf, 4096) != 4096) {
      fprintf(stderr, "Failure setting up disk!\n");
      return 0;
    }
  }
  lseek(fd, 0, SEEK_SET);

  if(!write_superblock(fd, &super)) {
    fprintf(stderr, "%s: Error writing superblock on %s: %s", argv[0], node, strerror(errno));
    exit(1);
  }

  if(close(fd)) {
    fprintf(stderr, "%s: Warning: error closing %s: %s", argv[0], node, strerror(errno));
    exit(1);
  }

  exit(0);
}
