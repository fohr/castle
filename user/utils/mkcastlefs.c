#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <string.h>

#include "castle_public.h"

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
		perror("Can't open /dev/urandom");
		exit(-4);
	}
	
	if(read(fd, data, len) != len) {
		perror("Error reading /dev/urandom");
		exit(-4);
	}
	close(fd);
	memcpy(&i, data, sizeof(i));
	return i;
}

void init_superblock(struct castle_slave_superblock *super)
{
	super->magic1 = CASTLE_SLAVE_MAGIC1;
	super->magic2 = CASTLE_SLAVE_MAGIC2;
	super->magic3 = CASTLE_SLAVE_MAGIC3;
	super->version = CASTLE_SLAVE_VERSION;
	super->uuid = get_random_uuid();
	super->used = 1; /* we are responsible for writing JUST the
				slave's superblock */
	super->flags = CASTLE_SLAVE_TARGET | CASTLE_SLAVE_NEWDEV;
	super->size = -1;
}

int write_superblock(int fd, struct castle_slave_superblock *super)
{
	const int max = 4096;
	const int len = sizeof(struct castle_slave_superblock);

	if(len > max) {
		fprintf(stderr, "superblock too big to fit in disk block\n");
		return 0;
	}

	if(write(fd, super, len) != len) {
		fprintf(stderr, "Failure writing superblock!\n");
		return 0;
	}
	
	fsync(fd);

	return 1;

}

int main(int argc, char *argv[])
{
	int rv, fd;
	char *node;
	struct stat st;
	struct castle_slave_superblock super;

	/* check args */
	if(argc != 2) {
		usage();
		exit(-1);
	}

	node = argv[1];

	if(stat(node, &st)) {
		perror("mkcastlefs");
		exit(-2);
	}

	if(!st.st_rdev) {
		fprintf(stderr, "Warning: %s does not seem to be a device node\n", node);
	}

	init_superblock(&super);

	/* write */
	if((fd = open(node, O_RDWR|O_LARGEFILE|O_SYNC)) == -1) {
		/* open failed */
		perror("mkcastlefs");
		exit(-3);
	}

	if(!write_superblock(fd, &super)) {
		fprintf(stderr, "Error writing superblock on %s", node);
		perror("write");
		exit(-6);
	}

	if(close(fd)) {
		fprintf(stderr, "Warning: error closing %s", node);
		perror("close");
		exit(-7);
	}

	exit(0);
}
