//Author: Doren Proctor
//Created for CS483 - Appled Systems Security
//Due Oct 13, 2017

#define _BSD_SOURCE //for lstat
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

// Fails *silently* when any of these are true:
// • ACL file does not exist
// • ACL file is a symbolic link
// • Existence of a malformed entry
// • basename.ext is not an ordinary file
// • Protection for basename.ext.access allows any world or group access (via the standard UNIX file protections)

// Access allowed only when all of these are true:
// • Source is owned by the effective uid of the executing process,
// • The effective uid of the executing process has read access to source, the file source.access exists and indicates read access for the real uid of the executing process,
// • The real uid of the executing process can write the file destination.


DIR* src; //global to make closing them easier
DIR* dest;

void silentlyClose() {
	if (src) { closedir(src); }
	if (dest) { closedir(dest); }
	exit(1);
}

int checkFile(DIR* file, char* name) {
	// struct stat fileWithPath;
	// struct dirent* entry;
	// DIR* dir;
	if (!file) {
			fprintf(stderr, "\n%s is not valid\n\n", name);
			silentlyClose();
	}
	return 0;
}

int main(int argc, char* argv[]) {
	//Check num of params
	if (argc != 3) {
		fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);
	}

	//Open files given by user
	src = opendir(argv[1]);
	checkFile(src, "Source");
	dest = opendir(argv[2]);
	checkFile(dest, "Destination");

	printf("Made it to the end!\n");
	return 0;
}
