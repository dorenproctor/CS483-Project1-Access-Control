	//Author: Doren Proctor
//Created for CS483 - Appled Systems Security
//Due Oct 13, 2017

#define _BSD_SOURCE //for lstat
#include <unistd.h>
#include <sys/stat.h>
#include <dirent.h>
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

int debug = 1;
DIR* ACL; //global to make closing them easier
DIR* src;
DIR* dest;

void silentlyClose() {
	if (src) { closedir(src); }
	if (dest) { closedir(dest); }
	exit(1);
}

int readable(char* path) {
	if (!access(path, R_OK)) return 1;
	else return 0;
}

int writable(char* path) {
	if (!access(path, W_OK)) return 1;
	else return 0;
}

void getFile(char* path, char* name) {
	struct stat file_info;
	DIR* dir = opendir(path);
	if (!dir || (lstat(path, &file_info) == -1)) {
			if (debug) fprintf(stderr, "\n%s is not valid\n\n", name);
			silentlyClose();
	}
}

int main(int argc, char* argv[]) {
	uid_t ruid = getuid(); // regular user: person running program
	uid_t euid = geteuid(); // effective user: person who owns program
	// seteuid(ruid); // de-escalate privileges
	printf("ruid: %i\n", ruid);
	printf("euid: %i\n", euid);

	//Check num of params
	if (argc != 3) {
		if (debug) fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);
	}

	//Open files given by user
	getFile(argv[1], "Source");
	//if (readable(argv[1])) printf("readable\n");
	//if (writable(argv[1])) printf("writable\n");
	getFile(argv[2], "Destination");

	if (debug) printf("Success\n");
	silentlyClose();
}
