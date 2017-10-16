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
#include <pwd.h>
#include <sys/types.h>
#include <errno.h>
#include <fcntl.h>
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
FILE* acl; //global to make closing them easier
FILE* src;
int dst;


void closeSuccess() {
	if (acl) fclose(acl);
	if (src) fclose(src);
	if (dst) close(dst);
	fprintf(stderr, "Success\n");
	exit(1);
}

void closeFailure() {
	if (acl) fclose(acl);
	if (src) fclose(src);
	if (dst) close(dst);
	fprintf(stderr, "Failure\n");
	exit(1);
}


FILE* getSource(char* path) {
	FILE* fptr = fopen(path, "r");
	if (fptr == NULL) {
		if (debug) fprintf(stderr, "Source is not valid\n");
		closeFailure();
	}
	return fptr;
}


int getDest(char* path) {
	int fptr = open(path, O_WRONLY | O_CREAT);
	if (fptr != -1) {
		if (debug) fprintf(stderr, "Destination is not valid\n");
		closeFailure();
	}
	return fptr;
}


char readAcl(char* path, char* username) { //returns your permission from acl
	char rights, user[128], buffer[256]; // max 256/line and 128/name
	acl = fopen(path, "r");
	// printf("getuid() inside readAcl(): %i\n", getuid());
	if (acl == NULL) {
		if (debug) fprintf(stderr, "acl file is not valid\n");
		closeFailure();
	}
	while (fgets(buffer, 257, acl) != NULL) { // read each line
			// printf("|| %s\n", buffer);
			fscanf(acl, "%s %c", user, &rights); // get data from line
			if (strcmp(user, "#")) { // not a commented line
				if (debug>1)  printf("user: %s\tpermissions: %c\n", user, rights);
				if (!strcmp(user, username)) {
					printf("Username matches '%s'\n", user);
					break;
				}
			}
	}
	if (debug) printf("Rights: %c\n", rights);
	if ((rights != 'b') && (rights != 'w')) {
		if (debug) fprintf(stderr, "You don't have \"w\" rights\n");
		closeFailure();
	}
	return rights;
}


int main(int argc, char* argv[]) {
	const uid_t ruid = getuid(); // regular user: person running program

	// const uid_t euid = geteuid(); // effective user: person who owns program
	// if (debug) printf("Initial euid: %i, ruid: %i\n", euid, ruid);
	// if (setuid(euid) < 0) {
	// 	printf("seteuid failed\n");
	// }
	// if (debug) printf("getuid() after setuid(): %i\n", getuid());

	char* username;
	struct passwd* pw = getpwuid(ruid);
	if (pw) {
		username = pw->pw_name;
		if (debug>1) printf("Your username is: %s\n", username);
	}
	else if (debug)  {
		fprintf(stderr, "Couldn't get your username\n");
		closeFailure();
	}

	//Check num of params
	if (argc != 3) {
		if (debug) fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);

	}

	char* aclPath = strcat(argv[1], ".access");
	readAcl(aclPath, username);
	src = getSource(argv[1]);
	dst = getDest(argv[2]);

	closeSuccess();
}

//will want sendfile
