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
FILE* dst;

void silentlyClose() {
	if (acl) fclose(acl);
	if (src) fclose(src);
	if (dst) fclose(dst);
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

FILE* getFile(char* path, char* name) {
	FILE* fptr = fopen(path, "r");
	if (fptr == NULL) {
		if (debug) fprintf(stderr, "%s is not valid\n", name);
		silentlyClose();
	}
	return fptr;
}

DIR* getDir(char* path) {
	struct stat file_info;
	DIR* dir = opendir(path);
	if (!dir || (lstat(path, &file_info) == -1)) {
			if (debug) fprintf(stderr, "Destination is not valid\n");
			silentlyClose();
	}
	return dir;
}

char readAcl(char* path, char* username) { //returns your permission from acl
	char rights, user[128], buffer[256]; // max 256/line and 128/name
	acl = fopen(path, "r");
	if (acl == NULL) {
		if (debug) fprintf(stderr, "acl file is not valid\n");
		silentlyClose();
	}
	while (fgets(buffer, 257, acl) != NULL) { // read each line
			// printf("|| %s\n", buffer);
			fscanf(acl, "%s %c", user, &rights); // get data from line
			if (strcmp(user, "#")) { // not a commented line
				if (debug) printf("user: %s\tpermissions: %c\n", user, rights);
				if (!strcmp(user, username)) {
					if (debug) printf("Username matches '%s'\n", user);
					break;
				}
			}
	}
	if (debug) printf("Rights: %c\n", rights);
	return rights;
}

int main(int argc, char* argv[]) {
	const uid_t ruid = getuid(); // regular user: person running program
	const uid_t euid = geteuid(); // effective user: person who owns program
	printf("euid: %i, ruid: %i\n", euid, ruid);
	if (seteuid(ruid) < 0) {
		printf("seteuid failed\n");
	}
	printf("GETEUID(): %i\n", geteuid());
	printf("euid: %i, ruid: %i\n", euid, ruid);
	if (seteuid(ruid) < 0) {
		printf("seteuid failed\n");
	}
	printf("euid: %i, ruid: %i\n", euid, ruid);


	char* username;
	struct passwd* pw = getpwuid(ruid);
	if (pw) {
		username = pw->pw_name;
		if (debug) printf("Your username is: %s\n", username);
	}
	else if (debug)  {
		fprintf(stderr, "Couldn't get your username\n");
		silentlyClose();
	}


	// if (debug) printf("ruid: %i\n", ruid);
	// if (debug) printf("euid: %i\n", euid);

	//Check num of params
	if (argc != 3) {
		if (debug) fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);

	}

	char* aclPath = strcat(argv[1], ".access");
	// printf("%s\n", aclPath);

	// char rights, user[128], buffer[256]; // max 256/line and 128/name
	// acl = getFile(aclPath, "acl");
	// while (fgets(buffer, 257, acl) != NULL) { // read each line
	// 		fscanf(acl, "%s %c", user, &rights); // get data from line
	// 		if (strcmp(user, "#")) { // not a commented line
	// 			if (debug) printf("user: %s\tpermissions: %c\n", user, rights);
	// 		}
	// }

	readAcl(aclPath, username);
	src = getFile(argv[1], "src");
	dst = getFile(argv[2], "dst");



	if (debug) printf("Success\n");
	silentlyClose();
}

//will want sendfile
