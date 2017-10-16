	//Author: Doren Proctor
//Created for CS483 - Appled Systems Security
//Due Oct 13, 2017

#define _BSD_SOURCE //for lstat
#include <unistd.h>
#include <dirent.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <sys/sendfile.h>

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
int src;
int dst;


void closeSuccess() {
	if (acl) fclose(acl);
	if (src) close(src);
	if (dst) close(dst);
	fprintf(stderr, "Success\n");
	exit(1);
}

void closeFailure() {
	if (acl) fclose(acl);
	if (src) close(src);
	if (dst) close(dst);
	fprintf(stderr, "Failure\n");
	exit(1);
}


int getSource(char* path) {
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (debug) fprintf(stderr, "src error: %s\n", strerror(errno));
		closeFailure();
	}
	return fd;
}


int getDest(char* path, struct stat srcPath) {
	int fd = open(path, O_WRONLY | O_CREAT, 0600);
	if (fd == -1) {
		if (debug) fprintf(stderr, "dst error: %s\n", strerror(errno));
		closeFailure();
	}
	return fd;
}


char readAcl(char* path, char* username) { //returns your permission from acl
	char rights, user[128], buffer[256]; // max 256/line and 128/name
	acl = fopen(path, "r");
	if (acl == NULL) {
		if (debug) fprintf(stderr, "acl file does not exist\n");
		closeFailure();
	}
	while (fgets(buffer, 257, acl) != NULL) { // read each line
			fscanf(acl, "%s %c", user, &rights); // get data from line
			if (strcmp(user, "#")) { // not a commented line
				if (debug>1)  printf("user: %s\tpermissions: %c\n", user, rights);
				if (!strcmp(user, username)) {
					if (debug>1) printf("Username matches '%s'\n", user);
					break;
				}
			}
	}
	if (debug>1) printf("Rights: %c\n", rights);
	if ((rights != 'b') && (rights != 'w')) {
		if (debug) fprintf(stderr, "You don't have \"w\" rights\n");
		closeFailure();
		}
	return rights;
}


int main(int argc, char* argv[]) {
	char* srcPath = argv[1];
	char* destPath = argv[2];
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
	char aclPath[4096]; //max length of path in Linux
	strcpy(aclPath, srcPath);
	strcat(aclPath, ".access");
	readAcl(aclPath, username);
	src = getSource(srcPath);
	struct stat aclStat, srcStat;
	if (lstat(aclPath, &aclStat) == -1) {
		if (debug) fprintf(stderr, "lstat says no to your acl\n");
		closeFailure();
	}
	if (lstat(srcPath, &srcStat) == -1) {
		if (debug) fprintf(stderr, "lstat says no to your src\n");
		closeFailure();
	}

	if S_ISLNK(aclStat.st_mode) {
		if (debug) fprintf(stderr, "acl file is a symbolic link\n");
		closeFailure();
	}
	if (!S_ISREG(srcStat.st_mode)) {
		if (debug) fprintf(stderr, "src is not an ordinary file\n");
		closeFailure();
	}
	if ((aclStat.st_mode & S_IRGRP) || // any world/group access
	(aclStat.st_mode & S_IWGRP) ||
	(aclStat.st_mode & S_IXGRP) ||
	(aclStat.st_mode & S_IROTH) ||
	(aclStat.st_mode & S_IWOTH) ||
	(aclStat.st_mode & S_IXOTH)) {
		fprintf(stderr, "acl file should not give world/group access\n");
		closeFailure();
	}
	// • ACL file does not exist						(Y)
	// • ACL file is a symbolic link (Y)
	// • Existence of a malformed entry
	// • basename.ext is not an ordinary file
	// • Protection for basename.ext.access allows any world or group access (via the standard UNIX file protections)


	dst = getDest(destPath, aclStat);

	int sentBytes = sendfile(dst, src, NULL, aclStat.st_size*sizeof(int));
	if (sentBytes == -1) printf("sendfile error: %s\n", strerror(errno));
	else if (debug>1) printf("sendfile: %i\n", sentBytes);

	closeSuccess();
}

//will want sendfile
