	//Author: Doren Proctor
//Created for CS483 - Appled Systems Security
//Due Oct 13, 2017

#define _GNU_SOURCE
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <pwd.h>
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
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

// global variables
int debug = 0;
FILE* acl; //global to make closing them easier
int src;
int dst;


void closeSuccess() {
	if (acl) fclose(acl);
	if (src) close(src);
	if (dst) close(dst);
	printf("Success\n");
	exit(1);
}


void closeFailure() {
	if (acl) fclose(acl);
	if (src) close(src);
	if (dst) close(dst);
	printf("Failure\n");
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


int getDst(char* path, struct stat srcPath) {
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
	if (acl == NULL) { // • ACL file does not exist
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
	if (debug>1) printf("Permissions: %c\n", rights);

	if ((rights != 'b') && (rights != 'w')) {
		if (debug) fprintf(stderr, "You don't have \"w\" rights\n");
		closeFailure();
		}

	return rights;
}

int main(int argc, char* argv[]) {
	char* srcPath = argv[1];
	char* dstPath = argv[2];
	char aclPath[4096]; //max length of path in Linux

	const uid_t uid = getuid();
	const uid_t euid = geteuid();
	if (debug>1) printf("Initial euid: %i, uid: %i\n", euid, uid);

	//Check num of params
	if (argc != 3) { // • Existence of a malformed entry
		if (debug) fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);
	}

	strcpy(aclPath, srcPath);
	strcat(aclPath, ".access");

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

	dst = getDst(dstPath, aclStat);

	if S_ISLNK(aclStat.st_mode) { // • ACL file is a symbolic link
		if (debug) fprintf(stderr, "acl file is a symbolic link\n");
		closeFailure();
	}
	if (!S_ISREG(srcStat.st_mode)) { // • basename.ext is not an ordinary file
		if (debug) fprintf(stderr, "src is not an ordinary file\n");
		closeFailure();
	}
	if ((aclStat.st_mode & S_IRGRP) ||
	(aclStat.st_mode & S_IWGRP) ||
	(aclStat.st_mode & S_IXGRP) ||
	(aclStat.st_mode & S_IROTH) ||
	(aclStat.st_mode & S_IWOTH) ||
	(aclStat.st_mode & S_IXOTH)) { // • Protection for acl allows any world or group access
	if (debug) fprintf(stderr, "acl file should not give world/group access\n");
		closeFailure();
	}

	if (seteuid(uid) < 0) { // change euid to real uid
		if (debug) fprintf(stderr, "seteuid(uid) failed\n");
		closeFailure();
	}
	if (debug>1) printf("geteuid() after seteuid() to uid: %i\n", geteuid());

	if (!euidaccess(srcPath, R_OK)) { // • euid has read access to src
		if (debug) fprintf(stderr, "euid doesn't have read access to src\n");
		closeFailure();
	}
	if (!euidaccess(dstPath, W_OK)) { // • real uid  can write to dst
		if (debug) fprintf(stderr, "uid cannot write to dst\n");
		closeFailure();
	}

	if (!euidaccess(aclPath, R_OK)) { // • acl exists and indicates read access for the real uid
		if (debug) fprintf(stderr, "uid cannot write to acl\n");
		closeFailure();

	}
	if (seteuid(euid) < 0) { // change euid back to euid
		if (debug) fprintf(stderr, "seteuid(euid) failed\n");
		closeFailure();
	}
	if (debug>1) printf("geteuid() after seteuid() to euid: %i\n", geteuid());

	if (srcStat.st_uid != geteuid()) { // • src is owned by the euid
		if (debug) fprintf(stderr, "Source not owned by euid\n");
		closeFailure();
	}

	char* username;
	struct passwd* pw = getpwuid(uid);
	if (pw) {
		username = pw->pw_name;
		if (debug>1) printf("Your username is: %s\n", username);
	}
	else if (debug)  {
		if (debug) fprintf(stderr, "Couldn't get your username\n");
		closeFailure();
	}

	readAcl(aclPath, username);

	int sentBytes = sendfile(dst, src, NULL, aclStat.st_size*sizeof(int));
	if (sentBytes == -1) {
		printf("sendfile error: %s\n", strerror(errno));
		closeFailure();
	}
	else if (debug>1) printf("sendfile: %i\n", sentBytes);

	closeSuccess();
}
