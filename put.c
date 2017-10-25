//Author: Doren Proctor
//Created for CS483 - Applied Systems Security
//Due Oct 23, 2017

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

// Access is allowed only when all of these are true:
// • The effective uid of the executing process owns destination
// • The effective uid of the executing process has write access to the file destination
// • The file destination.access exists and indicates write access for the real uid of the executing process
// • The real uid of the executing process may read source


int debug = 0; //0, 1, or 2 depending on how much feedback you want
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


int getSrc(char* path) {
	int fd = open(path, O_RDONLY);
	if (fd == -1) {
		if (debug) fprintf(stderr, "dst error: %s\n", strerror(errno));
		closeFailure();
	}
	return fd;
}


int getDst(char* path) {
	int fd = open(path, O_WRONLY | O_CREAT, 0400);
	if (fd == -1) {
		if (debug) fprintf(stderr, "src error: %s\n", strerror(errno));
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

	if ((rights != 'b') && (rights != 'r')) {
		if (debug) fprintf(stderr, "You don't have \"r\" rights\n");
		closeFailure();
		}

	return rights;
}


int main(int argc, char* argv[]) {
  char* srcPath = argv[1];
	char* dstPath = argv[2];
	char aclPath[4096]; //max length of path in Linux
	int dstExists = 0;

	const uid_t ruid = getuid();
	const uid_t euid = geteuid();
	if (debug>1) printf("Initial euid: %i, ruid: %i\n", euid, ruid);

	//Check num of params
	if (argc != 3) { // • Existence of a malformed entry
		if (debug) fprintf(stderr, "\nInput:   ./get <source> <destination>\n\n");
		exit(1);
	}

	strcpy(aclPath, srcPath);
	strcat(aclPath, ".access");

	src = getSrc(srcPath);

	struct stat aclStat, dstStat, srcStat;
	if (lstat(aclPath, &aclStat) == -1) {
		if (debug) fprintf(stderr, "lstat says no to your acl\n");
		closeFailure();
	}

	if (lstat(srcPath, &srcStat) == -1) {
		if (debug) fprintf(stderr, "lstat says no to your src\n");
		closeFailure();
	}

	if (lstat(dstPath, &dstStat) == -1) {
		// if (debug) fprintf(stderr, "lstat says no to your dst\n");
		// closeFailure();
		if (debug) printf("dst does not exist\n");
	}
	else {
		dstExists = 1;
	}

	dst = getDst(dstPath);

	if S_ISLNK(aclStat.st_mode) { // • ACL file is a symbolic link
		if (debug) fprintf(stderr, "acl file is a symbolic link\n");
		closeFailure();
	}

	if (!S_ISREG(srcStat.st_mode)) {
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

	if (euidaccess(dstPath, W_OK)) { // • euid has write access to dst
		if (debug) printf("euid doesn't have write access to dst: %s\n",  strerror(errno));
		closeFailure();
	}

	if (dstExists) {
		char answer;
		while (1) {
			printf("File exists. Overwrite? (y/n): ");
			scanf(" %c", &answer);
			if (answer == 'n' || answer == 'N') closeFailure();
			else if (answer != 'y' || answer != 'Y') break;
			else printf("Not a valid input\n\n");
		}
	}

	if (seteuid(ruid) < 0) {
		if (debug) fprintf(stderr, "seteuid(ruid) failed\n");
		closeFailure();
	}
	if (debug>1) printf("geteuid() after seteuid() to ruid: %i\n", geteuid());

	if (!euidaccess(aclPath, W_OK)) { // • acl exists and indicates write access for the real uid
		if (debug) fprintf(stderr, "ruid cannot write to acl\n");
		closeFailure();
	}

	if (!euidaccess(srcPath, R_OK)) { // • real uid may read src
		if (debug) fprintf(stderr, "ruid cannot write to src\n");
		closeFailure();
	}

	if (seteuid(euid) < 0) {
		if (debug) fprintf(stderr, "seteuid(euid) failed\n");
		closeFailure();
	}
	if (debug>1) printf("geteuid() after seteuid() to euid: %i\n", geteuid());

	char* username;
	struct passwd* pw = getpwuid(ruid);
	if (pw) {
		username = pw->pw_name;
		if (debug>1) printf("Your username is: %s\n", username);
	}
	else if (debug)  {
		if (debug) fprintf(stderr, "Couldn't get your username\n");
		closeFailure();
	}

	if (debug>1) printf("aclPath: %s\n", aclPath);
	readAcl(aclPath, username);
	if (debug>1) printf("src: %i\tdst: %i\n", src, dst);

	int sentBytes = sendfile(dst, src, NULL, srcStat.st_size*sizeof(int));
	if (sentBytes == -1) {
		printf("sendfile error: %s\n", strerror(errno));
		closeFailure();
	}
	else if (debug>1) printf("sendfile: %i\n", sentBytes);

	closeSuccess();
}
