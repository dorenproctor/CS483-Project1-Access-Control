//Author: Doren Proctor
//Created for CS483 - Appled Systems Security
//Due Oct 13, 2017

#define _BSD_SOURCE //for lstat
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include  <stdio.h>
#include <string.h>
#include <stdlib.h>
// Fails *silently* when any of these are true:
// • ACL file does not exist
// • ACL file is a symbolic link
// • Existence of a malformed entry
// • basename.ext is not an ordinary file
// • Protection for basename.ext.access allows any world or group access (via the standard UNIX file protections)

int main(int argc, char* argv[]) {
  return 0;
}
