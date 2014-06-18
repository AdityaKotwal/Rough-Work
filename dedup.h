/*********************************************************
 * Copyright 2014 VMware, Inc.  All rights reserved.
 * -- VMware Confidential
 *********************************************************/

/*
 * dedup.h -
 *
 *    This header file illustrates the modules used for
 *    the desiref purpose.
 */

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <regex.h>
#include <err.h>
#include <str.h>
#include "md5.h"
#define SRC "/testInDir"
#define DST "/testOutDir/dump"

#ifndef __dedup_h__
   #define __dedup_h__
   #define MAX_COMBINED_HASH_LEN 1024*1024
   #define MAX_FILE_NAME_LEN 1024
   #define MAX_BUF_LEN 4*1024
   #define RDLEN MAX_BUF_LEN

   void getMD5(const char *string,
	       long len,
	       char *md5len);
   char bin2Hex(unsigned char bin);
   void generateDedupDump(char* source,
			  FILE* op);
   void cleanDump(char *file);
   int isDedupCandidate(char *source);
   void traverse(char *dirPath);
   void printHeader(char *destination);
#endif
