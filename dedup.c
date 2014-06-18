/*********************************************************
 * Copyright 2014 VMware, Inc.  All rights reserved.
 * -- VMware Confidential
 *********************************************************/

#include "dedup.h"

/*
 * dedup.c
 *
 *    This module provides functions and wrappers to deal with
 *    the generating a record of hashes of consecutive 4K blocks
 *    in all the files of a directory for the purpose of
 *    deduplication analysis
*/

int main()
{
   traverse(SRC);
   return 0;
}

/*
 * ----------------------------------------------------------
 *
 * generateDedupDump --
 *
 *    Generate text dump consisting of file name, segment size,
 *    segment offset and md5hash for segments of files.
 *
 * Side Effects:
 *    File as specified by the MACRO SRC, shall have modifed
 *    contents
 *
 * -----------------------------------------------------------
 */

void generateDedupDump(char* source,// IN: Source file
		       FILE* op)    // IN: File pointer for destination file
{
   FILE *ip;
   unsigned long len;
   unsigned long offset;
   char buf[1024 * 4];
   char hashStr[MD5_HASH_LEN * 2 + 1];  // Each byte represented by 2 hex values.
				     // String terminated by a null char '\0'
   offset = 0;
   if(!isDedupCandidate(source)){
      printf("Source file %s is not valid\n",source);
      return;
   }

   ip = fopen(source, "rb");
   if(ip == NULL){
      printf("Failed to open file %s \n", source);
      return;
   }

   while((len = fread(buf, RDLEN, 1, ip)) != 0){
      getMD5(buf, len, hashStr);
      fprintf(op, "%s,%s,%lu,%lu\n", source, hashStr, offset, len);
      offset += len;
   }

   if(fclose(ip) != 0){
      printf("Error closing file %s\n", source);
      return;
   }

   return;
}

/*
 * -------------------------------------------------------
 *
 * isDedupCandidate --
 *
 *    Checks if the file can be accessed by the program.
 *    Objective is to avoid analyzing infinte streams,
 *    pipes & raw devices like /dev/random. Considers
 *    any file with a size lesser than 4kB as
 *    ineligible for deduplication analysis
 *
 * Results:
 *    Returns 1 on success, and 0 on failure
 *
 * Side Effect:
 *    None
 *
 * -------------------------------------------------------
 */

int isDedupCandidate(int *fd) // IN: Source file descriptor
{
   size_t size;
   struct stat st;
   fstat(fd, &st);
   size = st.st_size;
   if (!S_REG(st.st_mode)) {
      return 0;
   } 
   if (size < 1024 * 4) { // Files with size less than 4kB to be ignored
      return 0;
   }
   return 1;
}


/*
 * ------------------------------------------------------------
 *
 * traverse --
 *
 *    Traverses all the files in a directory and calls the
 *    method generateDedupDump for each file
 *
 * Side Effects:
 *    None
 * -------------------------------------------------------------
 */

void traverse(char *dirPath) // IN: Directory Path
{
   DIR* FD;
   FILE* op;
   struct dirent* in_file;
   char path[MAX_FILE_NAME_LEN];
   int len;

   Str_Strcpy(path, dirPath, MAX_FILE_NAME_LEN);
   len = (int) strlen(dirPath);
   path[len++] = '/';

   FD = opendir(dirPath);
   if (FD == NULL){
      printf("Error : Failed to open input directory\n");
      return;
   }

   op = fopen(DST, "wb");
   if(op == NULL){
      printf("Failed to open file %s \n", DST);
      return;
   }

   fprintf(op, "File Name,md5,offset,size\n"); //Print header for file

   while ((in_file = readdir(FD))){
      if (!strcmp(in_file->d_name, "."))
	 continue;
      if (!strcmp(in_file->d_name, ".."))
	 continue;
      Str_Strcpy(path + len, in_file->d_name, MAX_FILE_NAME_LEN - len);
      printf("Path is %s\n", path);
      generateDedupDump(path, op);
   }

   if(fclose(op) != 0){
      printf("Error closing file %s\n", DST);
      return;
   }

   if(closedir(FD) == -1){
      printf("Error closing directory\n");
      return;
   }

   return;
}
