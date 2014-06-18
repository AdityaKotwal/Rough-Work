/*********************************************************
 * Copyright 2014 VMware, Inc.  All rights reserved.
 * -- VMware Confidential
 *********************************************************/

/*
 * push.c
 *
 * This module deals with functions to encode string values
 * to their corresponing md5 hash
 */

#include <stdio.h>
#include <string.h>
#include "dedup.h"

/*
 * --------------------------------------------------------
 *
 * getMD5 --
 *
 *    A function to generate MD5 hash of a string using
 *    funcitons available in the openSSL library.
 *
 * Side Effects:
 *    None
 * ----------------------------------------------------------
 */

void getMD5(const char *string,	 // IN: String buffer which has to be encoded
	    long len,		 // IN: Length of the string buffer
	    char *md5buf)	 // OUT: Pre-allocated buffer to store result
{
   unsigned char final[MD5_HASH_LEN];
   MD5_CTX ctx;
   int i;
   char *str;
   unsigned char b;

   MD5Init(&ctx);
   str = (char*) string;
   MD5Update(&ctx, str, len);
   MD5Final(final, &ctx);

   for(i=0; i<MD5_HASH_LEN; i++){
      b = final[i];
      md5buf[i * 2] = bin2Hex(b >> 4);
      md5buf[i * 2 + 1] = bin2Hex(b & 0x0F);
   }
   md5buf[MD5_HASH_LEN * 2]='\0';

   return;
}

/*
 * ----------------------------------------------------------
 *
 * bin2Hex --
 *
 *    A function to get the equivalent hexadecimal representation
 *    of a binary value passed.
 *
 * Side Effects:
 *    None
 *
 * Note:
 *    The 4 LSB bits must be 0 for the input
 * ---------------------------------------------------------
 */

char bin2Hex(unsigned char bin) // IN: the binary number passed
{			        //     with higher nibble set to 0
   return (bin < 10) ? (bin + '0') : (bin - 10 + 'A');
}
