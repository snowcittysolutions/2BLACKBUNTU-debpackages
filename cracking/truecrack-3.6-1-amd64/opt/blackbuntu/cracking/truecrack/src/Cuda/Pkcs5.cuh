/*
 * Copyright (C)  2011  Luca Vaccaro
 * Based on TrueCrypt, freely available at http://www.truecrypt.org/
 *
 * TrueCrack is free software; you can redistribute it and/or
 * modify it under the terms of the GNU General Public License
 * as published by the Free Software Foundation; either version 3
 * of the License, or (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301, USA.
 *
 */
/*
 Legal Notice: Some portions of the source code contained in this file were
 derived from the source code of Encryption for the Masses 2.02a, which is
 Copyright (c) 1998-2000 Paul Le Roux and which is governed by the 'License
 Agreement for Encryption for the Masses'. Modifications and additions to
 the original source code (contained in this file) and all other portions
 of this file are Copyright (c) 2003-2008 TrueCrypt Developers Association
 and are governed by the TrueCrypt License 3.0 the full text of which is
 contained in the file License.txt included in TrueCrypt binary and source
 code distribution packages. */

#ifndef TC_HEADER_CUDAPKCS5
#define TC_HEADER_CUDAPKCS5

#include "Tcdefs.h"

#if defined(__cplusplus)
extern "C"
{
#endif

#include "Rmd160.alternative.cuh"
#include "Sha2.cuh"
#include "Whirlpool.cuh"

#define MAX_BLOCKS		12


struct supportPkcs5_t {	
	unsigned char cj[RIPEMD160_DIGESTSIZE], ck[RIPEMD160_DIGESTSIZE];
	unsigned char cinit[128];
	unsigned char ccounter[4];
	unsigned char cpad[65];  // outer -inner padding - key XORd with ipad 
	unsigned char ctk[RIPEMD160_DIGESTSIZE];
	RMD160_CTX ccontext;
	RMD160_CTX ctctx;
};

typedef struct supportPkcs5_t SupportPkcs5;

__device__ void cuda_hmac_sha512 (unsigned char *k, int lk, unsigned char *d, int ld, unsigned char *out, int t);
__device__ void cuda_derive_u_sha512 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b);
__device__ void cuda_derive_key_sha512 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen);


__device__ void cuda_hmac_whirlpool(  unsigned char *k, int lk, unsigned char *d, unsigned char *out,int t);
__device__ void cuda_derive_u_whirlpool (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b);
__device__ void cuda_derive_key_whirlpool (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen);

__device__ void cuda_hmac_ripemd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest);
__device__ void cuda_derive_u_ripemd160 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *u, int b);
__device__ void cuda_derive_key_ripemd160 (unsigned char *pwd, int pwd_len, unsigned char *salt, int salt_len, int iterations, unsigned char *dk, int dklen);

/*
__device__ void hmac_ripemd160 (char *key, int keylen, char *input, int len, char *digest);
__device__ void derive_u_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *u, int b);
__device__ void derive_key_ripemd160 (char *pwd, int pwd_len, char *salt, int salt_len, int iterations, char *dk, int dklen);

__device__ void cuda_Pbkdf2 ( unsigned char *salt, unsigned char *pwd, int pwd_len, unsigned char *headerkey) ;
__device__ void cuda_hmac_ripemd160 (unsigned char *key, int keylen, unsigned char *input, int len, unsigned char *digest, SupportPkcs5 *sup);
*/


#if defined(__cplusplus)
}
#endif

#endif // CUDAPKCS5
