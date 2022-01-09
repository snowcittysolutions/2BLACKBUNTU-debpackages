/*
 * Copyright (C)  2011  Luca Vaccaro
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
#include "Utils.h"
#include "Volumes.h"
#include <string.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>
#include "Core.h"

/* The name of this program.*/
const char *program_name;


/* Prints usage information for this program to STREAM (typically
   stdout or stderr), and exit the program with EXIT_CODE. Does not
   return. */
void print_usage (FILE* stream, int exit_code)
{
	fprintf(stream,"%s v%s\n", SOFTWARE,VERSION);
	fprintf(stream,"Website: %s\n",WEBSITE);
	fprintf(stream,"Contact us: %s\n",EMAIL);
	fprintf(stream,"%s\n",MESSAGE);

	fprintf (stream, "\nUsage for Dictionary attack:\n"
			" %s -t truecrypt_file -w passwords_file [-k ripemd160 | -k sha512 | -k whirlpool] [-e aes | -e serpent | -e twofish] [-a blocks] [-b] [-H] [-r number]\n"
			"Usage for Alphabet attack:\n"
			" %s -t truecrypt_file -c alphabet [-s minlength] -m maxlength [-p string] [-k ripemd160 | -k sha512 | -k whirlpool] [-e aes | -e serpent | -e twofish] [-a blocks] [-b] [-H] [-r number]\n"
			, program_name, program_name);
	fprintf (stream, "\nOptions:\n"
			" -h --help					Display this information.\n"
			" -t --truecrypt <truecrypt_file>		Truecrypt volume file.\n"
			" -k --key <ripemd160 | sha512 | whirlpool>	Key derivation function (default ripemd160).\n"
			" -e --encryption <aes | serpent | twofish>	Encryption algorithm (default aes).\n"
			" -a --aggressive <blocks>			Number of parallel computations (board dependent).\n"
			" -w --wordlist <wordlist_file>			File of words, for Dictionary attack.\n"
			" -c --charset <alphabet>			Alphabet generator, for Alphabet attack.\n"
			" -s --startlength <minlength>			Starting length of passwords, for Alphabet attack (default 1).\n"
			" -m --maxlength <maxlength>			Maximum length of passwords, for Alphabet attack.\n"
			" -p --prefix <string>				Prefix the first part of the password, for Alphabet attack.\n"
			" -r --restore <number>				Restore the computation.\n"
			" -b --backup					Backup header instead of volume header.\n"
			" -H --hidden					Hidden Truecrypt volume.\n"
			" -v --verbose					Show computation messages.\n"
		);
	fprintf (stream, "\nSample for Dictionary attack:\n"
			" %s -t volume.tc -w dictionary.txt \n"
			"Sample for Alphabet attack:\n"
			" %s -t volume.tc -c \"1234567890\" -s 4 -m 6\n"
			, program_name, program_name);

	exit (exit_code);
}

/* Main program entry point. ARGC contains number of argument list
   elements; ARGV is an array of pointers to them. */
int main (int argc, char* argv[])
{
	int next_option;
	/* A string listing valid short options letters.*/
	const char* const short_options = "ht:w:c:m:s:a:k:r:e:p:vbH";
	/* An array describing valid long options. */
	const struct option long_options[] = {
		{ "help", 0, NULL, 'h' },
		{ "truecrypt",1,NULL, 't'},
		{ "wordlist",1, NULL, 'w' },
		{ "charset",1, NULL, 'c' },
		{ "maxlength",1, NULL, 'm' },
		{ "startlength",1, NULL, 's' },
		{ "aggressive",1,NULL, 'a' },
		{ "key",1,NULL, 'k' },
		{ "restore",1,NULL,'r'},
		{ "encryption",1,NULL, 'e' },
		{ "prefix",1,NULL, 'p' },
		{ "verbose", 0, NULL, 'v' },
		{ "backup", 0, NULL, 'b' },
		{ "hidden", 0, NULL, 'H' },
		{ NULL, 0, NULL, 0 }
		/* Required at end of array.
		 */
	};
	/* The name of the file of words */
	char* wordlist_filename = NULL;
	/* The name of the file of truecrypt volume */
	char* volume_filename = NULL;
	/* The charset string */
	char* charset = NULL;
	/*The max length of words generated from charset */
	int maxlength=0;
	/*The min length of words generated from charset */
	int minlength=0;
	/* The type of attack */
	int typeAttack=-1;
	/* Size of the block of parallel words*/
	int blocksize=0;
	/* Whether to display verbose messages. */
	int verbose = 0;
	/* Key derivation function. */
	char *keyDerivationFunction=NULL;
	/* Encryption algorithm. */
	char *encryptionAlgorithm=NULL;
	/* Restore point. */
	long int restore=0;
	/* Prefix string */
	char *prefix=NULL;
	/* Backup header. */
	CORE_backup=0;
	/* Hidden volume. */
	CORE_hidden=0;

	/* Remember the name of the program, to incorporate in messages.
	   The name is stored in argv[0]. */
	program_name = argv[0];
	do {
		next_option = getopt_long (argc, argv, short_options, long_options, NULL);
		switch (next_option)
		{
			case 'h':
				/* -h or --help */
				/* User has requested usage information. Print it to standard
				   output, and exit with exit code zero (normal termination). */
				print_usage (stdout, 0);
			case 't':
				/* -t or --truecrypt */
				/* This option takes an argument, the name of the truecrypt volume.*/
				volume_filename = optarg;
				break;
			case 'w':
				/* -w or --wordlist */
				/* This option takes an argument, the name of the wordlist file.*/
				wordlist_filename = optarg;
				typeAttack=0;
				break;
			case 'c':
				/* -c or --charset */
				/* This option takes an argument, the charset string*/
				charset = optarg;
				typeAttack=1;
				break;
			case 'm':
				/* -m or --maxlength */
				/* This option takes an argument, the maxlength of generated words*/
				maxlength = atoi(optarg);
				typeAttack=1;
				break;
			case 's':
				/* -s or --startlength */
				/* This option takes an argument, the startlength of generated words*/
				minlength = atoi(optarg);
				typeAttack=1;
				break;
			case 'a':
				blocksize = atoi(optarg);
				break;
			case 'r':
				restore = atol (optarg);
				break;
			case 'k':
				/* -k or --key */
				/* This option takes an argument, the key derivation function.*/
				keyDerivationFunction = optarg;
				break;
			case 'e':
				/* -e or --encryption */
				/* This option takes an argument, the encryption algorithm.*/
				encryptionAlgorithm = optarg;
				break;
			case 'p':
				prefix=optarg;
				break;
			case 'b':
				CORE_backup = 1;
				break;
			case 'H':
				CORE_hidden = 1;
				break;
			case 'v':
				verbose = 1;
				break;
			case '?':
				/* The user specified an invalid option. */
				/* Print usage information to standard error, and exit with exit
				   code one (indicating abnormal termination). */
				print_usage (stderr, 1);
			case -1:
				break;
				/* Done with options.
				 */
			default:
				/* Something else: unexpected.*/
				abort ();
		}

	} while (next_option != -1);

	/*
	 * The main program goes here.
	 */
	CORE_verbose=verbose;
	CORE_blocksize=blocksize;
	CORE_restore=restore;

	if (volume_filename!=NULL)
		CORE_volumePath=volume_filename;
	else
		print_usage (stdout, 0);

	if (encryptionAlgorithm==NULL)
		CORE_encryptionAlgorithm=AES;
	else if (strcasecmp(encryptionAlgorithm,"aes")==0)
		CORE_encryptionAlgorithm=AES;
	else if (strcasecmp(encryptionAlgorithm,"serpent")==0)
		CORE_encryptionAlgorithm=SERPENT;
	else if (strcasecmp(encryptionAlgorithm,"twofish")==0)
		CORE_encryptionAlgorithm=TWOFISH;
	else
		print_usage (stdout, 0);

	if (keyDerivationFunction==NULL)
		CORE_keyDerivationFunction=RIPEMD160;
	else if (strcasecmp(keyDerivationFunction,"ripemd160")==0)
		CORE_keyDerivationFunction=RIPEMD160;
	else if (strcasecmp(keyDerivationFunction,"sha512")==0)
		CORE_keyDerivationFunction=SHA512;
	else if (strcasecmp(keyDerivationFunction,"whirlpool")==0)
		CORE_keyDerivationFunction=WHIRLPOOL;
	else
		print_usage (stdout, 0);

	if (typeAttack==0) {
		CORE_typeAttack=ATTACK_DICTIONARY;
		if (wordlist_filename!=NULL)
			CORE_wordsPath=wordlist_filename;
		else
			print_usage (stdout, 0);
	} else if (typeAttack==1) {
		CORE_typeAttack=ATTACK_CHARSET;
		if (charset!=NULL)
			CORE_charset=charset;
		else
			print_usage (stdout, 0);

		if (maxlength>0)
			CORE_maxlength=maxlength;
		else
			print_usage (stdout, 0);
		if (minlength>0)
			CORE_minlength=minlength;
		else
			CORE_minlength=1;
		if (prefix!=NULL)
			CORE_prefix=prefix;
	} else
		print_usage (stdout, 0);



	core();

	return 0;
}

