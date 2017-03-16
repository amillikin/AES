/********************************************************************************************
*										DES.cpp 											*
*																							*
*	DESCRIPTION: A DES encrypter and descripter that accepts filesizes up to 31-bytes.		*
*				 Input Parameters: DES <-action> <key> <mode> <infile> <outfile>.			*
*				 Accepted Actions: "-E" (encrypt), "-D" (decrypt)							*
*				 Accepted Keys: 16-Bit Hex string, 8-bit Char string						*
*				 Accepted Modes: EBC, CBC													*
*																							*
*																							*
*	AUTHOR: Aaron Millikin											START DATE: 2/7/2017	*
*********************************************************************************************/

#include "stdafx.h"
#include <intrin.h>
#include <iostream>
#include <iomanip>
#include <string>
#include <fstream>
#include <algorithm>
#include <cstdio>
#include <ctime>

using namespace std;
typedef unsigned long long ull;
int keyType;
FILE *inStream, *outStream;

//Organizes the steps for encryption - ARM
ull des(ull block, string actionType) {
	/*	Passes block through initial permutation
	Splits block into 32-bit leftIn and rightIn halves
	leftOut set to rightIn
	rightIn passed through expansion permutation
	rightIn XORed with round key
	rightIn passed through substitution boxes
	rightIn passed through straight permutation box
	rightOut = result of rightIn XORed with LeftIn
	leftOut and rightOut are joined back together to form 64-bit output
	Output passed through final permutation before returning to be saved in the outFile
	*/
	ull left, right, tempR;
	block = ip(block);
	left = ((block >> 32) & 0xffffffff);
	right = (block & 0xffffffff);
	for (int i = 0; i <= 15; i++) {
		//Direction keys are applied is determined by actionType passed in
		if (actionType == "E") {
			tempR = right;
			right = ep(right);
			right ^= roundkey[i];
			right = sb(right);
			right = sp(right);
			right = right ^ left;
			left = tempR;
		}
		else if (actionType == "D") {
			tempR = right;
			right = ep(right);
			right ^= roundkey[15 - i];
			right = sb(right);
			right = sp(right);
			right = right ^ left;
			left = tempR;
		}
	}
	block = ((right << 32) | left);
	block = fp(block);
	return block;
}

//Checks valid mode - ARM
bool validMode(string mode) {
	if (mode == "ECB" || mode == "CBC") {
		return true;
	}
	else {
		cout << "Not a valid mode. Valid modes include: ECB, CBC" << endl;
		return false;
	}
}

//Returns type of key used: 1) Hex, 2) 8-char (no space) 3) 8-char (with spaces). Else 0 if not valid. - ARM
int getKeyType(string strIn) {
	if (strIn.length() == 16) {
		for (int i = 0; i < 16; i++) {
			if (!isxdigit(strIn[i])) {
				cout << "Not a valid key. Must be 16-bit hex or 8-char" << endl;
				return 0;
			}
		}
		return 1;
	}
	else if (strIn.length() == 10 && strIn.substr(0, 1) == "'" && strIn.substr(9, 1) == "'") {
		return 2;
	}
	else {
		cout << "Not a valid key. Must be 16-bit hex or 8-char" << endl;
		return 0;
	}
}

//Checks valid action - ARM
bool validAction(string action) {
	if (action == "-E" || action == "-D") {
		return true;
	}
	else {
		cout << "Not a valid action. Valid actions include: -E, -D" << endl;
		return false;
	}
}

//Creates necessary hex bytes to and with buffer that should contain less than 8 bytes
ull getHexfBytes(size_t bytesLeft) {
	ull hexBytes = 0;
	for (size_t i = 0; i < bytesLeft; i++) {
		hexBytes <<= 8;
		hexBytes |= 0xff;
	}
	return hexBytes;
}

//Creates Random Pad Bits
ull getRandBits(int numToPad) {
	ull randBytes = 0;
	srand((unsigned int)time(NULL));
	for (int i = 0; i < numToPad; i++) {
		randBytes <<= 8;
		randBytes |= (rand() % 255);
	};
	return randBytes;
}

//Converts a string to all uppercase characters - ARM
string upCase(string str) {
	transform(str.begin(), str.end(), str.begin(), toupper);
	return str;
}

void prompt()
{
	cout << "Welcome to Aaron's DES Encrypter/Decrypter!" << endl;
	cout << "Accepted input: DES <-action> <key> <mode> <infile> <outfile>" << endl;
}

int main(int argc, char* argv[]) {
	clock_t startTime = clock(), endTime;
	double secondsElapsed;
	string action, mode, key;
	streampos begF, endF;
	ull hKey, block, iv, tempIV;
	int bytesLeft, size, shiftAmt, writeSize;
	errno_t err;

	if (argc != 6) {
		cout << "Incorrect number of arguments supplied." << endl;
		prompt();
		return 1;
	}

	action = upCase(argv[1]);
	if (!validAction(action)) {
		prompt();
		return 1;
	}
	action = action.substr(1, 1);
	key = argv[2];
	if (getKeyType(key) == 2) {
		hKey = (((ull)key[1] << 56) + ((ull)key[2] << 48) + ((ull)key[3] << 40) + ((ull)key[4] << 32) + ((ull)key[5] << 24) + ((ull)key[6] << 16) + ((ull)key[7] << 8) + (ull)key[8]);
	}
	else {
		hKey = strtoull(argv[2], nullptr, 16);
	}

	mode = upCase(argv[3]);
	if (!validMode(mode)) {
		prompt();
		return 1;
	}

	err = fopen_s(&inStream, argv[4], "rb");
	if (!(err == 0)) {
		cout << "Can't open input file " << argv[4] << endl;
		prompt();
		return 1;
	}

	err = fopen_s(&outStream, argv[5], "wb");
	if (!(err == 0)) {
		cout << "Can't open output file " << argv[5] << endl;
		prompt();
		return 1;
	}

	//	Determines length of file. - ARM
	fseek(inStream, 0, SEEK_END);
	size = ftell(inStream);
	rewind(inStream);

	//	Filesize limit of 31 bits. - ARM
	if (size > 2147483647) {
		cout << "File is too large to open. Must be <= 31 bits of data." << endl;
		prompt();
		return 1;
	}
	/*	Initialize block to 0, writeSize to 8, and generate round keys with hKey.
	When encrypting, need to encrypt filesize left padded with 32 random bits.
	When decrypting, need to check filesize by running first block through DES and
	keeping only the right half by ANDing with 0xffffffff. Take inStream filesize
	subtract 8 bytes (that were added from the filesize on encryption), then
	subtract the newly decrypted filesize to determine any excess bytes.
	This value will be the number of random bytes padded on, so subtracting this number
	from 8-bytes will give the number of padded bytes (8-padded bytes will be what we want to keep)
	*/
	block = 0;
	writeSize = 8;
	keygen(hKey);

	if (action == "E") {
		//Encrypting size block. Pad size with 32 random bytes.
		//If CBC, first block is iv set to 64 random bits. XOR plaintext with IV.
		//		  Then write encrypted iv to outfile. Next iv = size block ciphertext.

		block = size;
		block = ((getRandBits(32) << 32) | size);

		if (mode == "CBC") {
			iv = getRandBits(64);
			block ^= iv;
			iv = des(iv, action);
			iv = _byteswap_uint64(iv);
			fwrite(reinterpret_cast<char*>(&iv), 1, 8, outStream);
		}

		block = des(block, action);

		if (mode == "CBC") {
			iv = block;
		}

		block = _byteswap_uint64(block);
		fwrite(reinterpret_cast<char*>(&block), 1, 8, outStream);
		bytesLeft = (size % 8);
	}
	else {
		//Decrypting. If CBC, read first block -> decrypt = IV. Then read size block.
		//			  Else, just read size block.
		if (mode == "CBC") {
			fread_s(reinterpret_cast<char*>(&iv), 8, 1, 8, inStream);
			iv = _byteswap_uint64(iv);
			iv = des(iv, action);
		}

		fread_s(reinterpret_cast<char*>(&block), 8, 1, 8, inStream);
		block = _byteswap_uint64(block);

		//If CBC, next round's iv = ciphertext block
		if (mode == "CBC") {
			tempIV = block;
		}

		block = des(block, action);

		//If CBC, xor block with iv.
		if (mode == "CBC") {
			block ^= iv;
			iv = tempIV;
			bytesLeft = ((size - 16) - (block & 0xffffffff));
		}
		else {
			bytesLeft = ((size - 8) - (block & 0xffffffff));
		}
	};


	// If filesize is less than 8 bytes, only read that amount, padding appropriately before passing through DES.
	// Guaranteed to be encrpytion if this is true because an encrypted file being decrypted would have at least 9 bytes.
	if (size < 8) {
		fread_s(reinterpret_cast<char*>(&block), bytesLeft, 1, bytesLeft, inStream);
		block = _byteswap_uint64(block);
		block = (((block & getHexfBytes(bytesLeft)) << (8 - bytesLeft)) | (getRandBits(8 - bytesLeft)));
		if (mode == "CBC") {
			block ^= iv;
		}

		block = des(block, action);
	}

	// Read file while successfully reading eight 1-byte items, pass through DES, write to outFile.
	while (fread_s(reinterpret_cast<char*>(&block), 8, 1, 8, inStream) == 8) {
		block = _byteswap_uint64(block);

		//If CBC and Encrypting, XOR block with iv
		//If CBC and Decrypting, save ciphertext block for next iv in tempIV
		if (mode == "CBC" && action == "E") {
			block ^= iv;
		}
		else if (mode == "CBC" && action == "D") {
			tempIV = block;
		}

		block = des(block, action);

		//If CBC and Encrypting, set next iv to ciphertext block
		//If CBC and Decrypting, XOR block with iv, set next iv from tempIV
		if (mode == "CBC" && action == "D") {
			block ^= iv;
			iv = tempIV;
		}
		else if (mode == "CBC" && action == "E") {
			iv = block;
		}

		if (action == "D" && (ftell(inStream) == size)) {
			shiftAmt = (bytesLeft * 8);
			block >>= shiftAmt;
			writeSize = (8 - bytesLeft);
			fwrite(reinterpret_cast<char*>(&block), 1, writeSize, outStream);
			goto END;
		}

		block = _byteswap_uint64(block);
		fwrite(reinterpret_cast<char*>(&block), 1, writeSize, outStream);
		block = 0;
	};

	// Catch any bytes left over, push them left the appropriate amount, pad with random bytes.
	if ((bytesLeft > 0) && (action == "E")) {
		block &= getHexfBytes(bytesLeft);
		shiftAmt = ((8 - bytesLeft) * 8);
		block <<= shiftAmt;
		block |= getRandBits(8 - bytesLeft);

		if (mode == "CBC" && action == "E") {
			block ^= iv;
		}

		block = des(block, action);

		if (mode == "CBC" && action == "D") {
			block ^= iv;
		}

		block = _byteswap_uint64(block);
		fwrite(reinterpret_cast<char*>(&block), 1, writeSize, outStream);
	}

END:
	fclose(inStream);
	fclose(outStream);
	endTime = clock();
	secondsElapsed = double(endTime - startTime) / CLOCKS_PER_SEC;
	cout << fixed << setprecision(3);
	cout << secondsElapsed << " Seconds Elapsed." << endl;

	return 0;
}