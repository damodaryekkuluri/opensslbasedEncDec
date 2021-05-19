// OpenSSLbasedEncryptionDecryption.cpp : This file contains the 'main' function. Program execution begins and ends there.
//

#include <fstream>
#include <iostream>
#include <stdio.h>
#include <string>
#include <openssl/aes.h>
using namespace std;


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <openssl/aes.h>
#include <openssl/rand.h>
#include <bitset>
#include "Base64Encode.h"

// a simple hex-print routine. could be modified to print 16 bytes-per-line
static void hex_print(const void* pv, size_t len)
{
	const unsigned char * p = (const unsigned char*)pv;
	if (NULL == pv)
		printf("NULL");
	else
	{
		size_t i = 0;
		for (; i < len; ++i)
			printf("%04X ", *p++);
	}
	printf("\n");
}
int RsaMain();

#if 0
// main entrypoint
int main(int argc, char **argv)
{
	/*
	printf("start\n");
	string str{"C:\\Users\\win10pro\\Desktop\\CSO–FA7000-20-S-C001"};
	printf("%s", str.c_str());
	printf("end\n");
	return 0;
	*/
	constexpr int keylength = 16; //bytes;

	/* generate a key with a given length */
	unsigned char aes_key[] = "DATANCHOR_MASTER";
	/* init vector */
	//unsigned char iv_enc[AES_BLOCK_SIZE] = { 0x0F, 0x05, 0x00, 0x07, 0x06, 0x02, 0x02, 0x06, 0x07, 0x06, 0x07, 0x04, 0x06, 0x0F, 0x00, 0x0C };

	unsigned char iv_enc[AES_BLOCK_SIZE] = { 0xF, 0x5, 0x0, 0x7, 0x6, 0x2, 0x2, 0x6, 0x7, 0x6, 0x7, 0x4, 0x6, 0xF, 0x0, 0xC };
	unsigned char iv_dec[AES_BLOCK_SIZE] = { 0xF, 0x5, 0x0, 0x7, 0x6, 0x2, 0x2, 0x6, 0x7, 0x6, 0x7, 0x4, 0x6, 0xF, 0x0, 0xC };

	//unsigned char iv_dec[AES_BLOCK_SIZE] = { 0x7F, 0x65, 0x60, 0x77, 0x46, 0x32, 0x12, 0x26, 0x47, 0x16, 0x47, 0x34, 0x56, 0x6F, 0x20, 0x4C };

	unsigned char inputdata[] = "AAsZDAs5GiUsECcMERY9GAM7GCY+ISY7Pxs8Kh41CDg=";
	size_t inputlength = sizeof(inputdata) / sizeof(inputdata[0]);
	printf("Inputdata size = %ld\n", sizeof(inputdata[0]));

	// buffers for encryption and decryption
	const size_t encslength = ((inputlength + AES_BLOCK_SIZE) / AES_BLOCK_SIZE) * AES_BLOCK_SIZE;
	unsigned char* enc_out = new unsigned char(encslength);
	unsigned char* dec_out = new unsigned char(inputlength);
	memset(enc_out, 0, encslength);
	memset(dec_out, 0, inputlength);

	printf("Inputdata size = %ld, enc size = %ld\n", inputlength, encslength);

	// so i can do with this aes-cbc-128 aes-cbc-192 aes-cbc-256
	AES_KEY enc_key, dec_key;
	AES_set_encrypt_key(aes_key, keylength * 8, &enc_key);
	AES_set_decrypt_key(aes_key, keylength * 8, &dec_key);

	do {
		AES_cbc_encrypt((unsigned char *)inputdata, (unsigned char *)enc_out, inputlength, &enc_key, iv_enc, AES_ENCRYPT);
	} while (false);

	do {
		AES_cbc_encrypt((unsigned char *)enc_out, (unsigned char *)dec_out, encslength, &dec_key, iv_dec, AES_DECRYPT);
	} while(false);

	/*
	std::vector<unsigned char> out, reout;
	for (int i = 0; i < encslength; i++) {
		out.push_back(static_cast<unsigned char>(enc_out[i]));
	}
	string outstr = Base64Encode(out);
	//printf("\nOutstr = %s", outstr.c_str());

	reout = Base64Decode(outstr);
	int j = 0;
	for (auto x : out) {
		printf("%d ", x == reout[j++]);
	}
	*/

	printf("\noriginal:\t");

	for (int i = 0; i < inputlength; i++) {
		printf("%c ", inputdata[i]);
	}
	printf("\n");

	for (int i = 0; i < inputlength; i++) {
		printf("%d ", inputdata[i]);
	}


	printf("\nencrypt:\t");
	for (int i = 0; i < encslength; i++) {
		printf("%c ", enc_out[i]);
	}
	printf("\n");
	for (int i = 0; i < encslength; i++) {
		printf("%d ", enc_out[i]);
	}

	printf("\ndecrypt:\t");
	for (int i = 0; i < inputlength; i++) {
		printf("%c ", dec_out[i]);
	}
	printf("\n");

	for (int i = 0; i < inputlength; i++) {
		printf("%d ", dec_out[i]);
	}
	return 0;
}
#endif


#if 0

int main(int argc, char **argv){
	unsigned char xorKey = 'D';
	unsigned char inputdata[] = "AAsZDAs5GiUsECcMERY9GAM7GCY+ISY7Pxs8Kh41CDg=";
	size_t inputlength = sizeof(inputdata) / sizeof(inputdata[0]);
	printf("Inputdata size = %ld\n", sizeof(inputdata[0]));

	unsigned char* enc_out = new unsigned char(inputlength);
	memset(enc_out, 0, inputlength);

	unsigned char* dec_out = new unsigned char(inputlength);
	memset(dec_out, 0, inputlength);

	std::vector<unsigned char> bv, bd;
	for (unsigned int i = 0; i < inputlength -1; i++) {
		enc_out[i] = inputdata[i] ^ xorKey;
		dec_out[i] = enc_out[i] ^ xorKey;
		unsigned char c = enc_out[i];
		bv.push_back(c);
		printf("%c - %c - %c\n", inputdata[i], enc_out[i], dec_out[i]);
	}

	string b64 = Base64Encode(bv);
	printf("b64 = %s", b64.c_str());

	bd = Base64Decode(b64);

	for (unsigned int i = 0; i < inputlength - 1; i++) {
		if(bd[i] != enc_out[i]){
			printf("failed\n");
		}
	}
	printf("Pass\n");
	return 0;
}

#endif



/*
void main()
{

	// Buffers
	unsigned char inbuffer[1024] = { 0 };
	unsigned char encryptedbuffer[1024] = { 0 };
	unsigned char outbuffer[1024] = { 0 };


	// CODE FOR ENCRYPTION
	//--------------------
	unsigned char oneKey[] = "DATANCHOR_MASTER";
	AES_KEY enckey;
	AES_KEY deckey;

	AES_set_encrypt_key(oneKey, 128, &enckey);
	AES_set_decrypt_key(oneKey, 128, &deckey);

	//--------------------


	string straa("AAsZDAs5GiUsECcMERY9GAM7GCY+ISY7Pxs8Kh41CDg=");
	memcpy((char*)inbuffer, straa.c_str(), straa.size()+1);


	printf("%s\n", inbuffer);
	//this prints out fine

	AES_encrypt(inbuffer, encryptedbuffer, &enckey);
	//printf("%s",encryptedbuffer);
	//this is expected to pring out rubbish, so is commented

	AES_decrypt(encryptedbuffer, outbuffer, &deckey);
	printf("%s\n", outbuffer);

	getchar();

}
*/

int main() {
	return RsaMain();
}