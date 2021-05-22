#include <string>
#include <Windows.h>
#include <vector>
#include <iostream>

#include <openssl/pem.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/bio.h>
#include <openssl/err.h>
#include <stdio.h>

#include "Base64Encode.h"

using namespace std;

int padding = RSA_PKCS1_OAEP_PADDING;

RSA * createRSA(unsigned char * key, int ispublic)
{
	RSA *rsa = NULL;
	BIO *keybio;
	keybio = BIO_new_mem_buf(key, -1);
	if (keybio == NULL)
	{
		printf("Failed to create key BIO");
		return 0;
	}
	
	rsa = PEM_read_bio_RSAPrivateKey(keybio, NULL, NULL, NULL);
	if (rsa == NULL)
	{
		printf("Failed to create RSA");
	}

	BIO_free(keybio);
	return rsa;
}

int private_decrypt(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted){

	RSA * rsa = createRSA(key, 0);
	EVP_PKEY    *privKey = NULL;
	BIO         *bioPrivKey;
	size_t         outLen = 0, ret;

	if ((bioPrivKey = BIO_new(BIO_s_mem())))
	{
		// Read the private key from the RSA context into the memory BIO,
		// then convert it to an EVP_PKEY:
		if ((ret = PEM_write_bio_RSAPrivateKey(bioPrivKey, rsa, NULL, NULL, 0, NULL, NULL)) &&
			(privKey = PEM_read_bio_PrivateKey(bioPrivKey, NULL, NULL, NULL)))
		{
			EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new(privKey, NULL);

			EVP_PKEY_free(privKey);

			if (ctx)
			{
				if (EVP_PKEY_decrypt_init(ctx) > 0)
				{
					EVP_PKEY_CTX_ctrl_str(ctx, "rsa_padding_mode", "oaep");
					EVP_PKEY_CTX_ctrl_str(ctx, "rsa_oaep_md", "sha256");
					EVP_PKEY_CTX_ctrl_str(ctx, "rsa_mgf1_md", "sha256");

					outLen = 4098;
					ret = EVP_PKEY_decrypt(ctx, decrypted, &outLen, enc_data, data_len);
					if (ret > 0 && outLen > 0 && outLen <= 4098)
					{
						// Success :-)
					}
				}
				EVP_PKEY_CTX_free(ctx);
			}
		}

		BIO_free_all(bioPrivKey);
	}
	return ret;
}

int private_decrypt1(unsigned char * enc_data, int data_len, unsigned char * key, unsigned char *decrypted)
{
	RSA * rsa = createRSA(key, 0);
	int  result = RSA_private_decrypt(data_len, enc_data, decrypted, rsa, padding);
	return result;
}

void printLastError(const char *msg)
{
	char * err = (char*)malloc(130);;
	ERR_load_crypto_strings();
	ERR_error_string(ERR_get_error(), err);
	printf("%s ERROR: %s\n", msg, err);
	free(err);
}

bool ReadDataFromFile(const wstring& readFile, vector<BYTE>& fileContent)
{
	HANDLE hFile = CreateFile(readFile.c_str(),
		GENERIC_READ,
		0,
		NULL,
		OPEN_EXISTING,
		FILE_ATTRIBUTE_NORMAL,
		NULL);

	if (hFile == INVALID_HANDLE_VALUE)
	{
		printf("Unable to open file \"%ws\" for read with %ld.", readFile.c_str(), GetLastError());
		return false;
	}

	DWORD dwFileSize = GetFileSize(hFile, NULL);
	fileContent.resize(dwFileSize);

	DWORD dwBytesRead = 0;

	bool bResult = ReadFile(hFile, fileContent.data(), dwFileSize, &dwBytesRead, NULL);
	if (!bResult) {
		printf("Read file \"%ws\" failed with error:%ld.", readFile.c_str(), GetLastError());
	}

	CloseHandle(hFile);
	return bResult;
}

int RsaMain() {

	char plainText[2048 / 8] = "Hj0KKRoMPSUFLzoaMTYnLhg3BhEOPD47Pj80OSU6HDI="; //key length : 2048

	wstring pKeyFile = L"C:\\Users\\Dhamu\\Desktop\\DummyProjects\\OpenSSLbasedEncryptionDecryption\\k8s-key.pem";
	vector<BYTE> pKey;
	if (!ReadDataFromFile(pKeyFile, pKey)) {
		cout << "TOO BAD";
	}

	string encryptedBase64 = "jRJ3Lmy1/5dsJP1sDNTCIPcSN4V41GnBqfCZV7s7w6XHEKCupbUJPodkRwaA2Ff+acyFYzQjapJk4S2pX+YL6G45fOqmxgH1fNBR0g01JIEGqRMCxhNRRuYZJ/AtvMrPhAMfYBRphMlW9rEiOrn3+4rm0kr6wav+I98NuLvQtTu5nWKeXbgbOUlFvTdX+ZNRENFSpOmRZ5WhM4btTzPI/F1MUOXdmHxoU7//BXfYyLM457prwc3aQxmO/AWyHYPfkoMu9h5wPaQdID0BCCSUpG7DbvVkSoqSxSgZZse8Og6t/zaRbUCLq+WIzYuBEWfrqzxjStvJoHXz4jf3GzGo0DoNBMIsHXOsej7vFx7Ts6f25yOIU9HJll2QrjuSGuEnyOx+X7DRXzDKL5IC/pSbe+JgGMlN2XQ7vFqLLmwEA/kwtcCxuv6d2cA36C8dIEJ4WQdBMNH60SrG62hZs/HQf0g8NrcNwBZ5WyVkZz8w6GbzSOCisvLSpsu88gV0yo9H+LBEn56TSmkfjJT1nbR/FIiweMMjV4pqJAdImJ2lxdmU29Ca8AhukGRvygtT6K1edOAxhyDTbiF4vQSeyKCCfy6lXHMo/U3fTjNGBxp/Ew4uwhmPB7t5FyyiY6Qv4/2sRw8F0yW4+KcMe0ofI8bIW6BioYw7YxR1mo5db7ZvZdA=";
	std::vector<unsigned char> encrypted = Base64Decode(encryptedBase64);

	unsigned char decrypted[4098] = {};

	int decrypted_length = private_decrypt((unsigned char *)encrypted.data(), encrypted.size(), (unsigned char *)pKey.data(), decrypted);
	if (decrypted_length == -1)
	{
		printLastError("Private Decrypt failed ");
		exit(0);
	}

	printf("Decrypted Text: %s\n", decrypted);
}