//The code is not perfect, but demonstrates the given problem.
//The code is released under GPL (http://www.gnu.org/licenses/gpl.html), by Laszlo Toth.
//Use the code at your own responsibility.
//For more information: http://www.soonerorlater.hu/index.khtml?article_id=512



#include "stdafx.h"
#include <string.h>
#include <openssl/evp.h> 
#include <openssl/sha.h>
#include <openssl/md5.h>
#include "getopt.h"

//test1:test1 S:18C314BE125DF23689215C78C33F623AABF1152E 7FD52BC80AA5836695D4

int HexStringtoBinArray(char* str, unsigned char* array);

int main(int argc, char* argv[])
{
	
	unsigned char key_hash[24];
	unsigned char iv[16]={0,0,0,0,0,0,0,0,0,0,0,0,0,0,0,0};

	//AUTH_SESSKEY server
	unsigned char srv_authsk[256];
	unsigned char decr_srv_authsk[256];
	//AUTH_SESSKEY client
	unsigned char cl_authsk[256];
	unsigned char decr_cl_authsk[256];
	//Combined session keys
	unsigned char csk[24];
	unsigned char md1[16];
	unsigned char md2[16];
	//AUTH_PASSWORD
	unsigned char authp[256];
	int authp_len=32;
	unsigned char decr_authp[256];

	int outlen;
	int outlen2;
	EVP_CIPHER_CTX ctx;
	

	char c;
	int args=0;
	while ((c = getopt(argc, argv, "h:a:s:c:")) != -1){
		switch (c) {
			case 'h':
				if(strlen(optarg)!=40){
					printf("Wrong hash format!\n");
					return -1;
				};
				HexStringtoBinArray(optarg,key_hash);
				for(int i=20;i<24;i++){
					key_hash[i]=0;
				}
				args++;
				break;
			case 'a':
				if(strlen(optarg) > 256){
					printf("Wrong AUTH_PASSWORD format!\n");
					return -1;
				};
				authp_len=HexStringtoBinArray(optarg,authp);
				args++;
				break;
			case 's':
				if(strlen(optarg)!=96){
					printf("Wrong server session key format!\n");
					return -1;
				};
				HexStringtoBinArray(optarg,srv_authsk);
				args++;
				break;
			case 'c':
				if(strlen(optarg)!=96){
					printf("Wrong client session key format!\n");
					return -1;
				};
				HexStringtoBinArray(optarg,cl_authsk);
				args++;
				break;
		}
	}

	if(args!=4){
		printf("%s -s srv session key -c client session key -h password hash -a auth password\n", argv[0]);
		return -1;
	}
	
	//Decrypt AUTH_SESSKEY server
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key_hash, iv);
	EVP_DecryptUpdate(&ctx, decr_srv_authsk, &outlen, srv_authsk, 48);
	EVP_DecryptFinal_ex(&ctx, decr_srv_authsk+32, &outlen);
	EVP_CIPHER_CTX_cleanup(&ctx);

	//Decrypt AUTH_SESSKEY Client
	EVP_CIPHER_CTX_cleanup(&ctx);
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, key_hash, iv);
	EVP_DecryptUpdate(&ctx, decr_cl_authsk, &outlen, cl_authsk, 48);
	EVP_DecryptFinal_ex(&ctx, decr_cl_authsk+32, &outlen);
	EVP_CIPHER_CTX_cleanup(&ctx);

	//Combine decrypted server and decrypted client sessionkey
	for(int m=0; m<24; m++){
		csk[m]=decr_srv_authsk[m+16] ^ decr_cl_authsk[m+16];
	}
	MD5(csk, 16, md1);
	MD5(csk+16,8,md2);
	memcpy(csk,md1,16);
	memcpy(csk+16,md2,8);
	
	printf("\nThe AUTH_PASSWORD encryption key is: \n");
	for(int i=0;i<24;i++){
		printf("%X", csk[i]);
	}
	printf("\n");

	//Decrypt AUTH_PASSWORD
	EVP_CIPHER_CTX_init(&ctx);
	EVP_DecryptInit_ex(&ctx, EVP_aes_192_cbc(), NULL, csk, iv);
	EVP_DecryptUpdate(&ctx, decr_authp, &outlen, authp, authp_len);
	EVP_DecryptFinal_ex(&ctx, decr_authp+outlen, &outlen2);
	EVP_CIPHER_CTX_cleanup(&ctx);

	printf("\nThe password is: ");
	for(int i=16;i<outlen+outlen2;i++){
		printf("%c", decr_authp[i]);
	}
	printf("\n");

	return 0;


}

int HexStringtoBinArray(char* str, unsigned char* array){
	
	int alen=strlen(str)/2;
	unsigned char t[2];
	unsigned int hexc;
	int j=0;

	for(int i=0;i<strlen(str);i=i+2){
		t[0]=str[i];
		t[1]=str[i+1];
		hexc = t[0]-48;
		if (hexc > 9) hexc-=7;
		array[j]=hexc*16;
		hexc = t[1]-48;
		if (hexc > 9) hexc-=7;
		array[j]+=hexc;
		j++;
	}
	return j;
}
