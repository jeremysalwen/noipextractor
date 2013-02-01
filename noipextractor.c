#include "base64.h"
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <ctype.h>
#include <string.h>

#define USER_STR "username="
#define PASS_STR "&pass="

typedef struct {
	char		lastIP[16];
	uint16_t	interval;
	uint16_t	chksum;
	uint32_t	magic;
	uint16_t	rlength;
	uint16_t	elength;
	char		count;
	char		encrypt;
	char		nat;
	char		filler;
	char		device[16];
} CONFIG;

//Function from ThomasH on stackoverflow 
void urldecode2(char *dst, const char *src)
{
        char a, b;
        while (*src) {
                if ((*src == '%') &&
                    ((a = src[1]) && (b = src[2])) &&
                    (isxdigit(a) && isxdigit(b))) {
                        if (a >= 'a')
                                a -= 'A'-'a';
                        if (a >= 'A')
                                a -= ('A' - 10);
                        else
                                a -= '0';
                        if (b >= 'a')
                                b -= 'A'-'a';
                        if (b >= 'A')
                                b -= ('A' - 10);
                        else
                                b -= '0';
                        *dst++ = 16*a+b;
                        src+=3;
                } else {
                        *dst++ = *src++;
                }
        }
        *dst++ = '\0';
}

int main(int argc, char** argv) {
	if(argc<2) {
		fprintf(stderr, "Error: No config file was given to extract (it's likely named noip2.conf)\n");
		exit(1);
	}
	FILE* f=fopen(argv[1],"r");
	if(f==NULL) {
		fprintf(stderr, "Error: Unable to open config file\n");
		exit(2);
	}
	size_t CONFIG_SIZE= sizeof(CONFIG);
	CONFIG config;
	
	if(fread(&config,1,CONFIG_SIZE,f)!=CONFIG_SIZE) {
		fprintf(stderr, "Error: Unable to read config file or corrupt config file\n");
		exit(3);
	}
	size_t size = config.rlength;
	char* request = malloc(size + 1); // allow for bdecode expansion
	if (fread(request, 1, size,f) != size) {
		fprintf(stderr, "Error: Unable to read config file or corrupt config file \n");
		exit(4);
	}
	request[size] = 0;
	char* decoded=base64_decode(request);
	free(request);

	printf("DEBUG: Decoded request: %s\n",decoded);
	char* username=decoded+strlen(USER_STR);
	char* password=strstr(username,PASS_STR);
	if(password==NULL) {
		fprintf(stderr, "Error: Malformed configuration file\n");
		exit(5);
	}
	*password='\0';
	password+=strlen(PASS_STR);
	char* terminator=strchr(password,'&');
	if(terminator==NULL) {
		fprintf(stderr, "Error: Malformed configuration file\n");
		exit(6);
	}
	*terminator='\0';
	//Now we url decode the username and password (in place is safe)
	urldecode2(username,username);
	urldecode2(password,password);
	printf("Successfully extracted acount information\nUsername: %s\nPassword: %s\n",username,password);
	free(decoded);
	
}
