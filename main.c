#include <stdio.h>
#include <stdint.h>
#include <string.h>

#define DNS_HEADER_LEN 12
#define DNS_MAX_NAME_LEN 255
#define DNS_QUERY_MAX (DNS_HEADER_LEN + DNS_MAX_NAME_LEN + 4)// 4 FOR QTYPE AND QCLASS

//1 << 15 - n gives us position n

//derived from rfc 1035.
typedef struct dns_header_t{
	uint16_t id;
	uint16_t flags_and_codes;
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
}dns_header;

size_t encode_name(const char* name, uint8_t* out){
	size_t len = strlen(name);
	if(len + 2 > DNS_MAX_NAME_LEN) return 0; // + 2 for starting and end length byte.

	int j = 0;
	int currentLength = 0;
	int longestLength = 0;
	while(*(name + j) != '\0' && longestLength < 64){
		if(*(name + j) != '.'){
			currentLength++;
		}else{
			if(currentLength > longestLength) longestLength = currentLength;
			currentLength = 0;
		}

		j++;
		if(*(name + j) == '\0')longestLength = currentLength; // guards against label with no dots at all.
	}

	if(longestLength > 63) return 0;

	uint8_t* lengthLocation = out;

	uint8_t count = 0;
	int i = 0;

	while(*(name + i) != '\0'){
		if(*(name + i) != '.'){
			*(out + i + 1) = *(name + i);
			count++;
		}else{
			*(lengthLocation) = count;
			lengthLocation = (out + i + 1);
			count = 0;
		}
		i++;
	}

	*(lengthLocation) = count;
	*(out + i + 1) = 0x0; //end of name must be 0x0.
	return i + 2; //length of string, starting length byte and terminating length byte.
}

int main(int argc, char* argv[]){
	if (argc < 2) {
    	fprintf(stderr, "usage: %s <name>\n", argv[0]);
    	return 1;
	}

	size_t cursor = 0;
	uint8_t buf[DNS_QUERY_MAX];

	size_t n = encode_name(argv[1], buf);
	if (n == 0) { fprintf(stderr, "bad name\n"); return 1; }

	for (size_t k = 0; k < n; k++){
    	printf("%02x ", buf[k]);
	}

	printf("\n");

	return 0;
}
