#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <stdlib.h>
#include <arpa/inet.h>
#include <time.h>

#define DNS_HEADER_LEN 12
#define DNS_MAX_NAME_LEN 255
#define DNS_QUERY_MAX (DNS_HEADER_LEN + DNS_MAX_NAME_LEN + 4)// 4 FOR QTYPE AND QCLASS

//x << 15 - n gives us position 15 - n with length x
#define DNS_QR_MASK (1 << 15)
#define DNS_OPCODE_MASK (0xF << 11)
#define DNS_AA_MASK (1 << 10)
#define DNS_TC_MASK (1 << 9)
#define DNS_RD_MASK (1 << 8)
#define DNS_RA_MASK (1 << 7)
#define DNS_Z_MASK (0x7 << 4)
#define DNS_RCODE_MASK (0xF)

#define DNS_QR(f) (((f) & DNS_QR_MASK) >> 15)
#define DNS_OPCODE(f) (((f) & DNS_OPCODE_MASK) >> 11)
#define DNS_AA(f) (((f) & DNS_AA_MASK) >> 10)
#define DNS_TC(f) (((f) & DNS_TC_MASK) >> 9)
#define DNS_RD(f) (((f) & DNS_RD_MASK) >> 8)
#define DNS_RA(f) (((f) & DNS_RA_MASK) >> 7)
#define DNS_Z(f) (((f) & DNS_Z_MASK) >> 4)
#define DNS_RCODE(f) ((f) & DNS_RCODE_MASK)

//derived from rfc 1035.
typedef struct dns_header_t{
	uint16_t id;
	uint16_t flags_and_codes; // & with masks for value.
	uint16_t qdcount;
	uint16_t ancount;
	uint16_t nscount;
	uint16_t arcount;
}dns_header;

_Static_assert(sizeof(dns_header) == DNS_HEADER_LEN, "dns_header struct is not 12 bytes long");

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

	srand(time(NULL));
	size_t cursor = 0;
	uint8_t buf[DNS_QUERY_MAX];

	dns_header header;
	uint16_t id = rand() & 0xFFFF; //important to save for once reply comes back.
	//not trustworthy security wise but fine for this little project.
	header.id = htons(id);

	uint16_t flags = 0;
	//if flags wasnt 0 clearing would be in order.

	//these are useless but just practice for me.

	flags &= ~DNS_QR_MASK;	//qr 0
	flags |= (0 & 0xF) << 11; //opcode 0;
	flags &= ~DNS_AA_MASK; //aa 0
	flags &= ~DNS_TC_MASK; //tc 0
	flags &= ~DNS_RD_MASK; //rd 0
	flags &= ~DNS_RA_MASK; //ra 0
	flags |= (0 & 0x7) << 4; //z 0
	flags |= (0 & 0xF); //rcode 0
	
	header.flags_and_codes = flags;
	header.qdcount = htons(0x1);
	header.ancount = 0;
	header.nscount = 0;
	header.arcount = 0;

	memcpy(buf + cursor, &header, DNS_HEADER_LEN);//write the header.
	cursor += DNS_HEADER_LEN;

	//write the name
	size_t n = encode_name(argv[1], buf + cursor);
	if (n == 0) { fprintf(stderr, "bad name\n"); return 1; }
	cursor += n;

	uint16_t qtype = htons(1);
	memcpy(buf + cursor, &qtype, sizeof(qtype));
	cursor += 2;

	uint16_t qclass = htons(1);
	memcpy(buf + cursor, &qclass, sizeof(qclass));
	cursor += 2;

	//hex print.
	
	for (size_t k = 0; k < cursor; k++){
    	printf("%02x ", buf[k]);
	}
	

	printf("\n");

	return 0;
}
