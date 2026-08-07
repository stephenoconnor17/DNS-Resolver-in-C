#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

int main(int argc, char* argv[]){
	if (argc < 2) {
    	fprintf(stderr, "usage: %s <name>\n", argv[0]);
    	return 1;
	}

	srand(time(NULL));
	uint8_t buf[DNS_QUERY_MAX];

	uint16_t id = rand() & 0xFFFF; //important to save for once reply comes back.
	//not trustworthy security wise but fine for this little project.
	
	int sockfd = dns_socket(5);
	if(sockfd < 0) return 1;

	//build query
	size_t qlen = build_query(argv[1], buf, id);
	if(qlen == 0) return 1;

	uint8_t replyBuf[DNS_MAX_RESPONSE];

	ssize_t responseSize = send_query(sockfd, "198.41.0.4", buf, qlen, replyBuf, sizeof(replyBuf));
	if(responseSize < 0) return 1;

	int validReply = validate_reply(replyBuf, responseSize, buf, qlen, id);
	if(validReply != 0) return 1;

	printf("reply: %zd bytes\n", responseSize);

	dns_header rh;
	parse_header(replyBuf, DNS_MAX_RESPONSE, &rh);
	//printf("an=%u ns=%u ar=%u\n", rh.ancount, rh.nscount, rh.arcount);

	size_t cursor = DNS_HEADER_LEN;
	ssize_t r = skip_name(replyBuf, (size_t)responseSize, cursor);

	if(r < 0) return 1;

	cursor = r;

	if(cursor + 4 > (size_t)responseSize) return 1;

	cursor += 4;

	printf("records start at offset %zu\n", cursor);
	printf("\n");

	uint32_t recordAmount = rh.ancount + rh.arcount + rh.nscount;
	if(recordAmount > 100) return 1;

	dns_ns* records = malloc(sizeof(dns_ns) * 32);
	if(records == NULL) return 1;

	int validPairs = parse_records(replyBuf, sizeof(replyBuf), cursor, records, 32, (int)recordAmount);

	for(int i = 0; i < validPairs; i++){
		dns_ns rec = records[i];
		printf("name : %s address : %s\n", rec.name, rec.addr);
	}
	/*
	dns_record rec;
	ssize_t next = parse_record(replyBuf, responseSize, 28, &rec);
	printf("name=%s type=%u class=%u ttl=%u rdlen=%u next=%zd\n", rec.name, rec.type, rec.rclass, rec.ttl, rec.rdlength, next);
	
	char nameBuf[256];
	ssize_t rr = decode_name(replyBuf, responseSize, DNS_HEADER_LEN, nameBuf, sizeof(nameBuf));
	printf("decoded: %s, next offset %zd\n", nameBuf, rr);
	*/

	//free(records);
	close(sockfd);
	return 0;
}
