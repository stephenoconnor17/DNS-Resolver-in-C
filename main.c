#include "dns.h"
#include <stdio.h>
#include <stdlib.h>
#include <time.h>

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

	printf("\n");

	return 0;
}
