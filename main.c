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
	
	//build query
	size_t j = build_query(argv[1], buf, id);

	/*
	//hex print.
	for (size_t k = 0; k < cursor; k++){
    	printf("%02x ", buf[k]);
	}
	*/
	uint8_t replyBuf[DNS_MAX_RESPONSE];

	ssize_t responseSize = send_query(sockfd, "198.41.0.4", buf, j, replyBuf, j);
	int validReply = validate_reply(replyBuf, responseSize, buf, j, id);
	printf("\n");

	return 0;
}
