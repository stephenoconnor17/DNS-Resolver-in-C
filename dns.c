#include "dns.h"
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/time.h>
#include <unistd.h>

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

int dns_socket(int timeoutSeconds){
	int sockfd = socket(AF_INET, SOCK_DGRAM, 0);

	if(sockfd == -1){
		perror("socket");
		return -1;
	}
	
	struct timeval tv;
	tv.tv_sec = timeoutSeconds;
	tv.tv_usec = 0;

	int success = setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
	if(success == -1){
		perror("setsockopt");
		close(sockfd);
		return -1;
	}

	return sockfd;
}

size_t build_query(const char* name, uint8_t* buf, uint16_t id){
	size_t cursor = 0;
	dns_header header;
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
	size_t n = encode_name(name, buf + cursor);
	if (n == 0) { fprintf(stderr, "bad name\n"); return 0; }
	cursor += n;

	//qtype and qclass writes.
	uint16_t qtype = htons(1);
	memcpy(buf + cursor, &qtype, sizeof(qtype));
	cursor += 2;

	uint16_t qclass = htons(1);
	memcpy(buf + cursor, &qclass, sizeof(qclass));
	cursor += 2;

	return cursor;
}

ssize_t send_query(int sockfd, const char* server, const uint8_t* query, size_t qlen, uint8_t* reply, size_t replyCap){
	struct sockaddr_in dest;
	dest.sin_family = AF_INET;
	dest.sin_port = htons(53);

	if (inet_pton(AF_INET, server, &dest.sin_addr) != 1) {
		fprintf(stderr, "bad address\n");
		return -1;
	}

	ssize_t bytesSent = sendto(sockfd, query, qlen, 0, (struct sockaddr*)&dest, sizeof(dest));

	if(bytesSent < 0){
		perror("sendto");
		return -1;
	}

	struct sockaddr_in src;
	socklen_t srcLen = sizeof(src);
	ssize_t bytesReceived = recvfrom(sockfd, reply, replyCap, 0,(struct sockaddr*)&src, &srcLen);

	return bytesReceived;
}

int validate_reply(const uint8_t* reply, ssize_t n, const uint8_t* query, size_t qlen, uint16_t id){
	ssize_t bytesReceived = n;

	if(bytesReceived < DNS_HEADER_LEN){
		fprintf(stderr, "runt packet: %zd bytes\n", bytesReceived);
		return 1;
	}

	dns_header responseHeader;
	memcpy(&responseHeader, reply, DNS_HEADER_LEN);

	//DEBUG HEX PRINT
	printf("flags: %04x\n", ntohs(responseHeader.flags_and_codes));

	if(ntohs(responseHeader.id) != id){
		fprintf(stderr, "improper id packet: %zd bytes\n", bytesReceived);
		return 1;
	}
	
	if(!DNS_QR(ntohs(responseHeader.flags_and_codes))){
		fprintf(stderr, "not a reply packet: %zd bytes\n", bytesReceived);
		return 1;
	}

	if(DNS_RCODE(ntohs(responseHeader.flags_and_codes)) != 0){
		fprintf(stderr, "rcode != NOERROR: %zd bytes\n", bytesReceived);
		return 1;
	}

	if(DNS_TC(ntohs(responseHeader.flags_and_codes))){
		//TCP FALLBACK Occurs here.
		fprintf(stderr, "truncated packet: %zd bytes\n", bytesReceived);
		//return 1; //warning for now.
		return 0;
	}

	if((size_t)bytesReceived < qlen || memcmp(reply + DNS_HEADER_LEN, query + DNS_HEADER_LEN, qlen - DNS_HEADER_LEN) != 0){
		fprintf(stderr, "question mismatch\n");
		return 1;
	}

	return 0;
}

ssize_t skip_name(const uint8_t *buf, size_t len, size_t cursor){
	while(1){
		if(cursor >= len) return -1;

		uint8_t labelLen = buf[cursor];

		if(labelLen == 0x00){//name terminator.
			cursor += 1;
			return cursor;
		}else if((labelLen & (0xC0)) == 0xC0){//pointer
			if(cursor + 2 > len) return -1;
			cursor += 2;
			return cursor;
		}else{
			if(cursor + 1 + labelLen > len) return -1;
			cursor += 1 + labelLen;
			continue;
		}
	}
}
ssize_t decode_name(const uint8_t* buf, size_t len, size_t cursor, char* out, size_t outCap){
	size_t readPos = cursor;
	ssize_t next = -1;

	size_t written = 0;
	int jumps = 0;

	while(1){
		if(readPos >= len) return -1;

		if((buf[readPos] & (0xC0)) == 0xC0){
			if(readPos + 2 > len) return -1;
			if(next < 0) next = readPos + 2;

			size_t offset =  ((buf[readPos] & 0x3F) << 8) | buf[readPos + 1];

			if(offset >= len) return -1;
			readPos = offset;

			if(++jumps > 20) return -1;
		}else if(buf[readPos] == 0x00){
			if(written + 1 >= outCap) return -1;
			out[written] = '\0';

			if(next >= 0){
				return next;
			}else{
				return (ssize_t) readPos + 1;
			}
		}else{
			if(buf[readPos] + 1 + readPos > len) return -1;
			size_t n = (size_t)buf[readPos++];

			if(written + 1 >= outCap) return -1;
			if (written > 0) out[written++] = '.';

			for(size_t i = 0; i < n; i++){
				if(written + 1 >= outCap) return -1;
				if(readPos >= len) return -1;
				out[written++] = (char)buf[readPos++];
			}
		}		
	}


}