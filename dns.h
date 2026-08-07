#ifndef DNS_H
#define DNS_H

#include <stdint.h>
#include <stddef.h>
#include <sys/types.h>
#include <arpa/inet.h>

#define DNS_MAX_RESPONSE 512
#define DNS_HEADER_LEN 12
#define DNS_MAX_NAME_LEN 255
#define DNS_NAME_BUF (DNS_MAX_NAME_LEN + 1) // 255 + null terminator
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

typedef struct dns_record_t{
	char name[DNS_NAME_BUF];
	uint16_t type;
	uint16_t rclass;
	uint32_t ttl;
	uint16_t rdlength;
	size_t rDataOffset;
}dns_record;

typedef struct dns_ns_t{
	char name[DNS_NAME_BUF];
	char addr[INET_ADDRSTRLEN];
}dns_ns;

_Static_assert(sizeof(dns_header) == DNS_HEADER_LEN, "dns_header struct is not 12 bytes long");

size_t encode_name(const char* name, uint8_t* out);
int dns_socket(int timeoutSeconds);
size_t build_query(const char* name, uint8_t* buf, uint16_t id);
ssize_t send_query(int sockfd, const char* server, const uint8_t* query, size_t qlen, uint8_t* reply, size_t replyCap);
int validate_reply(const uint8_t* reply, ssize_t n, const uint8_t* query, size_t qlen, uint16_t id);
ssize_t skip_name(const uint8_t *buf, size_t len, size_t cursor);
ssize_t decode_name(const uint8_t* buf, size_t len, size_t cursor, char* out, size_t outCap);
ssize_t parse_header(const uint8_t *buf, size_t len, dns_header *out);
ssize_t parse_record(const uint8_t* buf, size_t len, size_t cursor, dns_record* out);
int parse_records(const uint8_t* buf, size_t len, size_t cursor, dns_ns* out, int outLen, int recordAmt);


#endif