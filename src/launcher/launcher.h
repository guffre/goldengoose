#ifndef COMMANDS_H
#define COMMANDS_H

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>

#pragma comment(lib, "ws2_32.lib")

#ifdef DEBUG
    #define dprintf(...) printf(__VA_ARGS__);
#else
    #define dprintf(...) do {} while (0);
#endif

#define JITTER(min, max) ((min) + rand() % ((max) - (min) + 1))

#pragma pack(push, 1)
typedef struct DNS_HEADER {
    unsigned short id;         // identification number
    unsigned char rd : 1;      // recursion desired
    unsigned char tc : 1;      // truncated message
    unsigned char aa : 1;      // authoritive answer
    unsigned char opcode : 4;  // purpose of message
    unsigned char qr : 1;      // query/response flag
    unsigned char rcode : 4;   // response code
    unsigned char cd : 1;      // checking disabled
    unsigned char ad : 1;      // authenticated data
    unsigned char z : 1;       // its z! reserved
    unsigned char ra : 1;      // recursion available
    unsigned short q_count;    // number of question entries
    unsigned short ans_count;  // number of answer entries
    unsigned short auth_count; // number of authority entries
    unsigned short add_count;  // number of resource entries
} DNS_HEADER;

typedef struct QUESTION {
    unsigned short qtype;
    unsigned short qclass;
} QUESTION;
#pragma pack(pop)

typedef struct C2CHANNEL {
    char* c2_server_ip;
    unsigned long c2_server_port;
} C2CHANNEL;

int get_dns_cache(char record_names[][NI_MAXHOST], int *record_count);
void print_addrinfo(struct addrinfo *res);
void build_dns_query(unsigned char *buf, const char *hostname, int *query_len);
int parse_dns_response(unsigned char *buf, int recv_len);
void perform_dns_request(const char *hostname);

#endif