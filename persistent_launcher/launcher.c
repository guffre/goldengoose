// cl.exe -DDEBUG launcher.c
#include "launcher.h"

#define MAX_RECORDS 5
#define DNS_SERVER_IP "127.0.0.1"
#define DNS_PORT 53

int get_dns_cache(char record_names[][NI_MAXHOST], int *record_count)
{
    FILE *fp;
    char path[1035];
    int count = 0;

    /* Open the command for reading. */
    fp = _popen("ipconfig /displaydns", "r");
    if (fp == NULL)
    {
        dprintf("Failed to run command\n");
        return 1;
    }

    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path) - 1, fp) != NULL && count < MAX_RECORDS)
    {
        if (strstr(path, "Record Name") != NULL)
        {
            sscanf(path, "    Record Name . . . . . : %s", record_names[count]);
            count++;
        }
    }

    *record_count = count;

    /* Close the command. */
    _pclose(fp);
    return 0;
}

void print_addrinfo(struct addrinfo *res)
{
    struct addrinfo *p;
    char ipstr[INET6_ADDRSTRLEN];
    void *addr;
    char *ipver;

    for (p = res; p != NULL; p = p->ai_next)
    {
        // get the pointer to the address itself,
        // different fields in IPv4 and IPv6:
        if (p->ai_family == AF_INET)
        { // IPv4
            struct sockaddr_in *ipv4 = (struct sockaddr_in *)p->ai_addr;
            addr = &(ipv4->sin_addr);
            ipver = "IPv4";
        }
        else
        { // IPv6
            struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)p->ai_addr;
            addr = &(ipv6->sin6_addr);
            ipver = "IPv6";
        }

        // convert the IP to a string and print it:
        inet_ntop(p->ai_family, addr, ipstr, sizeof ipstr);
        dprintf("  %s: %s\n", ipver, ipstr);
    }
}

void build_dns_query(unsigned char *buf, const char *hostname, int *query_len)
{
    DNS_HEADER *dns = NULL;
    QUESTION *qinfo = NULL;

    dns = (DNS_HEADER *)buf;
    dns->id = (unsigned short)htons(getpid());
    dns->qr = 0;     // This is a query
    dns->opcode = 0; // This is a standard query
    dns->aa = 0;     // Not Authoritative
    dns->tc = 0;     // This message is not truncated
    dns->rd = 1;     // Recursion Desired
    dns->ra = 0;     // Recursion not available! This is just a query
    dns->z = 0;
    dns->ad = 0;
    dns->cd = 0;
    dns->rcode = 0;
    dns->q_count = htons(1); // we have only 1 question
    dns->ans_count = 0;
    dns->auth_count = 0;
    dns->add_count = 0;

    // point to the query portion
    buf += sizeof(DNS_HEADER);

    // convert hostname to DNS format
    const char delim[2] = ".";
    char *token;
    char hostname_cpy[NI_MAXHOST];
    strncpy(hostname_cpy, hostname, NI_MAXHOST);
    token = strtok(hostname_cpy, delim);

    while (token != NULL)
    {
        *buf++ = strlen(token);
        for (int i = 0; i < strlen(token); i++)
        {
            *buf++ = token[i];
        }
        token = strtok(NULL, delim);
    }

    *buf++ = 0;

    qinfo = (QUESTION *)buf;
    qinfo->qtype = htons(1);  // type A query
    qinfo->qclass = htons(1); // class IN

    *query_len = sizeof(DNS_HEADER) + (strlen(hostname) + 2) + sizeof(QUESTION);
}

void parse_dns_response(unsigned char *buf, int recv_len)
{
    DNS_HEADER *dns = (DNS_HEADER *)buf;

    int offset = sizeof(DNS_HEADER);

    // Move past the DNS header
    buf += offset;

    // Skip over the questions section
    for (int i = 0; i < ntohs(dns->q_count); ++i)
    {
        while (*buf != 0)
        {
            ++buf;
        }
        ++buf;                          // Move past the null-terminator of the domain name
        buf += sizeof(struct QUESTION); // Move past the QTYPE and QCLASS fields
    }

    dprintf("BUF START: %02x %02x %02x\n", *buf, *(buf + 1), *(buf + 2));
    // Parse answers
    for (int i = 0; i < ntohs(dns->ans_count); ++i)
    {
        buf += 2;
        dprintf("current buf bytes: %02x %02x %02x\n", *buf, *(buf + 1), *(buf + 2));
        // Check if it's an IPv4 address (type A record)
        if (*(buf + 1) == 0x01)
        {
            buf += 2; // Move past the type (2 bytes)
            buf += 2; // Move past the class (2 bytes)
            unsigned long ttl = ntohl(*(u_long*)(buf));
            buf += 4; // Move past the TTL (4 bytes)
            buf += 2; // Move past the data length (4 bytes)

            // Extract the IPv4 address (4 bytes)
            struct in_addr ipv4;
            memcpy(&ipv4, buf, sizeof(struct in_addr));
            dprintf("IPv4 Address: %s\n", inet_ntoa(ipv4));
            dprintf("TTL: %lu\n", ttl);

            // Move to the next answer
            buf += sizeof(struct in_addr);
        }
        else if (*(buf + 1) == 0x05)
        {
            // It's a CNAME record
            buf += 2;                // Move past the type
            buf += 2;                // Move past the class
            buf += 4;                // Move past the TTL
            int length = *(buf + 1); // Length of the CNAME
            buf += length + 2;       // Move past the CNAME + length
        }
    }
}

void perform_dns_request(const char *hostname)
{
    struct sockaddr_in dest;
    unsigned char buf[65536], *qname;
    int query_len, sockfd;
    struct sockaddr_in from;
    int from_len = sizeof(from);

    // Create a UDP socket
    sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sockfd == INVALID_SOCKET)
    {
        dprintf("Socket creation failed.\n");
        return;
    }

    // Configure the DNS server address
    dest.sin_family = AF_INET;
    dest.sin_port = htons(DNS_PORT);
    dest.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

    // Build the DNS query
    memset(buf, 0, sizeof(buf));
    build_dns_query(buf, hostname, &query_len);

    // Send the DNS query
    if (sendto(sockfd, (char *)buf, query_len, 0, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
    {
        dprintf("DNS request to %s failed.\n", DNS_SERVER_IP);
        closesocket(sockfd);
        return;
    }

    // Receive the DNS response
    int recv_len = recvfrom(sockfd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
    if (recv_len == SOCKET_ERROR)
    {
        dprintf("DNS request to %s failed.\n", DNS_SERVER_IP);
    }
    else
    {
        dprintf("DNS request to %s succeeded. Received %d bytes of data:\n", hostname, recv_len);
        // Print the received data (in hex format)
        dprintf("%p] ", buf);
        for (int i = 0; i < recv_len; ++i)
        {
            dprintf("%02X ", buf[i]);
            if ((i + 1) % 16 == 0) // New line every 16 bytes
                dprintf("\n%p] ", &(buf[i]));
        }
        dprintf("\n");
        // Add length of hostname + 2 to skip past [some byte][hostname][null terminator]
        parse_dns_response(buf, recv_len);
    }

    closesocket(sockfd);
}

int main(int argc, char **argv)
{
    WSADATA wsaData;
    char record_names[MAX_RECORDS][NI_MAXHOST];
    int record_count   = 0;
    int current_record = 0;

    // Get DNS cache and extract record names
    while (!record_count)
    {
        get_dns_cache(record_names, &record_count);
    }

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    {
        dprintf("WSAStartup failed.\n");
        return;
    }

    // Perform DNS requests in a loop
    while (1)
    {
        dprintf("Performing DNS request for: %s\n", record_names[current_record]);
        perform_dns_request(record_names[current_record]);

        // Move to the next record
        current_record = (current_record + 1) % record_count;

        // Pause between requests
        Sleep(JITTER(1000, 5000));
    }
    WSACleanup();

    return 0;
}