#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "dns_protocol.h"
#include "stdint.h"
#include "netdb.h"
#include "netinet/in.h"
#include "strings.h"
#include "arpa/inet.h"

#define BUFFER_LENGTH 512


int main(int argc, char *argv[]) {
    (void)argc;
    (void)argv;
    size_t port = 53; // default port.
    //struct hostent *server;
    struct sockaddr_in sockaddrIn;
    char dnsName[BUFFER_LENGTH]; // the domain name to be queried.
    char dnsAddr[BUFFER_LENGTH]; // store the address of DNS Server.
    //char domainName[BUFFER_LENGTH]; // store the domain name that is sent to the DNS server for querying.


    /*
     * send the query message to the DNS Server.
     * */
    // initialize the variables
    bzero(dnsName, BUFFER_LENGTH);
    strcpy(dnsAddr, "127.0.0.1");
    //server = gethostbyname("localhost");

    // get parameters from console.
    if(argc < 2){
        fprintf(stderr, "Less Parameters\n");
        exit(1);
    } else if(argc >= 2){
        strcpy(dnsName, argv[1]);
        dnsName[strlen(argv[1])] = '\0';

        if(argc >= 3){
            if(strcmp(argv[2], "localhost") == 0){
                strcpy(dnsAddr, "127.0.0.1");
            } else{
                strcpy(dnsAddr, argv[2]);
            }
            dnsAddr[strlen(dnsAddr)] = '\0';

            if(argc == 4){
                port = atoi(argv[3]);
            }
        }
    }

    printf("[client] Going to create a socket\n");
    /* create a socket point */
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0){
        perror("ERROR on creating socket.");
        exit(1);
    }

    socklen_t addrLength = sizeof(sockaddrIn);
    memset((char *)&sockaddrIn, 0, addrLength);
    //memcpy(dnsAddr, server->h_addr_list[0], (size_t) server->h_length);
    //inet_pton(AF_INET, "127.0.0.1", &sockaddrIn.sin_addr);

    sockaddrIn.sin_family = AF_INET;
    //bcopy(server->h_addr_list[0], (char *) &sockaddrIn.sin_addr.s_addr, (size_t) server->h_length);
    sockaddrIn.sin_port = htons(port); // htonl() is not allowed.
    sockaddrIn.sin_addr.s_addr = inet_addr((const char *)dnsAddr);
    printf("dnsAddr: %s\n", dnsAddr);


    printf("[client] Going to create query message.\n");

    /* send the query to the DNS server. */
    char dnsMessage[BUFFER_LENGTH];
    bzero(dnsMessage, BUFFER_LENGTH);

    // fill in the DNS_HEADER
    struct DNS_HEADER *dnsHeader = (struct DNS_HEADER*)dnsMessage;
    dnsHeader->id = htons(55); // identification number
    dnsHeader->rd = htons(1);
    dnsHeader->opcode = 0;
    dnsHeader->ans_count = 0; // number of answer's entries
    dnsHeader->qr = 0; // query/request flag -- 0: ; response flag -- 1.
    dnsHeader->q_count = htons(1);
    dnsHeader->add_count = 0;
    dnsHeader->auth_count = 0;
    dnsHeader->ans_count = 0;

    printf("create DNS_HEADER\n");
    /* store the content of request/query using the structure of 'QUERY'. */
    // transform the format of address, for instance: 'yandex.ru' --> '6yandex2ru\0'.
    unsigned char qName[BUFFER_LENGTH];
    uint16_t dnsNameLength = strlen(dnsName);
    uint16_t index = 0;
    uint16_t i = 0;
    while(index < dnsNameLength){
        uint16_t startIndex = index; // refer to the number, not "."
        while((dnsName[index] != '.') && (index < dnsNameLength)){
            index++;
        }
        if(index < dnsNameLength){
            qName[i] = (unsigned char)(index - startIndex + 1);
        } else{
            qName[i] = (unsigned char)(index - startIndex);
        }
        i++;
        memcpy(qName+i, dnsName+startIndex, index - startIndex);
        i += index - startIndex;
        index++; // refer to the number, not the "."
    }
    qName[i] = (char)0;
    qName[++i] = '\0';


    printf("The qname is: %s\n", qName);
    uint32_t dnsHeaderLength = sizeof(struct DNS_HEADER);

//    QUERY *query = (QUERY *) (dnsMessage + sizeof(struct DNS_HEADER));
    //query->name = (unsigned char *) (dnsMessage + sizeof(struct DNS_HEADER) + 1);
    unsigned char *queryName = (unsigned char *) (dnsMessage + dnsHeaderLength);
    printf("size of DNS_HEADER: %u\n", dnsHeaderLength);
    uint32_t qNameLength = i; // not include the '\0'.
    memcpy(queryName, qName, qNameLength + 1); // the '\0' should be included.
    printf("*name: %s\n", queryName);


    struct QUESTION *question= (struct QUESTION *)(queryName + qNameLength + 1); // the '1' means the length of '\0'
    question->qclass = htons(1); // type of address, usually Internet Address, assign 1.
    question->qtype = htons(1); // the type for the resource recording of request/query. 1 means "A type of recording".

    int toSentQueryLength = dnsHeaderLength + sizeof(struct QUESTION) + qNameLength + 1;
    printf("tosendQueryLength: %d\n", toSentQueryLength);
    dnsMessage[toSentQueryLength] = '\0';
    printf("start to send query message\n");
    /*start to send the query message to DNS Server.*/

    if(toSentQueryLength > UDP_PACKAGE_LENGTH){
        dnsHeader->tc = htons(1);
    }else{
        dnsHeader->tc = 0;
    }

    printf("sockfd: %d\n", sockfd);
    printf("toSentQueryLength: %d\n", toSentQueryLength);
    printf("addrLength: %d\n", addrLength);
    int sendLength = sendto(sockfd, dnsMessage, toSentQueryLength, 0, (const struct sockaddr *)&sockaddrIn, addrLength);
    if ( sendLength < 0){
        perror("ERROR on sendto() function\n");
        exit(0);
    }


    /*
     * receive the response from DNS server and parse the message.
     * */
    char resultBuffer[BUFFER_LENGTH];

    /* get the response from DNS Server. */
    bzero(resultBuffer, BUFFER_LENGTH);
    if (recvfrom(sockfd, resultBuffer, BUFFER_LENGTH, 0, (struct sockaddr *)&sockaddrIn, &addrLength) < 0){
        exit(0);
    }

    struct DNS_HEADER *dnsResult = (struct DNS_HEADER *)resultBuffer;
    int ansCount = ntohs(dnsResult->ans_count);
    if(!ansCount){
        printf("Domain(%s) not Found\n", dnsName);
        exit(1);
    }

    //struct RES_RECORD *resRecord = (struct RES_RECORD *)(resultBuffer + sizeof(struct DNS_HEADER));
//    char *recordName = (char *)(resultBuffer + dnsHeaderLength);
//    uint32_t j = 0;
//    while(*(recordName + j) != '\0'){
//        j++;
//    }
    uint32_t rdata_start_point = sendLength + 2 + sizeof(struct R_DATA);
    unsigned char *rdata = (unsigned char *)(resultBuffer + rdata_start_point-1);

    //struct R_DATA *rData = (struct R_DATA *)(resultBuffer + toSentQueryLength + 2);
    //printf("rdata length: %d\n", ntohs(rData->data_len));
//    for (int i = 0; i < ansCount; i++){
//        if (ntohs(resRecord->resource->type) == 1){
//            rdata  = resRecord->rdata;
//            //inet_ntop(AF_INET, reader + rDataLen, IP, 17);
//            printf("Got IP address: %s\n", rdata);
//        }
//    }
    char IP[16];
    bzero(IP, 16);
    inet_ntop(AF_INET, rdata, IP, 16);
    printf("IP: %s\n", IP);
    return 0;
}



