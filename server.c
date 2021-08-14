#include "dns_protocol.h"
#include "stdio.h"
#include "stdlib.h"
#include "stdint.h"
#include "sys/types.h"
#include "sys/socket.h"
#include "netinet/in.h"
#include "arpa/inet.h"
#include "strings.h"
#include "string.h"
#define BUFFER_SIZE 1024

uint16_t getNameLength(char *domainName);
int main(int argc, char *argv[])
{
    uint16_t port = 53;
    struct sockaddr_in sockaddrIn;
    char recvBuffer[BUFFER_SIZE];
    if(argc == 2){
        port = (uint16_t)atoi(argv[1]);
        printf("Get new port: %u\n", port);
    }

    /* create a socket point */
    int sockfd = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if(sockfd < 0){
        perror("ERROR on creating socket.");
        exit(1);
    }

    socklen_t addrLength = sizeof(sockaddrIn);
    /* fill in sockaddr_in */
    bzero(&sockaddrIn, sizeof(sockaddrIn));
    //inet_pton(AF_INET, "localhost", &sockAddr.sin_addr);
    sockaddrIn.sin_family = AF_INET;
    //sockaddrIn.sin_addr.s_addr = inet_addr("127.0.0.1");
    sockaddrIn.sin_addr.s_addr = htonl(INADDR_ANY);
    sockaddrIn.sin_port = htons(port); // htonl() can be not applied.


    if(bind(sockfd, (struct sockaddr *)&sockaddrIn, sizeof(sockaddrIn)) < 0)
    {
        perror("ERROR on bind()");
        exit(1);
    }


    /*
     * receive the DNS query from client and deal with the query.
     * */
    while(1)
    {
        printf("start to recv query message\n");
        bzero(recvBuffer, sizeof(recvBuffer));
        ssize_t recvLength = recvfrom(sockfd, recvBuffer, BUFFER_SIZE - 1, 0, (struct sockaddr *)&sockaddrIn, &addrLength);
        printf("the recvLength is: %zd\n", recvLength);

        if(recvLength < 0){
            perror("ERROR on recvfrom()\n");
            exit(1);
        }

//        printf("received:\n");
//        for(int i = 0; i < recvLength; i++){
//            if(i % 10 == 0)
//                printf("\n");
//            printf("%16x", recvBuffer[i]);
//
//        }
//        printf("\n");


        uint16_t dnsHeaderLength = sizeof(struct DNS_HEADER);
        int queryMessageLength = dnsHeaderLength + sizeof(struct QUESTION) + strlen((char *)(recvBuffer + dnsHeaderLength)) + 1;

        /* to construct the response data. */
        // should add new data after the received package.
        char responseBuffer[BUFFER_SIZE];
        bzero(responseBuffer, BUFFER_SIZE);
        // get the DNS Header
        memcpy(responseBuffer, recvBuffer, recvLength);
        struct DNS_HEADER *dnsHeader = (struct DNS_HEADER *)responseBuffer;
        dnsHeader->qr = htons(1); // 1 means that this DNS message is response message.
        dnsHeader->auth_count = 0;
        dnsHeader->ra = 0; // not support the recursive query.
        dnsHeader->rd = 0;
        dnsHeader->ans_count = htons(1); // the number of resource recording. 1 means return one resource recording entry.
        dnsHeader->rcode = 0;
        dnsHeader->q_count = htons(1);
        dnsHeader->add_count = 0;
        dnsHeader->opcode = 0;
        dnsHeader->aa = htons(1);

        // get the length of domain name.
        char *name_start_point = (char *)(sizeof(struct DNS_HEADER) + recvBuffer);
        uint32_t sum = getNameLength(name_start_point);

        printf("the sum is: %u\n", sum);

        //struct RES_RECORD *res_record = (struct RES_RECORD *)(responseBuffer + recvLength);
        unsigned char *recordName = (unsigned char *)(responseBuffer + queryMessageLength);
//        uint32_t recordNameLength = index; // not include the length of '\0.
//        memcpy(recordName, recvBuffer + dnsHeaderLength, recordNameLength + 1);// copy the '\0' to the responseBuffer.
        uint32_t recordNameLength = 2;
        uint16_t QName = 0x0cc0;// in the package, it will be shown as "c0 0c".
        memcpy(recordName, &QName, recordNameLength);

        struct R_DATA *resourceInfor = (struct R_DATA *)(responseBuffer + queryMessageLength + recordNameLength);
        resourceInfor->type = htons(1); // 1 means the type of A recording.
        resourceInfor->_class = htons(1);
        resourceInfor->ttl = htons(1);
        resourceInfor->data_len = 0;

        unsigned char *rdata = (unsigned char *)(responseBuffer + queryMessageLength + recordNameLength + sizeof(struct R_DATA));

        // suppose that the length of domain name is less than 256.
        int queryResultLength = 16;
        char queryResult[queryResultLength];
        memset(queryResult, 0, queryResultLength);
        memcpy(queryResult, "0.0.0.", 6);
        sprintf(queryResult + 6, "%u", sum);
        queryResult[strlen(queryResult)] = '\0';
        //printf("queryResult: %s\n", queryResult);
        memcpy(rdata, queryResult, queryResultLength);
        //printf("After memcpy, rdata: %s\n", rdata);

        struct sockaddr_in ipAddress;
        inet_pton(AF_INET, queryResult, &ipAddress.sin_addr.s_addr);
        memcpy(rdata, &ipAddress.sin_addr.s_addr, sizeof(ipAddress.sin_addr.s_addr));
        queryResultLength = sizeof(ipAddress.sin_addr.s_addr);
        //printf("rdata: %s\n", rdata);
        //printf("sizeof(ipAddress.sin_addr.s_addr): %ld\n", sizeof(ipAddress.sin_addr.s_addr));


        resourceInfor->data_len = htons(queryResultLength); // the length of queryResult.
        //uint32_t responseBufferLength = recvLength + recordNameLength + 1 + sizeof(struct R_DATA) + queryResultLength;
        uint32_t responseBufferLength = queryMessageLength + recordNameLength + sizeof(struct R_DATA) + queryResultLength;
        if(responseBufferLength < UDP_PACKAGE_LENGTH){
            dnsHeader->tc = 0;
            printf("dnsHeader->tc = 0\n");
        } else{
            dnsHeader->tc = htons(1);
        }
//        printf("to sent:\n");
//        for(uint32_t i = 0; i < responseBufferLength; i++){
//            if(i % 10 == 0)
//                printf("\n");
//            printf("%16x", responseBuffer[i]);
//
//        }
//        printf("\n");

        sendto(sockfd, responseBuffer, responseBufferLength, 0, (struct sockaddr *)&sockaddrIn, addrLength);
    }
    return 0;
}
uint16_t getNameLength(char *domainName)
{
    //printf("[getNameLength] Got domain name: %s\n", domainName);

    uint16_t sum = 0;
    uint16_t index = 0;
    int firstElement = (int)domainName[0]; // must
    //printf("[getNameLength] Got first element: %d\n", firstElement);
    if(domainName[0] == 0){ // character '.' is represented as 0x0 in the package if no other characters.
        sum = 1;
    } else if((firstElement > 0) && (firstElement <= 9)){// the domainName is like: 7yandex2ru1
        //printf("the server travels the domain name(with number): ");
        int number = firstElement;
        //printf("outside number is: %d\n", number);
        sum += number;
        int flag = 0;
        int temp = (int)domainName[number];
        if((temp > 0) && (temp <= 9))
            flag = 1;
        while((*(domainName + index) != '\0') && (number != 0)){
            // it can't be recognized as a integer in such usage: *(domainName + index) <= '9'
            //printf("number: %d\n", number);
            if(flag == 0){
                index += number + 1;
                number = (int)domainName[index];
                sum += number + 1;
            } else{
                index += number;
                if(((int)domainName[index+1]) == 0)
                    index++;
                number = (int)domainName[index];
                sum += number;
            }
        }
        if(flag == 0)
            sum--;
    } else{ // the domainName is like: yandex.ru
        //printf("the server travels the domain name: ");
        while(*(domainName + index) != '\0'){
            //printf("%c", domainName[index]);
            index++;
        }
        sum = index - 1;
    }
    //printf("\n");
    return sum;
}



