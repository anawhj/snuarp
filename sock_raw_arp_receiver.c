#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

#define BUFFER_SIZE 46

int main() {
    int sockfd;
    struct sockaddr_in addr;
    unsigned char buffer[BUFFER_SIZE];

    // Create a raw socket for ARP packets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1) {
        perror("Failed to create socket");
        exit(1);
    }
    // Set socket options to receive all packets
    int sockopt = 1;
    // ### THE DRIVER INTERFACE NAME SHOULD BE UPDATED ### 
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, "eno1", strlen("eno1")) < 0) {
        perror("Failed to bind socket to device");
        exit(1);
    }

    // Receive ARP packets indefinitely
    while (1) {
        int len = recv(sockfd, buffer, BUFFER_SIZE, 0);
        if (len == -1) {
            perror("Failed to receive packet");
            exit(1);
        }

        // Check if it's an ARP packet
        struct ether_arp* arp = (struct ether_arp*)(buffer + 14);
        // ### THE IP VALUE SHOULD BE UPDATED ### 
        if (strcmp(inet_ntoa(*(struct in_addr*)&arp->arp_tpa), "147.46.246.105") == 0) {
            for (int i = 0; i < sizeof(buffer); i++) {
                printf("%02x ", buffer[i]);
            }
            printf("\n");
            printf("Received an ARP packet:\n");
			// Refer to https://github.com/leostratus/netinet/blob/master/if_ether.h#L79
            printf("Sender IP: %s\n", inet_ntoa(*(struct in_addr*)&arp->arp_spa));
            printf("Sender MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   arp->arp_sha[0], arp->arp_sha[1], arp->arp_sha[2],
                   arp->arp_sha[3], arp->arp_sha[4], arp->arp_sha[5]);
            printf("Target IP: %s\n", inet_ntoa(*(struct in_addr*)&arp->arp_tpa));
            printf("Target MAC: %02X:%02X:%02X:%02X:%02X:%02X\n",
                   arp->arp_tha[0], arp->arp_tha[1], arp->arp_tha[2],
                   arp->arp_tha[3], arp->arp_tha[4], arp->arp_tha[5]);
            printf("\n");
        }
    }

    return 0;
}
