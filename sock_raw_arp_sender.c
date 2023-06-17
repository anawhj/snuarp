#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <linux/if_packet.h>

int main() {
    int sockfd, result;
    struct sockaddr_ll addr;
    unsigned char buffer[46]; // ARP request packet size

    // Create a raw socket for ARP packets
    sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (sockfd == -1) {
        perror("Failed to create socket");
        exit(1);
    }

    // Set socket options to send on a specific network interface
    struct ifreq ifr;
    strncpy(ifr.ifr_name, "eno1", IFNAMSIZ - 1);
    if (setsockopt(sockfd, SOL_SOCKET, SO_BINDTODEVICE, (void *)&ifr, sizeof(ifr)) < 0) {
        perror("Failed to bind socket to device");
        exit(1);
    }

    // Set destination address
    memset(&addr, 0, sizeof(addr));
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ARP);
    addr.sll_ifindex = if_nametoindex("eno1");

    // Set destination MAC address to broadcast (FF:FF:FF:FF:FF:FF)
    unsigned char dest_mac[6] = {0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

    // Set source MAC address to your own MAC address
    unsigned char src_mac[6] = {0, 0, 0, 0, 0, 0};

    // Set ARP request packet data
    unsigned short int ether_type = htons(0x0806);  // 0x0806
    unsigned short int hardware_type = htons(ARPHRD_ETHER);  // 0x0001
    unsigned short int protocol_type = htons(ETH_P_IP);  //0x0806
    unsigned char hardware_size = 6;
    unsigned char protocol_size = 4;
    unsigned short int opcode = htons(ARPOP_REQUEST);  // 0x0001
    unsigned char sender_mac[6] = {0x70, 0x85, 0xc2, 0xba, 0x72, 0xa2};  // ### SHOULD BE UPDATED ###
    unsigned char sender_ip[4] = {0, 0, 0, 0};
    unsigned char target_mac[6] = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
    unsigned char target_ip[4] = {147, 46, 246, 105};  // ### SHOULD BE UPDATED ###
    unsigned char signature[4] = {0, 0, 0, 0};

    // Construct ARP request packet
    memset(&buffer, 0, sizeof(buffer));
    memcpy(buffer, dest_mac, 6);                   // Destination MAC address
    memcpy(buffer + 6, src_mac, 6);                // Source MAC address
    memcpy(buffer + 12, &ether_type, 2);                // Ethernet Type
    memcpy(buffer + 14, &hardware_type, 2);        // Hardware type
    memcpy(buffer + 16, &protocol_type, 2);        // Protocol type
    memcpy(buffer + 18, &hardware_size, 1);        // Hardware address length
    memcpy(buffer + 19, &protocol_size, 1);        // Protocol address length
    memcpy(buffer + 20, &opcode, 2);               // ARP opcode (request)
    memcpy(buffer + 22, sender_mac, 6);            // Sender MAC address
    memcpy(buffer + 28, sender_ip, 4);             // Sender IP address
    memcpy(buffer + 32, target_mac, 6);            // Target MAC address
    memcpy(buffer + 38, target_ip, 4);             // Target IP address
    memcpy(buffer + 42, signature, 4);             // Signature info

    for (int i = 0; i < sizeof(buffer); i++) {
        printf("%02x ", buffer[i]);
    }
    printf("\n");
    
    // Send the ARP request packet
    result = sendto(sockfd, buffer, sizeof(buffer), 0, (struct sockaddr*)&addr, sizeof(addr));
    if (result == -1) {
        perror("Failed to send packet");
        exit(1);
    }
    printf("%d\n", result);
    printf("ARP request packet sent.\n");

    return 0;
}
