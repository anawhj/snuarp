/* SPDX-License-Identifier: BSD-3-Clause
 * Copyright(c) 2010-2023 Seoul National University
 */

#include <stdint.h>
#include <sys/queue.h>
#include <sys/socket.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <assert.h>
#include <errno.h>
#include <signal.h>
#include <stdarg.h>
#include <inttypes.h>
#include <getopt.h>
#include <termios.h>
#include <unistd.h>
#include <pthread.h>

#include <rte_common.h>
#include <rte_log.h>
#include <rte_memory.h>
#include <rte_memcpy.h>
#include <rte_eal.h>
#include <rte_launch.h>
#include <rte_cycles.h>
#include <rte_prefetch.h>
#include <rte_per_lcore.h>
#include <rte_branch_prediction.h>
#include <rte_interrupts.h>
#include <rte_random.h>
#include <rte_debug.h>
#include <rte_ether.h>
#include <rte_ethdev.h>
#include <rte_mempool.h>
#include <rte_mbuf.h>
#include <rte_ip.h>
#include <rte_tcp.h>
#include <rte_arp.h>
#include <rte_spinlock.h>
#include <rte_devargs.h>
#include <rte_byteorder.h>
#include <rte_cpuflags.h>
#include <rte_eth_bond.h>

#include "snucert.c"

#define RX_RING_SIZE 1024
#define TX_RING_SIZE 1024

#define NUM_MBUFS 8191
#define MBUF_CACHE_SIZE 250
#define BURST_SIZE 32

#define TARGET_IP_1	4
#define TARGET_IP_2	0
#define TARGET_IP_3	168
#define TARGET_IP_4	192

static struct rte_mempool *mbuf_pool;

/*
 * Initializes a given port using global settings and with the RX buffers
 * coming from the mbuf_pool passed as a parameter.
 */

/* Main functional part of port initialization. */
static inline int
port_init(uint16_t port, struct rte_mempool *mbuf_pool)
{
	struct rte_eth_conf port_conf;
	const uint16_t rx_rings = 1, tx_rings = 1;
	uint16_t nb_rxd = RX_RING_SIZE;
	uint16_t nb_txd = TX_RING_SIZE;
	int retval;
	uint16_t q;
	struct rte_eth_dev_info dev_info;
	struct rte_eth_txconf txconf;

	if (!rte_eth_dev_is_valid_port(port))
		return -1;

	memset(&port_conf, 0, sizeof(struct rte_eth_conf));

	retval = rte_eth_dev_info_get(port, &dev_info);
	if (retval != 0) {
		printf("Error during getting device (port %u) info: %s\n",
				port, strerror(-retval));
		return retval;
	}

	if (dev_info.tx_offload_capa & RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE)
		port_conf.txmode.offloads |=
			RTE_ETH_TX_OFFLOAD_MBUF_FAST_FREE;

	/* Configure the Ethernet device. */
	retval = rte_eth_dev_configure(port, rx_rings, tx_rings, &port_conf);
	if (retval != 0)
		return retval;

	retval = rte_eth_dev_adjust_nb_rx_tx_desc(port, &nb_rxd, &nb_txd);
	if (retval != 0)
		return retval;

	/* Allocate and set up 1 RX queue per Ethernet port. */
	for (q = 0; q < rx_rings; q++) {
		retval = rte_eth_rx_queue_setup(port, q, nb_rxd,
				rte_eth_dev_socket_id(port), NULL, mbuf_pool);
		if (retval < 0)
			return retval;
	}

	txconf = dev_info.default_txconf;
	txconf.offloads = port_conf.txmode.offloads;
	/* Allocate and set up 1 TX queue per Ethernet port. */
	for (q = 0; q < tx_rings; q++) {
		retval = rte_eth_tx_queue_setup(port, q, nb_txd,
				rte_eth_dev_socket_id(port), &txconf);
		if (retval < 0)
			return retval;
	}

	/* Starting Ethernet port. */
	retval = rte_eth_dev_start(port);
	/* End of starting of ethernet port. */
	if (retval < 0)
		return retval;

	/* Display the port MAC address. */
	struct rte_ether_addr addr;
	retval = rte_eth_macaddr_get(port, &addr);
	if (retval != 0)
		return retval;

	printf("Port %u MAC: %02" PRIx8 " %02" PRIx8 " %02" PRIx8
			   " %02" PRIx8 " %02" PRIx8 " %02" PRIx8 "\n",
			port, RTE_ETHER_ADDR_BYTES(&addr));

	/* Enable RX in promiscuous mode for the Ethernet device. */
	retval = rte_eth_promiscuous_enable(port);
	/* End of setting RX port in promiscuous mode. */
	if (retval != 0)
		return retval;

	return 0;
}
/* End of main functional part of port initialization. */

static inline size_t
get_vlan_offset(struct rte_ether_hdr *eth_hdr, uint16_t *proto)
{
	size_t vlan_offset = 0;

	if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
		struct rte_vlan_hdr *vlan_hdr =
			(struct rte_vlan_hdr *)(eth_hdr + 1);

		vlan_offset = sizeof(struct rte_vlan_hdr);
		*proto = vlan_hdr->eth_proto;

		if (rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN) == *proto) {
			vlan_hdr = vlan_hdr + 1;

			*proto = vlan_hdr->eth_proto;
			vlan_offset += sizeof(struct rte_vlan_hdr);
		}
	}
	return vlan_offset;
}

/*
 * The lcore main. This is the main thread that does the work, reading from
 * an input port and writing to an output port.
 */

static int lcore_main(void)
{
	uint16_t ether_type, port;

	/*
	 * Check that the port is on the same NUMA node as the polling thread
	 * for best performance.
	 */
	RTE_ETH_FOREACH_DEV(port)
		if (rte_eth_dev_socket_id(port) >= 0 &&
				rte_eth_dev_socket_id(port) !=
						(int)rte_socket_id())
			printf("WARNING, port %u is on remote NUMA node to "
					"polling thread.\n\tPerformance will "
					"not be optimal.\n", port);

	printf("\n##################################################\n");
	printf("SNUARP Test Start! (Core ID: %u) [Ctrl+C to quit]\n", rte_lcore_id());
	printf("##################################################\n");

	/* Main work of application loop. */
	int count = 0;
	while (count++ < 2) {  // It requires only one roundtrip for this project.
		RTE_ETH_FOREACH_DEV(port) {
			
			/* Get burst of RX packets, from first port of pair. */
			struct rte_mbuf *bufs[BURST_SIZE];
			uint16_t offset;
			struct rte_ether_addr bond_mac_addr;
			struct rte_ether_addr dst_addr;
			struct rte_ether_hdr *eth_hdr;
			struct rte_arp_hdr *arp_hdr;
			if (port == 0){
				if (count == 2) {
					printf("[#1->#0]\n");
					measureTime("B to C");  // @@ 3. Recive an ARP Request Packet
					printf("##################################################\n");
				}
				printf("[port#%d] ARP Request Receiver\n", port);
				printf("[port#%d] ARP Request Listening..\n", port);
				const uint16_t nb_rx = rte_eth_rx_burst(port, 0, bufs, BURST_SIZE);
				int ret = rte_eth_macaddr_get(port, &bond_mac_addr);
				if (ret!=0){
					rte_pktmbuf_free(bufs[0]);
					continue;
				}
				uint32_t target_ip = TARGET_IP_1 | (TARGET_IP_2 << 8) |
				(TARGET_IP_3 << 16) | (TARGET_IP_4 << 24);

				if (count == 2) {
					measureTime("C to D");  // @@ 4. Start to create an ARP Reply packet
					printf("[port#%d] ARP Reply Sender\n", port);
					printf("\t-> Start to create the certificate\n");
				}
				
				//if (unlikely(nb_rx == 0))
				//	continue;

				for(int i=0;i<nb_rx;i++){
					//struct rte_mbuf *pkt = bufs[i];
					struct rte_ether_hdr *eth_hdr = rte_pktmbuf_mtod(bufs[i],struct rte_ether_hdr *);
					ether_type = eth_hdr->ether_type;
					if (ether_type == rte_cpu_to_be_16(RTE_ETHER_TYPE_VLAN))
						printf("VLAN tagged frame, offset:");
					offset = get_vlan_offset(eth_hdr, &ether_type);
					if (offset > 0)
						printf("%d\n", offset);

					if (rte_be_to_cpu_16(eth_hdr->ether_type)==RTE_ETHER_TYPE_ARP){
						printf("Received APR packet\n");
						arp_hdr = (struct rte_arp_hdr *)((char *)(eth_hdr + 1) + offset);
						uint32_t dst_ip=rte_be_to_cpu_32(arp_hdr->arp_data.arp_tip);
						struct in_addr dst_ip_addr;
						dst_ip_addr.s_addr=dst_ip;
						char dst_ip_str[INET_ADDRSTRLEN];
						inet_ntop(AF_INET,&(dst_ip_addr),dst_ip_str,INET_ADDRSTRLEN);
						printf("Dest IP: %s\n",dst_ip_str);
						/*print MAC addr*/
						// printf("arp_hdr, dst_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
						// arp_hdr->arp_data.arp_sha.addr_bytes[0],arp_hdr->arp_data.arp_sha.addr_bytes[1],
						// arp_hdr->arp_data.arp_sha.addr_bytes[2],arp_hdr->arp_data.arp_sha.addr_bytes[3],
						// arp_hdr->arp_data.arp_sha.addr_bytes[4],arp_hdr->arp_data.arp_sha.addr_bytes[5]);

						// printf("arp_hdr, src_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
						// arp_hdr->arp_data.arp_sha.addr_bytes[0],arp_hdr->arp_data.arp_sha.addr_bytes[1],
						// arp_hdr->arp_data.arp_sha.addr_bytes[2],arp_hdr->arp_data.arp_sha.addr_bytes[3],
						// arp_hdr->arp_data.arp_sha.addr_bytes[4],arp_hdr->arp_data.arp_sha.addr_bytes[5]);
						printf("$$$%d\n", arp_hdr->arp_data.arp_tip);

						if (arp_hdr->arp_data.arp_tip == target_ip) {
							if (arp_hdr->arp_opcode == rte_cpu_to_be_16(RTE_ARP_OP_REQUEST)) {
								arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REPLY);
								/* Switch src and dst data and set bonding MAC */
								rte_ether_addr_copy(&eth_hdr->src_addr, &eth_hdr->dst_addr);
								rte_ether_addr_copy(&bond_mac_addr, &eth_hdr->src_addr);
								rte_ether_addr_copy(&arp_hdr->arp_data.arp_sha,
										&arp_hdr->arp_data.arp_tha);
								arp_hdr->arp_data.arp_tip = arp_hdr->arp_data.arp_sip;
								rte_ether_addr_copy(&bond_mac_addr, &dst_addr);
								rte_ether_addr_copy(&dst_addr, &arp_hdr->arp_data.arp_sha);
								arp_hdr->arp_data.arp_sip = target_ip;
								printf("made ARP response msg\n");
								rte_eth_tx_burst(port ^ 1, 0, &bufs[i], 1);
								printf("made ARP response msg done\n");
								// is_free = 1;
							} else {
								rte_eth_tx_burst(port ^ 1, 0, NULL, 0);
							}
						}
					}
					// rintf("%u\n",rte_pktmbuf_pkt_len(pkt));
					// rte_pktmbuf_free(pkt);
				}
				// const unsigned char message = (char*) bufs;
				const unsigned char message[] = "1234567890123456789012345678901234567890"; // 40 bytes;
				generate_snu_certificate(message);
				if (count == 2)
					measureTime("D to E");  // @@ 5. Send an ARP Reply packet
				printf("##################################################\n");
			} else if (port == 1) {
				/* Send burst of TX packets, to second port of pair. */
				if (count == 1)
					printf("[port#%d] ARP Request Sender\n", port);
				if (count == 2) {
					printf("[#0->#1]\n");
					measureTime("E to F");  // @@ 6. Receive an ARP Reply packet
					printf("##################################################\n");
					printf("[port#%d] ARP Reply Receiver\n", port);
					printf("[port#%d] ARP Reply Listening..\n", port);
				}
				if (count == 1)
    				measureTime("");  // @@ 1. Start to create an ARP request packet
				struct rte_mbuf *created_pkt;

				// const char *my_ip_address="127.0.0.1";
				// struct in_addr my_ip;
				// inet_pton(AF_INET,my_ip_address,&(my_ip.s_addr));
				// uint32_t my_ip_addr=my_ip.s_addr;
			
				size_t pkt_size;
				int ret;

				uint32_t target_ip = TARGET_IP_1 | (TARGET_IP_2 << 8) |
				(TARGET_IP_3 << 16) | (TARGET_IP_4 << 24);

				// if (res->ip.family == AF_INET)
				// 	get_string(res, ip_str, INET_ADDRSTRLEN);
				// else
				// 	printf("Wrong IP format. Only IPv4 is supported\n");

				ret = rte_eth_macaddr_get(port, &bond_mac_addr);
				if (ret != 0) {
					printf("Failed to get bond (port %d) MAC address: %s\n",
							port, strerror(-ret));
				}

				created_pkt = rte_pktmbuf_alloc(mbuf_pool);
				if (created_pkt == NULL) {
					printf("Failed to allocate mbuf\n");
					// return;
				}

				pkt_size = sizeof(struct rte_ether_hdr) + sizeof(struct rte_arp_hdr);
				created_pkt->data_len = pkt_size;
				created_pkt->pkt_len = pkt_size;

				eth_hdr = rte_pktmbuf_mtod(created_pkt, struct rte_ether_hdr *);
				rte_ether_addr_copy(&bond_mac_addr, &eth_hdr->src_addr);
				memset(&eth_hdr->dst_addr, 0xFF, RTE_ETHER_ADDR_LEN);
				eth_hdr->ether_type = rte_cpu_to_be_16(RTE_ETHER_TYPE_ARP);
				
				// printf("eth_hdr, dst_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				// eth_hdr->dst_addr.addr_bytes[0],eth_hdr->dst_addr.addr_bytes[1],
				// eth_hdr->dst_addr.addr_bytes[2],eth_hdr->dst_addr.addr_bytes[3],
				// eth_hdr->dst_addr.addr_bytes[4],eth_hdr->dst_addr.addr_bytes[5]);

				// printf("eth_hdr, src_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				// eth_hdr->src_addr.addr_bytes[0],eth_hdr->src_addr.addr_bytes[1],
				// eth_hdr->src_addr.addr_bytes[2],eth_hdr->src_addr.addr_bytes[3],
				// eth_hdr->src_addr.addr_bytes[4],eth_hdr->src_addr.addr_bytes[5]);

				arp_hdr = (struct rte_arp_hdr *)(
					(char *)eth_hdr + sizeof(struct rte_ether_hdr));
				arp_hdr->arp_hardware = rte_cpu_to_be_16(RTE_ARP_HRD_ETHER);
				arp_hdr->arp_protocol = rte_cpu_to_be_16(RTE_ETHER_TYPE_IPV4);
				arp_hdr->arp_hlen = RTE_ETHER_ADDR_LEN;
				arp_hdr->arp_plen = sizeof(uint32_t);
				arp_hdr->arp_opcode = rte_cpu_to_be_16(RTE_ARP_OP_REQUEST);

				rte_ether_addr_copy(&bond_mac_addr, &arp_hdr->arp_data.arp_sha);
				arp_hdr->arp_data.arp_sip = target_ip;
				memset(&arp_hdr->arp_data.arp_tha, 0, RTE_ETHER_ADDR_LEN);
				// unsigned char * temp="127.0.0.1";
				// arp_hdr->arp_data.arp_tip=
				// ((unsigned char *)temp)[0]        |
				// (((unsigned char *)temp)[1] << 8)  |
				// (((unsigned char *)temp)[2] << 16) |
				// (((unsigned char *)temp)[3] << 24);
				arp_hdr->arp_data.arp_tip = target_ip;

				/*print MAC addr*/
				// printf("arp_hdr, dst_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				// arp_hdr->arp_data.arp_sha.addr_bytes[0],arp_hdr->arp_data.arp_sha.addr_bytes[1],
				// arp_hdr->arp_data.arp_sha.addr_bytes[2],arp_hdr->arp_data.arp_sha.addr_bytes[3],
				// arp_hdr->arp_data.arp_sha.addr_bytes[4],arp_hdr->arp_data.arp_sha.addr_bytes[5]);

				// printf("arp_hdr, src_addr: %02X:%02X:%02X:%02X:%02X:%02X\n",
				// arp_hdr->arp_data.arp_sha.addr_bytes[0],arp_hdr->arp_data.arp_sha.addr_bytes[1],
				// arp_hdr->arp_data.arp_sha.addr_bytes[2],arp_hdr->arp_data.arp_sha.addr_bytes[3],
				// arp_hdr->arp_data.arp_sha.addr_bytes[4],arp_hdr->arp_data.arp_sha.addr_bytes[5]);

				//struct rte_arp_ipv4 *arp_ipv4 = (struct rte_arp_ipv4 *)&arp_hdr->arp_data;

				unsigned int ip_addr = ntohl(arp_hdr->arp_data.arp_tip);
				struct in_addr ip;
				ip.s_addr=ip_addr;
				char* ip_str=inet_ntoa(ip);
				// printf("[#1] ARP target ip: %s\n",ip_str);
				// printf("[#1] made arp msg\n");
				const uint16_t nb_tx = rte_eth_tx_burst(port ^ 1, 0, &created_pkt, 1);
				// printf("[#1] tx_burst done\n");
				// rte_delay_ms(200); // To Be Removed
				if (count == 1)
					measureTime("A to B");  // @@ 2. Send an ARP request packet

				if (count == 2) {
					printf("\t-> Start to verify the certificate\n");
					const unsigned char message[] = "1234567890123456789012345678901234567890"; // 40 bytes;
					verify_snu_certificate(message);
					measureTime("F to G");  // @@ 7. Complete to verify the certificate
					measureTime("last");
				}
				// /* Free any unsent packets. */
				// if (unlikely(nb_tx < nb_rx)) {
				// 	uint16_t buf;
				// 	for (buf = nb_tx; buf < nb_rx; buf++)
				// 		rte_pktmbuf_free(created_pkt[buf]);
				// }
				// printf("8\n");
				// const uint16_t nb_rx = rte_eth_rx_burst(port, 0,bufs, BURST_SIZE);
				// printf("9\n");
				// if (unlikely(nb_rx == 0))
				// 	continue;
				// printf("10\n");
				// printf("#######################broadcast done and receive##########################\n");
				// for(int i=0;i<nb_rx;i++){
				// 	printf("Receive arp response\n");
				// 	printf("%p\n",bufs);
				// }
				printf("##################################################\n");
			} else {
				printf("%d port is not available", port);
				break;
			}
		}
	}
	/* End of loop. */
}
/* End Basic forwarding application lcore. */

/*
 * The main function, which does initialization and calls the per-lcore
 * functions.
 */
int
main(int argc, char *argv[])
{
	
	unsigned nb_ports;
	uint16_t portid;

	/* Initializion the Environment Abstraction Layer (EAL). */
	int ret = rte_eal_init(argc, argv);
	if (ret < 0)
		rte_exit(EXIT_FAILURE, "Error with EAL initialization\n");
	/* End of initialization the Environment Abstraction Layer (EAL). */

	argc -= ret;
	argv += ret;

	/* Check that there is an even number of ports to send/receive on. */
	nb_ports = rte_eth_dev_count_avail();
	if (nb_ports < 2 || (nb_ports & 1))
		rte_exit(EXIT_FAILURE, "Error: number of ports must be even\n");

	/* Creates a new mempool in memory to hold the mbufs. */

	/* Allocates mempool to hold the mbufs. */
	mbuf_pool = rte_pktmbuf_pool_create("MBUF_POOL", NUM_MBUFS * nb_ports,
		MBUF_CACHE_SIZE, 0, RTE_MBUF_DEFAULT_BUF_SIZE, rte_socket_id());
	/* End of allocating mempool to hold mbuf. */

	if (mbuf_pool == NULL)
		rte_exit(EXIT_FAILURE, "Cannot create mbuf pool\n");

	/* Initializing all ports. */
	RTE_ETH_FOREACH_DEV(portid)
		if (port_init(portid, mbuf_pool) != 0)
			rte_exit(EXIT_FAILURE, "Cannot init port %"PRIu16 "\n",
					portid);
	/* End of initializing all ports. */
	rte_delay_ms(1000);  // For the purpose of showing the configuration info.
	// 	if (rte_lcore_count() > 1)
	// 		printf("\nWARNING: Too many lcores enabled. Only 1 used.\n");

	/* Call lcore_main on the main core only. Called on single lcore. */
	lcore_main();
	/* End of called on single lcore. */

	/* clean up the EAL */
	rte_eal_cleanup();

	return 0;
}
