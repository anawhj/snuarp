
# SNUARP
SNUARP makes ARP reply to be sent in a secure way to protect ARP spoofing attack.

## Installation
1. Compilation of the DPDK
* https://doc.dpdk.org/guides/linux_gsg/sys_reqs.html
* https://doc.dpdk.org/guides/linux_gsg/linux_drivers.html
2. Configure a DPDK-compatible NIC (e.g. Intel X710-DA2)
```bash
$ sudo ./dpdk-devbind.py -b vfio-pci 01:00.0
$ sudo ./dpdk-devbind.py -b vfio-pci 01:00.1
```
3. Download the required files to run SNUARP.
```bash
$ git clone https://github.com/anawhj/snuarp
```

## How to run snuarp
```bash
$ make
$ sudo ./build/snuarp
```

## How to run sock_raw_arp_applications
1. Modify the NIC driver name, sender MAC address and target IP address in both files
2. Compile and run arp_r and arp_s in order
```bash
$ gcc -o arp_r sock_raw_arp_receiver.c
$ gcc -o arp_s sock_raw_arp_sender.c
$ sudo ./arp_r
$ sudo ./arp_s
```
