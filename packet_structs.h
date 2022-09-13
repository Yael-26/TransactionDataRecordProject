#include "pcap.h"
#include <netinet/in.h>
#include <time.h>
#include <arpa/inet.h>
#define SNAP_LEN 1518
/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14
/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN 6
#define IPHDRLEN 16
// for ip hash functiom
#define HASH_MASK ((1 << 20) - 1)
struct sniff_ip
{
    unsigned char ip_vhl;          /* version << 4 | header length >> 2 */
    unsigned char ip_tos;          /* type of service */
    unsigned short ip_len;         /* total length */
    unsigned short ip_id;          /* identification */
    unsigned short ip_off;         /* fragment offset field */
#define IP_RF 0x8000               /* reserved fragment flag */
#define IP_DF 0x4000               /* don't fragment flag */
#define IP_MF 0x2000               /* more fragments flag */
#define IP_OFFMASK 0x1fff          /* mask for fragmenting bits */
    unsigned char ip_ttl;          /* time to live */
    unsigned char ip_p;            /* protocol */
    unsigned short ip_sum;         /* checksum */
    struct in_addr ip_src, ip_dst; /* source and dest address */
};
struct sniff_udp
{
    unsigned short udp_srcport;
    unsigned short udp_destport;
    unsigned short udp_len;
    unsigned short udp_sum;
};
/* Length of the Ethernet Header (Data Link Layer) */
#define ETHERNET_HEADER_LEN 14 

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN  6

/* Ethernet header */
struct sniff_ethernet {
    unsigned char ether_dhost[ETHER_ADDR_LEN]; /* Destination host address (i.e. Destination MAC Address) */
    unsigned char ether_shost[ETHER_ADDR_LEN]; /* Source host address (i.e. Source MAC Address) */
    unsigned short ether_type; /* IP? ARP? RARP? etc */
};
