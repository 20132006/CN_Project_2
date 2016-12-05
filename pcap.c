#include <sys/time.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <pcap/pcap.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>


//added by Alibek

#define IP_V(ip)	(((ip)->ver_ihl & 0xf0) >> 4)
#define IP_HL(ip)	((ip)->ver_ihl & 0x0f)

/* 4 bytes IP address */
typedef struct ip_address{
    u_char byte1;
    u_char byte2;
    u_char byte3;
    u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header{
    u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
    u_char  tos;            // Type of service
    u_short tlen;           // Total length
    u_short identification; // Identification
    u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
    u_char  ttl;            // Time to live
    u_char  proto;          // Protocol
    u_short crc;            // Header checksum
    ip_address  saddr;      // Source address
    ip_address  daddr;      // Destination address
    u_int   op_pad;         // Option + Padding
}ip_header;

/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

//IP header structure
struct ip *iph;

//Callback function is called when the packet passes through the filter.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr, const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    //printf("%u\n",iph->ip_v);

    //Get the ethernet header.
    ep = (struct ether_header *)packet;

    //In order to get IP header, offset a size of ethernet header.
    packet += sizeof(struct ether_header);

    //Get a protocol type.
    ether_type = ntohs(ep->ether_type);

    ip_header *ih;

    /* retireve the position of the ip header */
    ih = (ip_header *) packet; //14 length of ethernet header

    struct ip *iph = (struct ip *)packet;
    
    if ((ih->saddr.byte1 == 192 && ih->saddr.byte2 == 168 && ih->saddr.byte3 == 16 && ih->saddr.byte1 == 136) ||
        (ih->daddr.byte1 == 192 && ih->daddr.byte2 == 168 && ih->daddr.byte3 == 16 && ih->daddr.byte4 == 136))
    {
      printf("Version     : %u\n", iph->ip_v );
      printf("Header Len  : %u\n", iph->ip_hl);
      printf("Ident       : %d\n", iph->ip_id);
      printf("TTL         : %u\n", iph->ip_ttl);
      printf("Src Address : %d.%d.%d.%d\nDst Address : %d.%d.%d.%d\n",
          ih->saddr.byte1,
          ih->saddr.byte2,
          ih->saddr.byte3,
          ih->saddr.byte4,

          ih->daddr.byte1,
          ih->daddr.byte2,
          ih->daddr.byte3,
          ih->daddr.byte4);

    }
//Write code2.
//If the packet is IP packet and the source or destination address is same as the IP address of Raspberry Pi,
//print out the packet information(version, header length, identification, time to live,
//source and destination address).


}

int main(int argc, char **argv)
{
    char *dev = NULL;
    bpf_u_int32 net;
    bpf_u_int32 mask;

    bpf_u_int32 netp;
    bpf_u_int32 maskp;
    char errbuf[PCAP_ERRBUF_SIZE];
    int ret;
    struct pcap_pkthdr hdr;
    struct in_addr net_addr, mask_addr;
    struct ether_header *eptr;
    const u_char *packet;
    struct bpf_program fp;

    pcap_t *pcd;
//added by Alibek
    int num_packets = atoi(argv[1]);			/* number of packets to capture */
    char *filter_exp = argv[2];		/* filter expression [3] */
    pcap_t *handle;				/* packet capture handle */

    printf("Number of packets %d\n", num_packets);
    printf("Filtering expression %s\n", filter_exp);

    //Get a current device name.
    dev = pcap_lookupdev(errbuf);
    printf("Stoped here %s\n", dev);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }
    printf("Stoped here\n");

//Write code1.
//Open the device for sniffing using "pcap_open_live".
//Filtering the traffic using "pcap_compile" and "pcap_setfilter"(Your filtering rule is received by argument 2).
//Use "pcap_loop" for callback function(The number of packet capturing is received by argument 1).

    /* get network number and mask associated with capture device */
    if (pcap_lookupnet(dev, &net, &mask, errbuf) == -1)
    {
        printf("Couldn't get netmask for device %s: %s\n",dev, errbuf);
        net = 0;
        mask = 0;
    }
    printf("Device: %s\n", dev);
    printf("Number of packets: %d\n", num_packets);

    /* open capture device */
  	handle = pcap_open_live(dev, SNAP_LEN, 1, 1000, errbuf);
  	if (handle == NULL)
    {
  		  printf("Couldn't open device %s: %s\n", dev, errbuf);
  		  exit(1);
  	}

    /* make sure we're capturing on an Ethernet device [2] */
  	if (pcap_datalink(handle) != DLT_EN10MB)
    {
  		  printf("%s is not an Ethernet\n", dev);
  		  exit(1);
  	}

    /* compile the filter expression */
  	if (pcap_compile(handle, &fp, filter_exp, 0, net) == -1)
    {
  		  printf("Couldn't parse filter %s: %s\n",filter_exp, pcap_geterr(handle));
  		  exit(1);
  	}

  	/* apply the compiled filter */
  	if (pcap_setfilter(handle, &fp) == -1)
    {
  		  printf("Couldn't install filter %s: %s\n",filter_exp, pcap_geterr(handle));
  		  exit(1);
  	}
    /* now we can set our callback function */
  	pcap_loop(handle, num_packets, callback, NULL);

  	/* cleanup */
  	pcap_freecode(&fp);
  	pcap_close(handle);

  	printf("\nCapture complete.\n");
    return 0;
}














//
