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
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>

//IP header structure
struct ip *iph;

//Callback function is called when the packet passes through the filter.
void callback(u_char *useless, const struct pcap_pkthdr *pkthdr,
                const u_char *packet)
{
    static int count = 1;
    struct ether_header *ep;
    unsigned short ether_type;
    int chcnt =0;
    int length=pkthdr->len;

    //Get the ethernet header.
    ep = (struct ether_header *)packet;

	//In order to get IP header, offset a size of ethernet header.
    packet += sizeof(struct ether_header);

    //Get a protocol type.
    ether_type = ntohs(ep->ether_type);

//Write code2.
//If the packet is IP packet and the source or destination address is same as the IP address of Raspberry Pi,
//print out the packet information(version, header length, identification, time to live,
//source and destination address).


}

void
got_packet(u_char *args, const struct pcap_pkthdr *header, const u_char *packet)
{
  	static int count = 1;                   /* packet counter */

  	/* declare pointers to packet headers */
  	const struct sniff_ethernet *ethernet;  /* The ethernet header [1] */
  	const struct sniff_ip *ip;              /* The IP header */
  	const struct sniff_tcp *tcp;            /* The TCP header */
  	const char *payload;                    /* Packet payload */

  	int size_ip;
  	int size_tcp;
  	int size_payload;

  	printf("\nPacket number %d:\n", count);
  	count++;

  	/* define ethernet header */
  	ethernet = (struct sniff_ethernet*)(packet);

  	/* define/compute ip header offset */
  	ip = (struct sniff_ip*)(packet + SIZE_ETHERNET);
  	size_ip = IP_HL(ip)*4;
  	if (size_ip < 20) {
  		printf("   * Invalid IP header length: %u bytes\n", size_ip);
  		return;
  	}

  	/* print source and destination IP addresses */
  	printf("       From: %s\n", inet_ntoa(ip->ip_src));
  	printf("         To: %s\n", inet_ntoa(ip->ip_dst));

  	/* determine protocol */
  	switch(ip->ip_p) {
  		case IPPROTO_TCP:
  			printf("   Protocol: TCP\n");
  			break;
  		case IPPROTO_UDP:
  			printf("   Protocol: UDP\n");
  			return;
  		case IPPROTO_ICMP:
  			printf("   Protocol: ICMP\n");
  			return;
  		case IPPROTO_IP:
  			printf("   Protocol: IP\n");
  			return;
  		default:
  			printf("   Protocol: unknown\n");
  			return;
  	}

  	/*
  	 *  OK, this packet is TCP.
  	 */

  	/* define/compute tcp header offset */
  	tcp = (struct sniff_tcp*)(packet + SIZE_ETHERNET + size_ip);
  	size_tcp = TH_OFF(tcp)*4;
  	if (size_tcp < 20) {
  		printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
  		return;
  	}

  	printf("   Src port: %d\n", ntohs(tcp->th_sport));
  	printf("   Dst port: %d\n", ntohs(tcp->th_dport));

  	/* define/compute tcp payload (segment) offset */
  	payload = (u_char *)(packet + SIZE_ETHERNET + size_ip + size_tcp);

  	/* compute tcp payload (segment) size */
  	size_payload = ntohs(ip->ip_len) - (size_ip + size_tcp);

  	/*
  	 * Print payload data; it might be binary, so don't just
  	 * treat it as a string.
  	 */
  	if (size_payload > 0) {
  		printf("   Payload (%d bytes):\n", size_payload);
  		print_payload(payload, size_payload);
  	}
    return;
}

int main(int argc, char **argv)
{
    char *dev;
    char *net;
    char *mask;

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
    char *filter_exp[] = argv[2];		/* filter expression [3] */

    printf("%s\n", filter_exp);

    //Get a current device name.
    dev = pcap_lookupdev(errbuf);
    if (dev == NULL)
    {
        printf("%s\n", errbuf);
        exit(1);
    }

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
