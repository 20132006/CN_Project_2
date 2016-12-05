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

//added by Alibek
/* default snap length (maximum bytes per packet to capture) */
#define SNAP_LEN 1518

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
