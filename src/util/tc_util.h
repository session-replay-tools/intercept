#ifndef  TC_UTIL_INCLUDED
#define  TC_UTIL_INCLUDED

#include <xcopy.h>


#define TCP_HDR_LEN(tcph) (tcph->doff << 2)
#define IP_HDR_LEN(iph) (iph->ihl << 2)
#define EXTRACT_32BITS(p)   ((uint32_t)ntohl(*(uint32_t *)(p)))

#define TCP_PAYLOAD_LENGTH(iph, tcph) \
        (ntohs(iph->tot_len) - IP_HDR_LEN(iph) - TCP_HDR_LEN(tcph))

#if (TC_UDP)
#define CHECKSUM_CARRY(x) \
        (x = (x >> 16) + (x & 0xffff), (~(x + (x >> 16)) & 0xffff))
#endif

#if (TC_ADVANCED)
int retrieve_devices(char *raw_device, devices_t *devices);
int get_l2_len(const unsigned char *, const int);
unsigned char *get_ip_data(pcap_t *, unsigned char *, const int , int *);
#endif

#endif   /* ----- #ifndef TC_UTIL_INCLUDED  ----- */

