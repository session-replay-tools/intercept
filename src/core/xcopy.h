#ifndef  XCOPY_H_INCLUDED
#define  XCOPY_H_INCLUDED

#include <tc_auto_config.h>
#include <limits.h>
#include <asm/types.h>
#include <stdarg.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <linux/if_ether.h>
#if (TC_UDP)
#include <netinet/udp.h>
#endif
#if (!TC_ADVANCED)
#if (!TC_NFQUEUE)
#include <linux/netlink.h>
#include <linux/netfilter_ipv4.h>
#include <linux/netfilter_ipv4/ip_queue.h>
#else
#include <linux/netfilter.h> 
#include <libnetfilter_queue/libnetfilter_queue.h>
#endif
#endif
#include <arpa/inet.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/resource.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <signal.h>
#include <unistd.h>
#include <time.h>
#include <errno.h>
#include <math.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <getopt.h>
#if (TC_ADVANCED)
#include <pcap.h>
#endif

#define VERSION "1.0.0"  

#define INTERNAL_VERSION 6

typedef struct tc_pool_s        tc_pool_t;
typedef struct tc_buf_s         tc_buf_t;
typedef struct tc_array_s       tc_array_t;


#define COPY_FROM_LINK_LAYER 1

#define ETHER_ADDR_LEN 0x6


#ifndef TC_CPU_CACHE_LINE
#define TC_CPU_CACHE_LINE  64
#endif

#define MAX_FILTER_LENGH 4096 

#define TC_PCAP_BUF_SIZE 16777216

#define TC_MAX_ALLOC_FROM_POOL  (tc_pagesize - 1)

#define TC_DEFAULT_POOL_SIZE    (16 * 1024)

#define TC_POOL_ALIGNMENT       16
#define TC_MIN_POOL_SIZE                                                     \
        tc_align((sizeof(tc_pool_t) + 2 * sizeof(tc_pool_large_t)),            \
                              TC_POOL_ALIGNMENT)

/* default listening port for intercept */
#define SERVER_PORT   36524

#define OUTPUT_INTERVAL  30000

#define CHECK_INTERVAL  2
#define DEFAULT_TIMEOUT 1200

#define MAX_WRITE_TRIES 1024
#define MAX_READ_LOG_TRIES 65536

/* max fd number for select */
#define MAX_FD_NUM    1024
#define MAX_FD_VALUE  (MAX_FD_NUM - 1)
#define MAX_SINGLE_CONN_NUM 16

#if (TC_SINGLE)
#undef TC_MILLION_SUPPORT
#endif

#if (!TC_MILLION_SUPPORT)
#define ROUTE_SLOTS 65536
#define ROUTE_ARRAY_SIZE 15
#define ROUTE_ARRAY_DEPTH 4
#define ROUTE_KEY_HIGH_MASK 0xFFFF0000
#define ROUTE_KEY_LOW_MASK 0x0000FFFF
#define ROUTE_KEY_SHIFT 16
#else
#define ROUTE_SLOTS 1048576
#define ROUTE_ARRAY_SIZE 31
#define ROUTE_ARRAY_DEPTH 5
#define ROUTE_KEY_HIGH_MASK 0xFFFFF000
#define ROUTE_KEY_LOW_MASK  0x00000FFF
#define ROUTE_KEY_SHIFT 12
#endif

#define ROUTE_ARRAY_ACTIVE_NUM_RANGE (ROUTE_ARRAY_SIZE + 1)

#if (TC_COMBINED)
#if (TC_PAYLOAD) 
#define COMB_MAX_NUM 6
#define MAX_PAYLOAD_LEN  128
#else
#define COMB_MAX_NUM 16
#endif
#define COMB_LENGTH (COMB_MAX_NUM * MSG_SERVER_SIZE)
#define TIME_DRIVEN 1
#define NUM_DRIVEN 2
#endif

#define SRC_DIRECTION 0
#define DST_DIRECTION 1
#define MAX_FILTER_ITEMS 32
#define MAX_FILTER_PORTS 32
#define MAX_FILTER_IPS 32
#define MAX_DEVICE_NUM 32
#define MAX_DEVICE_NAME_LEN 32

#define MAX_ALLOWED_IP_NUM 32

/* constants for netlink protocol */
#define FIREWALL_GROUP  0

/* in defence of occuping too much memory */
#define MAX_MEMORY_SIZE 1048576

/* route flags */
#define  CLIENT_ADD   1
#define  CLIENT_DEL   2

#define IPH_MIN_LEN sizeof(tc_iph_t)
#define TCPH_MIN_LEN sizeof(tc_tcph_t)
#define TCP_IP_PACK_MIN_LEN (IPH_MIN_LEN + TCPH_MIN_LEN)

typedef volatile sig_atomic_t tc_atomic_t;

typedef struct iphdr  tc_iph_t;
typedef struct tcphdr tc_tcph_t;

/* 
 * 40 bytes available for TCP options 
 * we support 24 bytes for TCP options
 */
#define MAX_OPTION_LEN 24
#define MAX_TCP_LEN_SUPPORTED (sizeof(tc_tcph_t) + MAX_OPTION_LEN)
#define TCPOPT_WSCALE 3

#define REP_HEADER_SIZE (sizeof(tc_iph_t) + MAX_TCP_LEN_SUPPORTED)
#if (TC_PAYLOAD)
#define REP_MAX_USEFUL_SIZE (REP_HEADER_SIZE + MAX_PAYLOAD_LEN)
#else
#define REP_MAX_USEFUL_SIZE REP_HEADER_SIZE
#endif

/* bool constants */
#if (HAVE_STDBOOL_H)
#include <stdbool.h>
#else
#define bool char
#define false 0
#define true 1
#endif /* HAVE_STDBOOL_H */ 

#define ETHER_ADDR_STR_LEN 17

#ifndef ETHERTYPE_VLAN
#define ETHERTYPE_VLAN 0x8100  /* IEEE 802.1Q VLAN tagging */
#endif

#define CISCO_HDLC_LEN 4
#define SLL_HDR_LEN 16
#define ETHERNET_HDR_LEN (sizeof(struct ethernet_hdr))
#define DEFAULT_DEVICE     "any"

/*  
 *  Ethernet II header
 *  static header size: 14 bytes          
 */ 
struct ethernet_hdr {
    uint8_t  ether_dhost[ETHER_ADDR_LEN];
    uint8_t  ether_shost[ETHER_ADDR_LEN];
    uint16_t ether_type;                 
};

#define CAPTURE_REP_HEADER_MAX_LEN 120
#if (TC_PAYLOAD)
#define CAPTURE_REP_MAX_SIZE (CAPTURE_REP_HEADER_MAX_LEN + MAX_PAYLOAD_LEN)
#else
#define CAPTURE_REP_MAX_SIZE CAPTURE_REP_HEADER_MAX_LEN
#endif
#if (TC_ADVANCED)
#define REP_RCV_BUF_SIZE (ETHERNET_HDR_LEN + CAPTURE_REP_MAX_SIZE)
#else
#define REP_RCV_BUF_SIZE (CAPTURE_REP_MAX_SIZE)
#endif


#if (TC_ADVANCED)
typedef struct device_s{
    char    name[MAX_DEVICE_NAME_LEN];
    pcap_t *pcap;
} device_t;

typedef struct devices_s{
    int       device_num;
    device_t  device[MAX_DEVICE_NUM];
} devices_t;
#endif

/* global functions */
int daemonize(void);

#define TC_OK      0
#define TC_ERR    -1
#define TC_ERR_EXIT  1
#define TC_DECLINED   -2

#define tc_cpymem(d, s, l) (((char *) memcpy(d, (void *) s, l)) + (l))
#define tc_memzero(d, l) (memset(d, 0, l))

#define tc_abs(value)       (((value) >= 0) ? (value) : - (value))
#define tc_max(val1, val2)  ((val1 < val2) ? (val2) : (val1))
#define tc_min(val1, val2)  ((val1 > val2) ? (val2) : (val1))
#define tc_string(str)     { sizeof(str) - 1, (u_char *) str }

#include <tc_config.h>
#include <tc_link_list.h>
#include <tc_hash.h>
#include <tc_time.h>
#include <tc_rbtree.h>
#include <tc_signal.h>

#include <tc_log.h>
#include <tc_msg.h>
#include <tc_socket.h>
#include <tc_util.h>
#include <tc_alloc.h>
#include <tc_palloc.h>
#include <tc_event.h>
#include <tc_event_timer.h>

#ifdef TC_HAVE_EPOLL
#include <sys/epoll.h>
#include <tc_epoll_module.h>
#else
#include <sys/select.h>
#include <tc_select_module.h>
#endif

#endif /* XCOPY_H_INCLUDED */

