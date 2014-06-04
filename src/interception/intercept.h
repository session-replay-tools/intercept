#ifndef TC_INCLUDED
#define TC_INCLUDED

typedef struct passed_ip_addr_s {
    /* It allows 32 ip addresses passed through server firewall */
    uint32_t    ips[MAX_ALLOWED_IP_NUM];
    int         num;
} passed_ip_addr_t;

#if (TC_ADVANCED)
typedef struct ip_port_pair_t {
    uint32_t ip;
    uint16_t port;
}ip_port_pair_t;


typedef struct ip_port_pairs_t {
    ip_port_pair_t **map;
    int              num;
}ip_port_pairs_t;

#endif

#if (TC_COMBINED)
typedef struct aggregation_s{
    time_t         access_time;
    long           access_msec;
    unsigned char *cur_write;
    uint16_t       num;
    unsigned char  resp[COMB_LENGTH];
}aggregation_t;
#endif

typedef struct tunnel_basic_t{
    tc_event_t     *ev;
#if (TC_COMBINED)
    aggregation_t  *combined;
#endif
    unsigned int    fd_valid:1;
    unsigned int    first_in:1;
    unsigned int    clt_msg_size:16; 
}tunnel_basic_t;

typedef struct xcopy_srv_settings {

#if (TC_NFQUEUE)   
    struct nfq_handle   *nfq_handler;    /* NFQUEUE library handler */
    struct nfq_q_handle *nfq_q_handler;  /* NFQUEUE queue handler */
    int                  max_queue_len;
#endif

    uint32_t             hash_size;      /* hash size for kinds of table */
    int                  max_fd;
#if (!TC_ADVANCED)
    passed_ip_addr_t     passed_ips;     /* passed ip list */
#endif
#if (TC_SINGLE)
    time_t               accepted_tunnel_time;
    int                  s_fd_num;
    int                  s_fd_index;
    int                  s_router_fds[MAX_FD_NUM];
    bool                 conn_protected;
#endif
    bool                 old;            /* old client flag */
    unsigned int         do_daemonize:1; /* daemon flag */
#if (TC_COMBINED)
    unsigned int         cur_combined_num:5;
#endif
    uint16_t             port;           /* TCP port number to listen on */

#if (TC_ADVANCED)
#if (TC_PCAP)
    char                *raw_device;
    char                *user_filter;
#endif
    ip_port_pairs_t      targets;
    char                *raw_tf;
#endif

    uint64_t             sock_w_cnt;
    tc_pool_t           *pool;
    tc_pool_t           *cpool;

#if (!TC_ADVANCED)
    char                *raw_ip_list;    /* raw ip list */
#endif
    char                *pid_file;       /* pid file */
    char                *bound_ip;       /* bound ip for security */
    char                *log_path;       /* error log path */

    tunnel_basic_t       tunnel[MAX_FD_NUM];
#if (TC_ADVANCED && TC_PCAP)
    devices_t            devices;
    char                 filter[MAX_FILTER_LENGH];
#endif
}xcopy_srv_settings;

extern xcopy_srv_settings srv_settings;

#include <tc_util.h>
#include <tc_combine.h>
#include <tc_delay.h>
#include <tc_server_common.h>
#include <tc_interception.h>
#include <tc_router.h>

#endif /* TC_INCLUDED */
