#include <xcopy.h>
#include <intercept.h>

#if (TC_ADVANCED)

static uint64_t     tot_copy_resp_packs = 0; 
static uint64_t     tot_resp_packs = 0; 
static uint64_t     tot_router_items = 0; 
static  pcap_t     *pcap_map[MAX_FD_NUM];

static int tc_msg_event_proc(tc_event_t *rev);


static int
tc_msg_event_accept(tc_event_t *rev)
{
    tc_event_t     *ev;
    register int    fd;
    tunnel_basic_t *tunnel;

    if ((fd = tc_socket_accept(rev->fd)) == TC_INVALID_SOCK) {
        tc_log_info(LOG_ERR, 0, "msg accept failed, from listen:%d", rev->fd);
        return TC_ERR;
    }
    
    tc_log_info(LOG_NOTICE, 0, "it adds fd:%d", fd);

    if (tc_socket_set_nodelay(fd) == TC_ERR) {
        tc_log_info(LOG_ERR, 0, "Set no delay to socket(%d) failed.", rev->fd);
        tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
        tc_socket_close(fd);
        return TC_ERR;
    }

#if (TC_SINGLE)  
    if (!tc_intercept_check_tunnel_for_single(fd)) {
        tc_log_info(LOG_WARN, 0, "sth tries to connect to server.");
        tc_log_info(LOG_NOTICE, 0, "it close socket:%d", fd);
        tc_socket_close(fd);
        return TC_ERR;
    }
#endif   

    ev = tc_event_create(rev->loop->pool, fd, tc_msg_event_proc, NULL);
    if (ev == NULL) {
        tc_log_info(LOG_ERR, 0, "Msg event create failed.");
        return TC_ERR;
    }

    if (tc_event_add(rev->loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        return TC_ERR;
    }

    tunnel = srv_settings.tunnel;
    tunnel[fd].ev = ev;
    tunnel[fd].first_in = 1;
    tunnel[fd].fd_valid = 1;

    return TC_OK;
}


static int 
tc_msg_event_proc(tc_event_t *rev)
{
    msg_clt_t       msg;
    register int    fd, version;
    tunnel_basic_t *tunnel;

    fd = rev->fd;
    tunnel = srv_settings.tunnel;

    if (!tunnel[fd].first_in) {
        if (tc_socket_rcv(fd, (char *) &msg, tunnel[fd].clt_msg_size) == TC_ERR)
        {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERR;
        }
    } else {

        if (tc_socket_rcv(fd, (char *) &msg, MSG_CLT_MIN_SIZE) != TC_ERR) {
            tunnel[fd].first_in = 0;

            version = ntohs(msg.type);
            if (msg.clt_ip != 0 || msg.clt_port != 0) {
                tc_log_info(LOG_ERR, 0, "client too old for intercept");
                return TC_ERR;
            } else {
                if (version != INTERNAL_VERSION) {
                    tc_log_info(LOG_WARN, 0, 
                            "not compatible,client:%d,intercept:%d",
                            msg.type, INTERNAL_VERSION);
                }
                tunnel[fd].clt_msg_size = MSG_CLT_SIZE;
                if (tc_socket_rcv(fd, ((char *) &msg + MSG_CLT_MIN_SIZE), 
                            MSG_CLT_SIZE - MSG_CLT_MIN_SIZE) == TC_ERR)
                {
                    tc_intercept_release_tunnel(fd, rev);
                    return TC_ERR;
                }
                return TC_OK;
            }
        } else {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERR;
        }
    }

    msg.type = ntohs(msg.type);

    switch (msg.type) {
        case CLIENT_ADD:
#if (!TC_SINGLE)
            tot_router_items++;
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u",
                    ntohs(msg.clt_port));
            router_add(msg.clt_ip, msg.clt_port, 
                    msg.target_ip,  msg.target_port, rev->fd);
#endif
            break;
        case CLIENT_DEL:
            tc_log_debug1(LOG_DEBUG, 0, "del client router:%u",
                    ntohs(msg.clt_port));
            break;
        default:
            tc_log_info(LOG_WARN, 0, "unknown msg type:%u", msg.type);
    }

    return TC_OK;
}


void
server_stat(tc_event_timer_t *evt)
{
    tc_log_info(LOG_NOTICE, 0, 
            "total resp packs:%llu, all:%llu, route:%llu, sock write cnt:%llu",
            tot_copy_resp_packs, tot_resp_packs, tot_router_items, 
            srv_settings.sock_w_cnt);
#if (!TC_SINGLE)
    router_stat();
#endif
    tc_event_update_timer(evt, OUTPUT_INTERVAL);    
}

#if (TC_COMBINED)
void
server_push(tc_event_timer_t *evt)
{
    send_buffered_packets();
    tc_event_update_timer(evt, CHECK_INTERVAL);    
}
#endif


static void 
resp_dispose(tc_iph_t *ip)
{
    uint16_t           size_ip, size_tcp, tot_len;
    tc_tcph_t         *tcp;

    if (ip->version != 4) {
        tc_log_debug1(LOG_DEBUG, 0, "ip version:%d", ip->version);
        return;
    }

    if (ip->protocol == IPPROTO_TCP) {
        tot_resp_packs++;

        size_ip   = ip->ihl << 2;
        if (size_ip >= IPH_MIN_LEN) {
            tot_len   = ntohs(ip->tot_len);

            tcp = (tc_tcph_t *) ((char *) ip + size_ip);
            size_tcp   = tcp->doff << 2;
            if (size_tcp >= TCPH_MIN_LEN) {
                if (srv_settings.user_filter != NULL) {
                    tot_copy_resp_packs++;
                    if (srv_settings.dockered_ips != NULL) {
                        if (ip->daddr == srv_settings.docker_target_dst_ip) {
                            ip->daddr = srv_settings.docker_target_orig_ip;
                        }
                    }
                    router_update(ip);
                }
            } else {
                tc_log_info(LOG_WARN, 0, "Invalid TCP len: %d,tot_len:%d",
                        size_tcp, tot_len);
            }

        } else {
            tc_log_info(LOG_WARN, 0, "Invalid IP header length: %d", size_ip);
        }
    }
}


static void 
pcap_pack_callback(unsigned char *args, const struct pcap_pkthdr *pkt_hdr,
        unsigned char *frame)
{
    int            l2_len;
    pcap_t        *pcap;
    unsigned char *ip_data; 

    if (pkt_hdr->len >= ETHERNET_HDR_LEN) {
        pcap = (pcap_t *) args;
        ip_data = get_ip_data(pcap, frame, pkt_hdr->len, &l2_len);
        resp_dispose((tc_iph_t *) ip_data);
    } else {
        tc_log_info(LOG_ERR, 0, "recv len is less than:%d", ETHERNET_HDR_LEN);
    }
}


static int
tc_proc_resp_packet(tc_event_t *rev)
{
    pcap_t        *pcap;

    pcap = pcap_map[rev->fd];
    pcap_dispatch(pcap, 10, (pcap_handler) pcap_pack_callback, 
            (u_char *) pcap);

    return TC_OK;
}


static int 
tc_device_set(tc_event_loop_t *event_loop, device_t *device) 
{
    int         fd;
    tc_event_t *ev;

    fd = tc_pcap_socket_in_init(&(device->pcap), device->name,
            REP_RCV_BUF_SIZE, TC_PCAP_BUF_SIZE, srv_settings.filter);
    if (fd == TC_INVALID_SOCK) {
        return TC_ERR;
    }

    pcap_map[fd] = device->pcap;

    ev = tc_event_create(event_loop->pool, fd, tc_proc_resp_packet, NULL);
    if (ev == NULL) {
        return TC_ERR;
    }

    ev->low_prior = 1;
    if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
        tc_log_info(LOG_ERR, 0, "add socket(%d) to event loop failed.", fd);
        return TC_ERR;
    }

    return TC_OK;
}


static int
sniff_init(tc_event_loop_t *event_loop)
{
    int         i;
    bool        work;
    char        ebuf[PCAP_ERRBUF_SIZE];
    devices_t  *devices;
    pcap_if_t  *alldevs, *d;

    devices = &(srv_settings.devices);
    if (srv_settings.raw_device == NULL) {
        if (pcap_findalldevs(&alldevs, ebuf) == -1) {
            tc_log_info(LOG_ERR, 0, "error in pcap_findalldevs:%s", ebuf);
            return TC_ERR;
        }

        i = 0;
        for (d = alldevs; d; d = d->next)
        {
            if (strcmp(d->name, DEFAULT_DEVICE) == 0) {
                continue;
            }

            if (i >= MAX_DEVICE_NUM) {
                pcap_freealldevs(alldevs);
                tc_log_info(LOG_ERR, 0, "It has too many devices");
                return TC_ERR;
            }

            strncpy(devices->device[i++].name, d->name,
                    MAX_DEVICE_NAME_LEN - 1);
        }
        devices->device_num = i;

        pcap_freealldevs(alldevs);
    }

    work = false;
    for (i = 0; i < devices->device_num; i++) {
        if (tc_device_set(event_loop, &(devices->device[i]))
                == TC_ERR) 
        {
            tc_log_info(LOG_WARN, 0, "device could not work:%s", 
                    devices->device[i].name);
        } else {
            work = true;
        }
    }

    if (!work) {
        tc_log_info(LOG_ERR, 0, "no device available for snooping packets");
        return TC_ERR;
    }

    return TC_OK;

}


int
server_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
    tc_event_t *ev;

    delay_table_init(srv_settings.pool, srv_settings.hash_size);
    if (router_init(srv_settings.pool) != TC_OK) {
        return TC_ERR;
    }

    if ((fd = tc_socket_init()) == TC_INVALID_SOCK) {
        return TC_ERR;

    } else {
        if (tc_socket_listen(fd, ip, port) == TC_ERR) {
            tc_socket_close(fd);
            return TC_ERR;
        }

        tc_log_info(LOG_NOTICE, 0, "msg listen socket:%d", fd);

        ev = tc_event_create(event_loop->pool, fd, tc_msg_event_accept, NULL);
        if (ev == NULL) {
            tc_socket_close(fd);
            return TC_ERR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            tc_socket_close(fd);
            return TC_ERR;
        }
    }

    
    if (sniff_init(event_loop) != TC_OK) {
        tc_socket_close(fd);
        return TC_ERR;
    }

    return TC_OK;
}


void
server_over()
{
    int i;

    router_destroy(srv_settings.pool);
    delay_table_destroy();

    for (i = 0; i < MAX_FD_NUM; i++) {
        if (pcap_map[i] != NULL) {
            pcap_close(pcap_map[i]);
            pcap_map[i] = NULL;
        }
    }
}

#endif

