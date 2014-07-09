#include <xcopy.h>
#include <intercept.h>

static pid_t           pid;
static uint64_t        tot_copy_resp_packs = 0; 
static uint64_t        tot_resp_packs = 0; 
static uint64_t        tot_router_items = 0; 

#if (!TC_NFQUEUE)
static uint32_t        seq = 1;
static unsigned char   buffer[128];
#endif

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
        tc_log_info(LOG_ERR, 0, "msg event create failed.");
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

    tc_memzero(&msg, sizeof(msg_clt_t));

    tunnel = srv_settings.tunnel;
    if (tunnel[fd].first_in) {
        if (tc_socket_rcv(fd, (char *) &msg, MSG_CLT_MIN_SIZE) == TC_ERR) {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERR;
        }

       version = ntohs(msg.type);

        tunnel[fd].first_in = 0;
        if (msg.clt_ip != 0 || msg.clt_port != 0) {
            tc_log_info(LOG_WARN, 0, "client too old for intercept");
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
        if (tc_socket_rcv(fd, (char *) &msg, tunnel[fd].clt_msg_size) == TC_ERR)
        {
            tc_intercept_release_tunnel(fd, rev);
            return TC_ERR;
        }
    }

    msg.clt_ip = msg.clt_ip;
    msg.clt_port = msg.clt_port;
    msg.type = ntohs(msg.type);
    msg.target_ip = msg.target_ip;
    msg.target_port = msg.target_port;

    switch (msg.type) {
        case CLIENT_ADD:
#if (!TC_SINGLE)
            tot_router_items++;
            tc_log_debug1(LOG_DEBUG, 0, "add client router:%u",
                          ntohs(msg.clt_port));
            router_add(msg.clt_ip, msg.clt_port, 
                    msg.target_ip, msg.target_port, fd);
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


#if (TC_NFQUEUE)
static int tc_nfq_proc_packet(struct nfq_q_handle *qh, 
        struct nfgenmsg *nfmsg, struct nfq_data *nfa, void *data)
{
    int                          id = 0, payload_len, ret,
                                 pass_through_flag;
    tc_iph_t                    *ip;
    register int                 i;
    unsigned char               *payload;
    struct nfqnl_msg_packet_hdr *ph;

    ph = nfq_get_msg_packet_hdr(nfa);
    if (ph) {
        id = ntohl(ph->packet_id);
    }

    payload_len = nfq_get_payload(nfa, &payload);

    if ((size_t) payload_len >= TCP_IP_PACK_MIN_LEN) {

        ip = (tc_iph_t *) payload;

        pass_through_flag = 0;
        if (ip != NULL) {
            for (i = 0; i < srv_settings.passed_ips.num; i++) {
                if (srv_settings.passed_ips.ips[i] == ip->daddr) {
                    pass_through_flag = 1;
                    break;
                }
            }

            tot_resp_packs++;

            if (pass_through_flag) {

                /* pass through the firewall */
                ret = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
            } else {

                tot_copy_resp_packs++;
                router_update(ip);

                /* drop the packet */
                ret = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
            }
        } else {
            ret = TC_ERR;
        }

        return ret;

    } else {
        tc_log_info(LOG_WARN, 0, "payload len wrong:%d", payload_len);
        return TC_ERR;
    }
}


static int
tc_nfq_event_proc(tc_event_t *rev)
{
    int   rv = 0;
    char  buffer[65536];

    if (tc_nfq_socket_rcv(rev->fd, buffer, 65536, &rv) == TC_ERR) {
        return TC_ERR;
    }

    nfq_handle_packet(srv_settings.nfq_handler, buffer, rv);

    return TC_OK;
}

#else

static int
dispose_netlink_packet(int fd, int verdict, unsigned long packet_id)
{
    struct nlmsghdr        *nl_header = (struct nlmsghdr *) buffer;
    struct sockaddr_nl      addr;
    struct ipq_verdict_msg *ver_data;

    /*
     * The IPQM_VERDICT message is used to communicate with
     * the kernel ip queue module.
     */
    nl_header->nlmsg_type  = IPQM_VERDICT;
    nl_header->nlmsg_len   = NLMSG_LENGTH(sizeof(struct ipq_verdict_msg));
    nl_header->nlmsg_flags = (NLM_F_REQUEST);
    nl_header->nlmsg_pid   = pid;
    nl_header->nlmsg_seq   = seq++;
    ver_data = (struct ipq_verdict_msg *) NLMSG_DATA(nl_header);
    ver_data->value = verdict;
    ver_data->id    = packet_id;
    tc_memzero(&addr, sizeof(addr));
    addr.nl_family  = AF_NETLINK;
    addr.nl_pid     = 0;
    addr.nl_groups  = 0;

    /*
     * In an effort to keep packets properly ordered,
     * the impelmentation of the protocol requires that
     * the user space application send an IPQM_VERDICT message
     * after every IPQM PACKET message is received.
     *
     */
    if (sendto(fd, (void *) nl_header, nl_header->nlmsg_len, 0,
                (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) < 0)
    {
        tc_log_info(LOG_ERR, errno, "unable to send mode message");
        return 0;
    }

    return 1;
}


static int
tc_nl_event_proc(tc_event_t *rev)
{
    char            buffer[65536];
    tc_iph_t       *ip;
    register int    i, pass_through_flag;
    unsigned long   packet_id;

    if (tc_nl_socket_rcv(rev->fd, buffer, 65536) == TC_ERR) {
        return TC_ERR;
    }

    ip = tc_nl_ip_header(buffer);
    packet_id = tc_nl_packet_id(buffer);

    if (ip != NULL) {

        pass_through_flag = 0;
        for (i = 0; i < srv_settings.passed_ips.num; i++) {
            if (srv_settings.passed_ips.ips[i] == ip->daddr) {
                pass_through_flag = 1;
                break;
            }
        }

        tot_resp_packs++;

        if (pass_through_flag) {

            /* pass through the firewall */
            dispose_netlink_packet(rev->fd, NF_ACCEPT, packet_id);
            
        } else {

            tot_copy_resp_packs++;
            router_update(ip);
            /* drop the packet */
            dispose_netlink_packet(rev->fd, NF_DROP, packet_id);
        }
    }

    return TC_OK;
}

#endif

int
server_init(tc_event_loop_t *event_loop, char *ip, uint16_t port)
{
    int         fd;
    tc_event_t *ev;

#if (!TC_SINGLE)
    delay_table_init(srv_settings.pool, srv_settings.hash_size);
    if (router_init(srv_settings.pool) != TC_OK) {
        return TC_ERR;
    }
#endif

    pid = getpid();

    /* init the listening socket */
    if ((fd = tc_socket_init()) == TC_INVALID_SOCK) {
        return TC_ERR;

    } else {
        if (tc_socket_listen(fd, ip, port) == TC_ERR) {
            return TC_ERR;
        }

        tc_log_info(LOG_NOTICE, 0, "msg listen socket:%d", fd);

        ev = tc_event_create(event_loop->pool, fd, tc_msg_event_accept, NULL);
        if (ev == NULL) {
            return TC_ERR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERR;
        }
    }

#if (TC_NFQUEUE)   
    if ((fd = tc_nfq_socket_init(&srv_settings.nfq_handler, 
                    &srv_settings.nfq_q_handler, tc_nfq_proc_packet, 
                    srv_settings.max_queue_len)) 
            == TC_INVALID_SOCK)
    {
        return TC_ERR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "nfq socket:%d", fd);

        ev = tc_event_create(event_loop->pool, fd, tc_nfq_event_proc, NULL);
        if (ev == NULL) {
            return TC_ERR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERR;
        }
    }
#else
    if ((fd = tc_nl_socket_init()) == TC_INVALID_SOCK) {
        return TC_ERR;

    } else {
        tc_log_info(LOG_NOTICE, 0, "firewall socket:%d", fd);

        ev = tc_event_create(event_loop->pool, fd, tc_nl_event_proc, NULL);
        if (ev == NULL) {
            return TC_ERR;
        }

        if (tc_event_add(event_loop, ev, TC_EVENT_READ) == TC_EVENT_ERROR) {
            return TC_ERR;
        }
    }

#endif

    return TC_OK;
}

/* clear resources for interception */
void
server_over(void)
{
#if (TC_NFQUEUE)   

    if (srv_settings.nfq_q_handler != NULL) {
        tc_log_info(LOG_NOTICE, 0, "unbinding from queue");
        nfq_destroy_queue(srv_settings.nfq_q_handler);
        srv_settings.nfq_q_handler = NULL;
    }

    if (srv_settings.nfq_handler != NULL) {
        tc_log_info(LOG_NOTICE, 0, "closing nfq library handle");
        nfq_close(srv_settings.nfq_handler);
        srv_settings.nfq_handler = NULL;
    }
#endif

#if (!TC_SINGLE)
    router_destroy(srv_settings.pool);
    delay_table_destroy();
#endif
}

