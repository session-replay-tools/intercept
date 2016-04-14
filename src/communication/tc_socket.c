 
#include <xcopy.h>

#if (TC_ADVANCED)

static int
tc_pcap_open(pcap_t **pd, char *device, int snap_len, int buf_size)
{
    int    status;
    char   ebuf[PCAP_ERRBUF_SIZE]; 

    *ebuf = '\0';

    *pd = pcap_create(device, ebuf);
    if (*pd == NULL) {
        tc_log_info(LOG_ERR, 0, "pcap create error:%s", ebuf);
        return TC_ERR;
    }

    status = pcap_set_snaplen(*pd, snap_len);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_snaplen error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_promisc(*pd, 0);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_promisc error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_timeout(*pd, 10);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_timeout error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    status = pcap_set_buffer_size(*pd, buf_size);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_buffer_size error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }

    tc_log_info(LOG_NOTICE, 0, "pcap_set_buffer_size:%d", buf_size);

#if (HAVE_SET_IMMEDIATE_MODE)
    status = pcap_set_immediate_mode(*pd, 1);
    if (status != 0) {
        tc_log_info(LOG_ERR, 0, "pcap_set_immediate_mode error:%s",
                pcap_statustostr(status));
        return TC_ERR;
    }
#endif

    status = pcap_activate(*pd);
    if (status < 0) {
        tc_log_info(LOG_ERR, 0, "pcap_activate error:%s",
                pcap_statustostr(status));
        return TC_ERR;

    } else if (status > 0) {
        tc_log_info(LOG_WARN, 0, "pcap activate warn:%s", 
                pcap_statustostr(status));
    }

    return TC_OK;
}


int
tc_pcap_socket_in_init(pcap_t **pd, char *device, 
        int snap_len, int buf_size, char *pcap_filter)
{
    int         fd;
    char        ebuf[PCAP_ERRBUF_SIZE]; 
    struct      bpf_program fp;
    bpf_u_int32 net, netmask;      

    if (device == NULL) {
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0, "pcap open,device:%s", device);

    *ebuf = '\0';

    if (tc_pcap_open(pd, device, snap_len, buf_size) == TC_ERR) {
        return TC_INVALID_SOCK;
    }

    if (pcap_lookupnet(device, &net, &netmask, ebuf) < 0) {
        tc_log_info(LOG_WARN, 0, "lookupnet:%s", ebuf);
        netmask = PCAP_NETMASK_UNKNOWN;
    }

    if (pcap_compile(*pd, &fp, pcap_filter, 0, netmask) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't parse filter %s: %s", 
                pcap_filter, pcap_geterr(*pd));
        return TC_INVALID_SOCK;
    }

    if (pcap_setfilter(*pd, &fp) == -1) {
        tc_log_info(LOG_ERR, 0, "couldn't install filter %s: %s",
                pcap_filter, pcap_geterr(*pd));
        pcap_freecode(&fp);
        return TC_INVALID_SOCK;
    }

    pcap_freecode(&fp);

    if (pcap_get_selectable_fd(*pd) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_get_selectable_fd fails"); 
        return TC_INVALID_SOCK;
    }

    if (pcap_setnonblock(*pd, 1, ebuf) == -1) {
        tc_log_info(LOG_ERR, 0, "pcap_setnonblock failed: %s", ebuf);
        return TC_INVALID_SOCK;
    }

    fd = pcap_get_selectable_fd(*pd);

    return fd;
}

#endif


#if (!TC_ADVANCED)

#if (!TC_NFQUEUE)
int
tc_nl_socket_init(void)
{
    int                  fd, rcvbuf;
    unsigned char        buf[128];
    struct nlmsghdr     *nl_header;
    struct sockaddr_nl   addr;
    struct ipq_mode_msg *mode_data;

   
    rcvbuf = 1048576;
   
    fd = socket(AF_NETLINK, SOCK_RAW, NETLINK_FIREWALL);

    if (fd == -1) {
        tc_log_info(LOG_ERR, errno, "Create netlink socket failed");
        return TC_INVALID_SOCK;
    }

    if (setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &rcvbuf, sizeof(rcvbuf)) == -1) {
        tc_log_info(LOG_ERR, errno,
                    "Set netlink socket(%d) recvbuf to (%d) failed",
                    fd, rcvbuf);
        return TC_INVALID_SOCK;
    }

    tc_memzero(&addr, sizeof(addr));
    tc_memzero(&buf, 128);

    addr.nl_family = AF_NETLINK;

    nl_header = (struct nlmsghdr *) buf;

    /* It must be ipq_peer_msg, not ipq_mode_msg */
    nl_header->nlmsg_len = NLMSG_LENGTH(sizeof(struct ipq_peer_msg));
    nl_header->nlmsg_flags = NLM_F_REQUEST;
    nl_header->nlmsg_type = IPQM_MODE;
    nl_header->nlmsg_pid = getpid();

    mode_data = NLMSG_DATA(nl_header);
    mode_data->value = IPQ_COPY_PACKET;
    mode_data->range = REP_MAX_USEFUL_SIZE;

    if (sendto(fd, (void *) nl_header, nl_header->nlmsg_len, 0,
               (struct sockaddr *) &addr, sizeof(struct sockaddr_nl)) == -1)
    {
        tc_log_info(LOG_ERR, errno,
                    "Set netlink socket(%d) mode failed, "
                    "check if ip queue is run", fd);
        return TC_INVALID_SOCK;
    }

    return fd;
}


int
tc_nl_socket_rcv(int fd, char *buffer, size_t len)
{
    ssize_t recv_len;

    for ( ;; ) {
        recv_len = recv(fd, buffer, len, 0);

        if (recv_len >= 0) {
            if (recv_len == 0) {
                tc_log_info(LOG_ERR, 0, "recv len is 0");
                return TC_ERR;
            }

            if ((size_t) recv_len < sizeof(struct nlmsghdr)) {
                tc_log_info(LOG_ERR, 0, "recv length not right for netlink");
                return TC_ERR;
            }


            if ((size_t) recv_len < TC_IPQ_NLMSG_LEN) {
                tc_log_info(LOG_WARN, 0, "recv msg len:%ld, expect len:%ld."
                        "(privilage problems or not the obj of intercept)",
                        recv_len, TC_IPQ_NLMSG_LEN);
                return TC_ERR;
            }

            return TC_OK;

        } else {
            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            tc_log_info(LOG_ERR, errno, "nl recvfrom");
            return TC_ERR;
        }
    }

}

#else

int 
tc_nfq_socket_init(struct nfq_handle **h, struct nfq_q_handle **qh,
        nfq_callback *cb, int max_queue_len)
{
    int fd;

    tc_log_info(LOG_NOTICE, 0, "opening library handle");
    *h = nfq_open();
    if (!(*h)) {
        tc_log_info(LOG_ERR, errno, "error during nfq_open()");
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0,
            "unbinding existing nf_queue handler for AF_INET (if any)");
    if (nfq_unbind_pf((*h), AF_INET) < 0) {
        tc_log_info(LOG_ERR, errno, "error during nfq_unbind_pf()");
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0,
            "binding nfnetlink_queue as nf_queue handler for AF_INET");
    if (nfq_bind_pf((*h), AF_INET) < 0) {
        tc_log_info(LOG_ERR, errno, "error during nfq_bind_pf()");
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0, "binding this socket to queue");
    *qh = nfq_create_queue((*h),  0, cb, NULL);
    if (!(*qh)) {
        tc_log_info(LOG_ERR, errno, "error during nfq_create_queue()");
        return TC_INVALID_SOCK;
    }

    tc_log_info(LOG_NOTICE, 0, "setting copy_packet mode");
    if (nfq_set_mode((*qh), NFQNL_COPY_PACKET, REP_MAX_USEFUL_SIZE) < 0) {
        tc_log_info(LOG_ERR, errno, "can't set packet_copy mode");
        return TC_INVALID_SOCK;
    }

    if (max_queue_len > 0) {
        if (nfq_set_queue_maxlen((*qh), (uint32_t) max_queue_len)  < 0) {
            tc_log_info(LOG_ERR, errno, "can't set queue max length:%d", 
                    max_queue_len);
            tc_log_info(LOG_WARN, 0, "unable to set queue maxlen");
            tc_log_info(LOG_WARN, 0, "your kernel probably doesn't support it");
        }
    }

    fd = nfq_fd(*h);

    nfnl_rcvbufsiz(nfq_nfnlh(*h), 16777216);

    return fd;
}


int
tc_nfq_socket_rcv(int fd, char *buffer, size_t len, int *rv)
{
    ssize_t recv_len;

    for ( ;; ) {

        recv_len = recv(fd, buffer, len, 0);

        if (recv_len >= 0) {
            if (recv_len == 0) {
                tc_log_info(LOG_ERR, 0, "nfq recv len is 0");
                return TC_ERR;
            }

            *rv = (int)recv_len;
        } else {

            if (errno == EAGAIN || errno == EINTR) {
                continue;
            }

            if (errno == ENOBUFS) {
                tc_log_info(LOG_WARN, errno, "losing packets!");
                return TC_OK;
            }

            tc_log_info(LOG_ERR, errno, "nfq recvfrom");

            return TC_ERR;
        }

        return TC_OK;
    }
}
#endif

#endif

int
tc_socket_init()
{
    int fd;
   
    fd = socket(AF_INET, SOCK_STREAM, 0);

    if (fd == -1) {
        tc_log_info(LOG_ERR, errno, "Create socket failed");
        return TC_INVALID_SOCK;
    }

    return fd;
}


int
tc_socket_set_nonblocking(int fd)
{
    int flags;

    flags = fcntl(fd, F_GETFL, 0);
    if (flags < 0) {
        return TC_ERR;
    }

    if (fcntl(fd, F_SETFL, flags | O_NONBLOCK) < 0) {
        return TC_ERR;
    }

    return TC_OK;
}


int
tc_socket_set_nodelay(int fd)
{
    int       flag;
    socklen_t len;

    flag = 1;
    len = (socklen_t) sizeof(flag);

    if (setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, (char *) &flag, len) == -1) { 
        return TC_ERR;
    } 

    return TC_OK;
}


int
tc_socket_listen(int fd, const char *bind_ip, uint16_t port)
{
    int                opt, ret;
    socklen_t          len; 
    struct sockaddr_in local_addr;

    tc_memzero(&local_addr, sizeof(local_addr));

    local_addr.sin_port   = ntohs(port);
    local_addr.sin_family = AF_INET;

    if (bind_ip) {
        /* set bind ip for security reasons */
        inet_aton(bind_ip, &local_addr.sin_addr);
    }

    opt = 1;
    ret = setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    if (ret == -1) {
        tc_log_info(LOG_ERR, errno, "setsockopt error");
        return TC_INVALID_SOCK;
    }

    len = (socklen_t) sizeof(local_addr);

    if (bind(fd, (struct sockaddr *) &local_addr, len) == -1) {
        tc_log_info(LOG_ERR, errno, "Bind socket(%d) to port:%u failed",
                    fd, port);
        fprintf(stderr, "Bind socket(%d) to port:%u failed\n", fd, port);
        return TC_ERR;
    }

    if (listen(fd, 5) == -1) {
        tc_log_info(LOG_ERR, errno, "Listen socket(%d) failed", fd);
        fprintf(stderr, "Listen socket(%d) failed\n", fd);
        return TC_ERR;
    }

    return TC_OK;
}


int
tc_socket_rcv(int fd, char *buffer, ssize_t len)
{
    int     cnt = 0;
    size_t  last;
    ssize_t n;

    last = 0;

    for ( ;; ) {
        n = recv(fd, buffer + last, len, 0);

        if (n >= 0) {
            if (n == 0) {
                tc_log_info(LOG_NOTICE, 0, "recv length 0,fd:%d", fd);
                return TC_ERR;
            }

            last += n;

            if ((len -= n) == 0) {
                break;
            }

        } else {
            if (errno == EAGAIN || errno == EINTR) {
                cnt++;
                if (cnt % MAX_READ_LOG_TRIES == 0) {
                    tc_log_info(LOG_NOTICE, 0, "recv tries:%d,fd:%d", cnt, fd);
                }
                continue;
            } else {
                tc_log_info(LOG_NOTICE, errno, "return -1,fd:%d", fd);
                return TC_ERR;
            }
        }
    }

    return TC_OK;
}


int
tc_socket_snd(int fd, char *buffer, int len)
{
    int         cnt = 0;
    ssize_t     send_len, offset = 0, num_bytes;
    const char *ptr;

    if (len <= 0) {
        return TC_OK;
    }

    ptr = buffer;
    num_bytes = len - offset;

    do {

        send_len = send(fd, ptr + offset, num_bytes, 0);

        if (send_len >= 0) {
            if (send_len != num_bytes) {
                tc_log_info(LOG_WARN, 0, "fd:%d, slen:%ld, bsize:%ld",
                        fd, send_len, num_bytes);
            }

            offset += send_len;
            num_bytes -= send_len;

        } else {

            if (cnt > MAX_WRITE_TRIES) {
                tc_log_info(LOG_ERR, 0, "send timeout,fd:%d", fd);
                return TC_ERR;
            }
            if (errno == EINTR) {
                tc_log_info(LOG_NOTICE, errno, "fd:%d EINTR", fd);
                cnt++;
            } else if (errno == EAGAIN) {
                tc_log_info(LOG_NOTICE, errno, "fd:%d EAGAIN", fd);
                cnt++;
            } else {
                tc_log_info(LOG_ERR, errno, "send fd:%d", fd);
                return TC_ERR;
            }
        }

    } while (offset < len);

    return TC_OK;
}

