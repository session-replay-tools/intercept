#include <xcopy.h>
#include <intercept.h>


#if (TC_COMBINED)
void
buffer_and_snd(int fd, msg_server_t *msg)
{
    int                ret = TC_OK, is_snd, bytes;
    unsigned char     *p;
    aggregation_t     *ag;

    if (fd > srv_settings.max_fd) {
        srv_settings.max_fd = fd;
    }

    if (srv_settings.max_fd <= MAX_FD_VALUE) {
        if (srv_settings.tunnel[fd].fd_valid) {

            ag = srv_settings.tunnel[fd].combined;
            if (!ag) {
                ag = (aggregation_t *) tc_palloc(srv_settings.cpool, 
                        sizeof(aggregation_t));
                if (ag != NULL) {
                    tc_log_info(LOG_INFO, 0, "malloc memory for fd:%d", fd);
                    tc_memzero(ag, sizeof(aggregation_t));
                    ag->cur_write = ag->resp;
                    srv_settings.tunnel[fd].combined = ag;
                } else {
                    tc_log_info(LOG_ERR, errno, "can't malloc memory");
                }
            }

            if (ag) {
                if (msg != NULL) {
                    p = ag->cur_write;
                    memcpy((char *) p, (char *) msg, MSG_SERVER_SIZE); 
                    ag->cur_write = p + MSG_SERVER_SIZE;
                    ag->num = ag->num + 1;
                } else {
                    if (ag->num == 0) {
                        return;
                    }
                }

                is_snd = 0;
                if (ag->num >= srv_settings.cur_combined_num) {
                    is_snd = NUM_DRIVEN;
                } else if (ag->access_time == tc_current_time_sec) {
                    if (ag->access_msec != tc_current_time_msec) {
                        is_snd = TIME_DRIVEN;
                    }
                } else if (ag->access_time < tc_current_time_sec) {
                    is_snd = TIME_DRIVEN;
                }

                if (is_snd) {
                    tc_log_debug2(LOG_DEBUG, 0, "combined send:%u,max:%u", 
                            ag->num, srv_settings.cur_combined_num);

                    if (is_snd == TIME_DRIVEN) {
                        if (ag->num < srv_settings.cur_combined_num) {
                            if (srv_settings.cur_combined_num > 1) {
                                srv_settings.cur_combined_num--;
                            }
                        }
                    }  else {
                        if (srv_settings.cur_combined_num < COMB_MAX_NUM) {
                            srv_settings.cur_combined_num++;
                        }
                    }

                    ag->num = htons(ag->num);
                    p = (unsigned char *) (&(ag->num));
                    bytes = ag->cur_write - ag->resp + sizeof(ag->num);
                    tc_log_debug1(LOG_DEBUG, 0, "send bytes:%d", bytes);
                    ret = tc_socket_snd(fd, (char *) p, bytes);
                    srv_settings.sock_w_cnt++;
                    ag->num = 0;
                    ag->cur_write = ag->resp;
                } 

                ag->access_time = tc_current_time_sec;
                ag->access_msec = tc_current_time_msec;

                if (ret == TC_ERR) {
                    tc_intercept_release_tunnel(fd, NULL);
                }
            }

        } else {
            tc_log_debug1(LOG_DEBUG, 0, "fd is not valid:%d", fd);
            return;
        }


    } else {
        tc_log_info(LOG_WARN, 0, "fd is too large:%d", srv_settings.max_fd);
        srv_settings.max_fd = MAX_FD_VALUE;
    }
}


void
send_buffered_packets()
{
    int i;

    for (i = 0; i <= srv_settings.max_fd; i++) {
        if (srv_settings.tunnel[i].fd_valid) {
            buffer_and_snd(i, NULL);
        }
    }
}

#endif


