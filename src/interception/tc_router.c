#include <xcopy.h>
#include <intercept.h>

static route_table_t  *table = NULL;

/* initiate router table */
int
router_init(tc_pool_t *pool)
{
    table = (route_table_t *) tc_palloc(pool, sizeof(route_table_t));

    if (table == NULL) {
        tc_log_info(LOG_ERR, 0, "malloc route table error");
        return TC_ERR;
    }

    tc_memzero(table, sizeof(route_table_t));
    
    return TC_OK;
}

#if (TC_MILLION_SUPPORT)
static uint64_t
get_route_key(bool old, uint32_t clt_ip, uint16_t clt_port, 
        uint32_t target_ip, uint16_t target_port)
{
    uint64_t value = clt_ip;
    uint64_t l_clt_port = clt_port;

    value = (value << 16) + (l_clt_port << 48);

    if (!old) {
        value = value + target_ip + target_port;
    }

    return value;
}
#else
static uint32_t
get_route_key(bool old, uint32_t clt_ip, uint16_t clt_port, 
        uint32_t target_ip, uint16_t target_port)
{
    uint32_t value  = clt_port;
    uint32_t l_target_port = target_port;

    value = (value << 16) + clt_ip + clt_port;
    if (!old) {
        value = value + target_ip + (l_target_port << 24) + 
            (l_target_port << 8) + target_port;
    }

    return value;
}
#endif

static void 
router_update_adjust(route_slot_t *slot, int child) 
{
    int          parent;
    route_item_t tmp;

    if (child >= 1) {
        parent = (child - 1) / 2;
        tmp = slot->items[parent];
        slot->items[parent] = slot->items[child];
        slot->items[child] = tmp;
    }
}

#if (TC_MILLION_SUPPORT)
static void router_add_adjust(route_slot_t *slot, uint64_t key, int fd) 
#else
static void router_add_adjust(route_slot_t *slot, int key, int fd) 
#endif
{
    int          i, tail_need_save;
    route_item_t item = {0, 0, 0}, tmp;

    tail_need_save = 0;

    if (slot->num > 0) {
        item = slot->items[0];
        if (slot->num == 1) {
            slot->items[1] = item;
        } else {
            tail_need_save = 1;
        }
    }

    slot->items[0].key = key;
    slot->items[0].fd = fd;
    slot->items[0].timestamp = tc_current_time_sec;

    for (i = 1; i < slot->num; i = (i << 1) + 1) {
        if (slot->items[i].timestamp > slot->items[i + 1].timestamp) {
            ++i;
        }

        /* TODO needs to be optimized */ 
        tmp = slot->items[i];
        slot->items[i] = item;
        item = tmp;
        if (item.timestamp == 0) {
            tail_need_save = 0;
        }
    }

    if (slot->num < ROUTE_ARRAY_SIZE) {
        if (tail_need_save) {
            slot->items[slot->num] = item;
        }
        slot->num++;
    } else {
        table->slot_full_cnt++;
    }
}


/* add item to the router table */
void
router_add(int old, uint32_t clt_ip, uint16_t clt_port, uint32_t target_ip, 
        uint16_t target_port, int fd)
{
    int           i, max, existed, index;
#if (TC_MILLION_SUPPORT)
    uint32_t      high_key, low_key;
    uint64_t      key, remainder;
#else
    uint32_t      key, remainder;
#endif
    route_slot_t *slot;

    table->total_sessions++;

#if (TC_DNAT)
    key = get_route_key(old, clt_ip, clt_port, 0, target_port);
#else
    key = get_route_key(old, clt_ip, clt_port, target_ip, target_port);
#endif

#if (TC_MILLION_SUPPORT)
    high_key =(uint32_t) (key << 32);
    low_key =(uint32_t) key;

    index = (int) ((high_key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT);
    remainder = high_key & ROUTE_KEY_LOW_MASK;
    remainder = (remainder << 32) + low_key;
#else
    index = (int) ((key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT);
    remainder = key & ROUTE_KEY_LOW_MASK;
#endif
    tc_log_debug3(LOG_DEBUG, 0, "key:%llu, index:%d, port:%u", 
            key, index, ntohs(clt_port));
    table->cache[index].key = remainder; 
    table->cache[index].fd  = (uint16_t) fd; 

    slot = table->slots + index;

    existed = 0;
    max = ROUTE_ARRAY_SIZE;
    if (slot->num < ROUTE_ARRAY_SIZE) {
        max = slot->num;
    }

    for (i = 0; i < max; i++) {
        if (slot->items[i].key == remainder) {
            slot->items[i].fd = fd;
            slot->items[i].timestamp = tc_current_time_sec;
            existed = 1;
            break;
        }

#if 0
        if (slot->items[i].timestamp == 0) {
            tc_log_info(LOG_WARN, 0, "in add visit %d null timestamp,all:%d",
                    i + 1, max);
        }
#endif

    }

    if (existed) {
        router_update_adjust(slot, i);
    } else {
        router_add_adjust(slot, remainder, fd);
    }

    delay_table_snd(key, fd);

}

#if (!TC_SINGLE)
#if (TC_MILLION_SUPPORT)
static int router_get(uint64_t key)
#else 
static int router_get(uint32_t key)
#endif
{
#if (TC_MILLION_SUPPORT)
    int           i, fd, index;
    uint32_t      high_key, low_key;
    uint64_t      remainder;
#else
    int           i, fd, index, remainder;
#endif
    route_slot_t *slot;

    table->searched++;
#if (TC_MILLION_SUPPORT)
    high_key =(uint32_t) (key << 32);
    low_key =(uint32_t) key;

    index = (int) ((high_key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT);
    remainder = high_key & ROUTE_KEY_LOW_MASK;
    remainder = (remainder << 32) + low_key;
#else
    index = (int) ((key & ROUTE_KEY_HIGH_MASK) >> ROUTE_KEY_SHIFT);
    remainder = key & ROUTE_KEY_LOW_MASK;
#endif

    if (table->cache[index].key == remainder) {
        table->hit++;
        return (int) table->cache[index].fd;
    }

    fd = 0;
    slot = table->slots + index;
    for (i = 0; i < slot->num; i++) {
        if (slot->items[i].key == remainder) {
            table->missed++;
            fd = (int) slot->items[i].fd;
            router_update_adjust(slot, i);
            break;
        }
        table->extra_compared++;
#if 1
        if (slot->items[i].timestamp == 0) {
            tc_log_info(LOG_WARN, 0, "in get, visit %d null timestamp, all:%d",
                    i + 1, slot->num);
        }
#endif
 
    }

    if (i < slot->num) {
        table->cache[index].key = remainder;
        table->cache[index].fd  = fd;
        return fd;
    }
    
    table->lost++;

    return -1;

}
#endif


void
router_update(bool old, tc_iph_t *ip)
{
    int                   fd;
#if (!TC_SINGLE)
#if (TC_MILLION_SUPPORT)
    uint64_t              key;
#else
    uint32_t              key;
#endif
#endif
    uint32_t              size_ip, size_tcp, tot_len;
#if (TC_PAYLOAD)
    uint32_t              cont_len;
    unsigned char        *payload, *p;
#endif
    tc_tcph_t            *tcp;
    msg_server_t          msg;

    size_ip = ip->ihl << 2;
    tcp = (tc_tcph_t *) ((char *) ip + size_ip);
    size_tcp = tcp->doff << 2;
    tot_len  = ntohs(ip->tot_len);

    tc_memzero(&msg, sizeof(struct msg_server_s));
    memcpy((void *) &(msg.ip), ip, sizeof(tc_iph_t));
    if (size_tcp <= MAX_TCP_LEN_SUPPORTED) {
        memcpy((void *) &(msg.tcp), tcp, size_tcp);
    } else {
        tc_log_info(LOG_NOTICE, 0, "tcp header size:%d", size_tcp);
        memcpy((void *) &(msg.tcp), tcp, MAX_TCP_LEN_SUPPORTED);
    }

#if (TC_PAYLOAD)
    cont_len = tot_len - size_ip - size_tcp;
    if (cont_len > 0) {
        payload = (unsigned char *) ((char *) tcp + size_tcp);
        if (cont_len <= MAX_PAYLOAD_LEN) {
            p = ((unsigned char *) &(msg.tcp)) + size_tcp;
            memcpy((void *) p, payload, cont_len);
        }
    }
#endif 

#if (TC_SINGLE)
    if (srv_settings.s_fd_num > 0) {
        fd = srv_settings.s_router_fds[srv_settings.s_fd_index];
        if (fd <= 0) {
            tc_log_info(LOG_WARN, 0, "fd is not valid");
            return;
        }
        srv_settings.s_fd_index = (srv_settings.s_fd_index + 1) % 
            srv_settings.s_fd_num;
    } else {
        tc_log_debug0(LOG_DEBUG, 0, "no valid fd for sending resp");
        return;
    }

#else

#if (TC_DNAT)
    key = get_route_key(old, ip->daddr, tcp->dest, 0, tcp->source);
#else
    key = get_route_key(old, ip->daddr, tcp->dest, ip->saddr, tcp->source);
#endif

    fd  = router_get(key);
    if (fd <= 0) {
        if (tcp->syn || tcp->rst) {
            if (tcp->rst) {
                tc_log_info(LOG_NOTICE, 0, "reset from tcp");
            } 
            tc_log_debug0(LOG_DEBUG, 0, "fd is null");
            delay_table_add(key, &msg);
            return ;
        } else {
            tc_log_info(LOG_NOTICE, 0, "fd is null after session is created");
            tc_log_trace(LOG_NOTICE, 0, ip, tcp);
            return;
        }
    }
#endif

    tc_log_debug_trace(LOG_DEBUG, 0, ip, tcp);

#if (TC_COMBINED)
    buffer_and_snd(fd, &msg);
#else
    if (tc_socket_snd(fd, (char *) &msg, MSG_SERVER_SIZE) == TC_ERR) {
        tc_intercept_release_tunnel(fd, NULL);
    }
#endif

}


void router_stat()
{
    tc_log_info(LOG_NOTICE, 0, "cache hit:%llu,missed:%llu,lost:%llu", 
            table->hit, table->missed, table->lost);
    tc_log_info(LOG_NOTICE, 0, 
            "search:%llu,extra compared:%llu,all sessions:%llu", 
            table->searched, table->extra_compared, table->total_sessions);

}

/* destroy router table */
void
router_destroy(tc_pool_t *pool)
{
    int i, stat[ROUTE_ARRAY_ACTIVE_NUM_RANGE];

    if (table != NULL) {

        tc_log_info(LOG_NOTICE, 0, "session dropped:%llu,all sessions:%llu", 
                table->slot_full_cnt, table->total_sessions);
        tc_log_info(LOG_NOTICE, 0, "cache hit:%llu,missed:%llu,lost:%llu", 
                table->hit, table->missed, table->lost);
        tc_log_info(LOG_NOTICE, 0, "search:%llu,extra compared:%llu", 
            table->searched, table->extra_compared);

        tc_memzero(stat, sizeof(int) * ROUTE_ARRAY_ACTIVE_NUM_RANGE);
        for (i = 0; i < ROUTE_SLOTS; i++) {
            stat[table->slots[i].num]++;
        }

        for (i = 0; i < ROUTE_ARRAY_ACTIVE_NUM_RANGE; i++) {
            tc_log_info(LOG_NOTICE, 0, "array has %d items and its stat:%d",
                    i, stat[i]);
        }

        tc_log_info(LOG_NOTICE, 0, "destroy router table");
        tc_pfree(pool, table);
        table = NULL;
    }
}

