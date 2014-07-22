
#include <xcopy.h>

#if (TC_ADVANCED)
int
retrieve_devices(char *raw_device, devices_t *devices)
{
    int          count = 0;
    size_t       len;
    const char  *split, *p;

    p = raw_device;

    while (true) {
        split = strchr(p, ',');
        if (split != NULL) {
            len = (size_t) (split - p);
        } else {
            len = strlen(p);
        }

        strncpy(devices->device[count++].name, p, len);

        if (count == MAX_DEVICE_NUM) {
            tc_log_info(LOG_WARN, 0, "reach the limit for devices");
            break;
        }

        if (split == NULL) {
            break;
        } else {
            p = split + 1;
        }
    }

    devices->device_num = count;

    return 1;
}


int
get_l2_len(const unsigned char *frame, const int datalink)
{
    struct ethernet_hdr *eth_hdr;

    switch (datalink) {
        case DLT_RAW:
            return 0;
            break;
        case DLT_EN10MB:
            eth_hdr = (struct ethernet_hdr *) frame;
            switch (ntohs(eth_hdr->ether_type)) {
                case ETHERTYPE_VLAN:
                    return 18;
                    break;
                default:
                    return 14;
                    break;
            }
            break;
        case DLT_C_HDLC:
            return CISCO_HDLC_LEN;
            break;
        case DLT_LINUX_SLL:
            return SLL_HDR_LEN;
            break;
        default:
            tc_log_info(LOG_ERR, 0, "unsupported DLT type: %s (0x%x)", 
                    pcap_datalink_val_to_description(datalink), datalink);
            break;
    }

    return -1;
}


#ifdef FORCE_ALIGN
static unsigned char pcap_ip_buf[65536];
#endif

unsigned char *
get_ip_data(pcap_t *pcap, unsigned char *frame, const int pkt_len, int *pl2_len)
{
    int      l2_len;
    u_char  *ptr;

    l2_len   = get_l2_len(frame, pcap_datalink(pcap));
    *pl2_len = l2_len;

    if (pkt_len <= l2_len) {
        return NULL;
    }
#ifdef FORCE_ALIGN
    if (l2_len % 4 == 0) {
        ptr = (&(frame)[l2_len]);
    } else {
        ptr = pcap_ip_buf;
        memcpy(ptr, (&(frame)[l2_len]), pkt_len - l2_len);
    }
#else
    ptr = (&(frame)[l2_len]);
#endif

    return ptr;

}
#endif

