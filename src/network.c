/**
 * @file network.c
 * @brief Network interface detection and cross-platform raw packet transport
 */

#include "ft_malcolm.h"

#if defined(FT_OS_BSD)
static char g_bpf_device[64] = {0};
#endif

static bool is_private_ipv4(const uint8_t ip[IP4_ALEN]) {
    return ip[0] == 10 ||
        (ip[0] == 172 && ip[1] >= 16 && ip[1] <= 31) ||
        (ip[0] == 192 && ip[1] == 168);
}

static bool same_subnet(const uint8_t a[IP4_ALEN], const uint8_t b[IP4_ALEN],
                        const uint8_t mask[IP4_ALEN]) {
    for (size_t i = 0; i < IP4_ALEN; i++) {
        if ((a[i] & mask[i]) != (b[i] & mask[i]))
            return false;
    }
    return true;
}

/**
 * @brief Scan network interfaces using getifaddrs() to find the active interface
 */
int find_active_interface(t_malcolm_config *cfg) {
    struct ifaddrs *ifaddr = NULL;
    struct ifaddrs *ifa = NULL;
    bool found = false;

    if (getifaddrs(&ifaddr) == -1) {
        perror("ft_malcolm: getifaddrs");
        return -1;
    }

    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_name || !ifa->ifa_addr)
            continue;

        /* Skip loopback unless explicitly requested */
        if (!cfg->custom_iface && (ifa->ifa_flags & IFF_LOOPBACK))
            continue;

        /* Check if interface is UP and RUNNING */
        if (!(ifa->ifa_flags & IFF_UP) || !(ifa->ifa_flags & IFF_RUNNING))
            continue;

        /* If custom interface specified, match name */
        if (cfg->custom_iface && strcmp(ifa->ifa_name, cfg->custom_iface) != 0)
            continue;

        /* Extract IPv4 address */
        if (ifa->ifa_addr->sa_family == AF_INET && ifa->ifa_netmask &&
            ifa->ifa_netmask->sa_family == AF_INET) {
            struct sockaddr_in *sin = (struct sockaddr_in *)ifa->ifa_addr;
            struct sockaddr_in *mask = (struct sockaddr_in *)ifa->ifa_netmask;
            uint8_t candidate_ip[IP4_ALEN];
            uint8_t candidate_mask[IP4_ALEN];
            memcpy(candidate_ip, &sin->sin_addr.s_addr, IP4_ALEN);
            memcpy(candidate_mask, &mask->sin_addr.s_addr, IP4_ALEN);
            if (!is_private_ipv4(candidate_ip) || !is_private_ipv4(cfg->src_ip) ||
                !is_private_ipv4(cfg->tgt_ip) ||
                !same_subnet(candidate_ip, cfg->src_ip, candidate_mask) ||
                !same_subnet(candidate_ip, cfg->tgt_ip, candidate_mask))
                continue;
            memcpy(cfg->local_ip, candidate_ip, IP4_ALEN);
            memcpy(cfg->local_netmask, &mask->sin_addr.s_addr, IP4_ALEN);
            strncpy(cfg->iface_name, ifa->ifa_name, sizeof(cfg->iface_name) - 1);
            found = true;
            break;
        }
    }

    if (!found) {
        if (cfg->custom_iface)
            fprintf(stderr, "ft_malcolm: interface '%s' not found or has no active IPv4 address.\n", cfg->custom_iface);
        else
            fprintf(stderr, "ft_malcolm: no active network interface with IPv4 found.\n");
        freeifaddrs(ifaddr);
        return -1;
    }

    /* Now find MAC address and interface index */
#if defined(FT_OS_LINUX)
    int dummy_sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (dummy_sock < 0) {
        perror("ft_malcolm: socket(interface query)");
        freeifaddrs(ifaddr);
        return -1;
    }
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cfg->iface_name, IFNAMSIZ - 1);
    if (ioctl(dummy_sock, SIOCGIFHWADDR, &ifr) < 0) {
        perror("ft_malcolm: ioctl(SIOCGIFHWADDR)");
        close(dummy_sock);
        freeifaddrs(ifaddr);
        return -1;
    }
    memcpy(cfg->local_mac, ifr.ifr_hwaddr.sa_data, ETH_ALEN);
    if (ioctl(dummy_sock, SIOCGIFINDEX, &ifr) < 0) {
        perror("ft_malcolm: ioctl(SIOCGIFINDEX)");
        close(dummy_sock);
        freeifaddrs(ifaddr);
        return -1;
    }
    cfg->iface_index = ifr.ifr_ifindex;
    close(dummy_sock);
#elif defined(FT_OS_BSD)
    for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name && strcmp(ifa->ifa_name, cfg->iface_name) == 0) {
            if (ifa->ifa_addr && ifa->ifa_addr->sa_family == AF_LINK) {
                struct sockaddr_dl *sdl = (struct sockaddr_dl *)ifa->ifa_addr;
                if (sdl->sdl_alen == ETH_ALEN) {
                    memcpy(cfg->local_mac, LLADDR(sdl), ETH_ALEN);
                    cfg->iface_index = sdl->sdl_index;
                    break;
                }
            }
        }
    }
#endif

    freeifaddrs(ifaddr);

    if (!is_private_ipv4(cfg->local_ip) || !is_private_ipv4(cfg->src_ip) ||
        !is_private_ipv4(cfg->tgt_ip) ||
        !same_subnet(cfg->local_ip, cfg->src_ip, cfg->local_netmask) ||
        !same_subnet(cfg->local_ip, cfg->tgt_ip, cfg->local_netmask)) {
        fprintf(stderr, "ft_malcolm: source, target and interface must share a private IPv4 lab subnet.\n");
        return -1;
    }
#if defined(FT_OS_LINUX)
    if (cfg->iface_index <= 0) {
        fprintf(stderr, "ft_malcolm: selected interface has no valid index.\n");
        return -1;
    }
#endif
    bool have_mac = false;
    for (size_t i = 0; i < ETH_ALEN; i++)
        have_mac = have_mac || cfg->local_mac[i] != 0;
    if (!have_mac) {
        fprintf(stderr, "ft_malcolm: selected interface has no usable MAC address.\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Open layer-2 raw packet socket or BSD BPF descriptor
 */
int open_packet_socket(t_malcolm_config *cfg) {
#if defined(FT_OS_LINUX)
    int fd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
    if (fd < 0) {
        perror("ft_malcolm: socket(AF_PACKET)");
        return -1;
    }

    /* Bind to the selected network interface */
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = cfg->iface_index;
    sll.sll_protocol = htons(ETH_P_ARP);

    if (bind(fd, (struct sockaddr *)&sll, sizeof(sll)) < 0) {
        perror("ft_malcolm: bind(AF_PACKET)");
        close(fd);
        return -1;
    }

    cfg->sock_fd = fd;
    return 0;

#elif defined(FT_OS_BSD)
    char bpf_path[32];
    int fd = -1;

    for (int i = 0; i < 99; i++) {
        snprintf(bpf_path, sizeof(bpf_path), "/dev/bpf%d", i);
        fd = open(bpf_path, O_RDWR);
        if (fd != -1) {
            strncpy(g_bpf_device, bpf_path, sizeof(g_bpf_device) - 1);
            break;
        }
        if (errno == EBUSY)
            continue;
        if (errno == EACCES) {
            fprintf(stderr, "ft_malcolm: permission denied opening %s (must be run as root).\n", bpf_path);
            return -1;
        }
    }

    if (fd < 0) {
        perror("ft_malcolm: open(/dev/bpf)");
        return -1;
    }

    /* Set buffer length */
    unsigned int buf_len = 65536;
    if (ioctl(fd, BIOCSBLEN, &buf_len) < 0) {
        perror("ft_malcolm: ioctl(BIOCSBLEN)");
        close(fd);
        return -1;
    }

    /* Bind to interface */
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strncpy(ifr.ifr_name, cfg->iface_name, sizeof(ifr.ifr_name) - 1);
    if (ioctl(fd, BIOCSETIF, &ifr) < 0) {
        perror("ft_malcolm: ioctl(BIOCSETIF)");
        close(fd);
        return -1;
    }

    /* Enable immediate mode so we don't block waiting for full buffer */
    unsigned int enable = 1;
    if (ioctl(fd, BIOCIMMEDIATE, &enable) < 0) {
        perror("ft_malcolm: ioctl(BIOCIMMEDIATE)");
        close(fd);
        return -1;
    }

    /* Set header complete */
    if (ioctl(fd, BIOCSHDRCMPLT, &enable) < 0) {
        perror("ft_malcolm: ioctl(BIOCSHDRCMPLT)");
        close(fd);
        return -1;
    }

    /* Set promiscuous mode */
    if (ioctl(fd, BIOCPROMISC, NULL) < 0) {
        /* Non-fatal warning */
    }

    cfg->sock_fd = fd;
    return 0;
#endif
}

/**
 * @brief Close packet socket / descriptor
 */
void close_packet_socket(t_malcolm_config *cfg) {
    if (cfg->sock_fd >= 0) {
        close(cfg->sock_fd);
        cfg->sock_fd = -1;
    }
}

/**
 * @brief Send raw Ethernet frame
 */
int send_raw_frame(const t_malcolm_config *cfg, const void *frame, size_t len) {
    if (cfg->sock_fd < 0 || !frame || len == 0)
        return -1;

#if defined(FT_OS_LINUX)
    struct sockaddr_ll sll;
    memset(&sll, 0, sizeof(sll));
    sll.sll_family = AF_PACKET;
    sll.sll_ifindex = cfg->iface_index;
    sll.sll_halen = ETH_ALEN;
    memcpy(sll.sll_addr, ((const t_eth_hdr *)frame)->dst_mac, ETH_ALEN);

    ssize_t sent = sendto(cfg->sock_fd, frame, len, 0,
                          (struct sockaddr *)&sll, sizeof(sll));
    if (sent < 0) {
        perror("ft_malcolm: sendto");
        return -1;
    }
    if ((size_t)sent != len) {
        fprintf(stderr, "ft_malcolm: short raw-frame write (%zd of %zu bytes).\n", sent, len);
        return -1;
    }
    return (int)sent;

#elif defined(FT_OS_BSD)
    ssize_t sent = write(cfg->sock_fd, frame, len);
    if (sent < 0) {
        perror("ft_malcolm: bpf write");
        return -1;
    }
    if ((size_t)sent != len) {
        fprintf(stderr, "ft_malcolm: short BPF write (%zd of %zu bytes).\n", sent, len);
        return -1;
    }
    return (int)sent;
#endif
}

/**
 * @brief Receive next raw layer-2 frame
 */
ssize_t recv_raw_frame(const t_malcolm_config *cfg, void *buf, size_t max_len) {
    if (cfg->sock_fd < 0 || !buf || max_len == 0)
        return -1;

#if defined(FT_OS_LINUX)
    ssize_t n = recvfrom(cfg->sock_fd, buf, max_len, 0, NULL, NULL);
    if (n < 0) {
        if (errno == EINTR)
            return 0;
        perror("ft_malcolm: recvfrom");
        return -1;
    }
    return n;

#elif defined(FT_OS_BSD)
    static uint8_t bpf_buffer[65536];
    static ssize_t bpf_bytes = 0;
    static ssize_t bpf_offset = 0;

    while (g_running) {
        if (bpf_offset >= bpf_bytes) {
            bpf_bytes = read(cfg->sock_fd, bpf_buffer, sizeof(bpf_buffer));
            bpf_offset = 0;
            if (bpf_bytes < 0) {
                if (errno == EINTR)
                    return 0;
                perror("ft_malcolm: bpf read");
                return -1;
            }
            if (bpf_bytes == 0)
                return 0;
        }

        if (bpf_offset < bpf_bytes) {
            size_t remaining = (size_t)(bpf_bytes - bpf_offset);
            if (remaining < sizeof(struct bpf_hdr)) {
                fprintf(stderr, "ft_malcolm: truncated BPF record header.\n");
                return -1;
            }
            struct bpf_hdr *hdr = (struct bpf_hdr *)(bpf_buffer + bpf_offset);
            size_t header_len = hdr->bh_hdrlen;
            size_t captured_len = hdr->bh_caplen;
            if (header_len < sizeof(*hdr) || header_len > remaining ||
                captured_len > remaining - header_len) {
                fprintf(stderr, "ft_malcolm: invalid BPF record lengths.\n");
                return -1;
            }
            uint8_t *pkt_data = bpf_buffer + bpf_offset + hdr->bh_hdrlen;
            size_t pkt_len = captured_len;

            size_t record_len = BPF_WORDALIGN(header_len + captured_len);
            if (record_len > remaining) {
                fprintf(stderr, "ft_malcolm: BPF record alignment exceeds buffer.\n");
                return -1;
            }
            bpf_offset += (ssize_t)record_len;

            if (pkt_len > max_len)
                pkt_len = max_len;

            memcpy(buf, pkt_data, pkt_len);
            return pkt_len;
        }
    }
    return 0;
#endif
}
