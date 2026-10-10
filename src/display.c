/**
 * @file display.c
 * @brief Output formatting, banners, and packet hex-dumping
 */

#include "ft_malcolm.h"

void print_banner(void) {
    printf(COLOR_CYAN COLOR_BOLD
        "  ███████╗████████╗    ███╗   ███╗ █████╗ ██╗      ██████╗ ██████╗ ██╗     ███╗   ███╗\n"
        "  ██╔════╝╚══██╔══╝    ████╗ ████║██╔══██╗██║     ██╔════╝██╔═══██╗██║     ████╗ ████║\n"
        "  █████╗     ██║       ██╔████╔██║███████║██║     ██║     ██║   ██║██║     ██╔████╔██║\n"
        "  ██╔══╝     ██║       ██║╚██╔╝██║██╔══██║██║     ██║     ██║   ██║██║     ██║╚██╔╝██║\n"
        "  ██║        ██║       ██║ ╚═╝ ██║██║  ██║███████╗╚██████╗╚██████╔╝███████╗██║ ╚═╝ ██║\n"
        "  ╚═╝        ╚═╝       ╚═╝     ╚═╝╚═╝  ╚═╝╚══════╝ ╚═════╝ ╚═════╝ ╚══════╝╚═╝     ╚═╝\n"
        COLOR_RESET COLOR_MAGENTA
        "  === Man In The Middle ARP Spoofing & Network Security Suite (2026 Edition) ===\n\n"
        COLOR_RESET);
}

void print_usage(const char *prog_name) {
    printf(COLOR_BOLD "Usage:" COLOR_RESET " %s <source ip> <source mac> <target ip> <target mac> [options]\n\n", prog_name);
    printf(COLOR_BOLD "Mandatory Arguments (in exact order):" COLOR_RESET "\n");
    printf("  " COLOR_GREEN "<source ip>" COLOR_RESET "       IP address to spoof (e.g. gateway router or host)\n");
    printf("  " COLOR_GREEN "<source mac>" COLOR_RESET "      MAC address associated with spoofed source (e.g. your MAC)\n");
    printf("  " COLOR_GREEN "<target ip>" COLOR_RESET "       IP address of target victim machine\n");
    printf("  " COLOR_GREEN "<target mac>" COLOR_RESET "      MAC address of target victim machine\n\n");

    printf(COLOR_BOLD "Bonus Options:" COLOR_RESET "\n");
    printf("  " COLOR_YELLOW "-v, --verbose" COLOR_RESET "        Enable verbose packet inspection and hex dumps\n");
    printf("  " COLOR_YELLOW "-c, --continuous" COLOR_RESET "     Keep spoofing continuously in loop (Man-In-The-Middle mode)\n");
    printf("  " COLOR_YELLOW "-i, --interval <ms>" COLOR_RESET "  Interval between continuous replies in ms (default: 1000)\n");
    printf("  " COLOR_YELLOW "-r, --restore" COLOR_RESET "        Cleanly restore victim's ARP table upon exit\n");
    printf("  " COLOR_YELLOW "-I, --interface <if>" COLOR_RESET " Specify network interface to use (auto-detected if omitted)\n");
    printf("  " COLOR_YELLOW "-h, --help" COLOR_RESET "           Display this help manual\n\n");

    printf(COLOR_BOLD "Features & RFC Compliance:" COLOR_RESET "\n");
    printf("  • RFC 826 ARP Protocol / RFC 7042 IANA Specifications\n");
    printf("  • Dotted-decimal, decimal integer (e.g. 2130706433), and hostname resolution (DNS)\n");
    printf("  • Cross-platform support (Linux AF_PACKET raw sockets & macOS BPF)\n\n");

    printf(COLOR_BOLD "Example:" COLOR_RESET "\n");
    printf("  sudo %s 192.168.1.1 aa:bb:cc:dd:ee:11 192.168.1.50 11:22:33:44:55:66\n\n", prog_name);
}

void print_subject_arp_detected(const t_arp_frame *frame) {
    char req_mac_s[24];
    char req_ip_s[24];

    format_mac(frame->arp.sender_mac, req_mac_s, sizeof(req_mac_s));
    format_ip(frame->arp.sender_ip, req_ip_s, sizeof(req_ip_s));

    printf("An ARP request has been broadcast.\n");
    printf("mac address of request: %s\n", req_mac_s);
    printf("IP address of request: %s\n", req_ip_s);
}

void print_subject_reply_sent(void) {
    printf("Sent an ARP reply packet, you may now check the arp table on the target.\n");
}

void print_packet_details(const t_arp_frame *frame, const char *title) {
    char eth_src[24], eth_dst[24];
    char arp_smac[24], arp_sip[24], arp_tmac[24], arp_tip[24];

    format_mac(frame->eth.src_mac, eth_src, sizeof(eth_src));
    format_mac(frame->eth.dst_mac, eth_dst, sizeof(eth_dst));
    format_mac(frame->arp.sender_mac, arp_smac, sizeof(arp_smac));
    format_ip(frame->arp.sender_ip, arp_sip, sizeof(arp_sip));
    format_mac(frame->arp.target_mac, arp_tmac, sizeof(arp_tmac));
    format_ip(frame->arp.target_ip, arp_tip, sizeof(arp_tip));

    uint16_t op = ntohs(frame->arp.opcode);
    const char *op_str = (op == ARPOP_REQUEST) ? "REQUEST" : (op == ARPOP_REPLY) ? "REPLY" : "UNKNOWN";

    printf("\n" COLOR_CYAN "┌────────────────── %s ──────────────────┐" COLOR_RESET "\n", title);
    printf("│ " COLOR_BOLD "Layer 2 Ethernet Header:" COLOR_RESET "\n");
    printf("│   Source MAC:      %s\n", eth_src);
    printf("│   Destination MAC: %s\n", eth_dst);
    printf("│   EtherType:       0x%04x (ARP)\n", ntohs(frame->eth.eth_type));
    printf("│\n");
    printf("│ " COLOR_BOLD "Layer 3 ARP Header (RFC 826):" COLOR_RESET "\n");
    printf("│   Opcode:          %u (%s)\n", op, op_str);
    printf("│   Sender MAC:      %s\n", arp_smac);
    printf("│   Sender IP:       %s\n", arp_sip);
    printf("│   Target MAC:      %s\n", arp_tmac);
    printf("│   Target IP:       %s\n", arp_tip);
    printf(COLOR_CYAN "└────────────────────────────────────────────────────────────────┘" COLOR_RESET "\n");

    hex_dump(frame, sizeof(t_eth_hdr) + sizeof(t_arp_hdr));
}

void hex_dump(const void *data, size_t len) {
    const uint8_t *p = (const uint8_t *)data;
    size_t i, j;

    printf(COLOR_GRAY "Frame Dump (%zu bytes):\n", len);
    for (i = 0; i < len; i += 16) {
        printf("  %04zx: ", i);

        for (j = 0; j < 16; j++) {
            if (i + j < len)
                printf("%02x ", p[i + j]);
            else
                printf("   ");
            if (j == 7)
                printf(" ");
        }

        printf(" |");
        for (j = 0; j < 16; j++) {
            if (i + j < len) {
                uint8_t c = p[i + j];
                printf("%c", (c >= 32 && c <= 126) ? c : '.');
            }
        }
        printf("|\n");
    }
    printf(COLOR_RESET);
}

