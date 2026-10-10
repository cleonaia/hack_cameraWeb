/**
 * @file ft_malcolm.h
 * @brief Header file for ft_malcolm - Man In The Middle ARP Spoofing Engine (2026 Edition)
 * @author 42 Security Curriculum & Modernization Suite
 */

#ifndef FT_MALCOLM_H
# define FT_MALCOLM_H

# define _DEFAULT_SOURCE
# define _GNU_SOURCE
# define _POSIX_C_SOURCE 200809L
# define _DARWIN_C_SOURCE 1

# include <sys/types.h>
# include <stdio.h>
# include <stdlib.h>
# include <string.h>
# include <stdint.h>
# include <stdbool.h>
# include <unistd.h>
# include <errno.h>
# include <signal.h>
# include <ctype.h>
# include <time.h>
# include <sys/socket.h>
# include <netdb.h>
# include <ifaddrs.h>
# include <arpa/inet.h>
# include <netinet/in.h>

# if defined(__APPLE__) || defined(__FreeBSD__) || defined(__OpenBSD__)
#  define FT_OS_BSD 1
#  include <sys/ioctl.h>
#  include <net/bpf.h>
#  include <fcntl.h>
#  include <net/if.h>
#  include <net/if_dl.h>
# else
#  define FT_OS_LINUX 1
#  include <net/if.h>
#  include <net/ethernet.h>
#  include <netpacket/packet.h>
#  include <sys/ioctl.h>
# endif

/* Protocol Constants */
# define ETH_ALEN           6
# define IP4_ALEN           4
# define ETHERTYPE_ARP      0x0806
# define ETHERTYPE_IP       0x0800
# define ARPHRD_ETHER       1
# define ARPOP_REQUEST      1
# define ARPOP_REPLY        2
# define ETH_MIN_LEN        60
# define MAX_IFACE_NAME     32

/* Terminal Colors for Modern CLI Output */
# define COLOR_RESET        "\033[0m"
# define COLOR_BOLD         "\033[1m"
# define COLOR_RED          "\033[31m"
# define COLOR_GREEN        "\033[32m"
# define COLOR_YELLOW       "\033[33m"
# define COLOR_BLUE         "\033[34m"
# define COLOR_MAGENTA      "\033[35m"
# define COLOR_CYAN         "\033[36m"
# define COLOR_GRAY         "\033[90m"

# pragma pack(push, 1)

/**
 * @brief Standard 14-byte Ethernet Header
 */
typedef struct s_eth_hdr {
    uint8_t  dst_mac[ETH_ALEN];
    uint8_t  src_mac[ETH_ALEN];
    uint16_t eth_type;
} t_eth_hdr;

/**
 * @brief Standard 28-byte ARP Packet Header (RFC 826)
 */
typedef struct s_arp_hdr {
    uint16_t hw_type;
    uint16_t proto_type;
    uint8_t  hw_len;
    uint8_t  proto_len;
    uint16_t opcode;
    uint8_t  sender_mac[ETH_ALEN];
    uint8_t  sender_ip[IP4_ALEN];
    uint8_t  target_mac[ETH_ALEN];
    uint8_t  target_ip[IP4_ALEN];
} t_arp_hdr;

/**
 * @brief Full Layer-2 ARP Frame (42 bytes + optional padding)
 */
typedef struct s_arp_frame {
    t_eth_hdr eth;
    t_arp_hdr arp;
    uint8_t   padding[18];
} t_arp_frame;

# pragma pack(pop)

/**
 * @brief Configuration and session state for ft_malcolm
 */
typedef struct s_malcolm_config {
    /* CLI Arguments */
    char        *src_ip_str;
    char        *src_mac_str;
    char        *tgt_ip_str;
    char        *tgt_mac_str;

    /* Parsed Binary Addresses */
    uint8_t     src_ip[IP4_ALEN];
    uint8_t     src_mac[ETH_ALEN];
    uint8_t     tgt_ip[IP4_ALEN];
    uint8_t     tgt_mac[ETH_ALEN];

    /* Interface Information */
    char        iface_name[MAX_IFACE_NAME];
    int         iface_index;
    uint8_t     local_mac[ETH_ALEN];
    uint8_t     local_ip[IP4_ALEN];
    uint8_t     local_netmask[IP4_ALEN];

    /* Socket / Descriptor */
    int         sock_fd;

    /* Bonus Flags */
    bool        verbose;
    bool        continuous;
    bool        restore_on_exit;
    bool        subject_compat;
    int         interval_ms;
    char        *custom_iface;
} t_malcolm_config;

/* Global running flag for signal handling (conforming to subject rule: max 1 global variable) */
extern volatile sig_atomic_t g_running;

/* --- Function Prototypes --- */

/* Parser & Address Validation */
bool    parse_ip(const char *str, uint8_t out_ip[IP4_ALEN]);
bool    parse_mac(const char *str, uint8_t out_mac[ETH_ALEN]);
void    format_ip(const uint8_t ip[IP4_ALEN], char *buf, size_t buf_len);
void    format_mac(const uint8_t mac[ETH_ALEN], char *buf, size_t buf_len);
bool    parse_cli_arguments(int argc, char **argv, t_malcolm_config *cfg);

/* Network & Interface Operations */
int     find_active_interface(t_malcolm_config *cfg);
int     open_packet_socket(t_malcolm_config *cfg);
void    close_packet_socket(t_malcolm_config *cfg);
int     send_raw_frame(const t_malcolm_config *cfg, const void *frame, size_t len);
ssize_t recv_raw_frame(const t_malcolm_config *cfg, void *buf, size_t max_len);

/* ARP Engine Operations */
void    build_arp_frame(t_arp_frame *frame,
                        uint16_t opcode,
                        const uint8_t src_eth_mac[ETH_ALEN],
                        const uint8_t dst_eth_mac[ETH_ALEN],
                        const uint8_t sender_mac[ETH_ALEN],
                        const uint8_t sender_ip[IP4_ALEN],
                        const uint8_t target_mac[ETH_ALEN],
                        const uint8_t target_ip[IP4_ALEN]);

bool    is_matching_arp_request(const t_arp_frame *frame, const t_malcolm_config *cfg);
int     run_malcolm_loop(t_malcolm_config *cfg);
int     send_spoofed_arp_reply(const t_malcolm_config *cfg);
int     restore_arp_table(const t_malcolm_config *cfg);

/* Display & Formatting */
void    print_banner(void);
void    print_usage(const char *prog_name);
void    print_subject_arp_detected(const t_arp_frame *frame);
void    print_subject_reply_sent(void);
void    print_packet_details(const t_arp_frame *frame, const char *title);
void    hex_dump(const void *data, size_t len);

/* Utilities */
void    setup_signals(void);
void    safe_msleep(int ms);
bool    is_valid_decimal_ip(const char *str, uint8_t out_ip[IP4_ALEN]);
bool    resolve_hostname(const char *hostname, uint8_t out_ip[IP4_ALEN]);

#endif /* FT_MALCOLM_H */
