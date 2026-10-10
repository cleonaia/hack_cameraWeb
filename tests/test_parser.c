/**
 * @file test_parser.c
 * @brief Unit tests for address parsing, validation, and conversion
 */

#include "ft_malcolm.h"
#include <assert.h>

volatile sig_atomic_t g_running = 1;

static int g_tests_run = 0;
static int g_tests_passed = 0;

#define TEST_ASSERT(expr, msg) do { \
    g_tests_run++; \
    if (expr) { \
        g_tests_passed++; \
        printf("  " COLOR_GREEN "[PASS]" COLOR_RESET " %s\n", msg); \
    } else { \
        printf("  " COLOR_RED "[FAIL]" COLOR_RESET " %s (Line %d)\n", msg, __LINE__); \
    } \
} while (0)

void test_mac_parser(void) {
    printf(COLOR_BOLD "\n--- Testing MAC Address Parsing ---" COLOR_RESET "\n");
    uint8_t mac[ETH_ALEN];

    TEST_ASSERT(parse_mac("aa:bb:cc:dd:ee:ff", mac) &&
                mac[0] == 0xaa && mac[5] == 0xff, "Standard lowercase colon MAC");

    TEST_ASSERT(parse_mac("AA:BB:CC:DD:EE:FF", mac) &&
                mac[0] == 0xaa && mac[5] == 0xff, "Uppercase colon MAC");

    TEST_ASSERT(parse_mac("00:11:22:33:44:55", mac) &&
                mac[0] == 0x00 && mac[5] == 0x55, "Numeric colon MAC");

    TEST_ASSERT(parse_mac("aa-bb-cc-dd-ee-ff", mac) &&
                mac[0] == 0xaa && mac[5] == 0xff, "Hyphenated MAC address");

    TEST_ASSERT(!parse_mac("aaa:bb:cc:dd:ee:ff", mac), "Reject 3-digit octet MAC");
    TEST_ASSERT(!parse_mac("aa:bb:cc:dd:ee", mac), "Reject 5-octet MAC");
    TEST_ASSERT(!parse_mac("aa:bb:cc:dd:ee:ff:11", mac), "Reject 7-octet MAC");
    TEST_ASSERT(!parse_mac("gg:hh:ii:jj:kk:ll", mac), "Reject non-hex MAC");
    TEST_ASSERT(!parse_mac("", mac), "Reject empty MAC");
    TEST_ASSERT(!parse_mac(NULL, mac), "Reject NULL MAC");
}

void test_ipv4_parser(void) {
    printf(COLOR_BOLD "\n--- Testing IPv4 Address Parsing ---" COLOR_RESET "\n");
    uint8_t ip[IP4_ALEN];

    TEST_ASSERT(parse_ip("192.168.1.1", ip) &&
                ip[0] == 192 && ip[1] == 168 && ip[2] == 1 && ip[3] == 1, "Dotted IPv4 192.168.1.1");

    TEST_ASSERT(parse_ip("127.0.0.1", ip) &&
                ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1, "Dotted IPv4 127.0.0.1");

    TEST_ASSERT(parse_ip("0.0.0.0", ip) &&
                ip[0] == 0 && ip[1] == 0 && ip[2] == 0 && ip[3] == 0, "Dotted IPv4 0.0.0.0");

    TEST_ASSERT(parse_ip("255.255.255.255", ip) &&
                ip[0] == 255 && ip[1] == 255 && ip[2] == 255 && ip[3] == 255, "Dotted IPv4 255.255.255.255");

    TEST_ASSERT(!parse_ip("10.11.11.1111", ip), "Reject out of range octet (1111)");
    TEST_ASSERT(!parse_ip("256.1.1.1", ip), "Reject octet > 255 (256)");
    TEST_ASSERT(!parse_ip("192.168.1", ip), "Reject 3-octet IP");
    TEST_ASSERT(!parse_ip("192.168.1.1.1", ip), "Reject 5-octet IP");
    TEST_ASSERT(!parse_ip("not_an_ip", ip), "Reject non-resolvable string");
    TEST_ASSERT(!parse_ip("", ip), "Reject empty IP");
    TEST_ASSERT(!parse_ip(NULL, ip), "Reject NULL IP");
}

void test_bonus_ip_formats(void) {
    printf(COLOR_BOLD "\n--- Testing Bonus IP Formats (Decimal / Hex / Hostname) ---" COLOR_RESET "\n");
    uint8_t ip[IP4_ALEN];

    /* 2130706433 = 127.0.0.1 in decimal integer format */
    TEST_ASSERT(parse_ip("2130706433", ip) &&
                ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1, "Decimal integer IP (2130706433 -> 127.0.0.1)");

    /* 0x7f000001 = 127.0.0.1 in hex format */
    TEST_ASSERT(parse_ip("0x7f000001", ip) &&
                ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1, "Hexadecimal IP (0x7f000001 -> 127.0.0.1)");

    /* Hostname DNS resolution bonus */
    TEST_ASSERT(parse_ip("localhost", ip) &&
                ip[0] == 127 && ip[1] == 0 && ip[2] == 0 && ip[3] == 1, "Hostname resolution (localhost -> 127.0.0.1)");
}

void test_arp_frame(void) {
    printf(COLOR_BOLD "\n--- Testing ARP Frame Construction and Filter ---" COLOR_RESET "\n");
    const uint8_t src_mac[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x10};
    const uint8_t dst_mac[ETH_ALEN] = {0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0x20};
    const uint8_t src_ip[IP4_ALEN] = {10, 42, 0, 1};
    const uint8_t dst_ip[IP4_ALEN] = {10, 42, 0, 20};
    const uint8_t broadcast[ETH_ALEN] = {255, 255, 255, 255, 255, 255};
    t_arp_frame frame;
    t_malcolm_config cfg;
    memset(&cfg, 0, sizeof(cfg));

    build_arp_frame(&frame, ARPOP_REPLY, src_mac, dst_mac, src_mac, src_ip, dst_mac, dst_ip);
    TEST_ASSERT(ntohs(frame.eth.eth_type) == ETHERTYPE_ARP &&
                ntohs(frame.arp.opcode) == ARPOP_REPLY &&
                memcmp(frame.arp.sender_ip, src_ip, IP4_ALEN) == 0,
                "Build Ethernet/ARP reply with network byte order");
    TEST_ASSERT(sizeof(frame) == ETH_MIN_LEN, "Pad Ethernet frame to minimum length");

    build_arp_frame(&frame, ARPOP_REQUEST, dst_mac, broadcast, dst_mac, dst_ip,
                    (const uint8_t[ETH_ALEN]){0}, src_ip);
    TEST_ASSERT(is_matching_arp_request(&frame, &cfg),
                "Accept broadcast ARP request (current behavior does not match target IP)");
    frame.eth.dst_mac[0] = 0xaa;
    TEST_ASSERT(!is_matching_arp_request(&frame, &cfg), "Reject non-broadcast ARP request");
}

int main(void) {
    printf(COLOR_CYAN COLOR_BOLD "========================================" COLOR_RESET "\n");
    printf(COLOR_CYAN COLOR_BOLD "   ft_malcolm Unit Test Suite (2026)   " COLOR_RESET "\n");
    printf(COLOR_CYAN COLOR_BOLD "========================================" COLOR_RESET "\n");

    test_mac_parser();
    test_ipv4_parser();
    test_bonus_ip_formats();
    test_arp_frame();

    printf("\n" COLOR_BOLD "Summary:" COLOR_RESET " %d / %d tests passed (%.1f%%)\n\n",
           g_tests_passed, g_tests_run, (float)g_tests_passed / g_tests_run * 100.0f);

    return (g_tests_passed == g_tests_run) ? 0 : 1;
}
