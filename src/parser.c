/**
 * @file parser.c
 * @brief Argument and address parsing functions for ft_malcolm
 */

#include "ft_malcolm.h"

/**
 * @brief Parse and validate a MAC address string
 * Format supported: XX:XX:XX:XX:XX:XX or XX-XX-XX-XX-XX-XX
 */
bool parse_mac(const char *str, uint8_t out_mac[ETH_ALEN]) {
    if (!str || !out_mac || strlen(str) != 17)
        return false;

    char sep = str[2];
    if (sep != ':' && sep != '-')
        return false;

    for (int i = 0; i < 6; i++) {
        char c1 = str[i * 3];
        char c2 = str[i * 3 + 1];

        if (!isxdigit((unsigned char)c1) || !isxdigit((unsigned char)c2))
            return false;

        if (i < 5 && str[i * 3 + 2] != sep)
            return false;

        char hex_byte[3] = { c1, c2, '\0' };
        out_mac[i] = (uint8_t)strtoul(hex_byte, NULL, 16);
    }
    return true;
}

/**
 * @brief Validate standard dotted-decimal IPv4 address
 */
static bool parse_dotted_ipv4(const char *str, uint8_t out_ip[IP4_ALEN]) {
    return inet_pton(AF_INET, str, out_ip) == 1;
}

static bool is_valid_hostname_syntax(const char *name) {
    size_t label_len = 0;
    size_t total_len = 0;
    char previous = '.';

    if (!name || !*name)
        return false;
    for (const unsigned char *p = (const unsigned char *)name; *p; p++) {
        total_len++;
        if (total_len > 253)
            return false;
        if (*p == '.') {
            if (label_len == 0 || previous == '-')
                return false;
            label_len = 0;
        } else if (isalnum(*p) || *p == '-') {
            if (label_len == 0 && *p == '-')
                return false;
            if (++label_len > 63)
                return false;
        } else {
            return false;
        }
        previous = (char)*p;
    }
    return label_len > 0 && previous != '-';
}

/**
 * @brief Check and parse decimal or hexadecimal integer IPv4 notation (Bonus)
 */
bool is_valid_decimal_ip(const char *str, uint8_t out_ip[IP4_ALEN]) {
    if (!str || *str == '\0')
        return false;

    char *endptr = NULL;
    errno = 0;
    unsigned long long val = 0;

    if (str[0] == '0' && (str[1] == 'x' || str[1] == 'X')) {
        val = strtoull(str, &endptr, 16);
    } else {
        /* Check all digits */
        for (const char *p = str; *p; p++) {
            if (!isdigit((unsigned char)*p))
                return false;
        }
        val = strtoull(str, &endptr, 10);
    }

    if (errno != 0 || endptr == str || *endptr != '\0' || val > 0xFFFFFFFFUL)
        return false;

    out_ip[0] = (uint8_t)((val >> 24) & 0xFF);
    out_ip[1] = (uint8_t)((val >> 16) & 0xFF);
    out_ip[2] = (uint8_t)((val >> 8) & 0xFF);
    out_ip[3] = (uint8_t)(val & 0xFF);
    return true;
}

/**
 * @brief Resolve hostname to IPv4 address using DNS (Bonus)
 */
bool resolve_hostname(const char *hostname, uint8_t out_ip[IP4_ALEN]) {
    if (!out_ip || !is_valid_hostname_syntax(hostname))
        return false;

    struct addrinfo hints;
    struct addrinfo *result = NULL;
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_DGRAM;
    int err = getaddrinfo(hostname, NULL, &hints, &result);
    if (err != 0 || !result)
        return false;
    struct sockaddr_in *addr = (struct sockaddr_in *)result->ai_addr;
    memcpy(out_ip, &addr->sin_addr, IP4_ALEN);
    freeaddrinfo(result);
    return true;
}

/**
 * @brief Universal IPv4 Parser supporting dotted-quad, integer, and hostname resolution
 */
bool parse_ip(const char *str, uint8_t out_ip[IP4_ALEN]) {
    if (!str || !out_ip || *str == '\0')
        return false;

    /* 1. Try standard dotted-decimal notation */
    if (parse_dotted_ipv4(str, out_ip))
        return true;

    /* Check if string looks like an invalid dotted IP (e.g. digits and dots) */
    bool has_dot = false;
    bool has_alpha = false;
    for (const char *p = str; *p; p++) {
        if (*p == '.')
            has_dot = true;
        else if (isalpha((unsigned char)*p))
            has_alpha = true;
    }

    if (has_dot && !has_alpha) {
        /* Contains dots and digits/symbols but not valid 4 octets: reject directly */
        return false;
    }

    /* 2. Try decimal/hex integer notation (Bonus) */
    if (is_valid_decimal_ip(str, out_ip))
        return true;

    /* 3. Try hostname resolution (Bonus) */
    if (resolve_hostname(str, out_ip))
        return true;

    return false;
}

/**
 * @brief Format binary IP to string
 */
void format_ip(const uint8_t ip[IP4_ALEN], char *buf, size_t buf_len) {
    if (!buf || buf_len == 0)
        return;
    snprintf(buf, buf_len, "%u.%u.%u.%u", ip[0], ip[1], ip[2], ip[3]);
}

/**
 * @brief Format binary MAC to string
 */
void format_mac(const uint8_t mac[ETH_ALEN], char *buf, size_t buf_len) {
    if (!buf || buf_len == 0)
        return;
    snprintf(buf, buf_len, "%02x:%02x:%02x:%02x:%02x:%02x",
             mac[0], mac[1], mac[2], mac[3], mac[4], mac[5]);
}

/**
 * @brief Parse command line arguments into configuration
 */
bool parse_cli_arguments(int argc, char **argv, t_malcolm_config *cfg) {
    char *pos_args[4] = { NULL, NULL, NULL, NULL };
    int pos_count = 0;

    for (int i = 1; i < argc; i++) {
        char *arg = argv[i];

        if (strcmp(arg, "-h") == 0 || strcmp(arg, "--help") == 0) {
            print_usage(argv[0]);
            exit(EXIT_SUCCESS);
        } else if (strcmp(arg, "-v") == 0 || strcmp(arg, "--verbose") == 0) {
            cfg->verbose = true;
        } else if (strcmp(arg, "-c") == 0 || strcmp(arg, "--continuous") == 0) {
            cfg->continuous = true;
        } else if (strcmp(arg, "-r") == 0 || strcmp(arg, "--restore") == 0) {
            cfg->restore_on_exit = true;
        } else if (strcmp(arg, "--subject-compat") == 0) {
            cfg->subject_compat = true;
        } else if ((strcmp(arg, "-I") == 0 || strcmp(arg, "--interface") == 0) && i + 1 < argc) {
            cfg->custom_iface = argv[++i];
        } else if ((strcmp(arg, "-i") == 0 || strcmp(arg, "--interval") == 0) && i + 1 < argc) {
            char *end = NULL;
            errno = 0;
            long interval = strtol(argv[++i], &end, 10);
            if (errno != 0 || end == argv[i] || *end != '\0' || interval < 1 || interval > 3600000) {
                fprintf(stderr, "ft_malcolm: interval must be an integer from 1 to 3600000 ms.\n");
                return false;
            }
            cfg->interval_ms = (int)interval;
        } else if (arg[0] == '-') {
            fprintf(stderr, "ft_malcolm: unrecognized option '%s'\n", arg);
            fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
            return false;
        } else {
            if (pos_count < 4) {
                pos_args[pos_count++] = arg;
            } else {
                fprintf(stderr, "ft_malcolm: too many arguments provided.\n");
                fprintf(stderr, "Try '%s --help' for more information.\n", argv[0]);
                return false;
            }
        }
    }

    if (pos_count != 4) {
        fprintf(stderr, "ft_malcolm: missing required arguments (expected 4, got %d).\n", pos_count);
        fprintf(stderr, "Usage: %s <source ip> <source mac> <target ip> <target mac> [options]\n", argv[0]);
        return false;
    }

    cfg->src_ip_str = pos_args[0];
    cfg->src_mac_str = pos_args[1];
    cfg->tgt_ip_str = pos_args[2];
    cfg->tgt_mac_str = pos_args[3];

    /* 1. Validate Source IP */
    if (!parse_ip(cfg->src_ip_str, cfg->src_ip)) {
        fprintf(stderr, "ft_malcolm: unknown host or invalid IP address: (%s).\n", cfg->src_ip_str);
        return false;
    }

    /* 2. Validate Source MAC */
    if (!parse_mac(cfg->src_mac_str, cfg->src_mac)) {
        fprintf(stderr, "ft_malcolm: invalid mac address: (%s).\n", cfg->src_mac_str);
        return false;
    }

    /* 3. Validate Target IP */
    if (!parse_ip(cfg->tgt_ip_str, cfg->tgt_ip)) {
        fprintf(stderr, "ft_malcolm: unknown host or invalid IP address: (%s).\n", cfg->tgt_ip_str);
        return false;
    }

    /* 4. Validate Target MAC */
    if (!parse_mac(cfg->tgt_mac_str, cfg->tgt_mac)) {
        fprintf(stderr, "ft_malcolm: invalid mac address: (%s).\n", cfg->tgt_mac_str);
        return false;
    }

    return true;
}
