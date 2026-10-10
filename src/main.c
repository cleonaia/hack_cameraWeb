/**
 * @file main.c
 * @brief Entry point for ft_malcolm ARP spoofing program
 */

#include "ft_malcolm.h"

/* Single global variable permitted by subject for signal handling */
volatile sig_atomic_t g_running = 1;

int main(int argc, char **argv) {
    t_malcolm_config cfg;
    memset(&cfg, 0, sizeof(cfg));
    cfg.sock_fd = -1;
    cfg.interval_ms = 1000;

    /* Quick check for help flag before root check */
    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "-h") == 0 || strcmp(argv[i], "--help") == 0) {
            print_usage(argv[0]);
            return EXIT_SUCCESS;
        }
    }

    /* 1. Verify root / administrative privileges required for raw sockets */
    if (getuid() != 0) {
        fprintf(stderr, "ft_malcolm: must be run as root / sudo user.\n");
        return EXIT_FAILURE;
    }

    /* 2. Setup POSIX signal handlers */
    setup_signals();

    /* 3. Parse command line arguments */
    if (!parse_cli_arguments(argc, argv, &cfg)) {
        return EXIT_FAILURE;
    }

    /* 4. Find and bind active network interface */
    if (find_active_interface(&cfg) != 0) {
        return EXIT_FAILURE;
    }

    /* 5. Open Layer-2 packet transport */
    if (open_packet_socket(&cfg) != 0) {
        return EXIT_FAILURE;
    }

    if (cfg.verbose) {
        print_banner();
        printf(COLOR_GREEN "[+] Initialized on interface: %s (Index: %d)" COLOR_RESET "\n",
               cfg.iface_name, cfg.iface_index);
    }

    /* 6. Run sniffing / spoofing engine */
    int ret = run_malcolm_loop(&cfg);

    /* 7. Clean up and close socket */
    close_packet_socket(&cfg);

    return (ret == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

