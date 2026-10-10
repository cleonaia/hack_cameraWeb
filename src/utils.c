/**
 * @file utils.c
 * @brief Signal handlers and utility functions
 */

#include "ft_malcolm.h"

static void handle_signal(int sig) {
    (void)sig;
    g_running = 0;
}

/**
 * @brief Register POSIX signal handlers
 */
void setup_signals(void) {
    struct sigaction sa;
    memset(&sa, 0, sizeof(sa));
    sa.sa_handler = handle_signal;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;

    sigaction(SIGINT, &sa, NULL);
    sigaction(SIGTERM, &sa, NULL);
    sigaction(SIGQUIT, &sa, NULL);
}

/**
 * @brief Safe millisecond sleep that resumes quickly upon signal
 */
void safe_msleep(int ms) {
    if (ms <= 0)
        return;

    struct timespec req;
    req.tv_sec = ms / 1000;
    req.tv_nsec = (ms % 1000) * 1000000L;

    while (nanosleep(&req, &req) == -1 && errno == EINTR) {
        if (!g_running)
            break;
    }
}

