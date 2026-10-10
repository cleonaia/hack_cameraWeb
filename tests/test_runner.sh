#!/usr/bin/env bash
# ==============================================================================
# ft_malcolm CLI smoke tests (no packet I/O)
# ==============================================================================

set -e

COLOR_GREEN="\033[32m"
COLOR_RED="\033[31m"
COLOR_YELLOW="\033[33m"
COLOR_CYAN="\033[36m"
COLOR_RESET="\033[0m"

echo -e "\n${COLOR_CYAN}=== Running ft_malcolm CLI Integration Tests ===${COLOR_RESET}"

EXECUTABLE="${FT_MALCOLM_BIN:-./ft_malcolm}"

if [ ! -f "$EXECUTABLE" ]; then
    echo -e "${COLOR_RED}[!] Executable $EXECUTABLE not found. Run 'make' first.${COLOR_RESET}"
    exit 1
fi

TOTAL_TESTS=0
PASSED_TESTS=0

run_test() {
    local desc="$1"
    local expected_status="$2"
    local expected_pattern="$3"
    shift 3

    TOTAL_TESTS=$((TOTAL_TESTS + 1))
    echo -ne "  [TEST $TOTAL_TESTS] $desc ... "

    set +e
    output=$("$@" 2>&1)
    status=$?
    set -e

    if [ "$status" -eq "$expected_status" ]; then
        if [ -n "$expected_pattern" ]; then
            if echo "$output" | grep -qE "$expected_pattern"; then
                echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
                PASSED_TESTS=$((PASSED_TESTS + 1))
                return 0
            else
                echo -e "${COLOR_RED}FAIL (Pattern '$expected_pattern' not found in output)${COLOR_RESET}"
                echo -e "      Output: $output"
                return 1
            fi
        else
            echo -e "${COLOR_GREEN}PASS${COLOR_RESET}"
            PASSED_TESTS=$((PASSED_TESTS + 1))
            return 0
        fi
    else
        echo -e "${COLOR_RED}FAIL (Expected exit code $expected_status, got $status)${COLOR_RESET}"
        echo -e "      Output: $output"
        return 1
    fi
}

# 1. Help flag tests
run_test "CLI --help flag" 0 "Usage:" "$EXECUTABLE" --help
run_test "CLI -h flag" 0 "Mandatory Arguments" "$EXECUTABLE" -h

# 2. Non-root execution test
if [ "$(id -u)" -ne 0 ]; then
    run_test "Non-root execution check" 1 "must be run as root" "$EXECUTABLE" 192.168.1.1 aa:bb:cc:dd:ee:ff 192.168.1.2 11:22:33:44:55:66
else
    echo "  [SKIP] Non-root execution check (test process is root)"
fi

echo -e "\n${COLOR_CYAN}Integration Test Results: $PASSED_TESTS / $TOTAL_TESTS passed.${COLOR_RESET}\n"
