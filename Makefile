# ==============================================================================
# ft_malcolm Makefile
# Reproducible C11 build; BUILD_DIR allows isolated builds and tests.
# ==============================================================================

CC          ?= cc
CFLAGS      ?= -Wall -Wextra -Werror -pedantic -std=c11 -O2
CPPFLAGS     += -Iinclude
LDFLAGS     ?=
LDLIBS      ?=
DEBUG_FLAGS := -g3 -O1 -fsanitize=address,undefined

SRC_DIR     := src
INC_DIR     := include
BUILD_DIR   ?= .
OBJ_DIR     ?= $(BUILD_DIR)/obj
TEST_DIR    := tests

SRCS        := $(SRC_DIR)/main.c \
               $(SRC_DIR)/parser.c \
               $(SRC_DIR)/network.c \
               $(SRC_DIR)/arp.c \
               $(SRC_DIR)/display.c \
               $(SRC_DIR)/utils.c

NAME        ?= $(BUILD_DIR)/ft_malcolm
TEST_NAME   ?= $(BUILD_DIR)/test_malcolm
OBJS        := $(patsubst $(SRC_DIR)/%.c, $(OBJ_DIR)/%.o, $(SRCS))
DEPS        := $(OBJS:.o=.d)
TEST_OBJS   := $(filter-out $(OBJ_DIR)/main.o,$(OBJS))

# ANSI Color Codes
COLOR_RESET   := \033[0m
COLOR_GREEN   := \033[32m
COLOR_YELLOW  := \033[33m
COLOR_BLUE    := \033[34m
COLOR_CYAN    := \033[36m

.PHONY: all bonus clean fclean re test debug python-test help

all: $(NAME)

$(NAME): $(OBJS)
	@printf "$(COLOR_BLUE)[BUILD] Linking $(NAME)...$(COLOR_RESET)\n"
	@$(CC) $(CFLAGS) $(LDFLAGS) $(OBJS) $(LDLIBS) -o $(NAME)
	@printf "$(COLOR_GREEN)[SUCCESS] $(NAME) compiled successfully!$(COLOR_RESET)\n"

bonus: $(NAME)
	@printf "$(COLOR_GREEN)[SUCCESS] Bonus features included in $(NAME)!$(COLOR_RESET)\n"

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.c | $(OBJ_DIR)
	@printf "$(COLOR_CYAN)[CC] $< -> $@$(COLOR_RESET)\n"
	@$(CC) $(CPPFLAGS) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR):
	@mkdir -p $(OBJ_DIR)

debug:
	@$(MAKE) BUILD_DIR=build/debug OBJ_DIR=build/debug/obj NAME=build/debug/ft_malcolm \
		CFLAGS="$(CFLAGS) $(DEBUG_FLAGS)" all
	@printf "$(COLOR_YELLOW)[DEBUG] Built build/debug/ft_malcolm with sanitizers.$(COLOR_RESET)\n"

test: $(NAME)
	@printf "$(COLOR_BLUE)[BUILD] Compiling unit test suite...$(COLOR_RESET)\n"
	@$(CC) $(CPPFLAGS) $(CFLAGS) $(LDFLAGS) $(TEST_DIR)/test_parser.c $(TEST_OBJS) $(LDLIBS) -o $(TEST_NAME)
	@printf "$(COLOR_GREEN)[RUN] Running unit tests...$(COLOR_RESET)\n"
	@$(TEST_NAME)
	@printf "$(COLOR_GREEN)[SUCCESS] All unit tests passed!$(COLOR_RESET)\n"
	@FT_MALCOLM_BIN=$(NAME) bash $(TEST_DIR)/test_runner.sh
	@$(MAKE) python-test

python-test:
	@$(PYTHON) -m unittest discover -s tests -p 'test_*.py' -v

PYTHON ?= .venv/bin/python

clean:
	@printf "$(COLOR_YELLOW)[CLEAN] Removing object files...$(COLOR_RESET)\n"
	@rm -rf $(OBJ_DIR)

fclean: clean
	@printf "$(COLOR_YELLOW)[FCLEAN] Removing binaries...$(COLOR_RESET)\n"
	@rm -f $(NAME) $(TEST_NAME)

re: fclean all

help:
	@printf "$(COLOR_CYAN)ft_malcolm Build Targets:$(COLOR_RESET)\n"
	@printf "  all      : Build standard ft_malcolm binary\n"
	@printf "  bonus    : Build binary with all bonus features enabled\n"
	@printf "  clean    : Remove object directory\n"
	@printf "  fclean   : Remove object directory and binary\n"
	@printf "  re       : Full re-compilation\n"
	@printf "  test     : Build and execute automated unit & integration test suites\n"
	@printf "  debug    : Compile with ASan & debug symbols\n"
	@printf "  python-test: Run Python unit tests (PYTHON=... to select interpreter)\n"

-include $(DEPS)
