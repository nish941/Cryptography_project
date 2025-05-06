CC = gcc
CFLAGS = -Wall -Wextra -I. $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS = $(shell pkg-config --libs gtk+-3.0)

SRCS_COMMON = sha256.c lamport.c utils.c
OBJS_COMMON = $(SRCS_COMMON:.c=.o)

SRCS_CLI = $(SRCS_COMMON) cli.c
OBJS_CLI = $(SRCS_CLI:.c=.o)

SRCS_GUI = $(SRCS_COMMON) file_sign_gui.c
OBJS_GUI = $(SRCS_GUI:.c=.o)

BIN_DIR = bin
TARGET_CLI = $(BIN_DIR)/file-sign
TARGET_GUI = $(BIN_DIR)/file-sign-gui

.PHONY: all clean

all: $(TARGET_CLI) $(TARGET_GUI)

$(TARGET_CLI): $(OBJS_CLI)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(TARGET_GUI): $(OBJS_GUI)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f *.o
	rm -rf $(BIN_DIR)
