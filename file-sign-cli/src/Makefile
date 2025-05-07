CC = gcc
CFLAGS = -Wall -Wextra -I. -pthread $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS_CLI = 
LDFLAGS_GUI = $(shell pkg-config --libs gtk+-3.0)

# CLI sources (no GUI code)
SRCS_CLI = sha256.c lamport.c utils.c cli.c
OBJS_CLI = $(SRCS_CLI:.c=.o)

# GUI sources (no CLI code)
SRCS_GUI = sha256.c lamport.c utils.c file_sign_gui.c
OBJS_GUI = $(SRCS_GUI:.c=.o)

BIN_DIR = bin

.PHONY: all clean

all: $(BIN_DIR)/file-sign $(BIN_DIR)/file-sign-gui

# Build CLI
$(BIN_DIR)/file-sign: $(OBJS_CLI)
	mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_CLI)

# Build GUI
$(BIN_DIR)/file-sign-gui: $(OBJS_GUI)
	mkdir -p $(BIN_DIR)
	$(CC) $^ -o $@ $(LDFLAGS_GUI)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_CLI) $(OBJS_GUI)
	rm -rf $(BIN_DIR)
