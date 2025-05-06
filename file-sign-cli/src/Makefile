CC        := gcc
PKG_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
PKG_LDFLAGS:= $(shell pkg-config --libs   gtk+-3.0)
CFLAGS    := -Wall -Wextra -I. $(PKG_CFLAGS)
LDFLAGS   := $(PKG_LDFLAGS)
BIN_DIR   := bin

# Sources
COMMON_SRCS := sha256.c lamport.c utils.c
CLI_SRCS    := cli.c
GUI_SRCS    := file_sign_gui.c

# Objects
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
CLI_OBJS    := $(CLI_SRCS:.c=.o)
GUI_OBJS    := $(GUI_SRCS:.c=.o)

# Targets
CLI_TARGET  := $(BIN_DIR)/file-sign
GUI_TARGET  := $(BIN_DIR)/file-sign-gui

.PHONY: all clean

all: $(CLI_TARGET) $(GUI_TARGET)

# Build the CLI executable
$(CLI_TARGET): $(COMMON_OBJS) $(CLI_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

# Build the GUI executable
$(GUI_TARGET): $(COMMON_OBJS) $(GUI_OBJS)
	@mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

# Generic rule for .o files
%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(COMMON_OBJS) $(CLI_OBJS) $(GUI_OBJS)
	rm -rf $(BIN_DIR)
