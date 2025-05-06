CC        := gcc
PKG_CFLAGS := $(shell pkg-config --cflags gtk+-3.0)
PKG_LDFLAGS:= $(shell pkg-config --libs   gtk+-3.0)
CFLAGS    := -Wall -Wextra -I. $(PKG_CFLAGS)
LDFLAGS   := $(PKG_LDFLAGS)
BIN_DIR   := bin
# Sources
COMMON_SRCS := sha256.c lamport.c utils.c
COMMON_OBJS := $(COMMON_SRCS:.c=.o)
# Objects
CLI_SRCS    := cli.c
CLI_OBJS    := $(CLI_SRCS:.c=.o)
CLI_TARGET  := $(BIN_DIR)/file-sign

GUI_SRCS    := file_sign_gui.c
GUI_OBJS    := $(GUI_SRCS:.c=.o)
GUI_TARGET  := $(BIN_DIR)/file-sign-gui

.PHONY: all clean

all: $(CLI_TARGET) $(GUI_TARGET)

$(CLI_TARGET): $(COMMON_OBJS) $(CLI_OBJS)
@mkdir -p $(BIN_DIR)
$(CC) $(CFLAGS) $^ -o $@



$(GUI_TARGET): $(COMMON_OBJS) $(GUI_OBJS)
@mkdir -p $(BIN_DIR)
$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)



%.o: %.c
$(CC) $(CFLAGS) -c $< -o $@

clean:
rm -f $(COMMON_OBJS) $(CLI_OBJS) $(GUI_OBJS)
rm -rf $(BIN_DIR)


