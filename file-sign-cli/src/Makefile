CC = gcc
CFLAGS = -Wall -Wextra -I. $(shell pkg-config --cflags gtk+-3.0)
LDFLAGS = $(shell pkg-config --libs gtk+-3.0)
SRCS_COMMON = sha256.c lamport.c utils.c
OBJS_COMMON = $(SRCS_COMMON:.c=.o)
BIN_DIR = bin

CLI_SRC = cli.c
CLI_OBJ = $(CLI_SRC:.c=.o)
CLI_TARGET = $(BIN_DIR)/file-sign

GUI_SRC = file_sign_gui.c
GUI_OBJ = $(GUI_SRC:.c=.o)
GUI_TARGET = $(BIN_DIR)/file-sign-gui

.PHONY: all clean

all: $(CLI_TARGET) $(GUI_TARGET)

$(CLI_TARGET): $(OBJS_COMMON) $(CLI_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

$(GUI_TARGET): $(OBJS_COMMON) $(GUI_OBJ)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDFLAGS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_COMMON) $(CLI_OBJ) $(GUI_OBJ)
	rm -rf $(BIN_DIR)
