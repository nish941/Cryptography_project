CC = gcc
CFLAGS = -Wall -Wextra -I. $(shell pkg-config --cflags gtk+-3.0)
LDLIBS = $(shell pkg-config --libs gtk+-3.0)
SRCS = sha256.c lamport.c utils.c cli.c file_sign_gui.c
OBJS = $(SRCS:.c=.o)
BIN_DIR = bin
TARGET = $(BIN_DIR)/file-sign

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
	rm -rf $(BIN_DIR)
