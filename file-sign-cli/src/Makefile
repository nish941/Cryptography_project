CC = gcc
CFLAGS = -Wall -Wextra -I.
SRCS = sha256.c lamport.c utils.c cli.c
OBJS = $(SRCS:.c=.o)
BIN_DIR = bin
TARGET = $(BIN_DIR)/file-sign

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(OBJS)
	mkdir -p $(BIN_DIR)
	$(CC) $(CFLAGS) $^ -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS)
	rm -rf $(BIN_DIR)
