CC = gcc
CFLAGS = -Wall -Wextra -I.
SRCS = sha256.c lamport.c utils.c cli.c
OBJS = $(SRCS:.c=.o)
BIN_DIR = bin
TARGET = $(BIN_DIR)/file-sign
GTK_CFLAGS  := $(shell pkg-config --cflags gtk+-3.0)
GTK_LIBS    := $(shell pkg-config --libs   gtk+-3.0)
CFLAGS      += $(GTK_CFLAGS)
LDLIBS      += $(GTK_LIBS)

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
