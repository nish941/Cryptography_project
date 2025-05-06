CC = gcc
CFLAGS = -Wall -Wextra -I. $(shell pkg-config --cflags gtk+-3.0)
LDLIBS = $(shell pkg-config --libs gtk+-3.0)

SRCS_COMMON = sha256.c lamport.c utils.c
OBJS_COMMON = $(SRCS_COMMON:.c=.o)

CLI_SRC = cli.c
CLI_OBJ = $(CLI_SRC:.c=.o)
CLI_TARGET = bin/file-sign-cli

GUI_SRC = file_sign_gui.c
GUI_OBJ = $(GUI_SRC:.c=.o)
GUI_TARGET = bin/file-sign-gui

.PHONY: all clean

all: $(CLI_TARGET) $(GUI_TARGET)

$(CLI_TARGET): $(OBJS_COMMON) $(CLI_OBJ)
	mkdir -p bin
	$(CC) $(CFLAGS) $^ -o $@

$(GUI_TARGET): $(OBJS_COMMON) $(GUI_OBJ)
	mkdir -p bin
	$(CC) $(CFLAGS) $^ -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS_COMMON) $(CLI_OBJ) $(GUI_OBJ)
	rm -rf bin
