VERSION = 0.0
CC = gcc
CFLAGS = -Wall -g3 -I./common/ -I./wpa_code_gen/ -DVERSION=\"$(VERSION)\" $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0 gio-2.0 gio-unix-2.0)
BIN = wpa_daemon
VPATH = ./wpa_code_gen
OBJ = main.o supplicant.o wpa.o wpa_interface.o wpa_peer.o wpa_group.o

$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

%.o:%.c
	$(CC) $(CFLAGS) -c $<


.PHONY: all clean

all:
	make $(BIN)
	
clean:
	rm -rf $(BIN) $(OBJ)

