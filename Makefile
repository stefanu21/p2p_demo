VERSION = 0.0
CC = gcc
CFLAGS = -Wall -g3 -I./common/ -I./wpa_code_gen/ -DVERSION=\"$(VERSION)\" $(shell pkg-config --cflags glib-2.0 gio-2.0 gio-unix-2.0)
LDFLAGS = $(shell pkg-config --libs glib-2.0 gio-2.0 gio-unix-2.0)
BIN = p2pd
OBJ = p2pd.o ap_mode.o interface.o common.o group.o wpa.o
OBJ += wpa_code_gen/wpa.o wpa_code_gen/wpa_interface.o wpa_code_gen/wpa_group.o wpa_code_gen/wpa_peer.o wpa_code_gen/wpa_pers_group.o

SRCS += $(wildcard wpa_code_gen/*.c) 
HDRS += $(wildcard wpa_code_gen/*.h))


$(BIN): $(OBJ)
	$(CC) $(CFLAGS) -o $(BIN) $(OBJ) $(LDFLAGS)

$(OBJDRI)/%.o:	%.c
	$(CC) $(CFLAGS) -c $<


.PHONY: all clean

all:
	make $(BIN)
	
clean:
	rm -rf $(BIN) $(OBJ)


