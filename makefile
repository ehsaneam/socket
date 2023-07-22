CC = gcc
CFLAGS = -Wall -Wextra
OBJ_DIR = build

all: client server

client: $(OBJ_DIR)/client.o $(OBJ_DIR)/header_comp.o $(OBJ_DIR)/common.o 
	$(CC) -o $(OBJ_DIR)/client $(CFLAGS) $(OBJ_DIR)/client.o $(OBJ_DIR)/header_comp.o $(OBJ_DIR)/common.o -lrohc

server: $(OBJ_DIR)/server.o $(OBJ_DIR)/header_comp.o $(OBJ_DIR)/common.o 
	$(CC) -o $(OBJ_DIR)/server $(CFLAGS) $(OBJ_DIR)/server.o $(OBJ_DIR)/header_comp.o $(OBJ_DIR)/common.o -lrohc

$(OBJ_DIR)/client.o: client.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c client.c -o $(OBJ_DIR)/client.o

$(OBJ_DIR)/server.o: server.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c server.c -o $(OBJ_DIR)/server.o

$(OBJ_DIR)/header_comp.o: header_comp.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c header_comp.c -o $(OBJ_DIR)/header_comp.o

$(OBJ_DIR)/common.o: common.c
	mkdir -p $(OBJ_DIR)
	$(CC) $(CFLAGS) -c common.c -o $(OBJ_DIR)/common.o

clean:
	rm -rf $(OBJ_DIR)