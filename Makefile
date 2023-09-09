CC 		 	= gcc
CFLAGS 	 	= -Wall -Werror -Wextra
SRC_DIR  	= sources
DIR_OBJSER 	= build_server
DIR_OBJCLI	= build_client
COMMON_DIR 	= $(SRC_DIR)/common
ROHC_DIR 	= $(SRC_DIR)/rohc
CLIENT_DIR 	= $(SRC_DIR)/client
COMP_DIR	= $(SRC_DIR)/rohc_comp
SERVER_DIR 	= $(SRC_DIR)/server
DECOMP_DIR	= $(SRC_DIR)/rohc_decomp
INC_CLIENT 	= -I$(ROHC_DIR) -I$(COMMON_DIR) -I$(COMP_DIR)
INC_SERVER 	= -I$(ROHC_DIR) -I$(COMMON_DIR) -I$(DECOMP_DIR)

# Files
SERVER_EX  = $(DIR_OBJSER)/server
SRC_SERVER = $(wildcard $(SERVER_DIR)/*.c) $(wildcard $(ROHC_DIR)/*.c) $(wildcard $(COMMON_DIR)/*.c) $(wildcard $(DECOMP_DIR)/*.c)
OBJ_SERVER = $(patsubst $(SERVER_DIR)/%.c,$(DIR_OBJSER)/%.o,$(filter $(SERVER_DIR)/%.c,$(SRC_SERVER))) $(patsubst $(ROHC_DIR)/%.c,$(DIR_OBJSER)/%.o,$(filter $(ROHC_DIR)/%.c,$(SRC_SERVER))) \
	   $(patsubst $(COMMON_DIR)/%.c,$(DIR_OBJSER)/%.o,$(filter $(COMMON_DIR)/%.c,$(SRC_SERVER))) $(patsubst $(DECOMP_DIR)/%.c,$(DIR_OBJSER)/%.o,$(filter $(DECOMP_DIR)/%.c,$(SRC_SERVER)))
DEP_SERVER = $(OBJ_SERVER:.o=.d)

CLIENT_EX  = $(DIR_OBJCLI)/client
SRC_CLIENT = $(wildcard $(CLIENT_DIR)/*.c) $(wildcard $(ROHC_DIR)/*.c) $(wildcard $(COMMON_DIR)/*.c) $(wildcard $(COMP_DIR)/*.c)
OBJ_CLIENT = $(patsubst $(CLIENT_DIR)/%.c,$(DIR_OBJCLI)/%.o,$(filter $(CLIENT_DIR)/%.c,$(SRC_CLIENT))) $(patsubst $(ROHC_DIR)/%.c,$(DIR_OBJCLI)/%.o,$(filter $(ROHC_DIR)/%.c,$(SRC_CLIENT))) \
	   $(patsubst $(COMMON_DIR)/%.c,$(DIR_OBJCLI)/%.o,$(filter $(COMMON_DIR)/%.c,$(SRC_CLIENT))) $(patsubst $(COMP_DIR)/%.c,$(DIR_OBJCLI)/%.o,$(filter $(COMP_DIR)/%.c,$(SRC_CLIENT)))
DEP_CLIENT = $(OBJ_CLIENT:.o=.d)

# Default target
all: $(SERVER_EX) $(CLIENT_EX)

# Build rule
$(CLIENT_EX): $(OBJ_CLIENT)
	mkdir -p $(DIR_OBJCLI)
	$(CC) $(CFLAGS) $^ -o $@ -lm

$(DIR_OBJCLI)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(INC_CLIENT) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJCLI)/%.o: $(ROHC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJCLI)/%.o: $(COMP_DIR)/%.c
	$(CC) $(INC_CLIENT) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJCLI)/%.o: $(CLIENT_DIR)/%.c
	$(CC) $(INC_CLIENT) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(SERVER_EX): $(OBJ_SERVER)
	mkdir -p $(DIR_OBJSER)
	$(CC) $(CFLAGS) $^ -o $@ -lm

$(DIR_OBJSER)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(INC_CLIENT) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJSER)/%.o: $(ROHC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJSER)/%.o: $(DECOMP_DIR)/%.c
	$(CC) $(INC_SERVER) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

$(DIR_OBJSER)/%.o: $(SERVER_DIR)/%.c
	$(CC) $(INC_SERVER) $(CFLAGS) -MMD -MP -c $< -o $@ -lm

# Include dependency files
-include $(DEP_SERVER) $(DEP_CLIENT)

# Phony targets
.PHONY: all clean

# Clean rule
clean:
	rm -f $(OBJ_SERVER) $(DEP_SERVER) $(SERVER_EX) $(OBJ_CLIENT) $(DEP_CLIENT) $(CLIENT_EX)
