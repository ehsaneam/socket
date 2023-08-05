CC 		 	= gcc
CFLAGS 	 	= -Wall -Werror -Wextra
SRC_DIR  	= sources
CLIENT_DIR 	= $(SRC_DIR)/client
# SERVER_DIR 	= $(SRC_DIR)/server
COMMON_DIR 	= $(SRC_DIR)/common
ROHC_DIR 	= $(SRC_DIR)/rohc
COMP_DIR	= $(SRC_DIR)/rohc_comp
# DECOMP_DIR	= $(SRC_DIR)/rohc_decomp
OBJ_DIR  	= build
INC		 	= -I$(ROHC_DIR) -I$(COMP_DIR) -I$(COMMON_DIR) -I$(CLIENT_DIR) 
#-I$(DECOMP_DIR) -I$(SERVER_DIR)

# Files
CLIENT_EX  = $(OBJ_DIR)/client
SRC_CLIENT = $(wildcard $(CLIENT_DIR)/*.c) $(wildcard $(ROHC_DIR)/*.c) $(wildcard $(COMMON_DIR)/*.c) $(wildcard $(COMP_DIR)/*.c)
OBJ_CLIENT = $(patsubst $(CLIENT_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(CLIENT_DIR)/%.c,$(SRC_CLIENT))) $(patsubst $(ROHC_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(ROHC_DIR)/%.c,$(SRC_CLIENT))) \
	   $(patsubst $(COMMON_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(COMMON_DIR)/%.c,$(SRC_CLIENT))) $(patsubst $(COMP_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(COMP_DIR)/%.c,$(SRC_CLIENT)))
DEP_CLIENT = $(OBJ_CLIENT:.o=.d)

# SERVER_EX  = $(OBJ_DIR)/server
# SRC_SERVER = $(wildcard $(SERVER_DIR)/*.c) $(wildcard $(ROHC_DIR)/*.c) $(wildcard $(COMMON_DIR)/*.c) $(wildcard $(DECOMP_DIR)/*.c)
# OBJ_SERVER = $(patsubst $(SERVER_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(SERVER_DIR)/%.c,$(SRC_SERVER))) $(patsubst $(ROHC_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(ROHC_DIR)/%.c,$(SRC_SERVER))) \
# 	   $(patsubst $(COMMON_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(COMMON_DIR)/%.c,$(SRC_SERVER))) $(patsubst $(DECOMP_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(DECOMP_DIR)/%.c,$(SRC_SERVER)))
# DEP_SERVER = $(OBJ_SERVER:.o=.d)

# Build rule
$(CLIENT_EX): $(OBJ_CLIENT)
	$(CC) $(CFLAGS) $^ -o $@

# $(SERVER_EX): $(OBJ_SERVER)
# 	$(CC) $(CFLAGS) $^ -o $@

$(OBJ_DIR)/%.o: $(ROHC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(COMP_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

# $(OBJ_DIR)/%.o: $(DECOMP_DIR)/%.c
# 	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(CLIENT_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

# $(OBJ_DIR)/%.o: $(SERVER_DIR)/%.c
# 	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

# Include dependency files
-include $(DEP_CLIENT)

# Phony targets
.PHONY: all clean

# Default target
all: $(CLIENT_EX) $(SERVER_EX)

# Clean rule
clean:
	rm -f $(OBJ_CLIENT) $(DEP_CLIENT) $(CLIENT_EX)
# $(OBJ_SERVER) $(DEP_SERVER) $(SERVER_EX)