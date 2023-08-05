CC 		 	= gcc
CFLAGS 	 	= -Wall -Werror -Wextra
SRC_DIR  	= sources
CLIENT_DIR 	= $(SRC_DIR)/client
# SERVER_DIR 	= $(SRC_DIR)/server
COMMON_DIR 	= $(SRC_DIR)/common
ROHC_DIR 	= $(SRC_DIR)/rohc
COMP_DIR	= $(SRC_DIR)/rohc_comp
OBJ_DIR  	= build
INC		 	= -I$(ROHC_DIR) -I$(COMP_DIR) -I$(COMMON_DIR) -I$(CLIENT_DIR) 

# Files
CLIENT_EX = $(OBJ_DIR)/client
# SERVER_EX = $(OBJ_DIR)/server
SRCS = $(wildcard $(CLIENT_DIR)/*.c) $(wildcard $(ROHC_DIR)/*.c) $(wildcard $(COMMON_DIR)/*.c) $(wildcard $(COMP_DIR)/*.c)
OBJS = $(patsubst $(CLIENT_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(CLIENT_DIR)/%.c,$(SRCS))) $(patsubst $(ROHC_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(ROHC_DIR)/%.c,$(SRCS))) \
	   $(patsubst $(COMMON_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(COMMON_DIR)/%.c,$(SRCS))) $(patsubst $(COMP_DIR)/%.c,$(OBJ_DIR)/%.o,$(filter $(COMP_DIR)/%.c,$(SRCS)))
DEPS = $(OBJS:.o=.d)

# Build rule
$(EXEC): $(OBJS)
	$(CC) $(CFLAGS) $^ -o $@

# Object files rule
$(OBJ_DIR)/%.o: $(ROHC_DIR)/%.c
	$(CC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(COMP_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(COMMON_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

$(OBJ_DIR)/%.o: $(CLIENT_DIR)/%.c
	$(CC) $(INC) $(CFLAGS) -MMD -MP -c $< -o $@

# Include dependency files
-include $(DEPS)

# Phony targets
.PHONY: all clean

# Default target
all: $(EXEC)

# Clean rule
clean:
	rm -f $(OBJS) $(DEPS) $(EXEC)