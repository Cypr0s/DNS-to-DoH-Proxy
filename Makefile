#taken from my project https://github.com/Cypr0s/CyprSH/blob/main/Makefile and modified with AI as per spec

CC = gcc
CFLAGS = -Wall -Wextra -std=c17 -pedantic -O2 -Isrc -D_POSIX_C_SOURCE=200809L 
LDFLAGS = 

SRC := $(shell find src -name '*.c')
OBJ = $(SRC:.c=.o)
TARGET = isa-dnsproxy
ZIP_NAME = xluptak00
TEST_SCRIPT = placeholder
DEVSHELL = c

.PHONY: all test clean NixDevShellName zip debug

# default build
all: clean $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(OBJ) $(LDFLAGS) -o $(TARGET)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test: all
	chmod +x $(TEST_SCRIPT)
	./$(TEST_SCRIPT)

# zip
zip:
	zip -r $(ZIP_NAME).zip Makefile LICENSE CHANGELOG.md README.md src -x *.o $(TARGET)

# debug
debug: CFLAGS += -DDEBUG -fsanitize=address,undefined -O0 -g -Werror 
debug: LDFLAGS += -fsanitize=address,undefined
debug: rebuild

# clean
clean:
	find src -name '*.o' -delete
	rm -f $(TARGET)

#devshel
NixDevShellName:
	@echo $(DEVSHELL)


# rebuild
rebuild: fclean all