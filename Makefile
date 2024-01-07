CC = clang
CFLAGS = -Wall -Wextra
LDLIBS = -lpcap

SRC_DIR=src
TEST_DIR=test
LIB_DIR=lib

CFLAGS += -I$(SRC_DIR) -I$(LIB_DIR)

OUT=sniff

SRC = $(shell find $(SRC_DIR) -iname *.c)
OBJ = $(SRC:.c=.o)

TEST_SRC = $(shell find $(TEST_DIR) $(SRC_DIR) -iname *.c -not -name $(OUT).c)
TEST_OBJ = $(TEST_SRC:.c=.o)

$(OUT): $(OBJ)
	$(CC) $(CFLAGS) $(OBJ) -o $@ $(LDLIBS)

%.o: %.c
	$(CC) $(CFLAGS) -c $< -o $@

test_runner: $(TEST_OBJ)
	$(CC) $(CFLAGS) $(TEST_OBJ) -o $@ $(LDLIBS)

compile_commands.json: clean
	bear -- make all

$(SRC_DIR)/utils/udp_port.h:
	$(SRC_DIR)/utils/gen_udp_port.fish > $@

$(SRC_DIR)/utils/tcp_port.h:
	$(SRC_DIR)/utils/gen_tcp_port.fish > $@

.PHONY: clean clean_all format test all help

all: $(OUT) test_runner

test: test_runner
	@./$<

clean:
	rm -f $(OUT) $(OBJ) $(TEST_OBJ) test_runner

clean_all: clean
	rm -f $(SRC_DIR)/utils/udp_port.h $(SRC_DIR)/utils/tcp_port.h

format:
	find $(SRC_DIR) $(TEST_DIR) -iname *.h -o -iname *.c | xargs clang-format --verbose -i

help:
	@echo "Makefile commands:"
	@echo "all - Compiles the main program and the test runner"
	@echo "test - Runs the test runner"
	@echo "clean - Removes the main program, object files, and the test runner"
	@echo "clean_all - Performs 'clean' and also removes generated header files"
	@echo "format - Formats all .h and .c files using clang-format"
