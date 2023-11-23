CC = clang
CFLAGS = -Wall -Wextra
LDLIBS = -lpcap

SRC_DIR=src
TEST_DIR=test

CFLAGS += -I$(SRC_DIR)

OUT=sniff

SRC = $(wildcard $(SRC_DIR)/*.c)
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

.PHONY: clean format test all

all: $(OUT) test_runner

test: test_runner
	@./$<

clean:
	rm -f $(OUT) $(OBJ) $(TEST_OBJ) test_runner

format:
	find $(SRC_DIR) $(TEST_DIR) -iname *.h -o -iname *.c | xargs clang-format --verbose -i
