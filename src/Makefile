CC = gcc
CFLAGS = -Wall -g -O2 $(shell pkg-config --cflags libgcrypt libcurl)
LDFLAGS = $(shell pkg-config --libs libgcrypt libcurl jansson)
SOURCES = knox.c crypt.c wallet.c mnemonic.c utxo.c hash.c
OBJECTS = $(SOURCES:.c=.o)
TARGET = knox

#Test file
TEST_SOURCES = test_vectors.c crypt.c mnemonic.c wallet.c utxo.c hash.c
TEST_OBJECTS = $(TEST_SOURCES:.c=.o)
TEST_TARGET = test_vectors

all: $(TARGET)

$(TARGET): $(OBJECTS)
		$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

test: $(TEST_TARGET)
		sudo ./$(TEST_TARGET)

$(TEST_TARGET): $(TEST_SOURCES) $(TEST_OBJECTS)
		$(CC) $(CFLAGS) $(TEST_SOURCES) -o $(TEST_TARGET) $(LDFLAGS)

clean:
		rm -f $(OBJECTS) $(TARGET)

.PHONY: all test clean
