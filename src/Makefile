CC = gcc
CFLAGS = -Wall -g -O2 $(shell pkg-config --cflags libgcrypt)
LDFLAGS = $(shell pkg-config --libs libgcrypt)
SOURCES = knox.c wallet.c
OBJECTS = $(SOURCES:.c=.o)
EXECUTABLE = knox

all: $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS)
		$(CC) $(OBJECTS) -o $@ $(LDFLAGS)

%.o: %.c
		$(CC) $(CFLAGS) -c $< -o $@

clean:
		rm -f $(OBJECTS) $(EXECUTABLE)

.PHONY: all clean
