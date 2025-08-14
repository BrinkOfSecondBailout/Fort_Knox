CC = gcc
CFLAGS = -Wall -g -O2
LDFLAGS =
SOURCES = knox.c
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
