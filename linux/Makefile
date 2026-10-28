CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -std=gnu11 -pthread
LIBS ?= -lcrypto -pthread
TARGET = bin/vpn
SRCS = src/main.c src/crypto.c
HDRS = src/crypto.h

all: $(TARGET)

$(TARGET): $(SRCS) $(HDRS)
	mkdir -p $(dir $(TARGET))
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

deps:
	./install

clean:
	rm -f $(TARGET)

.PHONY: all clean deps
