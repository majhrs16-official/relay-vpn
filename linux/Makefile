CC ?= gcc
CFLAGS ?= -Wall -Wextra -O2 -std=gnu11 -pthread
LIBS ?= -lcrypto -pthread

TARGET = bin/vpn
TARGET_X86 = bin/vpn-x86

X86_CC ?= $(CC)
X86_CFLAGS ?= -Wall -Wextra -O2 -std=gnu11 -pthread -m32
X86_LIBS ?= -lcrypto -pthread

SRCS = src/main.c src/crypto.c
HDRS = src/crypto.h

all: $(TARGET)

x86: $(TARGET_X86)

$(TARGET): $(SRCS) $(HDRS)
	mkdir -p $(dir $(TARGET))
	$(CC) $(CFLAGS) $(SRCS) -o $(TARGET) $(LIBS)

$(TARGET_X86): $(SRCS) $(HDRS)
	mkdir -p $(dir $(TARGET_X86))
	$(X86_CC) $(X86_CFLAGS) $(SRCS) -o $(TARGET_X86) $(X86_LIBS)

deps:
	./install

deps-x86:
	./install x86

clean:
	rm -f $(TARGET) $(TARGET_X86)

.PHONY: all x86 clean deps deps-x86
