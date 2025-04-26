# Makefile for test programs

# Compiler and flags
CC = gcc
CFLAGS = -g -fno-omit-frame-pointer -fno-pie

# Find all .c files in the current directory
SOURCES = $(wildcard *.c)
EXECUTABLES = $(SOURCES:.c=)

# Default target
all: $(EXECUTABLES)

# Rule to build executables
%: %.c
	$(CC) $(CFLAGS) -o $@ $<

# Clean target
clean:
	rm -f $(EXECUTABLES)

# Phony targets
.PHONY: all clean
