CC = gcc
CFLAGS = -Wall -Wextra -O2

all: user

user: main.c
	$(CC) $(CFLAGS) main.c -o user

clean:
	rm -f user