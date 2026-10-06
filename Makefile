CC = gcc
CFLAGS = -Wall -Wextra -O2

all: user

user: main.c client.c client.h
	$(CC) $(CFLAGS) main.c client.c -o user

clean:
	rm -f user