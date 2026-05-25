CC      = gcc
CFLAGS  = -static -Os -Wall -Wextra -o net-wait

net-wait: net-wait.c
	$(CC) $(CFLAGS) net-wait.c && strip net-wait

clean:
	rm -f net-wait
