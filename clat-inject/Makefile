CC      = gcc
CFLAGS  = -static -Os -Wall -Wextra

BINS = clat-init np_proxy

all: $(BINS)

clat-init: clat-init.c
	$(CC) $(CFLAGS) -o $@ $< && strip $@

np_proxy: np_proxy.c
	$(CC) $(CFLAGS) -o $@ $< && strip $@

clean:
	rm -f $(BINS)
