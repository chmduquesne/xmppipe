
CFLAGS=-I/usr/include/strophe
LDFLAGS=-lstrophe -lssl -lcrypto -lxml2 -lresolv

all:
	gcc ./xmppipe.c -o xmppipe $(CFLAGS) $(LDFLAGS)
