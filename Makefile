
CFLAGS=-I/usr/include/strophe
LDFLAGS=-lstrophe -lssl -lxml2 -lresolv

all:
	gcc ./xmppipe.c -o xmppipe $(CFLAGS) $(LDFLAGS)
