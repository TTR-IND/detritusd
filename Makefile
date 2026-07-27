CC       ?= gcc
CFLAGS   ?= -O2 -Wall -Wextra -Wno-unused-parameter
LDLIBS   := -lm -lpthread
PREFIX   ?= /usr/local
SBINDIR  := $(PREFIX)/sbin

.PHONY: all clean install uninstall

all: detritusd

detritusd: detritus.c
	$(CC) $(CFLAGS) -o $@ $< $(LDLIBS)

clean:
	rm -f detritusd

install: detritusd
	install -m 0755 -o root -g root detritusd $(SBINDIR)/detritusd
	@echo "Binary installed to $(SBINDIR)/detritusd."
	@echo "For OpenRC service setup, use ./install.sh instead, or see the README."

uninstall:
	rm -f $(SBINDIR)/detritusd
