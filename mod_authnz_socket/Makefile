# Location of apxs command:
#APXS=apxs2
APXS=apxs

TAR= README INSTALL INSTALL.HARDCODE CHANGES AUTHENTICATORS UPGRADE TODO \
	mod_authnz_socket.c test/* Makefile

.DEFAULT_GOAL:= build
.PHONY: install build clean

install: mod_authnz_socket.la
	$(APXS) -i -a mod_authnz_socket.la

build: mod_authnz_socket.la

mod_authnz_socket.la: mod_authnz_socket.c
	$(APXS) "-Wc,-Wall -Wextra" -c mod_authnz_socket.c

clean:
	rm -rf mod_authnz_socket.so mod_authnz_socket.o \
	    mod_authnz_socket.la mod_authnz_socket.slo \
	    mod_authnz_socket.lo .libs
	-ls -a .*.swp

mae.tar: $(TAR)
	tar cvf mae.tar $(TAR)
