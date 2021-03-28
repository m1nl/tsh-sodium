CC       = musl-gcc
RM       = rm -f
STRIP    = strip
CFLAGS   = -Wall -O3 -fstack-protector-strong -static -Idist/include -Ldist/lib
CPPFLAGS = -Wdate-time -D_FORTIFY_SOURCE=2
LDFLAGS  = -Wl,-z,relro -Wl,--as-needed -Wl,-Bstatic -lutil -lsodium -lpthread

TOOLCHAIN = /var/toolchain/sys30

COMM = pel.o hexutils.o
TSH  = tsh
TSHD = tshd

VERSION = tsh-sodium-0.1
CLIENT_OBJ = pel.c tsh.c hexutils.c
SERVER_OBJ = pel.c tshd.c hexutils.c setproctitle.c

DISTFILES= \
    README \
    ChangeLog\
    pel.h \
    hexutils.h \
    setproctitle.h \
    Makefile \
    $(CLIENT_OBJ) $(SERVER_OBJ)

all:
	@echo
	@echo "Please specify one of these targets:"
	@echo
	@echo "	make linux"
	@echo "	make linux_x64"
	@echo "	make freebsd"
	@echo "	make openbsd"
	@echo "	make netbsd"
	@echo "	make iphone"
	@echo "	make darwin"
	@echo
	make `uname | tr A-Z a-z`

osx: darwin

darwin:
	$(MAKE)	\
		CC="clang"	\
		CFLAGS="$(CFLAGS)"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS)"	\
		DEFS="$(DEFS) -DOPENBSD"	\
		$(TSH) $(TSHD)

iphone:
	$(MAKE)	\
		CFLAGS="$(CFLAGS) -I$(TOOLCHAIN)/usr/include"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS) -L$(TOOLCHAIN)/usr/lib"	\
		DEFS="$(DEFS) -DOPENBSD"	\
		$(TSH) $(TSHD)
	ldid -S $(TSH)
	ldid -S $(TSHD)

linux:
	$(MAKE)	\
		CFLAGS="$(CFLAGS)"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS)"	\
		DEFS="$(DEFS) -DLINUX"	\
		$(TSH) $(TSHD)

linux_x64:
	$(MAKE)	\
		CFLAGS="$(CFLAGS)"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS)"	\
		DEFS="$(DEFS) -DLINUX"	\
		$(TSH) $(TSHD)

openbsd:
	$(MAKE)	\
		CFLAGS="$(CFLAGS)"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS)"	\
		DEFS="$(DEFS) -DOPENBSD"	\
		$(TSH) $(TSHD)

freebsd:
	$(MAKE)	\
		CFLAGS="$(CFLAGS)"	\
		CPPFLAGS="$(CPPFLAGS)"	\
		LDFLAGS="$(LDFLAGS)"	\
		DEFS="$(DEFS) -DFREEBSD"	\
		$(TSH) $(TSHD)

netbsd: openbsd

$(TSH): $(COMM) tsh.o
	$(CC) ${CFLAGS} ${CPPFLAGS} -o $(TSH) $(COMM) tsh.o ${LDFLAGS}
	$(STRIP) $(TSH)

$(TSHD): $(COMM) tshd.o setproctitle.o
	$(CC) ${CFLAGS} ${CPPFLAGS} -o $(TSHD) $(COMM) tshd.o setproctitle.o ${LDFLAGS}
	$(STRIP) $(TSHD)

pel.o: pel.h
tsh.o: pel.h tsh.h
tshd.o: pel.h tsh.h

.c.o:
	$(CC) ${CFLAGS} ${CPPFLAGS} ${DEFS} -c $*.c

clean:
	$(RM) $(TSH) $(TSHD) *.o core

dist:
	mkdir $(VERSION)
	cp $(DISTFILES) $(VERSION)
	tar -czf $(VERSION).tar.gz $(VERSION)
	rm -r $(VERSION)

