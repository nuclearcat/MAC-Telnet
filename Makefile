
CC=gcc
CCFLAGS= 

all: macping mndp mactelnet mactelnetd macssh macsshd

clean: dist-clean

dist-clean:
	rm -f mactelnet macping mactelnetd macssh macsshd mndp
	rm -f *.o

strip-all: mndp macping mactelnet mactelnetd macssh macsshd
	strip -s mndp
	strip -s macping
	strip -s mactelnet
	strip -s mactelnetd
	strip -s macssh
	strip -s macsshd

install: all strip-all install-docs
	mkdir -p $(DESTDIR)/usr/bin
	cp mndp $(DESTDIR)/usr/bin/
	cp macping $(DESTDIR)/usr/bin/
	cp mactelnet $(DESTDIR)/usr/bin/
	mkdir -p $(DESTDIR)/usr/sbin
	cp mactelnetd $(DESTDIR)/usr/sbin/
	cp macssh $(DESTDIR)/usr/bin/
	cp macsshd $(DESTDIR)/usr/sbin/
	mkdir -p $(DESTDIR)/etc
	cp config/mactelnetd.users $(DESTDIR)/etc/
# Ubuntu upstart script
#	cp config/mactelnetd.init /etc/init/
	chown root $(DESTDIR)/etc/mactelnetd.users
	chmod 600 $(DESTDIR)/etc/mactelnetd.users

install-docs:
	mkdir -p $(DESTDIR)/usr/share/man/man1/
	cp docs/*.1 $(DESTDIR)/usr/share/man/man1/

udp.o: udp.c udp.h
	${CC} -Wall ${CCFLAGS} -c udp.c

users.o: users.c users.h
	${CC} -Wall ${CCFLAGS} -DUSERSFILE='"/etc/mactelnetd.users"' -c users.c

protocol.o: protocol.c protocol.h
	${CC} -Wall ${CCFLAGS} -c protocol.c

devices.o: devices.c devices.h
	${CC} -Wall ${CCFLAGS} -c devices.c
	
console.o: console.c console.h
	${CC} -Wall ${CCFLAGS} -c console.c

md5.o: md5.c md5.h
	${CC} -Wall ${CCFLAGS} -c md5.c

mactelnet: mactelnet.c config.h mactelnet.h udp.o protocol.o console.o devices.o md5.o
	${CC} -Wall ${CCFLAGS} -o mactelnet mactelnet.c udp.o protocol.o console.o devices.o md5.o

mactelnetd: mactelnetd.c  config.h udp.o protocol.o console.o users.o devices.o md5.o
	${CC} -Wall ${CCFLAGS} -o mactelnetd mactelnetd.c udp.o protocol.o console.o devices.o users.o md5.o

macssh: macssh.c mactelnet.h config.h udp.o protocol.o devices.o
	${CC} -Wall ${CCFLAGS} -o macssh macssh.c udp.o protocol.o devices.o

macsshd: macsshd.c config.h udp.o protocol.o devices.o
	${CC} -Wall ${CCFLAGS} -o macsshd macsshd.c udp.o protocol.o devices.o

mndp: mndp.c config.h protocol.o
	${CC} -Wall ${CCFLAGS} -o mndp mndp.c protocol.o

macping: macping.c config.h udp.o devices.o protocol.o
	${CC} -Wall ${CCFLAGS} -o macping macping.c devices.o udp.o protocol.o

