
all: mactelnet mactelnetd mndp

clean: dist-clean

dist-clean:
	rm -f mactelnet mactelnetd mndp

install: all
	cp mndp $(DESTDIR)/usr/bin/
	cp mactelnet $(DESTDIR)/usr/bin/
	cp mactelnetd $(DESTDIR)/usr/sbin/
	cp mactelnetd.users $(DESTDIR)/etc/
	chown $(DESTDIR)/etc/mactelnetd.users
	chmod 600 $(DESTDIR)/etc/mactelnetd.users

mactelnet: config.h udp.h udp.c mactelnet.c protocol.c protocol.h console.c console.h devices.c devices.h
	gcc -g -DUSERSFILE='"/etc/mactelnetd.users"' -o mactelnet -lcrypto mactelnet.c udp.c protocol.c console.c devices.c

mactelnetd: config.h mactelnetd.c udp.h udp.c protocol.c protocol.h console.c console.h users.c users.h
	gcc -g -DUSERSFILE='"/etc/mactelnetd.users"' -o mactelnetd -lcrypto mactelnetd.c udp.c protocol.c console.c users.c

mndp: config.h mndp.c protocol.h
	gcc -g -o mndp mndp.c protocol.c
