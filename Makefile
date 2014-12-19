PREFIX=/usr

all: eapolproxy

eapolproxy: main.cxx
	g++ -O1 -o eapolproxy main.cxx -lpcap -lz -lpthread

install:
	install eapolproxy $(PREFIX)/sbin/eapolproxy
	cp rc.eapolproxy /etc/init.d/eapolproxy
	chmod +x /etc/init.d/eapolproxy
	chkconfig --add eapolproxy
	chkconfig --level 23 eapolproxy on

