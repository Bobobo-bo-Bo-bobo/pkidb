GOPATH	= $(CURDIR)
BINDIR	= $(CURDIR)/bin

PROGRAMS = pkidb

depend:
	env GOPATH=$(GOPATH) go get -u github.com/sirupsen/logrus
	env GOPATH=$(GOPATH) go get -u gopkg.in/ini.v1
	env GOPATH=$(GOPATH) go get -u github.com/nu7hatch/gouuid

build:
	env GOPATH=$(GOPATH) go install $(PROGRAMS)

destdirs:
	mkdir -p -m 0755 $(DESTDIR)/usr/bin

strip: build
	strip --strip-all $(BINDIR)/pkidb

install: strip destdirs install-bin

install-bin:
	install -m 0755 $(BINDIR)/pkidb $(DESTDIR)/usr/bin

clean:
	/bin/rm -f bin/pkidb

distclean: clean
	rm -rf src/github.com/
	rm -rf src/gopkg.in/

uninstall:
	/bin/rm -f $(DESTDIR)/usr/bin

all: depend build strip install

