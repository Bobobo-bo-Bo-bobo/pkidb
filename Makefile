GOPATH	= $(CURDIR)
BINDIR	= $(CURDIR)/bin
DOCDIR	= $(CURDIR)/doc
ETCDIR	= $(CURDIR)/examples
DBDIR	= $(CURDIR)/sql

PROGRAMS = pkidb

depend:
	env GOPATH=$(GOPATH) go get -u gopkg.in/ini.v1
	env GOPATH=$(GOPATH) go get -u github.com/nu7hatch/gouuid
	env GOPATH=$(GOPATH) go get -u github.com/youmark/pkcs8
	env GOPATH=$(GOPATH) go get -u golang.org/x/crypto/pbkdf2
	env GOPATH=$(GOPATH) go get -u golang.org/x/crypto/scrypt
	env GOPATH=$(GOPATH) go get -u golang.org/x/crypto/ocsp
	env GOPATH=$(GOPATH) go get -u github.com/lib/pq
	env GOPATH=$(GOPATH) go get -u github.com/go-sql-driver/mysql
	env GOPATH=$(GOPATH) go get -u github.com/mattn/go-sqlite3
	env GOPATH=$(GOPATH) go get -u github.com/gorilla/mux

build:
	env GOPATH=$(GOPATH) go install $(PROGRAMS)

destdirs:
	mkdir -p -m 0755 $(DESTDIR)/usr/bin
	mkdir -p -m 0755 $(DESTDIR)/usr/share/man/man1
	mkdir -p -m 0755 $(DESTDIR)/etc/pkidb
	mkdir -p -m 0755 $(DESTDIR)/usr/share/pkidb/initialisation

strip: build
	strip --strip-all $(BINDIR)/pkidb

install: strip destdirs install-bin install-man install-etc install-sql

install-bin:
	install -m 0755 $(BINDIR)/pkidb $(DESTDIR)/usr/bin

install-man:
	install -m 0644 $(DOCDIR)/man/man1/pkidb.1 $(DESTDIR)/usr/share/man/man1

install-etc:
	install -m 0644 $(ETCDIR)/config.ini.example $(DESTDIR)/etc/pkidb
	install -m 0644 $(ETCDIR)/template.example $(DESTDIR)/etc/pkidb

install-sql:
	install -m 0644 $(DBDIR)/mysql/mysql.sql $(DESTDIR)/usr/share/pkidb/initialisation
	install -m 0644 $(DBDIR)/pgsql/pgsql.sql $(DESTDIR)/usr/share/pkidb/initialisation
	install -m 0644 $(DBDIR)/sqlite/sqlite.sql $(DESTDIR)/usr/share/pkidb/initialisation

clean:
	/bin/rm -f bin/pkidb

distclean: clean
	rm -rf src/github.com/
	rm -rf src/gopkg.in/
	rm -rf src/golang.org/

uninstall:
	/bin/rm -f $(DESTDIR)/usr/bin

all: depend build strip install

