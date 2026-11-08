BIN := sinty-keyd
PREFIX ?= /usr

.PHONY: all build static test vet install clean

all: build

build:
	go build -o $(BIN) ./cmd/sinty-keyd

static:
	CGO_ENABLED=0 go build -trimpath -ldflags "-s -w" -o $(BIN) ./cmd/sinty-keyd

test:
	go test ./...

vet:
	go vet ./...

install: static
	install -Dm755 $(BIN) $(DESTDIR)$(PREFIX)/libexec/$(BIN)
	install -Dm644 packaging/sinty-keyd.service $(DESTDIR)$(PREFIX)/lib/systemd/system/sinty-keyd.service
	install -Dm644 packaging/sinty-keyd.conf $(DESTDIR)$(PREFIX)/share/dbus-1/system.d/sinty-keyd.conf
	install -Dm644 packaging/dev.sinty.Key1.service $(DESTDIR)$(PREFIX)/share/dbus-1/system-services/dev.sinty.Key1.service

clean:
	rm -f $(BIN)
