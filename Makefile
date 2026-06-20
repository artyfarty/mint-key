# mint-key — build & install the `mintk` binary.
#
#   make                 # build ./mintk
#   make install         # build + install to $(PREFIX)/bin  (sudo if not writable)
#   make PREFIX=~/.local install
#   make test vet fmt-check
#
# go.mod requires Go 1.25; GOTOOLCHAIN=auto lets an older `go` fetch it.

BIN         := mintk
PREFIX      ?= /usr/local
BINDIR      := $(DESTDIR)$(PREFIX)/bin
GO          ?= go
GOTOOLCHAIN ?= auto
export GOTOOLCHAIN

GOFILES := $(wildcard *.go)

.PHONY: all build install uninstall test vet fmt fmt-check check clean help

all: build

build: $(BIN)
	@echo "built: $(CURDIR)/$(BIN)  (install with 'make install')"

$(BIN): $(GOFILES) go.mod go.sum
	$(GO) build -o $(BIN) .

install: build
	install -d $(BINDIR)
	install -m 0755 $(BIN) $(BINDIR)/$(BIN)
	@echo "installed $(BINDIR)/$(BIN)"

uninstall:
	rm -f $(BINDIR)/$(BIN)
	@echo "removed $(BINDIR)/$(BIN)"

test:
	$(GO) test ./...

vet:
	$(GO) vet ./...

fmt:
	gofmt -w $(GOFILES)

# Fail if any file isn't gofmt-clean (for CI / pre-commit).
fmt-check:
	@out="$$(gofmt -l $(GOFILES))"; \
	if [ -n "$$out" ]; then echo "needs gofmt:"; echo "$$out"; exit 1; fi

# Run the prerequisite checker (the install.sh "doctor").
check:
	./install.sh check

clean:
	rm -f $(BIN)

help:
	@echo "targets: build (default), install, uninstall, test, vet, fmt, fmt-check, check, clean"
	@echo "vars:    PREFIX (default /usr/local; installs to \$$(PREFIX)/bin), DESTDIR, GO, GOTOOLCHAIN"
