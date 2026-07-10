BIN  := lmount
GO   := go

.PHONY: all build test clean install

all: build

build:
	$(GO) build -o $(BIN) .

test:
	$(GO) test -v -count=1 ./...

clean:
	rm -f $(BIN)

install: build
	sudo install -m 0755 $(BIN) /usr/local/bin/$(BIN)
