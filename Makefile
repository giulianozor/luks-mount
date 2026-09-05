BIN  := lmount
GO   := go

.PHONY: all build test check clean install

all: build

build:
	$(GO) build -o $(BIN) .

test:
	$(GO) test -v -count=1 ./...

check:
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: fix the files above"; exit 1)
	$(GO) test -count=1 ./...

clean:
	rm -f $(BIN)

install: build
	sudo install -m 0755 $(BIN) /usr/local/bin/$(BIN)
