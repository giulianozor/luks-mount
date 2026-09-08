BIN  := lmount
GO   := go

.PHONY: all build test check stress clean install

all: build

build:
	$(GO) build -o $(BIN) .

test:
	$(GO) test -v -count=1 ./...

check:
	$(GO) vet ./...
	@test -z "$$(gofmt -l . | tee /dev/stderr)" || (echo "gofmt: fix the files above"; exit 1)
	$(GO) test -count=1 -race -shuffle=on ./...
	# The tool is Linux-only at runtime; compiling for the Linux targets here
	# prevents a subtle darwin-only slip from passing CI and failing on deploy.
	GOOS=linux GOARCH=amd64 $(GO) build -o /tmp/lmount-linux-amd64 .
	GOOS=linux GOARCH=arm64 $(GO) build -o /tmp/lmount-linux-arm64 .

stress:
	$(GO) test -count=2 -race -cpu 1,8 ./...

clean:
	rm -f $(BIN)

install: build
	sudo install -m 0755 $(BIN) /usr/local/bin/$(BIN)
