VERSION ?= $(shell git describe --tags --always --dirty)
LDFLAGS := -s -w -X main.version=$(VERSION)

.PHONY: build test lint clean

build:
	go build -ldflags "$(LDFLAGS)" -o talos ./cmd/talos

test:
	go test ./... -race

lint:
	golangci-lint run

clean:
	rm -f talos
