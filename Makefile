.PHONY: run build test clean help

help:
	@echo "Available targets:"
	@echo "  run    - Run the application in development mode"
	@echo "  build  - Build the application binary"
	@echo "  test   - Run tests"
	@echo "  clean  - Clean build artifacts"

run:
	go run ./cmd/web

build:
	go build -o bin/cve-analyzer ./cmd/web

test:
	go test ./...

clean:
	rm -rf bin/