.PHONY: all build install run clean

BINARY_NAME=asshi

all: build

build:
	go build -o $(BINARY_NAME) main.go

install: build
	mv $(BINARY_NAME) /usr/local/bin/

run:
	go run main.go

clean:
	go clean
	rm -f $(BINARY_NAME)
