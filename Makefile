bin_dir := bin
bin := $(bin_dir)/ambicert
all: clean build
clean:
	rm -r $(bin_dir) || true 
build: $(bin)
$(bin): main.go
	go mod tidy
	go mod download
	go test -v ./...
	go build -o $@ $^
install:
	go install .
run: $(bin)
	$(bin)
