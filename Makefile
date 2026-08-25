# Requirements: a Go toolchain, and clang only to rebuild the BPF program.
#
#   sudo apt install clang llvm libbpf-dev make golang-go
#
# cilium/ebpf needs Go 1.25 or newer. Debian 13 ships 1.24, so the build there
# fetches a newer toolchain on its own the first time.
BPF2GO_CFLAGS := -O2 -g -Wall -I/usr/include/$(shell uname -m)-linux-gnu

BPF_SRC := bpf/peertrail.bpf.c bpf/peertrail.h
BPF_OBJ := peertrail_bpfel.o

all: peertrail

# The object is a prerequisite, not a note in the README: `go build` embeds
# whatever is committed, so editing bpf/ and forgetting to regenerate would
# leave you running the previous program while everything looks fine.
peertrail: $(wildcard *.go) $(BPF_OBJ)
	go build -o $@ .

$(BPF_OBJ): $(BPF_SRC)
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./...

# Commit what this produces. It is what lets `go build` work without clang, and
# it is what the release is built from after being regenerated there.
generate:
	BPF2GO_CFLAGS="$(BPF2GO_CFLAGS)" go generate ./...

clean:
	rm -f peertrail

.PHONY: all generate clean
