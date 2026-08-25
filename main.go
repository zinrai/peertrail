// peertrail prints outbound connections as JSON Lines.
//
//	peertrail [-cgroup path]
//	peertrail -version
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"syscall"

	"github.com/cilium/ebpf/ringbuf"
)

// Why not write the loader and the Go form of struct event by hand: field
// offsets copied out of C drift the moment either side changes, and bpf2go
// takes both from the same BTF. Run `make generate` after editing the BPF
// program, and commit what it produces.
//
//go:generate go tool bpf2go -type event peertrail bpf/peertrail.bpf.c

func run(cgroupPath string) error {
	t, err := attach(cgroupPath)
	if err != nil {
		return err
	}
	defer t.Close()

	rd, err := ringbuf.NewReader(t.objs.Events)
	if err != nil {
		return fmt.Errorf("opening the ring buffer: %w", err)
	}
	defer rd.Close()

	// Why not cancel a context: the read blocks inside the reader, which does
	// not watch one. Closing it is what unblocks it.
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sig
		rd.Close()
	}()

	c, err := newClock()
	if err != nil {
		return err
	}
	c.start()
	defer c.Close()

	out := newEmitter(os.Stdout)
	drops := newDropReporter(t.objs.Drops, out, c)
	drops.start()
	// Why not register this alongside the tracer: deferred calls run in
	// reverse, and the last drop report needs that map still open.
	defer drops.Close()

	rend := newRenderer(c)

	// Which build produced the records is part of what they are worth, and
	// this line is what journald keeps.
	fmt.Fprintf(os.Stderr, "peertrail %s: watching %s\n", version, cgroupPath)

	for {
		rec, err := rd.Read()
		if errors.Is(err, ringbuf.ErrClosed) {
			return nil
		}
		if err != nil {
			return fmt.Errorf("reading from the ring buffer: %w", err)
		}

		e, err := decode(rec.RawSample)
		if err != nil {
			// Why not return here: one malformed sample is not a reason to
			// stop recording everything after it.
			fmt.Fprintf(os.Stderr, "peertrail: decoding a record: %v\n", err)
			continue
		}
		if err := out.emit(rend.render(e)); err != nil {
			return fmt.Errorf("writing a record: %w", err)
		}
	}
}

func main() {
	cgroupPath := flag.String("cgroup", "/sys/fs/cgroup", "cgroup v2 path to attach to")
	showVersion := flag.Bool("version", false, "print the version and exit")
	flag.Parse()

	if *showVersion {
		printVersion()
		return
	}
	// Why not ignore leftover arguments: the cgroup path used to be positional,
	// and silently running against the default would be a recording gap nobody
	// would notice.
	if flag.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "peertrail: unexpected argument %q\n", flag.Arg(0))
		flag.Usage()
		os.Exit(2)
	}

	if err := run(*cgroupPath); err != nil {
		fmt.Fprintf(os.Stderr, "peertrail: %v\n", err)
		os.Exit(1)
	}
}
