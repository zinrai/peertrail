package main

import (
	"sync"
	"time"

	"github.com/cilium/ebpf"
)

// Why not report this to stderr: whatever collects the records would then hold
// them without the gaps, and a record set that cannot say whether it is
// complete is not worth much.
//
// Why not add a "dropped":0 field to every connection record instead: it would
// cost a field on every line to carry a number that is almost always zero.
type dropRecord struct {
	TS      string `json:"timestamp"`
	Dropped uint64 `json:"dropped"`
}

// Why not read the counter on every event: it is a map lookup per record to
// learn something that changes only under load. Why not once a minute: a burst
// would be attributed too far from when it happened.
const dropInterval = 30 * time.Second

// Why not take an *ebpf.Map and time.Now directly: the reporting is the part
// worth testing, and a test cannot load a map or wait thirty seconds.
type dropReporter struct {
	read     func() ([]uint64, error)
	out      *emitter
	now      func() string
	interval time.Duration

	seen uint64
	done chan struct{}
	wg   sync.WaitGroup
}

func newDropReporter(counter *ebpf.Map, out *emitter, c *clock) *dropReporter {
	read := func() ([]uint64, error) {
		var perCPU []uint64
		err := counter.Lookup(uint32(0), &perCPU)
		return perCPU, err
	}
	return newDropReporterFunc(read, out, c.now, dropInterval)
}

func newDropReporterFunc(read func() ([]uint64, error), out *emitter, clock func() string, interval time.Duration) *dropReporter {
	return &dropReporter{
		read:     read,
		out:      out,
		now:      clock,
		interval: interval,
		done:     make(chan struct{}),
	}
}

func (r *dropReporter) start() {
	r.wg.Add(1)
	go func() {
		defer r.wg.Done()
		t := time.NewTicker(r.interval)
		defer t.Stop()
		for {
			select {
			case <-r.done:
				// Why not return straight away: whatever was lost since the
				// last tick would go with it, and stopping the process would
				// be a way to hide drops.
				r.report()
				return
			case <-t.C:
				r.report()
			}
		}
	}()
}

// Why not close this after the tracer: the counter lives in a map the tracer
// owns, and the last read needs it open.
func (r *dropReporter) Close() {
	close(r.done)
	r.wg.Wait()
}

// Why not write a record when the read fails: the counter is a diagnostic, and
// claiming zero drops because it could not be read is the one answer worse
// than saying nothing.
func (r *dropReporter) report() {
	perCPU, err := r.read()
	if err != nil {
		return
	}
	if n, ok := delta(perCPU, &r.seen); ok {
		r.out.emit(dropRecord{TS: r.now(), Dropped: n})
	}
}

// Why not report the running total: a reader that missed an earlier record
// could not tell how much of the total it had already seen, while differences
// add up whatever arrives.
func delta(perCPU []uint64, seen *uint64) (uint64, bool) {
	var total uint64
	for _, v := range perCPU {
		total += v
	}
	if total == *seen {
		return 0, false
	}
	n := total - *seen
	*seen = total
	return n, true
}
