package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"strings"
	"testing"
	"time"
)

func TestTheFirstReadCountsEverythingSoFar(t *testing.T) {
	var seen uint64

	n, ok := delta([]uint64{3, 4, 0, 1}, &seen)

	if !ok || n != 8 {
		t.Errorf("first read = %d/%v, want 8/true", n, ok)
	}
}

func TestAnUnchangedCounterReportsNothing(t *testing.T) {
	var seen uint64
	delta([]uint64{3, 4, 0, 1}, &seen)

	if n, ok := delta([]uint64{3, 4, 0, 1}, &seen); ok {
		t.Errorf("an unchanged counter reported %d", n)
	}
}

func TestEachReadReportsOnlyWhatWasAdded(t *testing.T) {
	var seen uint64
	delta([]uint64{3, 4, 0, 1}, &seen)

	n, ok := delta([]uint64{3, 9, 0, 1}, &seen)

	if !ok || n != 5 {
		t.Errorf("second read = %d/%v, want 5/true", n, ok)
	}
}

func TestAnEmptyCounterReportsNothing(t *testing.T) {
	var seen uint64

	if n, ok := delta(nil, &seen); ok {
		t.Errorf("an empty counter reported %d", n)
	}
}

// An interval this long means the ticker never fires, so only the shutdown
// path can produce output.
func closeOnlyReporter(read func() ([]uint64, error), out *emitter) *dropReporter {
	return newDropReporterFunc(read, out, func() string { return "2026-01-01T00:00:00.000Z" }, time.Hour)
}

func TestClosingReportsWhatWasLostSinceTheLastTick(t *testing.T) {
	var buf bytes.Buffer
	r := closeOnlyReporter(func() ([]uint64, error) { return []uint64{16360}, nil }, newEmitter(&buf))

	r.start()
	r.Close()

	var got dropRecord
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output was %q: %v", buf.String(), err)
	}
	if got.Dropped != 16360 {
		t.Errorf("dropped = %d, want 16360", got.Dropped)
	}
}

func TestNothingIsWrittenWhenNothingWasLost(t *testing.T) {
	var buf bytes.Buffer
	r := closeOnlyReporter(func() ([]uint64, error) { return []uint64{0, 0}, nil }, newEmitter(&buf))

	r.start()
	r.Close()

	if buf.Len() != 0 {
		t.Errorf("wrote %q with no drops to report", buf.String())
	}
}

func TestAnUnreadableCounterWritesNothing(t *testing.T) {
	var buf bytes.Buffer
	r := closeOnlyReporter(func() ([]uint64, error) { return nil, errors.New("map closed") }, newEmitter(&buf))

	r.start()
	r.Close()

	if buf.Len() != 0 {
		t.Errorf("wrote %q after a failed read", buf.String())
	}
}

func TestADropRecordCarriesNoDestination(t *testing.T) {
	out, err := json.Marshal(dropRecord{TS: "2026-01-01T00:00:00.000Z", Dropped: 1})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(out), "dest") {
		t.Errorf("a drop record carries dest: %s", out)
	}
}
