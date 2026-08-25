package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"golang.org/x/sys/unix"
)

const (
	afInet6 = 10

	hookSendmsg = 1
)

type record struct {
	TS     string `json:"timestamp"`
	AUID   int64  `json:"auid"`
	UID    uint32 `json:"uid"`
	Ses    int64  `json:"ses"`
	PID    uint32 `json:"pid"`
	Comm   string `json:"comm"`
	Exe    string `json:"exe,omitempty"`
	Proto  string `json:"proto"`
	Family string `json:"family"`
	Dest   string `json:"dest"`
	Port   uint16 `json:"port"`
	Hook   string `json:"hook"`
}

const unsetID = ^uint32(0)

// Why not pass the kernel's value through: 4294967295 in an auid field reads
// as an account, and -1 does not.
func signedID(v uint32) int64 {
	if v == unsetID {
		return -1
	}
	return int64(v)
}

// Why not second precision: two events in the same second are ordinary, and
// their order would then survive only as the order of the lines.
const stampFormat = "2006-01-02T15:04:05.000Z"

const clockRefresh = 30 * time.Second

// Why not call time.Now where a record is written: that stamps the drain, not
// the event, and the two are furthest apart exactly when the host is busiest.
// The kernel counts nanoseconds since boot, so the difference against the wall
// clock is what puts an event on a calendar.
type clock struct {
	offset atomic.Int64 // nanoseconds
	done   chan struct{}
	wg     sync.WaitGroup
}

func newClock() (*clock, error) {
	c := &clock{done: make(chan struct{})}
	if err := c.refresh(); err != nil {
		return nil, err
	}
	return c, nil
}

// Why not read the difference once at startup: a slew moves both clocks
// together and needs no correction, but a step moves only the wall clock, and
// a step is ordinary at boot, where chrony corrects on its first updates while
// this process is already running.
func (c *clock) refresh() error {
	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		return fmt.Errorf("reading the monotonic clock: %w", err)
	}
	mono := time.Duration(ts.Sec)*time.Second + time.Duration(ts.Nsec)
	c.offset.Store(time.Now().UnixNano() - mono.Nanoseconds())
	return nil
}

func (c *clock) start() {
	c.wg.Add(1)
	go func() {
		defer c.wg.Done()
		t := time.NewTicker(clockRefresh)
		defer t.Stop()
		for {
			select {
			case <-c.done:
				return
			case <-t.C:
				c.refresh()
			}
		}
	}()
}

// Why not refresh one last time here, the way the drop reporter reports one
// last time: nobody is left to stamp a record with it.
func (c *clock) Close() {
	close(c.done)
	c.wg.Wait()
}

func (c *clock) at(tsNS uint64) string {
	return time.Unix(0, c.offset.Load()+int64(tsNS)).UTC().Format(stampFormat)
}

func (c *clock) now() string {
	return time.Now().UTC().Format(stampFormat)
}

// Why not look this up by pid: comm belongs to a thread, so a program that
// names its workers with pthread_setname_np puts the worker's name in the
// event and the main thread's name in /proc/<pid>/comm, and the comparison
// below would throw away a good path. Every thread shares one executable, so
// going through the tid loses nothing.
//
// Why not trust the path once it is read: the id may have been reused since
// the event, and a record carrying somebody else's exe is a wrong answer that
// reads like a right one, which is worse than the gap a missing one leaves.
//
// Why not drop comm now that this exists: comm is the name the caller invoked,
// this is the file that ran, and a wrapper script makes those different
// answers rather than different lengths of one answer.
func exePath(tid uint32, comm string) string {
	dir := "/proc/" + strconv.FormatUint(uint64(tid), 10)
	p, err := os.Readlink(dir + "/exe")
	if err != nil {
		return ""
	}
	b, err := os.ReadFile(dir + "/comm")
	if err != nil || strings.TrimRight(string(b), "\n") != comm {
		return ""
	}
	return p
}

// Why not a plain string conversion: the field is []int8 padded with NULs,
// which would reach the JSON as escapes.
func cstring(b []int8) string {
	out := make([]byte, 0, len(b))
	for _, c := range b {
		if c == 0 {
			break
		}
		out = append(out, byte(c))
	}
	return string(out)
}

// Why not name an endianness: the Go struct is generated from the same BTF as
// the C one so the layout cannot drift, but the byte order is the machine's,
// and there is a big-endian object for machines where that differs.
func decode(sample []byte) (peertrailEvent, error) {
	var e peertrailEvent
	err := binary.Read(bytes.NewReader(sample), binary.NativeEndian, &e)
	return e, err
}

// Why not call the clock and procfs directly from render: the mapping is the
// part worth testing, and neither of those belongs in a test.
type renderer struct {
	at  func(tsNS uint64) string
	exe func(tid uint32, comm string) string
}

func newRenderer(c *clock) *renderer {
	return &renderer{at: c.at, exe: exePath}
}

func (r *renderer) render(e peertrailEvent) record {
	// Why not read all sixteen bytes regardless of family: a v4 address sits
	// in the first four, and the trailing zeroes would turn 192.168.100.1
	// into ::c0a8:6401.
	addr, _ := netip.AddrFromSlice(e.Daddr[:4])
	family := "inet"
	if e.Family == afInet6 {
		addr, _ = netip.AddrFromSlice(e.Daddr[:])
		family = "inet6"
	}

	proto := "tcp"
	if e.Proto == syscall.IPPROTO_UDP {
		proto = "udp"
	}

	hook := "connect"
	if e.Hook == hookSendmsg {
		hook = "sendmsg"
	}

	comm := cstring(e.Comm[:])

	return record{
		TS:     r.at(e.TsNs),
		AUID:   signedID(e.Auid),
		UID:    e.Uid,
		Ses:    signedID(e.Ses),
		PID:    e.Pid,
		Comm:   comm,
		Exe:    r.exe(e.Tid, comm),
		Proto:  proto,
		Family: family,
		Dest:   addr.String(),
		Port:   e.Dport,
		Hook:   hook,
	}
}

// Why not encode to stdout from both places directly: the ring buffer reader
// and the drop reporter run concurrently, and two encoders on one file can
// interleave a half-written line.
type emitter struct {
	mu  sync.Mutex
	enc *json.Encoder
}

func newEmitter(w io.Writer) *emitter {
	return &emitter{enc: json.NewEncoder(w)}
}

func (e *emitter) emit(v any) error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.enc.Encode(v)
}
