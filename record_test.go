package main

import (
	"bytes"
	"encoding/binary"
	"encoding/json"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func testRenderer(exe string) *renderer {
	return &renderer{
		at:  func(uint64) string { return "2026-01-01T00:00:00.000Z" },
		exe: func(uint32, string) string { return exe },
	}
}

func comm(s string) [16]int8 {
	var c [16]int8
	for i := 0; i < len(s) && i < len(c); i++ {
		c[i] = int8(s[i])
	}
	return c
}

func TestAnIPv4AddressComesFromTheFirstFourBytes(t *testing.T) {
	e := peertrailEvent{Family: 2, Proto: 6, Dport: 22}
	copy(e.Daddr[:], []byte{192, 168, 100, 1})

	got := testRenderer("/usr/bin/ssh").render(e)

	if got.Dest != "192.168.100.1" {
		t.Errorf("dest = %q, want 192.168.100.1", got.Dest)
	}
	if got.Family != "inet" {
		t.Errorf("family = %q, want inet", got.Family)
	}
}

func TestAnIPv6AddressComesFromAllSixteenBytes(t *testing.T) {
	e := peertrailEvent{Family: afInet6, Proto: 6, Dport: 8443}
	copy(e.Daddr[:], []byte{0xfd, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1})

	got := testRenderer("/usr/bin/curl").render(e)

	if got.Dest != "fd00::1" {
		t.Errorf("dest = %q, want fd00::1", got.Dest)
	}
	if got.Family != "inet6" {
		t.Errorf("family = %q, want inet6", got.Family)
	}
}

func TestNoLoginSessionRendersAsMinusOne(t *testing.T) {
	e := peertrailEvent{Family: 2, Auid: unsetID, Ses: unsetID}

	got := testRenderer("").render(e)

	if got.AUID != -1 {
		t.Errorf("auid = %d, want -1", got.AUID)
	}
	if got.Ses != -1 {
		t.Errorf("ses = %d, want -1", got.Ses)
	}
}

func TestARealLoginSessionKeepsItsNumbers(t *testing.T) {
	e := peertrailEvent{Family: 2, Auid: 1000, Uid: 1001, Ses: 24, Pid: 843}

	got := testRenderer("").render(e)

	if got.AUID != 1000 || got.UID != 1001 || got.Ses != 24 || got.PID != 843 {
		t.Errorf("auid/uid/ses/pid = %d/%d/%d/%d, want 1000/1001/24/843",
			got.AUID, got.UID, got.Ses, got.PID)
	}
}

func TestCommEndsAtItsTerminator(t *testing.T) {
	e := peertrailEvent{Family: 2, Comm: comm("curl")}

	if got := testRenderer("").render(e).Comm; got != "curl" {
		t.Errorf("comm = %q, want curl", got)
	}
}

func TestCommWithNoTerminatorStaysInsideTheField(t *testing.T) {
	var e peertrailEvent
	e.Family = 2
	for i := range e.Comm {
		e.Comm[i] = int8('x')
	}

	if got := testRenderer("").render(e).Comm; got != strings.Repeat("x", 16) {
		t.Errorf("comm = %q, want 16 x's", got)
	}
}

func TestProtocolAndHookAreNamed(t *testing.T) {
	cases := []struct {
		proto, hook       uint8
		wantProto, wantHk string
	}{
		{6, 0, "tcp", "connect"},
		{17, 0, "udp", "connect"},
		{17, hookSendmsg, "udp", "sendmsg"},
	}
	for _, c := range cases {
		got := testRenderer("").render(peertrailEvent{Family: 2, Proto: c.proto, Hook: c.hook})
		if got.Proto != c.wantProto || got.Hook != c.wantHk {
			t.Errorf("proto %d hook %d rendered as %s/%s, want %s/%s",
				c.proto, c.hook, got.Proto, got.Hook, c.wantProto, c.wantHk)
		}
	}
}

func TestAnUnknownExeLeavesTheFieldOutEntirely(t *testing.T) {
	e := peertrailEvent{Family: 2}

	out, err := json.Marshal(testRenderer("").render(e))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(out, []byte(`"exe"`)) {
		t.Errorf("exe present in %s", out)
	}

	out, err = json.Marshal(testRenderer("/usr/bin/host").render(e))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Contains(out, []byte(`"exe":"/usr/bin/host"`)) {
		t.Errorf("exe missing from %s", out)
	}
}

func TestTheTimestampIsTheEventsOwn(t *testing.T) {
	var c clock
	c.offset.Store(time.Unix(1_000_000_000, 0).UnixNano())

	r := &renderer{at: c.at, exe: func(uint32, string) string { return "" }}
	got := r.render(peertrailEvent{Family: 2, TsNs: 1_500_000_000}).TS

	if want := "2001-09-09T01:46:41.500Z"; got != want {
		t.Errorf("ts = %q, want %q", got, want)
	}
}

func TestAKernelTimestampOfNowRendersAsNow(t *testing.T) {
	c, err := newClock()
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()

	var ts unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC, &ts); err != nil {
		t.Fatal(err)
	}
	mono := uint64(ts.Sec)*uint64(time.Second) + uint64(ts.Nsec)

	got, err := time.Parse(stampFormat, c.at(mono))
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Since(got); d < -time.Second || d > time.Second {
		t.Errorf("a kernel timestamp of now rendered %v away from now", d)
	}
}

func TestTheClockStopsWhenClosed(t *testing.T) {
	c, err := newClock()
	if err != nil {
		t.Fatal(err)
	}
	c.start()
	c.Close()
}

func TestExeIsDroppedWhenTheNameDisagrees(t *testing.T) {
	self := uint32(os.Getpid())

	b, err := os.ReadFile("/proc/self/comm")
	if err != nil {
		t.Skip("no procfs")
	}
	mine := strings.TrimRight(string(b), "\n")

	if got := exePath(self, mine); got == "" {
		t.Errorf("exe was dropped for the matching name %q", mine)
	}
	if got := exePath(self, "somethingelse"); got != "" {
		t.Errorf("exe = %q for a name that disagrees, want it dropped", got)
	}
}

func TestExeIsEmptyForAnIDThatIsGone(t *testing.T) {
	if got := exePath(1<<30, "curl"); got != "" {
		t.Errorf("exe = %q for an id that does not exist", got)
	}
}

func TestAnEventSurvivesEncodingAndDecoding(t *testing.T) {
	want := peertrailEvent{
		TsNs: 12345, Uid: 1000, Auid: 1000, Ses: 24, Pid: 843, Tid: 844,
		Dport: 623, Family: 2, Proto: 17, Hook: hookSendmsg, Comm: comm("ipmitool"),
	}
	copy(want.Daddr[:], []byte{10, 0, 2, 99})

	var buf bytes.Buffer
	if err := binary.Write(&buf, binary.NativeEndian, want); err != nil {
		t.Fatal(err)
	}

	got, err := decode(buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if got != want {
		t.Errorf("decoding changed the event\n got %+v\nwant %+v", got, want)
	}
}

func TestATruncatedSampleIsAnError(t *testing.T) {
	if _, err := decode([]byte{1, 2, 3}); err == nil {
		t.Error("a truncated sample decoded without an error")
	}
}

// The two sides agree on this size or every field past the first difference is
// garbage. After changing struct event, run `make generate` and update it.
func TestTheEventIsSeventyTwoBytes(t *testing.T) {
	const want = 72
	if got := binary.Size(peertrailEvent{}); got != want {
		t.Errorf("sizeof(struct event) = %d, want %d", got, want)
	}
}

func TestConcurrentRecordsArriveWhole(t *testing.T) {
	const n = 200

	var buf bytes.Buffer
	e := newEmitter(&buf)

	var wg sync.WaitGroup
	for i := range n {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e.emit(record{TS: "2026-01-01T00:00:00.000Z", Comm: "curl", Port: uint16(i)})
		}(i)
	}
	wg.Wait()

	lines := strings.Split(strings.TrimRight(buf.String(), "\n"), "\n")
	if len(lines) != n {
		t.Fatalf("got %d lines, want %d", len(lines), n)
	}
	for i, l := range lines {
		var r record
		if err := json.Unmarshal([]byte(l), &r); err != nil {
			t.Fatalf("line %d is not a whole record: %q", i, l)
		}
	}
}
