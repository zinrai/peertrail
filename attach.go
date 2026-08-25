package main

import (
	"fmt"

	"github.com/cilium/ebpf"
	"github.com/cilium/ebpf/link"
	"github.com/cilium/ebpf/rlimit"
)

type tracer struct {
	objs  peertrailObjects
	links []link.Link
}

func attach(cgroupPath string) (*tracer, error) {
	if err := rlimit.RemoveMemlock(); err != nil {
		return nil, fmt.Errorf("raising the memlock limit: %w", err)
	}

	t := &tracer{}
	if err := loadPeertrailObjects(&t.objs, nil); err != nil {
		return nil, fmt.Errorf("loading BPF objects: %w", err)
	}

	// Why not derive the attach type from the program: it comes from the
	// section each was compiled into, and naming both here means a mismatch
	// is rejected at attach time instead of attaching somewhere harmless and
	// recording nothing.
	hooks := []struct {
		name     string
		prog     *ebpf.Program
		attachTo ebpf.AttachType
	}{
		{"connect4", t.objs.OnConnect4, ebpf.AttachCGroupInet4Connect},
		{"connect6", t.objs.OnConnect6, ebpf.AttachCGroupInet6Connect},
		{"sendmsg4", t.objs.OnSendmsg4, ebpf.AttachCGroupUDP4Sendmsg},
		{"sendmsg6", t.objs.OnSendmsg6, ebpf.AttachCGroupUDP6Sendmsg},
	}
	for _, h := range hooks {
		l, err := link.AttachCgroup(link.CgroupOptions{
			Path:    cgroupPath,
			Attach:  h.attachTo,
			Program: h.prog,
		})
		if err != nil {
			// Why not leave the links that did attach in place and carry on:
			// half attached records some families and quietly misses others,
			// which is worse than not running.
			t.Close()
			return nil, fmt.Errorf("attaching %s to %s: %w", h.name, cgroupPath, err)
		}
		t.links = append(t.links, l)
	}
	return t, nil
}

func (t *tracer) Close() {
	for _, l := range t.links {
		l.Close()
	}
	t.objs.Close()
}
