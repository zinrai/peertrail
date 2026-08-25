# peertrail

Records outbound connections as JSON Lines: who logged in, what they ran, and
where it went, in a single record.

```json
{"timestamp":"2026-08-24T11:41:07.634Z","auid":1000,"uid":1000,"ses":105,"pid":2969,"comm":"host","exe":"/usr/bin/host","proto":"udp","family":"inet","dest":"192.168.100.1","port":53,"hook":"connect"}
{"timestamp":"2026-08-24T11:41:07.654Z","auid":1000,"uid":1000,"ses":105,"pid":2972,"comm":"curl","exe":"/usr/bin/curl","proto":"tcp","family":"inet","dest":"192.168.100.1","port":8080,"hook":"connect"}
{"timestamp":"2026-08-24T11:41:07.667Z","auid":1000,"uid":1000,"ses":105,"pid":2973,"comm":"ssh","exe":"/usr/bin/ssh","proto":"tcp","family":"inet","dest":"192.168.100.1","port":22,"hook":"connect"}
{"timestamp":"2026-08-24T11:41:07.795Z","auid":1000,"uid":1000,"ses":105,"pid":2974,"comm":"curl","proto":"tcp","family":"inet6","dest":"fd00::1","port":8443,"hook":"connect"}
```

One login, four destinations, one line each. Traffic that did not come from a
login is not recorded at all, so a daemon's connections never appear here.

A second kind of record reports what the kernel had to discard under load:

```json
{"timestamp":"2026-08-24T11:39:36.104Z","dropped":16360}
```

It appears only when something was lost, carries the number lost since the
previous one, and has no `dest`. A record set that cannot say whether it is
complete is not worth much, so the count travels with the records.

## Reading a record

Most of the fields say what they are. Three do not.

**`auid`** is the login uid, set once at login and inherited, so it survives
`su` and `sudo`. `uid` is what the traffic actually went out under. They differ
when someone escalated:

```json
{"auid":1000,"uid":1000,"comm":"curl","dest":"192.168.100.55","port":7001}
{"auid":1000,"uid":0,"comm":"curl","dest":"192.168.100.55","port":7002}
{"auid":1000,"uid":65534,"comm":"curl","dest":"192.168.100.55","port":7003}
```

One person, three privileges: their own, `sudo curl`, and `sudo -u nobody
curl`. Both fields are `-1` when there is no login session. Ids stay numeric;
resolving them is left to whatever reads the logs.

**`ses`** is a per-login identifier: filter on it to get everything one login
did. It is a per-boot counter, so it repeats after a reboot. Pair it with a
time range narrower than the uptime.

**`comm` and `exe`** are different answers, not different lengths of one
answer. `comm` is the name the program was invoked as, 15 characters because
that is the size of the kernel's own field. `exe` is the file that ran:

```
invoked: /usr/local/bin/symlinked-long-name-x   (a symlink to python3)
comm   = "symlinked-long-"
exe    = "/usr/bin/python3.13"
```

`comm` is caller-controlled, so it is not evidence of anything. `exe` is absent
when the thread was already gone by the time it was read, or when it could not
be confirmed to still be the same thread.

## Run

Binaries are on the [releases](../../releases) page.

```bash
$ sudo ./peertrail                    # -cgroup defaults to /sys/fs/cgroup
$ ./peertrail -version
```

Root is required, along with cgroup v2 mounted and a kernel built with
`CONFIG_CGROUP_BPF=y`. To keep it running, see `peertrail.service`.

If you narrow the capabilities, keep `CAP_SYS_PTRACE`. Reading
`/proc/<tid>/exe` for a process owned by somebody else needs it, and without it
that readlink fails for every process worth recording. Nothing reports an
error; `exe` is simply absent from every record.

## Limits

**A record is an attempt, not a connection.** The hooks run before anything
reaches the destination, so a refused port and a working session produce the
same record. Someone tried to reach that address; whether they got there is not
in here.

Traffic through an SSH tunnel is recorded as the tunnel's own outbound
connection. That gives the destination, not what was asked of it.

TCP and UDP only. A ping leaves nothing behind: ICMP passes through neither
hook.

## Changing the BPF program

```bash
$ sudo apt install clang llvm libbpf-dev make
$ make               # regenerates the object when bpf/ is newer, then builds
$ go test -race ./...
```

Commit what that produces. The committed object is what `go build` embeds, what
`go install` gets, and what a release ships, so building through `make` is what
keeps an edit to `bpf/` from leaving all three on the previous program.

A release is built from the tag as it stands, with no regeneration. Rebuilding
in CI would ship an object that differs byte for byte from the one in the tag,
since a different clang produces a different object from the same source.

## License

This project is licensed under the [MIT License](./LICENSE).
