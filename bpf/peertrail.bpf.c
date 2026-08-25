/* Why not enter at the syscall tracepoints, the way most tools like this do:
 * the sockaddr would have to be read out of user memory and decoded here, and
 * the address family inferred from bytes the caller controls. The cgroup
 * attach points are UAPI, hand over a struct bpf_sock_addr, and put the
 * destination in a field.
 *
 * Why not also attach cgroup/connect_unix: AF_UNIX arrives there and nowhere
 * else, so leaving it alone is a filter that cannot be written wrong.
 */
#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>
#include "peertrail.h"

/* Why not include vmlinux.h: two fields are read, and CO-RE relocates them by
 * name against the running kernel's BTF, so a 4 MB header buys nothing. */
typedef struct {
	unsigned int val;
} peertrail_kuid_t;

struct task_struct {
	peertrail_kuid_t loginuid;
	unsigned int sessionid;
} __attribute__((preserve_access_index));

char LICENSE[] SEC("license") = "GPL";

#define AF_INET 2
#define AF_INET6 10
#define AUID_UNSET 0xffffffff

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} events SEC(".maps");

/* Why not delete this apparently unused declaration: a ring buffer map carries
 * no key or value type, so struct event would never reach BTF and the Go side
 * could not be generated from it. */
const struct event *unused __attribute__((unused));

/* Why not skip counting drops: a full ring buffer and an idle host would then
 * produce the same output, and a record that cannot say whether it is complete
 * is not worth much.
 *
 * Why not one shared counter: per-CPU keeps the increment off a contended
 * cache line, and summing is userspace's problem. */
struct {
	__uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
	__uint(max_entries, 1);
	__type(key, __u32);
	__type(value, __u64);
} drops SEC(".maps");

static __always_inline void count_drop(void)
{
	__u32 zero = 0;
	__u64 *n = bpf_map_lookup_elem(&drops, &zero);
	/* Why not a plain ++: per-CPU still leaves a task switch on the same CPU,
	 * which a preemptible kernel allows, and an atomic costs nothing here. */
	if (n)
		__sync_fetch_and_add(n, 1);
}

static __always_inline struct event *begin(struct bpf_sock_addr *ctx, __u8 hook, __u8 family)
{
	/* Why not filter on uid >= 1000, which is the obvious thing to write:
	 * sudo runs as uid 0, so that test discards exactly the escalation this
	 * exists to record. auid is set once at login and inherited, so it
	 * survives su and sudo, and a task that never logged in has AUID_UNSET. */
	struct task_struct *task = (struct task_struct *)bpf_get_current_task();
	__u32 auid = BPF_CORE_READ(task, loginuid.val);
	if (auid == AUID_UNSET)
		return 0;

	struct event *e = bpf_ringbuf_reserve(&events, sizeof(*e), 0);
	if (!e) {
		count_drop();
		return 0;
	}

	__builtin_memset(e->daddr, 0, sizeof(e->daddr));
	e->ts_ns = bpf_ktime_get_ns();
	e->uid = (__u32)bpf_get_current_uid_gid();
	__u64 pid_tgid = bpf_get_current_pid_tgid();
	e->pid = pid_tgid >> 32;
	e->tid = (__u32)pid_tgid;
	e->auid = auid;
	e->ses = BPF_CORE_READ(task, sessionid);
	e->dport = bpf_ntohl(ctx->user_port) >> 16;
	e->family = family;
	e->proto = ctx->protocol;
	e->hook = hook;
	bpf_get_current_comm(&e->comm, sizeof(e->comm));
	return e;
}

static __always_inline int emit4(struct bpf_sock_addr *ctx, __u8 hook)
{
	struct event *e = begin(ctx, hook, AF_INET);
	if (!e)
		return 1;
	/* Why not memcpy straight from ctx: the verifier rejects copies that go
	 * through a pointer into it. */
	__u32 a = ctx->user_ip4;
	__builtin_memcpy(e->daddr, &a, 4);
	bpf_ringbuf_submit(e, 0);
	return 1;
}

/* Why not one emit() that branches on family: the verifier rejects a read of
 * user_ip6 from a v4 attach point with invalid bpf_context access, so the two
 * paths cannot share a body. */
static __always_inline int emit6(struct bpf_sock_addr *ctx, __u8 hook)
{
	struct event *e = begin(ctx, hook, AF_INET6);
	if (!e)
		return 1;
	__u32 a0 = ctx->user_ip6[0];
	__u32 a1 = ctx->user_ip6[1];
	__u32 a2 = ctx->user_ip6[2];
	__u32 a3 = ctx->user_ip6[3];
	__builtin_memcpy(e->daddr + 0, &a0, 4);
	__builtin_memcpy(e->daddr + 4, &a1, 4);
	__builtin_memcpy(e->daddr + 8, &a2, 4);
	__builtin_memcpy(e->daddr + 12, &a3, 4);
	bpf_ringbuf_submit(e, 0);
	return 1;
}

/* Why not ever return 0: these observe. Denying a connection from an audit
 * tool would turn a recording bug into an outage. */

SEC("cgroup/connect4")
int on_connect4(struct bpf_sock_addr *ctx)
{
	return emit4(ctx, HOOK_CONNECT);
}

SEC("cgroup/connect6")
int on_connect6(struct bpf_sock_addr *ctx)
{
	return emit6(ctx, HOOK_CONNECT);
}

SEC("cgroup/sendmsg4")
int on_sendmsg4(struct bpf_sock_addr *ctx)
{
	return emit4(ctx, HOOK_SENDMSG);
}

SEC("cgroup/sendmsg6")
int on_sendmsg6(struct bpf_sock_addr *ctx)
{
	return emit6(ctx, HOOK_SENDMSG);
}
