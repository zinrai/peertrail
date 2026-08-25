/* Shared by the BPF program and userspace, so the layout cannot drift. */
#ifndef PEERTRAIL_H
#define PEERTRAIL_H

#define TASK_COMM_LEN 16

#define HOOK_CONNECT 0
#define HOOK_SENDMSG 1

struct event {
	__u64 ts_ns;
	__u32 uid;
	__u32 auid;
	__u32 ses;
	__u32 pid;
	/* Why not look procfs up by pid: comm belongs to a thread, so for a
	 * program that names its workers the two would disagree and userspace
	 * would discard a good path. */
	__u32 tid;
	/* Why not size this 4 for v4: one field for both families keeps the two
	 * emit paths identical apart from how much of it they fill. */
	__u8 daddr[16];
	/* Why not leave this in network order: every consumer would have to know
	 * to swap it, and one of them would forget. */
	__u16 dport;
	__u8 family;
	__u8 proto;
	__u8 hook;
	/* Why not make this longer: the kernel's own field is 16 bytes, so a
	 * wider one here would only be padding. */
	char comm[TASK_COMM_LEN];
};

#endif /* PEERTRAIL_H */
