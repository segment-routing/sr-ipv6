#ifndef _NET_SEG6_H
#define _NET_SEG6_H

#include <net/flow.h>
#include <net/ip6_fib.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/route.h>

#define seg6_addrto64(addr) ((u64)((u64)(addr)->s6_addr[0] << 56 | (u64)(addr)->s6_addr[1] << 48 | (u64)(addr)->s6_addr[2] << 40 | (u64)(addr)->s6_addr[3] << 32 | (addr)->s6_addr[12] << 24 | (addr)->s6_addr[13] << 16 | (addr)->s6_addr[14] << 8 | (addr)->s6_addr[15]))
#define seg6_hashfn(dst) hash_64(seg6_addrto64(dst), 12)

#define SEG6NEWPOL	0x0001
#define SEG6ADDSEG	0x0002
#define SEG6FLUSH	0x0004
#define SEG6DUMP	0x0005
#define SEG6DELSEG	0x0006

struct seg6_list {
	u16 id;
	struct in6_addr *segments;
	int seg_size;
	int cleanup;
	u8 hmackeyid;

	struct seg6_list *next;
};

struct seg6_info {
	struct in6_addr dst;
	int dst_len;

	struct seg6_list *list;
	int list_size;

	struct hlist_node seg_chain;
};

struct seg6_newpol {
	struct in6_addr dst;
	int dst_len;
};

struct seg6_addseg {
	struct in6_addr dst;
	int dst_len;
	u16 id;
	int cleanup;
	u8 hmackeyid;
	struct in6_addr segment;
};

struct seg6_delseg {
	struct in6_addr dst;
	int dst_len;
	u16 id;
};

struct seg6_msg {
	int msg;
	void *data;
};

extern int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr, struct in6_addr *saddr, u32 *output, int zero);
extern int seg6_add_segment(struct net *net, struct seg6_addseg *segmsg);
extern int seg6_del_segment(struct net *net, struct seg6_delseg *segmsg);
extern int seg6_dump_segments(struct net *net);
extern int seg6_flush_segments(struct net *net);
extern int seg6_create_pol(struct net *net, struct seg6_newpol *npmsg);
extern int seg6_process_skb(struct net *net, struct sk_buff **skb);
extern struct seg6_list *seg6_get_segments(struct net *net, struct in6_addr *dst);
extern void seg6_build_tmpl_srh(struct seg6_list *segments, struct ipv6_sr_hdr *srh);
extern void seg6_init_sysctl(void);

extern char seg6_hmac_key[];
#define SEG6_HMAC(srh) ((srh)->segments + (((srh)->last_segment + 4) >> 1))
#define SEG6_HMAC_MAX_SIZE	64
#define SEG6_HDR_BYTELEN(seglist) (8 + 16*((seglist)->seg_size + 1) + ((seglist)->hmackeyid ? 32 : 0))
#define SEG6_HDR_LEN(seglist) ((SEG6_HDR_BYTELEN(seglist) >> 3) - 1)

#endif
