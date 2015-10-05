/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *      modify it under the terms of the GNU General Public License
 *      as published by the Free Software Foundation; either version
 *      2 of the License, or (at your option) any later version.
 */

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

struct seg6_list {
	struct seg6_list *next;
	struct in6_addr *segments;
	int seg_size;
	int cleanup;
	int tunnel;
	u16 id;
	u8 hmackeyid;
};

struct seg6_info {
	struct in6_addr dst;
	int dst_len;

	int list_size;
	struct seg6_list *list;

	struct hlist_node seg_chain;
};

/* Binding-SID Information Base */
#define SEG6_BIND_NEXT		0	/* aka no-op, classical sr processing */
#define SEG6_BIND_ROUTE		1	/* force route through given next hop */
#define SEG6_BIND_INSERT	2	/* push segments in srh */
#define SEG6_BIND_TRANSLATE	3	/* translate source/dst ? */
#define SEG6_BIND_SERVICE	4	/* send packet to virtual service */

#define SEG6_BIND_FLAG_ASYM	0x01

struct seg6_bib_node {
	struct seg6_bib_node *next;
	struct in6_addr segment;

	int op;
	void *data;
	int datalen;
	u32 flags;
	/*
	 * NEXT: 		NULL
	 * ROUTE: 		struct in6_addr *
	 * INSERT:		<todo>
	 * TRANSLATE:	<todo>
	 * SERVICE:		u32 *
	 */
};

extern void seg6_flush_segments(struct net *net);
extern int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr, struct in6_addr *saddr, u32 *output);
extern int __seg6_process_skb(struct net *net, struct sk_buff *skb, struct seg6_list *segments);
extern int seg6_process_skb(struct net *net, struct sk_buff *skb);
extern struct seg6_list *seg6_get_segments(struct net *net, struct in6_addr *dst);
extern void seg6_build_tmpl_srh(struct seg6_list *segments, struct ipv6_sr_hdr *srh);
extern void seg6_init_sysctl(void);
extern void seg6_nl_init(void);
extern void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from, struct ipv6_sr_hdr *hdr_to, int reverse);
extern struct seg6_bib_node *seg6_bib_lookup(struct net *net, struct in6_addr *segment);
extern int seg6_bib_remove(struct net *net, struct in6_addr *addr);
extern int seg6_nl_packet_in(struct net *net, struct sk_buff *skb, void *bib_data);

extern int seg6_srh_reversal;
extern int seg6_hmac_strict_key;

#define SEG6_HDR_BYTELEN(seglist) (8 + 16*((seglist)->seg_size + 1) + ((seglist)->hmackeyid ? 32 : 0))
#define SEG6_HDR_LEN(seglist) ((SEG6_HDR_BYTELEN(seglist) >> 3) - 1)

#define SEG6_SRH_SEGSIZE(srh) ((srh)->first_segment + 1)

#endif
