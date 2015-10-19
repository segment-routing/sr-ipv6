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

/* flags <= 0xf reserved for SRH */
#define SR6_FLAG_EGRESS_PRESENT 0x10

struct seg6_policy {
	unsigned int flags;
	struct in6_addr entry;
};

struct seg6_list {
	struct seg6_list *next;
	struct in6_addr *segments;
	int seg_size;
	unsigned int flags;
	u16 id;
	u8 hmackeyid;
	struct seg6_policy pol[4];
};

#define SEG6_POL_FLAGS(seg, idx) ((seg)->pol[(idx)].flags)
#define SEG6_POL_ENTRY(seg, idx) (&((seg)->pol[(idx)].entry))
#define SEG6_POL_PRESENT(seg, idx) (SEG6_POL_FLAGS(seg, idx) > 0)
#define SEG6_SRH_POL_SIZE(srh) ((sr_get_flag_p1(srh) > 0) + (sr_get_flag_p2(srh) > 0) + (sr_get_flag_p3(srh) > 0) + (sr_get_flag_p4(srh) > 0))
#define SEG6_SRH_POL_ENTRY(srh, idx) ((srh)->segments + SEG6_SRH_SEGSIZE(srh) + idx)

static inline int seg6_pol_size(struct seg6_list *seg)
{
	int i, cnt = 0;

	for (i = 0; i < 4; i++)
		cnt += SEG6_POL_PRESENT(seg, i);

	return cnt;
}

static inline int seg6_pol_valid(struct seg6_list *seg)
{
	int i, gap = 0;

	for (i = 0; i < 4; i++)
		if (!SEG6_POL_PRESENT(seg, i))
			gap = 1;
		else if (gap)
			return 0;

	return 1;
}

struct seg6_info {
	struct in6_addr dst;
	int dst_len;

	int list_size;
	struct seg6_list *list;

	struct hlist_node seg_chain;
};

/* Binding-SID Information Base */
#define SEG6_BIND_NEXT			0	/* aka no-op, classical sr processing */
#define SEG6_BIND_ROUTE 		1	/* force route through given next hop */
#define SEG6_BIND_INSERT		2	/* push segments in srh */
#define SEG6_BIND_TRANSLATE		3	/* translate source/dst ? */
#define SEG6_BIND_SERVICE		4	/* send packet to virtual service */
#define SEG6_BIND_OVERRIDE_NEXT	5	/* override next segment (break HMAC) */

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
extern void seg6_init_sysctl(void);
extern void seg6_nl_init(void);
extern void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from, struct ipv6_sr_hdr *hdr_to, int reverse);
extern struct seg6_bib_node *seg6_bib_lookup(struct net *net, struct in6_addr *segment);
extern int seg6_bib_remove(struct net *net, struct in6_addr *addr);
extern int seg6_nl_packet_in(struct net *net, struct sk_buff *skb, void *bib_data);

extern int seg6_srh_reversal;
extern int seg6_hmac_strict_key;

#define SEG6_HDR_BYTELEN(seglist) (8 + 16*((seglist)->seg_size) + ((seglist)->hmackeyid ? 32 : 0) + 16*seg6_pol_size(seglist))
#define SEG6_HDR_LEN(seglist) ((SEG6_HDR_BYTELEN(seglist) >> 3) - 1)

#define SEG6_SRH_SEGSIZE(srh) ((srh)->first_segment + 1)

static inline int __prepare_mod_skb(struct net *net, struct sk_buff *skb)
{
	if (skb_cloned(skb)) {
		if (pskb_expand_head(skb, 0, 0, GFP_ATOMIC)) {
			IP6_INC_STATS_BH(net, ip6_dst_idev(skb_dst(skb)),
					IPSTATS_MIB_OUTDISCARDS);
			kfree_skb(skb);
			return -1;
		}
	}
	if (skb->ip_summed == CHECKSUM_COMPLETE)
		skb->ip_summed = CHECKSUM_NONE;

	return 0;
}

#endif
