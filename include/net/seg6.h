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
#include <linux/seg6.h>
#include <net/lwtunnel.h>
#include <net/seg6_hmac.h>

struct seg6_info;

extern int __init seg6_init(void);

extern void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from,
			struct ipv6_sr_hdr *hdr_to, int reverse);

extern struct seg6_bib_node *seg6_bib_lookup(struct net *net,
			struct in6_addr *segment);

extern int seg6_bib_remove(struct net *net, struct in6_addr *addr);
extern int seg6_nl_packet_in(struct net *net, struct sk_buff *skb,
			void *bib_data);

#define SEG6_SRH_SEGSIZE(srh) ((srh)->first_segment + 1)

struct seg6_bib_node {
	struct seg6_bib_node *next;
	struct in6_addr segment;

	int op;
	void *data;
	int datalen;
	u32 flags;
	/* NEXT:		NULL
	 * ROUTE:		struct in6_addr *
	 * INSERT:		<todo>
	 * TRANSLATE:	<todo>
	 * SERVICE:		u32 *
	 */
};

struct seg6_pernet_data {
	struct seg6_hmac_info __rcu *hmac_table[SEG6_MAX_HMAC_KEY];
	struct seg6_bib_node *bib_head;
	struct in6_addr tun_src;
};

extern int seg6_srh_reversal;
extern int seg6_hmac_strict_key;

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

static inline struct seg6_iptunnel_encap *seg6_lwtunnel_encap(struct lwtunnel_state *lwtstate)
{
	return (struct seg6_iptunnel_encap *)lwtstate->data;
}

static inline struct seg6_pernet_data *seg6_pernet(struct net *net)
{
	return net->ipv6.seg6_data;
}

#endif
