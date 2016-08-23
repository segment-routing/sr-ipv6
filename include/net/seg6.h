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

#define SEG6_VERSION_MAJOR	0
#define SEG6_VERSION_MINOR	22

extern int __init seg6_init(void);

extern void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from,
			struct ipv6_sr_hdr *hdr_to, int reverse);

extern struct seg6_action *seg6_action_lookup(struct net *net,
					      struct in6_addr *segment);

extern int seg6_nl_packet_in(struct net *net, struct sk_buff *skb,
			void *act_data);
extern struct sr6_tlv_hmac *seg6_get_tlv_hmac(struct ipv6_sr_hdr *srh);
extern void *seg6_get_tlv(struct ipv6_sr_hdr *srh, int type);

#define SEG6_SRH_SEGSIZE(srh) ((srh)->first_segment + 1)
#define SEG6_TLVS(s) ((s)->segments+SEG6_SRH_SEGSIZE(s))

struct seg6_action {
	struct list_head list;

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
	spinlock_t lock;
	struct list_head hmac_infos;
	struct list_head actions;
	struct in6_addr __rcu *tun_src;
};

extern int seg6_srh_reversal;

static inline struct seg6_iptunnel_encap *seg6_lwtunnel_encap(struct lwtunnel_state *lwtstate)
{
	return (struct seg6_iptunnel_encap *)lwtstate->data;
}

static inline struct seg6_pernet_data *seg6_pernet(struct net *net)
{
	return net->ipv6.seg6_data;
}

static inline void seg6_pernet_lock(struct net *net)
{
	spin_lock(&seg6_pernet(net)->lock);
}

static inline void seg6_pernet_unlock(struct net *net)
{
	spin_unlock(&seg6_pernet(net)->lock);
}

#endif
