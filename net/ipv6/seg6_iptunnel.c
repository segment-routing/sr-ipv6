/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *        modify it under the terms of the GNU General Public License
 *        as published by the Free Software Foundation; either version
 *        2 of the License, or (at your option) any later version.
 */

#include <linux/types.h>
#include <linux/skbuff.h>
#include <linux/net.h>
#include <linux/module.h>
#include <linux/mpls.h>
#include <linux/vmalloc.h>
#include <net/ip.h>
#include <net/dst.h>
#include <net/lwtunnel.h>
#include <net/netevent.h>
#include <net/netns/generic.h>
#include <net/ip6_fib.h>
#include <net/route.h>
#include <net/seg6.h>
#include <net/seg6_hmac.h>
#include <linux/seg6.h>
#include <linux/seg6_iptunnel.h>
#include <net/addrconf.h>
#include <net/ip6_route.h>

static const struct nla_policy seg6_iptunnel_policy[SEG6_IPTUNNEL_MAX + 1] = {
	[SEG6_IPTUNNEL_SRH]	= { .type = NLA_BINARY },
};

/* utility functions */
int nla_put_srh(struct sk_buff *skb, int attrtype,
		struct seg6_iptunnel_encap *tuninfo)
{
	struct nlattr *nla;
	struct seg6_iptunnel_encap *data;
	int len;

	len = SEG6_IPTUN_ENCAP_SIZE(tuninfo);

	nla = nla_reserve(skb, attrtype, len);
	if (!nla)
		return -EMSGSIZE;

	data = nla_data(nla);
	memcpy(data, tuninfo, len);

	return 0;
}
/* -- */

static void __set_tun_src(struct net *net, struct net_device *dev,
			  struct in6_addr *daddr, struct in6_addr *saddr)
{
	struct in6_addr *tun_src;
	struct seg6_pernet_data *sdata = seg6_pernet(net);

	rcu_read_lock();

	tun_src = rcu_dereference(sdata->tun_src);

	if (!ipv6_addr_any(tun_src)) {
		memcpy(saddr, tun_src, sizeof(struct in6_addr));
	} else {
		ipv6_dev_get_saddr(net, dev, daddr, IPV6_PREFER_SRC_PUBLIC,
				   saddr);
	}

	rcu_read_unlock();
}

static int seg6_do_srh_encap(struct sk_buff *skb, struct ipv6_sr_hdr *osrh)
{
	struct ipv6hdr *hdr, *inner_hdr;
	struct ipv6_sr_hdr *isrh;
	struct net *net = dev_net(skb_dst(skb)->dev);
	int hdrlen, tot_len, err;

	hdrlen = (osrh->hdrlen + 1) << 3;
	tot_len = hdrlen + sizeof(*hdr);

	/* TODO test skb_cow_head */
	if (unlikely((err = pskb_expand_head(skb, tot_len, 0, GFP_ATOMIC)))) {
		pr_debug("sr-ipv6: seg6_do_srh_encap: cannot expand head\n");
		return err;
	}

	inner_hdr = ipv6_hdr(skb);

	skb_push(skb, tot_len);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);
	hdr = ipv6_hdr(skb);

	/* inherit tc, flowlabel and hlim
	 * hlim will be decremented in ip6_forward() afterwards and
	 * decapsulation will overwrite inner hlim with outer hlim
	 */
	ip6_flow_hdr(hdr, ip6_tclass(ip6_flowinfo(inner_hdr)),
		     ip6_flowlabel(inner_hdr));
	hdr->hop_limit = inner_hdr->hop_limit;
	hdr->nexthdr = NEXTHDR_ROUTING;

	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, osrh, hdrlen);

	/* still needs to fill nexthdr field */
	isrh->nexthdr = NEXTHDR_IPV6;

	hdr->daddr = isrh->segments[isrh->first_segment];
	__set_tun_src(net, skb->dev, &hdr->daddr, &hdr->saddr);

	if (sr_get_flags(isrh) & SR6_FLAG_HMAC) {
		if (unlikely((err = seg6_push_hmac(net, &hdr->saddr, isrh))))
			return err;
	}

	return 0;
}

static int seg6_do_srh_inline(struct sk_buff *skb, struct ipv6_sr_hdr *osrh)
{
	struct ipv6hdr *hdr, *oldhdr;
	struct ipv6_sr_hdr *isrh;
	struct net *net = dev_net(skb_dst(skb)->dev);
	int hdrlen, err;

	hdrlen = (osrh->hdrlen + 1) << 3;

	/* TODO test skb_cow_head */
	if (unlikely((err = pskb_expand_head(skb, hdrlen, 0, GFP_ATOMIC)))) {
		pr_debug("sr-ipv6: seg6_do_srh_inline: cannot expand head\n");
		return err;
	}

	oldhdr = ipv6_hdr(skb);

	skb_push(skb, hdrlen);
	skb_reset_network_header(skb);
	skb_mac_header_rebuild(skb);

	hdr = ipv6_hdr(skb);

	memmove(hdr, oldhdr, sizeof(*hdr));

	isrh = (void *)hdr + sizeof(*hdr);
	memcpy(isrh, osrh, hdrlen);

	isrh->nexthdr = hdr->nexthdr;
	hdr->nexthdr = NEXTHDR_ROUTING;

	isrh->segments[0] = hdr->daddr;
	hdr->daddr = isrh->segments[isrh->first_segment];

	if (sr_get_flags(isrh) & SR6_FLAG_HMAC) {
		if (unlikely((err = seg6_push_hmac(net, &hdr->saddr, isrh))))
			return err;
	}

	return 0;
}


static int seg6_do_srh(struct sk_buff *skb)
{
	struct dst_entry *dst = skb_dst(skb);
	struct seg6_iptunnel_encap *tinfo = seg6_lwtunnel_encap(dst->lwtstate);
	int err = 0;

	if (likely(!skb->encapsulation)) {
		skb_reset_inner_headers(skb);
		skb->encapsulation = 1;
	}

	if (tinfo->flags & SEG6_IPTUN_FLAG_ENCAP) {
		err = seg6_do_srh_encap(skb, tinfo->srh);
	} else {
		err = seg6_do_srh_inline(skb, tinfo->srh);
		skb_reset_inner_headers(skb);
	}

	if (err)
		return err;

	ipv6_hdr(skb)->payload_len = htons(skb->len - sizeof(struct ipv6hdr));
	skb_set_transport_header(skb, sizeof(struct ipv6hdr));

	skb_set_inner_protocol(skb, skb->protocol);

	return 0;
}

int seg6_input(struct sk_buff *skb)
{
	int err;

	if ((unlikely(err = seg6_do_srh(skb))))
		return err;

	skb_dst_drop(skb);
	ip6_route_input(skb);

	return dst_input(skb);
}

int seg6_output(struct net *net, struct sock *sk, struct sk_buff *skb)
{
	int err;
	struct dst_entry *dst;
	struct ipv6hdr *hdr;
	struct flowi6 fl6;

	if ((unlikely(err = seg6_do_srh(skb))))
		return err;

	hdr = ipv6_hdr(skb);
	fl6.daddr = hdr->daddr;
	fl6.saddr = hdr->saddr;
	fl6.flowlabel = ip6_flowinfo(hdr);
	fl6.flowi6_mark = skb->mark;
	fl6.flowi6_proto = hdr->nexthdr;

	ip6_route_set_l4flow(skb, &fl6);

	skb_dst_drop(skb);

	if ((unlikely(err = ip6_dst_lookup(net, sk, &dst, &fl6))))
		return err;

	skb_dst_set(skb, dst);

	return dst_output(net, sk, skb);
}

static int seg6_build_state(struct net_device *dev, struct nlattr *nla,
			    unsigned int family, const void *cfg,
			    struct lwtunnel_state **ts)
{
	struct seg6_iptunnel_encap *tuninfo, *tuninfo_new;
	struct nlattr *tb[SEG6_IPTUNNEL_MAX + 1];
	struct lwtunnel_state *newts;
	int tuninfo_len;
	int err;

	err = nla_parse_nested(tb, SEG6_IPTUNNEL_MAX, nla,
			       seg6_iptunnel_policy);

	if (err < 0)
		return err;

	if (!tb[SEG6_IPTUNNEL_SRH])
		return -EINVAL;

	tuninfo = nla_data(tb[SEG6_IPTUNNEL_SRH]);
	tuninfo_len = SEG6_IPTUN_ENCAP_SIZE(tuninfo);

	newts = lwtunnel_state_alloc(tuninfo_len);
	if (!newts)
		return -ENOMEM;

	newts->len = tuninfo_len;
	tuninfo_new = seg6_lwtunnel_encap(newts);
	memcpy(tuninfo_new, tuninfo, tuninfo_len);

	newts->type = LWTUNNEL_ENCAP_SEG6;
	newts->flags |= LWTUNNEL_STATE_OUTPUT_REDIRECT |
			LWTUNNEL_STATE_INPUT_REDIRECT;

	*ts = newts;

	return 0;
}

static int seg6_fill_encap_info(struct sk_buff *skb,
				struct lwtunnel_state *lwtstate)
{
	struct seg6_iptunnel_encap *tuninfo = seg6_lwtunnel_encap(lwtstate);

	if (nla_put_srh(skb, SEG6_IPTUNNEL_SRH, tuninfo))
		return -EMSGSIZE;

	return 0;
}

static int seg6_encap_nlsize(struct lwtunnel_state *lwtstate)
{
	struct seg6_iptunnel_encap *tuninfo = seg6_lwtunnel_encap(lwtstate);

	return nla_total_size(SEG6_IPTUN_ENCAP_SIZE(tuninfo));
}

static int seg6_encap_cmp(struct lwtunnel_state *a, struct lwtunnel_state *b)
{
	struct seg6_iptunnel_encap *a_hdr = seg6_lwtunnel_encap(a);
	struct seg6_iptunnel_encap *b_hdr = seg6_lwtunnel_encap(b);
	int len = SEG6_IPTUN_ENCAP_SIZE(a_hdr);

	if (len != SEG6_IPTUN_ENCAP_SIZE(b_hdr))
		return 1;

	return memcmp(a_hdr, b_hdr, len);
}

static const struct lwtunnel_encap_ops seg6_iptun_ops = {
	.build_state = seg6_build_state,
	.output = seg6_output,
	.input = seg6_input,
	.fill_encap = seg6_fill_encap_info,
	.get_encap_size = seg6_encap_nlsize,
	.cmp_encap = seg6_encap_cmp,
};

static int __init seg6_iptunnel_init(void)
{
	return lwtunnel_encap_add_ops(&seg6_iptun_ops, LWTUNNEL_ENCAP_SEG6);
}
module_init(seg6_iptunnel_init);

static void __exit seg6_iptunnel_exit(void)
{
	lwtunnel_encap_del_ops(&seg6_iptun_ops, LWTUNNEL_ENCAP_SEG6);
}
module_exit(seg6_iptunnel_exit);

MODULE_DESCRIPTION("Segment Routing with IPv6 IP Tunnels");
MODULE_LICENSE("GPL v2");
