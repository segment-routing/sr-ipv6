/*
 *  SR-IPv6 implementation
 *
 *  Author:
 *  David Lebrun <david.lebrun@uclouvain.be>
 *
 *
 *  This program is free software; you can redistribute it and/or
 *	  modify it under the terms of the GNU General Public License
 *	  as published by the Free Software Foundation; either version
 *	  2 of the License, or (at your option) any later version.
 */

#include <linux/errno.h>
#include <linux/types.h>
#include <linux/socket.h>
#include <linux/sockios.h>
#include <linux/net.h>
#include <linux/netdevice.h>
#include <linux/in6.h>
#include <linux/icmpv6.h>
#include <linux/mroute6.h>
#include <linux/slab.h>

#include <linux/netfilter.h>
#include <linux/netfilter_ipv6.h>

#include <net/sock.h>
#include <net/snmp.h>

#include <net/ipv6.h>
#include <net/protocol.h>
#include <net/transp_v6.h>
#include <net/rawv6.h>
#include <net/ndisc.h>
#include <net/ip6_route.h>
#include <net/addrconf.h>
#include <net/xfrm.h>

#include <linux/cryptohash.h>
#include <crypto/hash.h>
#include <crypto/sha.h>
#include <net/seg6.h>
#include <net/genetlink.h>
#include <net/seg6_table.h>
#include <net/seg6_hmac.h>
#include <linux/random.h>

int seg6_srh_reversal = 0;
int seg6_hmac_strict_key = 0;

static inline void copy_segments_reverse(struct in6_addr *dst, struct in6_addr *src, int size)
{
	int i;

	for (i = 0; i < size; i++)
		memcpy(&dst[size - i - 1], &src[i], sizeof(struct in6_addr));
}

struct seg6_bib_node *seg6_bib_lookup(struct net *net, struct in6_addr *segment)
{
	struct seg6_bib_node *tmp;

	for (tmp = net->ipv6.seg6_bib_head; tmp; tmp = tmp->next) {
		if (memcmp(&tmp->segment, segment, 16) == 0)
			return tmp;
	}

	return NULL;
}

int seg6_bib_insert(struct net *net, struct seg6_bib_node *bib)
{
	struct seg6_bib_node *tmp;

	if (net->ipv6.seg6_bib_head == NULL) {
		net->ipv6.seg6_bib_head = bib;
		return 0;
	}

	for (tmp = net->ipv6.seg6_bib_head; tmp; tmp = tmp->next) {
		if (memcmp(&tmp->segment, &bib->segment, 16) == 0)
			return -EEXIST;

		if (tmp->next == NULL) {
			tmp->next = bib;
			break;
		}
	}

	return 0;
}

int seg6_bib_remove(struct net *net, struct in6_addr *addr)
{
	struct seg6_bib_node *tmp, *prev = NULL;

	for (tmp = net->ipv6.seg6_bib_head; tmp; tmp = tmp->next) {
		if (memcmp(&tmp->segment, addr, 16) == 0) {
			if (prev)
				prev->next = tmp->next;
			else
				net->ipv6.seg6_bib_head = tmp->next;
			return 1;
		}
		prev = tmp;
	}

	return 0;
}

struct seg6_info *seg6_segment_lookup(struct net *net, struct in6_addr *dst)
{
	struct seg6_info *info;
	struct s6ib_node *node;

	node = seg6_route_lookup(net->ipv6.seg6_fib_root, dst);
	if (!node || !node->s6info)
		return NULL;

	info = node->s6info;

	if (info->list_size == 0)
		return NULL;

	return info;
}
EXPORT_SYMBOL(seg6_segment_lookup);

struct seg6_list *seg6_pick_segments(struct seg6_info *info)
{
	int i, id;
	struct seg6_list *list_node;

	/* should never happen */
	if (info->list_size == 0) {
		printk(KERN_DEBUG "SR-IPv6: warning: info->list_size == 0 in seg6_pick_segments() for dst %pI6\n", &info->dst);
		return NULL;
	}

	id = prandom_u32()%info->list_size;
	list_node = info->list;
	for (i = 0; i < id; i++)
		list_node = list_node->next;

	return list_node;
}
EXPORT_SYMBOL(seg6_pick_segments);

struct seg6_list *seg6_get_segments(struct net *net, struct in6_addr *dst)
{
	struct seg6_info *seg_info;
	struct seg6_list *segments;

	seg_info = seg6_segment_lookup(net, dst);

	if (seg_info == NULL)
		return 0;

	segments = seg6_pick_segments(seg_info);

	return segments;
}
EXPORT_SYMBOL(seg6_get_segments);

/*
 * Build 1:1 SRH without adding lasthop / removing first hop
 */
void seg6_build_tmpl_srh(struct seg6_list *segments, struct ipv6_sr_hdr *srh)
{
	int flags = 0;

	srh->hdrlen = SEG6_HDR_LEN(segments);
	srh->type = IPV6_SRCRT_TYPE_4;
	srh->segments_left = segments->seg_size;
	srh->first_segment = segments->seg_size;

	if (segments->cleanup)
		flags |= SR6_FLAG_CLEANUP;
	if (segments->tunnel)
		flags |= SR6_FLAG_TUNNEL;

	sr_set_flags(srh, flags);

	if (segments->hmackeyid)
		sr_set_hmac_key_id(srh, segments->hmackeyid);

	/*
	 * The number of segments allocated for @srh is segments->seg_size + 1
	 * as defined in macro SEG6_HDR_BYTELEN. This is explained by the fact that
	 * @segments contains only the intermediate segments, without the last segment
	 * (i.e. the original destination).
	 * This allows us to already place the first segment at the end of the list
	 * as required by the specifications, so that we can track who is the first
	 * segment.
	 */

	copy_segments_reverse(srh->segments + 1, segments->segments, segments->seg_size);

	/* This will be the DA, let's fill with magic val in the meantime */
	memset(srh->segments, 0x42, sizeof(struct in6_addr));
}
EXPORT_SYMBOL(seg6_build_tmpl_srh);

void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from, struct ipv6_sr_hdr *hdr_to, int reverse)
{
	int seg_size;

	hdr_to->hdrlen = hdr_from->first_segment*2 + 4;
	hdr_to->type = IPV6_SRCRT_TYPE_4;
	hdr_to->first_segment = hdr_from->first_segment;

	seg_size = SEG6_SRH_SEGSIZE(hdr_from);
	if (reverse)
		copy_segments_reverse(hdr_to->segments + 1, hdr_from->segments + 1, seg_size - 1);
	else
		memcpy(hdr_to->segments + 1, hdr_from->segments + 1, (seg_size - 1)*sizeof(struct in6_addr));

	memset(hdr_to->segments, 0x42, sizeof(struct in6_addr));
}

int __seg6_process_skb(struct net *net, struct sk_buff *skb, struct seg6_list *segments)
{
	struct ipv6hdr *hdr;
	int srhlen, tot_len;
	struct ipv6_sr_hdr *srh;
	int flags = 0;

	srhlen = SEG6_HDR_BYTELEN(segments);
	tot_len = srhlen + (segments->tunnel ? sizeof(struct ipv6hdr) : 0);

	if (pskb_expand_head(skb, tot_len, 0, GFP_ATOMIC)) {
		printk(KERN_DEBUG "SR6: seg6_process_skb: cannot expand head\n");
		return -1;
	}

	/*
	 * Move the IPv6 header up to let place for the SRH and, if in tunnel mode,
	 * the inner IPv6 header.
	 */
	memmove(skb_network_header(skb) - tot_len, skb_network_header(skb), sizeof(struct ipv6hdr));

	/* update offsets and pointers */
	skb_push(skb, tot_len);
	skb->network_header -= tot_len;
	hdr = ipv6_hdr(skb);
	srh = (void *)hdr + sizeof(struct ipv6hdr);

	skb->transport_header = skb->network_header + sizeof(struct ipv6hdr);

	memset(srh, 0, tot_len);

	/*
	 * If we are in tunnel mode, the header next to the SRH is the original
	 * IPv6 header
	 */
	if (segments->tunnel)
		srh->nexthdr = NEXTHDR_IPV6;
	else
		srh->nexthdr = hdr->nexthdr;

	hdr->nexthdr = NEXTHDR_ROUTING;
	hdr->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	srh->hdrlen = SEG6_HDR_LEN(segments);
	srh->type = IPV6_SRCRT_TYPE_4;
	srh->segments_left = segments->seg_size;
	srh->first_segment = segments->seg_size;

	if (segments->cleanup)
		flags |= SR6_FLAG_CLEANUP;
	if (segments->tunnel)
		flags |= SR6_FLAG_TUNNEL;

	sr_set_flags(srh, flags);

	copy_segments_reverse(srh->segments + 1, segments->segments, segments->seg_size);
	srh->segments[0] = hdr->daddr;

	hdr->daddr = segments->segments[0];

	if (segments->tunnel)
		ipv6_dev_get_saddr(net, skb->dev, &hdr->daddr, IPV6_PREFER_SRC_PUBLIC, &hdr->saddr);

	if (segments->hmackeyid) {
		char *key;
		int keylen;
		struct seg6_hmac_info *hinfo;

		hinfo = net->ipv6.seg6_hmac_table[segments->hmackeyid];
		key = hinfo ? hinfo->secret : seg6_hmac_key;
		keylen = hinfo ? hinfo->slen : strlen(seg6_hmac_key);

		sr_set_hmac_key_id(srh, segments->hmackeyid);
		memset(SEG6_HMAC(srh), 0, 32);

		sr_hmac_sha1(key, keylen, srh, &hdr->saddr, (u32*)SEG6_HMAC(srh));
	}

	return 0;
}

/*
 * Push SRH in matching forwarded packets
 */
int seg6_process_skb(struct net *net, struct sk_buff *skb)
{
	struct ipv6hdr *hdr;
	struct seg6_info *seg_info;
	struct seg6_list *segments;

	hdr = ipv6_hdr(skb);

	/* TODO add sysctl */
	if (hdr->nexthdr == NEXTHDR_ROUTING)
		return 0;

	seg_info = seg6_segment_lookup(net, &hdr->daddr);

	if (seg_info == NULL)
		return 0;

	segments = seg6_pick_segments(seg_info);

	if (__seg6_process_skb(net, skb, segments) < 0)
		return 0;

	return 1;
}
EXPORT_SYMBOL(seg6_process_skb);

static void __seg6_flush_segment(struct seg6_info *info)
{
	struct seg6_list *list;

	while (info->list != NULL) {
		list = info->list->next;
		kfree(info->list->segments);
		kfree(info->list);
		info->list_size--;
		info->list = list;
	}
}

static int __seg6_remove_id(struct seg6_info *info, u16 id)
{
	struct seg6_list *list, *plist;
	int found = 0;

	plist = list = info->list;
	while (list != NULL) {
		if (list->id == id) {
			if (list == info->list)
				info->list = list->next;
			else
				plist->next = list->next;
			kfree(list->segments);
			kfree(list);
			info->list_size--;
			found = 1;
			break;
		}
		plist = list;
		list = list->next;
	}

	return found ? 0 : 1;
}

void seg6_flush_segments(struct net *net)
{
	struct seg6_info *s6info;
	struct hlist_node *itmp;
	int i;

	for (i = 0; i < 4096; i++) {
		hlist_for_each_entry_safe(s6info, itmp, &net->ipv6.seg6_hash[i], seg_chain) {
			__seg6_flush_segment(s6info);
			hlist_del_rcu(&s6info->seg_chain);
			seg6_route_delete(net->ipv6.seg6_fib_root, &s6info->dst, s6info->dst_len);
			kfree(s6info);
		}
	}
}
EXPORT_SYMBOL(seg6_flush_segments);

static struct ctl_table seg6_table[] = {
	{
		.procname 	= "hmac_key",
		.data 		= seg6_hmac_key,
		.maxlen		= SEG6_HMAC_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname 	= "srh_reversal",
		.data		= &seg6_srh_reversal,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{
		.procname	= "hmac_strict_key",
		.data		= &seg6_hmac_strict_key,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ }
};

void __net_init seg6_init_sysctl(void)
{
	register_net_sysctl(&init_net, "net/seg6", seg6_table);
}

enum {
	SEG6_ATTR_UNSPEC,
	SEG6_ATTR_DST,
	SEG6_ATTR_DSTLEN,
	SEG6_ATTR_SEGLISTID,
	SEG6_ATTR_FLAGS,
	SEG6_ATTR_HMACKEYID,
	SEG6_ATTR_SEGMENTS,
	SEG6_ATTR_SEGLEN,
	SEG6_ATTR_SEGINFO,
	SEG6_ATTR_SECRET,
	SEG6_ATTR_SECRETLEN,
	SEG6_ATTR_ALGID,
	SEG6_ATTR_HMACINFO,
	SEG6_ATTR_BIND_OP,
	SEG6_ATTR_BIND_DATA,
	SEG6_ATTR_BIND_DATALEN,
	SEG6_ATTR_BINDINFO,
	SEG6_ATTR_PACKET_DATA,
	SEG6_ATTR_PACKET_LEN,
	__SEG6_ATTR_MAX,
};

#define SEG6_ATTR_MAX (__SEG6_ATTR_MAX - 1)

static struct nla_policy seg6_genl_policy[SEG6_ATTR_MAX + 1] = {
	[SEG6_ATTR_DST] 			= { .type = NLA_BINARY, .len = sizeof(struct in6_addr) },
	[SEG6_ATTR_DSTLEN]			= { .type = NLA_S32, },
	[SEG6_ATTR_SEGLISTID] 		= { .type = NLA_U16, },
	[SEG6_ATTR_FLAGS] 			= { .type = NLA_U32, },
	[SEG6_ATTR_HMACKEYID] 		= { .type = NLA_U8, },
	[SEG6_ATTR_SEGMENTS] 		= { .type = NLA_BINARY, },
	[SEG6_ATTR_SEGLEN] 			= { .type = NLA_S32, },
	[SEG6_ATTR_SEGINFO]			= { .type = NLA_NESTED, },
	[SEG6_ATTR_SECRET]			= { .type = NLA_BINARY, },
	[SEG6_ATTR_SECRETLEN]		= { .type = NLA_U8, },
	[SEG6_ATTR_ALGID]			= { .type = NLA_U8, },
	[SEG6_ATTR_HMACINFO]		= { .type = NLA_NESTED, },
	[SEG6_ATTR_BIND_OP]			= { .type = NLA_U8, },
	[SEG6_ATTR_BIND_DATA]		= { .type = NLA_BINARY, },
	[SEG6_ATTR_BIND_DATALEN]	= { .type = NLA_S32, },
	[SEG6_ATTR_BINDINFO]		= {	.type = NLA_NESTED, },
	[SEG6_ATTR_PACKET_DATA]		= { .type = NLA_BINARY, },
	[SEG6_ATTR_PACKET_LEN]		= { .type = NLA_S32, },
};

static struct genl_family seg6_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = "SEG6",
	.version = 1,
	.maxattr = SEG6_ATTR_MAX,
	.netnsok = true,
};

enum {
	SEG6_CMD_UNSPEC,
	SEG6_CMD_ADDSEG,
	SEG6_CMD_DELSEG,
	SEG6_CMD_FLUSH,
	SEG6_CMD_DUMP,
	SEG6_CMD_SETHMAC,
	SEG6_CMD_DUMPHMAC,
	SEG6_CMD_ADDBIND,
	SEG6_CMD_DELBIND,
	SEG6_CMD_FLUSHBIND,
	SEG6_CMD_DUMPBIND,
	SEG6_CMD_PACKET_IN,
	SEG6_CMD_PACKET_OUT,
	__SEG6_CMD_MAX,
};

#define SEG6_CMD_MAX (__SEG6_CMD_MAX - 1)

/*
 * @skb's SRH has undergone segleft dec
 * Currently, tunnel mode is not supported
 *
 * We need to change DA to orig DA. When packet will be received in PACKET_OUT,
 * then we just need to overwrite DA to active seg.
 * SRH is not stripped, userland just has to follow header chain until transport
 * is reached.
 *
 * /!\ We are in atomic context.
 *
 */
int seg6_nl_packet_in(struct net *net, struct sk_buff *skb, void *bib_data)
{
	struct sk_buff *skb2, *msg;
	struct ipv6_sr_hdr *srhdr;
	struct in6_addr *orig_da;
	void *hdr;
	int rc;
	u32 portid;
	struct sock *dst_sk;

	portid = *(u32 *)bib_data;
	dst_sk = *(struct sock **)(bib_data + sizeof(u32));

	skb2 = skb_copy(skb, GFP_ATOMIC); /* linearize */
	srhdr = (struct ipv6_sr_hdr *)skb_transport_header(skb2);

	orig_da = srhdr->segments;
	ipv6_hdr(skb2)->daddr = *orig_da;

	skb_push(skb2, skb2->data - skb_network_header(skb2));

	msg = netlink_alloc_skb(dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE), portid, GFP_ATOMIC);
	if (!msg)
		goto err;

	hdr = genlmsg_put(msg, 0, 0, &seg6_genl_family, 0, SEG6_CMD_PACKET_IN);
	if (!hdr)
		goto err_free;

	if (nla_put(msg, SEG6_ATTR_PACKET_DATA, skb2->len, skb_network_header(skb2)))
		goto nla_put_failure;

	if (nla_put_s32(msg, SEG6_ATTR_PACKET_LEN, skb2->len))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);

	rc = genlmsg_unicast(net, msg, portid);

	kfree_skb(skb2);
	return rc;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
err_free:
	nlmsg_free(msg);
err:
	kfree_skb(skb2);
	return -ENOMEM;
}

static int seg6_genl_packet_out(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct sk_buff *msg;
	char *data;
	int len;
	struct ipv6_sr_hdr *srhdr;
	struct ipv6hdr *hdr;
	struct in6_addr *active_addr;
	struct dst_entry *dst;
	struct flowi6 fl6;

	if (!info->attrs[SEG6_ATTR_PACKET_DATA] || !info->attrs[SEG6_ATTR_PACKET_LEN])
		return -EINVAL;

	len = nla_get_s32(info->attrs[SEG6_ATTR_PACKET_LEN]);
	data = (char *)nla_data(info->attrs[SEG6_ATTR_PACKET_DATA]);

	msg = alloc_skb(len, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	skb_put(msg, len);
	skb_reset_network_header(msg);
	skb_reset_transport_header(msg);

	memcpy(msg->data, data, len);

	hdr = ipv6_hdr(msg);

	if (hdr->nexthdr != NEXTHDR_ROUTING) {
		kfree_skb(msg);
		return -EINVAL;
	}

	srhdr = (struct ipv6_sr_hdr *)(hdr + 1);

	active_addr = srhdr->segments + srhdr->segments_left;
	hdr->daddr = *active_addr;

	memset(&fl6, 0, sizeof(fl6));
	fl6.daddr = hdr->daddr;
	fl6.flowlabel = ((hdr->flow_lbl[0] & 0xF) << 16) |
						(hdr->flow_lbl[1] << 8) | hdr->flow_lbl[2];
	dst = ip6_route_output(net, NULL, &fl6);
	if (dst->error) {
		dst_release(dst);
		kfree_skb(msg);
		return -EINVAL;
	}
	skb_dst_drop(msg);
	skb_dst_set(msg, dst);
	msg->dev = dst->dev;
	msg->protocol = htons(ETH_P_IPV6);

	return dst_input(msg);
}

static int seg6_genl_addseg(struct sk_buff *skb, struct genl_info *info)
{
	struct seg6_info *s6info;
	struct seg6_list *tmp;
	int found = 0;
	struct in6_addr *dst;
	int dst_len, seg_len;
	unsigned int flags;
	u16 seglist_id;
	struct s6ib_node *node;
	struct net *net = genl_info_net(info);

	if (!info->attrs[SEG6_ATTR_DST] || !info->attrs[SEG6_ATTR_DSTLEN] || !info->attrs[SEG6_ATTR_SEGLISTID] ||
		!info->attrs[SEG6_ATTR_FLAGS] || !info->attrs[SEG6_ATTR_HMACKEYID] || !info->attrs[SEG6_ATTR_SEGMENTS] ||
		!info->attrs[SEG6_ATTR_SEGLEN])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);
	dst_len = nla_get_s32(info->attrs[SEG6_ATTR_DSTLEN]);
	seglist_id = nla_get_u16(info->attrs[SEG6_ATTR_SEGLISTID]);
	seg_len = nla_get_s32(info->attrs[SEG6_ATTR_SEGLEN]);
	flags = nla_get_u32(info->attrs[SEG6_ATTR_FLAGS]);

	hlist_for_each_entry_rcu(s6info, &net->ipv6.seg6_hash[seg6_hashfn(dst)], seg_chain) {
		if (memcmp(s6info->dst.s6_addr, dst->s6_addr, 16) == 0 && s6info->dst_len == dst_len) {
			found = 1;
			break;
		}
	}

	if (!found) {
		s6info = kzalloc(sizeof(*s6info), GFP_KERNEL);
		if (!s6info)
			return -ENOMEM;

		memcpy(s6info->dst.s6_addr, dst->s6_addr, 16);
		s6info->dst_len = dst_len;

		node = seg6_route_insert(net->ipv6.seg6_fib_root, s6info);
		if (IS_ERR(node)) {
			kfree(s6info);
			return PTR_ERR(node);
		}
		hlist_add_head_rcu(&s6info->seg_chain, &net->ipv6.seg6_hash[seg6_hashfn(dst)]);
	} else {
		for (tmp = s6info->list; tmp; tmp = tmp->next) {
			if (tmp->id == seglist_id)
				return -EEXIST;
		}
	}

	tmp = kzalloc(sizeof(struct seg6_list), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp->id = seglist_id;
	tmp->seg_size = seg_len;
	tmp->cleanup = (flags & SR6_FLAG_CLEANUP) ? 1 : 0;
	tmp->tunnel = (flags & SR6_FLAG_TUNNEL) ? 1 : 0;
	tmp->hmackeyid = nla_get_u8(info->attrs[SEG6_ATTR_HMACKEYID]);
	tmp->segments = kmalloc(seg_len*sizeof(struct in6_addr), GFP_KERNEL);
	if (!tmp->segments) {
		kfree(tmp);
		return -ENOMEM;
	}

	memcpy(tmp->segments, nla_data(info->attrs[SEG6_ATTR_SEGMENTS]), seg_len*sizeof(struct in6_addr));

	tmp->next = s6info->list;
	s6info->list = tmp;
	s6info->list_size++;

	return 0;
}

static int seg6_genl_delseg(struct sk_buff *skb, struct genl_info *info)
{
	struct seg6_info *s6info;
	int found = 0;
	struct in6_addr *dst;
	int dst_len;
	u16 seglist_id;
	struct net *net = genl_info_net(info);

	if (!info->attrs[SEG6_ATTR_DST] || !info->attrs[SEG6_ATTR_DSTLEN] || !info->attrs[SEG6_ATTR_SEGLISTID])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);
	dst_len = nla_get_s32(info->attrs[SEG6_ATTR_DSTLEN]);
	seglist_id = nla_get_u16(info->attrs[SEG6_ATTR_SEGLISTID]);

	hlist_for_each_entry_rcu(s6info, &net->ipv6.seg6_hash[seg6_hashfn(dst)], seg_chain) {
		if (memcmp(s6info->dst.s6_addr, dst->s6_addr, 16) == 0 && s6info->dst_len == dst_len) {
			found = 1;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	if (seglist_id == (u16)-1) {
		__seg6_flush_segment(s6info);
	} else {
		if (__seg6_remove_id(s6info, seglist_id))
			return -ENOENT;
	}

	if (s6info->list_size == 0) {
		hlist_del_rcu(&s6info->seg_chain);
		seg6_route_delete(net->ipv6.seg6_fib_root, dst, dst_len);
		kfree(s6info);
	}

	return 0;
}

static int seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	char *secret;
	u8 hmackeyid;
	u8 algid;
	u8 slen;
	struct seg6_hmac_info *hinfo;

	if (!info->attrs[SEG6_ATTR_HMACKEYID] || !info->attrs[SEG6_ATTR_SECRETLEN] || !info->attrs[SEG6_ATTR_ALGID])
		return -EINVAL;

	hmackeyid = nla_get_u8(info->attrs[SEG6_ATTR_HMACKEYID]);
	slen = nla_get_u8(info->attrs[SEG6_ATTR_SECRETLEN]);
	algid = nla_get_u8(info->attrs[SEG6_ATTR_ALGID]);

	if (hmackeyid == 0)
		return -EINVAL;

	hinfo = net->ipv6.seg6_hmac_table[hmackeyid];

	if (!slen) {
		if (!hinfo)
			return -ENOENT;
		kfree(hinfo);
		net->ipv6.seg6_hmac_table[hmackeyid] = NULL;
		return 0;
	}

	if (!info->attrs[SEG6_ATTR_SECRET])
		return -EINVAL;

	secret = (char *)nla_data(info->attrs[SEG6_ATTR_SECRET]);

	if (!hinfo)
		hinfo = kzalloc(sizeof(*hinfo), GFP_KERNEL);

	if (!hinfo)
		return -ENOMEM;

	memcpy(hinfo->secret, secret, slen);
	hinfo->slen = slen;
	hinfo->alg_id = algid;

	net->ipv6.seg6_hmac_table[hmackeyid] = hinfo;

	return 0;
}

static int seg6_genl_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);

	seg6_flush_segments(net);

	return 0;
}

static int seg6_genl_dump(struct sk_buff *skb, struct genl_info *info)
{
	struct seg6_info *s6info;
	struct seg6_list *list;
	int i;
	struct sk_buff *msg;
	void *hdr;
	struct nlattr *nla;
	struct net *net = genl_info_net(info);

	for (i = 0; i < 4096; i++) {
		hlist_for_each_entry_rcu(s6info, &net->ipv6.seg6_hash[i], seg_chain) {
			list = s6info->list;
			while (list != NULL) {
				msg = netlink_alloc_skb(info->dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE), info->snd_portid, GFP_KERNEL);
				if (!msg)
					return -ENOMEM;

				hdr = genlmsg_put(msg, 0, 0, &seg6_genl_family, 0, SEG6_CMD_DUMP);
				if (!hdr)
					goto free_msg;

				nla = nla_nest_start(msg, SEG6_ATTR_SEGINFO);
				if (!nla)
					goto nla_put_failure;

				if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &s6info->dst))
					goto nla_put_failure;

				if (nla_put_s32(msg, SEG6_ATTR_DSTLEN, s6info->dst_len))
					goto nla_put_failure;

				if (nla_put_u16(msg, SEG6_ATTR_SEGLISTID, list->id))
					goto nla_put_failure;

				if (nla_put_s32(msg, SEG6_ATTR_SEGLEN, list->seg_size))
					goto nla_put_failure;

				if (nla_put_u32(msg, SEG6_ATTR_FLAGS, ((list->cleanup & 0x1) << 3) | ((list->tunnel & 0x1) << 1)))
					goto nla_put_failure;

				if (nla_put_u8(msg, SEG6_ATTR_HMACKEYID, list->hmackeyid))
					goto nla_put_failure;

				if (nla_put(msg, SEG6_ATTR_SEGMENTS, list->seg_size*sizeof(struct in6_addr), list->segments))
					goto nla_put_failure;

				nla_nest_end(msg, nla);
				genlmsg_end(msg, hdr);
				genlmsg_reply(msg, info);

				list = list->next;
			}
		}
	}

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return -ENOMEM;
}

static int seg6_genl_dumphmac(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct nlattr *nla;
	struct net *net = genl_info_net(info);
	struct seg6_hmac_info *hinfo;
	int i;
	void *hdr;

	for (i = 0; i < 255; i++) {
		hinfo = net->ipv6.seg6_hmac_table[i];
		if (hinfo == NULL)
			continue;

		msg = netlink_alloc_skb(info->dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE), info->snd_portid, GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		hdr = genlmsg_put(msg, 0, 0, &seg6_genl_family, 0, SEG6_CMD_DUMPHMAC);
		if (!hdr)
			goto free_msg;

		nla = nla_nest_start(msg, SEG6_ATTR_HMACINFO);
		if (!nla)
			goto nla_put_failure;

		if (nla_put_u8(msg, SEG6_ATTR_HMACKEYID, i))
			goto nla_put_failure;

		if (nla_put_u8(msg, SEG6_ATTR_SECRETLEN, hinfo->slen))
			goto nla_put_failure;

		if (nla_put(msg, SEG6_ATTR_SECRET, hinfo->slen, hinfo->secret))
			goto nla_put_failure;

		if (nla_put_u8(msg, SEG6_ATTR_ALGID, hinfo->alg_id))
			goto nla_put_failure;

		nla_nest_end(msg, nla);
		genlmsg_end(msg, hdr);
		genlmsg_reply(msg, info);
	}

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return -ENOMEM;
}

static int seg6_genl_addbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *dst;
	struct seg6_bib_node *bib;
	int err, op, datalen;

	if (!info->attrs[SEG6_ATTR_DST] || !info->attrs[SEG6_ATTR_BIND_OP])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);
	op = nla_get_u8(info->attrs[SEG6_ATTR_BIND_OP]);

	if (!info->attrs[SEG6_ATTR_BIND_DATA] || !info->attrs[SEG6_ATTR_BIND_DATALEN])
		return -EINVAL;

	bib = kzalloc(sizeof(*bib), GFP_KERNEL);
	if (!bib)
		return -ENOMEM;

	bib->op = op;

	if (info->attrs[SEG6_ATTR_FLAGS])
		bib->flags = nla_get_u32(info->attrs[SEG6_ATTR_FLAGS]);

	if (op == SEG6_BIND_SERVICE) {
		bib->data = kzalloc(sizeof(u32)+sizeof(struct sock *), GFP_KERNEL);
		if (!bib->data) {
			kfree(bib);
			return -ENOMEM;
		}
		*(u32 *)bib->data = info->snd_portid;
		bib->datalen = sizeof(u32)+sizeof(struct sock *);
		*(struct sock **)(bib->data + sizeof(u32)) = info->dst_sk;
	} else {
		datalen = nla_get_s32(info->attrs[SEG6_ATTR_BIND_DATALEN]);
		bib->data = kzalloc(datalen, GFP_KERNEL);
		if (!bib->data) {
			kfree(bib);
			return -ENOMEM;
		}
		bib->datalen = datalen;
		memcpy(bib->data, nla_data(info->attrs[SEG6_ATTR_BIND_DATA]), datalen);
	}

	memcpy(&bib->segment, dst, 16);

	err = seg6_bib_insert(net, bib);

	return err;
}

static int seg6_genl_delbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *dst;
	struct seg6_bib_node *bib;

	if (!info->attrs[SEG6_ATTR_DST])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);

	bib = seg6_bib_lookup(net, dst);
	if (!bib)
		return -ENOENT;

	seg6_bib_remove(net, &bib->segment);
	kfree(bib);

	return 0;
}

static int seg6_genl_flushbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct seg6_bib_node *bib;

	while ((bib = net->ipv6.seg6_bib_head)) {
		net->ipv6.seg6_bib_head = bib->next;
		kfree(bib);
	}

	return 0;
}

static int seg6_genl_dumpbind(struct sk_buff *skb, struct genl_info *info)
{
	struct sk_buff *msg;
	struct nlattr *nla;
	struct net *net = genl_info_net(info);
	void *hdr;
	struct seg6_bib_node *bib;

	for (bib = net->ipv6.seg6_bib_head; bib; bib = bib->next) {
		msg = netlink_alloc_skb(info->dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE), info->snd_portid, GFP_KERNEL);
		if (!msg)
			return -ENOMEM;

		hdr = genlmsg_put(msg, 0, 0, &seg6_genl_family, 0, SEG6_CMD_DUMPBIND);
		if (!hdr)
			goto free_msg;

		nla = nla_nest_start(msg, SEG6_ATTR_BINDINFO);
		if (!nla)
			goto nla_put_failure;

		if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), &bib->segment))
			goto nla_put_failure;

		if (nla_put(msg, SEG6_ATTR_BIND_DATA, bib->datalen, bib->data))
			goto nla_put_failure;

		if (nla_put_s32(msg, SEG6_ATTR_BIND_DATALEN, bib->datalen))
			goto nla_put_failure;

		if (nla_put_u8(msg, SEG6_ATTR_BIND_OP, bib->op))
			goto nla_put_failure;

		nla_nest_end(msg, nla);
		genlmsg_end(msg, hdr);
		genlmsg_reply(msg, info);
	}

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return -ENOMEM;
}

static struct genl_ops seg6_genl_ops[] = {
	{
		.cmd 	= SEG6_CMD_ADDSEG,
		.doit 	= seg6_genl_addseg,
		.policy = seg6_genl_policy,
		.flags 	= GENL_ADMIN_PERM,
	},
	{
		.cmd 	= SEG6_CMD_DELSEG,
		.doit 	= seg6_genl_delseg,
		.policy	= seg6_genl_policy,
		.flags 	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_FLUSH,
		.doit 	= seg6_genl_flush,
		.policy	= seg6_genl_policy,
		.flags 	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_DUMP,
		.doit	= seg6_genl_dump,
		.policy	= seg6_genl_policy,
		.flags	= 0,
	},
	{
		.cmd	= SEG6_CMD_SETHMAC,
		.doit	= seg6_genl_sethmac,
		.policy = seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd 	= SEG6_CMD_DUMPHMAC,
		.doit	= seg6_genl_dumphmac,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd 	= SEG6_CMD_ADDBIND,
		.doit	= seg6_genl_addbind,
		.policy = seg6_genl_policy,
		.flags 	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_DELBIND,
		.doit	= seg6_genl_delbind,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_FLUSHBIND,
		.doit	= seg6_genl_flushbind,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_DUMPBIND,
		.doit	= seg6_genl_dumpbind,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_PACKET_OUT,
		.doit	= seg6_genl_packet_out,
		.policy = seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
};

void __net_init seg6_nl_init(void)
{
	genl_register_family_with_ops(&seg6_genl_family, seg6_genl_ops);
}
