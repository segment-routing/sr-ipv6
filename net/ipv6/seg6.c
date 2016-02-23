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
#include <net/seg6_hmac.h>
#include <linux/seg6.h>
#include <linux/random.h>
#include <linux/seg6_genl.h>

int seg6_srh_reversal;
int seg6_hmac_strict_key;
int seg6_enabled = 1;

static void copy_segments_reverse(struct in6_addr *dst, struct in6_addr *src,
				  int size)
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

	if (!net->ipv6.seg6_bib_head) {
		net->ipv6.seg6_bib_head = bib;
		return 0;
	}

	for (tmp = net->ipv6.seg6_bib_head; tmp; tmp = tmp->next) {
		if (memcmp(&tmp->segment, &bib->segment, 16) == 0)
			return -EEXIST;

		if (!tmp->next) {
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

void seg6_srh_to_tmpl(struct ipv6_sr_hdr *hdr_from, struct ipv6_sr_hdr *hdr_to,
		      int reverse)
{
	int seg_size;

	hdr_to->hdrlen = hdr_from->first_segment * 2 + 4;
	hdr_to->type = IPV6_SRCRT_TYPE_4;
	hdr_to->first_segment = hdr_from->first_segment;

	seg_size = SEG6_SRH_SEGSIZE(hdr_from);
	if (reverse)
		copy_segments_reverse(hdr_to->segments + 1,
				      hdr_from->segments + 1,
				      seg_size - 1);
	else
		memcpy(hdr_to->segments + 1, hdr_from->segments + 1,
		       (seg_size - 1) * sizeof(struct in6_addr));

	memset(hdr_to->segments, 0x42, sizeof(struct in6_addr));
}

static struct ctl_table seg6_table[] = {
	{
		.procname	= "hmac_key",
		.data		= seg6_hmac_key,
		.maxlen		= SEG6_HMAC_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
	},
	{
		.procname	= "srh_reversal",
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
	{
		.procname	= "enabled",
		.data		= &seg6_enabled,
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

static struct nla_policy seg6_genl_policy[SEG6_ATTR_MAX + 1] = {
	[SEG6_ATTR_DST]				= { .type = NLA_BINARY,
		.len = sizeof(struct in6_addr) },
	[SEG6_ATTR_DSTLEN]			= { .type = NLA_S32, },
	[SEG6_ATTR_SEGLISTID]		= { .type = NLA_U16, },
	[SEG6_ATTR_FLAGS]			= { .type = NLA_U32, },
	[SEG6_ATTR_HMACKEYID]		= { .type = NLA_U8, },
	[SEG6_ATTR_SEGMENTS]		= { .type = NLA_BINARY, },
	[SEG6_ATTR_SEGLEN]			= { .type = NLA_S32, },
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
	[SEG6_ATTR_POLICY_DATA]		= { .type = NLA_BINARY, },
	[SEG6_ATTR_POLICY_LEN]		= { .type = NLA_S32, },
};

static struct genl_family seg6_genl_family = {
	.id = GENL_ID_GENERATE,
	.hdrsize = 0,
	.name = SEG6_GENL_NAME,
	.version = SEG6_GENL_VERSION,
	.maxattr = SEG6_ATTR_MAX,
	.netnsok = true,
};

 /* @skb's SRH has undergone segleft dec
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

	msg = netlink_alloc_skb(dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE),
				portid, GFP_ATOMIC);
	if (!msg)
		goto err;

	hdr = genlmsg_put(msg, 0, 0, &seg6_genl_family, 0, SEG6_CMD_PACKET_IN);
	if (!hdr)
		goto err_free;

	if (nla_put(msg, SEG6_ATTR_PACKET_DATA, skb2->len,
		    skb_network_header(skb2)))
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

	if (!info->attrs[SEG6_ATTR_PACKET_DATA] ||
	    !info->attrs[SEG6_ATTR_PACKET_LEN])
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

static int seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	char *secret;
	u8 hmackeyid;
	u8 algid;
	u8 slen;
	struct seg6_hmac_info *hinfo;

	if (!info->attrs[SEG6_ATTR_HMACKEYID] ||
	    !info->attrs[SEG6_ATTR_SECRETLEN] ||
	    !info->attrs[SEG6_ATTR_ALGID])
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

static int seg6_genl_set_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *tunsrc;

	if (!info->attrs[SEG6_ATTR_DST])
		return -EINVAL;

	tunsrc = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);

	memcpy(&net->ipv6.seg6_tun_src, tunsrc, sizeof(struct in6_addr));

	return 0;
}

static int seg6_genl_get_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct sk_buff *msg;
	void *hdr;

	msg = netlink_alloc_skb(info->dst_sk,
				nlmsg_total_size(NLMSG_DEFAULT_SIZE),
				info->snd_portid, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &seg6_genl_family, 0, SEG6_CMD_GET_TUNSRC);
	if (!hdr)
		goto free_msg;

	if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr),
		    &net->ipv6.seg6_tun_src))
		goto nla_put_failure;

	genlmsg_end(msg, hdr);
	genlmsg_reply(msg, info);

	return 0;

nla_put_failure:
	genlmsg_cancel(msg, hdr);
free_msg:
	nlmsg_free(msg);
	return -ENOMEM;
}

static int __seg6_hmac_fill_info(int keyid, struct seg6_hmac_info *hinfo,
				 struct sk_buff *msg)
{
	if (nla_put_u8(msg, SEG6_ATTR_HMACKEYID, keyid) ||
	    nla_put_u8(msg, SEG6_ATTR_SECRETLEN, hinfo->slen) ||
	    nla_put(msg, SEG6_ATTR_SECRET, hinfo->slen, hinfo->secret) ||
	    nla_put_u8(msg, SEG6_ATTR_ALGID, hinfo->alg_id))
		return -1;

	return 0;
}

static int __seg6_genl_dumphmac_element(int keyid, struct seg6_hmac_info *hinfo,
					u32 portid, u32 seq, u32 flags,
					struct sk_buff *skb, u8 cmd)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &seg6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	if (__seg6_hmac_fill_info(keyid, hinfo, skb) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int seg6_genl_dumphmac(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct seg6_hmac_info *hinfo;
	int i, ret;

	for (i = 0; i < 255; i++) {
		if (i < cb->args[0])
			continue;

		hinfo = net->ipv6.seg6_hmac_table[i];
		if (!hinfo)
			continue;

		ret = __seg6_genl_dumphmac_element(i, hinfo,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI,
						   skb, SEG6_CMD_DUMPHMAC);
		if (ret)
			break;
	}

	cb->args[0] = i;
	return skb->len;
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

	if (!info->attrs[SEG6_ATTR_BIND_DATA] ||
	    !info->attrs[SEG6_ATTR_BIND_DATALEN])
		return -EINVAL;

	bib = kzalloc(sizeof(*bib), GFP_KERNEL);
	if (!bib)
		return -ENOMEM;

	bib->op = op;

	if (info->attrs[SEG6_ATTR_FLAGS])
		bib->flags = nla_get_u32(info->attrs[SEG6_ATTR_FLAGS]);

	if (op == SEG6_BIND_SERVICE) {
		bib->data = kzalloc(sizeof(u32) + sizeof(struct sock *),
				    GFP_KERNEL);
		if (!bib->data) {
			kfree(bib);
			return -ENOMEM;
		}
		*(u32 *)bib->data = info->snd_portid;
		bib->datalen = sizeof(u32) + sizeof(struct sock *);
		*(struct sock **)(bib->data + sizeof(u32)) = info->dst_sk;
	} else {
		datalen = nla_get_s32(info->attrs[SEG6_ATTR_BIND_DATALEN]);
		bib->data = kzalloc(datalen, GFP_KERNEL);
		if (!bib->data) {
			kfree(bib);
			return -ENOMEM;
		}
		bib->datalen = datalen;
		memcpy(bib->data, nla_data(info->attrs[SEG6_ATTR_BIND_DATA]),
		       datalen);
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

static int __seg6_bind_fill_info(struct seg6_bib_node *bib,
				 struct sk_buff *msg)
{
	if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr),
		    &bib->segment) ||
	    nla_put(msg, SEG6_ATTR_BIND_DATA, bib->datalen, bib->data) ||
	    nla_put_s32(msg, SEG6_ATTR_BIND_DATALEN, bib->datalen) ||
	    nla_put_u8(msg, SEG6_ATTR_BIND_OP, bib->op))
		return -1;

	return 0;
}

static int __seg6_genl_dumpbind_element(struct seg6_bib_node *bib, u32 portid,
					u32 seq, u32 flags, struct sk_buff *skb,
					u8 cmd)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &seg6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	if (__seg6_bind_fill_info(bib, skb) < 0)
		goto nla_put_failure;

	genlmsg_end(skb, hdr);
	return 0;

nla_put_failure:
	genlmsg_cancel(skb, hdr);
	return -EMSGSIZE;
}

static int seg6_genl_dumpbind(struct sk_buff *skb, struct netlink_callback *cb)
{
	struct net *net = sock_net(skb->sk);
	struct seg6_bib_node *bib;
	int idx = 0, ret;

	for (bib = net->ipv6.seg6_bib_head; bib; bib = bib->next) {
		if (idx++ < cb->args[0])
			continue;

		ret = __seg6_genl_dumpbind_element(bib,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI, skb,
						   SEG6_CMD_DUMPBIND);
		if (ret)
			break;
	}

	cb->args[0] = idx;
	return skb->len;
}

static struct genl_ops seg6_genl_ops[] = {
	{
		.cmd	= SEG6_CMD_SETHMAC,
		.doit	= seg6_genl_sethmac,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_DUMPHMAC,
		.dumpit	= seg6_genl_dumphmac,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_ADDBIND,
		.doit	= seg6_genl_addbind,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
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
		.dumpit	= seg6_genl_dumpbind,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_PACKET_OUT,
		.doit	= seg6_genl_packet_out,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_SET_TUNSRC,
		.doit	= seg6_genl_set_tunsrc,
		.policy	= seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
	{
		.cmd	= SEG6_CMD_GET_TUNSRC,
		.doit 	= seg6_genl_get_tunsrc,
		.policy = seg6_genl_policy,
		.flags	= GENL_ADMIN_PERM,
	},
};

void __net_init seg6_nl_init(void)
{
	genl_register_family_with_ops(&seg6_genl_family, seg6_genl_ops);
}
