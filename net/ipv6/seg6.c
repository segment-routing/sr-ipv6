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

static void copy_segments_reverse(struct in6_addr *dst, struct in6_addr *src,
				  int size)
{
	int i;

	for (i = 0; i < size; i++)
		memcpy(&dst[size - i - 1], &src[i], sizeof(struct in6_addr));
}

/* called with rcu_read_lock() */
struct seg6_action *seg6_action_lookup(struct net *net,
				       struct in6_addr *segment)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_action *act;

	list_for_each_entry_rcu(act, &sdata->actions, list) {
		if (memcmp(&act->segment, segment, 16) == 0)
			return act;
	}

	return NULL;
}
EXPORT_SYMBOL(seg6_action_lookup);

static int seg6_action_add(struct net *net, struct seg6_action *act)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	int err = 0;
	struct seg6_action *old_act;

	seg6_pernet_lock(net);
	if ((old_act = seg6_action_lookup(net, &act->segment)) != NULL) {
		if (act->flags & SEG6_BIND_FLAG_OVERRIDE) {
			list_del_rcu(&old_act->list);
		} else {
			err = -EEXIST;
			goto out_unlock;
		}
	}

	list_add_rcu(&act->list, &sdata->actions);
	seg6_pernet_unlock(net);

	if (old_act) {
		synchronize_net();
		if (old_act->data)
			kfree(old_act->data);
		kfree(old_act);
	}

out:
	return err;
out_unlock:
	seg6_pernet_unlock(net);
	goto out;
}

static int seg6_action_del(struct net *net, struct in6_addr *dst)
{
	struct seg6_action *act;
	int err = 0;

	seg6_pernet_lock(net);
	act = seg6_action_lookup(net, dst);
	if (!act) {
		err = -ENOENT;
		goto out_unlock;
	}
	list_del_rcu(&act->list);
	seg6_pernet_unlock(net);

	synchronize_net();
	if (act->data)
		kfree(act->data);
	kfree(act);

out:
	return err;
out_unlock:
	seg6_pernet_unlock(net);
	goto out;
}

static void seg6_action_flush(struct net *net)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_action *act;

	seg6_pernet_lock(net);
	while ((act = list_first_or_null_rcu(&sdata->actions,
					     struct seg6_action,
					     list)) != NULL) {
		list_del_rcu(&act->list);
		seg6_pernet_unlock(net);
		synchronize_net();
		if (act->data)
			kfree(act->data);
		kfree(act);
		seg6_pernet_lock(net);
	}

	seg6_pernet_unlock(net);
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
int seg6_nl_packet_in(struct net *net, struct sk_buff *skb, void *act_data)
{
	struct sk_buff *skb2, *msg;
	struct ipv6_sr_hdr *srhdr;
	struct in6_addr *orig_da;
	void *hdr;
	int rc;
	u32 portid;
	struct sock *dst_sk;

	portid = *(u32 *)act_data;
	dst_sk = *(struct sock **)(act_data + sizeof(u32));

	skb2 = skb_copy(skb, GFP_ATOMIC); /* linearize */
	srhdr = (struct ipv6_sr_hdr *)skb_transport_header(skb2);

	orig_da = srhdr->segments;
	ipv6_hdr(skb2)->daddr = *orig_da;

	skb_push(skb2, skb2->data - skb_network_header(skb2));

//	msg = netlink_alloc_skb(dst_sk, nlmsg_total_size(NLMSG_DEFAULT_SIZE),
//				portid, GFP_ATOMIC);
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_ATOMIC);
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
	int err, hh_len;

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
	fl6.saddr = hdr->saddr;
	fl6.flowlabel = ((hdr->flow_lbl[0] & 0xF) << 16) |
			 (hdr->flow_lbl[1] << 8) | hdr->flow_lbl[2];

	msg->protocol = htons(ETH_P_IPV6);

	if (srhdr->nexthdr == NEXTHDR_IPV6) {
		int offset;

		offset = sizeof(struct ipv6hdr) + ((srhdr->hdrlen + 1) << 3);
		skb_set_inner_protocol(msg, msg->protocol);
		skb_set_inner_network_header(msg, offset);
		offset += sizeof(struct ipv6hdr);
		skb_set_inner_transport_header(msg, offset);
		skb->encapsulation = 1;
	}

	skb_set_transport_header(msg, sizeof(struct ipv6hdr));

	skb_dst_drop(msg);

	if ((unlikely(err = ip6_dst_lookup(net, NULL, &dst, &fl6)))) {
		kfree_skb(msg);
		return err;
	}

	skb_dst_set(msg, dst);
	msg->dev = dst->dev;

	hh_len = LL_RESERVED_SPACE(dst->dev);
	if (skb_headroom(msg) < hh_len &&
	    pskb_expand_head(msg, HH_DATA_ALIGN(hh_len - skb_headroom(msg)),
			     0, GFP_KERNEL)) {
		kfree_skb(msg);
		return -ENOMEM;
	}

	return dst_output(net, NULL, msg);
}

static int seg6_genl_sethmac(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	char *secret;
	u8 hmackeyid;
	u8 algid;
	u8 slen;
	struct seg6_hmac_info *hinfo;
	int err = 0;
	struct seg6_pernet_data *sdata = seg6_pernet(net);

	if (!info->attrs[SEG6_ATTR_HMACKEYID] ||
	    !info->attrs[SEG6_ATTR_SECRETLEN] ||
	    !info->attrs[SEG6_ATTR_ALGID])
		return -EINVAL;

	hmackeyid = nla_get_u8(info->attrs[SEG6_ATTR_HMACKEYID]);
	slen = nla_get_u8(info->attrs[SEG6_ATTR_SECRETLEN]);
	algid = nla_get_u8(info->attrs[SEG6_ATTR_ALGID]);

	if (hmackeyid == 0)
		return -EINVAL;

	if (slen > SEG6_HMAC_SECRET_LEN)
		return -EINVAL;

	seg6_pernet_lock(net);

	hinfo = sdata->hmac_table[hmackeyid];

	if (!slen) {
		if (!hinfo || seg6_hmac_del_info(net, hmackeyid, hinfo)) {
			err = -ENOENT;
		} else {
			kfree(hinfo);
		}
		goto out_unlock;
	}

	if (!info->attrs[SEG6_ATTR_SECRET]) {
		err = -EINVAL;
		goto out_unlock;
	}

	if (hinfo) {
		if (seg6_hmac_del_info(net, hmackeyid, hinfo)) {
			err = -ENOENT;
			goto out_unlock;
		}
		kfree(hinfo);
	}

	secret = (char *)nla_data(info->attrs[SEG6_ATTR_SECRET]);

	hinfo = kzalloc(sizeof(*hinfo), GFP_KERNEL);
	if (!hinfo) {
		err = -ENOMEM;
		goto out_unlock;
	}

	memcpy(hinfo->secret, secret, slen);
	hinfo->slen = slen;
	hinfo->alg_id = algid;

	seg6_hmac_add_info(net, hmackeyid, hinfo);

out_unlock:
	seg6_pernet_unlock(net);
	return err;
}

static int seg6_genl_set_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct in6_addr *val, *t_old, *t_new;

	if (!info->attrs[SEG6_ATTR_DST])
		return -EINVAL;

	val = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);
	t_new = kmemdup(val, sizeof(*val), GFP_KERNEL);

	seg6_pernet_lock(net);

	t_old = sdata->tun_src;
	rcu_assign_pointer(sdata->tun_src, t_new);

	seg6_pernet_unlock(net);

	synchronize_net();
	kfree(t_old);

	return 0;
}

static int seg6_genl_get_tunsrc(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct sk_buff *msg;
	void *hdr;
	struct in6_addr *tun_src;

//	msg = netlink_alloc_skb(info->dst_sk,
//				nlmsg_total_size(NLMSG_DEFAULT_SIZE),
//				info->snd_portid, GFP_KERNEL);
	msg = genlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
	if (!msg)
		return -ENOMEM;

	hdr = genlmsg_put(msg, info->snd_portid, info->snd_seq,
			  &seg6_genl_family, 0, SEG6_CMD_GET_TUNSRC);
	if (!hdr)
		goto free_msg;

	rcu_read_lock();
	tun_src = rcu_dereference(seg6_pernet(net)->tun_src);

	if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr), tun_src))
		goto nla_put_failure;

	rcu_read_unlock();

	genlmsg_end(msg, hdr);
	genlmsg_reply(msg, info);

	return 0;

nla_put_failure:
	rcu_read_unlock();
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

	rcu_read_lock();
	for (i = 0; i < 255; i++) {
		if (i < cb->args[0])
			continue;

		hinfo = rcu_dereference(seg6_pernet(net)->hmac_table[i]);
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
	rcu_read_unlock();

	cb->args[0] = i;
	return skb->len;
}

static int seg6_genl_addbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *dst;
	struct seg6_action *act;
	int op, datalen, err = 0;

	if (!info->attrs[SEG6_ATTR_DST] || !info->attrs[SEG6_ATTR_BIND_OP])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);
	op = nla_get_u8(info->attrs[SEG6_ATTR_BIND_OP]);

	if (!info->attrs[SEG6_ATTR_BIND_DATA] ||
	    !info->attrs[SEG6_ATTR_BIND_DATALEN])
		return -EINVAL;

	act = kzalloc(sizeof(*act), GFP_KERNEL);
	if (!act)
		return -ENOMEM;

	act->op = op;

	if (info->attrs[SEG6_ATTR_FLAGS])
		act->flags = nla_get_u32(info->attrs[SEG6_ATTR_FLAGS]);

	if (op == SEG6_BIND_SERVICE) {
		return -ENOSYS;
#if 0
		act->data = kzalloc(sizeof(u32) + sizeof(struct sock *),
				    GFP_KERNEL);
		if (!act->data) {
			kfree(act);
			return -ENOMEM;
		}
		*(u32 *)act->data = info->snd_portid;
		act->datalen = sizeof(u32) + sizeof(struct sock *);
		*(struct sock **)(act->data + sizeof(u32)) = info->dst_sk;
#endif
	} else {
		datalen = nla_get_s32(info->attrs[SEG6_ATTR_BIND_DATALEN]);
		act->data = kzalloc(datalen, GFP_KERNEL);
		if (!act->data) {
			kfree(act);
			return -ENOMEM;
		}
		act->datalen = datalen;
		memcpy(act->data, nla_data(info->attrs[SEG6_ATTR_BIND_DATA]),
		       datalen);
	}

	memcpy(&act->segment, dst, 16);

	if (unlikely((err = seg6_action_add(net, act)) < 0))
		goto out_free;

out:
	return err;
out_free:
	if (act->data)
		kfree(act->data);
	kfree(act);
	goto out;
}

static int seg6_genl_delbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);
	struct in6_addr *dst;

	if (!info->attrs[SEG6_ATTR_DST])
		return -EINVAL;

	dst = (struct in6_addr *)nla_data(info->attrs[SEG6_ATTR_DST]);

	return seg6_action_del(net, dst);
}

static int seg6_genl_flushbind(struct sk_buff *skb, struct genl_info *info)
{
	struct net *net = genl_info_net(info);

	seg6_action_flush(net);

	return 0;
}

static int __seg6_bind_fill_info(struct seg6_action *act,
				 struct sk_buff *msg)
{
	if (nla_put(msg, SEG6_ATTR_DST, sizeof(struct in6_addr),
		    &act->segment) ||
	    nla_put(msg, SEG6_ATTR_BIND_DATA, act->datalen, act->data) ||
	    nla_put_s32(msg, SEG6_ATTR_BIND_DATALEN, act->datalen) ||
	    nla_put_u8(msg, SEG6_ATTR_BIND_OP, act->op))
		return -1;

	return 0;
}

static int __seg6_genl_dumpbind_element(struct seg6_action *act, u32 portid,
					u32 seq, u32 flags, struct sk_buff *skb,
					u8 cmd)
{
	void *hdr;

	hdr = genlmsg_put(skb, portid, seq, &seg6_genl_family, flags, cmd);
	if (!hdr)
		return -ENOMEM;

	if (__seg6_bind_fill_info(act, skb) < 0)
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
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_action *act;
	int idx = 0, ret;

	rcu_read_lock();

	list_for_each_entry_rcu(act, &sdata->actions, list) {
		if (idx++ < cb->args[0])
			continue;

		ret = __seg6_genl_dumpbind_element(act,
						   NETLINK_CB(cb->skb).portid,
						   cb->nlh->nlmsg_seq,
						   NLM_F_MULTI, skb,
						   SEG6_CMD_DUMPBIND);
		if (ret)
			break;
	}

	rcu_read_unlock();

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

static struct ctl_table seg6_table[] = {
	{
		.procname	= "srh_reversal",
		.data		= &seg6_srh_reversal,
		.maxlen		= sizeof(int),
		.mode		= 0644,
		.proc_handler	= &proc_dointvec
	},
	{ }
};

static struct ctl_table_header *seg6_table_hdr;

static int __net_init seg6_net_init(struct net *net)
{
	struct seg6_pernet_data *sdata;

	net->ipv6.seg6_data = kzalloc(sizeof(struct seg6_pernet_data),
				      GFP_KERNEL);

	sdata = seg6_pernet(net);
	if (!sdata)
		return -ENOMEM;

	spin_lock_init(&sdata->lock);

	sdata->tun_src = kzalloc(sizeof(struct in6_addr), GFP_KERNEL);

	INIT_LIST_HEAD(&sdata->actions);

	return 0;
}

static void __net_exit seg6_net_exit(struct net *net)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	int i;

	seg6_action_flush(net);

	for (i = 0; i < SEG6_HMAC_MAX_KEY; i++) {
		if (sdata->hmac_table[i])
			kfree(sdata->hmac_table[i]);
	}

	kfree(sdata->tun_src);
	kfree(seg6_pernet(net));
}

static struct pernet_operations ip6_segments_ops = {
	.init = seg6_net_init,
	.exit = seg6_net_exit,
};

int __init seg6_init(void)
{
	int err = -ENOMEM;

#ifdef CONFIG_SYSCTL
	seg6_table_hdr = register_net_sysctl(&init_net, "net/seg6", seg6_table);
	if (!seg6_table_hdr)
		goto out;
#endif
	err = genl_register_family_with_ops(&seg6_genl_family, seg6_genl_ops);
	if (err)
		goto out_unregister_sysctl;
	err = register_pernet_subsys(&ip6_segments_ops);
	if (err)
		goto out_unregister_genl;
	err = seg6_hmac_init();
	if (err)
		goto out_unregister_pernet;

	pr_info("SR-IPv6: Release v%d.%d\n", SEG6_VERSION_MAJOR,
		SEG6_VERSION_MINOR);
out:
	return err;
out_unregister_pernet:
	unregister_pernet_subsys(&ip6_segments_ops);
out_unregister_genl:
	genl_unregister_family(&seg6_genl_family);
out_unregister_sysctl:
#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(seg6_table_hdr);
#endif
	goto out;
}

void __exit seg6_exit(void)
{
	seg6_hmac_exit();
	unregister_pernet_subsys(&ip6_segments_ops);
	genl_unregister_family(&seg6_genl_family);
#ifdef CONFIG_SYSCTL
	unregister_net_sysctl_table(seg6_table_hdr);
#endif
}
