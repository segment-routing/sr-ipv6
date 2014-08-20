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

char seg6_hmac_key[SEG6_HMAC_MAX_SIZE] = "secret";

static void sr_sha1(u8 *message, u32 len, u32 *hash_out)
{
	u32 workspace[SHA_WORKSPACE_WORDS];
	u32 padlen;
	char *pptr;
	int i;
	__be64 bits;

	memset(workspace, 0, sizeof(workspace));

	if (len % 64 != 0)
		padlen = 64 - (len%64);
	else
		padlen = 0;

	char plaintext[len+padlen];
	memset(plaintext, 0, len+padlen);
	memcpy(plaintext, message, len);

	pptr = plaintext+len;

	if (padlen) {
		bits = cpu_to_be64(len << 3);
		memcpy(pptr + padlen - sizeof(bits), (const u8 *)&bits, sizeof(bits));
		*pptr = 0x80;
	}

	sha_init(hash_out);

	for (i = 0; i < len+padlen; i += 64)
		sha_transform(hash_out, plaintext+i, workspace);

	for (i = 0; i < 5; i++)
		hash_out[i] = cpu_to_be32(hash_out[i]);

	memset(workspace, 0, sizeof(workspace));
}

int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr, struct in6_addr *saddr, u32 *output)
{
	unsigned int plen;
	struct in6_addr *addr;
	int i;
	char *pptr;
	u8 i_pad[64], o_pad[64];
	u8 realkey[64];
	u32 hash_out[5];
	u8 outer_msg[84]; // 20 (hash) + 64 (o_pad)

	if (!ksize)
		return -EINVAL;

	plen = 16 + 1 + 1 + 1 + (hdr->last_segment+2)*8;

	u8 inner_msg[64+plen];
	pptr = inner_msg+64;

	memset(pptr, 0, plen);

	memcpy(pptr, saddr->s6_addr, 16);
	pptr += 16;
	*pptr++ = hdr->last_segment;
	*pptr++ = (sr_get_flags(hdr) & 0x8) << 4;
	*pptr++ = sr_get_hmac_key_id(hdr);

	for (i = 0; i < hdr->last_segment + 2; i += 2) {
		addr = hdr->segments + (i >> 1);
		memcpy(pptr, addr->s6_addr, 16);
		pptr += 16;
	}

	memset(realkey, 0, 64);
	memset(hash_out, 0, 20);

	if (ksize > 64) {
		sr_sha1(key, ksize, hash_out);
		memcpy(realkey, hash_out, 20);
		memset(hash_out, 0, 20);
	} else {
		memcpy(realkey, key, ksize);
	}

	memset(i_pad, 0x36, 64);
	memset(o_pad, 0x5c, 64);

	for (i = 0; i < 64; i++) {
		i_pad[i] ^= realkey[i];
		o_pad[i] ^= realkey[i];
	}

	memcpy(inner_msg, i_pad, 64);
	sr_sha1(inner_msg, 64+plen, hash_out);

	memcpy(outer_msg, o_pad, 64);
	memcpy(outer_msg+64, hash_out, 20);

	sr_sha1(outer_msg, 84, output);

	return 0;
}
EXPORT_SYMBOL(sr_hmac_sha1);

struct seg6_list *seg6_get_segments(struct net *net, struct in6_addr *dst)
{
	struct seg6_info *info;
	struct s6ib_node *node;
	struct seg6_list *list_node;
	int i, id;

	node = seg6_route_lookup(net->ipv6.seg6_fib_root, dst);
	if (!node || !node->s6info)
		return NULL;

	info = node->s6info;

	if (info->list_size == 0)
		return NULL;

	id = net_random()%info->list_size;
	list_node = info->list;
	for (i = 0; i < id; i++)
		list_node = list_node->next;

	return list_node;
}
EXPORT_SYMBOL(seg6_get_segments);

/*
 * Build 1:1 SRH without adding lasthop / removing first hop
 */
void seg6_build_tmpl_srh(struct seg6_list *segments, struct ipv6_sr_hdr *srh)
{
	srh->hdrlen = SEG6_HDR_LEN(segments);
	srh->type = IPV6_SRCRT_TYPE_4;
	srh->next_segment = 0;
	srh->last_segment = (segments->seg_size - 1) << 1;
	srh->f1 = 0;
	srh->f2 = 0;
	srh->f3 = 0;
	if (segments->cleanup)
		sr_set_flags(srh, 0x8);
	if (segments->hmackeyid)
		sr_set_hmac_key_id(srh, segments->hmackeyid);

	memcpy(srh->segments, segments->segments, (segments->seg_size)*sizeof(struct in6_addr));
	srh->segments[segments->seg_size] = segments->segments[0];
}
EXPORT_SYMBOL(seg6_build_tmpl_srh);

/*
 * Push SRH in matching forwarded packets
 */
int seg6_process_skb(struct net *net, struct sk_buff **skb_in)
{
	struct ipv6hdr *hdr;
	struct sk_buff *skb;
	struct seg6_list *segments;
	int srhlen, tot_len;
	struct ipv6_sr_hdr *srh;

	skb = *skb_in;
	hdr = ipv6_hdr(skb);
	segments = seg6_get_segments(net, &hdr->daddr);

	if (segments == NULL)
		return 0;

	srhlen = SEG6_HDR_BYTELEN(segments);
	tot_len = srhlen + (segments->tunnel ? sizeof(struct ipv6hdr) : 0);

	if (pskb_expand_head(skb, tot_len, 0, GFP_ATOMIC)) {
		printk(KERN_DEBUG "SR6: seg6_process_skb: cannot expand head\n");
		return 0;
	}

	memmove(skb_network_header(skb) - tot_len, skb_network_header(skb), sizeof(struct ipv6hdr));

	skb_push(skb, tot_len);
	skb->network_header -= tot_len;
	hdr = ipv6_hdr(skb);
	srh = (void *)hdr + sizeof(struct ipv6hdr);

	if (segments->tunnel)
		srh->nexthdr = NEXTHDR_IPV6;
	else
		srh->nexthdr = hdr->nexthdr;

	hdr->nexthdr = NEXTHDR_ROUTING;
	hdr->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	srh->hdrlen = SEG6_HDR_LEN(segments);
	srh->type = IPV6_SRCRT_TYPE_4;
	srh->next_segment = 0;
	srh->last_segment = (segments->seg_size - 1) << 1;
	srh->f1 = 0;
	srh->f2 = 0;
	srh->f3 = 0;
	if (segments->cleanup)
		sr_set_flags(srh, 0x8);
	if (segments->tunnel)
		sr_set_flags(srh, sr_get_flags(srh) | 0x2);

	memcpy(srh->segments, &segments->segments[1], (segments->seg_size - 1)*sizeof(struct in6_addr));
	srh->segments[segments->seg_size - 1] = hdr->daddr;
	srh->segments[segments->seg_size] = segments->segments[0];

	hdr->daddr = segments->segments[0];

	if (segments->tunnel)
		ipv6_dev_get_saddr(net, skb->dev, &hdr->daddr, IPV6_PREFER_SRC_PUBLIC, &hdr->saddr);

	if (segments->hmackeyid) {
		sr_set_hmac_key_id(srh, segments->hmackeyid);
		memset(SEG6_HMAC(srh), 0, 32);
		sr_hmac_sha1(seg6_hmac_key, strlen(seg6_hmac_key), srh, &hdr->saddr, (u32*)SEG6_HMAC(srh));
	}

	*skb_in = skb;

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

int seg6_flush_segments(struct net *net)
{
	struct seg6_info *info;
	struct hlist_node *itmp;
	int i;

	for (i = 0; i < 4096; i++) {
		hlist_for_each_entry_safe(info, itmp, &net->ipv6.seg6_hash[i], seg_chain) {
			__seg6_flush_segment(info);
			hlist_del_rcu(&info->seg_chain);
			kfree(info);
		}
	}

	return 0;
}
EXPORT_SYMBOL(seg6_flush_segments);

int seg6_dump_segments(struct net *net)
{
	struct seg6_info *info;
	struct seg6_list *list;
	int i, j;

	for (i = 0; i < 4096; i++) {
		hlist_for_each_entry_rcu(info, &net->ipv6.seg6_hash[i], seg_chain) {
			list = info->list;
			printk(KERN_DEBUG "seg6_dump_segments(): dumping %u entries for dst %pI6 dstlen %u\n", info->list_size, &info->dst, info->dst_len);
			while (list != NULL) {
				printk(KERN_DEBUG "seg6_dump_segments(): dumping %u segments for subentry %u\n", list->seg_size, list->id);
				for (j = 0; j < list->seg_size; j++)
					printk(KERN_DEBUG "seg6_dump_segments(): subentry %u segment #%u is %pI6\n", list->id, j, &list->segments[j]);
				list = list->next;
			}
		}
	}

	return 0;
}
EXPORT_SYMBOL(seg6_dump_segments);

int seg6_del_segment(struct net *net, struct seg6_delseg *segmsg)
{
	struct seg6_info *info;
	int found = 0;

	hlist_for_each_entry_rcu(info, &net->ipv6.seg6_hash[seg6_hashfn(&segmsg->dst)], seg_chain) {
		if (memcmp(info->dst.s6_addr, segmsg->dst.s6_addr, 16) == 0 && info->dst_len == segmsg->dst_len) {
			found = 1;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	if (segmsg->id == (u16)-1) {
		__seg6_flush_segment(info);
	} else {
		if (__seg6_remove_id(info, segmsg->id))
			return -ENOENT;
	}

	if (info->list_size == 0) {
		hlist_del_rcu(&info->seg_chain);
		kfree(info);
	}

	return 0;
}
EXPORT_SYMBOL(seg6_del_segment);

int seg6_add_segment(struct net *net, struct seg6_addseg *segmsg)
{
	struct seg6_info *info;
	struct seg6_list *tmp;
	int found = 0, err;

	hlist_for_each_entry_rcu(info, &net->ipv6.seg6_hash[seg6_hashfn(&segmsg->dst)], seg_chain) {
		if (memcmp(info->dst.s6_addr, segmsg->dst.s6_addr, 16) == 0 && info->dst_len == segmsg->dst_len) {
			found = 1;
			break;
		}
	}

	if (!found) {
		info = kzalloc(sizeof(*info), GFP_KERNEL);
		if (!info)
			return -ENOMEM;

		memcpy(info->dst.s6_addr, segmsg->dst.s6_addr, 16);
		info->dst_len = segmsg->dst_len;

		hlist_add_head_rcu(&info->seg_chain, &net->ipv6.seg6_hash[seg6_hashfn(&info->dst)]);
	} else {
		for (tmp = info->list; tmp; tmp = tmp->next) {
			if (tmp->id == segmsg->id)
				return -EEXIST;
		}
	}

	tmp = kzalloc(sizeof(struct seg6_list), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	tmp->id = segmsg->id;
	tmp->seg_size = segmsg->seg_len;
	tmp->cleanup = segmsg->cleanup;
	tmp->tunnel = segmsg->tunnel;
	tmp->hmackeyid = segmsg->hmackeyid;
	tmp->segments = kmalloc(segmsg->seg_len*sizeof(struct in6_addr), GFP_KERNEL);
	if (!tmp->segments) {
		kfree(tmp);
		return -ENOMEM;
	}

	err = copy_from_user(tmp->segments, segmsg->segments, segmsg->seg_len*sizeof(struct in6_addr));
	if (err) {
		kfree(tmp);
		return -EFAULT;
	}

	tmp->next = info->list;
	info->list = tmp;
	info->list_size++;
	return 0;
}
EXPORT_SYMBOL(seg6_add_segment);

static struct ctl_table seg6_table[] = {
	{
		.procname 	= "hmac_key",
		.data 		= seg6_hmac_key,
		.maxlen		= SEG6_HMAC_MAX_SIZE,
		.mode		= 0644,
		.proc_handler	= proc_dostring,
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
	__SEG6_ATTR_MAX,
};

#define SEG6_ATTR_MAX (__SEG6_ATTR_MAX - 1)

static struct nla_policy seg6_genl_policy[SEG6_ATTR_MAX + 1] = {
	[SEG6_ATTR_DST] 		= { .type = NLA_BINARY, .len = sizeof(struct in6_addr) },
	[SEG6_ATTR_DSTLEN]		= { .type = NLA_S32, },
	[SEG6_ATTR_SEGLISTID] 	= { .type = NLA_U16, },
	[SEG6_ATTR_FLAGS] 		= { .type = NLA_U32, },
	[SEG6_ATTR_HMACKEYID] 	= { .type = NLA_U8, },
	[SEG6_ATTR_SEGMENTS] 	= { .type = NLA_BINARY, },
	[SEG6_ATTR_SEGLEN] 		= { .type = NLA_S32, },
	[SEG6_ATTR_SEGINFO]		= { .type = NLA_NESTED, },
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
    __SEG6_CMD_MAX,
};

#define SEG6_CMD_MAX (__SEG6_CMD_MAX - 1)

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
	tmp->cleanup = (flags & 0x8) ? 1 : 0;
	tmp->tunnel = (flags & 0x2) ? 1 : 0;
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

static int seg6_genl_flush(struct sk_buff *skb, struct genl_info *info)
{
	struct seg6_info *s6info;
	struct hlist_node *itmp;
	int i;
	struct net *net = genl_info_net(info);

	for (i = 0; i < 4096; i++) {
		hlist_for_each_entry_safe(s6info, itmp, &net->ipv6.seg6_hash[i], seg_chain) {
			__seg6_flush_segment(s6info);
			hlist_del_rcu(&s6info->seg_chain);
			seg6_route_delete(net->ipv6.seg6_fib_root, &s6info->dst, s6info->dst_len);
			kfree(s6info);
		}
	}

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
				msg = nlmsg_new(NLMSG_DEFAULT_SIZE, GFP_KERNEL);
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
};

void __net_init seg6_nl_init(void)
{
	genl_register_family_with_ops(&seg6_genl_family, seg6_genl_ops, 4);
}
