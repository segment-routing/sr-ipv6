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

int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr, struct in6_addr *saddr, u32 *output, int zero)
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

	if (zero)
		memset((char*)output, 0, 32);

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
	struct seg6_list *node;
	int found = 0;
	int i, id;

	hlist_for_each_entry_rcu(info, &net->ipv6.seg6_hash[seg6_hashfn(dst)], seg_chain) {
		if (ipv6_prefix_equal(dst, &info->dst, info->dst_len)) {
			found = 1;
			break;
		}
	}

	if (!found)
		return NULL;

	if (info->list_size == 0)
		return NULL;

	id = net_random()%info->list_size;
	node = info->list;
	for (i = 0; i < id; i++)
		node = node->next;

	return node;
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
	int srhlen;
	struct ipv6_sr_hdr *srh;

	skb = *skb_in;
	hdr = ipv6_hdr(skb);
	segments = seg6_get_segments(net, &hdr->daddr);

	if (segments == NULL)
		return 0;

	srhlen = SEG6_HDR_BYTELEN(segments);

	if (pskb_expand_head(skb, srhlen, 0, GFP_ATOMIC)) {
		printk(KERN_DEBUG "SR6: seg6_process_skb: cannot expand head\n");
		return 0;
	}

	memmove(skb_network_header(skb) - srhlen, skb_network_header(skb), sizeof(struct ipv6hdr));
	skb_push(skb, srhlen);
	skb->network_header -= srhlen;
	hdr = ipv6_hdr(skb);
	srh = (void *)hdr + sizeof(struct ipv6hdr);

	srh->nexthdr = hdr->nexthdr;
	hdr->nexthdr = NEXTHDR_ROUTING;
	hdr->payload_len = htons(skb->len - sizeof(struct ipv6hdr));

	srh->hdrlen = ((segments->seg_size + 1) << 1) + (segments->hmackeyid ? 4 : 0);
	srh->type = IPV6_SRCRT_TYPE_4;
	srh->next_segment = 0;
	srh->last_segment = (segments->seg_size - 1) << 1;
	srh->f1 = 0;
	srh->f2 = 0;
	srh->f3 = 0;
	if (segments->cleanup)
		sr_set_flags(srh, 0x8);

	memcpy(srh->segments, &segments->segments[1], (segments->seg_size - 1)*sizeof(struct in6_addr));
	srh->segments[segments->seg_size - 1] = hdr->daddr;
	srh->segments[segments->seg_size] = segments->segments[0];

	hdr->daddr = segments->segments[0];

	if (segments->hmackeyid) {
		sr_set_hmac_key_id(srh, segments->hmackeyid);
		sr_hmac_sha1(seg6_hmac_key, strlen(seg6_hmac_key), srh, &hdr->saddr, (u32*)SEG6_HMAC(srh), 1);
	}

	*skb_in = skb;

	return 1;
}
EXPORT_SYMBOL(seg6_process_skb);

int seg6_create_pol(struct net *net, struct seg6_newpol *npmsg)
{
	struct seg6_info *tmp;

	hlist_for_each_entry_rcu(tmp, &net->ipv6.seg6_hash[seg6_hashfn(&npmsg->dst)], seg_chain) {
		if (memcmp(tmp->dst.s6_addr, npmsg->dst.s6_addr, 16) == 0 && tmp->dst_len == npmsg->dst_len)
			return -EEXIST;
	}

	// no entry, add one

	tmp = kzalloc(sizeof(*tmp), GFP_KERNEL);
	if (!tmp)
		return -ENOMEM;

	memcpy(tmp->dst.s6_addr, npmsg->dst.s6_addr, 16);
	tmp->dst_len = npmsg->dst_len;

	hlist_add_head_rcu(&tmp->seg_chain, &net->ipv6.seg6_hash[seg6_hashfn(&tmp->dst)]);

	return 0;
}
EXPORT_SYMBOL(seg6_create_pol);

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
	struct in6_addr *segments;
	int found = 0;

	hlist_for_each_entry_rcu(info, &net->ipv6.seg6_hash[seg6_hashfn(&segmsg->dst)], seg_chain) {
		if (memcmp(info->dst.s6_addr, segmsg->dst.s6_addr, 16) == 0 && info->dst_len == segmsg->dst_len) {
			found = 1;
			break;
		}
	}

	if (!found)
		return -ENOENT;

	// first call to SIOCADDSG after initial SIOCNEWSG
	if (info->list_size == 0) {
		info->list = kzalloc(sizeof(struct seg6_list), GFP_KERNEL);
		if (!info->list)
			return -ENOMEM;
		tmp = info->list;
		tmp->id = segmsg->id;
		tmp->seg_size = 1;
		tmp->cleanup = segmsg->cleanup;
		tmp->hmackeyid = segmsg->hmackeyid;
		tmp->next = NULL;
		tmp->segments = kmalloc(sizeof(struct in6_addr), GFP_KERNEL);
		if (!tmp->segments) {
			kfree(info->list);
			return -ENOMEM;
		}
		memcpy(tmp->segments[0].s6_addr, segmsg->segment.s6_addr, 16);

		info->list_size++;
		return 0;
	}

	found = 0;
	for (tmp = info->list; tmp; tmp = tmp->next) {
		if (tmp->id == segmsg->id) {
			found = 1;
			break;
		}
	}

	// entry for dst exists but id does not exist yet
	if (!found) {
		tmp = kzalloc(sizeof(struct seg6_list), GFP_KERNEL);
		if (!tmp)
			return -ENOMEM;
		tmp->id = segmsg->id;
		tmp->seg_size = 1;
		tmp->next = info->list;
		tmp->cleanup = segmsg->cleanup;
		tmp->hmackeyid = segmsg->hmackeyid;
		tmp->segments = kmalloc(sizeof(struct in6_addr), GFP_KERNEL);
		if (!tmp->segments) {
			kfree(tmp);
			return -ENOMEM;
		}
		memcpy(tmp->segments[0].s6_addr, segmsg->segment.s6_addr, 16);

		info->list = tmp;
		info->list_size++;
		return 0;
	}

	// entry for dst exists as well as id

	segments = krealloc(tmp->segments, (tmp->seg_size+1)*sizeof(struct in6_addr), GFP_KERNEL);
	if (!segments)
		return -ENOMEM;

	tmp->seg_size++;
	memcpy(segments[tmp->seg_size-1].s6_addr, segmsg->segment.s6_addr, 16);
	tmp->segments = segments;

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
