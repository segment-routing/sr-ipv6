/*
 *  SR-IPv6 implementation -- HMAC functions
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
#include <linux/random.h>

static char * __percpu *hmac_ring;

static struct seg6_hmac_algo hmac_algos[] = {
	{
		.alg_id = SEG6_HMAC_ALGO_SHA1,
		.name = "hmac(sha1)",
	},
	{
		.alg_id = SEG6_HMAC_ALGO_SHA256,
		.name = "hmac(sha256)",
	},
};

static struct seg6_hmac_algo *__hmac_get_algo(u8 alg_id)
{
	int i, alg_count;
	struct seg6_hmac_algo *algo;

	alg_count = sizeof(hmac_algos)/sizeof(struct seg6_hmac_algo);
	for (i = 0; i < alg_count; i++) {
		algo = &hmac_algos[i];
		if (algo->alg_id == alg_id)
			return algo;
	}

	return NULL;
}

static int __do_hmac(struct seg6_hmac_info *hinfo, const char *text, u8 psize,
		     u8 *output, int outlen)
{
	struct crypto_shash *tfm;
	struct shash_desc *shash;
	struct seg6_hmac_algo *algo;
	int ret, dgsize;

	algo = __hmac_get_algo(hinfo->alg_id);
	if (!algo)
		return -ENOENT;

	tfm = *this_cpu_ptr(algo->tfms);

	dgsize = crypto_shash_digestsize(tfm);
	if (dgsize > outlen) {
		pr_debug("sr-ipv6: __do_hmac: digest size too big (%d / %d)\n",
			 dgsize, outlen);
		return -ENOMEM;
	}

	ret = crypto_shash_setkey(tfm, hinfo->secret, hinfo->slen);
	if (ret < 0) {
		pr_debug("sr-ipv6: crypto_shash_setkey failed: err %d\n", ret);
		goto failed;
	}

	shash = *this_cpu_ptr(algo->shashs);
	shash->tfm = tfm;

	ret = crypto_shash_digest(shash, text, psize, output);
	if (ret < 0) {
		pr_debug("sr-ipv6: crypto_shash_digest failed: err %d\n", ret);
		goto failed;
	}

	return dgsize;

failed:
	return ret;
}

int seg6_hmac_compute(struct seg6_hmac_info *hinfo, struct ipv6_sr_hdr *hdr,
		      struct in6_addr *saddr, u8 *output)
{
	int plen, i, dgsize, wrsize;
	char *ring, *off;
	u8 tmp_out[SEG6_HMAC_MAX_DIGESTSIZE];
	__be32 hmackeyid = cpu_to_be32(hinfo->hmackeyid);

	/* a 160-byte buffer for digest output allows to store highest known
	 * hash function (RadioGatun) with up to 1216 bits
	 */

	/* saddr(16) + first_seg(1) + cleanup(1) + keyid(4) + seglist(16n) */
	plen = 16 + 1 + 1 + 4 + (hdr->first_segment + 1) * 16;

	/* this limit allows for 14 segments */
	if (plen >= SEG6_HMAC_RING_SIZE)
		return -EMSGSIZE;

	local_bh_disable();
	off = ring = *this_cpu_ptr(hmac_ring);
	memcpy(off, saddr, 16);
	off += 16;
	*off++ = hdr->first_segment;
	*off++ = !!(sr_get_flags(hdr) & SR6_FLAG_CLEANUP) << 7;
	memcpy(off, &hmackeyid, 4);
	off += 4;

	for (i = 0; i < hdr->first_segment + 1; i++) {
		memcpy(off, hdr->segments + i, 16);
		off += 16;
	}

	dgsize = __do_hmac(hinfo, ring, plen, tmp_out,
			   SEG6_HMAC_MAX_DIGESTSIZE);
	local_bh_enable();

	if (dgsize < 0)
		return dgsize;

	wrsize = SEG6_HMAC_FIELD_LEN;
	if (wrsize > dgsize)
		wrsize = dgsize;

	memset(output, 0, SEG6_HMAC_FIELD_LEN);
	memcpy(output, tmp_out, wrsize);

	return 0;
}
EXPORT_SYMBOL(seg6_hmac_compute);

/* checks if an incoming SR-enabled packet's HMAC status matches
 * the incoming policy.
 *
 * called with rcu_read_lock()
 */
bool seg6_hmac_validate_skb(struct sk_buff *skb)
{
	struct inet6_dev *idev;
	struct ipv6_sr_hdr *srh;
	struct sr6_tlv_hmac *tlv;
	struct seg6_hmac_info *hinfo;
	struct net *net = dev_net(skb->dev);
	u8 hmac_output[SEG6_HMAC_FIELD_LEN];

	idev = __in6_dev_get(skb->dev);

	srh = (struct ipv6_sr_hdr *)skb_transport_header(skb);

	tlv = seg6_get_tlv_hmac(srh);

	/* mandatory check but no tlv */
	if (idev->cnf.seg6_require_hmac > 0 && !tlv)
		return false;

	/* no check */
	if (idev->cnf.seg6_require_hmac < 0)
		return true;

	/* check only if present */
	if (idev->cnf.seg6_require_hmac == 0 && !tlv)
		return true;

	/* now, seg6_require_hmac >= 0 && tlv */

	hinfo = seg6_hmac_info_lookup(net, be32_to_cpu(tlv->hmackeyid));
	if (!hinfo)
		return false;

	if (seg6_hmac_compute(hinfo, srh, &ipv6_hdr(skb)->saddr, hmac_output))
		return false;

	if (memcmp(hmac_output, tlv->hmac, SEG6_HMAC_FIELD_LEN) != 0)
		return false;

	return true;
}

/* called with rcu_read_lock() */
struct seg6_hmac_info *seg6_hmac_info_lookup(struct net *net, u32 key)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_hmac_info *hinfo;

	list_for_each_entry_rcu(hinfo, &sdata->hmac_infos, list) {
		if (hinfo->hmackeyid == key)
			return hinfo;
	}

	return NULL;
}
EXPORT_SYMBOL(seg6_hmac_info_lookup);

int seg6_hmac_info_add(struct net *net, u32 key, struct seg6_hmac_info *hinfo)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_hmac_info *old_hinfo;

	if ((old_hinfo = seg6_hmac_info_lookup(net, key)) != NULL)
		return -EEXIST;

	list_add_rcu(&hinfo->list, &sdata->hmac_infos);

	return 0;
}
EXPORT_SYMBOL(seg6_hmac_info_add);

int seg6_hmac_info_del(struct net *net, u32 key, struct seg6_hmac_info *hinfo)
{
	struct seg6_hmac_info *tmp;

	if ((tmp = seg6_hmac_info_lookup(net, key)) == NULL)
		return -ENOENT;

	/* entry was replaced, ignore deletion */
	if (tmp != hinfo)
		return -ENOENT;

	list_del_rcu(&hinfo->list);
	synchronize_net();

	return 0;
}
EXPORT_SYMBOL(seg6_hmac_info_del);

static void seg6_hmac_info_flush(struct net *net)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);
	struct seg6_hmac_info *hinfo;

	seg6_pernet_lock(net);
	while ((hinfo = list_first_or_null_rcu(&sdata->hmac_infos,
					       struct seg6_hmac_info,
					       list)) != NULL) {
		list_del_rcu(&hinfo->list);
		seg6_pernet_unlock(net);
		synchronize_net();
		kfree(hinfo);
		seg6_pernet_lock(net);
	}

	seg6_pernet_unlock(net);
}

int seg6_push_hmac(struct net *net, struct in6_addr *saddr,
		   struct ipv6_sr_hdr *srh)
{
	struct seg6_hmac_info *hinfo;
	int err = -ENOENT;
	struct sr6_tlv_hmac *tlv;

	tlv = seg6_get_tlv(srh, SR6_TLV_HMAC);
	if (!tlv)
		return -EINVAL;

	rcu_read_lock();

	hinfo = seg6_hmac_info_lookup(net, be32_to_cpu(tlv->hmackeyid));
	if (!hinfo)
		goto out;

	memset(tlv->hmac, 0, SEG6_HMAC_FIELD_LEN);
	err = seg6_hmac_compute(hinfo, srh, saddr, tlv->hmac);

out:
	rcu_read_unlock();
	return err;
}
EXPORT_SYMBOL(seg6_push_hmac);

static int seg6_hmac_init_ring(void)
{
	int i;

	hmac_ring = alloc_percpu(char *);

	if (!hmac_ring)
		return -ENOMEM;

	for_each_possible_cpu(i) {
		char *ring = kzalloc(SEG6_HMAC_RING_SIZE, GFP_KERNEL);

		if (!ring)
			return -ENOMEM;

		*per_cpu_ptr(hmac_ring, i) = ring;
	}

	return 0;
}

static int seg6_hmac_init_algo(void)
{
	int i, alg_count, cpu;
	struct seg6_hmac_algo *algo;
	struct crypto_shash *tfm;
	struct shash_desc *shash;

	alg_count = sizeof(hmac_algos)/sizeof(struct seg6_hmac_algo);

	for (i = 0; i < alg_count; i++) {
		int shsize;
		struct crypto_shash **p_tfm;

		algo = &hmac_algos[i];
		algo->tfms = alloc_percpu(struct crypto_shash *);
		if (!algo->tfms)
			return -ENOMEM;

		for_each_possible_cpu(cpu) {
			tfm = crypto_alloc_shash(algo->name, 0, GFP_KERNEL);
			if (IS_ERR(tfm))
				return PTR_ERR(tfm);
			p_tfm = per_cpu_ptr(algo->tfms, cpu);
			*p_tfm = tfm;
		}

		p_tfm = this_cpu_ptr(algo->tfms);
		tfm = *p_tfm;

		shsize = sizeof(*shash) + crypto_shash_descsize(tfm);

		algo->shashs = alloc_percpu(struct shash_desc *);
		if (!algo->shashs)
			return -ENOMEM;

		for_each_possible_cpu(cpu) {
			shash = kzalloc(shsize, GFP_KERNEL);
			if (!shash)
				return -ENOMEM;
			*per_cpu_ptr(algo->shashs, cpu) = shash;
		}
	}

	return 0;
}

int __init seg6_hmac_init(void)
{
	int ret;

	ret = seg6_hmac_init_ring();
	if (ret < 0)
		goto out;

	ret = seg6_hmac_init_algo();

out:
	return ret;
}

int __net_init seg6_hmac_net_init(struct net *net)
{
	struct seg6_pernet_data *sdata = seg6_pernet(net);

	INIT_LIST_HEAD(&sdata->hmac_infos);
	return 0;
}

void __exit seg6_hmac_exit(void)
{
	int i, alg_count, cpu;
	struct seg6_hmac_algo *algo = NULL;

	for_each_possible_cpu(i) {
		char *ring = *per_cpu_ptr(hmac_ring, i);
		kfree(ring);
	}
	free_percpu(hmac_ring);

	alg_count = sizeof(hmac_algos)/sizeof(struct seg6_hmac_algo);
	for (i = 0; i < alg_count; i++) {
		algo = &hmac_algos[i];
		for_each_possible_cpu(cpu) {
			struct crypto_shash *tfm;
			struct shash_desc *shash;

			shash = *per_cpu_ptr(algo->shashs, cpu);
			kfree(shash);
			tfm = *per_cpu_ptr(algo->tfms, cpu);
			crypto_free_shash(tfm);
		}
		free_percpu(algo->tfms);
		free_percpu(algo->shashs);
	}
}

void __net_exit seg6_hmac_net_exit(struct net *net)
{
	seg6_hmac_info_flush(net);
}
