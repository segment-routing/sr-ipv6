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
#include <net/seg6_table.h>
#include <net/seg6_hmac.h>
#include <linux/random.h>

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
		padlen = 64 - (len % 64);
	else
		padlen = 0;

	{
		char plaintext[len + padlen];

		memset(plaintext, 0, len + padlen);
		memcpy(plaintext, message, len);

		pptr = plaintext + len;

		if (padlen) {
			bits = cpu_to_be64(len << 3);
			memcpy(pptr + padlen - sizeof(bits), (const u8 *)&bits,
			       sizeof(bits));
			*pptr = 0x80;
		}

		sha_init(hash_out);

		for (i = 0; i < len + padlen; i += 64)
			sha_transform(hash_out, plaintext + i, workspace);

		for (i = 0; i < 5; i++)
			hash_out[i] = cpu_to_be32(hash_out[i]);

		memset(workspace, 0, sizeof(workspace));
	}
}

int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr,
		 struct in6_addr *saddr, u32 *output)
{
	unsigned int plen;
	struct in6_addr *addr;
	int i;
	char *pptr;
	u8 i_pad[64], o_pad[64];
	u8 realkey[64];
	u32 hash_out[5];
	u8 outer_msg[84]; /* 20 (hash) + 64 (o_pad) */

	if (!ksize)
		return -EINVAL;

	plen = 16 + 1 + 1 + 1 + (hdr->first_segment + 1) * 16;

	{
		u8 inner_msg[64 + plen];

		pptr = inner_msg + 64;
		memset(pptr, 0, plen);

		memcpy(pptr, saddr->s6_addr, 16);
		pptr += 16;
		*pptr++ = hdr->first_segment;
		*pptr++ = !!(sr_get_flags(hdr) & SR6_FLAG_CLEANUP) << 7;
		*pptr++ = sr_get_hmac_key_id(hdr);

		for (i = 0; i < hdr->first_segment + 1; i += 1) {
			addr = hdr->segments + i;
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
		sr_sha1(inner_msg, 64 + plen, hash_out);

		memcpy(outer_msg, o_pad, 64);
		memcpy(outer_msg + 64, hash_out, 20);

		sr_sha1(outer_msg, 84, output);
	}

	return 0;
}
EXPORT_SYMBOL(sr_hmac_sha1);
