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

#ifndef _NET_SEG6_HMAC_H
#define _NET_SEG6_HMAC_H

#include <net/flow.h>
#include <net/ip6_fib.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/route.h>
#include <net/seg6.h>

#define SEG6_HMAC(s) ((s)->segments+SEG6_SRH_SEGSIZE(s))
#define SEG6_HMAC_MAX_SIZE  64

#define SEG6_MAX_HMAC_KEY 256

struct seg6_hmac_info {
	char secret[SEG6_HMAC_MAX_SIZE];
	u8 slen;
	u8 alg_id;
};

extern int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr,
			struct in6_addr *saddr, u32 *output);

extern int seg6_hmac_add_info(struct net *net, int key,
			      const struct seg6_hmac_info *hinfo);
extern int seg6_hmac_del_info(struct net *net, int key,
			      const struct seg6_hmac_info *hinfo);
extern int seg6_push_hmac(struct net *net, struct in6_addr *saddr,
			  struct ipv6_sr_hdr *srh);

#endif
