#ifndef _NET_SEG6_HMAC_H
#define _NET_SEG6_HMAC_H

#include <net/flow.h>
#include <net/ip6_fib.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/route.h>
#include <net/seg6.h>

extern int sr_hmac_sha1(u8 *key, u8 ksize, struct ipv6_sr_hdr *hdr, struct in6_addr *saddr, u32 *output);

extern char seg6_hmac_key[];

#define SEG6_HMAC(srh) ((srh)->segments + (((srh)->last_segment + 4) >> 1))
#define SEG6_HMAC_MAX_SIZE  64

#endif
