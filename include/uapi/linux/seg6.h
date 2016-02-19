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

#ifndef _UAPI_LINUX_SEG6_H
#define _UAPI_LINUX_SEG6_H

/*
 * SRH
 */
struct ipv6_sr_hdr {
	__u8	nexthdr;
	__u8	hdrlen;
	__u8	type;
	__u8	segments_left;
	__u8	first_segment;

	__u8	flag_1;
	__u8	flag_2;

	__u8	hmackeyid;

	struct in6_addr segments[0];
};

#define SR6_FLAG_CLEANUP	0x08
#define SR6_FLAG_PROTECTED	0x04
#define SR6_FLAGMASK		0x0f

#define sr_set_hmac_key_id(hdr, val) ((hdr)->hmackeyid = val)
#define sr_get_hmac_key_id(hdr) ((hdr)->hmackeyid)

static inline void sr_set_flags(struct ipv6_sr_hdr *hdr, int val)
{
	hdr->flag_1 = ((val & 0xF) << 4) | (hdr->flag_1 & 0xF);
}

static inline int sr_get_flags(struct ipv6_sr_hdr *hdr)
{
	return (hdr->flag_1 >> 4) & 0xF;
}

static inline void sr_set_flag_p1(struct ipv6_sr_hdr *hdr, int val)
{
	hdr->flag_1 = ((val & 0x7) << 1) | (hdr->flag_1 & 0xF1);
}

static inline int sr_get_flag_p1(struct ipv6_sr_hdr *hdr)
{
	return (hdr->flag_1 >> 1) & 0x7;
}

static inline void sr_set_flag_p2(struct ipv6_sr_hdr *hdr, int val)
{
	hdr->flag_1 = ((val & 0x7) >> 2) | (hdr->flag_1 & 0xFE);
	hdr->flag_2 = ((val & 0x3) << 6) | (hdr->flag_2 & 0x3F);
}

static inline int sr_get_flag_p2(struct ipv6_sr_hdr *hdr)
{
	return ((hdr->flag_1 & 0x1) << 2) | ((hdr->flag_2 >> 6) & 0x3);
}

static inline void sr_set_flag_p3(struct ipv6_sr_hdr *hdr, int val)
{
	hdr->flag_2 = ((val & 0x7) << 3) | (hdr->flag_2 & 0xC7);
}

static inline int sr_get_flag_p3(struct ipv6_sr_hdr *hdr)
{
	return (hdr->flag_2 >> 3) & 0x7;
}

static inline void sr_set_flag_p4(struct ipv6_sr_hdr *hdr, int val)
{
	hdr->flag_2 = (val & 0x7) | (hdr->flag_2 & 0xF8);
}

static inline int sr_get_flag_p4(struct ipv6_sr_hdr *hdr)
{
	return hdr->flag_2 & 0x7;
}

#endif
