#ifndef _NET_SEG6_H
#define _NET_SEG6_H

#include <net/flow.h>
#include <net/ip6_fib.h>
#include <net/sock.h>
#include <linux/ip.h>
#include <linux/ipv6.h>
#include <linux/route.h>

#define SEG6NEWPOL      0x0001
#define SEG6ADDSEG      0x0002
#define SEG6FLUSH       0x0004
#define SEG6DUMP        0x0005
#define SEG6DELSEG      0x0006

struct seg6_list {
    u16 id;
    struct in6_addr *segments;
    int seg_size;
    int cleanup;

    struct seg6_list *next;
};

struct seg6_info {
    struct in6_addr dst;
    int dst_len;

    struct seg6_list *list;
    int list_size;

    struct hlist_node seg_chain;
};

struct seg6_newpol {
    struct in6_addr dst;
    int dst_len;
};

struct seg6_addseg {
    struct in6_addr dst;
    int dst_len;
    u16 id;
    int cleanup;
    struct in6_addr segment;
};

struct seg6_delseg {
    struct in6_addr dst;
    int dst_len;
    u16 id;
};

struct seg6_msg {
    int msg;
    void *data;
};

extern int sr_hmac_sha1(u8 *key, u8 ksize, struct sk_buff *skb, u32 *output);
extern int seg6_add_segment(struct net *net, struct seg6_addseg *segmsg);
extern int seg6_del_segment(struct net *net, struct seg6_delseg *segmsg);
extern int seg6_dump_segments(struct net *net);
extern int seg6_flush_segments(struct net *net);
extern int seg6_create_pol(struct net *net, struct seg6_newpol *npmsg);
extern int seg6_process_skb(struct net *net, struct sk_buff *skb);

#endif
