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

#include <net/seg6.h>
#include <net/seg6_table.h>

static int get_bit(struct in6_addr *addr, int idx)
{
	u8 bit, byte;

	byte = addr->s6_addr[idx >> 3];
	bit = 1 << (7 - idx%8);

	return (byte & bit) != 0;
}

static int get_next_bit(struct in6_addr *addr, int dst_len, int cur_bit, int val)
{
	int idx = cur_bit;
	int bit;

	do {
		bit = get_bit(addr, idx);
		if (bit == val)
			break;
		idx++;
	} while (idx < dst_len);

	return idx;
}

struct s6ib_node *seg6_route_lookup(struct s6ib_node *root, struct in6_addr *addr)
{
	struct s6ib_node *node, *match, *child;
	int cur_val, i = 0, next_bit, delta;

	match = node = root;
	while (i < 128) {
		cur_val = get_bit(addr, i);
		child = node->children[cur_val];

		if (!child)
			return match;

		next_bit = get_next_bit(addr, 128, i+1, !cur_val);
		delta = next_bit - i;

		if (child->count > delta)
			return match;

		if (child->s6info)
			match = child;

		i += child->count;
		node = child;
	}

	return match;
}

struct s6ib_node *seg6_route_insert(struct s6ib_node *root, struct seg6_info *s6info)
{
	struct s6ib_node *node, *child, *newnode;
	int cur_bit = 0;
	int cur_val;
	int next_bit, delta;
	int plen = s6info->dst_len;
	struct in6_addr *addr = &s6info->dst;

	node = root;
	while (cur_bit < plen) {
		cur_val = get_bit(addr, cur_bit);
		next_bit = get_next_bit(addr, plen, cur_bit+1, !cur_val);

		if (next_bit > plen)
			next_bit = plen;

		delta = next_bit - cur_bit;
		child = node->children[cur_val];

		if (child) {
			if (child->count <= delta) {
				cur_bit += child->count;
				node = child;
				continue;
			} else {
				newnode = kzalloc(sizeof(*newnode), GFP_KERNEL);
				if (!newnode)
					return ERR_PTR(-ENOMEM);

				newnode->bit = cur_val;
				newnode->count = delta;
				newnode->children[cur_val] = child;
				child->parent = newnode;
				child->count -= delta;
				node->children[cur_val] = newnode;
				newnode->parent = node;
				cur_bit += delta;
				node = newnode;
				continue;
			}
		} else {
			newnode = kzalloc(sizeof(*newnode), GFP_KERNEL);
			if (!newnode)
				return ERR_PTR(-ENOMEM);

			newnode->bit = cur_val;
			newnode->count = delta;
			node->children[cur_val] = newnode;
			newnode->parent = node;
			cur_bit += delta;
			node = newnode;
			continue;
		}
	}

	if (node->s6info)
		return ERR_PTR(-EEXIST);

	node->s6info = s6info;

	return node;
}

static struct s6ib_node *seg6_route_lookup_exact(struct s6ib_node *root, struct in6_addr *addr, int plen)
{
	struct s6ib_node *node, *child;
	int cur_val, i = 0, next_bit, delta;

	node = root;
	while (i < plen) {
		cur_val = get_bit(addr, i);
		child = node->children[cur_val];

		if (!child)
			return NULL;

		next_bit = get_next_bit(addr, plen, i+1, !cur_val);
		if (next_bit > plen)
			next_bit = plen;

		delta = next_bit - i;

		if (child->count > delta)
			return NULL;

		if (child->s6info && memcmp(&child->s6info->dst, addr, 16) == 0 && child->s6info->dst_len == plen)
			return child;

		i += child->count;
		node = child;
	}

	return NULL;
}

int seg6_route_delete(struct s6ib_node *root, struct in6_addr *addr, int plen)
{
	struct s6ib_node *parent, *child, *node;
	int val, count;

	node = seg6_route_lookup_exact(root, addr, plen);
	if (!node)
		return 1;

	parent = node->parent;
	val = node->bit;
	count = node->count;
	node->s6info = NULL;

	if (node->children[!val])
		return 0;

	child = node->children[val];
	if (child) {
		child->count += count;
		child->parent = parent;
		parent->children[val] = child;
		kfree(node);
		return 0;
	}

	while (!node->s6info && !node->children[!val] && node != root) {
		val = node->bit;
		kfree(node);
		parent->children[val] = NULL;
		node = parent;
		parent = node->parent;
	}

	return 0;
}
