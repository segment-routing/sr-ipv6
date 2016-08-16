/*
 * (C) 2001 Clemson University and The University of Chicago
 *
 * See COPYING in top-level directory.
 */

#include "protocol.h"
#include "orangefs-kernel.h"
#include "orangefs-bufmap.h"

struct inode_operations orangefs_symlink_inode_operations = {
	.readlink = generic_readlink,
	.get_link = simple_get_link,
	.setattr = orangefs_setattr,
	.getattr = orangefs_getattr,
	.listxattr = orangefs_listxattr,
	.setxattr = generic_setxattr,
	.permission = orangefs_permission,
};
