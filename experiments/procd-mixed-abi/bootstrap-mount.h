/* SPDX-License-Identifier: MIT
 * Host-testable decision used only by the explicit mainroot bootstrap profile.
 * The native bootstrap owns the initial mounts: missing/wrong mounts are fatal
 * admission errors, never a reason to hide them under another mount.
 */
#ifndef BE6L_BOOTSTRAP_MOUNT_H
#define BE6L_BOOTSTRAP_MOUNT_H
static inline int be6l_bootstrap_fs_matches(int status, unsigned long actual,
					  unsigned long required)
{
	return status == 0 && actual == required;
}
#endif
