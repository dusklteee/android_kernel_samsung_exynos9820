#include <linux/types.h>

#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "policy/allowlist.h"

// Permission check functions
bool only_manager(void)
{
	return is_manager();
}

bool only_root(void)
{
	return current_uid().val == 0;
}

bool manager_or_root(void)
{
	return current_uid().val == 0 || is_manager();
}

bool always_allow(void)
{
	return true; // No permission check
}

bool allowed_for_su(void)
{
	bool is_allowed = is_manager() || ksu_is_allow_uid_for_current(current_uid().val);
	return is_allowed;
}

#ifdef CONFIG_KSU_SUSFS
/* Bridge for susfs (fs/susfs.c): its prctl control channel must honor the
 * signature-validated manager app too, not only root -- mirroring upstream
 * susfs which gates CMD_SUSFS_* with (from_root || from_manager). is_manager()
 * is a static inline in manager_identity.h, so expose it as a real symbol. */
bool susfs_is_manager(void)
{
	return is_manager();
}
#endif
