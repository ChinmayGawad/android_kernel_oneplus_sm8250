#include <linux/types.h>

#include "supercall/internal.h"
#include "manager/manager_identity.h"
#include "manager/throne_tracker.h"
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
	if (!ksu_is_manager_appid_valid()) {
		track_throne(false);
	}

	bool is_allowed = is_manager() || ksu_is_allow_uid_for_current(current_uid().val);

	if (!is_allowed && !ksu_is_manager_appid_valid()) {
		pr_warn("KSU bootstrap: manager not set, allowing uid %d through\n",
			current_uid().val);
		return true;
	}

	return is_allowed;
}
