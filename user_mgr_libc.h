/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * C entry points other services (bmcweb's PAM shim, wolfSSH, IPMI) use to
 * authenticate against the Zephyr local user store.  The return codes mirror
 * the PAM subset those callers already use.
 */
#pragma once

#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif

#define ZEPHYR_PAM_SUCCESS 0
#define ZEPHYR_PAM_MAXTRIES 6
#define ZEPHYR_PAM_USER_UNKNOWN 10
#define ZEPHYR_PAM_NEW_AUTHTOK_REQD 12
#define ZEPHYR_PAM_AUTHTOK_ERR 17

/*
 * Verify username/password against CONFIG_FS_ROOT_OVERLAY"/etc/users.json".
 * loginSource is informational ("web", "ipmi", "ssh").
 * Returns one of the ZEPHYR_PAM_* codes above.
 */
int zephyrAuthenticate(const char* username, uint32_t usernameLen,
                       const char* password, uint32_t passwordLen,
                       const char* loginSource);

/*
 * Change a local user's password (policy checked, persisted in users.json).
 * Returns ZEPHYR_PAM_SUCCESS or a ZEPHYR_PAM_* error code.
 */
int zephyrUpdatePassword(const char* username, uint32_t usernameLen,
                         const char* newPassword, uint32_t newPasswordLen);

#ifdef CONFIG_PHOSPHOR_USER_MANAGER_SELFTEST
/*
 * Self test only: rewind a user's password age (pwdUpdateTime / expireTime)
 * so the expiration path can be exercised without /etc/shadow.  Returns 0 on
 * success, -1 for an unknown user or a store write failure.
 */
int zephyrTestSetPasswordAge(const char* username, uint32_t usernameLen,
                             int64_t pwdUpdateTime, int64_t expireTime);
#endif

#ifdef __cplusplus
}
#endif
