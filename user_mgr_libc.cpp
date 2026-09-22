/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * C entry points of the Zephyr local user store (see user_mgr_libc.h).
 *
 * Only callers that need the C ABI live here: wolfSSH's wsUserAuth callback
 * and future C consumers.  C++ services should call the UserMgr statics
 * declared in user_mgr.hpp directly.
 */

#include "user_mgr_libc.h"

#include "user_mgr.hpp"

#include <string>

namespace
{
std::string toString(const char* text, uint32_t length)
{
    return std::string((text != nullptr) ? text : "", length);
}
} // namespace

int zephyrAuthenticate(const char* username, uint32_t usernameLen,
                       const char* password, uint32_t passwordLen,
                       const char* loginSource)
{
    return phosphor::user::UserMgr::zephyrAuthenticate(
        toString(username, usernameLen), toString(password, passwordLen),
        (loginSource != nullptr) ? loginSource : "web");
}

int zephyrUpdatePassword(const char* username, uint32_t usernameLen,
                         const char* newPassword, uint32_t newPasswordLen)
{
    return phosphor::user::UserMgr::zephyrUpdatePassword(
        toString(username, usernameLen), toString(newPassword, newPasswordLen));
}

#ifdef CONFIG_PHOSPHOR_USER_MANAGER_SELFTEST
int zephyrTestSetPasswordAge(const char* username, uint32_t usernameLen,
                             int64_t pwdUpdateTime, int64_t expireTime)
{
    return phosphor::user::UserMgr::zephyrSetPasswordAge(
        toString(username, usernameLen), pwdUpdateTime, expireTime);
}
#endif
