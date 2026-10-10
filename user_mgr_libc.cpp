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

#include <algorithm>
#include <cstring>
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

int zephyrGetPassword(const char* username, uint32_t usernameLen, char* out,
                      uint32_t outLen)
{
    if ((out == nullptr) || (outLen == 0))
    {
        return -1;
    }

    const std::string password =
        phosphor::user::UserMgr::zephyrGetPassword(toString(username, usernameLen));
    if (password.empty())
    {
        return -1;
    }

    const size_t copyLen =
        std::min(static_cast<size_t>(outLen - 1), password.size());
    std::memcpy(out, password.data(), copyLen);
    out[copyLen] = '\0';
    return static_cast<int>(copyLen);
}

#ifdef CONFIG_PHOSPHOR_USER_MANAGER_SELFTEST
int zephyrTestSetPasswordAge(const char* username, uint32_t usernameLen,
                             int64_t pwdUpdateTime, int64_t expireTime)
{
    return phosphor::user::UserMgr::zephyrSetPasswordAge(
        toString(username, usernameLen), pwdUpdateTime, expireTime);
}
#endif
