/*
// Copyright (c) 2018 Intel Corporation
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
*/

#include "config.h"

#include "user_mgr.hpp"

#include "file.hpp"
#include "shadowlock.hpp"
#include "users.hpp"
#ifdef __ZEPHYR__
#include "user_mgr_libc.h"
#endif

#include <grp.h>
#include <pwd.h>
#ifndef __ZEPHYR__
#include <shadow.h>
#endif
#include <sys/types.h>
#include <sys/wait.h>
#include <time.h>
#include <unistd.h>

#include <boost/algorithm/string/split.hpp>
#include <phosphor-logging/elog-errors.hpp>
#include <phosphor-logging/elog.hpp>
#include <phosphor-logging/lg2.hpp>
#include <xyz/openbmc_project/Common/error.hpp>
#include <xyz/openbmc_project/User/Common/error.hpp>

#include <algorithm>
#include <array>
#include <ctime>
#include <fstream>
#include <numeric>
#include <regex>
#include <span>
#include <string>
#include <string_view>
#include <vector>
#ifdef __ZEPHYR__
#include <nlohmann/json.hpp>
#include <openssl/aes.h>
#include <openssl/bio.h>
#include <openssl/buffer.h>
#include <openssl/evp.h>
#include <openssl/sha.h>

#include <cstdint>
#include <filesystem>
#include <sstream>
#endif

namespace phosphor
{
namespace user
{

static constexpr const char* passwdFileName = "/etc/passwd";
static constexpr size_t ipmiMaxUserNameLen = 16;
static constexpr size_t systemMaxUserNameLen = 30;
static constexpr const char* grpSsh = "ssh";
static constexpr int success = 0;
static constexpr int failure = -1;

// pam modules related
static constexpr const char* pamTally2 = "pam_tally2.so";
static constexpr const char* pamCrackLib = "pam_cracklib.so";
static constexpr const char* pamPWHistory = "pam_pwhistory.so";
static constexpr const char* minPasswdLenProp = "minlen";
static constexpr const char* remOldPasswdCount = "remember";
static constexpr const char* maxFailedAttempt = "deny";
static constexpr const char* unlockTimeout = "unlock_time";
static constexpr const char* defaultPamPasswdConfigFile =
    "/etc/pam.d/common-password";
static constexpr const char* defaultPamAuthConfigFile =
    "/etc/pam.d/common-auth";

// Object Manager related
static constexpr const char* ldapMgrObjBasePath =
    "/xyz/openbmc_project/user/ldap";

// Object Mapper related
static constexpr const char* objMapperService =
    "xyz.openbmc_project.ObjectMapper";
static constexpr const char* objMapperPath =
    "/xyz/openbmc_project/object_mapper";
static constexpr const char* objMapperInterface =
    "xyz.openbmc_project.ObjectMapper";

using namespace phosphor::logging;
using InsufficientPermission =
    sdbusplus::xyz::openbmc_project::Common::Error::InsufficientPermission;
using InternalFailure =
    sdbusplus::xyz::openbmc_project::Common::Error::InternalFailure;
using InvalidArgument =
    sdbusplus::xyz::openbmc_project::Common::Error::InvalidArgument;
using UserNameExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameExists;
using UserNameDoesNotExist =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameDoesNotExist;
using UserNameGroupFail =
    sdbusplus::xyz::openbmc_project::User::Common::Error::UserNameGroupFail;
using NoResource =
    sdbusplus::xyz::openbmc_project::User::Common::Error::NoResource;
using Argument = xyz::openbmc_project::Common::InvalidArgument;
using GroupNameExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameExists;
using GroupNameDoesNotExists =
    sdbusplus::xyz::openbmc_project::User::Common::Error::GroupNameDoesNotExist;

namespace
{

// The hardcoded groups in OpenBMC projects
constexpr std::array<const char*, 4> predefinedGroups = {"web", "redfish",
                                                         "ipmi", "ssh"};

// These prefixes are for Dynamic Redfish authorization. See
// https://github.com/openbmc/docs/blob/master/designs/redfish-authorization.md

// Base role and base privileges are added by Redfish implementation (e.g.,
// BMCWeb) at compile time
constexpr std::array<const char*, 4> allowedGroupPrefix = {
    "openbmc_rfr_",  // OpenBMC Redfish Base Role
    "openbmc_rfp_",  // OpenBMC Redfish Base Privileges
    "openbmc_orfr_", // OpenBMC Redfish OEM Role
    "openbmc_orfp_", // OpenBMC Redfish OEM Privileges
};

void checkAndThrowsForGroupChangeAllowed(const std::string& groupName)
{
    bool allowed = false;
    for (std::string_view prefix : allowedGroupPrefix)
    {
        if (groupName.starts_with(prefix))
        {
            allowed = true;
            break;
        }
    }
    if (!allowed)
    {
        lg2::error("Group name '{GROUP}' is not in the allowed list", "GROUP",
                   groupName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                              Argument::ARGUMENT_VALUE(groupName.c_str()));
    }
}

} // namespace

std::string getCSVFromVector(std::span<const std::string> vec)
{
    if (vec.empty())
    {
        return "";
    }
    return std::accumulate(std::next(vec.begin()), vec.end(), vec[0],
                           [](std::string&& val, std::string_view element) {
                               val += ',';
                               val += element;
                               return val;
                           });
}

bool removeStringFromCSV(std::string& csvStr, const std::string& delStr)
{
    std::string::size_type delStrPos = csvStr.find(delStr);
    if (delStrPos != std::string::npos)
    {
        // need to also delete the comma char
        if (delStrPos == 0)
        {
            csvStr.erase(delStrPos, delStr.size() + 1);
        }
        else
        {
            csvStr.erase(delStrPos - 1, delStr.size() + 1);
        }
        return true;
    }
    return false;
}

bool UserMgr::isUserExist(const std::string& userName)
{
    if (userName.empty())
    {
        lg2::error("User name is empty");
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Null"));
    }
    if (usersList.find(userName) == usersList.end())
    {
        return false;
    }
    return true;
}

void UserMgr::throwForUserDoesNotExist(const std::string& userName)
{
    if (!isUserExist(userName))
    {
        lg2::error("User '{USERNAME}' does not exist", "USERNAME", userName);
        elog<UserNameDoesNotExist>();
    }
}

void UserMgr::checkAndThrowForDisallowedGroupCreation(
    const std::string& groupName)
{
    if (groupName.size() > maxSystemGroupNameLength ||
        !std::regex_match(groupName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        lg2::error("Invalid group name '{GROUP}'", "GROUP", groupName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Group Name"),
                              Argument::ARGUMENT_VALUE(groupName.c_str()));
    }
    checkAndThrowsForGroupChangeAllowed(groupName);
}

void UserMgr::throwForUserExists(const std::string& userName)
{
    if (isUserExist(userName))
    {
        lg2::error("User '{USERNAME}' already exists", "USERNAME", userName);
        elog<UserNameExists>();
    }
}

void UserMgr::throwForUserNameConstraints(
    const std::string& userName, const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (userName.length() > ipmiMaxUserNameLen)
        {
            lg2::error("User '{USERNAME}' exceeds IPMI username length limit "
                       "({LENGTH} > {LIMIT})",
                       "USERNAME", userName, "LENGTH", userName.length(),
                       "LIMIT", ipmiMaxUserNameLen);
            elog<UserNameGroupFail>(
                xyz::openbmc_project::User::Common::UserNameGroupFail::REASON(
                    "IPMI length"));
        }
    }
    if (userName.length() > systemMaxUserNameLen)
    {
        lg2::error("User '{USERNAME}' exceeds system username length limit "
                   "({LENGTH} > {LIMIT})",
                   "USERNAME", userName, "LENGTH", userName.length(), "LIMIT",
                   systemMaxUserNameLen);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid length"));
    }
    if (!std::regex_match(userName.c_str(),
                          std::regex("[a-zA-z_][a-zA-Z_0-9]*")))
    {
        lg2::error("Invalid username '{USERNAME}'", "USERNAME", userName);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("User name"),
                              Argument::ARGUMENT_VALUE("Invalid data"));
    }
}

void UserMgr::throwForMaxGrpUserCount(
    const std::vector<std::string>& groupNames)
{
    if (std::find(groupNames.begin(), groupNames.end(), "ipmi") !=
        groupNames.end())
    {
        if (getIpmiUsersCount() >= ipmiMaxUsers)
        {
            lg2::error("IPMI user limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "IPMI user limit reached"));
        }
    }
    else
    {
        if (usersList.size() > 0 && (usersList.size() - getIpmiUsersCount()) >=
                                        (maxSystemUsers - ipmiMaxUsers))
        {
            lg2::error("Non-ipmi User limit reached");
            elog<NoResource>(
                xyz::openbmc_project::User::Common::NoResource::REASON(
                    "Non-ipmi user limit reached"));
        }
    }
    return;
}

void UserMgr::throwForInvalidPrivilege(const std::string& priv)
{
    if (!priv.empty() &&
        (std::find(privMgr.begin(), privMgr.end(), priv) == privMgr.end()))
    {
        lg2::error("Invalid privilege '{PRIVILEGE}'", "PRIVILEGE", priv);
        elog<InvalidArgument>(Argument::ARGUMENT_NAME("Privilege"),
                              Argument::ARGUMENT_VALUE(priv.c_str()));
    }
}

void UserMgr::throwForInvalidGroups(const std::vector<std::string>& groupNames)
{
    for (auto& group : groupNames)
    {
        if (std::find(groupsMgr.begin(), groupsMgr.end(), group) ==
            groupsMgr.end())
        {
            lg2::error("Invalid Group Name '{GROUPNAME}'", "GROUPNAME", group);
            elog<InvalidArgument>(Argument::ARGUMENT_NAME("GroupName"),
                                  Argument::ARGUMENT_VALUE(group.c_str()));
        }
    }
}

#ifdef __ZEPHYR__
// ---------------------------------------------------------------------------
// Zephyr local user store.
//
// Zephyr has no /etc/passwd|shadow|group, no NSS and no PAM.  Reference:
// origin/zephyr keeps the account data in a users.json file plus a small
// SHA256/AES password store; the same approach is used here, but the Linux
// code paths above stay untouched.
//
// File layout (compatible with origin/zephyr's config/users.json):
//   userList: [ { userId, userName, passWordHASH, passWordAES, priv,
//                 groupList, expireTime, enable, pwdUpdateTime,
//                 lockStatus, failTimes, lockTime }, ... ]
//   userRule: { gExpireTime, minlen, remember, deny, unlock_time, autoLock,
//               newUserId }
//               (policy keys reuse the Linux PAM argument names)
//   createdGroups: [ locally created groups ] (/etc/group equivalent)
// ---------------------------------------------------------------------------
namespace
{
using json = nlohmann::json;

constexpr const char* zephyrUsersFile =
    CONFIG_FS_ROOT_OVERLAY "/etc/users.json";
constexpr const char* zephyrAesKey = "thisisaverysecretkey012345678912";
constexpr const char* zephyrDefaultPassword = "0penBmc";
constexpr int64_t zephyrNeverExpireDays = 99999;
constexpr int zephyrDefaultMinPasswordLength = 8;
constexpr int zephyrDefaultRememberOldPasswordTimes = 0;
constexpr int zephyrDefaultLockDeny = 3;
constexpr int zephyrDefaultUnlockTime = 900;
constexpr uint64_t zephyrFirstUserId = 1000;
constexpr int64_t zephyrSecondsPerDay = 24 * 60 * 60;

// users.json keys.  The on-disk names stay compatible with origin/zephyr's
// config/users.json; always use these constants instead of raw string
// literals so read/write sides cannot drift apart.
// NOTE: the Linux PAM argument constants above (e.g. unlockTimeout ==
// "unlock_time") are a different layer and must not be confused with these
// users.json keys.
namespace zephyrJson
{
// top level
constexpr const char* userList = "userList";
constexpr const char* userRule = "userRule";
// Locally created groups (the /etc/group equivalent: group existence).
constexpr const char* createdGroups = "createdGroups";
// user entry (userList[])
constexpr const char* userId = "userId";
constexpr const char* userName = "userName";
constexpr const char* passWordHash = "passWordHASH";
constexpr const char* passWordAes = "passWordAES";
constexpr const char* priv = "priv";
constexpr const char* userGroupList = "groupList";
constexpr const char* expireTime = "expireTime";
constexpr const char* enable = "enable";
constexpr const char* pwdUpdateTime = "pwdUpdateTime";
constexpr const char* lockStatus = "lockStatus";
constexpr const char* failTimes = "failTimes";
constexpr const char* lockTime = "lockTime";
// userRule
constexpr const char* gExpireTime = "gExpireTime";
// The account policy keys reuse the Linux PAM argument constants instead of
// private json key names:
//   minPasswdLenProp ("minlen")     <- minPasswordLength
//   remOldPasswdCount ("remember")  <- rememberOldPasswordTimes
//   maxFailedAttempt ("deny")       <- maxLoginAttemptBeforeLockout
//   unlockTimeout ("unlock_time")   <- accountUnlockTimeout
constexpr const char* autoLock = "autoLock";
constexpr const char* newUserId = "newUserId";
} // namespace zephyrJson

json zephyrStore;

std::string zephyrSha256(const std::string& str)
{
    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, str.c_str(), str.size());
    SHA256_Final(hash, &ctx);

    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++)
    {
        ss << std::hex << std::setw(2) << std::setfill('0')
           << static_cast<int>(hash[i]);
    }
    return ss.str();
}

std::string zephyrBase64Encode(const unsigned char* data, int len)
{
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    BIO_write(bio, data, len);
    BIO_flush(bio);

    BUF_MEM* bufferPtr = nullptr;
    BIO_get_mem_ptr(bio, &bufferPtr);
    std::string result(bufferPtr->data, bufferPtr->length);
    BIO_free_all(bio);
    return result;
}

std::string zephyrBase64Decode(const std::string& encoded)
{
    std::vector<char> decoded(encoded.size());
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* bio = BIO_new_mem_buf(encoded.data(), encoded.size());
    bio = BIO_push(b64, bio);
    BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
    int len = BIO_read(bio, decoded.data(), decoded.size());
    BIO_free_all(bio);
    return (len > 0) ? std::string(decoded.data(), len) : std::string{};
}

std::string zephyrAesEncrypt(const std::string& plaintext)
{
    std::string key(zephyrAesKey);
    if (key.size() != 32)
    {
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        return {};
    }

    std::vector<unsigned char> ciphertext(plaintext.size() + 16);
    int len = 0;
    int finalLen = 0;
    std::string result;
    if ((EVP_EncryptInit_ex(
             ctx, EVP_aes_256_ecb(), nullptr,
             reinterpret_cast<const unsigned char*>(key.data()), nullptr) == 1) &&
        (EVP_EncryptUpdate(
             ctx, ciphertext.data(), &len,
             reinterpret_cast<const unsigned char*>(plaintext.data()),
             plaintext.size()) == 1) &&
        (EVP_EncryptFinal_ex(ctx, ciphertext.data() + len, &finalLen) == 1))
    {
        result = zephyrBase64Encode(ciphertext.data(), len + finalLen);
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

// TODO(zephyr-unhandled): used by the password verification path once the
// web/ssh/IPMI authentication is wired to the local store.
[[maybe_unused]] std::string zephyrAesDecrypt(const std::string& ciphertextB64)
{
    std::string key(zephyrAesKey);
    std::string ciphertext = zephyrBase64Decode(ciphertextB64);
    if ((key.size() != 32) || ciphertext.empty() ||
        (ciphertext.size() % 16 != 0))
    {
        return {};
    }

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (ctx == nullptr)
    {
        return {};
    }

    std::vector<unsigned char> plaintext(ciphertext.size() + 16);
    int len = 0;
    int finalLen = 0;
    std::string result;
    if ((EVP_DecryptInit_ex(
             ctx, EVP_aes_256_ecb(), nullptr,
             reinterpret_cast<const unsigned char*>(key.data()), nullptr) == 1) &&
        (EVP_DecryptUpdate(
             ctx, plaintext.data(), &len,
             reinterpret_cast<const unsigned char*>(ciphertext.data()),
             ciphertext.size()) == 1) &&
        (EVP_DecryptFinal_ex(ctx, plaintext.data() + len, &finalLen) == 1))
    {
        result.assign(reinterpret_cast<char*>(plaintext.data()), len + finalLen);
    }
    EVP_CIPHER_CTX_free(ctx);
    return result;
}

json& zephyrUserRule()
{
    if (!zephyrStore.contains(zephyrJson::userRule) ||
        !zephyrStore[zephyrJson::userRule].is_object())
    {
        zephyrStore[zephyrJson::userRule] = json::object();
    }
    json& rule = zephyrStore[zephyrJson::userRule];
    if (!rule.contains(zephyrJson::gExpireTime))
    {
        rule[zephyrJson::gExpireTime] = zephyrNeverExpireDays;
    }
    if (!rule.contains(minPasswdLenProp))
    {
        rule[minPasswdLenProp] = zephyrDefaultMinPasswordLength;
    }
    if (!rule.contains(remOldPasswdCount))
    {
        rule[remOldPasswdCount] = zephyrDefaultRememberOldPasswordTimes;
    }
    if (!rule.contains(maxFailedAttempt))
    {
        rule[maxFailedAttempt] = zephyrDefaultLockDeny;
    }
    if (!rule.contains(unlockTimeout))
    {
        rule[unlockTimeout] = zephyrDefaultUnlockTime;
    }
    if (!rule.contains(zephyrJson::autoLock))
    {
        rule[zephyrJson::autoLock] = true;
    }
    if (!rule.contains(zephyrJson::newUserId))
    {
        rule[zephyrJson::newUserId] = zephyrFirstUserId;
    }
    return rule;
}

bool zephyrSaveStore()
{
    std::ofstream out(zephyrUsersFile, std::ios::out | std::ios::trunc);
    if (!out.is_open())
    {
        // TODO(zephyr-unhandled): mkdir/seed the overlay directory if the
        // image does not provide CONFIG_FS_ROOT_OVERLAY"/etc".
        // The failure is logged once by the operation level caller, so no
        // extra log here (avoids duplicate messages like Linux's
        // executeCmd() + caller pair).
        return false;
    }
    out << zephyrStore.dump(4);
    out.flush();
    return !out.fail();
}

void zephyrLoadStore()
{
    zephyrStore = json::object();
    zephyrStore[zephyrJson::userList] = json::array();
    zephyrUserRule();

    std::ifstream in(zephyrUsersFile, std::ios::in);
    if (!in.is_open())
    {
        // First boot: no account is pre-seeded, create the (empty) store.
        if (!zephyrSaveStore())
        {
            lg2::error("Unable to create local user store {FILENAME}",
                       "FILENAME", zephyrUsersFile);
        }
        return;
    }
    try
    {
        zephyrStore = json::parse(std::string(std::istreambuf_iterator<char>(in),
                                              std::istreambuf_iterator<char>()));
        if (!zephyrStore.is_object())
        {
            lg2::error("Invalid top level in {FILENAME}, resetting",
                       "FILENAME", zephyrUsersFile);
            zephyrStore = json::object();
        }
        if (!zephyrStore.contains(zephyrJson::userList) ||
            !zephyrStore[zephyrJson::userList].is_array())
        {
            zephyrStore[zephyrJson::userList] = json::array();
        }
        zephyrUserRule();
    }
    catch (const std::exception& e)
    {
        lg2::error("Failed to parse {FILENAME}: {ERR}", "FILENAME",
                   zephyrUsersFile, "ERR", e);
        zephyrStore = json::object();
        zephyrStore[zephyrJson::userList] = json::array();
        zephyrUserRule();
    }
}

// Non-throwing typed readers.  A malformed users.json must not let a
// nlohmann::json exception escape into the sd-bus callbacks (those only
// translate InternalFailure), so these log and fall back to the default,
// mirroring origin/zephyr's try/catch(json::exception) handling.
int64_t zephyrJsonInt(const json& obj, const char* key, int64_t defaultValue)
{
    try
    {
        return obj.value(key, defaultValue);
    }
    catch (const json::exception& e)
    {
        lg2::error("Invalid '{KEY}' in local user store: {ERR}", "KEY", key,
                   "ERR", e);
        return defaultValue;
    }
}

bool zephyrJsonBool(const json& obj, const char* key, bool defaultValue)
{
    try
    {
        return obj.value(key, defaultValue);
    }
    catch (const json::exception& e)
    {
        lg2::error("Invalid '{KEY}' in local user store: {ERR}", "KEY", key,
                   "ERR", e);
        return defaultValue;
    }
}

std::string zephyrJsonString(const json& obj, const char* key,
                             const std::string& defaultValue = std::string{})
{
    try
    {
        return obj.value(key, defaultValue);
    }
    catch (const json::exception& e)
    {
        lg2::error("Invalid '{KEY}' in local user store: {ERR}", "KEY", key,
                   "ERR", e);
        return defaultValue;
    }
}

json* zephyrFindUser(const std::string& userName)
{
    for (auto& user : zephyrStore[zephyrJson::userList])
    {
        if (!user.is_object())
        {
            continue;
        }
        if (zephyrJsonString(user, zephyrJson::userName) == userName)
        {
            return &user;
        }
    }
    return nullptr;
}

std::vector<std::string> zephyrStringList(const json& value)
{
    std::vector<std::string> result;
    if (value.is_array())
    {
        for (const auto& item : value)
        {
            if (item.is_string())
            {
                result.emplace_back(item.get<std::string>());
            }
        }
    }
    return result;
}

bool zephyrAddUser(const std::string& userName,
                   const std::vector<std::string>& groupNames,
                   const std::string& priv, bool enabled)
{
    if (zephyrFindUser(userName) != nullptr)
    {
        return false;
    }
    json& rule = zephyrUserRule();
    uint64_t userId = static_cast<uint64_t>(zephyrJsonInt(
        rule, zephyrJson::newUserId, static_cast<int64_t>(zephyrFirstUserId)));
    rule[zephyrJson::newUserId] = userId + 1;

    json user;
    user[zephyrJson::userId] = userId;
    user[zephyrJson::userName] = userName;
    // TODO(zephyr-unhandled): no password setting D-Bus API / PAM in Zephyr,
    // new accounts get the factory default password until the account
    // management UI provides a local password path.
    user[zephyrJson::passWordHash] = zephyrSha256(zephyrDefaultPassword);
    user[zephyrJson::passWordAes] = zephyrAesEncrypt(zephyrDefaultPassword);
    user[zephyrJson::priv] = priv;
    user[zephyrJson::userGroupList] = groupNames;
    user[zephyrJson::expireTime] =
        zephyrJsonInt(rule, zephyrJson::gExpireTime, zephyrNeverExpireDays);
    user[zephyrJson::enable] = enabled;
    user[zephyrJson::pwdUpdateTime] = static_cast<int64_t>(std::time(nullptr));
    user[zephyrJson::lockStatus] = false;
    user[zephyrJson::failTimes] = 0;
    user[zephyrJson::lockTime] = static_cast<uint64_t>(std::time(nullptr));
    zephyrStore[zephyrJson::userList].push_back(std::move(user));
    return zephyrSaveStore();
}

bool zephyrRemoveUser(const std::string& userName)
{
    auto& users = zephyrStore[zephyrJson::userList];
    for (auto it = users.begin(); it != users.end(); ++it)
    {
        if (!it->is_object())
        {
            continue;
        }
        if (zephyrJsonString(*it, zephyrJson::userName) == userName)
        {
            users.erase(it);
            return zephyrSaveStore();
        }
    }
    return false;
}

bool zephyrRenameUser(const std::string& userName,
                      const std::string& newUserName)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    (*user)[zephyrJson::userName] = newUserName;
    return zephyrSaveStore();
}

bool zephyrSetUserGroups(const std::string& userName,
                         const std::vector<std::string>& groupNames)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    (*user)[zephyrJson::userGroupList] = groupNames;
    return zephyrSaveStore();
}

bool zephyrSetUserPrivilege(const std::string& userName,
                            const std::string& priv)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    (*user)[zephyrJson::priv] = priv;
    return zephyrSaveStore();
}

bool zephyrSetUserEnabled(const std::string& userName, bool enabled)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    (*user)[zephyrJson::enable] = enabled;
    return zephyrSaveStore();
}

bool zephyrGetUserBool(const std::string& userName, const char* key,
                       bool defaultValue)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return defaultValue;
    }
    return zephyrJsonBool(*user, key, defaultValue);
}

int zephyrGetFailCount(const std::string& userName)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return -1;
    }
    return static_cast<int>(
        zephyrJsonInt(*user, zephyrJson::failTimes, 0));
}

bool zephyrSetFailCount(const std::string& userName, int count)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    (*user)[zephyrJson::failTimes] = count;
    (*user)[zephyrJson::lockStatus] = false;
    return zephyrSaveStore();
}

int64_t zephyrGetLockTime(const std::string& userName)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return 0;
    }
    return zephyrJsonInt(*user, zephyrJson::lockTime, 0);
}

bool zephyrAddGroup(const std::string& groupName)
{
    if (!zephyrStore.contains(zephyrJson::createdGroups) ||
        !zephyrStore[zephyrJson::createdGroups].is_array())
    {
        zephyrStore[zephyrJson::createdGroups] = json::array();
    }
    auto& groups = zephyrStore[zephyrJson::createdGroups];
    if (std::find(groups.begin(), groups.end(), groupName) != groups.end())
    {
        return true;
    }
    groups.push_back(groupName);
    return zephyrSaveStore();
}

bool zephyrRemoveGroup(const std::string& groupName)
{
    // Groups are local state only; remove it from the store and drop the
    // membership from every local account.
    const auto removeFromArray = [&groupName](json& array) {
        if (array.is_array())
        {
            array.erase(std::remove(array.begin(), array.end(), groupName),
                        array.end());
        }
    };
    if (zephyrStore.contains(zephyrJson::createdGroups))
    {
        removeFromArray(zephyrStore[zephyrJson::createdGroups]);
    }
    for (auto& user : zephyrStore[zephyrJson::userList])
    {
        if (!user.is_object())
        {
            continue;
        }
        auto groupNames =
            zephyrStringList(user.value(zephyrJson::userGroupList, json()));
        const auto it =
            std::remove(groupNames.begin(), groupNames.end(), groupName);
        groupNames.erase(it, groupNames.end());
        user[zephyrJson::userGroupList] = groupNames;
    }
    return zephyrSaveStore();
}

std::vector<std::string> zephyrCollectGroups()
{
    std::vector<std::string> groups = {predefinedGroups.begin(),
                                       predefinedGroups.end()};
    // Linux enumerates /etc/group and keeps only the dynamic Redfish groups
    // (names starting with allowedGroupPrefix).  The local store plays the
    // role of /etc/group here, so apply the same prefix filter.
    // createdGroups is deduplicated on write (zephyrAddGroup) and cannot
    // collide with the predefined groups (createGroup validates the name), so
    // no post-sort is needed; deduplicate while appending instead, keeping the
    // Linux order (predefined first, then the group store order).
    const auto appendAllowedGroup = [&groups](const std::string& group) {
        if (std::find(groups.begin(), groups.end(), group) != groups.end())
        {
            return;
        }
        for (std::string_view prefix : allowedGroupPrefix)
        {
            if (group.starts_with(prefix))
            {
                groups.emplace_back(group);
                return;
            }
        }
    };
    if (zephyrStore.contains(zephyrJson::createdGroups) &&
        zephyrStore[zephyrJson::createdGroups].is_array())
    {
        for (const auto& group : zephyrStore[zephyrJson::createdGroups])
        {
            if (group.is_string())
            {
                appendAllowedGroup(group.get<std::string>());
            }
        }
    }
    return groups;
}

// ---------------------------------------------------------------------------
// Local (users.json) authentication used by other services through the C API
// in user_mgr_libc.h.  Replaces the Linux PAM stack on Zephyr.
// ---------------------------------------------------------------------------
int zephyrLocalAuthenticate(const std::string& userName,
                            const std::string& password,
                            const std::string& loginSource)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return ZEPHYR_PAM_USER_UNKNOWN;
    }
    if (!zephyrJsonBool(*user, zephyrJson::enable, false))
    {
        lg2::warning("Local user '{USERNAME}' is disabled ({SOURCE})",
                     "USERNAME", userName, "SOURCE", loginSource);
        return ZEPHYR_PAM_USER_UNKNOWN;
    }

    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    const int64_t deny =
        zephyrJsonInt(zephyrUserRule(), maxFailedAttempt, zephyrDefaultLockDeny);
    const int64_t unlockTime =
        zephyrJsonInt(zephyrUserRule(), unlockTimeout, zephyrDefaultUnlockTime);
    int64_t failTimes = zephyrJsonInt(*user, zephyrJson::failTimes, 0);
    const int64_t lockTime = zephyrJsonInt(*user, zephyrJson::lockTime, 0);
    if ((deny > 0) && (failTimes >= deny) && ((lockTime + unlockTime) > now))
    {
        lg2::warning("Local user '{USERNAME}' is locked out ({SOURCE})",
                     "USERNAME", userName, "SOURCE", loginSource);
        return ZEPHYR_PAM_MAXTRIES;
    }

    const int64_t expireTime =
        zephyrJsonInt(*user, zephyrJson::expireTime, zephyrNeverExpireDays);
    const int64_t pwdUpdateTime =
        zephyrJsonInt(*user, zephyrJson::pwdUpdateTime, 0);
    const bool passwordExpired =
        (expireTime < zephyrNeverExpireDays) &&
        (((now - pwdUpdateTime) / zephyrSecondsPerDay) > expireTime);

    const std::string storedHash =
        zephyrJsonString(*user, zephyrJson::passWordHash);
    if (storedHash.empty() || (storedHash != zephyrSha256(password)))
    {
        ++failTimes;
        (*user)[zephyrJson::failTimes] = failTimes;
        (*user)[zephyrJson::lockTime] = static_cast<uint64_t>(now);
        (*user)[zephyrJson::lockStatus] = (deny > 0) && (failTimes >= deny);
        zephyrSaveStore();
        lg2::warning("Authentication failed for '{USERNAME}' ({SOURCE}), "
                     "failed attempts {COUNT}",
                     "USERNAME", userName, "SOURCE", loginSource, "COUNT",
                     failTimes);
        return ZEPHYR_PAM_AUTHTOK_ERR;
    }

    // Successful login clears the lockout counters.
    (*user)[zephyrJson::failTimes] = 0;
    (*user)[zephyrJson::lockStatus] = false;
    zephyrSaveStore();
    return passwordExpired ? ZEPHYR_PAM_NEW_AUTHTOK_REQD : ZEPHYR_PAM_SUCCESS;
}

int zephyrLocalUpdatePassword(const std::string& userName,
                              const std::string& newPassword)
{
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return ZEPHYR_PAM_USER_UNKNOWN;
    }

    const int64_t minLen = zephyrJsonInt(zephyrUserRule(), minPasswdLenProp,
                                         zephyrDefaultMinPasswordLength);
    if (static_cast<int64_t>(newPassword.size()) < minLen)
    {
        lg2::error("New password for '{USERNAME}' is shorter than {MINLEN}",
                   "USERNAME", userName, "MINLEN", minLen);
        return ZEPHYR_PAM_AUTHTOK_ERR;
    }

    (*user)[zephyrJson::passWordHash] = zephyrSha256(newPassword);
    (*user)[zephyrJson::passWordAes] = zephyrAesEncrypt(newPassword);
    (*user)[zephyrJson::pwdUpdateTime] = static_cast<int64_t>(std::time(nullptr));
    (*user)[zephyrJson::failTimes] = 0;
    (*user)[zephyrJson::lockStatus] = false;
    return zephyrSaveStore() ? ZEPHYR_PAM_SUCCESS : ZEPHYR_PAM_AUTHTOK_ERR;
}
} // namespace

std::vector<std::string> UserMgr::readAllGroupsOnSystem()
{
    return zephyrCollectGroups();
}
#else
std::vector<std::string> UserMgr::readAllGroupsOnSystem()
{
    std::vector<std::string> allGroups = {predefinedGroups.begin(),
                                          predefinedGroups.end()};
    // rewinds to the beginning of the group database
    setgrent();
    struct group* gr = getgrent();
    while (gr != nullptr)
    {
        std::string group(gr->gr_name);
        for (std::string_view prefix : allowedGroupPrefix)
        {
            if (group.starts_with(prefix))
            {
                allGroups.push_back(gr->gr_name);
            }
        }
        gr = getgrent();
    }
    // close the group database
    endgrent();
    return allGroups;
}
#endif

void UserMgr::createUser(std::string userName,
                         std::vector<std::string> groupNames, std::string priv,
                         bool enabled)
{
    throwForInvalidPrivilege(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserExists(userName);
    throwForUserNameConstraints(userName, groupNames);
    throwForMaxGrpUserCount(groupNames);

    std::string groups = getCSVFromVector(groupNames);
    bool sshRequested = removeStringFromCSV(groups, grpSsh);

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserAdd(userName.c_str(), groups.c_str(), sshRequested, enabled);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to create new user '{USERNAME}'", "USERNAME",
                   userName);
        elog<InternalFailure>();
    }

    // Add the users object before sending out the signal
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= userName;
    std::string userObj(tempObjPath);
    std::sort(groupNames.begin(), groupNames.end());
    usersList.emplace(
        userName, std::make_unique<phosphor::user::Users>(
                      bus, userObj.c_str(), groupNames, priv, enabled, *this));

    lg2::info("User '{USERNAME}' created successfully", "USERNAME", userName);
    return;
}

void UserMgr::deleteUser(std::string userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    try
    {
        executeUserDelete(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Delete User '{USERNAME}' failed", "USERNAME", userName);
        elog<InternalFailure>();
    }

    usersList.erase(userName);

    lg2::info("User '{USERNAME}' deleted successfully", "USERNAME", userName);
    return;
}

void UserMgr::checkDeleteGroupConstraints(const std::string& groupName)
{
    if (std::find(groupsMgr.begin(), groupsMgr.end(), groupName) ==
        groupsMgr.end())
    {
        lg2::error("Group '{GROUP}' already exists", "GROUP", groupName);
        elog<GroupNameDoesNotExists>();
    }
    checkAndThrowsForGroupChangeAllowed(groupName);
}

void UserMgr::deleteGroup(std::string groupName)
{
    checkDeleteGroupConstraints(groupName);
    try
    {
        executeGroupDeletion(groupName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Failed to delete group '{GROUP}'", "GROUP", groupName);
        elog<InternalFailure>();
    }

    groupsMgr.erase(std::find(groupsMgr.begin(), groupsMgr.end(), groupName));
    UserMgrIface::allGroups(groupsMgr);
    lg2::info("Successfully deleted group '{GROUP}'", "GROUP", groupName);
}

void UserMgr::checkCreateGroupConstraints(const std::string& groupName)
{
    if (std::find(groupsMgr.begin(), groupsMgr.end(), groupName) !=
        groupsMgr.end())
    {
        lg2::error("Group '{GROUP}' already exists", "GROUP", groupName);
        elog<GroupNameExists>();
    }
    checkAndThrowForDisallowedGroupCreation(groupName);
    if (groupsMgr.size() >= maxSystemGroupCount)
    {
        lg2::error("Group limit reached");
        elog<NoResource>(xyz::openbmc_project::User::Common::NoResource::REASON(
            "Group limit reached"));
    }
}

void UserMgr::createGroup(std::string groupName)
{
    checkCreateGroupConstraints(groupName);
    try
    {
        executeGroupCreation(groupName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Failed to create group '{GROUP}'", "GROUP", groupName);
        elog<InternalFailure>();
    }
    groupsMgr.push_back(groupName);
    UserMgrIface::allGroups(groupsMgr);
}

void UserMgr::renameUser(std::string userName, std::string newUserName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    throwForUserExists(newUserName);
    throwForUserNameConstraints(newUserName,
                                usersList[userName].get()->userGroups());
    try
    {
        executeUserRename(userName.c_str(), newUserName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Rename '{USERNAME}' to '{NEWUSERNAME}' failed", "USERNAME",
                   userName, "NEWUSERNAME", newUserName);
        elog<InternalFailure>();
    }
    const auto& user = usersList[userName];
    std::string priv = user.get()->userPrivilege();
    std::vector<std::string> groupNames = user.get()->userGroups();
    bool enabled = user.get()->userEnabled();
    sdbusplus::message::object_path tempObjPath(usersObjPath);
    tempObjPath /= newUserName;
    std::string newUserObj(tempObjPath);
    // Special group 'ipmi' needs a way to identify user renamed, in order to
    // update encrypted password. It can't rely only on InterfacesRemoved &
    // InterfacesAdded. So first send out userRenamed signal.
    this->userRenamed(userName, newUserName);
    usersList.erase(userName);
    usersList.emplace(newUserName, std::make_unique<phosphor::user::Users>(
                                       bus, newUserObj.c_str(), groupNames,
                                       priv, enabled, *this));
    return;
}

void UserMgr::updateGroupsAndPriv(const std::string& userName,
                                  std::vector<std::string> groupNames,
                                  const std::string& priv)
{
    throwForInvalidPrivilege(priv);
    throwForInvalidGroups(groupNames);
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    const std::vector<std::string>& oldGroupNames =
        usersList[userName].get()->userGroups();
    std::vector<std::string> groupDiff;
    // Note: already dealing with sorted group lists.
    std::set_symmetric_difference(oldGroupNames.begin(), oldGroupNames.end(),
                                  groupNames.begin(), groupNames.end(),
                                  std::back_inserter(groupDiff));
    if (std::find(groupDiff.begin(), groupDiff.end(), "ipmi") !=
        groupDiff.end())
    {
        throwForUserNameConstraints(userName, groupNames);
        throwForMaxGrpUserCount(groupNames);
    }

    std::string groups = getCSVFromVector(groupNames);
    bool sshRequested = removeStringFromCSV(groups, grpSsh);

    // treat privilege as a group - This is to avoid using different file to
    // store the same.
    if (!priv.empty())
    {
        if (groups.size() != 0)
        {
            groups += ",";
        }
        groups += priv;
    }
    try
    {
        executeUserModify(userName.c_str(), groups.c_str(), sshRequested);
    }
    catch (const InternalFailure& e)
    {
        lg2::error(
            "Unable to modify user privilege / groups for user '{USERNAME}'",
            "USERNAME", userName);
        elog<InternalFailure>();
    }

    std::sort(groupNames.begin(), groupNames.end());
    usersList[userName]->setUserGroups(groupNames);
    usersList[userName]->setUserPrivilege(priv);
    lg2::info("User '{USERNAME}' groups / privilege updated successfully",
              "USERNAME", userName);
}

uint8_t UserMgr::minPasswordLength(uint8_t value)
{
    if (value == AccountPolicyIface::minPasswordLength())
    {
        return value;
    }
    if (value < minPasswdLength)
    {
        lg2::error("Attempting to set minPasswordLength to {VALUE}, less than "
                   "{MINVALUE}",
                   "VALUE", value, "MINVALUE", minPasswdLength);
        elog<InvalidArgument>(
            Argument::ARGUMENT_NAME("minPasswordLength"),
            Argument::ARGUMENT_VALUE(std::to_string(value).c_str()));
    }
#ifdef __ZEPHYR__
    // Zephyr: account policy lives in the local users.json store, not in
    // /etc/pam.d/common-password.
    // Zephyr: pam_cracklib minlen is replaced by userRule.minlen (same name as
    // the Linux PAM argument, see minPasswdLenProp).
    zephyrUserRule()[minPasswdLenProp] = value;
    if (!zephyrSaveStore())
    {
        lg2::error("Unable to set minPasswordLength to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#else
    if (setPamModuleArgValue(pamCrackLib, minPasswdLenProp,
                             std::to_string(value)) != success)
    {
        lg2::error("Unable to set minPasswordLength to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#endif
    return AccountPolicyIface::minPasswordLength(value);
}

uint8_t UserMgr::rememberOldPasswordTimes(uint8_t value)
{
    if (value == AccountPolicyIface::rememberOldPasswordTimes())
    {
        return value;
    }
#ifdef __ZEPHYR__
    // Zephyr: account policy lives in the local users.json store.
    // Zephyr: pam_pwhistory remember is replaced by userRule.remember (same
    // name as the Linux PAM argument, see remOldPasswdCount).
    zephyrUserRule()[remOldPasswdCount] = value;
    if (!zephyrSaveStore())
    {
        lg2::error("Unable to set rememberOldPasswordTimes to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#else
    if (setPamModuleArgValue(pamPWHistory, remOldPasswdCount,
                             std::to_string(value)) != success)
    {
        lg2::error("Unable to set rememberOldPasswordTimes to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#endif
    return AccountPolicyIface::rememberOldPasswordTimes(value);
}

uint16_t UserMgr::maxLoginAttemptBeforeLockout(uint16_t value)
{
    if (value == AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return value;
    }
#ifdef __ZEPHYR__
    // Zephyr: pam_tally2 deny is replaced by userRule.deny (same name as the
    // Linux PAM argument, see maxFailedAttempt).
    zephyrUserRule()[maxFailedAttempt] = value;
    if (!zephyrSaveStore())
    {
        lg2::error("Unable to set maxLoginAttemptBeforeLockout to {VALUE}",
                   "VALUE", value);
        elog<InternalFailure>();
    }
#else
    if (setPamModuleArgValue(pamTally2, maxFailedAttempt,
                             std::to_string(value)) != success)
    {
        lg2::error("Unable to set maxLoginAttemptBeforeLockout to {VALUE}",
                   "VALUE", value);
        elog<InternalFailure>();
    }
#endif
    return AccountPolicyIface::maxLoginAttemptBeforeLockout(value);
}

uint32_t UserMgr::accountUnlockTimeout(uint32_t value)
{
    if (value == AccountPolicyIface::accountUnlockTimeout())
    {
        return value;
    }
#ifdef __ZEPHYR__
    // Zephyr: pam_tally2 unlock_time is replaced by userRule.unlock_time
    // (same name as the Linux PAM argument, see unlockTimeout).
    zephyrUserRule()[unlockTimeout] = value;
    if (!zephyrSaveStore())
    {
        lg2::error("Unable to set accountUnlockTimeout to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#else
    if (setPamModuleArgValue(pamTally2, unlockTimeout, std::to_string(value)) !=
        success)
    {
        lg2::error("Unable to set accountUnlockTimeout to {VALUE}", "VALUE",
                   value);
        elog<InternalFailure>();
    }
#endif
    return AccountPolicyIface::accountUnlockTimeout(value);
}

int UserMgr::getPamModuleArgValue(const std::string& moduleName,
                                  const std::string& argName,
                                  std::string& argValue)
{
#ifdef __ZEPHYR__
    // TODO(zephyr-unhandled): PAM configuration files do not exist on Zephyr.
    // The account policy is stored in users.json (see zephyrUserRule()).
    (void)moduleName;
    (void)argName;
    (void)argValue;
    return failure;
#else
    std::string fileName;
    if (moduleName == pamTally2)
    {
        fileName = pamAuthConfigFile;
    }
    else
    {
        fileName = pamPasswdConfigFile;
    }
    std::ifstream fileToRead(fileName, std::ios::in);
    if (!fileToRead.is_open())
    {
        lg2::error("Failed to open pam configuration file {FILENAME}",
                   "FILENAME", fileName);
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if (line.find(moduleName) != std::string::npos)
        {
            if ((startPos = line.find(argSearch)) != std::string::npos)
            {
                if ((endPos = line.find(' ', startPos)) == std::string::npos)
                {
                    endPos = line.size();
                }
                startPos += argSearch.size();
                argValue = line.substr(startPos, endPos - startPos);
                return success;
            }
        }
    }
    return failure;
#endif
}

int UserMgr::setPamModuleArgValue(const std::string& moduleName,
                                  const std::string& argName,
                                  const std::string& argValue)
{
#ifdef __ZEPHYR__
    // TODO(zephyr-unhandled): PAM configuration files do not exist on Zephyr.
    // The account policy is stored in users.json (see zephyrUserRule()).
    (void)moduleName;
    (void)argName;
    (void)argValue;
    return failure;
#else
    std::string fileName;
    if (moduleName == pamTally2)
    {
        fileName = pamAuthConfigFile;
    }
    else
    {
        fileName = pamPasswdConfigFile;
    }
    std::string tmpFileName = fileName + "_tmp";
    std::ifstream fileToRead(fileName, std::ios::in);
    std::ofstream fileToWrite(tmpFileName, std::ios::out);
    if (!fileToRead.is_open() || !fileToWrite.is_open())
    {
        lg2::error("Failed to open pam configuration file {FILENAME}",
                   "FILENAME", fileName);
        return failure;
    }
    std::string line;
    auto argSearch = argName + "=";
    size_t startPos = 0;
    size_t endPos = 0;
    bool found = false;
    while (getline(fileToRead, line))
    {
        // skip comments section starting with #
        if ((startPos = line.find('#')) != std::string::npos)
        {
            if (startPos == 0)
            {
                fileToWrite << line << std::endl;
                continue;
            }
            // skip comments after meaningful section and process those
            line = line.substr(0, startPos);
        }
        if (line.find(moduleName) != std::string::npos)
        {
            if ((startPos = line.find(argSearch)) != std::string::npos)
            {
                if ((endPos = line.find(' ', startPos)) == std::string::npos)
                {
                    endPos = line.size();
                }
                startPos += argSearch.size();
                fileToWrite << line.substr(0, startPos) << argValue
                            << line.substr(endPos, line.size() - endPos)
                            << std::endl;
                found = true;
                continue;
            }
        }
        fileToWrite << line << std::endl;
    }
    fileToWrite.close();
    fileToRead.close();
    if (found)
    {
        if (std::rename(tmpFileName.c_str(), fileName.c_str()) == 0)
        {
            return success;
        }
    }
    return failure;
#endif
}

void UserMgr::userEnable(const std::string& userName, bool enabled)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    throwForUserDoesNotExist(userName);
    try
    {
        executeUserModifyUserEnable(userName.c_str(), enabled);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to modify user enabled state for '{USERNAME}'",
                   "USERNAME", userName);
        elog<InternalFailure>();
    }

    usersList[userName]->setUserEnabled(enabled);
    lg2::info("User '{USERNAME}' has been {STATUS}", "USERNAME", userName,
              "STATUS", enabled ? "Enabled" : "Disabled");
}

/**
 * pam_tally2 app will provide the user failure count and failure status
 * in second line of output with words position [0] - user name,
 * [1] - failure count, [2] - latest failure date, [3] - latest failure time
 * [4] - failure app
 **/

static constexpr size_t t2FailCntIdx = 1;
static constexpr size_t t2FailDateIdx = 2;
static constexpr size_t t2FailTimeIdx = 3;
static constexpr size_t t2OutputIndex = 1;

#ifdef __ZEPHYR__
bool UserMgr::userLockedForFailedAttempt(const std::string& userName)
{
    // Zephyr: the pam_tally2 counter is replaced by failTimes/lockTime in the
    // local users.json store (userRule.deny / userRule.unlock_time).
    const int failAttempts = zephyrGetFailCount(userName);
    if (failAttempts < 0)
    {
        // Unknown user: report "not locked".
        // TODO(zephyr-unhandled): Linux returns a D-Bus InternalFailure when
        // pam_tally2 cannot be queried; align once the local account store is
        // authoritative for every consumer.
        return false;
    }
    const int64_t lockDeny =
        zephyrJsonInt(zephyrUserRule(), maxFailedAttempt, zephyrDefaultLockDeny);
    if ((lockDeny <= 0) || (failAttempts < lockDeny))
    {
        return false;
    }
    const int64_t unlockTime = zephyrJsonInt(zephyrUserRule(), unlockTimeout,
                                             zephyrDefaultUnlockTime);
    const int64_t lockTime = zephyrGetLockTime(userName);
    return (lockTime + unlockTime) > static_cast<int64_t>(std::time(nullptr));
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName,
                                         const bool& value)
{
    if (value == true)
    {
        return userLockedForFailedAttempt(userName);
    }
    // Reset the local failure counter instead of running pam_tally2.
    if (!zephyrSetFailCount(userName, 0))
    {
        lg2::error("Unable to reset login failure counter");
        elog<InternalFailure>();
    }
    return userLockedForFailedAttempt(userName);
}
#else
bool UserMgr::userLockedForFailedAttempt(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    if (AccountPolicyIface::maxLoginAttemptBeforeLockout() == 0)
    {
        return false;
    }

    std::vector<std::string> output;
    try
    {
        output = getFailedAttempt(userName.c_str());
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to read login failure counter");
        elog<InternalFailure>();
    }

    std::vector<std::string> splitWords;
    boost::algorithm::split(splitWords, output[t2OutputIndex],
                            boost::algorithm::is_any_of("\t "),
                            boost::token_compress_on);
    uint16_t failAttempts = 0;
    try
    {
        unsigned long tmp = std::stoul(splitWords[t2FailCntIdx], nullptr);
        if (tmp > std::numeric_limits<decltype(failAttempts)>::max())
        {
            throw std::out_of_range("Out of range");
        }
        failAttempts = static_cast<decltype(failAttempts)>(tmp);
    }
    catch (const std::exception& e)
    {
        lg2::error("Exception for userLockedForFailedAttempt: {ERR}", "ERR", e);
        elog<InternalFailure>();
    }

    if (failAttempts < AccountPolicyIface::maxLoginAttemptBeforeLockout())
    {
        return false;
    }

    // When failedAttempts is not 0, Latest failure date/time should be
    // available
    if (splitWords.size() < 4)
    {
        lg2::error("Unable to read latest failure date/time");
        elog<InternalFailure>();
    }

    const std::string failDateTime =
        splitWords[t2FailDateIdx] + ' ' + splitWords[t2FailTimeIdx];

    // NOTE: Cannot use std::get_time() here as the implementation of %y in
    // libstdc++ does not match POSIX strptime() before gcc 12.1.0
    // https://gcc.gnu.org/git/?p=gcc.git;a=commit;h=a8d3c98746098e2784be7144c1ccc9fcc34a0888
    std::tm tmStruct = {};
    if (!strptime(failDateTime.c_str(), "%D %H:%M:%S", &tmStruct))
    {
        lg2::error("Failed to parse latest failure date/time");
        elog<InternalFailure>();
    }

    time_t failTimestamp = std::mktime(&tmStruct);
    if (failTimestamp +
            static_cast<time_t>(AccountPolicyIface::accountUnlockTimeout()) <=
        std::time(NULL))
    {
        return false;
    }

    return true;
}

bool UserMgr::userLockedForFailedAttempt(const std::string& userName,
                                         const bool& value)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    if (value == true)
    {
        return userLockedForFailedAttempt(userName);
    }

    try
    {
        executeCmd("/usr/sbin/pam_tally2", "-u", userName.c_str(), "-r");
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to reset login failure counter");
        elog<InternalFailure>();
    }

    return userLockedForFailedAttempt(userName);
}
#endif

#ifdef __ZEPHYR__
bool UserMgr::userPasswordExpired(const std::string& userName)
{
    // Zephyr: password expiry comes from the local store (pwdUpdateTime /
    // expireTime) instead of /etc/shadow (struct spwd / getspnam_r).
    json* user = zephyrFindUser(userName);
    if (user == nullptr)
    {
        return false;
    }
    const int64_t expireTime =
        zephyrJsonInt(*user, zephyrJson::expireTime, zephyrNeverExpireDays);
    if (expireTime >= zephyrNeverExpireDays)
    {
        return false;
    }
    const int64_t pwdUpdateTime =
        zephyrJsonInt(*user, zephyrJson::pwdUpdateTime, 0);
    const int64_t now = static_cast<int64_t>(std::time(nullptr));
    return ((now - pwdUpdateTime) / zephyrSecondsPerDay) > expireTime;
}
#else
bool UserMgr::userPasswordExpired(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    struct spwd spwd
    {};
    struct spwd* spwdPtr = nullptr;
    auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen < -1)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }
    std::vector<char> buffer(buflen);
    auto status =
        getspnam_r(userName.c_str(), &spwd, buffer.data(), buflen, &spwdPtr);
    // On success, getspnam_r() returns zero, and sets *spwdPtr to spwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *spwdPtr
    if ((status == 0) && (&spwd == spwdPtr))
    {
        // Determine password validity per "chage" docs, where:
        //   spwd.sp_lstchg == 0 means password is expired, and
        //   spwd.sp_max == -1 means the password does not expire.
        constexpr long secondsPerDay = 60 * 60 * 24;
        long today = static_cast<long>(time(NULL)) / secondsPerDay;
        if ((spwd.sp_lstchg == 0) ||
            ((spwd.sp_max != -1) && ((spwd.sp_max + spwd.sp_lstchg) < today)))
        {
            return true;
        }
    }
    else
    {
        // User entry is missing in /etc/shadow, indicating no SHA password.
        // Treat this as new user without password entry in /etc/shadow
        // TODO: Add property to indicate user password was not set yet
        // https://github.com/openbmc/phosphor-user-manager/issues/8
        return false;
    }

    return false;
}
#endif

#ifdef __ZEPHYR__
UserSSHLists UserMgr::getUserAndSshGrpList()
{
    // Zephyr: the user list comes from the local store instead of /etc/passwd
    // (fgetpwent_r/endpwent); the ssh list is the "ssh" group membership.
    std::vector<std::string> userList;
    std::vector<std::string> sshUsersList;
    for (const auto& user : zephyrStore[zephyrJson::userList])
    {
        if (!user.is_object())
        {
            continue;
        }
        const std::string userName =
            zephyrJsonString(user, zephyrJson::userName);
        if (userName.empty())
        {
            continue;
        }
        userList.emplace_back(userName);
        const auto groupNames =
            zephyrStringList(user.value(zephyrJson::userGroupList, json()));
        if (std::find(groupNames.begin(), groupNames.end(), grpSsh) !=
            groupNames.end())
        {
            sshUsersList.emplace_back(userName);
        }
    }
    return std::make_pair(std::move(userList), std::move(sshUsersList));
}
#else
UserSSHLists UserMgr::getUserAndSshGrpList()
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};

    std::vector<std::string> userList;
    std::vector<std::string> sshUsersList;
    struct passwd pw, *pwp = nullptr;
    std::array<char, 1024> buffer{};

    phosphor::user::File passwd(passwdFileName, "r");
    if ((passwd)() == NULL)
    {
        lg2::error("Error opening {FILENAME}", "FILENAME", passwdFileName);
        elog<InternalFailure>();
    }

    while (true)
    {
        auto r = fgetpwent_r((passwd)(), &pw, buffer.data(), buffer.max_size(),
                             &pwp);
        if ((r != 0) || (pwp == NULL))
        {
            // Any error, break the loop.
            break;
        }
#ifdef ENABLE_ROOT_USER_MGMT
        // Add all users whose UID >= 1000 and < 65534
        // and special UID 0.
        if ((pwp->pw_uid == 0) ||
            ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534)))
#else
        // Add all users whose UID >=1000 and < 65534
        if ((pwp->pw_uid >= 1000) && (pwp->pw_uid < 65534))
#endif
        {
            std::string userName(pwp->pw_name);
            userList.emplace_back(userName);

            // ssh doesn't have separate group. Check login shell entry to
            // get all users list which are member of ssh group.
            std::string loginShell(pwp->pw_shell);
            if (loginShell == "/bin/sh")
            {
                sshUsersList.emplace_back(userName);
            }
        }
    }
    endpwent();
    return std::make_pair(std::move(userList), std::move(sshUsersList));
}
#endif

size_t UserMgr::getIpmiUsersCount()
{
    std::vector<std::string> userList = getUsersInGroup("ipmi");
    return userList.size();
}

size_t UserMgr::getNonIpmiUsersCount()
{
    std::vector<std::string> ipmiUsers = getUsersInGroup("ipmi");
    return usersList.size() - ipmiUsers.size();
}

#ifdef __ZEPHYR__
bool UserMgr::isUserEnabled(const std::string& userName)
{
    // Zephyr: enabled state comes from the local store instead of /etc/shadow
    // (struct spwd / getspnam_r).
    return zephyrGetUserBool(userName, zephyrJson::enable, false);
}
#else
bool UserMgr::isUserEnabled(const std::string& userName)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::array<char, 4096> buffer{};
    struct spwd spwd;
    struct spwd* resultPtr = nullptr;
    int status = getspnam_r(userName.c_str(), &spwd, buffer.data(),
                            buffer.max_size(), &resultPtr);
    if (!status && (&spwd == resultPtr))
    {
        if (resultPtr->sp_expire >= 0)
        {
            return false; // user locked out
        }
        return true;
    }
    return false; // assume user is disabled for any error.
}
#endif

#ifdef __ZEPHYR__
std::vector<std::string> UserMgr::getUsersInGroup(const std::string& groupName)
{
    // Zephyr: /etc/group does not exist (the Zephyr getgrnam_r() stub returns
    // ENOSYS).  Group existence comes from the local store (predefinedGroups +
    // createdGroups, plus the privilege names); membership comes from each
    // user's groupList and from the privilege field (Linux encodes privileges
    // as group membership).
    std::vector<std::string> usersInGroup;
    const std::vector<std::string> knownGroups = zephyrCollectGroups();
    const bool groupExists =
        (std::find(privMgr.begin(), privMgr.end(), groupName) !=
         privMgr.end()) ||
        (std::find(knownGroups.begin(), knownGroups.end(), groupName) !=
         knownGroups.end());

    for (const auto& user : zephyrStore[zephyrJson::userList])
    {
        if (!user.is_object())
        {
            continue;
        }
        const std::string userName =
            zephyrJsonString(user, zephyrJson::userName);
        if (userName.empty())
        {
            continue;
        }
        const auto groupNames =
            zephyrStringList(user.value(zephyrJson::userGroupList, json()));
        if ((std::find(groupNames.begin(), groupNames.end(), groupName) !=
             groupNames.end()) ||
            (zephyrJsonString(user, zephyrJson::priv) == groupName))
        {
            usersInGroup.emplace_back(userName);
        }
    }

    if (!groupExists && usersInGroup.empty())
    {
        lg2::error("Group '{GROUPNAME}' not found", "GROUPNAME", groupName);
        // Don't throw error, just return empty userList - fallback
    }
    return usersInGroup;
}
#else
std::vector<std::string> UserMgr::getUsersInGroup(const std::string& groupName)
{
    std::vector<std::string> usersInGroup;
    // Should be more than enough to get the pwd structure.
    std::array<char, 4096> buffer{};
    struct group grp;
    struct group* resultPtr = nullptr;

    int status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.max_size(), &resultPtr);

    if (!status && (&grp == resultPtr))
    {
        for (; *(grp.gr_mem) != NULL; ++(grp.gr_mem))
        {
            usersInGroup.emplace_back(*(grp.gr_mem));
        }
    }
    else
    {
        lg2::error("Group '{GROUPNAME}' not found", "GROUPNAME", groupName);
        // Don't throw error, just return empty userList - fallback
    }
    return usersInGroup;
}
#endif

DbusUserObj UserMgr::getPrivilegeMapperObject(void)
{
    DbusUserObj objects;
    try
    {
        std::string basePath = "/xyz/openbmc_project/user/ldap/openldap";
        std::string interface = "xyz.openbmc_project.User.Ldap.Config";

        auto ldapMgmtService =
            getServiceName(std::move(basePath), std::move(interface));
        auto method = bus.new_method_call(
            ldapMgmtService.c_str(), ldapMgrObjBasePath,
            "org.freedesktop.DBus.ObjectManager", "GetManagedObjects");

        auto reply = bus.call(method);
        reply.read(objects);
    }
    catch (const InternalFailure& e)
    {
        lg2::error("Unable to get the User Service: {ERR}", "ERR", e);
        throw;
    }
    catch (const sdbusplus::exception_t& e)
    {
        lg2::error("Failed to excute GetManagedObjects at {PATH}: {ERR}",
                   "PATH", ldapMgrObjBasePath, "ERR", e);
        throw;
    }
    return objects;
}

std::string UserMgr::getServiceName(std::string&& path, std::string&& intf)
{
    auto mapperCall = bus.new_method_call(objMapperService, objMapperPath,
                                          objMapperInterface, "GetObject");

    mapperCall.append(std::move(path));
    mapperCall.append(std::vector<std::string>({std::move(intf)}));

    auto mapperResponseMsg = bus.call(mapperCall);

    if (mapperResponseMsg.is_method_error())
    {
        lg2::error("Error in mapper call");
        elog<InternalFailure>();
    }

    std::map<std::string, std::vector<std::string>> mapperResponse;
    mapperResponseMsg.read(mapperResponse);

    if (mapperResponse.begin() == mapperResponse.end())
    {
        lg2::error("Invalid response from mapper");
        elog<InternalFailure>();
    }

    return mapperResponse.begin()->first;
}

gid_t UserMgr::getPrimaryGroup(const std::string& userName) const
{
    static auto buflen = sysconf(_SC_GETPW_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct passwd pwd;
    struct passwd* pwdPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getpwnam_r(userName.c_str(), &pwd, buffer.data(),
                             buffer.size(), &pwdPtr);
    // On success, getpwnam_r() returns zero, and set *pwdPtr to pwd.
    // If no matching password record was found, these functions return 0
    // and store NULL in *pwdPtr
    if (!status && (&pwd == pwdPtr))
    {
        return pwd.pw_gid;
    }

    lg2::error("User {USERNAME} does not exist", "USERNAME", userName);
    elog<UserNameDoesNotExist>();
}

bool UserMgr::isGroupMember(const std::string& userName, gid_t primaryGid,
                            const std::string& groupName) const
{
    static auto buflen = sysconf(_SC_GETGR_R_SIZE_MAX);
    if (buflen <= 0)
    {
        // Use a default size if there is no hard limit suggested by sysconf()
        buflen = 1024;
    }

    struct group grp;
    struct group* grpPtr = nullptr;
    std::vector<char> buffer(buflen);

    auto status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                             buffer.size(), &grpPtr);

    // Groups with a lot of members may require a buffer of bigger size than
    // suggested by _SC_GETGR_R_SIZE_MAX.
    // 32K should be enough for about 2K members.
    constexpr auto maxBufferLength = 32 * 1024;
    while (status == ERANGE && buflen < maxBufferLength)
    {
        buflen *= 2;
        buffer.resize(buflen);

        lg2::debug("Increase buffer for getgrnam_r() to {SIZE}", "SIZE",
                   buflen);

        status = getgrnam_r(groupName.c_str(), &grp, buffer.data(),
                            buffer.size(), &grpPtr);
    }

    // On success, getgrnam_r() returns zero, and set *grpPtr to grp.
    // If no matching group record was found, these functions return 0
    // and store NULL in *grpPtr
    if (!status && (&grp == grpPtr))
    {
        if (primaryGid == grp.gr_gid)
        {
            return true;
        }

        for (auto i = 0; grp.gr_mem && grp.gr_mem[i]; ++i)
        {
            if (userName == grp.gr_mem[i])
            {
                return true;
            }
        }
    }
    else if (status == ERANGE)
    {
        lg2::error("Group info of {GROUP} requires too much memory", "GROUP",
                   groupName);
    }
    else
    {
        lg2::error("Group {GROUP} does not exist", "GROUP", groupName);
    }

    return false;
}

#ifdef __ZEPHYR__
void UserMgr::executeGroupCreation(const char* groupName)
{
    // Zephyr: /usr/sbin/groupadd is replaced by the local group list in
    // users.json ("createdGroups").
    if (!zephyrAddGroup(groupName))
    {
        elog<InternalFailure>();
    }
}

void UserMgr::executeGroupDeletion(const char* groupName)
{
    // Zephyr: /usr/sbin/groupdel is replaced by the local group list in
    // users.json; memberships are dropped as well.
    if (!zephyrRemoveGroup(groupName))
    {
        elog<InternalFailure>();
    }
}
#else
void UserMgr::executeGroupCreation(const char* groupName)
{
    executeCmd("/usr/sbin/groupadd", groupName);
}

void UserMgr::executeGroupDeletion(const char* groupName)
{
    executeCmd("/usr/sbin/groupdel", groupName);
}
#endif

UserInfoMap UserMgr::getUserInfo(std::string userName)
{
    UserInfoMap userInfo;
    // Check whether the given user is local user or not.
    if (isUserExist(userName))
    {
        const auto& user = usersList[userName];
        userInfo.emplace("UserPrivilege", user.get()->userPrivilege());
        userInfo.emplace("UserGroups", user.get()->userGroups());
        userInfo.emplace("UserEnabled", user.get()->userEnabled());
        userInfo.emplace("UserLockedForFailedAttempt",
                         user.get()->userLockedForFailedAttempt());
        userInfo.emplace("UserPasswordExpired",
                         user.get()->userPasswordExpired());
        userInfo.emplace("RemoteUser", false);
    }
    else
    {
#ifdef __ZEPHYR__
        // TODO(zephyr-unhandled): LDAP/remote users need the ObjectMapper
        // privilege mapping plus getPrimaryGroup()/isGroupMember(), which read
        // /etc/passwd and /etc/group.  The local Zephyr account store does not
        // model remote users yet, so return an empty result (no RemoteUser
        // property) instead of the Linux LDAP lookup.
        return userInfo;
#else
        auto primaryGid = getPrimaryGroup(userName);

        DbusUserObj objects = getPrivilegeMapperObject();

        std::string ldapConfigPath;
        std::string userPrivilege;

        try
        {
            for (const auto& [path, interfaces] : objects)
            {
                auto it = interfaces.find("xyz.openbmc_project.Object.Enable");
                if (it != interfaces.end())
                {
                    auto propIt = it->second.find("Enabled");
                    if (propIt != it->second.end() &&
                        std::get<bool>(propIt->second))
                    {
                        ldapConfigPath = path.str + '/';
                        break;
                    }
                }
            }

            if (ldapConfigPath.empty())
            {
                return userInfo;
            }

            for (const auto& [path, interfaces] : objects)
            {
                if (!path.str.starts_with(ldapConfigPath))
                {
                    continue;
                }

                auto it = interfaces.find(
                    "xyz.openbmc_project.User.PrivilegeMapperEntry");
                if (it != interfaces.end())
                {
                    std::string privilege;
                    std::string groupName;

                    for (const auto& [propName, propValue] : it->second)
                    {
                        if (propName == "GroupName")
                        {
                            groupName = std::get<std::string>(propValue);
                        }
                        else if (propName == "Privilege")
                        {
                            privilege = std::get<std::string>(propValue);
                        }
                    }

                    if (!groupName.empty() && !privilege.empty() &&
                        isGroupMember(userName, primaryGid, groupName))
                    {
                        userPrivilege = privilege;
                        break;
                    }
                }
                if (!userPrivilege.empty())
                {
                    break;
                }
            }

            if (!userPrivilege.empty())
            {
                userInfo.emplace("UserPrivilege", userPrivilege);
            }
            else
            {
                lg2::warning("LDAP group privilege mapping does not exist, "
                             "default \"priv-user\" is used");
                userInfo.emplace("UserPrivilege", "priv-user");
            }
        }
        catch (const std::bad_variant_access& e)
        {
            lg2::error("Error while accessing variant: {ERR}", "ERR", e);
            elog<InternalFailure>();
        }
        userInfo.emplace("RemoteUser", true);
#endif
    }

    return userInfo;
}

#ifdef __ZEPHYR__
void UserMgr::initializeAccountPolicy()
{
    // Zephyr: PAM is replaced by the account policy fields in users.json.
    json& rule = zephyrUserRule();
    AccountPolicyIface::minPasswordLength(
        zephyrJsonInt(rule, minPasswdLenProp,
                      zephyrDefaultMinPasswordLength));
    AccountPolicyIface::rememberOldPasswordTimes(
        zephyrJsonInt(rule, remOldPasswdCount,
                      zephyrDefaultRememberOldPasswordTimes));
    AccountPolicyIface::maxLoginAttemptBeforeLockout(
        zephyrJsonInt(rule, maxFailedAttempt, zephyrDefaultLockDeny));
    AccountPolicyIface::accountUnlockTimeout(
        zephyrJsonInt(rule, unlockTimeout, zephyrDefaultUnlockTime));
}
#else
void UserMgr::initializeAccountPolicy()
{
    std::string valueStr;
    auto value = minPasswdLength;
    unsigned long tmp = 0;
    if (getPamModuleArgValue(pamCrackLib, minPasswdLenProp, valueStr) !=
        success)
    {
        AccountPolicyIface::minPasswordLength(minPasswdLength);
    }
    else
    {
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for MinPasswordLength: {ERR}", "ERR", e);
            throw;
        }
        AccountPolicyIface::minPasswordLength(value);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamPWHistory, remOldPasswdCount, valueStr) !=
        success)
    {
        AccountPolicyIface::rememberOldPasswordTimes(0);
    }
    else
    {
        value = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value = static_cast<decltype(value)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for RememberOldPasswordTimes: {ERR}", "ERR",
                       e);
            throw;
        }
        AccountPolicyIface::rememberOldPasswordTimes(value);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamTally2, maxFailedAttempt, valueStr) != success)
    {
        AccountPolicyIface::maxLoginAttemptBeforeLockout(0);
    }
    else
    {
        uint16_t value16 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value16)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value16 = static_cast<decltype(value16)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for MaxLoginAttemptBeforLockout: {ERR}",
                       "ERR", e);
            throw;
        }
        AccountPolicyIface::maxLoginAttemptBeforeLockout(value16);
    }
    valueStr.clear();
    if (getPamModuleArgValue(pamTally2, unlockTimeout, valueStr) != success)
    {
        AccountPolicyIface::accountUnlockTimeout(0);
    }
    else
    {
        uint32_t value32 = 0;
        try
        {
            tmp = std::stoul(valueStr, nullptr);
            if (tmp > std::numeric_limits<decltype(value32)>::max())
            {
                throw std::out_of_range("Out of range");
            }
            value32 = static_cast<decltype(value32)>(tmp);
        }
        catch (const std::exception& e)
        {
            lg2::error("Exception for AccountUnlockTimeout: {ERR}", "ERR", e);
            throw;
        }
        AccountPolicyIface::accountUnlockTimeout(value32);
    }
}
#endif

void UserMgr::initUserObjects(void)
{
    // All user management lock has to be based on /etc/shadow
    // TODO  phosphor-user-manager#10 phosphor::user::shadow::Lock lock{};
    std::vector<std::string> userNameList;
    std::vector<std::string> sshGrpUsersList;
    UserSSHLists userSSHLists = getUserAndSshGrpList();
    userNameList = std::move(userSSHLists.first);
    sshGrpUsersList = std::move(userSSHLists.second);

    if (!userNameList.empty())
    {
        std::map<std::string, std::vector<std::string>> groupLists;
        // We only track users that are in the |predefinedGroups|
        // The other groups don't contain real BMC users.
        for (const char* grp : predefinedGroups)
        {
            if (grp == grpSsh)
            {
                groupLists.emplace(grp, sshGrpUsersList);
            }
            else
            {
                std::vector<std::string> grpUsersList = getUsersInGroup(grp);
                groupLists.emplace(grp, grpUsersList);
            }
        }
        for (auto& grp : privMgr)
        {
            std::vector<std::string> grpUsersList = getUsersInGroup(grp);
            groupLists.emplace(grp, grpUsersList);
        }

        for (auto& user : userNameList)
        {
            std::vector<std::string> userGroups;
            std::string userPriv;
            for (const auto& grp : groupLists)
            {
                std::vector<std::string> tempGrp = grp.second;
                if (std::find(tempGrp.begin(), tempGrp.end(), user) !=
                    tempGrp.end())
                {
                    if (std::find(privMgr.begin(), privMgr.end(), grp.first) !=
                        privMgr.end())
                    {
                        userPriv = grp.first;
                    }
                    else
                    {
                        userGroups.emplace_back(grp.first);
                    }
                }
            }
            // Add user objects to the Users path.
            sdbusplus::message::object_path tempObjPath(usersObjPath);
            tempObjPath /= user;
            std::string objPath(tempObjPath);
            std::sort(userGroups.begin(), userGroups.end());
            usersList.emplace(user, std::make_unique<phosphor::user::Users>(
                                        bus, objPath.c_str(), userGroups,
                                        userPriv, isUserEnabled(user), *this));
        }
    }
}

UserMgr::UserMgr(sdbusplus::bus_t& bus, const char* path) :
    Ifaces(bus, path, Ifaces::action::defer_emit), bus(bus), path(path),
    pamPasswdConfigFile(defaultPamPasswdConfigFile),
    pamAuthConfigFile(defaultPamAuthConfigFile)
{
#ifdef __ZEPHYR__
    // Load the local account store before any user object is created.
    zephyrLoadStore();
#endif
    UserMgrIface::allPrivileges(privMgr);
    groupsMgr = readAllGroupsOnSystem();
    std::sort(groupsMgr.begin(), groupsMgr.end());
    UserMgrIface::allGroups(groupsMgr);
    initializeAccountPolicy();
    initUserObjects();

    // emit the signal
    this->emit_object_added();
}

#ifdef __ZEPHYR__
namespace
{
std::vector<std::string> zephyrSplitGroups(const char* groups)
{
    std::vector<std::string> groupNames;
    if (groups == nullptr)
    {
        return groupNames;
    }
    std::string csv(groups);
    std::stringstream stream(csv);
    std::string item;
    while (std::getline(stream, item, ','))
    {
        if (!item.empty())
        {
            groupNames.emplace_back(item);
        }
    }
    return groupNames;
}

struct ZephyrUserGroups
{
    std::vector<std::string> groupNames;
    std::string priv;
};

// Convert the Linux CSV convention used by useradd/usermod into the local
// store model:
//   - the caller appends the privilege as a pseudo group ("treat privilege as
//     a group"), so tokens listed in privList become the local "priv" field;
//   - the caller removes "ssh" from the CSV (Linux encodes ssh membership
//     through the login shell), so sshRequested re-adds the local "ssh" group.
ZephyrUserGroups zephyrParseUserGroups(const char* csv, bool sshRequested,
                                       const std::vector<std::string>& privList)
{
    ZephyrUserGroups result;
    for (const auto& token : zephyrSplitGroups(csv))
    {
        if (std::find(privList.begin(), privList.end(), token) != privList.end())
        {
            result.priv = token;
        }
        else
        {
            result.groupNames.emplace_back(token);
        }
    }
    if (sshRequested)
    {
        result.groupNames.emplace_back(grpSsh);
    }
    std::sort(result.groupNames.begin(), result.groupNames.end());
    result.groupNames.erase(
        std::unique(result.groupNames.begin(), result.groupNames.end()),
        result.groupNames.end());
    return result;
}
} // namespace

void UserMgr::executeUserAdd(const char* userName, const char* groups,
                             bool sshRequested, bool enabled)
{
    // Zephyr: /usr/sbin/useradd is replaced by the local users.json store.
    // The CSV convention (privilege appended as a group, ssh removed) is
    // converted back to the local model; createUser() writes the store
    // directly, this path is kept for other/future callers.
    const ZephyrUserGroups parsed =
        zephyrParseUserGroups(groups, sshRequested, privMgr);
    if (!zephyrAddUser(userName, parsed.groupNames, parsed.priv, enabled))
    {
        // Low-level failure is logged by the store; the caller logs the
        // operation-level error, like Linux executeCmd()/caller.
        elog<InternalFailure>();
    }
}

void UserMgr::executeUserDelete(const char* userName)
{
    // Zephyr: /usr/sbin/userdel is replaced by the local users.json store.
    if (!zephyrRemoveUser(userName))
    {
        elog<InternalFailure>();
    }
}

void UserMgr::executeUserRename(const char* userName, const char* newUserName)
{
    // Zephyr: /usr/sbin/usermod is replaced by the local users.json store.
    if (!zephyrRenameUser(userName, newUserName))
    {
        elog<InternalFailure>();
    }
}

void UserMgr::executeUserModify(const char* userName, const char* newGroups,
                                bool sshRequested)
{
    // Zephyr: /usr/sbin/usermod is replaced by the local users.json store.
    // The CSV convention (privilege appended as a group, ssh removed) is
    // converted back to the local model; updateGroupsAndPriv() writes the
    // store directly, this path is kept for other/future callers.
    const ZephyrUserGroups parsed =
        zephyrParseUserGroups(newGroups, sshRequested, privMgr);
    if (!zephyrSetUserGroups(userName, parsed.groupNames) ||
        !zephyrSetUserPrivilege(userName, parsed.priv))
    {
        elog<InternalFailure>();
    }
}

void UserMgr::executeUserModifyUserEnable(const char* userName, bool enabled)
{
    // Zephyr: /usr/sbin/usermod is replaced by the local users.json store.
    if (!zephyrSetUserEnabled(userName, enabled))
    {
        elog<InternalFailure>();
    }
}

std::vector<std::string> UserMgr::getFailedAttempt(const char* userName)
{
    // Zephyr: pam_tally2 output is replaced by the local failTimes counter.
    // The two callers (userLockedForFailedAttempt) read the store directly,
    // so no pam_tally2 formatted output is produced here.
    // TODO(zephyr-unhandled): keep this in sync if another caller starts
    // consuming the pam_tally2 output format.
    (void)userName;
    return {};
}
#else
void UserMgr::executeUserAdd(const char* userName, const char* groups,
                             bool sshRequested, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/useradd", userName, "-G", groups, "-m", "-N", "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"), "-e",
               (enabled ? "" : "1970-01-01"));
}

void UserMgr::executeUserDelete(const char* userName)
{
    executeCmd("/usr/sbin/userdel", userName, "-r");
}

void UserMgr::executeUserRename(const char* userName, const char* newUserName)
{
    std::string newHomeDir = "/home/";
    newHomeDir += newUserName;
    executeCmd("/usr/sbin/usermod", "-l", newUserName, userName, "-d",
               newHomeDir.c_str(), "-m");
}

void UserMgr::executeUserModify(const char* userName, const char* newGroups,
                                bool sshRequested)
{
    executeCmd("/usr/sbin/usermod", userName, "-G", newGroups, "-s",
               (sshRequested ? "/bin/sh" : "/sbin/nologin"));
}

void UserMgr::executeUserModifyUserEnable(const char* userName, bool enabled)
{
    // set EXPIRE_DATE to 0 to disable user, PAM takes 0 as expire on
    // 1970-01-01, that's an implementation-defined behavior
    executeCmd("/usr/sbin/usermod", userName, "-e",
               (enabled ? "" : "1970-01-01"));
}

std::vector<std::string> UserMgr::getFailedAttempt(const char* userName)
{
    return executeCmd("/usr/sbin/pam_tally2", "-u", userName);
}
#endif

} // namespace user
} // namespace phosphor

#ifdef __ZEPHYR__
// C API used by other services (bmcweb's PAM shim, wolfSSH, ...).
extern "C" int zephyrAuthenticate(const char* username, uint32_t usernameLen,
                                  const char* password, uint32_t passwordLen,
                                  const char* loginSource)
{
    return phosphor::user::zephyrLocalAuthenticate(
        std::string((username != nullptr) ? username : "", usernameLen),
        std::string((password != nullptr) ? password : "", passwordLen),
        std::string((loginSource != nullptr) ? loginSource : "web"));
}

extern "C" int zephyrUpdatePassword(const char* username, uint32_t usernameLen,
                                    const char* newPassword,
                                    uint32_t newPasswordLen)
{
    return phosphor::user::zephyrLocalUpdatePassword(
        std::string((username != nullptr) ? username : "", usernameLen),
        std::string((newPassword != nullptr) ? newPassword : "",
                    newPasswordLen));
}

#ifdef CONFIG_PHOSPHOR_USER_MANAGER_SELFTEST
// Self test only, see user_mgr_libc.h.
extern "C" int zephyrTestSetPasswordAge(const char* username,
                                        uint32_t usernameLen,
                                        int64_t pwdUpdateTime,
                                        int64_t expireTime)
{
    nlohmann::json* user = phosphor::user::zephyrFindUser(
        std::string((username != nullptr) ? username : "", usernameLen));
    if (user == nullptr)
    {
        return -1;
    }
    (*user)[phosphor::user::zephyrJson::pwdUpdateTime] = pwdUpdateTime;
    (*user)[phosphor::user::zephyrJson::expireTime] = expireTime;
    return phosphor::user::zephyrSaveStore() ? 0 : -1;
}
#endif
#endif /* __ZEPHYR__ */
