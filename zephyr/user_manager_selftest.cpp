/*
 * Copyright (c) 2026
 *
 * SPDX-License-Identifier: Apache-2.0
 *
 * Zephyr D-Bus self test for phosphor-user-manager.
 *
 * Build the app with -DCONFIG_PHOSPHOR_USER_MANAGER_SELFTEST=y.  The test
 * thread waits for the D-Bus broker and for the User.Manager name to appear,
 * then calls the full D-Bus API exactly like another service (bmcweb, ipmid,
 * ...) would, printing PASS/FAIL per case and a final summary.
 */

#include "dbus_broker.h"
#include "user_mgr_libc.h"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/message.hpp>

#include <nlohmann/json.hpp>

#include <pthread.h>

#include <zephyr/kernel.h>
#include <zephyr/sys/printk.h>

#include <algorithm>
#include <cstring>
#include <ctime>
#include <fstream>
#include <map>
#include <string>
#include <variant>
#include <vector>

namespace
{

constexpr const char* userManagerService = "xyz.openbmc_project.User.Manager";
constexpr const char* dbusService = "org.freedesktop.DBus";
constexpr const char* dbusPath = "/org/freedesktop/DBus";
constexpr const char* dbusIface = "org.freedesktop.DBus";
constexpr const char* propertiesIface = "org.freedesktop.DBus.Properties";
constexpr const char* userRoot = "/xyz/openbmc_project/user";
constexpr const char* managerIface = "xyz.openbmc_project.User.Manager";
constexpr const char* policyIface = "xyz.openbmc_project.User.AccountPolicy";
constexpr const char* attributesIface = "xyz.openbmc_project.User.Attributes";
constexpr const char* deleteIface = "xyz.openbmc_project.Object.Delete";
constexpr const char* usersFile = CONFIG_FS_ROOT_OVERLAY "/etc/users.json";

constexpr const char* testUser = "ut_user1";
constexpr const char* renamedUser = "ut_user2";
constexpr const char* passwordUser = "ut_pass1";
constexpr const char* testGroup = "openbmc_rfr_ut";

// Factory password of a freshly created account and the sha256 the store has
// to keep for it (see config/users.json).
constexpr const char* defaultPassword = "0penBmc";
constexpr const char* changedPassword = "NewPassw0rd!";
constexpr const char* defaultPasswordHash =
    "5d953a0f660e3c5db5223eebeaa47a10432c2f8bf4829278d0bfa1effefe4d02";
constexpr const char* changedPasswordHash =
    "4adae1fb4dba8c2e8188a269de964a107a40f94770b6a96ba6e1132d50be354d";

using Bus = sdbusplus::bus::bus;
using UserInfo = std::map<
    std::string, std::variant<std::string, std::vector<std::string>, bool>>;
using PropValue = std::variant<std::string, std::vector<std::string>, bool,
                               uint8_t, uint16_t, uint32_t>;

int passed = 0;
int failed = 0;

void check(bool ok, const char* what)
{
    printk("[usermgr-test] %-56s %s\n", what, ok ? "PASS" : "FAIL");
    if (ok)
    {
        ++passed;
    }
    else
    {
        ++failed;
    }
}

std::string userPath(const std::string& user)
{
    return std::string(userRoot) + "/" + user;
}

bool contains(const std::vector<std::string>& list, const char* item)
{
    return std::find(list.begin(), list.end(), std::string(item)) !=
           list.end();
}

const std::string* infoString(const UserInfo& info, const char* key)
{
    const auto it = info.find(key);
    return (it == info.end()) ? nullptr : std::get_if<std::string>(&it->second);
}

const std::vector<std::string>* infoList(const UserInfo& info, const char* key)
{
    const auto it = info.find(key);
    return (it == info.end()) ? nullptr
                             : std::get_if<std::vector<std::string>>(
                                   &it->second);
}

const bool* infoBool(const UserInfo& info, const char* key)
{
    const auto it = info.find(key);
    return (it == info.end()) ? nullptr : std::get_if<bool>(&it->second);
}

template <typename... Args>
bool callManager(Bus& bus, const char* iface, const char* method,
                 const std::string& path, std::string& err,
                 const Args&... args)
{
    try
    {
        auto msg =
            bus.new_method_call(userManagerService, path.c_str(), iface,
                                method);
        if constexpr (sizeof...(Args) > 0)
        {
            msg.append(args...);
        }
        bus.call(msg);
        return true;
    }
    catch (const sdbusplus::exception_t& e)
    {
        err = e.name();
        return false;
    }
    catch (const std::exception& e)
    {
        err = e.what();
        return false;
    }
}

bool getUserInfo(Bus& bus, const std::string& user, UserInfo& info,
                 std::string& err)
{
    try
    {
        auto msg = bus.new_method_call(userManagerService, userRoot,
                                      managerIface, "GetUserInfo");
        msg.append(user);
        auto reply = bus.call(msg);
        reply.read(info);
        return true;
    }
    catch (const sdbusplus::exception_t& e)
    {
        err = e.name();
        return false;
    }
    catch (const std::exception& e)
    {
        err = e.what();
        return false;
    }
}

template <typename T>
bool getProperty(Bus& bus, const std::string& path, const char* iface,
                 const char* prop, T& out, std::string& err)
{
    try
    {
        auto msg = bus.new_method_call(userManagerService, path.c_str(),
                                      propertiesIface, "Get");
        msg.append(std::string(iface), std::string(prop));
        auto reply = bus.call(msg);
        PropValue value;
        reply.read(value);
        if (const auto* typed = std::get_if<T>(&value))
        {
            out = *typed;
            return true;
        }
        err = "unexpected property type";
        return false;
    }
    catch (const sdbusplus::exception_t& e)
    {
        err = e.name();
        return false;
    }
    catch (const std::exception& e)
    {
        err = e.what();
        return false;
    }
}

template <typename T>
bool setProperty(Bus& bus, const std::string& path, const char* iface,
                 const char* prop, const T& value, std::string& err)
{
    try
    {
        auto msg = bus.new_method_call(userManagerService, path.c_str(),
                                      propertiesIface, "Set");
        PropValue wrapped{value};
        msg.append(std::string(iface), std::string(prop), wrapped);
        bus.call(msg);
        return true;
    }
    catch (const sdbusplus::exception_t& e)
    {
        err = e.name();
        return false;
    }
    catch (const std::exception& e)
    {
        err = e.what();
        return false;
    }
}

void removeIfPresent(Bus& bus, const char* user)
{
    std::string ignored;
    callManager(bus, deleteIface, "Delete", userPath(user), ignored);
}

void runManagerTests(Bus& bus)
{
    std::string err;

    // Seeded root account.
    {
        UserInfo info;
        const bool ok = getUserInfo(bus, "root", info, err);
        const std::string* priv = ok ? infoString(info, "UserPrivilege") : nullptr;
        const std::vector<std::string>* groups =
            ok ? infoList(info, "UserGroups") : nullptr;
        const bool* enabled = ok ? infoBool(info, "UserEnabled") : nullptr;
        const bool* expired = ok ? infoBool(info, "UserPasswordExpired") : nullptr;
        const bool* remote = ok ? infoBool(info, "RemoteUser") : nullptr;
        check(ok && priv != nullptr && *priv == "priv-admin" && groups != nullptr &&
                  contains(*groups, "web") && contains(*groups, "redfish") &&
                  contains(*groups, "ipmi") && contains(*groups, "ssh") &&
                  enabled != nullptr && *enabled && expired != nullptr &&
                  !*expired && remote != nullptr && !*remote,
              "GetUserInfo(root): priv-admin + groups + enabled");
    }

    // Manager properties.
    {
        std::vector<std::string> privs;
        std::vector<std::string> groups;
        check(getProperty(bus, userRoot, managerIface, "AllPrivileges", privs,
                          err) &&
                  contains(privs, "priv-admin") &&
                  contains(privs, "priv-operator") &&
                  contains(privs, "priv-user"),
              "Manager.AllPrivileges");
        check(getProperty(bus, userRoot, managerIface, "AllGroups", groups,
                          err) &&
                  contains(groups, "web") && contains(groups, "redfish") &&
                  contains(groups, "ipmi") && contains(groups, "ssh"),
              "Manager.AllGroups contains predefined groups");
    }

    removeIfPresent(bus, testUser);
    removeIfPresent(bus, renamedUser);

    // CreateUser + GetUserInfo.
    check(callManager(bus, managerIface, "CreateUser", userRoot, err,
                      std::string(testUser),
                      std::vector<std::string>{"web", "redfish"},
                      std::string("priv-user"), true),
          "CreateUser ut_user1");
    {
        UserInfo info;
        const bool ok = getUserInfo(bus, testUser, info, err);
        const std::string* priv = ok ? infoString(info, "UserPrivilege") : nullptr;
        const std::vector<std::string>* groups =
            ok ? infoList(info, "UserGroups") : nullptr;
        const bool* enabled = ok ? infoBool(info, "UserEnabled") : nullptr;
        check(ok && priv != nullptr && *priv == "priv-user" && groups != nullptr &&
                  contains(*groups, "web") && contains(*groups, "redfish") &&
                  enabled != nullptr && *enabled,
              "GetUserInfo(ut_user1) matches CreateUser");
    }

    // Negative: duplicate user.
    {
        std::string e;
        const bool ok = callManager(bus, managerIface, "CreateUser", userRoot, e,
                                    std::string(testUser),
                                    std::vector<std::string>{"web"},
                                    std::string("priv-user"), true);
        check(!ok &&
                  e == "xyz.openbmc_project.User.Common.Error.UserNameExists",
              "CreateUser duplicate rejected (UserNameExists)");
    }

    // Negative: unknown group.
    {
        std::string e;
        const bool ok = callManager(bus, managerIface, "CreateUser", userRoot, e,
                                    std::string("ut_bad"),
                                    std::vector<std::string>{"not_a_group"},
                                    std::string("priv-user"), true);
        check(!ok && e == "xyz.openbmc_project.Common.Error.InvalidArgument",
              "CreateUser with invalid group rejected (InvalidArgument)");
    }

    // User.Attributes properties (UserEnabled / UserGroups / UserPrivilege).
    check(setProperty(bus, userPath(testUser), attributesIface, "UserEnabled",
                      false, err),
          "set UserEnabled=false");
    {
        UserInfo info;
        const bool ok = getUserInfo(bus, testUser, info, err);
        const bool* enabled = ok ? infoBool(info, "UserEnabled") : nullptr;
        check(ok && enabled != nullptr && !*enabled,
              "GetUserInfo reflects UserEnabled=false");
    }
    check(setProperty(bus, userPath(testUser), attributesIface, "UserGroups",
                      std::vector<std::string>{"ipmi", "redfish"}, err) &&
              setProperty(bus, userPath(testUser), attributesIface,
                          "UserPrivilege", std::string("priv-operator"), err),
          "set UserGroups/UserPrivilege");
    {
        UserInfo info;
        const bool ok = getUserInfo(bus, testUser, info, err);
        const std::string* priv = ok ? infoString(info, "UserPrivilege") : nullptr;
        const std::vector<std::string>* groups =
            ok ? infoList(info, "UserGroups") : nullptr;
        check(ok && priv != nullptr && *priv == "priv-operator" &&
                  groups != nullptr && contains(*groups, "ipmi") &&
                  contains(*groups, "redfish") && !contains(*groups, "web"),
              "GetUserInfo reflects updated groups/privilege");
    }

    // Locked state query + failure counter reset.
    check(setProperty(bus, userPath(testUser), attributesIface,
                      "UserLockedForFailedAttempt", true, err) &&
              setProperty(bus, userPath(testUser), attributesIface,
                          "UserLockedForFailedAttempt", false, err),
          "set/reset UserLockedForFailedAttempt");
    {
        bool locked = true;
        check(getProperty(bus, userPath(testUser), attributesIface,
                          "UserLockedForFailedAttempt", locked, err) &&
                  !locked,
              "UserLockedForFailedAttempt stays false after reset");
    }

    // AccountPolicy defaults, update, restore and negative case.
    {
        uint8_t minlen = 0;
        uint8_t remember = 0;
        uint16_t deny = 0;
        uint32_t unlockTime = 0;
        check(getProperty(bus, userRoot, policyIface, "MinPasswordLength",
                          minlen, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "RememberOldPasswordTimes", remember, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "MaxLoginAttemptBeforeLockout", deny, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "AccountUnlockTimeout", unlockTime, err) &&
                  minlen == 8 && remember == 0 && deny == 3 && unlockTime == 900,
              "AccountPolicy defaults (8/0/3/900)");
    }
    check(setProperty(bus, userRoot, policyIface, "MinPasswordLength",
                      static_cast<uint8_t>(12), err) &&
              setProperty(bus, userRoot, policyIface,
                          "RememberOldPasswordTimes", static_cast<uint8_t>(2),
                          err) &&
              setProperty(bus, userRoot, policyIface,
                          "MaxLoginAttemptBeforeLockout",
                          static_cast<uint16_t>(5), err) &&
              setProperty(bus, userRoot, policyIface, "AccountUnlockTimeout",
                          static_cast<uint32_t>(1800), err),
          "set AccountPolicy (12/2/5/1800)");
    {
        uint8_t minlen = 0;
        uint8_t remember = 0;
        uint16_t deny = 0;
        uint32_t unlockTime = 0;
        check(getProperty(bus, userRoot, policyIface, "MinPasswordLength",
                          minlen, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "RememberOldPasswordTimes", remember, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "MaxLoginAttemptBeforeLockout", deny, err) &&
                  getProperty(bus, userRoot, policyIface,
                              "AccountUnlockTimeout", unlockTime, err) &&
                  minlen == 12 && remember == 2 && deny == 5 &&
                  unlockTime == 1800,
              "AccountPolicy read back updated values");
    }
    {
        std::string e;
        const bool ok = setProperty(bus, userRoot, policyIface,
                                    "MinPasswordLength",
                                    static_cast<uint8_t>(4), e);
        check(!ok && e == "xyz.openbmc_project.Common.Error.InvalidArgument",
              "MinPasswordLength<8 rejected (InvalidArgument)");
    }
    setProperty(bus, userRoot, policyIface, "MinPasswordLength",
                static_cast<uint8_t>(8), err);
    setProperty(bus, userRoot, policyIface, "RememberOldPasswordTimes",
                static_cast<uint8_t>(0), err);
    setProperty(bus, userRoot, policyIface, "MaxLoginAttemptBeforeLockout",
                static_cast<uint16_t>(3), err);
    setProperty(bus, userRoot, policyIface, "AccountUnlockTimeout",
                static_cast<uint32_t>(900), err);

    // CreateGroup / DeleteGroup + AllGroups.
    {
        std::string e;
        const bool created =
            callManager(bus, managerIface, "CreateGroup", userRoot, e,
                        std::string(testGroup));
        std::vector<std::string> groups;
        check(created &&
                  getProperty(bus, userRoot, managerIface, "AllGroups", groups,
                              e) &&
                  contains(groups, testGroup),
              "CreateGroup appears in AllGroups");
        const bool deleted =
            callManager(bus, managerIface, "DeleteGroup", userRoot, e,
                        std::string(testGroup));
        groups.clear();
        check(deleted &&
                  getProperty(bus, userRoot, managerIface, "AllGroups", groups,
                              e) &&
                  !contains(groups, testGroup),
              "DeleteGroup removed from AllGroups");
        std::string e2;
        const bool again = callManager(bus, managerIface, "DeleteGroup",
                                       userRoot, e2, std::string(testGroup));
        check(!again &&
                  e2 ==
                      "xyz.openbmc_project.User.Common.Error.GroupNameDoesNotExist",
              "DeleteGroup unknown group rejected");
    }

    // RenameUser + Object.Delete.
    check(callManager(bus, managerIface, "RenameUser", userRoot, err,
                      std::string(testUser), std::string(renamedUser)),
          "RenameUser ut_user1 -> ut_user2");
    {
        UserInfo info;
        const bool ok = getUserInfo(bus, renamedUser, info, err);
        const std::string* priv = ok ? infoString(info, "UserPrivilege") : nullptr;
        check(ok && priv != nullptr && *priv == "priv-operator",
              "renamed user keeps its properties");
    }
    check(callManager(bus, deleteIface, "Delete", userPath(renamedUser), err),
          "Object.Delete removes the user");
    {
        UserInfo info;
        std::string e;
        const bool ok = getUserInfo(bus, renamedUser, info, e);
        check(ok && info.empty(), "deleted user returns empty info");
    }
}

void runStoreTests()
{
    std::ifstream in(usersFile);
    nlohmann::json store;
    bool parsed = false;
    if (in.is_open())
    {
        try
        {
            store = nlohmann::json::parse(std::string(
                std::istreambuf_iterator<char>(in),
                std::istreambuf_iterator<char>()));
            parsed = store.is_object();
        }
        catch (const std::exception&)
        {
            parsed = false;
        }
    }
    check(parsed, "users.json readable and valid");
    if (!parsed)
    {
        return;
    }

    const auto& users = store.value("userList", nlohmann::json::array());
    bool rootOk = false;
    for (const auto& user : users)
    {
        if (user.value("userName", std::string{}) == "root")
        {
            rootOk = user.value("priv", std::string{}) == "priv-admin";
        }
    }
    check(rootOk, "users.json keeps the seeded root account");

    const auto& rule = store.value("userRule", nlohmann::json::object());
    check(rule.contains("minlen") && rule.contains("remember") &&
              rule.contains("deny") && rule.contains("unlock_time"),
          "users.json userRule uses Linux PAM key names");

    check(store.contains("createdGroups") && store["createdGroups"].is_array(),
          "users.json has createdGroups array");

    bool leftovers = false;
    for (const auto& user : users)
    {
        const std::string name = user.value("userName", std::string{});
        if (name == testUser || name == renamedUser || name == passwordUser)
        {
            leftovers = true;
        }
    }
    check(!leftovers, "test users are not persisted after delete");
}

// ---------------------------------------------------------------------------
// Password tests: hash, verification, change and expiration, driven through
// the same C API bmcweb's PAM shim uses.
// ---------------------------------------------------------------------------
bool readStore(nlohmann::json& store)
{
    std::ifstream in(usersFile);
    if (!in.is_open())
    {
        return false;
    }
    try
    {
        store = nlohmann::json::parse(std::string(
            std::istreambuf_iterator<char>(in),
            std::istreambuf_iterator<char>()));
    }
    catch (const std::exception&)
    {
        return false;
    }
    return store.is_object();
}

const nlohmann::json* findStoreUser(const nlohmann::json& store,
                                    const char* name)
{
    // NOTE: json::value() returns a copy, so the entry has to be looked up
    // through find() to keep the returned pointer valid for the caller.
    const auto users = store.find("userList");
    if ((users == store.end()) || !users->is_array())
    {
        return nullptr;
    }
    for (const auto& user : *users)
    {
        if (user.is_object() && user.value("userName", std::string{}) == name)
        {
            return &user;
        }
    }
    return nullptr;
}

std::string storeHash(const nlohmann::json& store, const char* name)
{
    const nlohmann::json* user = findStoreUser(store, name);
    return (user == nullptr) ? std::string{}
                             : user->value("passWordHASH", std::string{});
}

int storeFailTimes(const nlohmann::json& store, const char* name)
{
    const nlohmann::json* user = findStoreUser(store, name);
    return (user == nullptr) ? -1 : user->value("failTimes", -1);
}

int authenticate(const char* user, const char* password)
{
    return zephyrAuthenticate(user, static_cast<uint32_t>(strlen(user)),
                              password,
                              static_cast<uint32_t>(strlen(password)),
                              "selftest");
}

int changePassword(const char* user, const char* password)
{
    return zephyrUpdatePassword(user, static_cast<uint32_t>(strlen(user)),
                                password,
                                static_cast<uint32_t>(strlen(password)));
}

std::string storedPassword(const char* user)
{
    char buffer[64] = {0};
    const int len = zephyrGetPassword(user, static_cast<uint32_t>(strlen(user)),
                                      buffer, sizeof(buffer));
    return (len > 0) ? std::string(buffer, static_cast<size_t>(len))
                     : std::string{};
}

void runPasswordTests(Bus& bus)
{
    std::string err;
    nlohmann::json store;

    // Password hash: the store keeps the sha256 of the factory password.
    check(readStore(store) &&
              storeHash(store, "root") == defaultPasswordHash,
          "users.json keeps sha256(0penBmc) for root");
    check(storedPassword("root") == defaultPassword,
          "passWordAES of root decrypts to 0penBmc");

    // Password verification, the path bmcweb's PAM shim takes.
    check(authenticate("root", defaultPassword) == ZEPHYR_PAM_SUCCESS,
          "authenticate root with the factory password");
    check(authenticate("root", "not-the-password") == ZEPHYR_PAM_AUTHTOK_ERR,
          "authenticate root with a wrong password");

    // The failure counter is persisted, and a good login clears it again.
    check(readStore(store) && storeFailTimes(store, "root") == 1,
          "wrong password counts as a failed attempt");
    check(authenticate("root", defaultPassword) == ZEPHYR_PAM_SUCCESS,
          "correct password after a failed attempt");
    check(readStore(store) && storeFailTimes(store, "root") == 0,
          "successful login clears failTimes");

    // A created account starts with the default password.
    removeIfPresent(bus, passwordUser);
    check(callManager(bus, managerIface, "CreateUser", userRoot, err,
                      std::string(passwordUser),
                      std::vector<std::string>{"web"},
                      std::string("priv-user"), true),
          "CreateUser for the password tests");
    check(readStore(store) &&
              storeHash(store, passwordUser) == defaultPasswordHash,
          "new account stores sha256 of the default password");
    check(storedPassword(passwordUser) == defaultPassword,
          "new account stores the default password for RAKP");
    check(authenticate(passwordUser, defaultPassword) == ZEPHYR_PAM_SUCCESS,
          "new account authenticates with the default password");

    // Password change, the path bmcweb's PATCH Account Password takes.
    check(changePassword(passwordUser, changedPassword) == ZEPHYR_PAM_SUCCESS,
          "change the password of the test account");
    check(authenticate(passwordUser, defaultPassword) ==
              ZEPHYR_PAM_AUTHTOK_ERR,
          "old password stops working after the change");
    check(authenticate(passwordUser, changedPassword) == ZEPHYR_PAM_SUCCESS,
          "new password works after the change");
    check(readStore(store) &&
              storeHash(store, passwordUser) == changedPasswordHash,
          "password change rewrites passWordHASH");
    check(storedPassword(passwordUser) == changedPassword,
          "clear text password follows a password change");
    check(storedPassword("ut_no_such_user").empty(),
          "unknown user has no clear text password");
    check(changePassword(passwordUser, "short") == ZEPHYR_PAM_AUTHTOK_ERR,
          "password change enforces minlen");

    // Password expiration: pwdUpdateTime / expireTime in users.json.
    int64_t now = static_cast<int64_t>(std::time(nullptr));
    check(zephyrTestSetPasswordAge(
              passwordUser, static_cast<uint32_t>(strlen(passwordUser)),
              now - (2 * 24 * 60 * 60), 1) == 0,
          "age the test account password");
    check(authenticate(passwordUser, changedPassword) ==
              ZEPHYR_PAM_NEW_AUTHTOK_REQD,
          "expired password asks for a new one");
    {
        UserInfo info;
        std::string e;
        const bool ok = getUserInfo(bus, passwordUser, info, e);
        const bool* expired =
            ok ? infoBool(info, "UserPasswordExpired") : nullptr;
        check(expired != nullptr && *expired,
              "GetUserInfo reports UserPasswordExpired");
    }
    check(zephyrTestSetPasswordAge(
              passwordUser, static_cast<uint32_t>(strlen(passwordUser)), now,
              99999) == 0,
          "restore the test account password age");
    check(authenticate(passwordUser, changedPassword) == ZEPHYR_PAM_SUCCESS,
          "password verifies again once the age is restored");

    check(callManager(bus, deleteIface, "Delete", userPath(passwordUser), err),
          "delete the password test account");
}

void runTests(Bus& bus)
{
    runManagerTests(bus);
    runPasswordTests(bus);
    runStoreTests();
}

void* selftestThread(void*)
{
    sd_bus* rawBus = nullptr;
    for (int i = 0; i < 100 && connect_to_dbroker(&rawBus) != 0; ++i)
    {
        k_msleep(100);
    }
    if (rawBus == nullptr)
    {
        printk("[usermgr-test] no D-Bus broker connection\n");
        return nullptr;
    }

    Bus bus(rawBus, std::false_type());

    bool serviceUp = false;
    for (int i = 0; i < 100 && !serviceUp; ++i)
    {
        try
        {
            auto msg = bus.new_method_call(dbusService, dbusPath, dbusIface,
                                          "GetNameOwner");
            msg.append(std::string(userManagerService));
            bus.call(msg);
            serviceUp = true;
        }
        catch (const sdbusplus::exception_t&)
        {
            k_msleep(100);
        }
    }
    if (!serviceUp)
    {
        printk("[usermgr-test] %s is not on the bus\n", userManagerService);
        return nullptr;
    }

    // The service claims its bus name just before it enters process_loop(),
    // so wait until it actually answers a request instead of assuming the
    // loop is already running.
    bool answering = false;
    std::string probeErr;
    for (int i = 0; i < 40 && !answering; ++i)
    {
        UserInfo probe;
        answering = getUserInfo(bus, "root", probe, probeErr);
        if (!answering)
        {
            k_msleep(250);
        }
    }
    if (!answering)
    {
        printk("[usermgr-test] %s is not answering (%s)\n", userManagerService,
               probeErr.c_str());
    }

    printk("[usermgr-test] user manager ready, running D-Bus self test\n");
    runTests(bus);
    printk("[usermgr-test] ==== %d passed, %d failed ====\n", passed, failed);

#ifdef CONFIG_PHOSPHOR_USER_MANAGER_SELFTEST_DISCONNECT_BUG
    // Known bug reproduction, kept for whoever fixes the broker socketpair
    // pool: disconnecting hands the socketpair back and the next client
    // connection makes the broker thread fault.
    printk("[usermgr-test] reproducing disconnect bug (broker may die)\n");
    disconnect_from_dbroker(rawBus);
#endif

    // Keep the connection (and this thread) alive: returning the socketpair to
    // the broker pool corrupted the broker when the next client connected, and
    // a one-shot test image has nothing to gain from tearing the connection
    // down.
    while (true)
    {
        k_sleep(K_FOREVER);
    }
}

// The test thread must be a pthread: the D-Bus client throws C++ exceptions
// (SdBusError) and those cannot unwind in a plain K_THREAD_DEFINE thread on
// this target, which ends in std::terminate.
//
// The stack array has K_KERNEL_STACK_LEN() elements (size + reserved trap
// space); pthread_attr_setstack() must be given the array pointer plus the
// logical size, exactly like the app does with its CREATE_TASK_WITH_PTHREAD
// stacks.
K_KERNEL_STACK_DEFINE(selftestStack, 32768);

} // namespace

int user_manager_selftest_start(void)
{
    // Called from user_manager_main() once the service owns its name.
    pthread_attr_t attr;
    int ret = pthread_attr_init(&attr);
    if (ret != 0)
    {
        return ret;
    }
    ret = pthread_attr_setstack(&attr, selftestStack, 32768);
    if (ret != 0)
    {
        return ret;
    }
    pthread_t thread;
    return pthread_create(
        &thread, &attr,
        [](void*) -> void* { return selftestThread(nullptr); }, nullptr);
}
