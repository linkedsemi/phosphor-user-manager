/**
 * Copyright © 2016 IBM Corporation
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "config.h"

#include "user_mgr.hpp"

#include <sdbusplus/bus.hpp>
#include <sdbusplus/server/manager.hpp>

// D-Bus root for user manager
constexpr auto userManagerRoot = "/xyz/openbmc_project/user";

#ifdef __ZEPHYR__
#include <dbus_broker.h>
#include <printk_thread.h>

extern struct k_sem user_manager_ready_sem;

int user_manager_main(int argc, char** argv)
{
    printk_thread(">>> user_manager_main");
    sd_bus* busTmp;
    int rc = connect_to_dbroker(&busTmp);
    if (rc < 0)
    {
        printk_thread("Failed to connect to dbroker: %d", rc);
        return rc;
    }
    // auto io = std::make_shared<boost::asio::io_context>();
    // auto sdbusp = std::make_shared<sdbusplus::asio::connection>(*io, bus);

    sdbusplus::bus::bus bus(busTmp, std::false_type());
    
    sdbusplus::server::manager_t objManager(bus, userManagerRoot);

    phosphor::user::UserMgr userMgr(bus, userManagerRoot);

    // Claim the bus now
    bus.request_name(USER_MANAGER_BUSNAME);

    printk_thread("process_loop");
    k_sem_give(&user_manager_ready_sem);
    // Wait for client request
    bus.process_loop();
    
    // io->run();
    return 0;
}
#else
int main(int /*argc*/, char** /*argv*/)
{
    auto bus = sdbusplus::bus::new_default();
    sdbusplus::server::manager_t objManager(bus, userManagerRoot);

    phosphor::user::UserMgr userMgr(bus, userManagerRoot);

    // Claim the bus now
    bus.request_name(USER_MANAGER_BUSNAME);

    // Wait for client request
    bus.process_loop();
}
#endif
