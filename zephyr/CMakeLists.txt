if(CONFIG_PHOSPHOR_USER_MANAGER)
    zephyr_library_named(phosphor-user-manager)
    zephyr_library_sources(
        ${ZEPHYR_CURRENT_MODULE_DIR}/mainapp.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/user_mgr.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/user_mgr_libc.cpp
        ${ZEPHYR_CURRENT_MODULE_DIR}/users.cpp
        # ${ZEPHYR_CURRENT_MODULE_DIR}/user-manager-test.cpp
    )

    zephyr_export_include_directories(
        ${ZEPHYR_CURRENT_MODULE_DIR}
    )

    zephyr_library_link_libraries(phosphor-dbus-interfaces)
    zephyr_library_link_libraries(phosphor-logging)

    add_definitions(-DENABLE_ROOT_USER_MGMT) #root_user_mgmt enable

    # #install /lfs/etc/users.json
    # include(${ZEPHYR_CURRENT_MODULE_DIR}/../mk-rofs/zephyr/utils.cmake)
    # file(GLOB FILES ${ZEPHYR_CURRENT_MODULE_DIR}/config/*.json)
    # # configure/后跟目标配置文件在文件系统中的绝对路径, 即usr/share/crashdump/input为配置文件在zephyr文件系统中的路径
    # set(dest_file ${CMAKE_BINARY_DIR}/configure_file/etc/)
    # # install_config_file的具体使用方法请参考mk-rofs中utils.cmake
    # install_config_file(${FILES} DESTINATION ${dest_file})
endif()
