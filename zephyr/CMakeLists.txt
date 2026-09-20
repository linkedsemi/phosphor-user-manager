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

    # Install the packaged user store as /etc/users.json in the rofs image.
    # At runtime the overlay fs exposes it as
    # CONFIG_FS_ROOT_OVERLAY "/etc/users.json" and copies it up to the rw layer
    # on the first write.
    if(EXISTS "${ZEPHYR_MK_ROFS_MODULE_DIR}")
        include(${ZEPHYR_MK_ROFS_MODULE_DIR}/zephyr/utils.cmake)
        set(FILES ${ZEPHYR_CURRENT_MODULE_DIR}/config/users.json)
        # Staged under <build>/configure_file/..., which is the absolute path of
        # the file inside the Zephyr filesystem (rofs staging directory).
        set(dest_file ${CMAKE_BINARY_DIR}/configure_file/etc/)
        # See mk-rofs/zephyr/utils.cmake for install_config_file usage.
        install_config_file(${FILES} DESTINATION ${dest_file})

        # Let CMake watch the source file so changing it re-runs the configure
        # step (otherwise ninja reports "no work to do").
        set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${FILES})
    else()
        message(FATAL_ERROR
                "Required mk-rofs module missing at ${ZEPHYR_MK_ROFS_MODULE_DIR}, build abort!")
    endif()
endif()
