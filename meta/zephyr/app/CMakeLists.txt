cmake_minimum_required(VERSION 3.20.0)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(service)

# Zephyr only tracks syscall headers under ZEPHYR_BASE/include, so edits to ours
# would not regenerate syscalls.json in an existing (e.g. cached) build dir.
# Reconfigure when the header changes, and drop the stale output when it does.
set(ATMLAB_SYSCALL_HEADER ${CMAKE_CURRENT_SOURCE_DIR}/atmlab_syscall.h)
set(ATMLAB_SYSCALLS_JSON ${CMAKE_BINARY_DIR}/zephyr/misc/generated/syscalls.json)
set_property(DIRECTORY APPEND PROPERTY CMAKE_CONFIGURE_DEPENDS ${ATMLAB_SYSCALL_HEADER})
if(${ATMLAB_SYSCALL_HEADER} IS_NEWER_THAN ${ATMLAB_SYSCALLS_JSON})
  file(REMOVE ${ATMLAB_SYSCALLS_JSON})
endif()

target_sources(app PRIVATE
  src/aal5.c
  src/atm.c
  src/coap_service.c
  src/crc.c
  src/f5.c
  src/inet.c
  src/main.c
  src/netdev.c
  src/pppoeoa.c
  src/signaling.c
  src/socket_atm.c
  src/syscall_guard.c
  src/user_data.c
  src/userspace.c
)
target_compile_options(app PRIVATE -fno-inline)

# Tests
target_sources_ifdef(CONFIG_SELFTEST app PRIVATE src/test/selftest.c)
target_sources_ifdef(CONFIG_SELFTEST_ATM_NETDEV app PRIVATE src/test/netdev.c)

# Ensure the SOC is set correctly
if(NOT CONFIG_SOC STREQUAL "dc233c")
  error("Unsupported SOC ${CONFIG_SOC}")
endif()

# Ship zephyr.elf without our debug info and symbols, keeping Zephyr's. Only the
# final link may use the stripped archive; gen_kobject_list.py needs our DWARF.
set(APP_NODWARF ${APPLICATION_BINARY_DIR}/libapp-nodwarf.a)
add_custom_command(
  OUTPUT ${APP_NODWARF}
  COMMAND ${CMAKE_OBJCOPY} --strip-debug $<TARGET_FILE:app> ${APP_NODWARF}
  DEPENDS app
  COMMENT "Dropping application debug info for the final link"
  VERBATIM
)
add_custom_target(app-nodwarf DEPENDS ${APP_NODWARF})
add_dependencies(${logical_target_for_zephyr_elf} app-nodwarf)

get_target_property(FINAL_LIBS ${logical_target_for_zephyr_elf} LINK_LIBRARIES)
list(TRANSFORM FINAL_LIBS REPLACE "^app$" ${APP_NODWARF})
set_target_properties(${logical_target_for_zephyr_elf} PROPERTIES LINK_LIBRARIES "${FINAL_LIBS}")

# .text is writable due to `-Wl,-N` (ld `--omagic`) in the linker flags.
# Combined with Xtensa's constant pools, this messes with tooling in a horrible way.
# I'd leave this normally, but it's unnecessary pain for ECSC.
add_custom_target(text-readonly ALL
  COMMAND ${PYTHON_EXECUTABLE} ${APPLICATION_SOURCE_DIR}/scripts/clear_section_write_flag.py
          ${APPLICATION_BINARY_DIR}/zephyr/${KERNEL_ELF_NAME} .text
  DEPENDS ${APPLICATION_SOURCE_DIR}/scripts/clear_section_write_flag.py
  COMMENT "Clearing the SHF_WRITE bit -Wl,-N leaves on .text"
  VERBATIM
)
add_dependencies(text-readonly ${logical_target_for_zephyr_elf})

# Dropping our names from the symbol table on top of that is optional: with
# CONFIG_STRIP_APP_SYMBOLS=n, ${KERNEL_ELF_NAME} keeps our function and object
# names.
if(CONFIG_STRIP_APP_SYMBOLS)
  set(DEBUG_ELF ${APPLICATION_BINARY_DIR}/zephyr/zephyr-debug.elf)
  add_custom_command(
    OUTPUT ${DEBUG_ELF}
    COMMAND ${PYTHON_EXECUTABLE} ${APPLICATION_SOURCE_DIR}/scripts/strip_app_symbols.py
            --nm ${CMAKE_NM} --ar ${CMAKE_AR} --objcopy ${CMAKE_OBJCOPY}
            --build-dir ${APPLICATION_BINARY_DIR} --app-lib $<TARGET_FILE:app>
            --debug-copy ${DEBUG_ELF}
            ${APPLICATION_BINARY_DIR}/zephyr/${KERNEL_ELF_NAME}
    DEPENDS ${logical_target_for_zephyr_elf} text-readonly
            ${APPLICATION_SOURCE_DIR}/scripts/strip_app_symbols.py
    COMMENT "Stripping application symbols from ${KERNEL_ELF_NAME}"
    VERBATIM
  )
  add_custom_target(strip-app-symbols ALL DEPENDS ${DEBUG_ELF})
endif()

# Build base-disk to build the template disk image
set(BASE_DISK ${APPLICATION_BINARY_DIR}/base-disk.img)
add_custom_command(
  OUTPUT ${BASE_DISK}
  COMMAND
    env
      BASE_DISK=${BASE_DISK}
      SLOTS_PER_GENERATION=${CONFIG_OAM_SLOTS_PER_GENERATION}
      LIVE_GENERATIONS=${CONFIG_OAM_LIVE_GENERATIONS}
      RECORD_SIZE=${CONFIG_OAM_RECORD_SIZE}
    ${APPLICATION_SOURCE_DIR}/../mkdisk.sh
  DEPENDS ${APPLICATION_SOURCE_DIR}/../mkdisk.sh
  COMMENT "Building base-disk.img"
  VERBATIM
)
add_custom_target(base-disk DEPENDS ${BASE_DISK})

# run-virt to run with the correct hardware setup
add_custom_target(run-virt
  COMMAND
    env
      KERNEL=${APPLICATION_BINARY_DIR}/zephyr/${KERNEL_ELF_NAME}
      QEMU=${QEMU}
      BASE_DISK=${BASE_DISK}
    ${APPLICATION_SOURCE_DIR}/../run.sh
  DEPENDS ${logical_target_for_zephyr_elf} ${BASE_DISK}
  USES_TERMINAL
  VERBATIM
)
