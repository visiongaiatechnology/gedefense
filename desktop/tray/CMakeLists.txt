# STATUS: DIAMANT VGT SUPREME
# SPDX-FileCopyrightText: 2026 VisionGaia Technology
# SPDX-License-Identifier: AGPL-3.0-only
#
# gedefense-tray - Qt6/C++17 StatusNotifierItem tray client for the GeDefense
# control plane. Reads exactly one bounded JSON line from the read-only
# /run/gedefense/gedefense.sock Unix domain socket.

cmake_minimum_required(VERSION 3.16)

project(gedefense-tray
    VERSION 5.0.0
    DESCRIPTION "GeDefense desktop tray client"
    LANGUAGES CXX)

# CMake project() versions must be numeric. The public product version is a
# pre-release string and is passed to the tray through its own definition.
set(GEDEFENSE_TRAY_PRODUCT_VERSION "5.0.0-beta.2")

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
    set(CMAKE_BUILD_TYPE RelWithDebInfo CACHE STRING "Build type" FORCE)
endif()

include(GNUInstallDirs)

# Qt6::Svg renders the bundled, hand-written status silhouettes. No icon font,
# no external asset and no network dependency is involved.
find_package(Qt6 6.4 REQUIRED COMPONENTS Core Gui Widgets Network Svg)
qt_standard_project_setup()

# The status silhouettes are compiled into the binary from
# resources/gedefense-tray.qrc. AUTORCC is set explicitly: it is not implied by
# qt_standard_project_setup() on all Qt versions, and without it the .qrc would
# be silently ignored and the icons would fall back to the painted placeholder.
set(CMAKE_AUTORCC ON)

enable_testing()

# ---------------------------------------------------------------------------
# Warnings as errors, applied to the project's own translation units only.
# moc/rcc generated sources are separate translation units and are not touched
# by this, so nothing here can be "fixed" by lowering a flag for our code.
# ---------------------------------------------------------------------------
set(GEDEFENSE_STRICT_WARNINGS "")
if(CMAKE_CXX_COMPILER_ID MATCHES "GNU")
    list(APPEND GEDEFENSE_STRICT_WARNINGS
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wold-style-cast
        -Wnon-virtual-dtor
        -Woverloaded-virtual
        -Wdouble-promotion
        -Wformat=2
        -Wcast-qual
        -Wnull-dereference
        -Wduplicated-cond
        -Wduplicated-branches
        -Werror)
elseif(CMAKE_CXX_COMPILER_ID MATCHES "Clang")
    list(APPEND GEDEFENSE_STRICT_WARNINGS
        -Wall
        -Wextra
        -Wpedantic
        -Wshadow
        -Wconversion
        -Wsign-conversion
        -Wold-style-cast
        -Wnon-virtual-dtor
        -Woverloaded-virtual
        -Wdouble-promotion
        -Wformat=2
        -Wcast-qual
        -Wnull-dereference
        -Werror)
endif()

function(gedefense_apply_strict_warnings)
    if(NOT GEDEFENSE_STRICT_WARNINGS)
        return()
    endif()
    foreach(source_file IN LISTS ARGN)
        set_source_files_properties("${source_file}" PROPERTIES
            COMPILE_OPTIONS "${GEDEFENSE_STRICT_WARNINGS}")
    endforeach()
endfunction()

# ---------------------------------------------------------------------------
# Core library: transport, validation, tray presence, flyout.
# ---------------------------------------------------------------------------
set(GEDEFENSE_CORE_SOURCES
    src/app_paths.h
    src/state_icons.cpp
    src/state_icons.h
    src/state_labels.cpp
    src/state_labels.h
    src/status_client.cpp
    src/status_client.h
    src/status_payload.cpp
    src/status_payload.h
    src/status_popup.cpp
    src/status_popup.h
    src/theme.h
    src/tray_controller.cpp
    src/tray_controller.h)

add_library(gedefense-tray-core STATIC
    ${GEDEFENSE_CORE_SOURCES}
    resources/gedefense-tray.qrc)

add_library(gedefense::tray-core ALIAS gedefense-tray-core)

target_include_directories(gedefense-tray-core
    PUBLIC "${CMAKE_CURRENT_SOURCE_DIR}/src")

target_link_libraries(gedefense-tray-core
    PUBLIC
        Qt6::Core
        Qt6::Gui
        Qt6::Widgets
        Qt6::Network
        Qt6::Svg)

# Explicit string construction everywhere: no implicit const char* -> QString
# conversion, which is how untrusted text usually leaks into the UI by accident.
target_compile_definitions(gedefense-tray-core
    PUBLIC
        QT_NO_CAST_FROM_ASCII
        QT_NO_CAST_TO_ASCII
        QT_NO_CAST_FROM_BYTEARRAY
        QT_NO_URL_CAST_FROM_STRING)

gedefense_apply_strict_warnings(${GEDEFENSE_CORE_SOURCES})

# ---------------------------------------------------------------------------
# Application
# ---------------------------------------------------------------------------
qt_add_executable(gedefense-tray src/main.cpp)
target_link_libraries(gedefense-tray PRIVATE gedefense-tray-core)
target_compile_definitions(gedefense-tray
    PRIVATE GEDEFENSE_TRAY_VERSION="${GEDEFENSE_TRAY_PRODUCT_VERSION}")
gedefense_apply_strict_warnings(src/main.cpp)

# ---------------------------------------------------------------------------
# Translations: compiled by lrelease when Qt6 LinguistTools is available.
# Without lrelease the binary still builds and runs; it then uses the built-in
# German strings (see main.cpp).
# ---------------------------------------------------------------------------
set(GEDEFENSE_LANGUAGES de en ru zh)
set(GEDEFENSE_QM_FILES "")

find_package(Qt6 QUIET COMPONENTS LinguistTools)
if(Qt6LinguistTools_FOUND)
    foreach(language IN LISTS GEDEFENSE_LANGUAGES)
        set(ts_file "${CMAKE_CURRENT_SOURCE_DIR}/i18n/gedefense-tray_${language}.ts")
        set(qm_file "${CMAKE_BINARY_DIR}/i18n/gedefense-tray_${language}.qm")
        add_custom_command(
            OUTPUT "${qm_file}"
            COMMAND "${CMAKE_COMMAND}" -E make_directory "${CMAKE_BINARY_DIR}/i18n"
            COMMAND Qt6::lrelease "${ts_file}" -qm "${qm_file}"
            DEPENDS "${ts_file}"
            COMMENT "Compiling translation gedefense-tray_${language}.qm"
            VERBATIM)
        list(APPEND GEDEFENSE_QM_FILES "${qm_file}")
    endforeach()
    add_custom_target(gedefense-tray-translations ALL DEPENDS ${GEDEFENSE_QM_FILES})
    add_dependencies(gedefense-tray gedefense-tray-translations)
else()
    message(STATUS "Qt6 LinguistTools not found: skipping .qm compilation (built-in German strings are used).")
endif()

# ---------------------------------------------------------------------------
# Installation
# ---------------------------------------------------------------------------
install(TARGETS gedefense-tray RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(FILES packaging/gedefense-tray.desktop
    DESTINATION "${CMAKE_INSTALL_DATADIR}/applications")
install(FILES packaging/gedefense-tray-autostart.desktop
    DESTINATION "${CMAKE_INSTALL_DATADIR}/autostart")
install(FILES resources/shield-secure.svg
    DESTINATION "${CMAKE_INSTALL_DATADIR}/icons/hicolor/scalable/apps"
    RENAME gedefense-tray.svg)
if(GEDEFENSE_QM_FILES)
    install(FILES ${GEDEFENSE_QM_FILES}
        DESTINATION "${CMAKE_INSTALL_DATADIR}/gedefense-tray/i18n")
endif()

add_subdirectory(tests)
