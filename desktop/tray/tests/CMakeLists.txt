# STATUS: DIAMANT VGT SUPREME
# SPDX-FileCopyrightText: 2026 VisionGaia Technology
# SPDX-License-Identifier: AGPL-3.0-only

find_package(Qt6 REQUIRED COMPONENTS Test)

set(GEDEFENSE_TEST_SOURCES
    tst_popup_render.cpp
    tst_status_client.cpp
    tst_status_payload.cpp)

foreach(test_source IN LISTS GEDEFENSE_TEST_SOURCES)
    get_filename_component(test_name "${test_source}" NAME_WE)
    add_executable("${test_name}" "${test_source}")
    target_link_libraries("${test_name}" PRIVATE gedefense-tray-core Qt6::Test)
    add_test(NAME "${test_name}" COMMAND "${test_name}")
    set_tests_properties("${test_name}" PROPERTIES
        ENVIRONMENT "QT_QPA_PLATFORM=offscreen"
        TIMEOUT 120)
    gedefense_apply_strict_warnings("${test_source}")
endforeach()

# The render test writes one PNG per state so that the composition can be
# reviewed without a desktop session. The resources are compiled in and the test
# asserts that the bundled SVGs - not the painted fallback - are used.
target_compile_definitions(tst_popup_render
    PRIVATE GEDEFENSE_SCREENSHOT_DIR="${CMAKE_BINARY_DIR}/screenshots")
