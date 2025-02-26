cmake_minimum_required(VERSION 3.5)

project(barectf_test LANGUAGES C)

if(NOT CMAKE_C_STANDARD)
    set(CMAKE_C_STANDARD 99)
endif()

set(OUTPUT_DIR ${CMAKE_SOURCE_DIR}/../../fixtures/full)

set(BARECTF_CONFIG_FILE ${CMAKE_SOURCE_DIR}/config/schema.yaml)

set(BARECTF_GENERATED_FILES
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/barectf-bitfield.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include/barectf.h
    ${CMAKE_CURRENT_BINARY_DIR}/generated/barectf.c
    ${OUTPUT_DIR}/trace/metadata
    ${OUTPUT_DIR}/effective_config.yaml)

add_custom_command(
    OUTPUT ${BARECTF_GENERATED_FILES}
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated
    COMMAND ${CMAKE_COMMAND} -E make_directory ${CMAKE_CURRENT_BINARY_DIR}/generated/include
    COMMAND ${CMAKE_COMMAND} -E make_directory ${OUTPUT_DIR}/trace
    COMMAND barectf generate
        --metadata-dir ${OUTPUT_DIR}/trace
        --code-dir ${CMAKE_CURRENT_BINARY_DIR}/generated
        --headers-dir ${CMAKE_CURRENT_BINARY_DIR}/generated/include
        --include-dir ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${BARECTF_CONFIG_FILE}
    COMMAND barectf show-effective-configuration
        --include-dir ${CMAKE_CURRENT_SOURCE_DIR}/config
        ${BARECTF_CONFIG_FILE}
        > ${OUTPUT_DIR}/effective_config.yaml
    DEPENDS ${BARECTF_CONFIG_FILES}
    COMMENT "Generating barectf files"
    VERBATIM)

add_custom_target(
    barectf_generated_files
    DEPENDS
    ${BARECTF_GENERATED_FILES})

add_library(
    barectf
    ${CMAKE_CURRENT_BINARY_DIR}/generated/barectf.c)

target_include_directories(
    barectf
    PUBLIC
    ${CMAKE_CURRENT_BINARY_DIR}/generated/include)

target_compile_options(
    barectf
    PRIVATE
    -Wall -Wextra -Werror
    -Wshadow -Wmissing-include-dirs -Wstrict-prototypes
    -Wno-sign-conversion -Wno-unused-function
    -Wno-shift-negative-value)

target_compile_definitions(
    barectf
    PUBLIC
    TRACE_CFG_STREAM_TYPE=default
    TRACE_CFG_CLOCK_TYPE=default
    TRACE_CFG_PACKET_CONTEXT_FIELD=22)

add_dependencies(
    barectf
    barectf_generated_files)

add_executable(
    ${PROJECT_NAME}
    ../common/barectf_platform_linux_fs.c
    src/main.c)

target_include_directories(
    ${PROJECT_NAME}
    PRIVATE
    ../common)

target_link_libraries(
    ${PROJECT_NAME}
    barectf)

target_compile_definitions(
    ${PROJECT_NAME}
    PRIVATE
    TRACE_DIR="${OUTPUT_DIR}/trace")

add_custom_target(
    run
    DEPENDS ${PROJECT_NAME})

add_custom_command(
    TARGET run
    POST_BUILD
    MAIN_DEPENDENCY ${PROJECT_NAME}
    COMMAND ./${PROJECT_NAME}
    COMMENT "Running the full test")
