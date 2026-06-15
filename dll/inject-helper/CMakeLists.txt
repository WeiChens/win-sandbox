cmake_minimum_required(VERSION 3.20)
project(inject-helper
    VERSION 1.0.0
    DESCRIPTION "Windows Sandbox WOW64 Injection Helper (32-bit)"
    LANGUAGES CXX
)

# ============================================================================
# 32-bit 控制台可执行文件 — WOW64 DLL 注入辅助
# ============================================================================

set(SOURCES
    src/main.cpp
)

add_executable(inject_helper ${SOURCES})

set_target_properties(inject_helper PROPERTIES
    PREFIX ""
    SUFFIX ".exe"
    DEBUG_POSTFIX "_d"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ============================================================================
# ★ 编译为控制台应用（输出调试信息到管道）
# ============================================================================
target_compile_options(inject_helper PRIVATE
    /TP
    /utf-8
    /O2
    /W3
    /GS
    /EHsc
    /wd4100
)

target_compile_definitions(inject_helper PRIVATE
    WIN32_LEAN_AND_MEAN
    _CONSOLE
    _WIN32_WINNT=0x0A00
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)

target_link_libraries(inject_helper PRIVATE
    kernel32.lib
)

message(STATUS "=== inject-helper ===")
message(STATUS "  架构: ${CMAKE_GENERATOR_PLATFORM}")
message(STATUS "  构建: ${CMAKE_BUILD_TYPE}")
message(STATUS "  输出: ${CMAKE_BINARY_DIR}/Release/inject_helper.exe")
