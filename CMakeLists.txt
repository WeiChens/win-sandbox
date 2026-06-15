cmake_minimum_required(VERSION 3.20)
project(windows-sandbox
    VERSION 2.0.0
    DESCRIPTION "Windows Sandbox — AI-callable sandbox terminal"
    LANGUAGES CXX
)

# ============================================================================
# Windows Sandbox — 一键构建所有子项目
#
# 子项目:
#   1. sandbox-hook    — C++ 注入 DLL (CMake)
#   2. sandbox-core    — Rust 共享类型库 (Cargo)
#   3. sandbox-host    — Rust 宿主进程 (Cargo)
# ============================================================================

set(SANDBOX_ROOT ${CMAKE_CURRENT_SOURCE_DIR})
set(OUTPUT_DIR ${SANDBOX_ROOT}/output)

# ============================================================================
# 检测工具链
# ============================================================================
find_program(CARGO cargo REQUIRED)
message(STATUS "Cargo: ${CARGO}")
message(STATUS "CMake: ${CMAKE_COMMAND}")

# 创建 output 目录
file(MAKE_DIRECTORY ${OUTPUT_DIR})

# ============================================================================
# 1. C++ DLL (sandbox-hook) — x64 + x86
# ============================================================================
set(DLL_SRC_DIR ${SANDBOX_ROOT}/dll/sandbox-hook)

add_custom_target(sandbox-hook-x64 ALL
    COMMAND ${CMAKE_COMMAND} -B ${DLL_SRC_DIR}/build-x64 -A x64 -DCMAKE_BUILD_TYPE=Release
    COMMAND ${CMAKE_COMMAND} --build ${DLL_SRC_DIR}/build-x64 --config Release
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${DLL_SRC_DIR}/build-x64/Release/sandbox_hook.dll
        ${OUTPUT_DIR}/sandbox_hook_x64.dll
    WORKING_DIRECTORY ${DLL_SRC_DIR}
    COMMENT "Building sandbox-hook.dll (x64) → output/"
)

add_custom_target(sandbox-hook-x86 ALL
    COMMAND ${CMAKE_COMMAND} -B ${DLL_SRC_DIR}/build-x86 -A Win32 -DCMAKE_BUILD_TYPE=Release
    COMMAND ${CMAKE_COMMAND} --build ${DLL_SRC_DIR}/build-x86 --config Release
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${DLL_SRC_DIR}/build-x86/Release/sandbox_hook.dll
        ${OUTPUT_DIR}/sandbox_hook_x86.dll
    WORKING_DIRECTORY ${DLL_SRC_DIR}
    COMMENT "Building sandbox-hook.dll (x86) → output/"
)

# ============================================================================
# 1.5. WOW64 注入辅助程序 (32-bit)
# ============================================================================
set(INJECT_HELPER_DIR ${SANDBOX_ROOT}/dll/inject-helper)

add_custom_target(inject-helper-x86 ALL
    COMMAND ${CMAKE_COMMAND} -B ${INJECT_HELPER_DIR}/build -A Win32 -DCMAKE_BUILD_TYPE=Release
    COMMAND ${CMAKE_COMMAND} --build ${INJECT_HELPER_DIR}/build --config Release
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${INJECT_HELPER_DIR}/build/Release/inject_helper.exe
        ${OUTPUT_DIR}/sandbox_helper_x86.exe
    WORKING_DIRECTORY ${INJECT_HELPER_DIR}
    COMMENT "Building inject-helper.exe (x86) → output/"
)

# ============================================================================
# 2 & 3. Rust 项目 (sandbox-core + sandbox-host)
# ============================================================================
if(WIN32)
    set(CARGO_BUILD_FLAGS --release)
else()
    set(CARGO_BUILD_FLAGS)
endif()

add_custom_target(sandbox-host ALL
    COMMAND ${CARGO} build ${CARGO_BUILD_FLAGS}
    COMMAND ${CMAKE_COMMAND} -E copy_if_different
        ${SANDBOX_ROOT}/target/release/sandbox-host.exe
        ${OUTPUT_DIR}/sandbox-host.exe
    WORKING_DIRECTORY ${SANDBOX_ROOT}
    COMMENT "Building Rust host → output/"
)

# ============================================================================
# 聚合目标
# ============================================================================
add_custom_target(all-dlls
    DEPENDS sandbox-hook-x64 sandbox-hook-x86
    COMMENT "All DLLs built → output/"
)

add_custom_target(all-rust
    DEPENDS sandbox-host
    COMMENT "All Rust targets built → output/"
)

# ============================================================================
# 帮助信息
# ============================================================================
message(STATUS "")
message(STATUS "=== Windows Sandbox Build System ===")
message(STATUS "  Targets:")
message(STATUS "    sandbox-hook-x64  — x64 注入 DLL")
message(STATUS "    sandbox-hook-x86  — x86 注入 DLL")
message(STATUS "    sandbox-host      — Rust 宿主进程")
message(STATUS "    all-dlls          — 两个 DLL")
message(STATUS "    all-rust          — Rust 项目")
message(STATUS "")
message(STATUS "  Build all:")
message(STATUS "    cmake --build build --config Release")
message(STATUS "")
