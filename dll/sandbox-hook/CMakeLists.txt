cmake_minimum_required(VERSION 3.20)
project(sandbox-hook
    VERSION 2.0.0
    DESCRIPTION "Windows Sandbox Hook DLL — NT API hook engine with self-injection"
    LANGUAGES CXX
)

if(NOT MSVC)
    message(FATAL_ERROR "仅支持 MSVC (Microsoft Visual C++)")
endif()

# ============================================================================
# ★ Microsoft Detours — 内联编译（源文件直接加入项目）
# ============================================================================
# Detours 不支持 CMake FetchContent，直接编译源码
set(DETOURS_SRC_DIR ${CMAKE_BINARY_DIR}/_deps/detours-src/src)
if(NOT EXISTS ${DETOURS_SRC_DIR}/detours.cpp)
    # 如果没有预下载，从 GitHub 克隆
    include(FetchContent)
    FetchContent_Declare(detours_src
        GIT_REPOSITORY https://github.com/microsoft/Detours.git
        GIT_TAG v4.0.1
        GIT_SHALLOW TRUE
        SOURCE_DIR ${CMAKE_BINARY_DIR}/_deps/detours-src
    )
    FetchContent_Populate(detours_src)
endif()

set(DETOURS_SOURCES
    ${DETOURS_SRC_DIR}/detours.cpp
    ${DETOURS_SRC_DIR}/modules.cpp
    ${DETOURS_SRC_DIR}/disasm.cpp
    ${DETOURS_SRC_DIR}/image.cpp
)

# ============================================================================
# 源文件
# ============================================================================
set(SOURCES
    src/dllmain.cpp
    src/detour.cpp
    src/hook_engine.cpp       # 编排器：Init/InstallAll/UninstallAll
    src/hook_file.cpp         # 文件 Hook：NtCreate/Open/Delete/SetInfo/WriteFile/QueryDir
    src/hook_process.cpp      # 进程 Hook：NtCreateUserProcess/ResumeThread + SelfInject
    src/hook_crash.cpp        # 崩溃处理：VEH + CorExitProcess 等
    src/hook_memory.cpp       # 内存映射 Hook：NtMapViewOfSection + NtOpenSection
    src/path_resolver.cpp     # 路径解析：NtQueryObject + GetFinalPathNameByHandleW
    src/file_acl.cpp
    src/net_acl.cpp
    src/ipc_client.cpp
    src/shared_config.cpp
    src/utils.cpp
    ${DETOURS_SOURCES}
)

set(HEADERS
    include/detour.h
    include/hook_engine.h
    include/file_acl.h
    include/net_acl.h
    include/ipc_client.h
    include/shared_config.h
    include/utils.h
)

# ============================================================================
# DLL 目标
# ============================================================================
add_library(sandbox_hook SHARED ${SOURCES} ${HEADERS})

set_target_properties(sandbox_hook PROPERTIES
    PREFIX ""
    SUFFIX ".dll"
    DEBUG_POSTFIX "_d"
    CXX_STANDARD 17
    CXX_STANDARD_REQUIRED ON
)

# ============================================================================
# ★ 编译选项 — 完整 CRT + C++17
# ============================================================================
target_compile_options(sandbox_hook PRIVATE
    /TP                                # ★ 强制 C++ 编译（避免 .cpp 被误编译为 C）
    /utf-8                             # ★ UTF-8 源文件编码（消除 C4819 警告）
    /O2                                # 最大速度
    /W3                                # 警告级别 3
    /GS                                # 缓冲区安全检查
    /EHsc                              # C++ 异常处理
    /Zc:__cplusplus                    # 正确的 __cplusplus 宏
    /wd4100 /wd4200 /wd4706            # 抑制噪音警告
)

target_compile_definitions(sandbox_hook PRIVATE
    WIN32_LEAN_AND_MEAN
    _WINDOWS
    _WIN32_WINNT=0x0A00
    _CRT_SECURE_NO_WARNINGS
    NOMINMAX
)

target_include_directories(sandbox_hook PRIVATE
    ${CMAKE_CURRENT_SOURCE_DIR}/include
    ${CMAKE_CURRENT_SOURCE_DIR}/src
    ${DETOURS_SRC_DIR}
)

target_link_libraries(sandbox_hook PRIVATE
    kernel32.lib
    ntdll.lib
    user32.lib
    ws2_32.lib
    advapi32.lib
    shell32.lib          # SHGetFolderPathW for WOW64 dynamic path detection
)

install(TARGETS sandbox_hook
    RUNTIME DESTINATION ${CMAKE_INSTALL_PREFIX}/bin
    LIBRARY DESTINATION ${CMAKE_INSTALL_PREFIX}/lib
)

message(STATUS "=== sandbox-hook DLL ===")
message(STATUS "  架构: ${CMAKE_GENERATOR_PLATFORM}")
message(STATUS "  构建: ${CMAKE_BUILD_TYPE}")
message(STATUS "  CRT:  完整 CRT")
message(STATUS "  输出: ${CMAKE_BINARY_DIR}/Release/sandbox_hook.dll")
