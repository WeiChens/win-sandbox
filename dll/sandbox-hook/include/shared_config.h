// shared_config.h — 从共享内存读取配置
//
// Rust Host 在创建目标进程前将 SandboxConfig JSON 写入共享内存。
// C++ DLL 在 DllMain 中通过环境变量找到共享内存并解析配置。

#pragma once
#include <string>

/// 共享内存布局（与 Rust sandbox_core::ipc::SharedMemLayout 一致）
#pragma pack(push, 1)
struct SharedMemHeader {
    uint32_t magic;             // 0x53424F58 "SBOX"
    uint32_t version;           // 2
    uint32_t file_rule_count;
    uint32_t net_rule_count;
    wchar_t  audit_event_name[64];
    uint32_t data_size;         // JSON 数据大小
    uint8_t  _reserved[64];
};
#pragma pack(pop)

/// 从共享内存加载配置
/// @return JSON 字符串，失败返回空字符串
std::string LoadConfigFromSharedMemory();

/// 通过环境变量获取共享内存名称
std::string GetSharedMemoryName();
