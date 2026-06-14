// shared_config.cpp — 从共享内存读取配置

#include "shared_config.h"
#include <windows.h>
#include <string>

std::string GetSharedMemoryName() {
    wchar_t nameBuf[256] = {0};
    if (GetEnvironmentVariableW(L"SBOX_SHARED_DATA", nameBuf, 256) > 0) {
        char mb[256] = {0};
        WideCharToMultiByte(CP_UTF8, 0, nameBuf, -1, mb, sizeof(mb), nullptr, nullptr);
        return std::string(mb);
    }
    return "";
}

std::string LoadConfigFromSharedMemory() {
    std::string shmName = GetSharedMemoryName();
    if (shmName.empty()) {
        OutputDebugStringA("[sandbox_hook] SBOX_SHARED_DATA not set\n");
        return "";
    }

    // 转换为宽字符
    int wideLen = MultiByteToWideChar(CP_UTF8, 0, shmName.c_str(), -1, nullptr, 0);
    std::wstring wideName(wideLen, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, shmName.c_str(), -1, &wideName[0], wideLen);

    // 打开共享内存
    HANDLE hShm = OpenFileMappingW(FILE_MAP_READ, FALSE, wideName.c_str());
    if (!hShm) {
        OutputDebugStringA("[sandbox_hook] OpenFileMappingW failed\n");
        return "";
    }

    // 映射视图
    void* view = MapViewOfFile(hShm, FILE_MAP_READ, 0, 0, 0);
    if (!view) {
        CloseHandle(hShm);
        OutputDebugStringA("[sandbox_hook] MapViewOfFile failed\n");
        return "";
    }

    // 读取头部
    auto* hdr = reinterpret_cast<SharedMemHeader*>(view);
    if (hdr->magic != 0x53424F58) { // "SBOX"
        UnmapViewOfFile(view);
        CloseHandle(hShm);
        OutputDebugStringA("[sandbox_hook] Bad magic\n");
        return "";
    }

    if (hdr->data_size == 0 || hdr->data_size > 256 * 1024) {
        UnmapViewOfFile(view);
        CloseHandle(hShm);
        OutputDebugStringA("[sandbox_hook] Invalid data size\n");
        return "";
    }

    // 读取 JSON 数据
    size_t hdrSize = sizeof(SharedMemHeader);
    std::string json(reinterpret_cast<char*>(static_cast<uint8_t*>(view) + hdrSize), hdr->data_size);

    UnmapViewOfFile(view);
    CloseHandle(hShm);

    char buf[256];
    snprintf(buf, sizeof(buf), "[sandbox_hook] Config loaded: %u bytes, %u file rules, %u net rules\n",
             hdr->data_size, hdr->file_rule_count, hdr->net_rule_count);
    OutputDebugStringA(buf);

    return json;
}
