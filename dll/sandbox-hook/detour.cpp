// detour.cpp — x64/x86 内联 Hook 引擎（从 Failure-01 detour.c 移植，C++ 化）
//
// 核心算法保持不变，使用 C++ STL 替代手写数据结构。

#include "detour.h"
#include <cstring>
#include <vector>
#include <algorithm>

// ============================================================================
// CRT 函数（之前 CRT-free 需要手写，现在直接用标准库）
// ============================================================================

// ============================================================================
// 全局 hook 上下文注册表
// ============================================================================
static std::vector<DetourContext*> g_contexts;

// 跳板内存区域追踪（VEH 使用）
struct TrampolineRegion {
    BYTE* base;
    SIZE_T size;
};
static std::vector<TrampolineRegion> g_trampoline_regions;

static void RegisterContext(DetourContext* ctx) {
    g_contexts.push_back(ctx);
    if (ctx->trampoline) {
        g_trampoline_regions.push_back({ctx->trampoline, (SIZE_T)(ctx->patch_size + JMP_SIZE)});
    }
}

static void UnregisterContext(DetourContext* ctx) {
    // 从跳板追踪中移除
    for (auto it = g_trampoline_regions.begin(); it != g_trampoline_regions.end(); ++it) {
        if (it->base == ctx->trampoline) {
            g_trampoline_regions.erase(it);
            break;
        }
    }
}

void DetourUninstallAll() {
    for (auto* ctx : g_contexts) {
        if (ctx && ctx->installed) {
            DetourUninstall(ctx);
        }
    }
    g_contexts.clear();
    g_trampoline_regions.clear();
}

bool IsAddressInTrampoline(const BYTE* addr) {
    for (auto& region : g_trampoline_regions) {
        if (addr >= region.base && addr < (region.base + region.size)) {
            return true;
        }
    }
    return false;
}

// ============================================================================
// 可执行内存分配
// ============================================================================
static BYTE* AllocExec(SIZE_T size) {
    return reinterpret_cast<BYTE*>(
        VirtualAlloc(nullptr, size, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE)
    );
}

static void FreeExec(BYTE* ptr) {
    if (ptr) VirtualFree(ptr, 0, MEM_RELEASE);
}

// ============================================================================
// 指令长度解码器（x64 + x86）
// 从 detour.c 直接移植，保持原有逻辑
// ============================================================================
int GetInstructionLen(BYTE* src) {
    int len = 0;
    int rex = 0;
    BYTE b;

    // 跳过 legacy 前缀
    while (true) {
        b = src[len];
        if (b == 0xF0 || b == 0xF2 || b == 0xF3 ||
            b == 0x2E || b == 0x36 || b == 0x3E ||
            b == 0x26 || b == 0x64 || b == 0x65 ||
            b == 0x66 || b == 0x67) {
            len++;
            continue;
        }
        break;
    }

#if !defined(_M_IX86) && !defined(__i386__)
    // REX 前缀 (0x40-0x4F) — x64 only
    if ((src[len] & 0xF0) == 0x40) {
        rex = 1;
        len++;
    }
#endif

    b = src[len];
    // VEX 2-byte: C5
    if (b == 0xC5 && len + 1 < 15) {
        len += 1;
        b = src[len];
    }
    // VEX 3-byte: C4
    else if (b == 0xC4 && len + 2 < 15) {
        len += 2;
        b = src[len];
    }

    // 双字节 opcode (0F xx)
    int prev = 0;
    if (b == 0x0F) {
        prev = b;
        len += 2;
    } else {
        len += 1;
    }

    b = src[len - 1];
    int has_modrm = 0;

    // 单字节 opcode 含 ModRM
    if ((b >= 0x00 && b <= 0x3F) || (b >= 0x88 && b <= 0x8F) ||
        (b >= 0xD0 && b <= 0xDF) || b == 0x62 || b == 0x63 ||
        b == 0x69 || b == 0x6B || b == 0x80 || b == 0x81 ||
        b == 0x83 || b == 0x84 || b == 0x85 || b == 0x86 ||
        b == 0x87 || b == 0x8A || b == 0x8B || b == 0x8D ||
        b == 0xC6 || b == 0xC7 || b == 0xF6 || b == 0xF7 ||
        b == 0xFE || b == 0xFF || (b >= 0xC0 && b <= 0xC1)) {
        has_modrm = 1;
    }

    // 双字节 opcode 含 ModRM
    if (prev == 0x0F) {
        if ((b >= 0x00 && b <= 0x7F) || (b >= 0x90 && b <= 0x9F) ||
            (b >= 0xA4 && b <= 0xAF) || (b >= 0xB0 && b <= 0xB7) ||
            b == 0x40 || b == 0x41 || b == 0x44 || b == 0x45 ||
            b == 0x4C || b == 0x4D || b == 0x4E || b == 0x4F ||
            b == 0x80 || b == 0x81 || b == 0x82 || b == 0x83 ||
            b == 0x84 || b == 0x85 || b == 0x86 || b == 0x87 ||
            b == 0x8C || b == 0x8D || b == 0x8E || b == 0x8F ||
            (b >= 0xAE && b <= 0xAF)) {
            has_modrm = 1;
        }
    }

    if (has_modrm) {
        BYTE modrm = src[len];
        int mod = (modrm >> 6) & 3;
        int rm = modrm & 7;
        len++;

        // SIB
        if (mod != 3 && rm == 4) {
            BYTE sib = src[len];
            len++;
            int base = sib & 7;
            if (mod == 0 && base == 5) len += 4;
        }

        if (mod == 1) len += 1;
        else if (mod == 2) len += 4;
        else if (mod == 0 && rm == 5) len += 4;

        // 立即数
        if (b == 0x80 || b == 0x83 || b == 0xC6 || b == 0xF6) len += 1;
        else if (b == 0x81 || b == 0xC7 || b == 0xF7) {
            if (b == 0xF7) {
                int reg = (modrm >> 3) & 7;
                if (reg == 0) len += 4;
            } else {
                len += 4;
            }
        }
    } else {
        if (b == 0x68) len += 4;
        else if (b == 0x6A) len += 1;
        else if (b >= 0x70 && b <= 0x7F) len += 1;
        else if (b >= 0xA0 && b <= 0xA3) {
#if defined(_M_IX86) || defined(__i386__)
            len += 4;
#else
            len += 8;
#endif
        }
        else if (b == 0xA8) len += 1;
        else if (b == 0xA9) len += 4;
        else if (b >= 0xB0 && b <= 0xB7) len += 1;
        else if (b >= 0xB8 && b <= 0xBF) {
#if defined(_M_IX86) || defined(__i386__)
            len += 4;
#else
            len += rex ? 8 : 4;
#endif
        }
        else if (b == 0xC2) len += 2;
        else if (b == 0xCD) len += 1;
        else if (b == 0xE8) len += 4;
        else if (b == 0xE9) len += 4;
        else if (b == 0xEB) len += 1;
    }

    return (len > 0 && len <= 15) ? len : 1;
}

// ============================================================================
// Opcode 是否有 ModRM
// ============================================================================
static bool OpcodeHasModrm(BYTE opcode, BYTE prev_op) {
    if ((opcode >= 0x00 && opcode <= 0x3F) || (opcode >= 0x88 && opcode <= 0x8F) ||
        (opcode >= 0xD0 && opcode <= 0xDF) || opcode == 0x62 || opcode == 0x63 ||
        opcode == 0x69 || opcode == 0x6B || opcode == 0x80 || opcode == 0x81 ||
        opcode == 0x83 || opcode == 0x84 || opcode == 0x85 || opcode == 0x86 ||
        opcode == 0x87 || opcode == 0x8A || opcode == 0x8B || opcode == 0x8D ||
        opcode == 0xC6 || opcode == 0xC7 || opcode == 0xF6 || opcode == 0xF7 ||
        opcode == 0xFE || opcode == 0xFF || (opcode >= 0xC0 && opcode <= 0xC1))
        return true;

    if (prev_op == 0x0F) {
        if ((opcode >= 0x00 && opcode <= 0x7F) || (opcode >= 0x90 && opcode <= 0x9F) ||
            (opcode >= 0xA4 && opcode <= 0xAF) || (opcode >= 0xB0 && opcode <= 0xB7) ||
            opcode == 0x40 || opcode == 0x41 || opcode == 0x44 || opcode == 0x45 ||
            opcode == 0x4C || opcode == 0x4D || opcode == 0x4E || opcode == 0x4F ||
            opcode == 0x80 || opcode == 0x81 || opcode == 0x82 || opcode == 0x83 ||
            opcode == 0x84 || opcode == 0x85 || opcode == 0x86 || opcode == 0x87 ||
            opcode == 0x8C || opcode == 0x8D || opcode == 0x8E || opcode == 0x8F ||
            (opcode >= 0xAE && opcode <= 0xAF))
            return true;
    }
    return false;
}

// ============================================================================
// RIP-relative 重定位（x64）
// ============================================================================
static int RelocateInstruction(BYTE* dst, BYTE* src, BYTE* trampoline, BYTE* target) {
#ifdef _M_IX86
    (void)dst; (void)src; (void)trampoline; (void)target;
    return 0;
#else
    int total_len = GetInstructionLen(src);
    if (total_len <= 0) return 0;

    int prefix_len = 0;
    while (src[prefix_len] == 0xF0 || src[prefix_len] == 0xF2 || src[prefix_len] == 0xF3 ||
           src[prefix_len] == 0x2E || src[prefix_len] == 0x36 || src[prefix_len] == 0x3E ||
           src[prefix_len] == 0x26 || src[prefix_len] == 0x64 || src[prefix_len] == 0x65 ||
           src[prefix_len] == 0x66 || src[prefix_len] == 0x67) {
        prefix_len++;
    }
    if ((src[prefix_len] & 0xF0) == 0x40) prefix_len++;

    int opcode_len = (src[prefix_len] == 0x0F) ? 2 : 1;
    BYTE b = src[prefix_len + opcode_len - 1];
    BYTE prev = (opcode_len >= 2) ? src[prefix_len] : 0;

    // ★ x64 CALL (0xE8) / JMP (0xE9) 重定位
    //   这些指令没有 ModRM，但包含相对偏移，需要在跳板中重新计算
    if (b == 0xE8 || b == 0xE9) {
        // 确认完整指令长度 (E8/E9 + rel32 = 5 bytes)
        if (total_len < 5) return 0;
        // 原始目标地址 = src + 5 + old_offset
        int old_offset = *(int*)(src + prefix_len + opcode_len);
        BYTE* orig_target = src + total_len + old_offset;
        // 新目标地址相对跳板位置重新计算
        BYTE* new_pos = dst + total_len;
        int new_offset = (int)(orig_target - new_pos);
        // 拷贝指令（前缀+opcode）
        for (int i = 0; i < prefix_len + opcode_len; i++)
            dst[i] = src[i];
        // 写入新偏移
        *(int*)(dst + prefix_len + opcode_len) = new_offset;
        return total_len;
    }

    // ★ x64 条件跳转 (0F 8x — rel32) 重定位
    if (prev == 0x0F && b >= 0x80 && b <= 0x8F) {
        if (total_len < 6) return 0;
        int old_offset = *(int*)(src + prefix_len + 2);  // 0F 8x + rel32
        BYTE* orig_target = src + total_len + old_offset;
        BYTE* new_pos = dst + total_len;
        int new_offset = (int)(orig_target - new_pos);
        for (int i = 0; i < prefix_len + 2; i++)
            dst[i] = src[i];
        *(int*)(dst + prefix_len + 2) = new_offset;
        return total_len;
    }

    // ★ x64 短跳转 (EB — rel8, 70-7F — 条件 rel8) 重定位
    if (b == 0xEB || (b >= 0x70 && b <= 0x7F)) {
        if (total_len < 2) return 0;
        signed char old_offset = *(signed char*)(src + prefix_len + opcode_len);
        BYTE* orig_target = src + total_len + old_offset;
        BYTE* new_pos = dst + total_len;
        int new_offset = (int)(orig_target - new_pos);
        if (new_offset >= -128 && new_offset <= 127) {
            for (int i = 0; i < prefix_len + opcode_len; i++)
                dst[i] = src[i];
            dst[prefix_len + opcode_len] = (BYTE)(signed char)new_offset;
            return total_len;
        }
        // 偏移超出短跳范围，无法重定位 → 让调用者原始拷贝
        return 0;
    }

    if (!OpcodeHasModrm(b, prev)) return 0;

    int modrm_offset = prefix_len + opcode_len;
    BYTE modrm = src[modrm_offset];
    int mod = (modrm >> 6) & 3;
    int rm = modrm & 7;
    BYTE* disp_ptr = nullptr;

    if (mod != 3) {
        if (rm == 4) {
            BYTE sib = src[modrm_offset + 1];
            int base = sib & 7;
            if (mod == 0 && base == 5) return 0;
        } else if (mod == 0 && rm == 5) {
            disp_ptr = src + modrm_offset + 1;
        }
    }

    if (!disp_ptr) return 0;

    int before_disp = (int)(disp_ptr - src);
    DWORD old_disp = *(DWORD*)(disp_ptr);
    LONG_PTR orig_rip = (LONG_PTR)(src + total_len);
    LONG_PTR eff_addr = orig_rip + (LONG)(old_disp);
    LONG_PTR new_rip = (LONG_PTR)(dst + total_len);
    LONG new_disp_signed = (LONG)(eff_addr - new_rip);

    if ((LONG_PTR)new_disp_signed != eff_addr - new_rip) return 0;

    DWORD new_disp = (DWORD)new_disp_signed;
    for (int i = 0; i < before_disp; i++) dst[i] = src[i];
    *(DWORD*)(dst + before_disp) = new_disp;
    int after_disp = before_disp + 4;
    for (int i = after_disp; i < total_len; i++) dst[i] = src[i];

    return total_len;
#endif
}

// ============================================================================
// x86 相对跳转重定位
// ============================================================================
#ifdef _M_IX86
static int RelocateInstruction_x86(BYTE* dst, BYTE* src, BYTE* trampoline, BYTE* target) {
    (void)trampoline; (void)target;
    int total_len = GetInstructionLen(src);
    if (total_len <= 0 || total_len > 15) return 0;

    BYTE opcode = src[0];

    // E8 — CALL rel32
    if (opcode == 0xE8 && total_len >= 5) {
        int rel_offset = *(int*)(src + 1);
        BYTE* orig_target = src + 5 + rel_offset;
        BYTE* new_dst = dst + 5;
        int new_offset = (int)(orig_target - new_dst);

        dst[0] = 0xE8;
        *(int*)(dst + 1) = new_offset;
        return 5;
    }

    // E9 — JMP rel32
    if (opcode == 0xE9 && total_len >= 5) {
        int rel_offset = *(int*)(src + 1);
        BYTE* orig_target = src + 5 + rel_offset;
        BYTE* new_dst = dst + 5;
        int new_offset = (int)(orig_target - new_dst);

        dst[0] = 0xE9;
        *(int*)(dst + 1) = new_offset;
        return 5;
    }

    // EB — JMP short
    if (opcode == 0xEB && total_len >= 2) {
        signed char rel8 = *(signed char*)(src + 1);
        BYTE* orig_target = src + 2 + rel8;
        BYTE* new_dst = dst + 2;
        int new_offset = (int)(orig_target - new_dst);

        if (new_offset >= -128 && new_offset <= 127) {
            dst[0] = 0xEB;
            dst[1] = (BYTE)(signed char)new_offset;
            return 2;
        }
        return 0;
    }

    // 0F 8x — 条件 JMP rel32
    if (opcode == 0x0F && total_len >= 6) {
        BYTE cond = src[1];
        if (cond >= 0x80 && cond <= 0x8F) {
            int rel_offset = *(int*)(src + 2);
            BYTE* orig_target = src + 6 + rel_offset;
            BYTE* new_dst = dst + 6;
            int new_offset = (int)(orig_target - new_dst);

            dst[0] = 0x0F;
            dst[1] = cond;
            *(int*)(dst + 2) = new_offset;
            return 6;
        }
    }

    // 70-7F — 条件 JMP rel8
    if (opcode >= 0x70 && opcode <= 0x7F && total_len >= 2) {
        signed char rel8 = *(signed char*)(src + 1);
        BYTE* orig_target = src + 2 + rel8;
        BYTE* new_dst = dst + 2;
        int new_offset = (int)(orig_target - new_dst);

        if (new_offset >= -128 && new_offset <= 127) {
            dst[0] = opcode;
            dst[1] = (BYTE)(signed char)new_offset;
            return 2;
        }
        return 0;
    }

    return 0;
}
#endif

// ============================================================================
// 安全 Patch 大小计算
// ============================================================================
static int CalcSafePatchSize(BYTE* target, int min_size) {
    // ★ x64 JMP 指令需要 12 字节，但必须停在完整指令边界
    int needed = min_size;
#ifndef _M_IX86
    if (needed < 12) needed = 12;
#endif
    int pos = 0;
    while (pos < needed) {
        int len = GetInstructionLen(target + pos);
        if (len <= 0) return needed > 24 ? needed : 24;
        pos += len;
    }
    return pos;
}

// ============================================================================
// 跟踪间接跳转（WOW64 关键）
// ============================================================================
static BYTE* FollowJumps(BYTE* target) {
    BYTE* original = target;

#ifdef _M_IX86
    // x86: jmp [imm32] (FF 25 XX XX XX XX)
    if (target[0] == 0xFF && target[1] == 0x25) {
        DWORD ptr_addr = *(DWORD*)(target + 2);
        target = *(BYTE**)(ULONG_PTR)ptr_addr;
    }
    // EB — short jmp
    if (target[0] == 0xEB) {
        target = target + 2 + *(signed char*)&target[1];
    }
    // E9 — near jmp
    if (target[0] == 0xE9) {
        target = target + 5 + *(int*)&target[1];
    }
#endif

    return (target != original) ? target : original;
}

// ============================================================================
// 查找函数地址
// ============================================================================
BYTE* FindFunction(const char* module, const char* name) {
    HMODULE hMod = GetModuleHandleA(module);
    if (!hMod) return nullptr;
    return reinterpret_cast<BYTE*>(GetProcAddress(hMod, name));
}

// ============================================================================
// 安装 Hook
// ============================================================================
void* DetourInstall(BYTE* target, BYTE* detour_fn, const char* name) {
    auto* ctx = new DetourContext();
    ctx->target = target;
    ctx->detour_fn = detour_fn;
    ctx->installed = false;
    strncpy_s(ctx->name, sizeof(ctx->name), name, sizeof(ctx->name) - 1);

    // 跟踪间接跳转
    target = FollowJumps(target);

    int patch_size = CalcSafePatchSize(target, HOOK_MIN_SIZE);
    if (patch_size > HOOK_PATCH_SIZE) patch_size = HOOK_PATCH_SIZE;
    ctx->patch_size = patch_size;

    // 保存原始字节
    memcpy(ctx->original_bytes, target, patch_size);

    // 分配跳板
    SIZE_T trampoline_size = patch_size + JMP_SIZE;
    BYTE* trampoline = AllocExec(trampoline_size);
    if (!trampoline) {
        delete ctx;
        return nullptr;
    }
    ctx->trampoline = trampoline;

    // 构建跳板：逐指令拷贝 + 重定位
    int pos = 0;
    while (pos < patch_size) {
        int consumed = 0;
#ifdef _M_IX86
        consumed = RelocateInstruction_x86(trampoline + pos, target + pos, trampoline, target);
#else
        consumed = RelocateInstruction(trampoline + pos, target + pos, trampoline, target);
#endif
        if (consumed > 0 && consumed <= patch_size - pos) {
            pos += consumed;
        } else {
            int instr_len = GetInstructionLen(target + pos);
            if (instr_len <= 0 || instr_len > patch_size - pos) instr_len = 1;
            memcpy(trampoline + pos, target + pos, instr_len);
            pos += instr_len;
        }
    }

    // 跳板末尾：跳回 target + patch_size
    BYTE* jmp_pos = trampoline + patch_size;
#ifdef _M_IX86
    jmp_pos[0] = 0xE9;
    *(int*)(jmp_pos + 1) = (int)((target + patch_size) - (jmp_pos + 5));
#else
    jmp_pos[0] = 0xFF;
    jmp_pos[1] = 0x25;
    *(DWORD*)(jmp_pos + 2) = 0;
    *(BYTE**)(jmp_pos + 6) = target + patch_size;
#endif

    // 写入 hook
    DWORD old_protect;
    VirtualProtect(target, patch_size, PAGE_EXECUTE_READWRITE, &old_protect);

#ifdef _M_IX86
    target[0] = 0xE9;
    *(int*)(target + 1) = (int)(detour_fn - (target + 5));
    for (int i = 5; i < patch_size; i++) target[i] = 0x90;
#else
    target[0] = 0x48;
    target[1] = 0xB8;
    *(BYTE**)(target + 2) = detour_fn;
    target[10] = 0xFF;
    target[11] = 0xE0;
    for (int i = 12; i < patch_size; i++) target[i] = 0x90;
#endif

    VirtualProtect(target, patch_size, old_protect, &old_protect);
    FlushInstructionCache(GetCurrentProcess(), target, patch_size);

    ctx->installed = true;
    RegisterContext(ctx);
    return trampoline;
}

// ============================================================================
// 卸载 Hook
// ============================================================================
bool DetourUninstall(DetourContext* ctx) {
    if (!ctx || !ctx->installed) return false;

    DWORD old_protect;
    if (!VirtualProtect(ctx->target, ctx->patch_size, PAGE_EXECUTE_READWRITE, &old_protect)) {
        // DLL 可能已卸载，跳过恢复
        ctx->installed = false;
        if (ctx->trampoline) {
            FreeExec(ctx->trampoline);
            ctx->trampoline = nullptr;
        }
        delete ctx;
        return false;
    }

    memcpy(ctx->target, ctx->original_bytes, ctx->patch_size);
    VirtualProtect(ctx->target, ctx->patch_size, old_protect, &old_protect);

    if (ctx->trampoline) {
        FreeExec(ctx->trampoline);
        ctx->trampoline = nullptr;
    }
    ctx->installed = false;
    delete ctx;
    return true;
}
