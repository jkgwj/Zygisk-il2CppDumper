//
// key_hook.cpp
// 用例实现：见 key_hook.h。
// 目标方法：Beyond.VFS.VirtualFileSystem::GetCommonChachaKeyBs(Span<byte>)
//           RVA 0xcb97990（Common.Beyond.dll，dump.cs 已确认）。
//
// 关键设计：hook 与 dump 解耦。prepare 全程包在 SIGSEGV/SIGBUS 护栏里——
// 类定位/装 hook 等读游戏内存的步骤内部异常都会被捕获并记日志，然后解除
// 已安装的 hook 并返回失败，绝不影响 hack_start 里原有的 dump。
// flush 刻意不上护栏：它是纯自家缓冲/文件操作，而 SIGSEGV handler 是进程级
// 唯一槽位，挂满 flush 循环会与 metadata_dump 的 CrashGuardScope 互相 clobber。
//

#include "key_hook.h"
#include "hook_framework.h"
#include "log.h"

#include <cstdio>
#include <cstring>
#include <setjmp.h>
#include <signal.h>
#include <unistd.h>
#include <thread>

#define TARGET_NS "Beyond.VFS"
#define TARGET_CLASS "VirtualFileSystem"
#define TARGET_METHOD "GetCommonChachaKeyBs"
#define TARGET_RVA 0xcb97990ull
#define KEY_FIELD "s_commomChachaKeyBs"
#define KEY_FIELD_LEN 32
#define ENABLE_MANUAL_CALL 1
#define ENABLE_CALL_FALLBACK 0

namespace KeyHook {

namespace {

// ---------------------------------------------------------------------------
// 崩溃护栏：SIGSEGV/SIGBUS -> siglongjmp 回本线程 setjmp 点。
// 仅当本线程 g_guard 置位时捕获，其余转发给原 handler（不影响游戏自身信号）。
// ---------------------------------------------------------------------------
thread_local sigjmp_buf g_jmp;
thread_local volatile sig_atomic_t g_guard = 0;
thread_local int g_fault_sig = 0;
struct sigaction g_old_segv{};
struct sigaction g_old_bus{};

void crash_handler(int sig, siginfo_t *si, void *uc) {
    if (g_guard) {
        g_fault_sig = sig;
        siglongjmp(g_jmp, 1);
    }
    struct sigaction *old = (sig == SIGSEGV) ? &g_old_segv : &g_old_bus;
    if (old->sa_flags & SA_SIGINFO) {
        if (old->sa_sigaction) old->sa_sigaction(sig, si, uc);
    } else if (old->sa_handler && old->sa_handler != SIG_DFL && old->sa_handler != SIG_IGN) {
        old->sa_handler(sig);
    } else {
        signal(sig, SIG_DFL);
        raise(sig);
    }
}

bool install_guard() {
    struct sigaction act{};
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = crash_handler;
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, &g_old_segv) != 0) return false;
    if (sigaction(SIGBUS, &act, &g_old_bus) != 0) {
        sigaction(SIGSEGV, &g_old_segv, nullptr);
        return false;
    }
    return true;
}

void uninstall_guard() {
    sigaction(SIGSEGV, &g_old_segv, nullptr);
    sigaction(SIGBUS, &g_old_bus, nullptr);
}

void hex_of(const uint8_t *d, int n, char *out) {
    static const char hex[] = "0123456789abcdef";
    for (int i = 0; i < n; ++i) {
        out[i * 2] = hex[d[i] >> 4];
        out[i * 2 + 1] = hex[d[i] & 0xf];
    }
    out[n * 2] = '\0';
}

} // namespace

namespace {

int prepare_locked(const char *game_data_dir) {
    static char out_path[512];
    snprintf(out_path, sizeof(out_path), "%s/files/hook.out", game_data_dir);

    int rc = HookFramework::install_span_hook(TARGET_NS, TARGET_CLASS, TARGET_METHOD, 1,
                                              TARGET_RVA, out_path);
    HookFramework::log_line("[key_hook] install rc=%d", rc);
    LOGI("[key_hook] install rc=%d", rc);
    if (rc != 0) {
        // 注意: 此处的"未找到"/"未就绪"并非故障——start_synced 会重试。
        return rc;
    }

    // 交叉比对：静态字段 s_commomChachaKeyBs
    uint8_t st[KEY_FIELD_LEN];
    int64_t st_len = 0;
    if (HookFramework::read_static_byte_array(TARGET_NS, TARGET_CLASS, KEY_FIELD,
                                                  st, sizeof(st), &st_len) == 0 && st_len > 0) {
        char hex[KEY_FIELD_LEN * 2 + 1];
        hex_of(st, (int) st_len, hex);
        char hdr[256];
        snprintf(hdr, sizeof(hdr), "static %s len=%lld data=%s", KEY_FIELD,
                 (long long) st_len, hex);
        HookFramework::set_extra_header(hdr);
        HookFramework::log_line("[key_hook] 静态字段比对: %s", hdr);
        LOGI("[key_hook] 静态字段比对: %s", hdr);
    } else {
        HookFramework::log_line("[key_hook] 静态字段 %s 暂未初始化或读取失败", KEY_FIELD);
        LOGI("[key_hook] 静态字段 %s 暂未初始化或读取失败", KEY_FIELD);
    }

#if ENABLE_MANUAL_CALL
    // 手动调用不再在安装后立即执行（早期在 dump 线程执行游戏方法会 SIGBUS，
    // siglongjmp 弃锁导致游戏主线程死锁黑屏）。改为 flush 线程延后 3 分钟触发，
    // 由 run_flush_loop 的 on_time_cb 一次性调用 delayed_manual_call()。
    // 见 flush()/delayed_manual_call()。
#endif

#if ENABLE_CALL_FALLBACK
    // 兜底：主动调用（用 32 字节 native buffer 试"填满入参 buffer"语义）
    uint8_t arg_buf[KEY_FIELD_LEN] = {0};
    uint8_t ret_buf[KEY_FIELD_LEN];
    int64_t ret_len = 0;
    int rc2 = HookFramework::call_method_span16(TARGET_NS, TARGET_CLASS, TARGET_METHOD, 1,
                                                arg_buf, KEY_FIELD_LEN,
                                                ret_buf, sizeof(ret_buf), &ret_len);
    LOGI("[key_hook] 主动调用 rc=%d ret_len=%lld", rc2, (long long) ret_len);
    if (rc2 == 0 && ret_len > 0) {
        char hex[KEY_FIELD_LEN * 2 + 1];
        hex_of(ret_buf, (int) ret_len, hex);
        LOGI("[key_hook] 主动调用返回: %s", hex);
    }
#endif

    return rc;
}

} // namespace

int prepare(const char *game_data_dir) {
    if (!install_guard()) {
        LOGI("[key_hook] 护栏安装失败, 跳过 hook");
        return -1;
    }
    g_fault_sig = 0;
    g_guard = 1;
    int rc = -1;
    if (sigsetjmp(g_jmp, 1) == 0) {
        rc = prepare_locked(game_data_dir);
    } else {
        LOGI("[key_hook] prepare 触发异常信号 %d", g_fault_sig);
        HookFramework::log_line("[key_hook] prepare 触发异常信号 %d, 解除 hook 还原 (绝不留半截函数坑给游戏)",
                                g_fault_sig);
        // jkgbk: 一律 unhook 还原原始 methodPointer，返回失败让 start_synced 重试。
        // 若 hook 已装但后续步骤(读静态字段/手动调用)故障，保留损坏的 trampoline
        // 会让游戏后续真实调用死锁/带崩(卡住不闪退的根因)。宁可这次不装，下次重试。
        HookFramework::unhook();
        rc = -1;
    }
    g_guard = 0;
    uninstall_guard();
    return rc;
}

// 延后手动调用（flush 线程 run_flush_loop 的 on_time_cb，3 分钟后触发一次）：
// 等静态字段 s_commomChachaKeyBs 就绪后再经已装 tramp 主动调一次拿密钥。
// 单独起崩溃护栏：手动调用会执行游戏托管方法，若仍异常绝不留坑给游戏。
void delayed_manual_call() {
#if ENABLE_MANUAL_CALL
    HookFramework::log_line("[key_hook] 延时手动调用触发 (3 分钟到点)");
    if (!install_guard()) {
        HookFramework::log_line("[key_hook] 护栏安装失败, 跳过延时手动调用");
        return;
    }
    g_fault_sig = 0;
    g_guard = 1;
    if (sigsetjmp(g_jmp, 1) == 0) {
        uint8_t arg_buf[KEY_FIELD_LEN] = {0};
        uint8_t ret_buf[KEY_FIELD_LEN];
        int64_t ret_len = 0;
        int rc = HookFramework::call_once(arg_buf, KEY_FIELD_LEN,
                                          ret_buf, sizeof(ret_buf), &ret_len);
        HookFramework::log_line("[key_hook] 延时手动调用 rc=%d ret_len=%lld", rc, (long long) ret_len);
        if (rc == 0 && ret_len > 0) {
            char hex[KEY_FIELD_LEN * 2 + 1];
            hex_of(ret_buf, (int) ret_len, hex);
            char hdr[256];
            snprintf(hdr, sizeof(hdr), "manual call ret len=%lld data=%s",
                     (long long) ret_len, hex);
            HookFramework::set_extra_header(hdr);
            HookFramework::log_line("[key_hook] 延时手动调用返回: %s", hex);
        } else {
            HookFramework::log_line("[key_hook] 延时手动调用未取得有效返回");
        }
    } else {
        HookFramework::log_line("[key_hook] 延时手动调用触发异常信号 %d, 解除 hook 还原",
                                g_fault_sig);
        HookFramework::unhook();
    }
    g_guard = 0;
    uninstall_guard();
#endif
}

void flush() {
    if (!HookFramework::hook_installed()) {
        LOGI("[key_hook] 未安装 hook, 跳过 flush");
        return;
    }
    // 注意：刻意不装崩溃护栏。flush 只操作自家环形缓冲/文件/mutex，
    // 不可能触发 SIGSEGV/SIGBUS；而 SIGSEGV handler 是进程级唯一槽位，
    // 挂满整个 flush 循环会与 metadata_dump 的 CrashGuardScope 互相
    // 覆盖 clobber（保存/恢复的 old handler 交错时链失效）。良性操作不上护栏。
    // 手动调用延后 3 分钟在 flush 线程触发一次（on_time_cb）：
    // 等 s_commomChachaKeyBs 静态字段就绪后再执行，避免早期在 dump 线程
    // 直接跑游戏方法 SIGBUS + siglongjmp 弃锁 → 游戏主线程死锁黑屏。
    HookFramework::run_flush_loop(200, delayed_manual_call, 3 * 60 * 1000);
}

void start_synced(const char *game_data_dir) {
    LOGI("[key_hook] start_synced: dump.cs 已完成, 由 dump 线程本线程安装 hook");
    const int kInstallTries = 10;
    for (int i = 1; i <= kInstallTries; ++i) {
        if (prepare(game_data_dir) == 0) {
            LOGI("[key_hook] 安装成功, 另起独立 flush 线程 (不阻塞 metadata/so dump)");
            std::thread flush_thread(flush);
            flush_thread.detach();
            return;
        }
        LOGI("[key_hook] 第 %d/%d 次安装未成功, 1s 后重试", i, kInstallTries);
        sleep(1);
    }
    LOGI("[key_hook] %d 次尝试仍未安装成功, 放弃 hook (不影响 dump)", kInstallTries);
}

} // namespace KeyHook
