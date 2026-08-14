//
// hook_framework.h
//
// 实验性（jkgbk 分支）：按偏移/MethodInfo 换 methodPointer 的通用 hook 框架。
// 与 dump 一样走"零新增"路线：不 dlopen 新 so、不新增可执行映射、不新增线程，
// 仅替换目标方法 MethodInfo.methodPointer 数据字段，拦截后透明转发并记录参数/返回值。
//
// 当前支持签名：static Span<byte> fn(Span<byte> arg)（arm64 上 16 字节结构经 x0/x1 传/返）。
// 记录：seq 从 1 起，最多 kMaxCalls=500 条；flush 线程把记录追加写入 hook.out。
//

#ifndef ZYGISK_IL2CPPDUMPER_HOOK_FRAMEWORK_H
#define ZYGISK_IL2CPPDUMPER_HOOK_FRAMEWORK_H

#include <cstdint>
#include <cstddef>

namespace HookFramework {

// 与 IL2CPP Span<byte> 内存布局一致：{void* ref; int64_t len}，16 字节。
struct Span16 {
    void *ref;
    int64_t len;
};

// 最多记录的调用次数
constexpr int kMaxCalls = 500;

// 结果码
enum {
    kOk = 0,
    kErrNoLibil2cpp = -1,   // libil2cpp.so 未加载
    kErrApiMissing = -2,    // 关键 il2cpp API 缺失
    kErrClassNotFound = -3, // 类未找到
    kErrMethodNotFound = -4,// 方法未找到
    kErrInstall = -5,       // 安装失败
    kErrNotReady = -6,      // il2cpp 运行时未就绪（宁可等，绝不提前遍历类型表）
};

// il2cpp 运行时就绪检测：is_vm_thread 为真 / domain_get 非空。
// 就绪前 install_span_hook 直接返回 kErrNotReady，不碰类型表（提前并发遍历
// 会扰乱运行时懒初始化，把游戏主线程带崩，这是之前闪退的根因）。
bool runtime_ready();

// 定位 libil2cpp 基址（xdl_info，不新增加载）
uintptr_t libil2cpp_base();

// 安装 hook：找到 (ns.cls.method, argc) 的 MethodInfo，把 methodPointer 换成内部 trampoline。
// 若 expected_rva != 0，则校验 methodPointer == libil2cpp_base + expected_rva（不符仅告警，
// 可能已被 IFix 换体）。out_path 为 hook.out 输出路径，run_flush_loop() 会写入它。
int install_span_hook(const char *ns, const char *cls, const char *method, int argc,
                      uintptr_t expected_rva, const char *out_path);

// 当前是否已安装 hook（用于护栏异常后决定是否 needs unhook）。
bool hook_installed();

// 撤销 hook：把 methodPointer 恢复为原始指针。护栏捕获异常后调用，避免残留 trampoline。
void unhook();

// 按 RVA 反向定位：扫描类方法列表中 methodPointer==base+rva 的那个。
// 返回该方法 methodPointer（失败 0）。方法名被 strip 时可用。
uintptr_t find_method_by_rva(uintptr_t rva, const char *ns, const char *cls);

// 主动调用（兜底）：用 il2cpp_runtime_invoke 调 (ns.cls.method, argc)，参数为 arg_buf 的
// Span<byte>，返回值字节写入 out_ret（最多 out_cap）。仅供必要时启用，默认框架不自动触发。
int call_method_span16(const char *ns, const char *cls, const char *method, int argc,
                       void *arg_buf, int64_t arg_len,
                       uint8_t *out_ret, int64_t out_cap, int64_t *out_ret_len);

// 读静态 Byte[] 字段（交叉比对用，如 s_commomChachaKeyBs）
int read_static_byte_array(const char *ns, const char *cls, const char *field_name,
                           uint8_t *out, int64_t out_cap, int64_t *out_len);

// 手动调用一次目标方法（jkgbk 分支）：时机不对偷不到调用时，主动经当前
// methodPointer(= 本框架已装的 tramp) 触发一次真实调用 + 捕获。arg_buf 为
// Span<byte> 入参，返回值字节写入 out_ret（最多 out_cap）。返回 kOk 成功。
int call_once(uint8_t *arg_buf, int64_t arg_len,
              uint8_t *out_ret, int64_t out_cap, int64_t *out_ret_len);

// 设置写入 hook.out 头部的一段附加说明（例如静态字段交叉比对结果），flush 时打印。
void set_extra_header(const char *line);

// flush 循环内到点(定时)后由 flush 线程调用一次的回调（jkgbk，用于延后手动调用）。
typedef void (*FlushOnTimeCb)(void);

// flush 循环（阻塞）：轮询内部缓冲，把新记录追加写入 install 时指定的 out_path。
// on_time_cb != nullptr 且 on_time_ms > 0 时，循环运行满 on_time_ms 毫秒后调用一次
// 回调（例如"3分钟后的手动调用"），并把回调期间 set_extra_header 的新内容写盘。
// 达到 kMaxCalls 后退出。由 zygisk 那个线程调用（与 dump 同一线程，不新增线程）。
void run_flush_loop(int interval_ms, FlushOnTimeCb on_time_cb = nullptr,
                    int64_t on_time_ms = 0);

// 框架内部日志：落盘 hook.log + logcat
void log_line(const char *fmt, ...);

} // namespace HookFramework

#endif // ZYGISK_IL2CPPDUMPER_HOOK_FRAMEWORK_H
