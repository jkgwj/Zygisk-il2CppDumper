//
// hook_framework.cpp
//
// 见 hook_framework.h。实现 methodPointer 替换 trampoline + 环形记录 + hook.out 落盘。
// 防检测要点：只改数据字段；读内存一律用 /proc/self/mem pread（不装 SIGSEGV handler，
// 避免与 metadata_dump 的 crash-guard 冲突，也绝不写 .text / 不开新 RX 映射）。
//

#include "hook_framework.h"
#include "il2cpp-class.h"
#include "xdl.h"
#include "log.h"

#include <cstdio>
#include <cstring>
#include <cstdarg>
#include <cstdlib>
#include <cinttypes>
#include <ctime>
#include <vector>
#include <unistd.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <pthread.h>

namespace HookFramework {

namespace {

// ---------------------------------------------------------------------------
// 所需 il2cpp API（仅解析本框架用到的几个，避免全量符号表）
// ---------------------------------------------------------------------------
#define HOOK_DECL(r, n, p) static r (*n) p

HOOK_DECL(void, il2cpp_class_for_each, (void (*klassReportFunc)(Il2CppClass *klass, void *userData), void *userData));
HOOK_DECL(const char *, il2cpp_class_get_name, (Il2CppClass * klass));
HOOK_DECL(const char *, il2cpp_class_get_namespace, (Il2CppClass * klass));
HOOK_DECL(const MethodInfo *, il2cpp_class_get_method_from_name, (Il2CppClass * klass, const char *name, int argsCount));
HOOK_DECL(const MethodInfo *, il2cpp_class_get_methods, (Il2CppClass * klass, void * *iter));
HOOK_DECL(FieldInfo *, il2cpp_class_get_field_from_name, (Il2CppClass * klass, const char *name));
HOOK_DECL(void, il2cpp_field_static_get_value, (FieldInfo * field, void *value));
HOOK_DECL(uint32_t, il2cpp_array_get_byte_length, (Il2CppArray * array));
HOOK_DECL(const char *, il2cpp_method_get_name, (const MethodInfo * method));
HOOK_DECL(Il2CppDomain *, il2cpp_domain_get, ());
HOOK_DECL(const Il2CppAssembly **, il2cpp_domain_get_assemblies, (const Il2CppDomain * domain, size_t * size));
HOOK_DECL(const Il2CppImage *, il2cpp_assembly_get_image, (const Il2CppAssembly * assembly));
HOOK_DECL(const char *, il2cpp_image_get_name, (const Il2CppImage * image));
HOOK_DECL(Il2CppClass *, il2cpp_class_from_name, (const Il2CppImage * image, const char *namespaze, const char *name));
HOOK_DECL(void *, il2cpp_runtime_invoke, (const MethodInfo * method, void *obj, void **params, Il2CppException **exc));
HOOK_DECL(int, il2cpp_is_vm_thread, (void *));
HOOK_DECL(void *, il2cpp_thread_attach, (Il2CppDomain * domain));

#undef HOOK_DECL

void *g_handle = nullptr;
uintptr_t g_base = 0;
bool g_api_ok = false;

char *g_out_path = nullptr;
char *g_extra_header = nullptr;
const MethodInfo *g_hooked_m = nullptr;

#define RESOLVE(name)                                                                      \
    do {                                                                                   \
        name = (decltype(name)) xdl_sym(g_handle, #name, nullptr);                         \
        if (!name) {                                                                       \
            log_line("il2cpp api 缺失: %s", #name);                                        \
        }                                                                                  \
    } while (0)

bool ensure_api() {
    if (g_api_ok) return true;
    if (!g_handle) g_handle = xdl_open("libil2cpp.so", 0);
    if (!g_handle) return false;
    RESOLVE(il2cpp_class_for_each);
    RESOLVE(il2cpp_class_get_name);
    RESOLVE(il2cpp_class_get_namespace);
    RESOLVE(il2cpp_class_get_method_from_name);
    RESOLVE(il2cpp_class_get_methods);
    RESOLVE(il2cpp_class_get_field_from_name);
    RESOLVE(il2cpp_field_static_get_value);
    RESOLVE(il2cpp_array_get_byte_length);
    RESOLVE(il2cpp_method_get_name);
    RESOLVE(il2cpp_domain_get);
    RESOLVE(il2cpp_domain_get_assemblies);
    RESOLVE(il2cpp_assembly_get_image);
    RESOLVE(il2cpp_image_get_name);
    RESOLVE(il2cpp_class_from_name);
    RESOLVE(il2cpp_runtime_invoke);
    RESOLVE(il2cpp_is_vm_thread);
    RESOLVE(il2cpp_thread_attach);
    g_api_ok = il2cpp_class_for_each && il2cpp_class_get_name && il2cpp_class_get_namespace &&
               il2cpp_class_get_method_from_name && il2cpp_class_get_methods;
    return g_api_ok;
}

// ---------------------------------------------------------------------------
// 日志：hook.log（与 hook.out 同目录）+ logcat
// ---------------------------------------------------------------------------
FILE *g_log_fp = nullptr;

void open_log_if_needed() {
    if (g_log_fp || !g_out_path) return;
    const char *slash = strrchr(g_out_path, '/');
    if (!slash) return;
    char log_path[512];
    snprintf(log_path, sizeof(log_path), "%.*s/hook.log", (int) (slash - g_out_path), g_out_path);
    g_log_fp = fopen(log_path, "w");
    if (g_log_fp) fputs("\xEF\xBB\xBF", g_log_fp);
}

} // namespace

bool runtime_ready() {
    if (!ensure_api()) return false;
    // 与 .cs dump 的等待语义一致：is_vm_thread 为真 = 运行时已初始化完成。
    // 缺该符号时退化为 domain_get 非空。两者都没有则视为不就绪（安全优先）。
    if (il2cpp_is_vm_thread) return il2cpp_is_vm_thread(nullptr) != 0;
    if (il2cpp_domain_get) return il2cpp_domain_get() != nullptr;
    return false;
}

void log_line(const char *fmt, ...) {
    char buf[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(buf, sizeof(buf), fmt, ap);
    va_end(ap);
    LOGI("[hook] %s", buf);
    open_log_if_needed();
    if (g_log_fp) {
        fprintf(g_log_fp, "%s\n", buf);
        fflush(g_log_fp);
    }
}

uintptr_t libil2cpp_base() {
    if (g_base) return g_base;
    if (!g_handle) g_handle = xdl_open("libil2cpp.so", 0);
    if (!g_handle) return 0;
    xdl_info_t info{};
    if (xdl_info(g_handle, XDL_DI_DLINFO, &info) == 0 && info.dli_fbase) {
        g_base = (uintptr_t) info.dli_fbase;
    }
    return g_base;
}

namespace {

// ---------------------------------------------------------------------------
// 类定位：优先 class_for_each，缺符号时退回 assemblies 扫描
// ---------------------------------------------------------------------------
struct ClassQuery {
    const char *ns;
    const char *name;
    void *klass;
};

void class_report(Il2CppClass *klass, void *userData) {
    auto *q = (ClassQuery *) userData;
    if (q->klass) return;
    const char *ns = il2cpp_class_get_namespace(klass);
    const char *nm = il2cpp_class_get_name(klass);
    if (nm && q->name && strcmp(nm, q->name) == 0 &&
        ((q->ns && ns && strcmp(ns, q->ns) == 0) || (!q->ns && !ns))) {
        q->klass = klass;
    }
}

void *find_class(const char *ns, const char *name) {
    if (!ensure_api()) return nullptr;
    ClassQuery q{ns, name, nullptr};
    if (il2cpp_class_for_each) {
        il2cpp_class_for_each(class_report, &q);
    }
    if (q.klass) return q.klass;

    // 精确 ns+name 未命中，再按名字单独扫一轮（模仿 dump.cs：遍历不看 ns，
    // 避免命名空间/混淆名差异导致类找不到）
    if (name && il2cpp_class_for_each) {
        ClassQuery q2{nullptr, name, nullptr};
        il2cpp_class_for_each(class_report, &q2);
        if (q2.klass) {
            log_line("class 按名字匹配命中: %s (ns=%s)", name,
                     il2cpp_class_get_namespace((Il2CppClass *) q2.klass));
            return q2.klass;
        }
    }

    // 退回：扫描 assemblies
    Il2CppDomain *domain = il2cpp_domain_get ? il2cpp_domain_get() : nullptr;
    if (domain && il2cpp_domain_get_assemblies && il2cpp_assembly_get_image &&
        il2cpp_image_get_name && il2cpp_class_from_name) {
        size_t n = 0;
        const Il2CppAssembly **asms = il2cpp_domain_get_assemblies(domain, &n);
        for (size_t i = 0; i < n; ++i) {
            const Il2CppImage *img = il2cpp_assembly_get_image(asms[i]);
            if (!img) continue;
            if (strstr(il2cpp_image_get_name(img), "Common.Beyond") == nullptr) continue;
            void *k = il2cpp_class_from_name(img, ns, name);
            if (k) return k;
        }
    }
    return nullptr;
}

// 模仿 dump.cs：class_get_methods 全量遍历按名字匹配（不卡 argc）。
// 若已知期望 RVA，优先返回 methodPointer == base+rva 的那个（即 dump.cs 打印的那个）。
const MethodInfo *find_method_by_name_any_arity(Il2CppClass *klass, const char *name,
                                                uintptr_t expected_rva) {
    if (!il2cpp_class_get_methods || !il2cpp_method_get_name) return nullptr;
    uintptr_t base = libil2cpp_base();
    uintptr_t target = (expected_rva && base) ? base + expected_rva : 0;
    const MethodInfo *first = nullptr;
    void *iter = nullptr;
    const MethodInfo *m;
    while ((m = il2cpp_class_get_methods(klass, &iter)) != nullptr) {
        const char *mn = il2cpp_method_get_name(m);
        if (!mn || strcmp(mn, name) != 0) continue;
        if (!first) first = m;
        if (target && (uintptr_t) m->methodPointer == target) {
            log_line("find_method_by_name: %s 命中期望 RVA (methodPointer=0x%" PRIxPTR ")",
                     name, (uintptr_t) m->methodPointer);
            return m;
        }
    }
    if (first) {
        log_line("find_method_by_name: %s 找到(未匹配期望 RVA, 可能被 IFix 换体) "
                 "methodPointer=0x%" PRIxPTR, name, (uintptr_t) first->methodPointer);
    }
    return first;
}

// 终极兜底（用 dump.cs 给出的已知 RVA 反查全表）：class 未找到时，
// 全局扫 methodPointer == base+rva 的方法，直接拿到 MethodInfo。
struct RvaScan {
    uintptr_t target;
    const MethodInfo *m;
};

void rva_report(Il2CppClass *klass, void *userData) {
    auto *s = (RvaScan *) userData;
    if (s->m) return;
    if (!il2cpp_class_get_methods) return;
    void *iter = nullptr;
    const MethodInfo *mi;
    while ((mi = il2cpp_class_get_methods(klass, &iter)) != nullptr) {
        if ((uintptr_t) mi->methodPointer == s->target) {
            s->m = mi;
            return;
        }
    }
}

const MethodInfo *find_method_by_rva_global(uintptr_t rva) {
    uintptr_t base = libil2cpp_base();
    if (!base || !rva || !il2cpp_class_for_each) return nullptr;
    RvaScan s{base + rva, nullptr};
    il2cpp_class_for_each(rva_report, &s);
    if (s.m) log_line("find_method_by_rva_global: rva=0x%" PRIxPTR " -> 方法命中", rva);
    return s.m;
}

// ---------------------------------------------------------------------------
// 内存快照：优先 /proc/self/mem pread；打开失败(Permission denied, Android 14+)
// 时退化为 /proc/self/maps 校验 + 直接读引用内存。与 metadata_dump 的
// "进程内直接读"一致——hook.out 之前的全零就是缺这层兜底所致。
// ---------------------------------------------------------------------------
int g_mem_fd = -1;

bool range_readable(uintptr_t lo, uintptr_t hi) {
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) return false;
    char line[512];
    bool ok = false;
    while (fgets(line, sizeof(line), fp)) {
        uintptr_t a = 0, b = 0;
        char perms[8] = {0};
        if (sscanf(line, "%" SCNxPTR "-%" SCNxPTR " %7s", &a, &b, perms) == 3 &&
            perms[0] == 'r' && lo >= a && hi <= b) {
            ok = true;
            break;
        }
    }
    fclose(fp);
    return ok;
}

void snapshot(void *ref, int64_t len, uint8_t *out, size_t out_cap) {
    memset(out, 0, out_cap);
    if (!ref || len <= 0) return;
    size_t n = (size_t) len < out_cap ? (size_t) len : out_cap;

    // 主路径：/proc/self/mem pread
    if (g_mem_fd < 0) g_mem_fd = open("/proc/self/mem", O_RDONLY);
    if (g_mem_fd >= 0) {
        ssize_t r = pread(g_mem_fd, out, n, (off_t) (uintptr_t) ref);
        if (r > 0 && (size_t) r < n) memset(out + r, 0, n - (size_t) r);
        if (r >= (ssize_t) n) return;  // 完整读到了
        // 部分/失败：若整体区间可读，直接读；否则保留已读部分
        if (range_readable((uintptr_t) ref, (uintptr_t) ref + n)) {
            memcpy(out, ref, n);
        }
        return;
    }
    // mem fd 打开失败(Android 新版本 Permission denied)：maps 校验后直读
    if (range_readable((uintptr_t) ref, (uintptr_t) ref + n)) {
        memcpy(out, ref, n);
    }
}

// ---------------------------------------------------------------------------
// 环形记录 + trampoline
// ---------------------------------------------------------------------------
struct CallRecord {
    int64_t seq;
    uint64_t when_ms;
    uintptr_t args_ref;
    int64_t args_len;
    uintptr_t ret_ref;
    int64_t ret_len;
    uint8_t args_snapshot[64];
    uint8_t ret_snapshot[64];
};

constexpr int kRingCapacity = 512;

pthread_mutex_t g_lock = PTHREAD_MUTEX_INITIALIZER;
CallRecord g_ring[kRingCapacity];
int g_ring_head = 0;
int g_ring_count = 0;
int64_t g_seq = 0;

typedef Span16 (*span16fn)(Span16, const void *);
span16fn g_orig = nullptr;

uint64_t now_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000u);
}

Span16 tramp_span16(Span16 arg, const void *method) {
    CallRecord rec;
    rec.when_ms = now_ms();
    rec.args_ref = (uintptr_t) arg.ref;
    rec.args_len = arg.len;
    snapshot(arg.ref, arg.len, rec.args_snapshot, sizeof(rec.args_snapshot));

    Span16 ret = g_orig ? g_orig(arg, method) : Span16{nullptr, 0};

    rec.ret_ref = (uintptr_t) ret.ref;
    rec.ret_len = ret.len;
    snapshot(ret.ref, ret.len, rec.ret_snapshot, sizeof(rec.ret_snapshot));

    pthread_mutex_lock(&g_lock);
    if (g_seq < kMaxCalls) {
        ++g_seq;
        rec.seq = g_seq;
        g_ring[(g_ring_head + g_ring_count) % kRingCapacity] = rec;
        ++g_ring_count;
    }
    pthread_mutex_unlock(&g_lock);
    return ret;
}

} // namespace

int install_span_hook(const char *ns, const char *cls, const char *method, int argc,
                      uintptr_t expected_rva, const char *out_path) {
    if (!ensure_api()) return kErrApiMissing;
    // 运行时就绪门：未就绪绝不遍历类型表（会在懒初始化期把游戏主线程带崩）。
    if (!runtime_ready()) {
        log_line("il2cpp 运行时未就绪, 返回 kErrNotReady (等待下一轮重试)");
        return kErrNotReady;
    }
    if (g_out_path) free(g_out_path);
    g_out_path = strdup(out_path);
    uintptr_t base = libil2cpp_base();
    log_line("install: ns=%s cls=%s method=%s argc=%d base=0x%" PRIxPTR,
             ns ? ns : "", cls, method, argc, base);

    void *k = find_class(ns, cls);
    const MethodInfo *m = nullptr;
    if (k) {
        m = il2cpp_class_get_method_from_name((Il2CppClass *) k, method, argc);
        if (!m) {
            log_line("get_method_from_name %s(argc=%d) 未命中, 转 dump.cs 式全量按名匹配",
                     method, argc);
            m = find_method_by_name_any_arity((Il2CppClass *) k, method, expected_rva);
        }
    }
    if (!m) {
        // class 找不到/方法按名也未中，直接用 dump.cs 已知 RVA 反查全表
        log_line("class/method 常规查找均未命中, 用已知 RVA 0x%" PRIxPTR " 全局定位",
                 expected_rva);
        m = find_method_by_rva_global(expected_rva);
    }
    if (!m) {
        log_line("method 未找到: %s.%s.%s argc=%d", ns ? ns : "", cls, method, argc);
        return kErrMethodNotFound;
    }
    uintptr_t addr = (uintptr_t) m->methodPointer;
    log_line("methodPointer=0x%" PRIxPTR " (期望 base+0x%" PRIxPTR "=0x%" PRIxPTR ")",
             addr, expected_rva, base + expected_rva);
    if (expected_rva && base && addr != base + expected_rva) {
        log_line("提示: methodPointer 与 base+expected_rva 不一致，可能已被 IFix 换体，仍继续安装");
    }

    g_orig = (span16fn) addr;
    if (!g_orig) return kErrInstall;

    // 数据页 mprotect（只读→RW，非可执行页）
    long pg = sysconf(_SC_PAGESIZE);
    uintptr_t page = ((uintptr_t) &m->methodPointer) & ~((uintptr_t) pg - 1);
    if (mprotect((void *) page, (size_t) pg, PROT_READ | PROT_WRITE) != 0) {
        log_line("mprotect MethodInfo 失败");
        return kErrInstall;
    }

    ((MethodInfo *) m)->methodPointer = (Il2CppMethodPointer) tramp_span16;
    g_hooked_m = m;
    log_line("hook 已安装, 记录上限 %d 次", kMaxCalls);
    return kOk;
}

bool hook_installed() {
    return g_hooked_m != nullptr;
}

void unhook() {
    if (g_hooked_m && g_orig) {
        ((MethodInfo *) g_hooked_m)->methodPointer = (Il2CppMethodPointer) g_orig;
        log_line("unhook: 已恢复原始 methodPointer");
        g_hooked_m = nullptr;
    }
}

uintptr_t find_method_by_rva(uintptr_t rva, const char *ns, const char *cls) {
    void *k = find_class(ns, cls);
    uintptr_t base = libil2cpp_base();
    if (!k || !base) return 0;
    uintptr_t target = base + rva;
    void *iter = nullptr;
    const MethodInfo *m;
    while ((m = il2cpp_class_get_methods((Il2CppClass *) k, &iter)) != nullptr) {
        if ((uintptr_t) m->methodPointer == target) {
            log_line("find_method_by_rva: rva=0x%" PRIxPTR " -> %s (0x%" PRIxPTR ")",
                     rva, il2cpp_method_get_name(m), target);
            return target;
        }
    }
    return 0;
}

int call_method_span16(const char *ns, const char *cls, const char *method, int argc,
                       void *arg_buf, int64_t arg_len,
                       uint8_t *out_ret, int64_t out_cap, int64_t *out_ret_len) {
    if (!ensure_api() || !il2cpp_runtime_invoke) return kErrApiMissing;
    void *k = find_class(ns, cls);
    if (!k) return kErrClassNotFound;
    const MethodInfo *m = il2cpp_class_get_method_from_name((Il2CppClass *) k, method, argc);
    if (!m) return kErrMethodNotFound;

    Span16 arg{arg_buf, arg_len};
    void *params[1] = {&arg};
    Il2CppException *exc = nullptr;
    void *ret = il2cpp_runtime_invoke(m, nullptr, params, &exc);
    if (exc) return kErrInstall;
    if (!ret) return kErrInstall;

    auto *s = (Span16 *) ret;
    int64_t n = s->len < out_cap ? s->len : out_cap;
    snapshot(s->ref, n, out_ret, (size_t) out_cap);
    if (out_ret_len) *out_ret_len = n;
    return kOk;
}

int call_once(uint8_t *arg_buf, int64_t arg_len,
              uint8_t *out_ret, int64_t out_cap, int64_t *out_ret_len) {
    if (!g_hooked_m) return kErrInstall;  // 必须先安装成功
    // 目标方法内部会做托管分配/类初始化（UnSafeStringAlloc/class_init），
    // 必须先把本线程 attach 到 il2cpp domain（非托管线程分配会 SIGSEGV，
    // 这是此前 install->unhook 死循环 + 主线程卡死的根因）。
    if (il2cpp_thread_attach && il2cpp_domain_get) {
        Il2CppDomain *d = il2cpp_domain_get();
        if (d) il2cpp_thread_attach(d);
    }
    // 直接经已装的 tramp 调用：methodPointer 已是 tramp，触发真实调用+捕获。
    // 签名与目标一致（aarch64: x0=ref x1=len，x2 被原函数忽略）。
    Span16 arg{arg_buf, arg_len};
    Span16 ret = ((span16fn) g_hooked_m->methodPointer)(arg, nullptr);
    int64_t n = (ret.ref && ret.len > 0) ? (ret.len < out_cap ? ret.len : out_cap) : 0;
    if (n > 0) snapshot(ret.ref, n, out_ret, (size_t) out_cap);
    if (out_ret_len) *out_ret_len = n;
    return kOk;
}

int read_static_byte_array(const char *ns, const char *cls, const char *field_name,
                           uint8_t *out, int64_t out_cap, int64_t *out_len) {
    if (!ensure_api()) return kErrApiMissing;
    void *k = find_class(ns, cls);
    if (!k) return kErrClassNotFound;
    FieldInfo *f = il2cpp_class_get_field_from_name((Il2CppClass *) k, field_name);
    if (!f) return kErrMethodNotFound;

    Il2CppArray *arr = nullptr;
    il2cpp_field_static_get_value(f, &arr);
    if (!arr || !il2cpp_array_get_byte_length) return kErrInstall;
    uint32_t blen = il2cpp_array_get_byte_length(arr);
    int64_t n = blen < out_cap ? blen : out_cap;
    uintptr_t data = (uintptr_t) arr + offsetof(Il2CppArray, vector);
    snapshot((void *) data, n, out, (size_t) out_cap);
    if (out_len) *out_len = n;
    return kOk;
}

void set_extra_header(const char *line) {
    if (g_extra_header) free(g_extra_header);
    g_extra_header = line ? strdup(line) : nullptr;
}

namespace {

void hex_append(FILE *fp, const uint8_t *d, size_t n) {
    static const char hex[] = "0123456789abcdef";
    for (size_t i = 0; i < n; ++i) {
        fputc(hex[d[i] >> 4], fp);
        fputc(hex[d[i] & 0xf], fp);
    }
}

void write_record(FILE *fp, const CallRecord &rec) {
    int args_n = (int) (rec.args_len < 64 ? rec.args_len : 64);
    int ret_n = (int) (rec.ret_len < 64 ? rec.ret_len : 64);
    fprintf(fp, "seq=%lld t=%llu args_ref=0x%" PRIxPTR " args_len=%lld args=",
            (long long) rec.seq, (unsigned long long) rec.when_ms, rec.args_ref,
            (long long) rec.args_len);
    hex_append(fp, rec.args_snapshot, (size_t) args_n);
    fprintf(fp, " ret_ref=0x%" PRIxPTR " ret_len=%lld ret=", rec.ret_ref,
            (long long) rec.ret_len);
    hex_append(fp, rec.ret_snapshot, (size_t) ret_n);
    fprintf(fp, "\n");
}

} // namespace

void run_flush_loop(int interval_ms, FlushOnTimeCb on_time_cb, int64_t on_time_ms) {
    if (!g_out_path) return;
    FILE *fp = fopen(g_out_path, "w");
    if (!fp) {
        log_line("无法创建 hook.out: %s", g_out_path);
        return;
    }
    fputs("\xEF\xBB\xBF", fp);
    fprintf(fp, "hook.out v1 max_calls=%d\n", kMaxCalls);
    if (g_extra_header) fprintf(fp, "# %s\n", g_extra_header);
    fflush(fp);

    log_line("flush loop 开始, 输出=%s", g_out_path);
    // jkgbk: 不再设空闲超时——hook 捕获只按数量上限(kMaxCalls)结束。
    // 之前 30s 空闲就关文件退出，导致之后游戏真实调用被记录进环形缓冲
    // 却无人写盘(写者已退出)，文件头就永远停在那里。现在写者存活到
    // 500 条上限为止，期间新记录随时落盘。
    // 另：到 on_time_ms 后触发一次定时回调(延后手动调用，等静态密钥字段就绪)，
    // 避免早期在 dump 线程直接执行游戏方法导致 SIGBUS 弃锁死锁。
    uint64_t started_ms = now_ms();
    bool timer_fired = (on_time_cb == nullptr || on_time_ms <= 0);
    while (true) {
        if (!timer_fired && now_ms() - started_ms >= (uint64_t) on_time_ms) {
            timer_fired = true;
            log_line("flush: 到达定时点(%lld ms), 触发回调", (long long) on_time_ms);
            on_time_cb();
            // 回调可能 set_extra_header，把新头部补写进文件（表头在文件开头，
            // 这里以注释追加，避免破坏已写记录）
            if (g_extra_header) {
                fprintf(fp, "# %s\n", g_extra_header);
                fflush(fp);
            }
        }

        pthread_mutex_lock(&g_lock);
        int n = g_ring_count;
        int head = g_ring_head;
        g_ring_count = 0;
        g_ring_head = (g_ring_head + n) % kRingCapacity;
        int64_t seq = g_seq;
        pthread_mutex_unlock(&g_lock);

        for (int i = 0; i < n; ++i) {
            write_record(fp, g_ring[(head + i) % kRingCapacity]);
        }
        if (n > 0) {
            fflush(fp);
            log_line("flush: %d 条 -> %s (累计 %lld/%d)", n, g_out_path,
                     (long long) seq, kMaxCalls);
        }
        if (seq >= kMaxCalls && n == 0) break;
        usleep((unsigned) interval_ms * 1000u);
    }
    fclose(fp);
    log_line("flush loop 结束: 已达 %d 条上限", kMaxCalls);
}

} // namespace HookFramework
