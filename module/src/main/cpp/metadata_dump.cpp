#include "metadata_dump.h"

#include <unistd.h>
#include <fcntl.h>
#include <time.h>
#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <climits>
#include <algorithm>
#include <string>
#include <setjmp.h>
#include <signal.h>
#include <elf.h>

#include "dump_log.h"
#include "xdl.h"

namespace MetadataDump {

namespace {

uint64_t nowMs() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000);
}

// 私有字节拷贝：不经过可能被反作弊 inline-hook 的 libc memcpy 符号。
// noinline + volatile 防止编译器把循环优化回 memcpy 调用。
__attribute__((noinline))
static void copyBytes(void *dst, const void *src, size_t n) {
    volatile uint8_t *d = (volatile uint8_t *) dst;
    const volatile uint8_t *s = (const volatile uint8_t *) src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
}

// SIGSEGV/SIGBUS 兜底：读取可能已失效/受保护的内存时捕获 fault，避免崩溃。
// 仅当「本线程正处于 guardedCopy 内」时才 siglongjmp 回本线程的 sigsetjmp 点，
// 其余情况转发给原 handler（保证不影响游戏自身的信号处理）。
thread_local sigjmp_buf g_crash_jmp;
thread_local volatile sig_atomic_t g_crash_guard = 0;
struct sigaction g_old_segv{};
struct sigaction g_old_bus{};
bool g_crash_installed = false;

void crashHandler(int sig, siginfo_t *si, void *uc) {
    if (g_crash_guard) {
        siglongjmp(g_crash_jmp, 1);
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

bool installCrashGuard() {
    struct sigaction act{};
    memset(&act, 0, sizeof(act));
    act.sa_sigaction = crashHandler;
    act.sa_flags = SA_SIGINFO | SA_NODEFER;
    sigemptyset(&act.sa_mask);
    if (sigaction(SIGSEGV, &act, &g_old_segv) != 0) return false;
    if (sigaction(SIGBUS, &act, &g_old_bus) != 0) {
        sigaction(SIGSEGV, &g_old_segv, nullptr);
        return false;
    }
    g_crash_installed = true;
    return true;
}

void uninstallCrashGuard() {
    if (!g_crash_installed) return;
    sigaction(SIGSEGV, &g_old_segv, nullptr);
    sigaction(SIGBUS, &g_old_bus, nullptr);
    g_crash_installed = false;
}

// 作用域守卫：进入时装 handler，离开作用域（含所有提前 return）时恢复。
struct CrashGuardScope {
    CrashGuardScope() { installCrashGuard(); }
    ~CrashGuardScope() { uninstallCrashGuard(); }
};

__attribute__((noinline))
bool guardedCopy(void *dst, const void *src, size_t n) {
    g_crash_guard = 1;
    if (sigsetjmp(g_crash_jmp, 1) == 0) {
        copyBytes(dst, src, n);
        g_crash_guard = 0;
        return true;
    }
    g_crash_guard = 0;
    return false;
}

}

Dumper::Dumper() = default;

Dumper::~Dumper() {
    if (memFd_ >= 0) {
        close(memFd_);
        memFd_ = -1;
    }
}

bool Dumper::safeRead(uintptr_t addr, void *out, size_t n) {
    if (n == 0) return true;
    // 主路径：整段落在可读区间内则私有直接拷贝（零系统调用）
    if (fullyReadable(addr, n)) {
        if (guardedCopy(out, (const void *) addr, n)) return true;
        // guardedCopy 触发 fault（读取已失效/受保护内存），继续尝试 /proc/self/mem
    }
    // 备用路径：/proc/self/mem pread（内核读，坏地址返回 EIO 而非崩溃）
    if (memFd_ >= 0) {
        size_t done = 0;
        while (done < n) {
            ssize_t r = pread(memFd_, (char *) out + done, n - done, (off_t) (addr + done));
            if (r <= 0) return false;
            done += (size_t) r;
        }
        return true;
    }
    return false;
}

void Dumper::logStep(int phase, int total, const char *method, MethodStatus st,
                     const char *fmt, ...) {
    char reason[1024];
    va_list ap;
    va_start(ap, fmt);
    vsnprintf(reason, sizeof(reason), fmt, ap);
    va_end(ap);

    StepLog sl;
    sl.phase = phase;
    sl.total = total;
    sl.method = method;
    sl.status = st;
    sl.reason = reason;

    const char *statusName = st == MethodStatus::OK ? "成功" :
                             st == MethodStatus::WARN ? "警告" :
                             st == MethodStatus::FAIL ? "失败" : "跳过";
    DumpLog::info("步骤 %d/%d [%s] -> %s 原因/说明: %s", phase, total, method, statusName,
            reason);
    steps_.push_back(std::move(sl));
}

bool Dumper::loadRegions() {
    regions_.clear();
    FILE *fp = fopen("/proc/self/maps", "r");
    if (!fp) {
        DumpLog::error("无法打开 /proc/self/maps: %s", strerror(errno));
        return false;
    }
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        char range[64] = {0};
        char perms[8] = {0};
        unsigned long start = 0, end = 0;
        if (sscanf(line, "%63[^-]-%lx %7s", range, &end, perms) == 3) {
            if (sscanf(range, "%lx", &start) != 1) continue;
        } else if (sscanf(line, "%lx-%lx %7s", &start, &end, perms) == 3) {
        } else {
            continue;
        }
        if (end <= start) continue;
        std::string path;
        const char *it = strchr(line, '/');
        if (it) {
            path = it;
            while (!path.empty() && (path.back() == '\n' || path.back() == '\r')) {
                path.pop_back();
            }
        } else if (strstr(line, "[anon:") || strcmp(perms, "rw-p") == 0) {
            const char *lb = strchr(line, '[');
            if (lb) {
                const char *rb = strchr(lb, ']');
                if (rb) path = std::string(lb, rb - lb + 1);
            }
        }
        Region r;
        r.start = (uintptr_t) start;
        r.end = (uintptr_t) end;
        r.perms = perms;
        r.path = path;
        regions_.push_back(std::move(r));
    }
    fclose(fp);
    size_t readable = 0;
    for (const auto &r : regions_) {
        if (r.perms.find('r') != std::string::npos) ++readable;
    }
    DumpLog::info("/proc/self/maps 解析完成: 总区间 %zu, 可读 %zu", regions_.size(), readable);
    for (const auto &r : regions_) {
        if (r.path.find("libil2cpp") != std::string::npos ||
            r.path.find("global-metadata") != std::string::npos) {
            DumpLog::info("  关键区间 [0x%" PRIxPTR "-0x%" PRIxPTR "] %s %s",
                          r.start, r.end, r.perms.c_str(), r.path.c_str());
        }
    }
    return !regions_.empty();
}

const Region *Dumper::regionAt(uintptr_t addr) const {
    // regions_ 由 /proc/self/maps 解析而来，按 start 升序、互不重叠
    size_t lo = 0, hi = regions_.size();
    while (lo < hi) {
        size_t mid = lo + (hi - lo) / 2;
        if (regions_[mid].end <= addr) lo = mid + 1;
        else hi = mid;
    }
    if (lo < regions_.size() && regions_[lo].start <= addr && addr < regions_[lo].end)
        return &regions_[lo];
    return nullptr;
}

uintptr_t Dumper::regionEndAt(uintptr_t addr) const {
    const Region *r = regionAt(addr);
    return r ? r->end : 0;
}

bool Dumper::fullyReadable(uintptr_t addr, size_t n) const {
    uintptr_t cur = addr;
    size_t remaining = n;
    while (remaining > 0) {
        const Region *r = regionAt(cur);
        if (!r || r->perms.find('r') == std::string::npos) return false;
        size_t can = (size_t) (r->end - cur);
        if (can > remaining) can = remaining;
        cur += can;
        remaining -= can;
    }
    return true;
}

void Dumper::loadPairs(uintptr_t base, int32_t *out, size_t maxPairs) {
    memset(out, 0, maxPairs * sizeof(int32_t));
    const size_t MAX = 68;
    size_t n = maxPairs < MAX ? maxPairs : MAX;
    safeRead(base + 8, out, n * sizeof(int32_t));
}

int Dumper::scoreCandidate(uintptr_t base) {
    uint32_t sanity = 0;
    int32_t version = 0;
    if (!safeRead(base, &sanity, 4)) return 0;
    if (!safeRead(base + 4, &version, 4)) return 0;

    int s = 0;
    bool sanityOk = (sanity == kMagic);
    bool versionOk = (version >= kMinVersion && version <= kMaxVersion);
    if (sanityOk) {
        s += 30;
    } else if (sanity < 0x10000u) {
        s += 2;
    }
    if (versionOk) {
        s += 20;
    } else if (version >= 16 && version <= 1000) {
        s += 5;
    }

    uintptr_t regionEnd = regionEndAt(base);
    size_t limit = regionEnd ? regionEnd - base : kMaxDumpSize * 2;
    if (limit == 0) limit = kMaxDumpSize * 2;

    int32_t pairs[68];
    loadPairs(base, pairs, 68);
    int good = 0;
    for (int k = 0; k + 1 < 68; k += 2) {
        int32_t off = pairs[k];
        int32_t sz = pairs[k + 1];
        if (off > 0 && sz > 0 && (size_t) off + (size_t) sz <= limit) ++good;
    }
    if (good >= 6) s += 15;
    else if (good >= 2) s += 6;

    int32_t stringOffset = pairs[4];
    if (stringOffset > 0 && (size_t) stringOffset <= limit && stringOffset >= 0x20) {
        s += 8;
    }
    int32_t imagesOffset = pairs[42];
    int32_t assembliesOffset = pairs[44];
    if (imagesOffset > 0) s += 4;
    if (assembliesOffset > 0) s += 2;

    int32_t stringLiteralOffset = pairs[0];
    if (stringLiteralOffset >= 0xF0 && stringLiteralOffset <= 0x120) s += 6;
    return s;
}

uintptr_t Dumper::evalBest(uintptr_t addr, int &score) {
    score = 0;
    if (addr == 0) return 0;
    uintptr_t cur = addr;
    for (int depth = 0; depth < 3; ++depth) {
        int s = scoreCandidate(cur);
        if (s > score) {
            score = s;
            if (score >= kAcceptScore) return cur;
        }
        uintptr_t nxt = 0;
        if (sizeof(uintptr_t) == 8) {
            if (!safeRead(cur, &nxt, 8)) break;
        } else {
            uint32_t v = 0;
            if (!safeRead(cur, &v, 4)) break;
            nxt = v;
        }
        if (nxt == 0 || nxt == cur) break;
        cur = nxt;
    }
    return addr;
}

int Dumper::locateByMaps() {
    int best = 0;
    for (const auto &r : regions_) {
        if (r.path.empty()) continue;
        size_t pos = r.path.rfind('/');
        std::string name = (pos == std::string::npos) ? r.path : r.path.substr(pos + 1);
        if (name != "global-metadata.dat") continue;
        int s = scoreCandidate(r.start);
        DumpLog::debug("maps 候选 %s [0x%" PRIxPTR "] 评分 %d", r.path.c_str(), r.start, s);
        if (s > best) {
            best = s;
            base_ = r.start;
            sourceMethod_ = "maps";
            sourceDetail_ = r.path;
        }
    }
    return best;
}

int Dumper::locateByDlsym() {
    const char *symbols[] = {"s_GlobalMetadata", "s_GlobalMetadataHeader"};
    int best = 0;
    for (const char *name : symbols) {
        void *addr = xdl_sym(handle_, name, nullptr);
        if (!addr) addr = xdl_dsym(handle_, name, nullptr);
        if (!addr) {
            DumpLog::warn("符号 %s 未找到 (dynsym/symtab 均无)", name);
            continue;
        }
        uintptr_t base = 0;
        if (sizeof(uintptr_t) == 8) {
            safeRead((uintptr_t) addr, &base, 8);
        } else {
            uint32_t v = 0;
            safeRead((uintptr_t) addr, &v, 4);
            base = v;
        }
        if (!base) {
            DumpLog::warn("符号 %s 存在但其值为空", name);
            continue;
        }
        int s = scoreCandidate(base);
        DumpLog::info("符号 %s = %" PRIxPTR " 评分 %d", name, base, s);
        if (s > best) {
            best = s;
            base_ = base;
            sourceMethod_ = "dlsym";
            sourceDetail_ = name;
        }
    }
    return best;
}

int Dumper::locateBySGlobalMetadata() {
    xdl_info_t info{};
    if (xdl_info(handle_, XDL_DI_DLINFO, &info) != 0 || !info.dli_fbase || !info.dlpi_phdr ||
        info.dlpi_phnum == 0) {
        DumpLog::warn("xdl_info 无法取得 libil2cpp.so 的基址/程序头");
        return 0;
    }
    int best = 0;
    uintptr_t base = (uintptr_t) info.dli_fbase;
    for (size_t i = 0; i < info.dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info.dlpi_phdr[i];
        if (ph.p_type != PT_LOAD || !(ph.p_flags & PF_W)) continue;
        uintptr_t segStart = base + ph.p_vaddr;
        uintptr_t segEnd = segStart + ph.p_memsz;
        if (segEnd <= segStart) continue;
        DumpLog::info("s_GlobalMetadata 扫描 RW 段 [0x%" PRIxPTR "-0x%" PRIxPTR "] 大小 %zu",
                      segStart, segEnd, (size_t) ph.p_memsz);
        const size_t CHUNK = 1u << 20;
        std::vector<uint8_t> buf(CHUNK, 0);
        for (uintptr_t off = 0; off < ph.p_memsz; off += CHUNK) {
            size_t want = (size_t) (ph.p_memsz - off < CHUNK ? ph.p_memsz - off : CHUNK);
            if (!safeRead(segStart + off, buf.data(), want)) break;
            for (size_t j = 0; j + 8 <= want; j += 8) {
                uintptr_t candidate = 0;
                memcpy(&candidate, buf.data() + j, 8);
                if (candidate < 0x1000 || candidate == (uintptr_t) -1) continue;
                uint32_t magic = 0;
                int32_t version = 0;
                if (!safeRead(candidate, &magic, 4)) continue;
                if (magic != kMagic) continue;
                if (!safeRead(candidate + 4, &version, 4)) continue;
                if (version < kMinVersion || version > kMaxVersion) continue;
                int s = scoreCandidate(candidate);
                DumpLog::info("s_GlobalMetadata 命中: 指针 0x%" PRIxPTR " -> magic @0x%" PRIxPTR " 评分 %d",
                              segStart + off + j, candidate, s);
                if (s > best) {
                    best = s;
                    base_ = candidate;
                    sourceMethod_ = "s_global_metadata";
                    sourceDetail_ = "libil2cpp.so RW 段指针";
                }
                if (best >= kAcceptScore) return best;
            }
        }
    }
    return best;
}

int Dumper::locateByMagicScan() {
    int best = 0;
    loadRegions();
    size_t scanned = 0;
    uint64_t started = nowMs();
    size_t regionIdx = 0;
    for (const auto &r : regions_) {
        ++regionIdx;
        if (best >= kAcceptScore && scanned > 0x1000000ULL) break;
        if (r.perms.find('r') == std::string::npos) continue;
        bool isAnon = r.path.empty();
        bool isMeta = r.path.find("global") != std::string::npos;
        bool isBad = !r.path.empty() &&
                     (r.path.size() > 3 &&
                      (r.path.substr(r.path.size() - 3) == ".so" ||
                       r.path.substr(r.path.size() - 4) == ".dex" ||
                       r.path.substr(r.path.size() - 4) == ".oat" ||
                       r.path.substr(r.path.size() - 4) == ".art" ||
                       r.path.substr(r.path.size() - 4) == ".jar" ||
                       r.path.substr(r.path.size() - 4) == ".apk"));
        if (!isAnon && !isMeta) continue;
        if (isBad) continue;
        if ((size_t) (r.end - r.start) < kMinScanRegion) continue;

        size_t hits = 0;
        DumpLog::info("magic_scan 扫描区间 #%zu [0x%" PRIxPTR "-0x%" PRIxPTR "] %s %s, 大小 %zu",
                      regionIdx, r.start, r.end, r.perms.c_str(),
                      r.path.empty() ? "(匿名)" : r.path.c_str(), (size_t) (r.end - r.start));
        size_t len = r.end - r.start;
        size_t chunkSize = 1u << 20;
        std::vector<uint8_t> buf(chunkSize, 0);
        uint8_t carry[3] = {0, 0, 0};
        size_t done = 0;
        while (done < len && (nowMs() - started) < kScanMsBudget && scanned < kScanByteBudget) {
            size_t want = len - done < chunkSize ? len - done : chunkSize;
            if (!safeRead(r.start + done, buf.data(), want)) break;
            scanned += want;
            {
                auto checkHit = [&](size_t hitOff) {
                    uintptr_t hit = r.start + hitOff;
                    int s = scoreCandidate(hit);
                    if (hits < 20) {
                        DumpLog::info("magic_scan 命中候选 @0x%" PRIxPTR " (偏移+0x%zx) 评分 %d",
                                      hit, hitOff, s);
                    }
                    ++hits;
                    if (s > best) {
                        best = s;
                        base_ = hit;
                        sourceMethod_ = "magic_scan";
                        char tmp[64];
                        snprintf(tmp, sizeof(tmp), "%s +0x%zx",
                                 r.path.empty() ? "(匿名)" : r.path.c_str(), hitOff);
                        sourceDetail_ = tmp;
                    }
                };
                if (done > 0 && want >= 1 &&
                    carry[0] == 0xAF && carry[1] == 0x1B && carry[2] == 0xB1 && buf[0] == 0xFA) {
                    checkHit(done - 3);
                }
                if (done > 0 && want >= 2 &&
                    carry[1] == 0xAF && carry[2] == 0x1B && buf[0] == 0xB1 && buf[1] == 0xFA) {
                    checkHit(done - 2);
                }
                if (done > 0 && want >= 3 &&
                    carry[2] == 0xAF && buf[0] == 0x1B && buf[1] == 0xB1 && buf[2] == 0xFA) {
                    checkHit(done - 1);
                }
                for (size_t i = 0; i + 4 <= want; ++i) {
                    if (buf[i] == 0xAF && buf[i + 1] == 0x1B && buf[i + 2] == 0xB1 &&
                        buf[i + 3] == 0xFA) {
                        checkHit(done + i);
                    }
                }
                if (want >= 3) {
                    carry[0] = buf[want - 3];
                    carry[1] = buf[want - 2];
                    carry[2] = buf[want - 1];
                }
            }
            done += want;
            if (want < chunkSize) break;
        }
        DumpLog::info("magic_scan 区间 #%zu 完成: 命中 %zu, 当前最高分 %d", regionIdx, hits, best);
    }
    return best;
}

void Dumper::collectArchAddr(const void *code, size_t len, std::vector<uintptr_t> &out) {
#if defined(__aarch64__)
    const uint8_t *bytes = (const uint8_t *) code;
    uint64_t baseAddr = (uint64_t) code;
    struct { uint64_t v; bool known; } reg[32];
    memset(reg, 0, sizeof(reg));
    size_t n = len / 4;
    for (size_t i = 0; i < n; ++i) {
        uint32_t w;
        memcpy(&w, bytes + i * 4, 4);
        if ((w & 0x9F000000u) == 0x90000000u) {
            int rd = w & 0x1F;
            uint64_t immhi = (w >> 5) & 0x7FFFF;
            uint64_t immlo = (w >> 29) & 0x3;
            uint64_t imm = (immhi << 2) | immlo;
            if (imm & (1u << 20)) imm -= (1u << 21);
            uint64_t pcPage = (baseAddr + i * 4) & ~0xFFFull;
            reg[rd].v = (pcPage + imm * 0x1000) & ~0xFFFull;
            reg[rd].known = true;
        } else if ((w & 0xFF800000u) == 0x91000000u || (w & 0xFF800000u) == 0x11000000u) {
            int rd = w & 0x1F;
            int rn = (w >> 5) & 0x1F;
            uint32_t imm12 = (w >> 10) & 0xFFF;
            if (reg[rn].known) {
                reg[rd].v = reg[rn].v + imm12;
                reg[rd].known = true;
                out.push_back((uintptr_t) reg[rd].v);
            }
        } else if ((w & 0xFFC00000u) == 0xF9400000u) {
            int rn = (w >> 5) & 0x1F;
            uint32_t imm12 = (w >> 10) & 0xFFF;
            if (reg[rn].known) {
                out.push_back((uintptr_t) (reg[rn].v + imm12 * 8));
            }
        }
    }
#elif defined(__arm__)
    const uint8_t *bytes = (const uint8_t *) code;
    size_t n = len / 4;
    for (size_t i = 0; i < n; ++i) {
        uint32_t w;
        memcpy(&w, bytes + i * 4, 4);
        if ((w & 0x0FFF0000u) == 0x051F0000u) {
            uint32_t imm = w & 0xFFF;
            uint64_t pc = (uint64_t) (bytes + i * 4) + 8;
            out.push_back((uintptr_t) ((pc & ~3u) + imm));
        }
    }
#elif defined(__x86_64__)
    const uint8_t *b = (const uint8_t *) code;
    for (size_t i = 0; i + 8 < len; ++i) {
        if (b[i] == 0x48 && (b[i + 1] == 0x8D || b[i + 1] == 0x8B) &&
            (b[i + 2] & 0xC7) == 0x05) {
            int32_t disp = 0;
            memcpy(&disp, b + i + 3, 4);
            uintptr_t next = (uintptr_t) (b + i + 7);
            out.push_back(next + (intptr_t) disp);
        }
    }
#elif defined(__i386__)
    const uint8_t *b = (const uint8_t *) code;
    for (size_t i = 0; i + 6 < len; ++i) {
        if ((b[i] == 0xA1) ||
            (b[i] == 0x8B && (b[i + 1] & 0xC7) == 0x05) ||
            (b[i] == 0x8D && (b[i + 1] & 0xC7) == 0x05)) {
            uint32_t disp = 0;
            memcpy(&disp, b + i + (b[i] == 0xA1 ? 1 : 2), 4);
            out.push_back(disp);
        }
    }
#endif
}

int Dumper::locateByCodeRecovery() {
    struct { void **ptr; const char *name; } fns[5];
    fns[0] = {&apiGetName_, "il2cpp_class_get_name"};
    fns[1] = {&apiGetNamespace_, "il2cpp_class_get_namespace"};
    fns[2] = {&apiMethodName_, "il2cpp_method_get_name"};
    fns[3] = {&apiFieldName_, "il2cpp_field_get_name"};
    fns[4] = {&apiImageName_, "il2cpp_image_get_name"};

    int best = 0;
    for (auto &fn : fns) {
        *(fn.ptr) = xdl_sym(handle_, fn.name, nullptr);
        if (!*(fn.ptr)) {
            DumpLog::warn("导出符号 %s 不存在, 跳过该扫描点", fn.name);
            continue;
        }
        const Region *reg = regionAt((uintptr_t) * (fn.ptr));
        if (reg && reg->perms.find('r') == std::string::npos) {
            DumpLog::warn("导出符号 %s 所在区间不可读, 无法扫描其代码", fn.name);
            continue;
        }
        std::vector<uintptr_t> addrs;
        collectArchAddr(*(fn.ptr), 0x80, addrs);
        if (addrs.empty()) {
            DumpLog::warn("导出符号 %s 前 0x80 字节未发现数据地址模式", fn.name);
            continue;
        }
        scanFunctions_.push_back(fn.name);
        DumpLog::info("导出符号 %s 中解析出 %zu 个数据地址候选", fn.name, addrs.size());
        for (uintptr_t a : addrs) {
            candidates_.push_back(a);
            int s = 0;
            uintptr_t bs = evalBest(a, s);
            if (s > best) {
                best = s;
                base_ = bs;
                sourceMethod_ = "code_recovery";
                sourceDetail_ = fn.name;
            }
        }
    }
    return best;
}

size_t Dumper::deriveSize() {
    if (sourceMethod_ == "maps") {
        uintptr_t regionEnd = regionEndAt(base_);
        if (regionEnd > base_) {
            metaSize_ = regionEnd - base_;
            if (metaSize_ > kMaxDumpSize) {
                DumpLog::warn("映射区间过大(%zu 字节), 截断到 %zu 字节", metaSize_, kMaxDumpSize);
                metaSize_ = kMaxDumpSize;
            }
            DumpLog::info("大小来源: named-map 区间长度 %zu 字节", metaSize_);
            return metaSize_;
        }
    }

    int32_t pairs[68];
    loadPairs(base_, pairs, 68);
    size_t maxEnd = 0;
    for (int i = 0; i + 1 < 68; i += 2) {
        int32_t off = pairs[i];
        int32_t sz = pairs[i + 1];
        if (off > 0 && sz > 0) {
            size_t end = (size_t) off + (size_t) sz;
            if (end > maxEnd) maxEnd = end;
        }
    }

    uintptr_t regionEnd = regionEndAt(base_);
    size_t regionLen = regionEnd > base_ ? regionEnd - base_ : 0;
    size_t cand = maxEnd + 0x1000;
    if (regionLen && regionLen >= cand && regionLen <= kMaxDumpSize) {
        cand = regionLen;
        DumpLog::info("大小来源: 专用匿名区(区间即文件) %zu 字节", regionLen);
    } else {
        DumpLog::info("大小来源: 表推算 maxEnd %zu, 若被截断以区间上限为界", maxEnd);
    }
    if (regionLen && cand > regionLen) {
        DumpLog::warn("推算大小 %zu 超过所在区间 %zu, 已截断, 存在截断风险", cand, regionLen);
        cand = regionLen;
    }
    if (cand == 0 || cand > kMaxDumpSize) cand = kMaxDumpSize;
    metaSize_ = (cand + 3) & ~(size_t) 3;
    return metaSize_;
}

int Dumper::guessVersion() {
    int32_t pairs[68];
    loadPairs(base_, pairs, 68);
    int32_t slo = pairs[0];
    static const int kSizes[] = {0x100, 0x104, 0x108, 0x10C, 0x110, 0x114, 0x118};
    for (size_t i = 0; i < sizeof(kSizes) / sizeof(kSizes[0]); ++i) {
        if (slo == kSizes[i]) return kMinVersion + (int) i;
    }
    return 29;
}

void Dumper::logWinnerBreakdown() {
    uint32_t sanity = 0;
    int32_t version = 0;
    safeRead(base_, &sanity, 4);
    safeRead(base_ + 4, &version, 4);
    int32_t pairs[68];
    loadPairs(base_, pairs, 68);
    uintptr_t regionEnd = regionEndAt(base_);
    size_t limit = regionEnd ? regionEnd - base_ : kMaxDumpSize * 2;
    int good = 0;
    for (int k = 0; k + 1 < 68; k += 2) {
        int32_t off = pairs[k], sz = pairs[k + 1];
        if (off > 0 && sz > 0 && (size_t) off + (size_t) sz <= limit) ++good;
    }
    DumpLog::info("胜者明细: sanity=0x%08" PRIx32 " version=%d 有效表对=%d/34 "
                  "stringOffset=%d imagesOffset=%d assembliesOffset=%d",
                  sanity, version, good, pairs[4], pairs[42], pairs[44]);
}

bool Dumper::writeFile(const std::string &path, const uint8_t *data, size_t n) {
    int fd = open(path.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DumpLog::error("打开输出文件失败 %s: %s", path.c_str(), strerror(errno));
        return false;
    }
    size_t done = 0;
    while (done < n) {
        ssize_t w = write(fd, data + done, n - done);
        if (w <= 0) {
            if (errno == EINTR) continue;
            DumpLog::error("写入失败 %s @%zu: %s", path.c_str(), done, strerror(errno));
            close(fd);
            return false;
        }
        done += (size_t) w;
    }
    close(fd);
    DumpLog::info("已写出 %zu 字节到 %s", n, path.c_str());
    return true;
}

bool Dumper::writeDump() {
    loadRegions();
    std::vector<uint8_t> data;
    data.resize(metaSize_);
    const size_t CHUNK = 1u << 20;
    size_t filled = 0;
    size_t nextLog = 8u << 20;
    while (filled < metaSize_) {
        size_t want = metaSize_ - filled < CHUNK ? metaSize_ - filled : CHUNK;
        if (!safeRead(base_ + filled, data.data() + filled, want)) {
            DumpLog::warn("读取内存 metadata 中断 @%" PRIxPTR " +%zu, 仅保留已读部分",
                    base_ + filled, want);
            break;
        }
        filled += want;
        if (filled >= nextLog) {
            DumpLog::info("转储进度 %zu/%zu 字节", filled, metaSize_);
            nextLog += 8u << 20;
        }
    }
    if (filled == 0) {
        DumpLog::error("未能读取到任何 metadata 字节");
        return false;
    }
    if (filled < metaSize_) {
        DumpLog::warn("实际读取 %zu 字节, 小于预估大小 %zu", filled, metaSize_);
        data.resize(filled);
        metaSize_ = filled;
    }

    uint32_t sanity = 0;
    int32_t version = 0;
    memcpy(&sanity, data.data(), 4);
    memcpy(&version, data.data() + 4, 4);

    auto outPath = outDir_ + "/files/global-metadata.dat";
    int32_t writtenVersion = version;
    if (sanity != kMagic) {
        sanityMangled_ = true;
        DumpLog::warn("内存中 sanity 魔数异常(0x%08" PRIx32 "), 将回写为 0xFAB11BAF", sanity);
        uint32_t m = kMagic;
        memcpy(data.data(), &m, 4);
    }
    if (version < kMinVersion || version > kMaxVersion) {
        versionMangled_ = true;
        metaVersion_ = guessVersion();
        DumpLog::warn("内存中 version 异常(%d), 猜测为 %d, 将同时输出各候选版本文件", version,
                metaVersion_);
        int32_t gv = metaVersion_;
        memcpy(data.data() + 4, &gv, 4);
        writtenVersion = gv;
        for (int v = kMinVersion; v <= kMaxVersion; ++v) {
            char altName[128];
            snprintf(altName, sizeof(altName), "global-metadata_v%02X.dat", v);
            std::vector<uint8_t> alt = data;
            int32_t vv = v;
            memcpy(alt.data() + 4, &vv, 4);
            writeFile(outDir_ + "/files/" + altName, alt.data(), alt.size());
        }
    } else {
        metaVersion_ = version;
        writtenVersion = version;
        DumpLog::info("version 字段正常 (%d), 主文件按原值输出", version);
    }
    DumpLog::info("主文件 version 写为 %d", writtenVersion);
    if (!writeFile(outPath, data.data(), data.size())) {
        return false;
    }
    return true;
}

bool Dumper::run(const char *outDir) {
    if (!outDir) return false;
    outDir_ = outDir;
    DumpLog::init(outDir_ + "/files/dump.log");
    CrashGuardScope crashGuard;  // 读内存 SIGSEGV 兜底，作用域结束自动恢复
    memFd_ = open("/proc/self/mem", O_RDONLY);
    if (memFd_ < 0) {
        DumpLog::warn("打开 /proc/self/mem 失败(%s), 改用进程内直接读(主路径)", strerror(errno));
    } else {
        DumpLog::info("备用读后端 /proc/self/mem 可用(fd=%d)", memFd_);
    }

    uint64_t startAll = nowMs();
    DumpLog::info("======== 元数据内存转储开始 ========");
    DumpLog::info("进程 PID=%d, 架构="
#if defined(__aarch64__)
            "aarch64"
#elif defined(__arm__)
            "arm32"
#elif defined(__x86_64__)
            "x86_64"
#elif defined(__i386__)
            "x86"
#endif
            ", 输出目录: %s", getpid(), outDir_.c_str());
    DumpLog::info("约定: magic=0x%08" PRIx32 " 版本区间=%d..%d", kMagic, kMinVersion, kMaxVersion);

    handle_ = xdl_open("libil2cpp.so", 0);
    if (!handle_) {
        DumpLog::error("xdl_open(libil2cpp.so) 失败, 无法继续");
        DumpLog::info("======== [结果] 元数据转储失败: 未加载 libil2cpp.so ========");
        return false;
    }
    DumpLog::info("libil2cpp.so 已打开(%p)", handle_);

    if (!loadRegions()) {
        DumpLog::error("解析 /proc/self/maps 失败, 保留部分定位手段受限");
    }

    bool bestFound = false;
    int bestScore = 0;
    uintptr_t bestAddr = 0;
    std::string bestMethod;
    std::string bestDetail;

    {
        uint64_t t0 = nowMs();
        int s = locateByMaps();
        uint64_t el = nowMs() - t0;
        if (s > 0) {
            bestScore = s;
            bestAddr = base_;
            bestMethod = "maps";
            bestDetail = sourceDetail_;
            bestFound = true;
            logStep(1, 5, "locate_by_maps", MethodStatus::OK,
                    "命中映射 %s, 评分 %d, 耗时 %" PRIu64 "ms", sourceDetail_.c_str(), s, el);
        } else {
            logStep(1, 5, "locate_by_maps", MethodStatus::FAIL,
                    "未找到名为 global-metadata.dat 的映射区间, 耗时 %" PRIu64 "ms", el);
        }
    }

    if (!bestFound || bestScore < kAcceptScore) {
        uint64_t t0 = nowMs();
        int s = locateByDlsym();
        uint64_t el = nowMs() - t0;
        if (s > bestScore) {
            bestScore = s;
            bestAddr = base_;
            bestMethod = "dlsym";
            bestDetail = sourceDetail_;
            bestFound = true;
            logStep(2, 5, "locate_by_dlsym", MethodStatus::OK,
                    "符号 %s 解析出 base=%" PRIxPTR ", 评分 %d, 耗时 %" PRIu64 "ms",
                    sourceDetail_.c_str(), base_, s, el);
        } else {
            logStep(2, 5, "locate_by_dlsym", MethodStatus::FAIL,
                    "未通过符号 s_GlobalMetadata/s_GlobalMetadataHeader 找到有效 base, 耗时 %" PRIu64 "ms",
                    el);
        }
    } else {
        logStep(2, 5, "locate_by_dlsym", MethodStatus::SKIPPED, "上一方法已命中并达到置信线");
    }

    if (!bestFound || bestScore < kAcceptScore) {
        uint64_t t0 = nowMs();
        int s = locateBySGlobalMetadata();
        uint64_t el = nowMs() - t0;
        if (s > bestScore) {
            bestScore = s;
            bestAddr = base_;
            bestMethod = "s_global_metadata";
            bestDetail = sourceDetail_;
            bestFound = true;
            logStep(3, 5, "locate_by_s_global_metadata", MethodStatus::OK,
                    "RW 段指针命中 base=%" PRIxPTR ", 评分 %d, 耗时 %" PRIu64 "ms",
                    base_, s, el);
        } else {
            logStep(3, 5, "locate_by_s_global_metadata", MethodStatus::FAIL,
                    "RW 段未找到指向 magic 的指针, 耗时 %" PRIu64 "ms", el);
        }
    } else {
        logStep(3, 5, "locate_by_s_global_metadata", MethodStatus::SKIPPED, "上一方法已命中并达到置信线");
    }

    if (!bestFound || bestScore < kAcceptScore) {
        uint64_t t0 = nowMs();
        int s = locateByCodeRecovery();
        uint64_t el = nowMs() - t0;
        if (s > bestScore) {
            bestScore = s;
            bestAddr = base_;
            bestMethod = "code_recovery";
            bestDetail = sourceDetail_;
            bestFound = true;
            logStep(4, 5, "locate_by_code_recovery", MethodStatus::OK,
                    "经 %s 反推 base=%" PRIxPTR ", 评分 %d, 耗时 %" PRIu64 "ms",
                    sourceDetail_.c_str(), base_, s, el);
        } else {
            logStep(4, 5, "locate_by_code_recovery", MethodStatus::FAIL,
                    "导出函数前 0x80 字节未反推出有效 base, 耗时 %" PRIu64 "ms", el);
        }
    } else {
        logStep(4, 5, "locate_by_code_recovery", MethodStatus::SKIPPED, "上一方法已命中并达到置信线");
    }

    if (!bestFound || bestScore < kAcceptScore) {
        uint64_t t0 = nowMs();
        int s = locateByMagicScan();
        uint64_t el = nowMs() - t0;
        if (s > bestScore) {
            bestScore = s;
            bestAddr = base_;
            bestMethod = "magic_scan";
            bestDetail = sourceDetail_;
            bestFound = true;
            logStep(5, 5, "locate_by_magic_scan", MethodStatus::OK,
                    "命中 %s, base=%" PRIxPTR ", 评分 %d, 耗时 %" PRIu64 "ms",
                    sourceDetail_.c_str(), base_, s, el);
        } else {
            logStep(5, 5, "locate_by_magic_scan", MethodStatus::FAIL,
                    "全内存未搜到可信 magic 候选(最高评分 %d), 耗时 %" PRIu64 "ms", s, el);
        }
    } else {
        logStep(5, 5, "locate_by_magic_scan", MethodStatus::SKIPPED, "上一方法已命中并达到置信线");
    }

    if (!bestFound) {
        DumpLog::error("五种定位方法均失败, 无任何候选 base");
        DumpLog::info("======== [结果] 元数据转储失败: 未能定位内存中的 global-metadata ========");
        return false;
    }

    base_ = bestAddr;
    sourceMethod_ = bestMethod;
    sourceDetail_ = bestDetail;
    wellVerified_ = bestScore >= kAcceptScore;
    DumpLog::info("定位确认: base=%" PRIxPTR ", 最高评分=%d (%s), 方法=%s %s", base_, bestScore,
            wellVerified_ ? "高置信" : "低置信(降级WARN)",
            sourceMethod_.c_str(), sourceDetail_.c_str());
    logWinnerBreakdown();

    if (wellVerified_) {
        int32_t v = 0;
        safeRead(base_ + 4, &v, 4);
        DumpLog::info("校验通过: sanity=%s version=%d",
                [&]() -> const char * {
                    uint32_t s;
                    safeRead(base_, &s, 4);
                    return s == kMagic ? "有效" : "异常(稍后回写)";
                }(), v);
    } else {
        DumpLog::warn("候选 base 未达置信线, 按兜底策略仍尝试转储(WARN)");
    }

    deriveSize();
    if (metaSize_ == 0) {
        DumpLog::error("无法确定大小, 放弃转储");
        DumpLog::info("======== [结果] 元数据转储失败: size 推算为 0 ========");
        return false;
    }

    uint32_t sanity0 = 0;
    int32_t ver0 = 0;
    safeRead(base_, &sanity0, 4);
    safeRead(base_ + 4, &ver0, 4);
    DumpLog::info("内存头部原始值: sanity=0x%08" PRIx32 ", version=%d", sanity0, ver0);

    if (!writeDump()) {
        DumpLog::error("写盘失败, 请检查目录权限与磁盘空间");
        DumpLog::info("======== [结果] 元数据转储失败: 写盘阶段出错 ========");
        return false;
    }

    dumped_ = true;
    uint64_t totalElapsed = nowMs() - startAll;
    DumpLog::info("======== [结果] 元数据转储%s ========",
            wellVerified_ ? "成功" : "成功(低置信度, 内容可能需要离线校对)");
    DumpLog::info("产物清单:");
    DumpLog::info("  主文件: %s/files/global-metadata.dat (%zu 字节)", outDir_.c_str(), metaSize_);
    DumpLog::info("  日志文件: %s/files/dump.log", outDir_.c_str());
    if (versionMangled_) {
        DumpLog::warn("因 version 被混淆, 已额外输出 24..31 各候选版本文件, 建议用 Il2CppDumper/Il2CppInspector 逐个验证");
    }
    DumpLog::info("定位方法链: %s", sourceMethod_.c_str());
    DumpLog::info("耗时总计 %" PRIu64 "ms", totalElapsed);
    return true;
}

}