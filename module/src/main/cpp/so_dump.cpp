#include "so_dump.h"
#include "dump_log.h"
#include "xdl.h"

#include <cstring>
#include <cerrno>
#include <cinttypes>
#include <string>
#include <vector>
#include <thread>
#include <unistd.h>
#include <fcntl.h>
#include <elf.h>

namespace SoDump {

namespace {

// 需要 dump 的 .so 列表（后续要加 libunity.so 等，往这里加名字即可）
constexpr const char *kSoNames[] = {
    "libil2cpp.so",
    // "libmain.so",
};

// 私有字节拷贝：不经过可能被反作弊 inline-hook 的 libc memcpy 符号
__attribute__((noinline))
static void copyBytes(void *dst, const void *src, size_t n) {
    volatile uint8_t *d = (volatile uint8_t *) dst;
    const volatile uint8_t *s = (const volatile uint8_t *) src;
    for (size_t i = 0; i < n; ++i) d[i] = s[i];
}

bool dumpOneSo(const char *name, const char *outDir) {
    void *handle = xdl_open(name, 0);
    if (!handle) {
        DumpLog::warn("xdl_open(%s) 失败, 跳过", name);
        return false;
    }
    xdl_info_t info{};
    if (xdl_info(handle, XDL_DI_DLINFO, &info) != 0 || !info.dli_fbase || !info.dlpi_phdr ||
        info.dlpi_phnum == 0) {
        DumpLog::warn("xdl_info(%s) 无法取得基址/程序头, 跳过", name);
        return false;
    }

    std::string outPath = std::string(outDir) + "/files/" + name;
    int fd = open(outPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        DumpLog::error("打开输出文件失败 %s: %s", outPath.c_str(), strerror(errno));
        return false;
    }

    uintptr_t base = (uintptr_t) info.dli_fbase;
    DumpLog::info("dump %s: base=0x%" PRIxPTR ", 程序头 %zu 个", name, base, info.dlpi_phnum);

    // 加壳 .so 的 p_offset 可能与内存布局不一致（重叠/压缩），不可信。
    // 改用内存镜像布局：p_offset = p_vaddr - minVaddr。
    uintptr_t minVaddr = (uintptr_t) -1;
    for (size_t i = 0; i < info.dlpi_phnum; ++i) {
        const ElfW(Phdr) &ph = info.dlpi_phdr[i];
        if (ph.p_type == PT_LOAD && ph.p_vaddr < minVaddr) minVaddr = ph.p_vaddr;
    }
    if (minVaddr == (uintptr_t) -1) {
        DumpLog::error("dump %s: 无 PT_LOAD 段", name);
        close(fd);
        return false;
    }

    // 拷贝程序头并修正 p_offset
    std::vector<ElfW(Phdr)> phdrs(info.dlpi_phdr, info.dlpi_phdr + info.dlpi_phnum);
    for (auto &ph : phdrs) {
        if (ph.p_type == PT_LOAD) ph.p_offset = (ElfW(Off)) (ph.p_vaddr - minVaddr);
    }

    const size_t CHUNK = 1u << 20;
    std::vector<uint8_t> buf(CHUNK, 0);
    size_t totalWritten = 0;

    for (const auto &ph : phdrs) {
        if (ph.p_type != PT_LOAD || ph.p_filesz == 0) continue;
        uintptr_t segAddr = base + ph.p_vaddr;
        size_t filesz = (size_t) ph.p_filesz;
        off_t offset = (off_t) (ph.p_vaddr - minVaddr);
        DumpLog::info("  段: vaddr=0x%" PRIxPTR " filesz=%zu offset=%zu",
                      segAddr, filesz, (size_t) offset);
        if (lseek(fd, offset, SEEK_SET) < 0) {
            DumpLog::warn("  lseek 失败: %s", strerror(errno));
            continue;
        }
        size_t done = 0;
        while (done < filesz) {
            size_t want = filesz - done < CHUNK ? filesz - done : CHUNK;
            copyBytes(buf.data(), (const void *) (segAddr + done), want);
            ssize_t w = write(fd, buf.data(), want);
            if (w <= 0) {
                DumpLog::warn("  段写入中断 @+%zu: %s", done, strerror(errno));
                break;
            }
            done += (size_t) w;
        }
        totalWritten += done;
    }

    // 最后回写修正后的 ELF 头 + 程序头（覆盖段1里原始的、p_offset 不一致的头，
    // 并清零节头表，交给 SoFixer 重建）
    ElfW(Ehdr) ehdr{};
    copyBytes(&ehdr, (const void *) base, sizeof(ehdr));
    ehdr.e_shoff = 0;
    ehdr.e_shnum = 0;
    ehdr.e_shstrndx = 0;
    lseek(fd, 0, SEEK_SET);
    write(fd, &ehdr, sizeof(ehdr));
    lseek(fd, (off_t) ehdr.e_phoff, SEEK_SET);
    write(fd, phdrs.data(), phdrs.size() * sizeof(ElfW(Phdr)));

    close(fd);
    DumpLog::info("dump %s 完成: 写出 %zu 字节 -> %s", name, totalWritten, outPath.c_str());
    return true;
}

} // namespace

bool dump(const char *outDir) {
    if (!outDir) return false;
    DumpLog::info("======== .so 转储开始 ========");
    for (const char *name : kSoNames) {
        dumpOneSo(name, outDir);
    }
    DumpLog::info("======== .so 转储结束 ========");
    return true;
}

namespace {

// 只读遍历已加载 so，把名字含 unity/UnityPlayer 的全部打进 dump.log（不 dump）。
void listUnityModules() {
    DumpLog::info("==== libunity 相关已加载模块列表 ====");
    struct Ctx {
        int count;
    } ctx{0};
    xdl_iterate_phdr([](struct dl_phdr_info *info, size_t size, void *data) -> int {
        (void) size;
        auto *c = (Ctx *) data;
        if (!info || !info->dlpi_name) return 0;
        const char *n = info->dlpi_name;
        if (strstr(n, "unity") || strstr(n, "Unity") || strstr(n, "UnityPlayer")) {
            uintptr_t seg = 0;
            for (size_t i = 0; i < info->dlpi_phnum; ++i) {
                if (info->dlpi_phdr[i].p_type == PT_LOAD && info->dlpi_phdr[i].p_filesz) {
                    seg += info->dlpi_phdr[i].p_filesz;
                }
            }
            DumpLog::info("  模块[%d]: %s base=0x%" PRIxPTR " phnum=%u 段总和=%zu",
                          c->count++, n, (uintptr_t) info->dlpi_addr,
                          (unsigned) info->dlpi_phnum, seg);
        }
        return 0;
    }, &ctx, XDL_FULL_PATHNAME);
    DumpLog::info("==== libunity 相关模块共 %d 个 ====", ctx.count);
}

// 独立线程：轮询等 libunity.so 出现 → dump；未命中则列出候选后放行。
void libunity_thread(const char *outDir) {
    constexpr int kMaxTries = 20;
    for (int i = 1; i <= kMaxTries; ++i) {
        void *h = xdl_open("libunity.so", 0);
        if (h) {
            DumpLog::info("libunity.so 已命中(第 %d/%d 次), 开始转储", i, kMaxTries);
            dumpOneSo("libunity.so", outDir);
            xdl_close(h);
            return;
        }
        DumpLog::info("libunity.so 尚未加载(%d/%d), 1s 后重试", i, kMaxTries);
        sleep(1);
    }
    DumpLog::warn("libunity.so 等待超时(%ds), 未转储. 列出候选模块供排查:",
                  kMaxTries);
    listUnityModules();
}

} // namespace

void dump_libunity_only(const char *outDir) {
    if (!outDir) return;
    DumpLog::info("======== libunity.so 独立转储启动(后台线程) ========");
    std::thread t(libunity_thread, outDir);
    t.detach();
}

} // namespace SoDump
