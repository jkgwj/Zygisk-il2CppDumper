#ifndef ZYGISK_IL2CPPDUMPER_DUMP_LOG_H
#define ZYGISK_IL2CPPDUMPER_DUMP_LOG_H

#include <cinttypes>
#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <ctime>
#include <string>

// 仅落盘的共享文件日志器（header-only，inline 变量保证进程内唯一实例）。
// 供 .cs 转储(il2cpp_dump.cpp) 与 metadata 转储(metadata_dump.cpp) 共用，
// 输出到 {应用data目录}/files/dump.log。不写 logcat，避免污染。
namespace DumpLog {

enum Level { kError = 0, kWarn = 1, kInfo = 2, kDebug = 3 };

inline FILE *g_fp = nullptr;
inline uint64_t g_start_ms = 0;

inline uint64_t now_ms() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (uint64_t) ts.tv_sec * 1000u + (uint64_t) (ts.tv_nsec / 1000000u);
}

inline bool init(const std::string &path) {
    if (g_fp) return true;
    g_fp = fopen(path.c_str(), "w");
    if (g_fp) {
        g_start_ms = now_ms();
        // 写 BOM，便于 Windows 记事本正确显示中文日志
        fputs("\xEF\xBB\xBF", g_fp);
    }
    return g_fp != nullptr;
}

inline void close() {
    if (g_fp) {
        fflush(g_fp);
        fclose(g_fp);
        g_fp = nullptr;
    }
}

inline void vlog(Level level, const char *fmt, va_list ap) {
    if (!g_fp) return;
    char buf[2048];
    va_list ap2;
    va_copy(ap2, ap);
    vsnprintf(buf, sizeof(buf), fmt, ap2);
    va_end(ap2);
    const char *tag = level == kError ? "ERROR" : level == kWarn ? "WARN"
                      : level == kDebug ? "DEBUG" : "INFO";
    uint64_t el = now_ms() - g_start_ms;
    fprintf(g_fp, "[%6" PRIu64 ".%03" PRIu64 "][%-5s] %s\n",
            el / 1000u, el % 1000u, tag, buf);
    fflush(g_fp);
}

inline void error(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
inline void error(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(kError, fmt, ap);
    va_end(ap);
}

inline void warn(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
inline void warn(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(kWarn, fmt, ap);
    va_end(ap);
}

inline void info(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
inline void info(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(kInfo, fmt, ap);
    va_end(ap);
}

inline void debug(const char *fmt, ...) __attribute__((format(printf, 1, 2)));
inline void debug(const char *fmt, ...) {
    va_list ap;
    va_start(ap, fmt);
    vlog(kDebug, fmt, ap);
    va_end(ap);
}

} // namespace DumpLog

#endif // ZYGISK_IL2CPPDUMPER_DUMP_LOG_H
