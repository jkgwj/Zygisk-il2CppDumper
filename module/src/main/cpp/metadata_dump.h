#ifndef ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H
#define ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H

#include <cstdarg>
#include <cstdint>
#include <cstdio>
#include <string>
#include <utility>
#include <vector>

namespace MetadataDump {

enum class MethodStatus {
    OK,
    WARN,
    FAIL,
    SKIPPED,
};

struct StepLog {
    int phase;
    int total;
    std::string method;
    MethodStatus status;
    std::string reason;
    uint64_t elapsed_ms;
};

struct Region {
    uintptr_t start;
    uintptr_t end;
    std::string perms;
    std::string path;
};

class Dumper {
public:
    Dumper();
    ~Dumper();

    bool run(const char *outDir);

    bool dumped() const { return dumped_; }
    bool wellVerified() const { return wellVerified_; }
    const std::vector<StepLog> &steps() const { return steps_; }

private:
    static constexpr uint32_t kMagic = 0xFAB11BAFu;
    static constexpr int kMinVersion = 24;
    static constexpr int kMaxVersion = 31;
    static constexpr int kAcceptScore = 45;
    static constexpr size_t kMaxDumpSize = 64u * 1024 * 1024;
    static constexpr size_t kScanByteBudget = 0x60000000ULL;
    static constexpr uint64_t kScanMsBudget = 25000;

    void *handle_ = nullptr;
    int memFd_ = -1;
    FILE *logFp_ = nullptr;
    std::string outDir_;
    std::string logPath_;
    std::vector<StepLog> steps_;
    std::vector<Region> regions_;
    bool dumped_ = false;
    bool wellVerified_ = false;

    uintptr_t base_ = 0;
    size_t metaSize_ = 0;
    int metaVersion_ = -1;
    std::string sourceMethod_;
    std::string sourceDetail_;
    std::vector<std::string> scanFunctions_;
    std::vector<uintptr_t> candidates_;
    bool versionMangled_ = false;
    bool sanityMangled_ = false;

    void *apiGetName_ = nullptr;
    void *apiGetNamespace_ = nullptr;
    void *apiMethodName_ = nullptr;
    void *apiFieldName_ = nullptr;
    void *apiImageName_ = nullptr;

    bool safeRead(uintptr_t addr, void *out, size_t n);

    void flushLog(int level, const char *fmt, va_list ap);
    void logInfo(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void logWarn(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void logErr(const char *fmt, ...) __attribute__((format(printf, 2, 3)));
    void logStep(int phase, int total, const char *method, MethodStatus st,
                 const char *fmt, ...) __attribute__((format(printf, 6, 7)));

    bool loadRegions();
    const Region *regionAt(uintptr_t addr) const;
    uintptr_t regionEndAt(uintptr_t addr) const;

    int scoreCandidate(uintptr_t base);
    uintptr_t evalBest(uintptr_t addr, int &score);
    void loadPairs(uintptr_t base, int32_t *out, size_t maxPairs);
    size_t deriveSize();

    int locateByMaps();
    int locateByDlsym();
    int locateByMagicScan();
    int locateByCodeRecovery();
    void collectArchAddr(const void *code, size_t len, std::vector<uintptr_t> &out);

    bool writeDump();
    bool writeFile(const std::string &path, const uint8_t *data, size_t n);
    int guessVersion();
};

} // namespace MetadataDump

#endif // ZYGISK_IL2CPPDUMPER_METADATA_DUMP_H