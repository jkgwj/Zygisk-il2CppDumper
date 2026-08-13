#ifndef ZYGISK_IL2CPPDUMPER_SO_DUMP_H
#define ZYGISK_IL2CPPDUMPER_SO_DUMP_H

namespace SoDump {

// 从内存 dump 已加载的 .so（加载后的内存布局，即解壳/解密后的内容），
// 输出到 {outDir}/files/ 下。与 .cs / metadata 转储相互独立，互不影响。
bool dump(const char *outDir);

} // namespace SoDump

#endif // ZYGISK_IL2CPPDUMPER_SO_DUMP_H
