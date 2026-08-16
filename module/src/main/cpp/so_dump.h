#ifndef ZYGISK_IL2CPPDUMPER_SO_DUMP_H
#define ZYGISK_IL2CPPDUMPER_SO_DUMP_H

namespace SoDump {

// 从内存 dump 已加载的 .so（加载后的内存布局，即解壳/解密后的内容），
// 输出到 {outDir}/files/ 下。与 .cs / metadata 转储相互独立，互不影响。
bool dump(const char *outDir);

// 独立线程转储 libunity.so（Android 名；Windows 才是 UnityPlayer）。
// 完全解耦于 .cs/metadata/libil2cpp dump：仅 xdl 查找 + 内存拷段 + 落盘，
// 不触碰任何 il2cpp api。找不到该 so 时只打印相关模块日志后放行，
// 绝不影响其他 dump/游戏运行。
void dump_libunity_only(const char *outDir);

} // namespace SoDump

#endif // ZYGISK_IL2CPPDUMPER_SO_DUMP_H
