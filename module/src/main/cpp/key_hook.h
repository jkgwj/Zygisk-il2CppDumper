//
// key_hook.h
// 用例：拦截 Beyond.VFS.VirtualFileSystem.GetCommonChachaKeyBs(Span<byte>)，
// 记录真实参数与返回值（chacha 解密密钥），写 /data/<pkg>/files/hook.out。
// 运行方式：start_synced() 由 dump 线程在 dump.cs 完成后调用（与 dump.cs 时机
// 同步），prepare 内安装 → 成功后另起独立线程 flush。prepare 崩溃护栏捕获
// 异常后只打日志，不影响原 dump。
//

#ifndef ZYGISK_IL2CPPDUMPER_KEY_HOOK_H
#define ZYGISK_IL2CPPDUMPER_KEY_HOOK_H

#include <string>

namespace KeyHook {

// 安装 hook（需 il2cpp 运行时已初始化）。返回 0 成功。
int prepare(const char *game_data_dir);

// flush 循环入口（阻塞）。把捕获记录写入 hook.out，达到上限后返回。
void flush();

// 与 dump.cs 时机同步安装（jkgbk）：hack_start 在 il2cpp_api_init 成功、
// dump.cs 跑完后，由 dump 线程调用本入口。内部最多补试 kInstallTries 次，
// 成功后另起独立 flush 线程(不阻塞 metadata/so dump)。
// 不再像以前那样独立线程"运行时就绪第一时间"并发扫类型表——那是把游戏
// 在懒初始化期带崩的根因；反正有 call_once 手动调用，无需抢早期真实调用。
// prepare 全程护栏；flush 刻意不上护栏(避免进程级 SIGSEGV handler 与
// metadata_dump 的 CrashGuardScope 互相 clobber)。
void start_synced(const char *game_data_dir);

} // namespace KeyHook

#endif // ZYGISK_IL2CPPDUMPER_KEY_HOOK_H