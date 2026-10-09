# Codec 版本适配与回归证据

2026-10-09。只修改 codec 与针对性 C++ 测试，不改服务或 CMake。协议事实来自本次新版 `Richonline/RnClient.exe` 的 IDA 证据，SHA-256 `cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`。

## 接口和行为

- `ClientVersion::{legacy,richonline}`，`Transport` 新增最后一个 `version` 字段，默认为 legacy。原两字段聚合初始化保持可编译。
- `encode_envelope(envelope, version=legacy)`、`decode_envelope(frame, version=legacy)`。旧版保留四字节 tail；新版只写五字节语义头和 encoded 数据。新版 decode 的零 tail 数组仅表示内部“没有尾”，没有线上四字节占位；新版 encode 拒绝非零 tail，防止悄悄丢弃调用者数据。
- `modpow_signed32(base, exponent, modulus)`，返回 `int32_t`。仅接受正 exponent/modulus，异常参数抛 `CodecError`。乘法有意保留低32位，再转换为有符号值取有符号余数；不依赖 C++ signed-overflow UB。除零与有符号除法溢出在 helper 中另有显式拒绝，正模数入口也排除了它们。
- 新版仅 C2S type759 被识别为必须明文的已证握手回应。没有把 S2C type579 声明为新版首握手；新版应用必须按状态选择首次明文接收。旧版现有579/759保留规则不变。
- 新版 C2S 与 S2C 根据各自已证分支支持 signed key。encode/decode 对同一方向均为该方向的互逆变换（字节 XOR 与整段反转可交换），没有假定两个方向的负 key 行为相同。

## 汇编依据

- `protocol-analysis/richonline-rebuild/transport-send/transport-evidence.txt`：`0x88D2B9` 完整 DWORD 魔数；`0x88D2D0–0x88D2DC` C2S length=总长−4；`0x88DB90` S2C +4 总长。原 frame 实现已符合这两种不同头部，新增固定字节回归锁定。
- `0x8DF990`：`0x8DF9FB–0x8DFA07` 计算有符号 `%2`，`0x8DFA09 jnz` 对任何非零余数反转。`0x8DFAC0`：`0x8DFAE7–0x8DFAF3` 计算同一余数，`0x8DFAF3 cmp eax,1`、`0x8DFAF6 jnz` 仅余数1反转。因此负奇数只在 C2S 反转，不能用 `(key&1)` 同时替代两方向。
- `0x8DFFF0`：`0x8E0032/0x8E0048 imul` 低32位结果，`0x8E0036/0x8E004C cdq`，`0x8E0037/0x8E004D idiv` 有符号余数；指数 `0x8E0040 sar`。表中实际指数为正，API也限定正数。
- `0x88D017 push 2F7h`、`0x87F410`、`0x87F320` 证实759回应总长16、4字节公开值，直接入发送队列绕过普通载荷加密。
- `protocol-analysis/richonline-rebuild/game/INDEX.md` 的 `0x828F60 case9`、`0x87BD20/0x87BE40/0x87CA90` 证明新版299外层8字节头，内部只有 `tag:u16,length:u16,flag:i8,encoded`，不存在旧版四字节tail。接收函数预读9字节的实现行为不等于新增线上字段。

## 测试与执行

测试先于实现加入，第一次独立 clang++ 编译 exit1，错误为旧头文件没有 `ClientVersion` / `modpow_signed32`。实现后使用原项目 LLVM-MinGW 编译器、C++20 与原项目严格警告选项：

```text
clang++ -std=c++20 -Wall -Wextra -Wpedantic -Werror -Wconversion -Wsign-conversion -I include tests/codec_tests.cpp src/frame.cpp src/inner.cpp src/handshake.cpp -o build-ninja/codec_tests_standalone.exe
build-ninja/codec_tests_standalone.exe
```

最终结果：编译 exit0；程序 exit0，输出 `codec regression fixtures passed`。

`codec_tests.cpp` 用独立固定字节数组验证 C2S魔数/length、S2C总长、明文759、新299无tail和旧版tail；并验证所有两帧流切分点、逐字节碎片、多个帧、截断/坏头/超大长度拒绝。signed key 样本覆盖 `-1,-2,INT_MIN,INT_MAX` 且分别断言两个方向的具体载荷字节。

模幂固定溢出样本不是用被测函数算期望：`50000²=2500000000` 的 low32 有符号值为 `-1794967296`，对100000的有符号余数为 `-67296`；`46341²=2147488281` 的 low32 有符号值为 `-2147479015`，对INT_MAX余数仍为该值。另有小参数、INT_MIN底数、模数1、零/负指数及零/负模数边界。

没有运行真实客户端、没有连接线上服务，没有证实首握手 type 或端到端游戏可用。构建产物仅为本地 `build-ninja/codec_tests_standalone.exe`；这份测试证明 codec 的已证字节规则，不证明服务器状态机完整。
