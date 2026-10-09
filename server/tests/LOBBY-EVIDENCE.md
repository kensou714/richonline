# C++ 大厅会话服务证据

## 实现及接入接口

- `include/lobby.hpp`：`LobbyOptions`、`LobbyCallbacks`、`RichLobbySession`、`RichLobbyService`；`LobbyOptions::version` defaults to `ClientVersion::richonline` and can explicitly select the original client profile.
- `src/lobby.cpp`：帧边界、握手密钥切换、144-byte login parsing, profile-specific descriptor validation and username decoding, authentication state machine.
- `src/lobby_service.cpp`：TCP 监听、最多 32 个同时连接、停机、日志。
- `tests/lobby_tests.cpp`：真实 C++ 状态机与 TCP 测试。

服务明确注入账号验证及业务响应构造器，不复制旧 Python 服务实现，不写数据库，不自行填未知业务字段。`verify_credentials` 收到 UTF-8 用户名及密码槽中的原始 password bytes；Richonline uses Big5/CP950 username bytes and the original client profile uses GBK/CP936. Password bytes are passed unchanged to the credential adapter. The password span is valid only during the callback and no credential text is logged.

接入顺序：构造 `LobbyOptions`，显式配置 `handshake`；注入 `verify_credentials`、`login_responses`、`authenticated_request`；调用 `RichLobbyService::run()`。`stop()` 通过事件循环检查退出，不关闭其他线程持有的 socket；正常空闲退出约 200 ms，单次发送等待上限 5 秒。`bound_port()` 支持独立测试时绑定端口 0。CMake 由根代理整合，本任务未改 CMake、共享编解码、存储、控制接口或 Python 服务。

## 协议依据

### Original client profile

`LobbyOptions{..., ClientVersion::legacy}` is an explicit original-client mode. It keeps the same 579/759 DH handshake and legacy transport transform, requires the 144-byte login descriptor `(opaque_u32, 132, 0)`, preserves `opaque_u32` as `LobbyLogin::unknown_descriptor_u32`, decodes the username slot as GBK/CP936, and leaves the password slot as raw bytes. Any other descriptor is rejected before authentication. The default remains Richonline mode `(0, 0, 0)` with Big5/CP950 decoding.

Behavioral sources are the read-only original service: `local-server/lobby_io.py:42-52` for descriptor/slots/GBK, `local-server/lobby_session_handler.py:50-64` for handshake and profile distinction, and `local-server/check_login_defaults.py:62-71` for the original descriptor fixture. This patch does not claim new original-client disassembly or a successful desktop lobby login.

`tests/original_lobby_tests.cpp` uses a test-only sentinel response and checks coalesced and byte-fragmented 759+58 streams, GBK Chinese username conversion, non-ASCII password byte preservation, unknown descriptor preservation, descriptor/profile rejection, unterminated/invalid GBK slots, authentication failure, and metadata-only logs. It does not construct a real channel list, role record, room record, or game response.

新版客户端 SHA-256：`cb35f69f3d49c2093897d4ea2cb547a1e38b213f3a8df0af52b859f9e661de77`。

详见 `protocol-analysis/richonline-rebuild/transport-send/INDEX.md` 与 `lobby-receive/INDEX.md`：

| 内容 | 证据与处理 |
|---|---|
| C2S 头 | magic `0x10A1D85F`、type DWORD、length `total-4`；12-byte 头；使用 `richnet_codec` |
| S2C 头 | type DWORD、total length DWORD；8-byte 头；使用 `richnet_codec` |
| 首帧 DH | `0x8DD020` 消费 g/p/public 三个 DWORD；首帧 type 未由官方动态数据确认 |
| type759 | 4-byte clientPublic，明文发送，`0x88CFC0` |
| 密钥 | `0x8DFFF0` signed32 模幂；每完成一帧之后更新 key，支持一次读取中合并759与58 |
| 加密 | 仅 payload XOR byte key，奇数 key 的反转，按新版方向规则使用 codec |
| C2S58 | `0x87E430`：144 bytes，前三 DWORD 为常量 `(0,0,0)`，两个64-byte NUL字符串槽，最后 DWORD 语义未知 |
| padding | 字符串 NUL 后剩余槽不要求为零，原始构造器未清空；测试使用 `0xCA` 非零 padding |
| 登录尾 DWORD | 保留为 `LobbyLogin::unknown_tail_u32`，交由响应构造器判定，未假称业务语义 |
| 响应 | 由根提供已证 S2C builder；首版本身不构造未经证实的账号、资产、频道、房间或地图字段 |

`LobbyOptions::handshake` 默认缺省，未配置时明确抛 `lobby_handshake_not_configured`。`local_lobby_handshake()` 返回 **type579,g5,p251,server exponent7**，serverPublic=64。这组参数来源为当前本地服务 `lobby_session_handler.py:50` 和 `local-server/runtime/manager-57796.log` 中真实新版登录成功并显示频道列表的记录（根代理提供并复核）。它是已被本地新版接受的兼容策略，不是官方首帧 type 的唯一常量证明；当前实现不会把这个策略隐式当成客户端静态证据。

参数限制为 `3 <= p <= 46340`、`2 <= g < p`、正指数，以及 `0 < clientPublic < p`。模数上限保证正数乘法不超过 signed32 范围，因此双方的 DH 计算保持一致。本实现没有宣称支持所有溢出或负数参数组合。

## 拒绝与日志

未配置握手、错误 magic/长度、错误握手帧、错误144-byte 登录、未终止字符串、未知 descriptor、认证失败、重复登录、缺失业务响应构造器均明确拒绝。失败关闭连接并记录稳定原因代码；不使用零填充错误回包或伪造成功。帧日志只记录 type 与 payload_bytes，成功只记 `lobby_authenticated`。

未覆盖：业务失败 S2C、具体登录成功字段/频道列表/频道初始化、房间创建/游戏接入、多客户端房间广播、协议速率限制与可玩性，由根继续整合并验证。回调返回的每个 Frame 仍需根按目标客户端字段证据构造。Original-profile tests intentionally use a sentinel callback frame only.

## 运行验证

2026-10-09 在 Windows LLVM-MinGW 上运行：

```sh
cmake --build native-server/build-ninja --target richnet_lobby_tests richnet_original_lobby_tests -j 4
./native-server/build-ninja/richnet_lobby_tests.exe
./native-server/build-ninja/richnet_original_lobby_tests.exe
```

退出 0，输出 `lobby state machine tests PASS` 与 `original lobby session tests PASS`。新版测试包含显式缺省握手拒绝与已知20-byte握手、同chunk759+58密钥切换、逐字节碎片、Big5用户名、非零槽padding、错误descriptor/magic/截断、认证失败不调用success，以及**真实本机TCP**绑定动态端口、握手、合并759+58+34、读回加密S2C1/S2C9及停机。Original-profile tests cover the explicit legacy behavior described above and use a sentinel callback frame. No real RnClient was started and no account database was modified.
