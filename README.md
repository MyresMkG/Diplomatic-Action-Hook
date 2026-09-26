# diplo_action_hook

让群星脚本能够**真正新增**外交行动（`common/diplomatic_actions/` 里的全新条目）的
DLL 注入实现。

完整的问题分析（为什么脚本加不了、两道硬墙在哪、逐条证据行号）见
`stellaris_4.5_diplomatic_action_新增机制分析.md`。

（注：使用deepseek-v4.1-flash编写，harness为Kimi Code）

---

## 1. 它解决的两个问题

反编译产物（Linux 版 4.5.0 的 Ghidra dump）显示，mod 在
`common/diplomatic_actions/` 里写一个全新名字**不会**被拒绝：加载器
`TSingleObjectGameDatabase<...>::LoadFromReader` 按名字查重，找不到就
`calloc(1, 0x5e0)` 新建一个 `CDiplomaticActionType` 并追加进数据库。真正卡住的是后面两步：

**墙 1 —— token 只能来自编译期关键字表。**
`CDiplomaticActionType` 的构造函数里：

```c
uVar2 = CStaticLexer::FindTok(name);     // 查静态关键字表
this->token = uVar2;                     // 存在 +0x50
```

`CStaticLexer::FindTok` 查不到就返回 `0xc`，而 `0xc` 正是四种内置原始 token 里的
`"num"`。于是新行动带着"这不是关键字"的 token 进库，日志里出现
`Diplomatic action is missing token: <名字>`。

**墙 2 —— 工厂按 token 硬编码。**
`NDiplomacyUtil::CreateDiplomaticAction` 用 `type->token` 调 `CreateEmptyAction(token)`，
后者是一个巨大的比较树，**未知 token 直接返回 NULL**，于是外交界面拿不到对象、按钮不存在。

**本 DLL 的补法：**

| 钩子 | 位置 | 做法 |
| --- | --- | --- |
| `HookTypeCtor` | `CDiplomaticActionType::CDiplomaticActionType(int, CString const&)` | 先对名字调用引擎自带的 `CStaticLexer::AddDynamicToken(name, true)`，再执行原函数。名字因此拿到合法动态 token |
| `HookCreateEmptyAction` | `CreateEmptyAction(int)` | 先调原函数；只有返回 NULL **且**该 token 是本 DLL 注册出来的动态 token时，才用 `operator new` + 基类构造函数造一个通用 `CDiplomaticAction` |

关键点：**只在原函数本会返回 NULL 的地方补行为**，所以原版行动的路径完全不变。

之所以通用对象就够用，是因为基类 `CDiplomaticAction` 的
`IsPotential` / `IsPossible` / `IsProposable` / `ExecuteAccept` / `ExecuteDecline` /
`ShouldShowAcceptMessage` 等全部是脚本驱动的，而不是纯虚函数；外交视图
`CDiplomacyView::ShowDiplomaticActions` 也是**遍历整个数据库**，不是硬编码列表。

---

## 2. 目录结构

```
diplo_action_hook_src/
├── build.bat                     一键编译（MinGW-w64）
├── README.md                     本文件
├── src/
│   ├── lde.h / lde.cpp           极简 x86-64 指令长度解码器（钩子定位用）
│   ├── anchor.h / anchor.cpp     PE 内存布局 + "字符串→引用它的函数" 解析
│   ├── resolver.h / resolver.cpp 把锚点串成完整的一套地址（见第 4 节）
│   ├── hook.h / hook.cpp         x64 入口 detour（近跳转网关 + 蹦床）
│   ├── game_hooks.h / .cpp       两个真正的 detour
│   ├── log.h / log.cpp           日志（DLL 旁边 + OutputDebugString）
│   └── dllmain.cpp               入口：在独立线程里做事，避免 loader lock
└── tools/
    ├── lde_test.cpp              解码器验证工具
    ├── validate_lde.py           用 capstone 校验解码器
    ├── census_lde.py             全量统计 + "能不能偷 5 字节"普查
    ├── anchor_test.cpp           锚点解析验证工具
    ├── resolve_test.cpp          整套地址解析验证工具（可传期望值做断言）
    └── walk_test.cpp             打印某个函数的解码流，排查走偏
```

把 DLL 注入游戏的加载器**不在本目录**，见 `..\stellaris_mod_injector_src\`（源码）
与 `..\stellaris_mod_injector_bin\`（成品，用法见那里的 `使用说明.md`）。

编译：

```
build.bat
```

需要 MinGW-w64 的 `g++` 在 PATH 里，或者设置 `MINGW_BIN`。产物在 `build/`。
没有任何第三方依赖（不链接 capstone，不依赖 MinGW 运行库，全部静态链接）。

---

## 3. 为什么地址在运行时解析

反编译产物是 **Linux ELF 版 4.5.0**，要注入的是 **Windows PE 版 4.5.1**，两者代码布局、
地址、甚至对象偏移都不同（例如判断"这个行动类型可用"的标志字节：dump 里是
`type+0x5d8`，Windows 版是 `type+0x620`）。所以 dump 里的地址一个都不能用，
所有地址都在运行时从**字符串锚点**重新解析：

- 锚点 1：`"Diplomatic action is missing token: "` → 行动类型构造函数
- 锚点 2：`"Creation of dynamic token"` → `CStaticLexer::AddDynamicToken`

其余地址靠**调用链与指令形状**推出来（见下），因此同一份二进制在 4.5.0 和 4.5.1 上都能跑。

解析顺序（`resolver.cpp` 的 `ResolveAll`）：

1. 两个字符串锚点 → 构造函数、`AddDynamicToken`；
2. `AddDynamicToken` 里的**第一个 call** 就是词法器单例的访问函数
   （`GetStaticLexer`）。再用"构造函数里也必须出现同一个 call"做**互证**，
   两边不一致就整体放弃；
3. 用三张 UI 字符串（`diplo_actions_window` / `favors_container` / `actions_list`）
   的交集定位外交视图函数；视图里调用的、体型很小、且含
   `mov ecx, [rcx+0x50]`（读 token）与 `mov r9, [rax]`（读虚表）的函数，
   就是 `NDiplomacyUtil::CreateDiplomaticAction`；该函数里紧随 token 读取的那个 call
   就是 `CreateEmptyAction`；
4. 在 `CreateEmptyAction` 里统计 `mov edx, <token>; mov rcx, rax; call X` 的 X，
   **得票最多**的那个就是通用 `CDiplomaticAction(int)` 构造函数（本机 4.5.1 上有 64 票）；
   同一条里 `mov ecx, <对象大小>; call Y` 给出 `operator new`；
5. 构造函数里 `lea rax,[rip+..]; mov [rcx],rax` 给出通用虚表；
   同时扫描构造函数对自身的字段写入，算出对象**至少要多少字节**（本机 4.5.1 = 0x50，
   与原版对无成员子类的分配大小一致）。

任何一步失败都只写日志并停止，**绝不在信息不全的情况下装钩子**。

---

## 4. 两个钩子的实现要点

**`HookTypeCtor`** —— 拿到的是 `CString const&`。DLL **不解释**它的内存布局，
而是把同一个指针原样转交给引擎自己的 `AddDynamicToken`，因此不受
libstdc++ / MSVC `std::string` 布局差异影响。只有在写日志时才按 MSVC 布局
（`{vtable; data@+0x10; size@+0x20; capacity@+0x28}`）读名字。

是否"新 token"用词法器的计数器判定：`token > 静态关键字数`（读
`[lexer+0x84]` 与 `[lexer+0x64]`，两个偏移都在 `AddDynamicToken` 的反汇编里核对过），
并且对结果做合理性检查，不合理就宁可当成"不是新 token"。

**`HookCreateEmptyAction`** —— 先调原函数；只有返回 NULL 且 token 属于本 DLL
注册集合时才构造。构造后还会回读对象里的类型指针，确认它的 token 真的等于
请求的 token，不是空对象类型；不对就记一条 warning。分配大小取
"构造函数自身字段写入所需字节数"（扫描会跟踪 rcx 被复制到的寄存器，
本机 4.5.1 = 0x50），下限 0x50，上限是派发里见到的最大类大小。

`HookTypeCtor` 不依赖虚表形状，所以**即使基类虚表的形状与预期不符也会照常装上**：
那种情况下新行动仍能拿到合法 token，只是不会再被合成对象、进不了外交界面。
只要合成对象那一步没有装上（形状不符或工厂钩子安装失败），日志末行会是
`partial -- ...` 而不是 `ready -- ...`。

**`hook.cpp`** 的 detour 引擎：入口写 5 字节 `jmp rel32` 跳到目标附近
`VirtualAlloc` 出来的网关，网关再做绝对跳转（因为注入的 DLL 可能离游戏主模块
超过 ±2GB）；蹦床保存被覆盖的整条指令并修正 rip 相对/rel32/rel8 位移。
**只有当完整指令能刚好铺满 ≥5 字节、且每条都能安全重定位时才动手**，
否则返回失败。

---

## 5. 验证情况

已经做过的验证（都能重跑）：

| 对象 | 方法 | 结果 |
| --- | --- | --- |
| 指令长度解码器 | `py tools/validate_lde.py` / `census_lde.py`，与 capstone 逐条比对**全部 134762 个 `.pdata` 函数入口**的前 4 条指令边界 | 134756 条完全一致（99.9955%）；唯一不符的是 VEX 指令，解码器**故意拒绝**而不是猜 |
| 能否偷 5 字节 | 同一次普查 | 134425 / 134762（99.75%）的函数序言可以干净地铺满 5 字节；不能的会安全放弃 |
| 整套地址解析（4.5.1） | `tools/resolve_test.exe`，10 项全部与人工反汇编核对过的 RVA 断言 | **10/10 通过** |
| 整套地址解析（4.5.0） | 同上，用另一份 exe | 通过（RVA 全部不同，对象大小同样是 0x50） |
| **真实游戏 · 注入不崩** | 用注入器启动 `stellaris.exe`（先启动后注入） | 游戏存活，钩子 1.0 s 装好 |
| **真实游戏 · 原版行动未受影响** | 数据加载时（t≈52 s）钩子 1 逐条触发 | 68 个原版行动全部沿用原有 token（`action_improve_relation -> 13597`、`action_declare_war -> 11602`），与离线 token 表一致 |
| **真实游戏 · 新行动拿到真实 token** | 启用测试模组后重启 | `registered keyword 'action_hook_greeting' -> token 66908`，不再是哨兵 `0xc` |
| **真实游戏 · 新行动进库** | DLL 回扫数据库 | `scanned 69 action types`（68 原版 + 1 新增），数量吻合 |
| **真实游戏 · 工厂路径可用** | DLL 自检直接调用外交界面所用的工厂入口 | `self-test: OK ... type confirmed` |
| **真实游戏 · 外交界面的调用不再崩** | 自检调用崩过的那两处虚表槽 `+0x48`/`+0x50` | `called the diplomacy view's own check slots (2/2) ... without incident`，游戏存活 |
| **真实游戏 · 曾崩过（已修）** | 早期版本用基类抽象虚表 | 打开外交界面即 `Pure Virtual Function Call`（崩溃报告 `crashes/stellaris_20260925_111022/exception.txt`）；改用自建具体虚表后不再出现 |
| **真实游戏 · 症状消失** | 检查 `error.log` | `Diplomatic action is missing token` 出现 **0** 次 |
| **真实游戏 · 挂起注入会崩** | 早期版本用 `CREATE_SUSPENDED` | 游戏立刻退出 `0xC0000005`；已改为先启动后注入，并把 `--suspend` 标为不可用 |
| Unicode 路径 | 在含中文的路径下注入 | 成功（注入器全程用 UTF-16 命令行与 `_wfopen`） |
| 失败安全性 | 把**真正的钩子 DLL** 注入 `notepad.exe` | 解析失败 → 写日志 → **一个钩子都没装**，notepad 继续正常运行 |
| 独立复核 | 另起一个独立调查，用不同的字符串引用扫描方式重新定位全部地址 | 与我这边**逐项一致**（含通用虚表 `0x23a8b68`、通用构造函数 `0x940680`、工厂 `0x9aa7f0`） |

**没有验证的部分**：没有在外交界面里手动点开按钮确认它列在那里（那需要实际操作游戏 UI）。
但界面所用的工厂代码已由 DLL 自检在真实游戏里跑通，见上表最后几行。

---
