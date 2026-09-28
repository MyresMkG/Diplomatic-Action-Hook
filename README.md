# diplo_action_hook

让群星脚本能够**真正新增**外交行动（`common/diplomatic_actions/` 里的全新条目）的
DLL 注入实现。

完整的问题分析（为什么脚本加不了、几道口子分别在哪、逐条证据行号）见
`stellaris_4.5_diplomatic_action_新增机制分析.md`。

---

## 1. 它解决的问题

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
| `OurShouldAIPropose` | 合成虚表的 `ShouldAIPropose(int)` 槽（运行时解析，本机是 `+0x60`） | 基类在这个槽上直接 `xor al,al; ret`，所以 AI 永远不会提议任何没有专用子类的行动。把这一槽换成对引擎自己的 `CDiplomaticAction::ScriptedShouldAIPropose` 的调用，AI 的答案就来自脚本里的 `should_ai_propose`——和 55 个原版专用类走的是同一个函数 |
| `HookGetAIAcceptance` | `GetAIAcceptance(action, favors, reasons)`（自由函数，运行时解析） | 引擎的 AI 接受度里，`AI_acceptance_base_value` 只从**按 token 硬编码**的表里读，新 token 不在表里、贡献恒为 0。这个 detour 在返回值上把该行动的 `AI_acceptance_base_value` 加回去（只对本 DLL 注册的 token），新行动于是和原版一样能"基础接受/基础抗拒" |

关键点：**只在原函数本会返回 NULL 的地方补行为**，所以原版行动的路径完全不变；
AI 那一槽也**只作用于本 DLL 造出来的对象**（`g_our_vtable` 是自建的，原版虚表一个字节都没改）；
接受度那个 detour 对原版 token 直接原样返回，不动任何数字。

之所以通用对象就够用，是因为基类 `CDiplomaticAction` 的
`IsPotential` / `IsPossible` / `IsProposable` / `ExecuteAccept` / `ExecuteDecline` /
`ShouldShowAcceptMessage` 等全部是脚本驱动的，而不是纯虚函数；外交视图
`CDiplomacyView::ShowDiplomaticActions` 也是**遍历整个数据库**，不是硬编码列表。

AI 主动提议补上之后，"新行动只能玩家手动发起"这条限制没有了：AI 帝国会像对待原版行动
一样，创建对象 → 检查 `potential` / `possible` / `proposable` → 问 `ShouldAIPropose`
→ 决定要不要发给对方。写脚本时用 `should_ai_propose = { weight = ... }` 控制意愿，
缺省的建议是**一定要写**（不写就走引擎对空 MTTH 的默认行为，见第 6 节）。

`AI_acceptance_base_value` 补上之后，"AI 愿不愿意接受"这件事也完整了：新行动的接受度
= `AI_acceptance_base_value` + 脚本 `ai_acceptance` + 好感额度，判定门槛是**大于 0**
（原版这个键全是 -50 这类"基础抗拒"，新行动不写就是 0）。

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
│   ├── game_hooks.h / .cpp       三个入口 detour + 合成虚表上的 AI 提议槽
│   ├── log.h / log.cpp           日志（DLL 旁边 + OutputDebugString）
│   └── dllmain.cpp               入口：在独立线程里做事，避免 loader lock
└── tools/
    ├── lde_test.cpp              解码器验证工具
    ├── validate_lde.py           用 capstone 校验解码器
    ├── census_lde.py             全量统计 + "能不能偷 5 字节"普查
    ├── anchor_test.cpp           锚点解析验证工具
    ├── resolve_test.cpp          整套地址解析验证工具（可传期望值做断言）
    ├── ai_propose_probe.py       独立脚本：只用字符串锚点+虚表投票定位 AI 提议槽，
    │                             并复核接受度那一链（GetScriptedAcceptance / GetAIAcceptance）
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
- 锚点 3：`".should_ai_propose"` → `CDiplomaticAction::ScriptedShouldAIPropose`
  （只有它拼这个本地化键片段）
- 锚点 4：`".ai_acceptance"` → `GetScriptedAcceptance`（脚本 `ai_acceptance` 字段的求值函数，
  同样只有它拼这个片段）

其余地址靠**调用链与指令形状**推出来（见下），因此同一份二进制在 4.5.0 和 4.5.1 上都能跑。

解析顺序（`resolver.cpp` 的 `ResolveAll`）：

1. 前两个字符串锚点 → 构造函数、`AddDynamicToken`；
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
6. AI 提议那一槽：工厂派发里每个 `lea rax,[rip+..]` 都是它给某个 token 装的**具体虚表**，
   逐槽比对哪些槽指向"会调用 `ScriptedShouldAIPropose` 的函数"，**得票最多的槽**
   就是 `ShouldAIPropose`（两份 exe 上都是 `+0x60`，55 / 69 张虚表投它）；
   再要求基类虚表同一槽是一个 `xor al,al; ret` 这类"直接返回 0"的桩。
   任何一条不成立就**不装这个特性**（其余钩子照常），并写明原因。
7. AI 接受度那一链：锚点 4 给出 `GetScriptedAcceptance`，它的**唯一调用者**就是
   `GetAIAcceptance`（要求候选唯一、函数大小正常、内部 call 数 ≥ 8，也就是一棵
   per-token 比较树）；`AI_acceptance_base_value` 的字段偏移取 4.5.x 版式里核过的那一个，
   并且**由数据库再验一次**（见第 4 节）。同样：不成立就不装。

任何一步失败都只写日志并停止，**绝不在信息不全的情况下装钩子**。

---

## 4. 钩子与合成虚表的实现要点

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

**`OurShouldAIPropose`** —— 合成虚表里那一槽指向 DLL 自己的函数，
函数体只有一句有意义的调用：`ScriptedShouldAIPropose(this)`。
两个细节：

- 返回 `int`（0/1）而不是 `bool`：基类那个桩是 `xor al,al; ret`，高 24 位是垃圾，
  调用方只读 `al`；DLL 这边干脆把整个 `eax` 写清楚，省得给调用方留半个未定义寄存器。
- 引擎那个函数**只吃 `this` 一个参数**（prologue 里 `xor esi,esi` 只是拿 esi 当零用，
  `push rsi` 保过），所以 DLL 完全不碰第二个参数——AI 传进来的那个 `int` 是什么语义
  无关紧要。这一点是在反汇编里逐条核对过的，不是猜的。

日志里只会写头 4 次真实 AI 询问（`AI propose check on token N: ... answers yes/no`）：
这一行出现就说明 AI 真的在问这个行动，而不是只装上了钩子。

**`HookGetAIAcceptance`** —— 引擎给每个候选行动算"对方愿不愿意接受"的那个函数。
原版所有"基础接受/基础抗拒"都写在它内部一张按 token 硬编码的表里（新 token 拿不到），
所以 DLL 的 detour 只做一件事：**在它的返回值上加上本行动的 `AI_acceptance_base_value`**。
两个刻意的选择：

- **加在总返回值上，而不是并进脚本值**：原版结构是
  `接受度 = 硬编码基数 + 脚本 ai_acceptance + 好感额度`，脚本块里的 `factor`/`mult`
  只作用于脚本那一部分；并进脚本值会被脚本的乘法放大，语义就和原版不一样了。
- **加在*最外层*调用上**：`WillFederationAccept` 会用同一个入口给联邦成员打分，
  所以钩子里用 `thread_local` 标记挡住嵌套调用，避免同一个基数被算两次。

字段偏移（本机 `+0x78`，两份 Windows exe 与 dump 一致）不是"信了就上"，而是
**让数据库自己作证**：脚本加载完后 DLL 会扫一遍行动数据库，统计该偏移处的取值分布——
原版 68 个行动里 49 个是 0、其余都是 `-50` 这一个值，与"原版这个键只写 -50/0"完全吻合，
于是才把 `g_acceptance_base_trusted` 置真开始生效；不吻合就只在日志里说明并不生效
（越界值另有 ±10000 的夹取）。探针模组实测：给新行动写 `AI_acceptance_base_value = 77`，
日志里就是 `reads 77`。

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
| 整套地址解析（4.5.1） | `tools/resolve_test.exe`，15 项全部与人工反汇编核对过的 RVA 断言 | **15/15 通过**（含 `ScriptedShouldAIPropose = 0x943890`、`ShouldAIPropose 槽 = +0x60`、`GetScriptedAcceptance = 0xb8cc70`、`GetAIAcceptance = 0xb8c5c0`、`AI_acceptance_base_value = +0x78`、55 张原版虚表投那一槽） |
| 整套地址解析（4.5.0） | 同上，用另一份 exe | **15/15 通过**（RVA 全部不同、通用虚表/构造函数也都不同，对象大小与那些偏移一样是 0x50 / `+0x60` / `+0x78`） |
| **真实游戏 · 注入不崩** | 用注入器启动 `stellaris.exe`（先启动后注入） | 游戏存活，三个钩子 1.4 s 装好 |
| **真实游戏 · 原版行动未受影响** | 数据加载时（t≈52 s）钩子 1 逐条触发 | 68 个原版行动全部沿用原有 token（`action_improve_relation -> 13597`、`action_declare_war -> 11602`），与离线 token 表一致 |
| **真实游戏 · 新行动拿到真实 token** | 启用测试模组后重启 | `registered keyword 'action_hook_greeting' -> token 66908`，不再是哨兵 `0xc` |
| **真实游戏 · 新行动进库** | DLL 回扫数据库 | `scanned 69 action types`（68 原版 + 1 新增），数量吻合 |
| **真实游戏 · 工厂路径可用** | DLL 自检直接调用外交界面所用的工厂入口 | `self-test: OK ... type confirmed` |
| **真实游戏 · 外交界面的调用不再崩** | 自检调用崩过的那两处虚表槽 `+0x48`/`+0x50` | `called the diplomacy view's own check slots (2/2) ... without incident`，游戏存活 |
| **真实游戏 · AI 提议槽已接管**（4.5.1 + 两个新行动） | 自检回读新对象虚表的 `+0x60` | `AI propose gate (+0x60) is the scripted implementation, so an AI empire can propose this action itself`（`action_cntr_destruction` / `action_hook_greeting` 各一条），`error.log` 里 `missing token` 仍为 0 次 |
| AI 提议槽的解析（离线） | `tools/ai_propose_probe.py`（独立脚本，与本 DLL 无关的实现） | 两份 exe 上都得到 `+0x60` + 55 张虚表同意；基类那一槽是 `32 c0 c3`（`xor al,al; ret`） |
| **真实游戏 · AI 接受度钩子装上**（4.5.1） | 看着三个新行动一起跑 | `hook 3 installed ... AI_acceptance_base_value now counts for new actions` |
| **真实游戏 · 接受度字段自证**（4.5.1） | DLL 数据加载后统计该偏移的取值分布 | `AI acceptance base field (+0x78): 49 of 68 stock action types stand at 0, 1 distinct non-zero value(s) in [-50, 0] -> trusted`——原版正是只写 `-50`/`0`，偏移读对了才可能出现这种分布 |
| **真实游戏 · 新行动读到脚本值**（4.5.1） | 临时探针行动写 `AI_acceptance_base_value = 77` | `self-test: AI_acceptance_base_value for token 66923 reads 77 (counted by the acceptance hook)`，同一批另外两个没写该键的新行动读到 0 |
| **真实游戏 · 曾崩过（已修）** | 早期版本用基类抽象虚表 | 打开外交界面即 `Pure Virtual Function Call`（崩溃报告 `crashes/stellaris_20260925_111022/exception.txt`）；改用自建具体虚表后不再出现 |
| **真实游戏 · 症状消失** | 检查 `error.log` | `Diplomatic action is missing token` 出现 **0** 次 |
| **真实游戏 · 挂起注入会崩** | 早期版本用 `CREATE_SUSPENDED` | 游戏立刻退出 `0xC0000005`；已改为先启动后注入，并把 `--suspend` 标为不可用 |
| Unicode 路径 | 在含中文的路径下注入 | 成功（注入器全程用 UTF-16 命令行与 `_wfopen`） |
| 失败安全性 | 把**真正的钩子 DLL** 注入 `ping.exe` | 解析失败 → 写日志 → **一个钩子都没装**，ping 继续正常运行 |
| 独立复核 | 另起一个独立调查，用不同的字符串引用扫描方式重新定位全部地址 | 与我这边**逐项一致**（含通用虚表 `0x23a8b68`、通用构造函数 `0x940680`、工厂 `0x9aa7f0`） |

**没有验证的部分**：

- 没有在外交界面里手动点开按钮确认它列在那里（那需要实际操作游戏 UI）。
  但界面所用的工厂代码已由 DLL 自检在真实游戏里跑通，见上表最后几行。
- **没有在真正跑起来的对局里看到 AI 主动提议**（那需要在游戏里载入存档、让 AI 跑几个回合）。
  已验证到的是"AI 那一槽确实换成了脚本实现"——自检直接回读了新对象虚表里的 `+0x60`；
  真正被 AI 调用时日志会多出 `AI propose check on token N: ... answers yes/no`，
  测试模组 `action_hook_greeting` 被 AI 接受时 `logs/game.log` 里还会有一行
  `diplo_action_hook: exchange pleasantries accepted`。
- **接受度那个勾子同样只在"字段读对了"这一层验证过**：分布自证 + 探针读到 77 都是真机证据，
  但"AI 因此接受了某个新行动的提议"需要一局进行中的游戏（而且要好感到门槛之上）。
  逻辑上它就是把原版那一项加回去，且对原版 token 原样返回。

---
