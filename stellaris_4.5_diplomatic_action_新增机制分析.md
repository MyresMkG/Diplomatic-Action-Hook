# Stellaris 4.5：脚本为什么无法真正新增 diplomatic_action

阅读对象是群星主程序的反编译产物 `D:\学习\stellaris_4.5_source.cpp`。

- 反编译源码：`D:\学习\stellaris_4.5_source.cpp`（Ghidra，139552 个函数，8698910 行）
- **该 dump 来自 Linux ELF 版 4.5.0**（`Platform: Linux x86/64 ELF64`；含 `glxewInit`、`XCB`、`pthread_mutex_lock`、`__cxa_throw`，无 `CreateFileW`/`D3D11CreateDevice`）。Ghidra 泄漏的 RAM 地址形如 `ram,0x01a7a1a3`，非 `0x14xxxxxxx`，所以地址是 Linux 版的，**不能直接当成 Windows PE 的 RVA 用**。本文所有行号都指该 dump 的行号，所有偏移都指 Linux 版代码里的对象偏移；Windows 版偏移需要单独确认（见第 7 节）。
- 游戏脚本目录：`D:\SteamLibrary\steamapps\common\Stellaris`
- 本文档对应的游戏版本：反编译产物 = `Cygnus v4.5.0 (8697)`；当前已安装 = `Cygnus v4.5.1`

反编译代码里几乎没有真实成员名，大量使用结构体偏移。下面所有字段含义都是从构造点、序列化 token 与调用点反推的，凡推断而非直接确认的地方都会单独标注。

---

## 0. 结论速览

| 问题 | 结论 |
| --- | --- |
| 在 `common/diplomatic_actions/` 里新写一个 `action_xxx = { ... }` 会怎样？ | **会被解析，也会被真的创建成 `CDiplomaticActionType` 并追加进数据库**，但它的 token 会等于 `0xc`（"不是关键字"的哨兵值） |
| 第一道墙 | token 不是从名字算出来的，而是 `CStaticLexer::FindTok(name)` 在**编译期生成的静态关键字表**里查出来的；查不到一律返回 `0xc`。mod 无法往这张表里加东西 |
| 第二道墙 | 外交行动的身份就是 token。运行时工厂 `CreateEmptyAction(token)` 是一个**巨型硬编码 switch**，未知 token 直接 `return 0`，于是视图拿不到行动对象，按钮永远不出现 |
| 为什么 token 是身份 | `CDiplomaticActionTypeDatabase::GetByToken` 比较对象 `+0x50`；`CDiplomaticAction` 构造时用 token 反查 type；排序/比较/存档/消息全走 token |
| 好消息一 | 引擎自带**运行时关键字注册 API** `CStaticLexer::AddDynamicToken`，游戏自己就调了 567 处 |
| 好消息二 | 外交视图 `ShowDiplomaticActions` 是**遍历整个数据库**，不是硬编码列表 |
| 好消息三 | 基类 `CDiplomaticAction` 的 `potential` / `possible` / `proposable` / `on_propose` / `on_accept` / `on_decline` **全部是脚本驱动的**，不是纯虚函数 |
| 所以 | 用 DLL 注入把上面三道口子补上，就能让脚本新增的 `action_xxx` 真正生效、真正出现在外交界面并被发送 |
| 做不到 | 新行动拿不到原版那些**专用子类**的行为（贸易、宣战、和平、联邦投票等有专门的 C++ 类）；AI 默认不会主动提议（可通过替换虚表槽解决，见 7.3） |

---

## 1. 三个类，以及"身份 = token"

### 1.1 类的关系

| 类 | 大小 | 角色 |
| --- | --- | --- |
| `CDiplomaticActionType` | `0x5e0` | 脚本定义（`common/diplomatic_actions/` 里的一个块），全局唯一，进程内常驻 |
| `CDiplomaticAction` | `0x50` | 一次具体提议的运行时实例（actor + recipient + 状态） |
| `CDiplomaticActionTypeDatabase` | — | `TSingleObjectGameDatabase<CDiplomaticActionTypeDatabase, CDiplomaticActionType, false>`，持有 `CPdxArray<CDiplomaticActionType const*>` |

数据库构造（2339876-2339934）把目录名写死成 `common/diplomatic_actions`：

```c
// CDiplomaticActionTypeDatabase::CDiplomaticActionTypeDatabase()   2339876
::CString::CString(local_40,"common/diplomatic_actions");
```

元素访问在两个偏移上：`this + 0x5c` 是元素个数，`this + 0x50` 是 `CPdxArray` 的数据指针（步长 8 字节）。

### 1.2 token 存在 `CDiplomaticActionType + 0x50`

`CDiplomaticActionType::CDiplomaticActionType(int, CString const&)`（2337826-2337973）末尾：

```c
// 2337903-2337904
uVar2 = CStaticLexer::FindTok(*(char **)(param_2 + 0x10));   // param_2 = 名字 CString
*(undefined4 *)(this + 0x50) = uVar2;                        // ← 身份在这里定下来
```

`param_2 + 0x10` 是 libstdc++ 版 `std::string` 的字符指针（`CString` 派生自 `basic_string<char, char_traits<char>, CPdxCommonStringAllocator>`）。**这一点在 Windows 版上偏移不同**，见第 7 节说明。

### 1.3 token 被用作身份的三处硬证据

```c
// CDiplomaticActionTypeDatabase::GetByToken(int)   2339946-2339970
if (0 < (int)*(uint *)(this + 0x5c)) {
    uVar2 = 0;
    do {
      lVar1 = *(long *)(*(long *)(this + 0x50) + uVar2 * 8);
      if (*(int *)(lVar1 + 0x50) == param_1) {      // 线性扫描比 token
        return lVar1;
      }
      uVar2 = uVar2 + 1;
    } while (*(uint *)(this + 0x5c) != uVar2);
}
return TPdxNullObject<CDiplomaticActionType>::_pInstance;
```

```c
// CDiplomaticAction::CDiplomaticAction(int)   2331838-2331865（节选）
this->_type = CDiplomaticActionTypeDatabase::GetByToken(
                  TGameDatabase<CDiplomaticActionTypeDatabase>::_pInstance, param_1);  // 2331860
...
// 比较两个行动是否同一个，也只比 token
// CDiplomaticAction::Compare  2331891-2331900
return ...(*(int *)(*(long *)(this + 0x40) + 0x50) == *(int *)(*(long *)(param_1 + 0x40) + 0x50));
```

也就是说：**token 是外交行动的唯一身份**。type 是脚本定义，action 是实例，两者靠 token 关联。

---

## 2. 第一道墙：token 只能来自编译期关键字表

### 2.1 FindTok 对未知名返回 0xc

```c
// CStaticLexer::FindTok(char const*)   8099500-8099513
undefined4 CStaticLexer::FindTok(char *param_1)
{
  undefined4 *puVar1;
  GetStaticLexer();
  puVar1 = (undefined4 *)
           (**(code **)(AccessStaticLexer()::StaticLexerInstance + 0x10))
                     (&AccessStaticLexer()::StaticLexerInstance,param_1);   // 查 token 树
  if (puVar1 != (undefined4 *)0x0) {
    return *puVar1;                                                     // 命中：返回 token id
  }
  return 0xc;                                                           // 未命中：返回 12
}
```

`0xc = 12` 不是普通关键字，它是四种内置原始 token 里的第一个：

```c
// CStaticLexer::GetPrimitiveString(int, bool)   8099706-8099737
switch(param_1) {
case 0xc:  pcVar3 = "num";    break;
case 0xd:  pcVar3 = "float";  break;
case 0xe:  pcVar3 = "bool";   break;
case 0xf:  pcVar3 = "string"; break;
```

**所以"名字不在关键字表里"和"这个位置写了个数字字面量"在 token 层面是同一件事。** 这是整件事的根。

### 2.2 构造函数会为此报警

```c
// CDiplomaticActionType::CDiplomaticActionType   2337951-2337971（节选）
if ((*(long *)(param_2 + 0x18) != 0) && (*(int *)(this + 0x50) == 0xc)) {
    // param_2+0x18 是字符串长度（非空），this+0x50 是刚算出的 token
    CLogger::Log(...);
    CLogStream::operator<<[abi:cxx11](local_1c0,"Diplomatic action is missing token: ");
    ... << param_2 << endl;
}
```

日志原文：`Diplomatic action is missing token: <名字>`。这就是"新行动加不进去"时用户在 `error.log` 里能看到的那条线索。

### 2.3 关键字表为什么加不了

关键字表是 `CStaticLexer` 的静态数组：

```c
// GetTokenType(int)   155983-155988
return &GetTokenArray()::s_pTokenArray + (long)param_1 * 0x48;   // 步长 0x48，entry+0 = id
```
```c
// FindTokenType(int)   155999-156020（线性扫描版本）
lVar2 = 0x270a;                                    // 静态项数上限
piVar1 = &GetTokenArray()::s_pTokenArray;
while( true ) {
    if (*piVar1 == param_1) return piVar1;
    ...
}
```

`0x270a = 9994` 个静态项，是构建时由引擎的关键字清单生成的，落在只读数据段。**脚本层没有任何语法可以往里加一个关键字**——mod 能改数据文件，改不了这个表。

### 2.4 但"新行动块"本身不会被拒绝

这是最容易被误解的一点。数据库加载器 `TSingleObjectGameDatabase<CDiplomaticActionTypeDatabase, CDiplomaticActionType, false>::LoadFromReader`（2340790-2340985）的逻辑是：

```c
// 取当前顶层键的名字
lVar7 = CLexer::Tok(*(CLexer **)(param_1 + 0x30));
::CString::CString((CString *)&local_150,*(char **)(lVar7 + 0x10));   // 2340852-2340853
// 在已有条目里按名字线性查重（比较 entry+0x20 指针 / entry+0x28 长度）
uVar1 = *(uint *)(this + 0x5c);
if (0 < (int)uVar1) {
   ... bcmp(*(void **)(lVar2 + 0x20), puVar4, uVar9) ...              // 2340867
   if (iVar5 == 0) {                                                 // 命中同名
       (**(code **)(*(long *)this + 0x28))(this,param_1,&local_150,lVar2,0);  // ReadExistingEntry
       goto LAB_025c5d33;
   }
}
// 没找到 → 无条件新建
pCVar8 = calloc(1,0x5e0);                                            // 2340883
CDiplomaticActionType::CDiplomaticActionType(pCVar8,uVar1,(CString *)&local_150);  // 2340885
...
CPdxArray<CDiplomaticActionType_const*,int>::InsertAtEmplace<...>(...); // 2340890-2340893
```

**结论：新名字会被建对象、会被追加进数组，不会被拒绝。** 它只是带着 token=0xc 进去的。

`PostReadInit`（2338293-2338430）之后也只做两件事：拼 `diplomatic_action.<名字>.*` 各种本地化键去 `CheckLocalizationKey`（缺了只报警告），以及 `CMeanTimeToHave::ValidateDescriptor`。**没有 token 合法性检查。**

---

## 3. 第二道墙：工厂按 token 硬编码

有了 type 还不够，界面上要出现按钮就必须造出一个运行时实例。这条路是：

```c
// NDiplomacyUtil::CreateDiplomaticAction(CDiplomaticActionType const*, CCountry const*, CCountry const*)
// 2330498-2330510
long * NDiplomacyUtil::CreateDiplomaticAction(CDiplomaticActionType *param_1,CCountry *param_2,CCountry *param_3)
{
  long *plVar1;
  if ((((byte)param_1[0x5d8] & 1) != 0) &&
     (plVar1 = (long *)CreateEmptyAction(*(int *)(param_1 + 0x50)), plVar1 != (long *)0x0)) {  // ← 按 token 造
    (**(code **)(*plVar1 + 0x40))(plVar1,param_2,param_3);      // 设 actor/recipient
    return plVar1;
  }
  return (long *)0x0;
}
```

而 `CreateEmptyAction(int token)`（2628904-2629501）是一个约 600 行的 switch：

```c
// 2628965-2628967
pCVar1 = TPdxNullObject<CCountry>::_pInstance;
this_49 = (CDemandSubjugationAction *)0x0;          // ← 默认置空
if (0x3bd4 < param_1) {
  ...
  if (param_1 != 0x3cab) {
      return (CDemandSubjugationAction *)0x0;       // 2628978 ← 未知 token 直接返回 NULL
  }
  this_05 = operator_new(0x50);
  CFormCommercialPactAction::CFormCommercialPactAction(this_05,pCVar1,pCVar1);
  return (CDemandSubjugationAction *)this_05;
```

被识别的 token 会 `operator_new(0x50)` 出各自的**专用子类**（`CDeclareWarAction`、`COfferPeaceAction`、`CFormCommercialPactAction`、`CVoteForFederationLawAction`……），最后：

```c
// 2629476-2629498
default:
  switch(param_1) {
  case 0x3584: goto switchD_02741fea_caseD_2e88;
  case 0x3585: ... CReleaseSubjectAction ... 
  case 0x359d: ... CIntegrateSubjectAction ...
  case 0x35a2: ... CCancelSubjectIntegrationAction ...
  }
}
...
return this_49;
```

**未知 token 一定得到 NULL**，于是 `CreateDiplomaticAction` 返回 0，按钮不出现。

顺带记一下两个特例，它们对 DLL 方案有用：**token `0x3e5c` 和 `0x3e5d` 造的是"裸"`CDiplomaticAction`**（不是子类），只是换了虚表：

```c
// 2628997-2629004（0x3e5c = action_build_spy_network）
pCVar2 = operator_new(0x50);
CDiplomaticAction::CDiplomaticAction(pCVar2,0x3e5c);
*(undefined ***)pCVar2 = &PTR__CDiplomaticAction_053512a0;   // 只改虚表指针
return (CDemandSubjugationAction *)pCVar2;

// 2629006-2629011（0x3e5d = action_manage_spy_network）
pCVar2 = operator_new(0x50);
CDiplomaticAction::CDiplomaticAction(pCVar2,0x3e5d);
*(undefined ***)pCVar2 = &PTR__CDiplomaticAction_05351460;
```

**说明基类 `CDiplomaticAction` 本身是可以直接实例化并正常工作的**，这正是 DLL 方案能成立的基础。

---

## 4. 哪些地方**不是**墙（DLL 方案的关键前提）

### 4.1 外交视图是遍历数据库的，不是硬编码列表

`CDiplomacyView::ShowDiplomaticActions`（3922161-3922376）核心循环：

```c
// 3922229-3922294
uVar1 = *(uint *)(TGameDatabase<CDiplomaticActionTypeDatabase>::_pInstance + 0x5c);   // 条目数
if (0 < (int)uVar1) {
  uVar16 = 0;
  uVar11 = (ulong)uVar1;
  do {
    puVar12 = (undefined8 *)(uVar16 * 8 +
              *(long *)(TGameDatabase<CDiplomaticActionTypeDatabase>::_pInstance + 0x50));  // 取第 i 个 type
    pCVar2 = (CDiplomaticActionType *)*puVar12;
    pCVar9 = (CCountry *)CGameState::GetLocalObserved(g_CurrentGameState);      // actor
    pCVar13 = <this+0x5c8 指向的国家>;                                          // recipient
    plVar10 = (long *)NDiplomacyUtil::CreateDiplomaticAction(pCVar2,pCVar9,pCVar13);
    if (plVar10 != (long *)0x0) {
      cVar5 = (**(code **)(*plVar10 + 0x50))(plVar10);       // 虚表 +0x50
      if (cVar5 == '\0') {
        (**(code **)(*plVar10 + 8))(plVar10);                // 不通过 → 删掉
      } else {
        cVar5 = (**(code **)(*plVar10 + 0x58))(plVar10,0);   // 虚表 +0x58
        ... 按 cVar5 排序插入 {bool, action} 数组 ...
      }
    }
    uVar16 = uVar16 + 1;
  } while (uVar16 != uVar1);
}
```

**只要数据库里有这个 type，并且工厂能造出对象，界面就会出现它。** 没有白名单，没有枚举表。

### 4.2 基类 `CDiplomaticAction` 完全由脚本驱动

```c
// CDiplomaticAction::IsPotential(CString*) const   2333910-2333979（结尾）
LAB_025bccfb:
  bVar2 = CDiplomaticActionType::IsPotential(*(CDiplomaticActionType **)(this + 0x40),this_00,this_01,param_1);
  return bVar2 & bVar5;
```

`CDiplomaticActionType::IsPotential(CCountry const*, CCountry const*, CString*)`（2338840-2338901）→ 求值脚本里的 `potential` 触发器。`CDiplomaticAction::IsPossible`（2333987-2334005）同样转发到 type。此外 `IsProposable` / `ExecuteAccept` / `ExecuteDecline` / `ExecuteProposed` / `CanDecline` / `ShouldShowAcceptMessage` 等**全部在基类里有实现**（见 2333904-2335987 一整段）。

`CDiplomaticAction::IsSelectable()` 只是转发到虚表 +0x60：

```c
// 2333278-2333285
(**(code **)(*(long *)this + 0x60))(this,1,0);
```

### 4.3 脚本定义里的设置名都是静态关键字

`CDiplomaticActionType::ReadMember`（2337976-2338273）读取的设置项（`is_listed`、`prerequisites`、`potential`、`possible`、`proposable`、`on_propose`、`on_accept`、`on_decline`、`action_type`、`ai_acceptance`、`should_ai_propose`、`require_envoy`……）全部是**已有的静态关键字**，mod 只需要用现成的名字，不需要新关键字。所以"新设置名"不是问题。

（字段清单与 token 对照见 `analysis/diplo_action_fields.csv`，共 35 项。）

### 4.4 本地化键的规律

`CDiplomaticActionType::IsPotential` 里拼的是 `"diplomatic_action." + name + ".potential"`（2338775-2338794），`ScriptedShouldAIPropose` 拼 `".should_ai_propose"`（2334858-2334875），`PostReadInit` 拼一整套（2338355-2338418）。这些都是纯字符串拼接，mod 自己写本地化即可。

---

## 5. 引擎自带的运行时关键字注册：`AddDynamicToken`

这是整个方案的钥匙。`CStaticLexer` 不仅有静态表，还有一套**动态 token**机制，游戏自己有 567 处调用。

```c
// CStaticLexer::AddDynamicToken(CString const&, bool)   8099846-8099973（整理后）
int CStaticLexer::AddDynamicToken(CString *param_1,bool param_2)
{
  // 1) 懒初始化静态词法器
  if (... guard 未设置 ...) { CStaticLexer(&StaticLexerInstance); ... }

  // 2) 名字不能以数字或 '-' 开头，否则打日志并返回 0
  pcVar7 = (char *)::CString::operator[](param_1,0);
  if ((*pcVar7 == '-') || ((int)*pcVar7 - 0x30U < 10)) {
      ... "Creation of dynamic token \"" ... "\" failed, keywords may not start with a digit or '-'." ...
      iVar6 = 0;
  }
  else {
      // 3) 先在 token 树里找：已存在就返回旧 token（幂等）
      pcVar7 = (char *)::CString::GetTCharPtr(param_1);
      if (DAT_06271b80 != (undefined8 *)0x0) {
        ... walk tree; if ((int *)*puVar10 != (int *)0x0) return *(int *)*puVar10; ...
      }
LAB_043d87a2:
      // 4) 分配新 token：id = 已有动态数 + 静态数 + 1
      iVar3 = DAT_06271bfc;                       // 静态 token 数量
      iVar2 = DAT_06271bdc;                       // 动态 token 数量
      iVar6 = DAT_06271bdc + DAT_06271bfc + 1;    // ← 新 token id
      this = operator_new(0x120);
      CToken::CToken(this,iVar6,param_1);
      local_1e8 = this;
      ::CString::CString((CString *)&local_1b8,*(char **)(this + 0x10));
      piVar9 = operator_new(4);
      *piVar9 = iVar6;
      CTernary<int*,STernaryTrait<int*>>::Add(
                (CTernary<int*,STernaryTrait<int*>> *)&AccessStaticLexer()::StaticLexerInstance,
                (CString *)&local_1b8,piVar9);                 // ← 名字 → id 写入 token 树
      ...
      CPdxArray<CToken*,int>::InsertAtEmplace<CToken*const&>(
                (CPdxArray<CToken*,int> *)&DAT_06271bc8,DAT_06271bdc,&local_1e8);
      DAT_06271bf8 = iVar2 + iVar3 + 2;                        // ← 总 token 数 +1
  }
  return iVar6;
}
```

配套的两个判定：

```c
// CStaticLexer::IsDynamic(int)   8099779-8099783
GetStaticLexer();
return param_1 < DAT_06271bf8 && DAT_06271bfc < param_1;      // 严格落在动态区间内
```
```c
// CStaticLexer::GetPrimitiveString   8099731-8099737
if (((param_2) && (GetStaticLexer(), DAT_06271bfc < param_1)) && (param_1 < DAT_06271bf8)) {
    pCVar1 = (CString *)GetString(param_1);
    ::CString::CString((CString *)this,"dynamic: ");     // 动态 token 打印时加前缀
    ::CString::operator+=((CString *)this,pCVar1);
    return this;
}
```

`RebuildLookup`（8099522-8099653）会把 `CString` 数组 `SetSizeAndEmplace` 到 `DAT_06271bf8` 那么大（8099572），并逐个写入静态 token 名和动态 token 名（8099589-8099603），所以**新增 token 后 token→字符串 的方向也是自洽的**。

**要点**：`AddDynamicToken` 是幂等的、可随时调用的，且会同时维护 `名字→token` 与 `token→名字` 两个方向。这就是不需要改 exe 文件、纯运行时就能让新关键字合法的原因。

---

## 6. 于是：两道墙都能在运行时补上

把第 2 节和第 3 节的两道墙对上第 5 节的钥匙，方案就很直接了：

1. **补第一道墙**：在 `CDiplomaticActionType` 的构造函数里，先对名字调用一次 `AddDynamicToken(name, true)`，再执行原函数。这样 `FindTok` 就能查到这个关键字，`type+0x50` 拿到一个**合法的动态 token**，不再触发 `Diplomatic action is missing token`。
2. **补第二道墙**：拦截 `CreateEmptyAction(token)`；当 token 落在动态区间时，自己 `operator_new(0x50)` 一个基类 `CDiplomaticAction`，调用游戏的 `CDiplomaticAction::CDiplomaticAction(obj, token)`，再写入一个可用的虚表指针。

第 4 节已经证明这两步之外的部分（界面列出、potential/possible/proposable 判定、接受/拒绝、on_* 效果、本地化键）**全部由脚本和既有代码自动完成**，不需要再打补丁。

第 7 节的 DLL 就是这个方案的实现。

---

## 7. DLL 注入方案的边界与风险

### 7.1 版本与偏移

- 反编译产物是 **Linux 版 4.5.0**；要注入的是 **Windows 版 4.5.1**（`D:\SteamLibrary\steamapps\common\Stellaris\stellaris.exe`，`Cygnus v4.5.1`，image base `0x140000000`）。**dump 里的地址一律不能用**，Windows 侧必须重新定位函数（用字符串引用锚点，见下）。
- `CString` 的布局也不同：dump 里读字符指针用 `+0x10`，那是 libstdc++ 的 `std::string`（ptr/size/buf）；MSVC 的 `std::string` 是 buf/size/capacity，所以字符指针在 `+0x00`、长度在 `+0x10`。**DLL 里绝不能照抄 `+0x10`。**
  - 规避办法：把拿到的 `CString const*` **原样转交给游戏自己的 `AddDynamicToken`**，不自己解释它的布局。只在需要打日志时才读取名字，并且读取方式要按 Windows 布局处理。
- 对象偏移（`type+0x50` = token、`type+0x5d8` = 标志位、DB `+0x50`/`+0x5c`）在同一个引擎版本的不同平台构建里**大概率一致**（都是同源的类布局，只有 STL 类型会变），但必须在 Windows 二进制上逐一核对后才能依赖。

### 7.2 定位方式：字符串锚点，而不是硬编码 RVA

`AddDynamicToken` 有两句独一无二的日志字符串：

```
Creation of dynamic token "
" failed, keywords may not start with a digit or '-'."
```

`CDiplomaticActionType` 的构造函数有：

```
Diplomatic action is missing token: 
```

在 `.rdata` 里找到这些字符串，再回扫 `.text` 里引用它们的 `lea rXX,[rip+disp]`，就能定位到函数——**这套定位在运行时做，所以对 4.5.0 / 4.5.1 都成立**，比写死 RVA 稳。

### 7.3 已知做不到 / 需要额外处理的部分

| 限制 | 说明 | 能否绕过 |
| --- | --- | --- |
| 新行动没有专用 C++ 子类 | `CreateEmptyAction` 里贸易、宣战、和平、联邦投票等各自有专门的类，行为不只在脚本里 | 不能。新行动只能用基类行为（脚本驱动的那套） |
| AI 默认不会主动提议 | 基类 `CDiplomaticAction::ShouldAIPropose(int)` 直接 `return 0`（2337135-2337141）；专用子类才覆写它去调 `ScriptedShouldAIPropose`（2334821） | **已由 `diplo_action_hook` 实现**：自建虚表，把 `ShouldAIPropose` 那一槽（Windows 4.5.x 上是 `+0x60`）换成自己的函数，内部调用游戏的 `ScriptedShouldAIPropose`（对应脚本里的 `should_ai_propose`）。槽偏移不写死：工厂派发里的 69 张原版虚表有 55 张在该槽调用同一个函数，基类那一槽则是 `xor al,al; ret` 的桩，两者一致才装 |
| 动态 token 的 id 是运行时分配的 | `id = 动态数 + 静态数 + 1`，取决于**注册顺序**。存档里写的是 token id | 需要保证注册顺序稳定（例如固定时点、按名字排序注册），否则读旧档会错位 |
| 多人游戏 | 动态 token 会改变词的数值，可能与对端/校验和不一致 | 未验证；单机无此问题 |
| 纯 UI 细节 | 图标 / 音效 / 本地化需要 mod 自己提供；`icon`、`sound` 是脚本里指定的 | mod 侧解决 |

---

## 8. Windows 版实机核对结果

上面全部结论都来自 Linux 版 dump。为了确认它们同样成立在**要注入的 Windows 版**上，
我用"字符串锚点 → 反查引用它的函数"的方式在 Windows PE 里重新定位了每一个关键函数，
并逐条反汇编核对语义。

### 8.1 定位方法

不需要反汇编整个 `.text`：一条 rip 相对引用满足 `target = 下一条指令地址 + disp32`，
所以扫描全段 4 字节窗口、令 `下一条指令地址 = target - disp32`，再回头检查那几字节
是不是合法的 rip 相对编码，就能**不解码整段**地找出全部引用点。配合已验证的
指令长度解码器（与 capstone 在 134762 个函数入口上比对，一致率 99.9955%），
再按 `.pdata` 表把引用点归到函数上，每个锚点都得到**唯一**候选。

### 8.2 核对结果（4.5.1 / 4.5.0）

| 目标 | 4.5.1 RVA | 4.5.0 RVA | 与 dump 语义是否一致 |
| --- | --- | --- | --- |
| `CDiplomaticActionType::CDiplomaticActionType(int, CString const&)` | `0x004b3f20` | `0x004b3f00` | ✅ 一致：`r8+0x10` 取名、`FindTok` 经词法器虚表 `+0x10`、`mov [rdi+0x50], ecx`、查不到时 `mov ecx, 0xc` |
| `CStaticLexer::AddDynamicToken(CString const&, bool)` | `0x01bb5bb0` | `0x01bb5090` | ✅ 一致：名字在 `rcx+0x10`、容量在 `+0x18`、名字首字符是 `'-'` 或数字则拒绝、`new_id = 动态数[+0x64] + 静态数[+0x84] + 1`、写入 token 树后追加数组并更新总数 |
| `CDiplomacyView::ShowDiplomaticActions` | `0x01173f90` | `0x01173270` | ✅ 一致：遍历数据库 `[+0x50]`/`[+0x5c]` 逐个造对象 |
| `NDiplomacyUtil::CreateDiplomaticAction` | `0x00ab7400` | `0x00ab6fd0` | ✅ 一致，但**偏移不同**：标志字节是 `type+0x620`（dump 是 `0x5d8`）、虚表槽是 `+0x38`（dump 是 `+0x40`） |
| `CreateEmptyAction(int)` | `0x009aa7f0` | `0x009aa4f0` | ✅ 一致：token 在 `+0x50`、未知 token 走 `xor eax,eax` 返回 NULL；实现是**多级比较树**而非跳表 |
| `CDiplomaticAction::CDiplomaticAction(int)` | `0x00940680` | `0x00940360` | ✅ 一致：内联了 `GetByToken`（`[db+0x5c]` 个数 / `[db+0x50]` 数组 / 比较 `entry+0x50`），类型存到 `+0x40` |
| 通用 `CDiplomaticAction` 虚表 | `0x023a8b68` | `0x023a7b08` | ✅ 由上面的构造函数在 `[rcx]` 写入，即"裸"基类虚表 |
| `operator new` | `0x020213e8` | `0x020208c8` | ✅ `CreateEmptyAction` 里 `mov ecx, <类大小>; call` 的目标 |
| 词法器单例访问函数 | `0x01bb5650` | `0x01bb4b30` | ✅ 构造函数与 `AddDynamicToken` 都调用它，可互为印证 |
| `sizeof(CDiplomaticAction)` | `0x50` | `0x50` | ✅ 与"无成员子类"（token `0x3e5c`/`0x3e5d`）的分配大小一致 |
| `CDiplomaticAction::ScriptedShouldAIPropose()` | `0x00943890` | `0x009435e0` | ✅ 一致：拼 `"diplomatic_action." + <类型名> + ".should_ai_propose"`，读 `type+0x568` 的 MTTH，作用域是对象 `+0x20`（root/发起方）与 `+0x24`（from/接收方），最后 `0 < factor` |
| `ShouldAIPropose` 的虚表槽（**新**） | `+0x60` | `+0x60` | ✅ 由投票推出：工厂派发里 69 张具体虚表，**55 张**在 `+0x60` 放着"会调用 `ScriptedShouldAIPropose` 的函数"（第二名只有 1 票）；基类虚表同一槽是 `32 c0 c3`（`xor al,al; ret`）。AI 决策函数（`0xb8a1a0`）在这条链上依次问 `+0x58` / `+0x60` / `+0x68`，`+0x60` 那一次带一个 `int` 参数、结果 `test al,al` 决定要不要生成提议 |

补充确认的布局：`CString = {vtable; data@+0x10; size@+0x20; capacity@+0x28}`；
`CDiplomaticActionType` 在 Windows 版是 `0x628` 字节（dump 里是 `0x5e0`）。
另外，原版有 **64 个 token** 在工厂里走的就是通用构造函数，这说明"通用类足以工作"不是特例。

> **对下面证据表里 `IsSelectable → +0x60` 那一条的更正**：那是 Ghidra 在
> "Could not recover jumptable" 的函数里把跳转表的一个分支误报成了虚表调用。
> 实际证据都指向 `+0x60` 是 `ShouldAIPropose`：`+0x60` 的 55 个实现体里调用的正是
> `ScriptedShouldAIPropose`（读脚本的 `should_ai_propose`）；外交视图
> `ShowDiplomaticActions` 用的是 `+0x50` / `+0x70` / `+0x78`，**从不调用 `+0x60`**；
> 而 AI 决策函数在这条链上正好问 `+0x58` / `+0x60` / `+0x68`。

### 8.3 结论

- 第 2、3 节的两道墙在 Windows 版上**一模一样**，连哨兵值 `0xc` 和告警文案都相同；
- 第 5 节的 `AddDynamicToken` 机制在 Windows 版上**完全可用**，接口和内部记账逻辑都一致；
- 第 7 节预判的"偏移会变"得到证实（`+0x5d8 → +0x620`，虚表槽 `+0x40 → +0x38`），
  所以 DLL 里**不能照抄 dump 的偏移**，凡是需要的偏移都在运行时重新推导或核对；
- 上面每个地址都是**运行时用字符串锚点重新解析**出来的，不写死 RVA，
  因此在 4.5.0 与 4.5.1 上都能正确工作。

---

### 8.4 实机验证（4.5.1，真实游戏进程）

按第 7 节做出来的 DLL 已在**真实运行的游戏**里跑通，日志原文（节选）：

```
[     1.047] hook 1 installed (stole 5 prologue bytes): scripted action names now get real keyword tokens
[     1.047] hook 2 installed (stole 5 prologue bytes): new tokens now produce a generic scripted action
[    52.094] token space: 18948 static keywords, 47956 dynamic already present
[    52.157] registered keyword 'action_hook_greeting' -> token 66908 (0x1055c)
[    59.375] catch-up: scanned 69 action types, repaired 0, already registered 1
[    59.375] self-test: OK -- a generic diplomatic action object was built for token 66908 (0x1055c), type confirmed
```

逐条对应本文的结论：

| 日志 | 对应结论 |
| --- | --- |
| `registered keyword 'action_hook_greeting' -> token 66908` | 第 2 节的墙被补上了：一个原版不存在的名字拿到了**真实 token**，而不是哨兵 `0xc` |
| `existing keyword 'action_improve_relation' -> token 13597` 等 68 条 | 原版行动全部沿用原有 token（`13597 = 0x351d`、`declared_war = 0x2d52`），与 `analysis/diplo_action_tokens.csv` 完全一致，说明没有动到原版行为 |
| `catch-up: scanned 69 action types` | 原版 `00_actions.txt` 里 68 个唯一 `action_*` 定义 + 测试模组 1 个 = 69，数量吻合 |
| `self-test: OK ... type confirmed` | 第 3 节的墙也被补上了：外交界面调用的那条工厂路径（`CreateDiplomaticAction` → `CreateEmptyAction`）确实为新 token 造出了对象，且对象里的类型 token 对得上 |
| `error.log` 中 `missing token` 出现 **0 次** | 第 2.2 节那条告警消失了，这正是"原来加不了"的直接症状 |
| `AI propose gate wired: vtable slot +0x60 ...` + `self-test: AI propose gate (+0x60) is the scripted implementation ...` | 第 7.3 节里"AI 默认不会主动提议"那条限制也补上了：新对象的虚表那一槽已指向 DLL 的实现，AI 问到的答案从此来自脚本里的 `should_ai_propose` |

装好这一版之后又跑过一次真实游戏（4.5.1 + 两个新行动），日志原文（节选）：

```
[     1.282]   CDiplomaticAction::ScriptedShouldAIPropose   rva 0x00943890
[     1.282]   AI propose gate (ShouldAIPropose slot)       +0x60, agreed by 55 stock action vtables
[     1.282] AI propose gate wired: vtable slot +0x60 now answers from the action's script (should_ai_propose), the same way 55 stock action classes do
[    67.047] registered keyword 'action_cntr_destruction' -> token 66921 (0x10569)
[    67.047] registered keyword 'action_hook_greeting' -> token 66922 (0x1056a)
[    67.594] catch-up: scanned 70 action types, repaired 0, already registered 2
[    67.594] self-test: AI propose gate (+0x60) is the scripted implementation, so an AI empire can propose this action itself
[    67.594] self-test: 2 of 2 newly registered action(s) verified through the factory the diplomacy view uses
```

另外实测确认了两件工程上的事：

1. **挂起启动（`CREATE_SUSPENDED`）注入会让游戏立刻崩在 `0xC0000005`**，而游戏正常启动后再注入完全正常。
   所以注入器改成"先启动、等 700 ms、再注入"，并把 `--suspend` 标为不可用。
2. 时序不再敏感：钩子早于数据加载时由构造函数钩子覆盖，晚于加载时由**回扫数据库**补上
   （第 7.3 节提到的动态 token 分配顺序问题因此不再依赖注入时机）。

仍未验证的是两件需要"真的玩一局"的事：在外交界面里看到按钮并点击生效、
以及 AI 帝国真的把新行动提出来。前者 DLL 自检已经跑过界面所用的同一段工厂代码；
后者自检只能确认"那一槽确实是脚本实现"，AI 真的来问时日志里会多出
`AI propose check on token N: should_ai_propose answers yes/no`，测试模组的 `on_accept`
里也写了 `log =`，AI 提议被接受时 `logs/game.log` 里会留下痕迹。

---

### 7.4 一个必须记录下来的坑：基类虚表是抽象虚表

第一版 DLL 按"用基类 `CDiplomaticAction` 的虚表造通用对象"实现，结果**一打开外交界面就闪退**。
游戏的崩溃报告说得非常直接：

```
Application: Stellaris
Version: 4.5.1
Pure Virtual Function Call
```

原因：**`CDiplomaticAction` 是抽象类**。它自己的虚表里，`+0x70` 与 `+0x78` 两个槽放的是
MSVC 的 `_purecall` 桩函数（本机 RVA `0x2023540`，全二进制共 873 处引用它）。引擎从来
不把这个虚表当作最终虚表用——工厂对每个 token 都是
`operator_new(0x50)` → 基类构造函数 → **再覆盖成派生类的虚表**：

```asm
; CreateEmptyAction 里每个 token 的固定形状（以 0x351d 为例）
mov  ecx, 0x50
call operator_new
mov  edx, 0x351d
mov  rcx, rax
call CDiplomaticAction::CDiplomaticAction      ; 先装基类虚表
lea  rax, [rip + <派生虚表>]
mov  [obj], rax                                ; 再换成派生虚表 ← 关键的一步
```

外交视图遍历数据库时会对每个行动调用虚表槽 `+0x48`、`+0x50`，而基类的实现会**内部再分派**
到 `+0x70`/`+0x78`——于是打到 `_purecall`，进程直接终止。审计 64 个派生虚表也印证了这一点：
**每一个**都与基类虚表在 `+0x70`/`+0x78` 两槽不同，也就是说每个派生类都必须实现这两个纯虚函数。

**修正做法**：不再用基类虚表，而是在 DLL 里自建一张具体虚表——把基类虚表的 20 个槽原样复制，
只把 `+0x70`、`+0x78` 换成自己的实现：

| 槽 | 语义（由 64 个原版实现反推） | 本 hook 的实现 |
| --- | --- | --- |
| `+0x70` | 返回该行动的**本地化键前缀**（原版各写各的：`ACTION_EMBASSY`、`improve_relations`、`build_spy_network`……） | 返回**该 type 自身名字的大写形式**——这与引擎 `PostReadInit` 校验本地化键用的前缀完全一致，所以新行动的 `<NAME>_TITLE` / `<NAME>_DESC` 等键天然对得上 |
| `+0x78` | 克隆一个行动（`operator_new` → 复制 → 装自己的虚表） | 复用**引擎自己的复制函数**（本机 `0x9a7290`，从任一原版克隆体里推出），复制完再把虚表换成上面那张 |

两个地址都在运行时推导，并且加了**形状校验**：只有当基类虚表的纯虚槽**恰好是 `+0x70` 和 `+0x78`**
时才启用对象合成；否则只保留第一层（token 注册）并明确写日志，绝不在形状不符时冒险合成。

定位 `_purecall` 用的是它的字节特征（`48 83 EC 28 E8 … 48 85 C0 74 06 FF 15 … E8`），
复制函数则从原版克隆体的 `mov ecx,<size>; call operator_new; …; call <copy>` 形状里取。

实机复现与原版路径等价的调用（`+0x48`、`+0x50`，正是崩过的那两处）后日志为：

```
concrete action vtable built at 0x7ff9051c5080: base slots copied, +0x70 -> localisation prefix from the type name, +0x78 -> clone
registered keyword 'action_hook_greeting' -> token 66908 (0x1055c)
self-test: OK -- a generic diplomatic action object was built for token 66908 (0x1055c), type confirmed
self-test: called the diplomacy view's own check slots (2/2) on the new action without incident
self-test: localisation keys will be looked up as '<prefix>_TITLE', '<prefix>_DESC', ... with prefix 'ACTION_HOOK_GREETING'
```

**教训**：dump 里"基类有完整实现"不等于"基类虚表可以直接用"。
`CDiplomaticAction::IsSelectable` 在 dump 中是 `(**(code **)(*this + 0x60))(this,1,0)` 这种
**转发型**实现——转发目标就是派生类必须补上的纯虚函数。只要看到转发型实现，
就必须去检查最终虚表的每一个槽，而不是只看基类有没有同名函数。

---

## 9. 证据行号汇总

| 主题 | 位置（dump 行号） |
| --- | --- |
| `CDiplomaticActionTypeDatabase` 构造，目录名 `common/diplomatic_actions` | 2339876-2339934 |
| DB 条目数 `+0x5c` / 数据指针 `+0x50` | 2339946-2339970、2340166、3922229-3922293 |
| `GetByToken` 线性扫描比较 `+0x50` | 2339946-2339970 |
| `CDiplomaticActionType::CDiplomaticActionType(int, CString const&)` | 2337826-2337973 |
| token 赋值 `CStaticLexer::FindTok(name)` → `+0x50` | 2337903-2337904 |
| "Diplomatic action is missing token:" 日志 | 2337951-2337971 |
| `CStaticLexer::FindTok` 未命中返回 `0xc` | 8099500-8099513 |
| `0xc` 是原始 token `"num"` | 8099706-8099737 |
| `GetTokenType` / `FindTokenType` / 静态表步长 0x48 / 上限 0x270a | 155983-155988、155999-156020 |
| `CStaticLexer::AddDynamicToken` | 8099846-8099973 |
| `IsDynamic` / `GetPrimitiveString` 的 "dynamic: " | 8099779-8099783、8099731-8099737 |
| `RebuildLookup` 重建 token→字符串 数组 | 8099522-8099653 |
| 加载器 `LoadFromReader`：按名字查重，未命中就新建 | 2340790-2340985（新建见 2340883-2340893、2340957-2340967） |
| `PostReadInit` 只校验本地化键与 MTTH | 2338293-2338430 |
| `NDiplomacyUtil::CreateDiplomaticAction` | 2330498-2330510 |
| `CreateEmptyAction` 巨型 switch，未知 token 返回 NULL | 2628904-2629501（默认置空 2628966；提前 return 2628978/2628998/2629014） |
| `0x3e5c` / `0x3e5d` 造裸 `CDiplomaticAction` | 2628997-2629011 |
| `CDiplomacyView::ShowDiplomaticActions` 遍历整个 DB | 3922161-3922376（循环 3922229-3922294） |
| `CDiplomaticAction::IsSelectable` → 虚表 `+0x60` | 2333278-2333285（**这条是 Ghidra 在跳转表函数里的误报**，见 8.2 节更正：`+0x60` 是 `ShouldAIPropose`） |
| `CDiplomaticAction::IsPotential` → type 的脚本触发器 | 2333910-2333979 |
| `CDiplomaticAction::IsPossible` | 2333987-2334005 |
| `CDiplomaticAction` 全套脚本驱动虚函数 | 2333904-2335987 |
| `CDiplomaticAction::ShouldAIPropose` 基类返回 0 | 2337135-2337141 |
| `CDiplomaticAction::ScriptedShouldAIPropose`（脚本 `should_ai_propose`） | 2334821-2334953 |
| `CDiplomaticActionType::IsPotential` 拼 `diplomatic_action.<name>.potential` | 2338742-2338794 |
| `set_diplomatic_action_settings` 用 `ReadKeyReference<CDiplomaticActionTypeDatabase>` 解析行动名 | 6146635-6146651 |
| 行动设置项字段与 token 对照 | `analysis/diplo_action_fields.csv`（35 项） |
| 原版行动清单 | `common/diplomatic_actions/00_actions.txt`（6550 行，89 个行动） |
| 使用 DB 的全部代码位置（仅 18 处） | 见 `analysis/` 检索结果：`SetCacheTech`、`NAgreementUtil::OpenNegotiationWindowWithSubjectIfPossible`、`NCountryUtil::IsEspionageAvailableFor`、`NDiplomacyUtil::GetTradeDealVoteMode`、`CDiplomaticAction::CDiplomaticAction(int)`、`CFederationProgression::ReadMember/WriteMembers`、`FindBestLawToPropose`、`CDiplomacyView::ShowDiplomaticActions`、`CAgreementsListViewController::OnTermsNegotiationClick`、`CSetDiplomacyActionSettingEffect::ReadMember`、`OpenEventWindow` |
