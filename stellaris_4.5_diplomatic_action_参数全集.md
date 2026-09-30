# Stellaris 4.5 外交行动（`common/diplomatic_actions`）参数全集

> **适用范围**：Cygnus v4.5.1 / v4.5.0（Windows 版 `stellaris.exe`，另与 Linux/Ghidra 反编译产物交叉核对）
> **依据**：`CDiplomaticActionType::ReadMember` 完整分派树（Windows RVA `0x4b42d0`，794 条指令逐块反汇编）+ 从 exe 注册点恢复的静态关键字表（9994 条，`kdump.py`）
> **结论**：一个 `action_xxx = { }` 块里引擎认识的键共 **36 个** = 22 个布尔位（同一个 dword，Windows `type+0x620`，dump `type+0x5d8`）+ 14 个独立字段。**其它任何键都会报 `Unexpected token`**（默认分支 `0x4b4ec9` → `0x1bac000` 里拼的就是这句），然后被忽略。

---

## 0. 速查

### 0.1 布尔位一览（`type+0x620`，Windows）

| bit | 掩码 | 键 | 默认 |
| --- | --- | --- | --- |
| 0 | `0x1` | `is_listed` | **开** |
| 1 | `0x2` | `requires_actor_peace` | 关 |
| 2 | `0x4` | `requires_recipient_peace` | 关 |
| 3 | `0x8` | `requires_alliance_vote` | 关 |
| 4 | `0x10` | `requires_unanimous_vote` | 关 |
| 5 | `0x20` | `requires_recipient_alliance_vote` | 关 |
| 6 | `0x40` | `requires_actor_independence` | **开** |
| 7 | `0x80` | `requires_recipient_independence` | **开** |
| 8 | `0x100` | `auto_accepted` | 关 |
| 9 | `0x200` | `diplo_view_acceptance_icon` | 关 |
| 10 | `0x400` | `requires_recipient_federation_leader` | 关 |
| 11 | `0x800` | `requires_actor_federation_leader` | 关 |
| 12 | `0x1000` | `show_decline_to_alliance_members` | 关 |
| 13 | `0x2000` | `show_to_alliance_members` | 关（**死键**，见 §3） |
| 14 | `0x4000` | `should_show_auto_accept_message_recipient` | 关 |
| 15 | `0x8000` | `should_open_auto_accept_message_recipient` | 关 |
| 16 | `0x10000` | `should_show_auto_accept_message_actor` | 关 |
| 17 | `0x20000` | `should_notify_auto_recipient_on_vote_fail` | 关 |
| 18 | `0x40000` | `should_notify_all_communications` | 关 |
| 19 | `0x80000` | `should_show_accept_message` | **开** |
| 20 | `0x100000` | `should_remove_response_message_when_not_possible` | 关 |
| 21 | `0x200000` | `require_envoy` | 关 |

**默认值来源**：类型构造函数写死的 `flags = 0x800c1`（dump 行 2337950 / Windows `0x4b41af`）= bit 0 + bit 6 + bit 7 + bit 19。也就是说**默认只有 `is_listed`、`requires_actor_independence`、`requires_recipient_independence`、`should_show_accept_message` 是开**，另外 18 位默认关。

> 原版文件头注释里 "`requires_recipient_federation_leader`, true by default" 与构造函数对不上，不要照抄注释。

### 0.2 非布尔字段

| 键 | 取值 | 存放位置（Windows `type` 起） | 默认 |
| --- | --- | --- | --- |
| `prerequisites` | 列表 | `+0x58` | 空 |
| `AI_acceptance_base_value` | int | `+0x78` | 0 |
| `icon` | string（GFX 名） | `+0x80` | 空 |
| `sound` | string（音效名） | `+0xb0` | 空 |
| `envoy_assignment` | 关键字 | `+0xe0` | 0 |
| `action_type` | 关键字 | `+0xe4` | 0 |
| `potential` | trigger | `+0xe8` | 空 |
| `possible` | trigger | `+0x1c0` | 空 |
| `proposable` | trigger | `+0x298` | 空 |
| `on_accept` | effect | `+0x370` | 空 |
| `on_decline` | effect | `+0x430` | 空 |
| `on_propose` | effect | `+0x4f0` | 空 |
| `should_ai_propose` | weight 块（`CMeanTimeToHappen`） | `+0x5b0` | 空 = 0 |
| `ai_acceptance` | weight 块（`CMeanTimeToHappen`） | `+0x5e8` | 空 = 0 |

> 偏移的推导方式：`ReadMember` 的 `this` 是 `CPersistent` 子对象（`type+0x40`），所以它写的 `this+0xNN` 等于 `type+0xNN+0x40`；用 DLL 实测过的 `AI_acceptance_base_value = type+0x78` 与构造函数写 `flags@type+0x620` 两条独立证据校正。

---

## 1. 触发器与效果

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `potential` | trigger | 决定行动**是否出现在界面**。`CDiplomaticAction::IsPotential` → `CDiplomaticActionType::IsPotential`，失败会给 tooltip | ✅ 通用 |
| `possible` | trigger | 已经造出对象后是否**仍然能发**。`CDiplomaticAction::IsPossible`；`prev` 只在 `ask_xxx` 回应里是请求方 | ✅ 通用 |
| `proposable` | trigger | 是否**可提交**（界面禁用/提示）。`CDiplomaticAction::IsProposable` | ✅ 通用 |
| `prerequisites` | 列表 | 发起方的科技/前置检查。`IsPotential` 把 `type+0x58` 交给国家的科技模块（`CCountry::GetTechnologyModule` 的 `+0x98` 槽） | ✅ 通用 |
| `on_propose` | effect | 提交时执行（`ExecuteProposed` → `Type::OnPropose`）。**4.5.1 原版一次没用过** | ✅ 通用 |
| `on_accept` | effect | 接受时执行（`ExecuteAccept` → `Type::OnAccept`） | ✅ 通用 |
| `on_decline` | effect | 拒绝时执行（`ExecuteDecline` → `Type::OnDecline`）。**4.5.1 原版一次没用过** | ✅ 通用 |

作用域：`root` = 发起方、`from` = 接收方（`potential`/`possible`/`proposable`/三个 `on_*` 都一样）。

## 2. AI 与接受度

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `ai_acceptance` | weight 块 | 接收方 AI 的**脚本接受度**贡献。`GetScriptedAcceptance` 读 `CScriptableValue(type+0x5a0)`(dump)/`+0x5e8`(Win)；`CDiplomaticAction::ShouldUseScriptedAcceptance()` 基类 `return 1`，所以**任何 token 都算**。作用域**反过来**：`root` = 接收方、`from` = 发起方。写法：`modifier = { add = N ... }`（官方注释：只建议 add/subtract，`factor`/`mult` 不会放大硬编码部分） | ✅ 通用 |
| `should_ai_propose` | weight 块 | 发起方 AI**要不要主动提**。`ScriptedShouldAIPropose` 读 MTTH（dump `+0x568` / Win `+0x5b0`），`0 < 结果` 才提。写法：`weight = N` + `modifier = { factor = ... }` | ⚠️ 需 DLL：基类那一槽是 `xor al,al;ret`，`diplo_action_hook` 的 AI 提议槽（`+0x60`）已接管 |
| `AI_acceptance_base_value` | int | "基础接受/抗拒"。引擎在 `GetAIAcceptance` 里**按 token 硬编码**的表里加它，新 token 查不到 → 恒为 0 | ⚠️ 需 DLL：`diplo_action_hook` 的 hook 3 在返回值上补回来（原版只写 0 / -50） |
| `require_envoy` | bool（bit 21） | 点这个行动时是否走**特使指派**界面。`CDiplomacyView::SelectAction` / `ShowActionView` | ⚠️ 只有玩家外交界面这条路看它，AI 那条路不看 |
| `envoy_assignment` | 关键字：`improve_relations` / `harm_relations` / `spy_network` | 特使去执行哪种任务（字段存的是关键字的 token）。与 `require_envoy` 配套，同一批消费者 | ⚠️ 同上（且值必须是已存在的关键字） |

## 3. 界面与表现

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `is_listed` | bool（bit 0） | 外交界面是否列出。`NDiplomacyUtil::CreateDiplomaticAction` 的第一道门（`type+0x620 & 1`），关了就**连对象都不造** | ✅ 通用（默认开） |
| `icon` | string（GFX 名） | 行动按钮 / 来讯窗口的图标。`CDiplomacyView::ShowActionView`、`CIncomingDiplomacyView::GetBackgroundSprite`、`OpenEventWindow` 读 `type+0x80` | ✅ 通用（需 mod 自己提供 GFX） |
| `action_type` | 关键字：`neutral` / `positive` / `negative` / `aggressive` | 行动分类，决定窗口底色与语气。`ShowActionView`、`GetBackgroundSprite` 读 `type+0xe4` | ✅ 通用（值必须写上面四个关键字之一） |
| `sound` | string（音效名） | 接受时播放：`Type::OnAccept` → `NSoundUtil::PlaySoundEffect(type+0xb0)`，只在本地玩家是当事方时 | ✅ 通用 |
| `diplo_view_acceptance_icon` | bool（bit 9） | 外交界面那一行是否显示 **AI 接受度图标**。`CDiploActionEntry::PerFrameUpdate` 的门（`type+0x620` bit 9，虚表 `+0xe8`）+ `HasEnoughAIAcceptance` | ✅ 通用（**默认关，必须显式写 `yes`**） |
| `show_to_alliance_members` | bool（bit 13） | **死键**：4.5.0/4.5.1 全二进制找不到任何消费者（原版有 3 处写 `yes`，写不写都一样） | ❌ 无效 |

## 4. 资格开关

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `requires_actor_peace` / `requires_recipient_peace` | bool（bit 1 / 2） | `CDiplomaticAction::IsPossible` 里逐条检查，失败给本地化提示 | ✅ 通用（默认关） |
| `requires_actor_independence` / `requires_recipient_independence` | bool（bit 6 / 7） | 同上，要求该方是独立国家（不是附庸） | ✅ 通用（默认**开**） |
| `requires_actor_federation_leader` / `requires_recipient_federation_leader` | bool（bit 11 / 10） | `Requires*FederationLeader()`：在联邦里时要求是领袖；另外联邦 progression 的 action setting 也能强制为真 | ✅ 通用（默认关） |
| `auto_accepted` | bool（bit 8） | 接收方不参与决定，直接算"永远接受"（`IsAutoAccepted`）。附带效果：`PostReadInit` 会跳过一部分本地化键检查；接受度会被引擎覆盖成 `NAI::ACCEPTANCE_DEAL_ALWAYS` | ✅ 通用 |

## 5. 联邦 / 联盟投票

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `requires_alliance_vote` | bool（bit 3） | 需要联盟投票。`NDiplomacyUtil::GetActionVoteMode` / `ActionRequiresVoting` / `GetTradeDealVoteMode` | ⚠️ 通用，但只在联盟/联邦场景有意义 |
| `requires_unanimous_vote` | bool（bit 4） | 需要全票（投票模式 3 → 4），同一批消费者 | ⚠️ 同上 |
| `requires_recipient_alliance_vote` | bool（bit 5） | 接收方的联盟成员也要同意：`GetAIAcceptance`、`GetFederationMemberWarAcceptance`、`GetFederationMemberInviteAcceptance`、`IsProposalOngoing`（防重复提案）、外交 tooltip | ⚠️ 同上 |

## 6. 消息与通知

| 键 | 取值 | 作用（消费者） | 新行动可用性 |
| --- | --- | --- | --- |
| `should_show_accept_message` | bool（bit 19） | 被接受时给发起方回执消息（`ShouldShowAcceptMessage`） | ✅ 通用（默认**开**） |
| `should_show_auto_accept_message_actor` | bool（bit 16） | 自动接受时给发起方消息（`ShouldShowAutoAcceptMessageActor`） | ✅ 通用 |
| `should_show_auto_accept_message_recipient` | bool（bit 14） | 自动接受时给接收方消息（`ShouldShowAutoAcceptMessageRecipient`） | ✅ 通用 |
| `should_open_auto_accept_message_recipient` | bool（bit 15） | 上一条的消息自动弹开（`ShouldOpenAutoAcceptMessageRecipient`） | ✅ 通用 |
| `should_notify_auto_recipient_on_vote_fail` | bool（bit 17） | 自动接受但投票失败时通知接收方（`ShouldNotifyRecipientOnVoteFail`） | ✅ 通用 |
| `should_notify_all_communications` | bool（bit 18） | 所有与当事方有通讯关系的国家都收到通知（`ExecuteAccept`、`AddRejectedAction`） | ✅ 通用 |
| `should_remove_response_message_when_not_possible` | bool（bit 20） | `possible` 不再成立时自动移除回执消息（`CGameState::ShouldAutoRemoveMessage`） | ✅ 通用 |
| `show_decline_to_alliance_members` | bool（bit 12） | 拒绝时让联盟成员看到（`CCountry::HandleIncomingDiplomacy`）。**4.5.1 原版一次没用过** | ✅ 通用（引擎支持，原版没示例） |

---

## 7. 这些参数对"脚本新增的行动"都可用吗？

**大部分完全可用，因为消费者全是与 token 无关的通用代码**（基类 `CDiplomaticAction`、`NDiplomacyUtil`、外交/来讯视图、消息系统）。逐条结论：

| 分类 | 键 | 说明 |
| --- | --- | --- |
| ✅ 开箱即用（28 个） | `potential` / `possible` / `proposable` / `prerequisites` / `on_propose` / `on_accept` / `on_decline`（7）；`ai_acceptance`（1）；`is_listed` / `icon` / `action_type` / `sound` / `diplo_view_acceptance_icon`（5）；`auto_accepted` 与 6 个 `requires_*`（peace×2、independence×2、federation_leader×2）（7）；8 个消息/通知键 | 脚本写了就生效，和原版走同一段代码 |
| ⚠️ 需要 `diplo_action_hook`（2 个） | `should_ai_propose`、`AI_acceptance_base_value` | 引擎侧这两项对未知 token 恒为"不提议 / 0"；DLL 分别用"AI 提议槽 `+0x60`"和"在接受度返回值上补基数"补上。**不装 DLL 时这两个键对新行动无效**（但不会报错） |
| ⚠️ 只有玩家外交界面看（2 个） | `require_envoy`、`envoy_assignment` | 决定要不要弹特使指派界面、派哪种任务；AI 那条路完全不看，也不参与 `potential/possible/proposable` 判定 |
| ⚠️ 只在联盟/联邦场景有意义（3 个） | `requires_alliance_vote`、`requires_unanimous_vote`、`requires_recipient_alliance_vote` | 代码通用，但只有当事方处于联盟/联邦时才会走到 |
| ❌ 谁都无效（1 个） | `show_to_alliance_members` | 全二进制无消费者，原版写了也没用 |

**另有两点与"可用性"无关但很容易踩**：

1. 原版 4.5.1 从未使用过的键：`on_propose`、`on_decline`、`prerequisites`、`show_decline_to_alliance_members`、`show_to_alliance_members`。前四个引擎支持（可用，只是没有范例），最后一个无效。
2. 新行动**没有专用 C++ 子类**：贸易条款、宣战/和平的具体内容、联邦投票语义、间谍网络、臣服条款这些"额外块"属于那些行动独有的语法，通用类不解析——这与参数表本身无关，但决定了"能写什么"。

### 给新行动的最小可用模板

```c
action_my_action = {
	icon = "GFX_diplomacy_improve_relation"
	action_type = neutral
	is_listed = yes
	diplo_view_acceptance_icon = yes        # 想要接受度图标就必须写

	potential = { hidden_trigger = { is_country_type = default } }
	possible = { }
	proposable = { }

	ai_acceptance = { modifier = { add = -20 desc = BASE_RELUCTANCE } }
	should_ai_propose = {
		weight = 0
		modifier = { add = 10 opinion = { who = from value > 50 } }
	}
	AI_acceptance_base_value = 0

	on_accept = { from = { add_opinion_modifier = { who = root modifier = ... } } }
	on_decline = { }
}
```

---
