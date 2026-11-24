# 派生密钥集的结构与失败语义

分析对象：`keyderivation` 包（`KeysetDeriver`）、`keyset` 包的 `Handle`/`Manager`，以及
`internal/factoryutil` 的启用项迭代。所有结论均对照源码逐行核实，并用临时探针测试实际运行验证
（探针文件已删除，`go test ./keyderivation/...` 全绿）。

---

## 0. 组合链：从「派生包装」到「新句柄」

```
调用方
  └─ keyderivation.New / NewWithConfig(handle)            keyderivation/keyset_deriver_factory.go:57-102
       │  1. handle.Len()==0 → 直接拒绝
       │  2. for entry := range factoryutil.EnabledUnmonitoredEntries(handle)
       │        （只迭代 KeyStatus==Enabled 的项；见 internal/factoryutil/factoryutil.go:51-75）
       │  3. config.PrimitiveFromKey[keyderiver.KeyDeriver](entry.Key(), config)
       │        → 每项必须能构造出「派生基元」，否则 New 整体失败
       │  4. 记录 primaryKeyID = 主键项的 KeyID()
       │  5. 若是 legacy 基元 → 用 fullPrimitiveWrapper 包一层
       │        （keyset_deriver_factory.go:80-94, 30-53）
       └─ 返回 &wrappedKeysetDeriver{fullKeyDerivers, primaryKeyID}

  └─ deriver.DeriveKeyset(salt)                            keyset_deriver_factory.go:121-138
        km := keyset.NewManager()          ← 全新、空的管理器，未对外泄漏
        for each (fullKeyDeriver, sourceKeyID):
            a. derivedKey = fullKeyDeriver.DeriveKey(salt)    任何错误 → return nil, err
            b. km.AddKeyWithOpts(derivedKey, WithFixedID(sourceKeyID))
                任何错误 → return nil, err
            c. 若 sourceKeyID == primaryKeyID → km.SetPrimary(sourceKeyID)
        return km.Handle()                                    失败 → return nil, err
```

单键派生的入口是 `prfbasedkeyderivation.keyDeriver.DeriveKey`
（`keyderivation/prfbasedkeyderivation/keyderiver.go:64-77`）：

1. `streamingPRF.Compute(salt)` 把 **DeriveKeyset 的盐** 作为 HKDF 的 `info`，
   PRF 键自身参数里的 salt 作为 HKDF 的 `salt`（`internal/streamingprf/hkdf_streaming_prf.go:53-55`）；
2. 用该伪随机流作为 `reader`，按派生键参数（算法、密钥长度、变体）注册的派生函数
   （`internal/keyderivers/keyderivers.go`）读满所需字节；
3. 用**源键自己的 ID 要求**构造新键：`idRequirement, _ := k.key.IDRequirement()`
   （`keyderiver.go:75-76`）——注意这里不查任何外部状态，单键派生的结果自带 ID 要求。

`wrappedKeysetDeriver` 随后用 **源条目的 KeyID 覆写** 这个 ID（`WithFixedID(e.keyID)`），
这就是「键身份由主键关系承担路由职责」的落点：派生材料只由盐决定，而新键在派生集合中的
身份（KeyID、是否主键）全部来自源密钥集。

### 两种包装路径的差异（结构继承强度不同）

| 路径 | 谁设置派生键的变体/前缀与 ID | 是否强制与源一致 |
| --- | --- | --- |
| 新版「完整基元」（`config.PrimitiveFromKey` 直接给出 `keyderiver.KeyDeriver`） | 派生基元自己决定变体；ID 由 `WithFixedID` 强制 | 只校验 ID 兼容性，**不**校验前缀类型 |
| legacy 基元 + `fullPrimitiveWrapper`（`keyset_deriver_factory.go:38-53`） | 序列化派生键后，用源条目的 `prefixType` 与 `idRequirement` 重建 `KeySerialization` 再解析 | 强制覆盖；RAW 源强制 `idRequirement=0` |

legacy 路径因此更强：它把源条目的输出前缀类型写死到派生键上，若重建后无法解析
（例如被强制成 TINK 但键材料对应的变体不允许），派生整体失败。新版路径允许派生基元
返回「前缀类型与源不同但 ID 兼容」的键（见 §1.3 的边界案例）。

---

## 1. 派生失败与不合规范的子结果如何影响整份输出

### 1.1 结论：原子性——失败即无句柄

**派生失败时没有可消费的半成品句柄。** 这一点由三重结构共同保证：

1. `DeriveKeyset` 内的 `keyset.Manager` 是局部变量，只在成功路径的最后一行通过
   `km.Handle()` 物化为 `*keyset.Handle`（`keyset_deriver_factory.go:122,137`）；
2. 循环中任何一步出错都 `return nil, err`，已 `AddKeyWithOpts` 进管理器的条目随局部变量一起
   被丢弃，调用方拿到的永远是 `(nil, error)`；
3. `keyset.Manager.Handle()` 自身也做全量校验（`keyset/manager.go:347-353` →
   `keyset/handle.go:238-264`）：存在 `Unknown` 状态或没有主键时返回错误，而不是返回残缺句柄。

因此不存在「部分条目可用、其余缺失」的中间态；失败信息只能通过 error 传递，
错误串带有 `keyset_deriver_factory:` 前缀以便定位（`SetPrimary`/`Handle` 的个别错误除外，
它们直接透传 `keyset.Manager:` 文本）。

### 1.2 失败点清单（逐一实测）

| 失败点 | 代码位置 | 返回 | 实测错误文本 |
| --- | --- | --- | --- |
| 构造期：空/ nil 句柄 | `keyset_deriver_factory.go:67-69` | `New` 失败 | `keyset_deriver_factory: empty or nil keyset handle` |
| 构造期：某个**启用**项不是派生基元 | :73-76, `factoryutil.PrimitiveFromKey` | `New` 失败 | `factoryutil: primitive is not a keyderiver.KeyDeriver` |
| 构造期：legacy 键无法序列化 | :82-85 | `New` 失败 | `cannot get proto key from entry: ...` |
| 派生期：单键派生报错 | :124-127 | 无句柄 | `keyset_deriver_factory: keyset derivation failed: ...` |
| 派生期：派生键为 nil | :128-130 | 无句柄 | `cannot add derived key: keyset.Manager: key is nil` |
| 派生期：派生键的 ID 要求与源 ID 冲突 | :128-130（`keyset/manager.go:164-174`） | 无句柄 | `key requires ID 4661, but WithFixedID was given ID 4660` |
| 派生期：两个派生键撞 ID | `keyset/manager.go:226-231` | 无句柄 | `keyset.Manager: key already has ID N` |
| 派生期：主键项 SetPrimary 失败（如状态非 Enabled） | :131-135 | 无句柄 | `cannot set primary key: ...` |
| 派生期：Handle 校验失败（无主键 / Unknown 状态） | :137 → `handle.go:238-251` | 无句柄 | `keyset.Handle: no primary key` 等 |

现有测试对这些语义有直接覆盖：
`keyset_deriver_factory_test.go:603-651`（单键派生失败令整次派生失败）、
`:505-595`（多键集合只派生启用项）、`:253-367` 与 `:381-502`（legacy / 完整基元两条路径）、
`keyset_deriver_factory_x_test.go:31-220`（真实 PRF 派生集合的端到端行为）。

### 1.3 「不合规范的子结果」分两类：被拒绝 vs 被容忍

**(a) 被框架拒绝的子结果**（导致整份输出失败）：

- 派生键为 `nil`；
- 派生键的 ID 要求与源条目 ID 不一致（上面的 0x1234/0x1235 实测）；
- 派生键声称了别的条目的 ID（与 `WithFixedID` 冲突，或与先前条目重复）；
- 派生基元返回错误、返回无法序列化的键类型（legacy 路径）；
- 源集合中任何**启用**项无法构造派生基元。

**(b) 被框架容忍、但会改变结构的子结果**（不报错，属于需要注意的边界）：

- **前缀类型漂移**：完整基元路径下，派生键的变体可以与源条目不同。实测：源条目为
  TINK 前缀，派生基元返回 RAW 键（无 ID 要求）时，`AddKeyWithOpts` 接受源 ID
  （因为无 ID 要求），最终派生键的前缀类型是 RAW，与源结构不一致但调用成功。
  legacy 路径不会出现这一情况（它强制用源前缀重建）。
- **RAW 条目的 KeyID 非零**：`keysetToEntries` 在构造 `KeySerialization` 时把 RAW 键 ID
  归零（`keyset/handle.go:284-287`），但 `Entry.keyID` 仍保留 proto 里的 `KeyId`
  （`handle.go:302`）。因此派生集合中 RAW 条目的 `KeysetInfo().KeyId` 可以是非零源 ID，
  而键自身的 `IDRequirement()` 是 0。写入再读回后该值保持不变（实测源 ID 原样出现在
  派生键条的 KeyId 上）。这对路由无害（RAW 输出无前缀），但会让「ID 是否被使用」与
  「ID 是否出现在结构里」分离。
- **重复的派生材料**：两个源条目若 PRF 材料与派生参数完全相同，同一盐下派生出的
  密钥字节完全相同（实测两键 `KeyData.Value` 逐字节相同），仅 KeyID 不同。框架不检测
  这种材料重复——它只保证 ID 唯一。

### 1.4 被继承 / 不被继承的状态

**被继承（决定路由与身份）：**

- **条目集合**：只有 `KeyStatus==Enabled` 的源条目进入派生集合；
  Disabled / Destroyed 条目被**静默丢弃**（`factoryutil.go:63`），不报错、也不在输出中
  保留为 Disabled。实测：源 2 条（1 启用 + 1 禁用）→ 派生 1 条，无错误。
- **KeyID**：逐条原样继承（`WithFixedID(e.keyID)`）。
- **主键身份**：源主键项的 ID 被记录为 `primaryKeyID`，派生时对该项调用 `SetPrimary`；
  主键关系按「ID 相等」传递，不依赖位置。
- **相对顺序**：`fullKeyDerivers` 按源迭代顺序追加，派生条目的顺序即启用条目的相对顺序。
- **状态归一**：所有派生条目都是 `Enabled`（`AddKeyWithOpts` 默认状态，
  `keyset/manager.go:199-204`）。不存在「继承 Disabled」的情况——禁用项根本不参与派生。
- **前缀类型**：完整基元路径来自派生键自身；legacy 路径强制取源条目前缀。
- **键参数（算法/长度/变体）**：来自派生模板，同一盐下逐次相同（实测 `Parameters().Equal`
  为 true）。

**不被继承：**

- **密钥材料**：只由 PRF 材料 + 盐决定，与源条目 ID 无关。
- **注解（annotations）**：派生管理器从不调用 `SetAnnotations`，`Handle()` 以 nil 注解构造。
  实测源 `map[a:b]` → 派生 `map[]`。
- **监控/日志配置**：派生句柄按全局监控客户端重新构造；由于注解为空，
  `setEntryMonitoringIfNeeded` 直接跳过（`keyset/handle.go:216-236`），条目使用
  `DoNothingLogger`。即源集合上的导出审计不会延续到派生集合。
- **加密/主密钥上下文**：派生句柄只在内存中存在，`Write` 仍需调用方提供 master key。

---

## 2. 「盐变化导致的材料变化」与「键集结构变化」的区分

### 2.1 盐只改变材料，不改变结构（实测矩阵）

对同一个 `KeysetDeriver`，用不同盐派生：

| 维度 | 盐 A → 盐 B | 依据 |
| --- | --- | --- |
| 密钥字节（KeyData.Value） | **变** | 单键派生以盐为 HKDF `info`，读出的伪随机字节随之改变 |
| 条目数 | **不变** | 由源启用条目数决定，盐不参与 |
| KeyID | **不变** | 由 `WithFixedID(源 ID)` 决定 |
| 主键 ID / 主键位置 | **不变** | 由 `primaryKeyID` 决定 |
| 条目顺序 | **不变** | 由 `fullKeyDerivers` 顺序决定 |
| 输出前缀类型 | **不变** | 由派生键变体/源前缀决定 |
| 键参数（算法、长度） | **不变** | 由派生模板决定 |
| `KeysetInfo()`（含 PrimaryKeyId、TypeUrl、Status、KeyId、OutputPrefixType） | **完全相同** | 实测两次派生 `KeysetInfo().String()` 相等 |
| `Handle.Equal` | **false** | 因为 `Entry.Equal` 比较了 `key.Equal`，而材料不同 |
| 同盐重派生 | **完全相等** | 确定性：同盐同派生器 `Equal` 为 true（也是接口文档所要求的「等价于按盐缓存」） |

关键实测：**跨盐解密的失败不是路由失败**。两次派生得到相同主键 ID、相同 TINK 前缀
（前缀里编码的正是该 ID），因此密文被正确路由到同一逻辑槽位，但该槽位的密钥字节已随盐
改变，AEAD 解密返回 `aead_factory: decryption failed`。这正说明：
**键身份与主键关系承担路由职责，密钥材料由盐承担机密性/独立性职责**，二者正交。

### 2.2 结构变化只来自源密钥集，不来自盐

「键集结构变化」指以下任一项改变：条目数、KeyID 集合、主键指定、条目的启用/禁用状态、
条目的输出前缀类型或算法/参数。它们只能通过修改**源**（派生）密钥集产生：

- **新增/删除条目** → 派生集合的启用条目集合随之增减（禁用/销毁项不出现）；
- **轮换（新 KeyID 成为主键）** → 派生集合的主键切到新 ID，旧条目仍可解密（若仍启用），
  这是 Tink 轮换语义在派生集合上的自然投影；
- **禁用条目** → 该条目从派生集合中**消失**（而不是变成 Disabled），这一点与普通密钥集的
  「禁用但保留」不同，属于派生路径特有行为，值得在运维层面注意（旧密文若只能由被禁用条目
  解密，派生集合里将没有对应条目可尝试）；
- **改变派生模板（算法/长度/变体）** → 派生集合的 TypeUrl、前缀类型改变；
- **改变 PRF 键材料** → 材料变、结构不变（与换盐效果同构，但换 PRF 键等于换整个材料域）。

**盐不能造成任何结构变化**：它既不能增删条目，也不能改变 ID、主键、顺序、状态或前缀类型。
因此可以用一句话区分两者：

> 盐是**材料维度**上的输入（一次派生 = 一个独立的材料域）；
> 源密钥集是**结构维度**上的输入（条目集合、ID、主键、前缀）。

### 2.3 两个易混淆的交叉点

1. **ID 被写入前缀 = 结构信息进入输出**。TINK/CRUNCHY/LEGACY 前缀由 ID 决定，所以「结构」
   会影响密文外观与路由；RAW 前缀不含 ID，结构信息只存在于句柄元数据中。
2. **材料重复不等于结构重复**。两个源条目若 PRF 材料与派生参数相同，同一盐下密钥字节
   完全相同（实测），KeyID 不同——结构上仍是两个槽位。

---

## 3. 结论摘要

1. **组合方式**：`New` 把源句柄的每个启用条目编译成「派生基元 + 源 KeyID」的有序列表，
   并单独记住主键 ID；`DeriveKeyset(salt)` 用全新的 `Manager` 逐条派生、以源 ID 固定身份、
   按 ID 关系恢复主键，最后一次性物化成句柄。
2. **失败原子性**：任何单键派生错误、任何不合规的派生键（nil、ID 冲突、不可序列化、
   主键设置失败、Handle 校验失败）都会让整次派生返回 `(nil, error)`；不存在半成品句柄，
   也不会暴露已构造的部分条目。
3. **状态继承**：启用集合、KeyID、主键关系、相对顺序、算法参数被继承；密钥材料、注解、
   监控配置不被继承；禁用/销毁条目被静默丢弃，输出条目一律为 Enabled。
4. **盐 vs 结构**：盐只改变密钥字节，结构（条目数、ID、主键、顺序、前缀、参数）完全不变
   （`KeysetInfo` 跨盐逐字节相同，`Handle.Equal` 为 false）；结构变化只来自源密钥集本身。
   路由靠 ID/主键，机密性与域隔离靠盐。
