# PRF 密钥集选择机制报告：主键轮换下的按 ID 求值责任边界

本报告基于对 `prf/`、`internal/factoryutil/`、`keyset/` 实际代码的阅读，说明多键 PRF
集合（`prf.Set`）在轮换主键时如何保持每把仍有效密钥按自身身份（key ID）产生输出，
以及各层在密钥状态、输出长度、按 ID 求值上的责任边界。

## 1. 密钥集 → PRF 的入口与构造流程

入口为 `prf.NewPRFSet(handle)` / `prf.NewPRFSetWithConfig(handle, config)`
（`prf/prf_set_factory.go:28`、`prf/prf_set_factory.go:34`）。构造流程：

1. 空 keyset 直接报错（`prf_set_factory.go:35-37`）。
2. 通过 `factoryutil.EnabledUnmonitoredEntries(handle)` 迭代密钥条目
   （`prf_set_factory.go:44`）。
3. 对每个条目调用 `factoryutil.PrimitiveFromKey[PRF](entry.Key(), config)`，
   用**该条目自己的密钥材料**构造独立的 PRF 实例（`prf_set_factory.go:45`）。
4. 若条目是主键，记录 `primaryKeyID = entry.KeyID()`（`prf_set_factory.go:49-51`）。
5. 以**该条目自己的 key ID** 为键，把包装了监控的 PRF 放入 map：
   `prfs[entry.KeyID()] = &monitoredPRF{prf: primitive, keyID: entry.KeyID(), ...}`
   （`prf_set_factory.go:52-56`）。
6. 返回 `&Set{PrimaryID: primaryKeyID, PRFs: prfs}`（`prf_set_factory.go:58-61`）。

关键点：`Set.PRFs` 是 `map[uint32]PRF`（`prf/prf_set.go:93`），map 的键就是密钥集
中各密钥自己的 key ID。**主键选择（PrimaryID）只是 map 的一个索引，不是任何输出的
身份**。轮换主键只改变 `PrimaryID` 的值，不改变其他密钥的 ID、密钥材料或输出。

## 2. 密钥状态的责任边界：不可用键不得派生

状态过滤发生在 `factoryutil.EnabledUnmonitoredEntries`
（`internal/factoryutil/factoryutil.go:53-73`）：

```go
if entry.KeyStatus() != keyset.Enabled {
    continue
}
```

- 只有 `keyset.Enabled` 状态的条目会进入 PRF 构造循环；`Disabled`、`Destroyed`、
  `Unknown`（`keyset/handle.go:49-58`）一律被跳过，**不会出现在 `Set.PRFs` 中**。
- 因此不可用键不会被"解释为仍可派生的凭据"：它在工厂阶段就被排除，调用方无法通过
  `set.PRFs[disabledKeyID]` 得到任何输出（map 查找失败，得到的是零值/不存在）。
- 防御是双层的：keyset 解析/校验阶段（`keyset/validation.go:63-64`）已经拒绝
  "非 ENABLED 的主键"和"无 ENABLED 密钥"的密钥集；工厂阶段的过滤是第二道防线，
  覆盖以编程方式构造、绕过了解析校验的 Handle。
- 边界情况：若主键被禁用（非法但可能由编程构造产生），迭代器不会看到它，
  `primaryKeyID` 保持初始值 0。此时 `ComputePrimaryPRF` 会因
  `PRFs[0]` 不存在而报错（`prf/prf_set.go:98-101`），**失败而非静默地用别的键
  顶替主键身份**——这正是"不把主键选择误当成所有输出身份"的体现。

## 3. 按 ID 求值的责任边界

`prf.Set`（`prf/prf_set.go:89-103`）的职责仅仅是**路由**，不重新派生、不改写身份：

- `ComputePrimaryPRF(input, outputLength)` 等价于
  `PRFs[PrimaryID].ComputePRF(...)`；PrimaryID 不在 map 中时返回错误
  （`prf_set.go:97-103`）。
- 调用方要对某把仍有效的旧键求值，直接用其自身 ID：
  `set.PRFs[oldKeyID].ComputePRF(input, length)`。该输出由旧键自己的密钥材料
  决定，与当前主键是谁无关。主键轮换后，旧键（只要仍 Enabled）的输出**逐比特
  不变**。
- 监控层同样保留逐键身份：每个 PRF 被包装为 `monitoredPRF{keyID: entry.KeyID()}`，
  成功时 `logger.Log(w.keyID, len(input))`（`prf_set.go:74-82`）——日志记录的
  是实际求值那把键的 ID，而不是主键 ID。
- 各 `PRF` 实例之间无共享状态；`PRF` 接口契约（`prf_set.go:30-37`）保证确定性
  （同键同输入同输出）与前缀性质（`length1 < length2` 时短输出是长输出的前缀）。

## 4. 输出长度的责任边界

输出长度校验**不在** `Set` 或工厂层，而在每个算法的 `ComputePRF` 实现内
（`prf/subtle/`），逐算法不同：

| 算法 | 实现 | 输出长度上限 | 超限行为 | 密钥长度要求 |
|---|---|---|---|---|
| AES-CMAC PRF | `prf/subtle/aes_cmac.go:56-61` | 16 字节（`aescmac.BlockSize`，`internal/mac/aescmac/aescmac.go:27`） | 返回错误 `invalid output length` | 推荐 32 字节（`ValidateAESCMACPRFParams`，`aes_cmac.go:44-49`） |
| HMAC PRF | `prf/subtle/hmac.go:60-67` | 哈希输出长度（SHA-256→32，SHA-512→64） | 返回错误 `outputLength must be between 0 and N` | ≥16 字节（`minHMACKeySizeInBytes`，`hmac.go:26`） |
| HKDF PRF | `prf/subtle/hkdf.go:70-78` | HKDF 流上限（RFC 5869：255×HashLen） | `io.ReadAtLeast` 失败时返回错误 | ≥32 字节（`minHKDFKeySizeInBytes`，`hkdf.go:31`）；哈希仅允许 SHA-256/SHA-512（`hkdf.go:63-65`） |

接口层面的约定（`prf_set.go:49-63`）：`ComputePRF` 在算法失败或底层算法输出不足
`outputLength` 时返回非 nil 错误；调用方需按生日界选取长度（建议
`ceil(n/4 + 4)` 字节，对应 2n+32 位，碰撞概率 < 1:2³²）。

## 5. 责任分层总结

| 层 | 位置 | 责任 |
|---|---|---|
| keyset 校验 | `keyset/validation.go` | 拒绝非 ENABLED 主键、无主键、多主键的密钥集 |
| 状态过滤 | `internal/factoryutil/factoryutil.go:53` | 仅 Enabled 条目进入构造；Disabled/Destroyed 键不可派生 |
| 工厂 | `prf/prf_set_factory.go` | 用各条目自己的密钥材料建 PRF，以各条目自己的 key ID 入 map，记录主键 ID |
| 路由 | `prf/prf_set.go` (`Set`) | 按 ID 查找并委托；主键缺失时报错而非顶替 |
| 监控 | `prf/prf_set.go` (`monitoredPRF`) | 以实际求值键的 ID 记录日志 |
| 算法实现 | `prf/subtle/*.go` | 输出长度上限校验、密钥参数校验、实际计算 |

结论：在该实现中，主键只是一个指向 map 中某个条目的游标。每把仍 Enabled 的密钥
在 `Set.PRFs` 中以自己的 key ID 持有独立的 PRF 实例，其输出身份永远属于它自己；
不可用键在工厂阶段即被排除，不存在"禁用键仍可派生"的解释空间。
