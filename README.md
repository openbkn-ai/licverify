# licverify

OpenBKN 产品侧 License 验证 SDK。纯标准库、零第三方依赖，完全离线工作——
验签、有效期判定、机器码、激活绑定自校验都在本地完成，不依赖签发服务在线。

```bash
go get github.com/openbkn-ai/licverify
```

## 用法

```go
import "github.com/openbkn-ai/licverify"

// 验签公钥编译期内置（来自签发方发布的 kid → base64 公钥）
keys := map[string]ed25519.PublicKey{"2026-07": pub}

// 四态门控判定：有效 / 宽限（功能保持）/ 回落社区（曾授权）/ 无效
state, p := licverify.Eval(licenseText, keys)

// 机器码 + 激活绑定自校验：复制来的 license 离线即拒
localFP, _ := licverify.Fingerprint()
if state != licverify.StateInvalid && licverify.VerifyBound(p, localFP) != nil {
    state = licverify.StateInvalid
}

switch state {
case licverify.StateValid, licverify.StateGrace:
    if p.HasFeature("rbac_basic") { /* 开启能力 */ }
    if n := p.Limit("max_users"); n != -1 && userCount > n { /* 拒绝新增 */ }
case licverify.StateFallback:
    // 商业授权过期但签名可验 = 曾授权，自动降级社区能力集，数据保留
case licverify.StateInvalid:
    // 未激活：只开放激活引导与数据读取/导出
}
```

## License 格式

```
v1.<base64url(payload)>.<base64url(Ed25519 签名)>
```

签名覆盖传输的原始 payload 字节，验签不重新序列化（无 JSON 规范化问题）。
payload 携带 `edition` / `features` / `limits` / `expires_at` /
`contract_expires_at`（`0` = 永不过期）/ `hw_fingerprint`（激活后绑定）。

## 机器码（实例指纹）

```
fp = "fp_" + hex( SHA-256( salt + identity )[:8] )
```

identity 按优先级：`OPENBKN_INSTANCE_ID` 环境变量 → machine-id（Linux/macOS/Windows）→
物理网卡 MAC。算法公开，不靠保密——防复制的强制力在签发服务端（一码一激活 first-wins + 续期校验绑定）。

| 部署形态 | 做法 | 指纹标识什么 |
|---|---|---|
| 裸机 / 虚机 | 默认即可（machine-id） | 这台主机 |
| 单机 Docker | 挂载 `-v /etc/machine-id:/etc/machine-id:ro` | 这台主机（与主机一致） |
| K8s | `OPENBKN_INSTANCE_ID` = 集群稳定标识 | 这套集群 |

离线激活：`ActivationCode(licID, fp)` 生成申请码 → 客户门户兑换绑定指纹的回执 license。

## 安全模型

本库**公开无损安全**：验签用公钥，没有签发私钥就伪造不出 License（私钥只存在于
签发服务，不在本仓库）；指纹算法与盐不是秘密——防复制的强制力在签发服务端
（一次性激活 first-wins + 续期校验绑定），伪造指纹骗不过服务端记录。
客户端反篡改明确**不是目标**：验证代码运行在使用方环境，技术上不设防，
授权约束力在合同与审计。

payload 字段与状态语义是签发方与产品方的**长期契约**：v0.x 期间字段可能调整，
冻结后升 v1 并按 semver 演进。

## API 一览

| 函数 | 作用 |
|---|---|
| `Verify / VerifyAt` | 验签 + 有效期检查，返回 payload |
| `Parse` | 只验签不查有效期（判定"曾授权"用） |
| `Eval` | 四态门控判定（valid / grace / fallback_community / invalid） |
| `Fingerprint / FingerprintFrom` | 本机 / 自定义身份的实例指纹 |
| `VerifyBound` | license 绑定指纹 = 本机指纹自校验 |
| `ActivationCode` | 离线激活申请码 |
| `ParsePublicKey` | 解析签发方发布的 base64 公钥 |

