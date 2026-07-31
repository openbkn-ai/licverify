# licverify

OpenBKN 产品侧 License 验证 SDK。纯标准库、零第三方依赖，完全离线工作——
验签、有效期判定、机器码、激活绑定自校验都在本地完成，不依赖签发服务在线。

```bash
go get github.com/openbkn-ai/licverify
```

## 用法

```go
import (
    "github.com/openbkn-ai/licverify"
    "github.com/openbkn-ai/licverify/keys"   // 官方验签公钥表（单一来源）
)

// 门控判定：有效 / 宽限（功能保持）/ 回落社区（曾授权）/ 无效
state, p := licverify.Eval(licenseText, keys.Official())

// 无证时（全新安装）：试用窗口内静默，之后转为常驻激活提示。
// 两者都跑社区能力集——从不因未激活而收走功能。
state = licverify.TrialAt(firstRunUnix, time.Now())   // StateTrial / StateUnlicensed

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
出厂烧录的网卡 MAC。算法公开，不靠保密——防复制的强制力在签发服务端（一码一激活 first-wins + 续期校验绑定）。

| 部署形态 | 做法 | 指纹标识什么 |
|---|---|---|
| 裸机 / 虚机 | 默认即可（machine-id） | 这台主机 |
| 单机 Docker | 挂载 `-v /etc/machine-id:/etc/machine-id:ro` | 这台主机（与主机一致） |
| K8s | 安装器在宿主上读 `/sys/class/dmi/id/product_uuid`，注入 `OPENBKN_INSTANCE_ID` | 这台宿主机 |

K8s 那条有一个**不可妥协的约束：安装器只能从宿主推导，绝不能随机生成**。
派生是幂等的（同一台机器跑多少次都是同一个值，升级、重装都自洽）；随机生成的
UUID 存储丢了就指纹漂移，配置被复制到别的机器又会跟着跑。

MAC 兜底只收出厂烧录（globally administered）的地址。容器 `eth0`、veth、网桥、
hypervisor tap 用的是启动时临时分配的 locally administered 地址（首字节 `& 0x02`
置位），拿它算指纹会在 Pod 重建后静默变化、让已激活的证失效——这类地址一律拒绝，
候选为空时返回 `ErrNoFingerprint`，**宁可启动报错也不给一个会漂的值**。

离线激活：把 `Fingerprint()` 的设备指纹（`fp_…`）粘贴到客户门户 → 兑换绑定指纹的激活证书（新 `.lic`）。

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
| `Eval` | 持证判定（valid / grace / fallback_community / invalid） |
| `TrialAt / TrialRemaining` | 无证判定（trial / unlicensed）与剩余试用时长 |
| `Fingerprint / FingerprintFrom` | 本机 / 自定义身份的实例指纹 |
| `VerifyBound` | license 绑定指纹 = 本机指纹自校验 |
| `ParsePublicKey` | 解析签发方发布的 base64 公钥 |

