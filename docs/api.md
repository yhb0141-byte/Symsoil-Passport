# API、签名协议与 NFC

所有写请求使用 `Content-Type: application/json`，正文上限 64KB。除公开配置和明确开启的本地试用入口外，接口需要 `Authorization: Bearer <角色凭证>`。凭证不得写入 NFC 标签。

## 路由

| 方法与路径 | 角色 | 用途 |
| --- | --- | --- |
| `GET /api/config` | 公开 | 社区、协议版本、试用开关和服务时间 |
| `POST /api/demo/session` | 试用且本机 | 获取本地试用角色；普通模式关闭 |
| `GET /api/me` | 成员 | 自己的积分、事项、回执、卡片入口和授权 |
| `GET /api/me/export` | 成员 | 导出完整的本人成员记录与核验公钥 |
| `POST /api/devices` | 成员 | 首次登记 P-256 公钥；不覆盖现有设备 |
| `GET /api/admin` | 核定人 | 社区运营和审计记录 |
| `POST /api/members` | 核定人 | 创建零起始积分的成员 |
| `GET /api/credentials` | 核定人 | 入口元数据，不含凭证原文或哈希 |
| `POST /api/credentials` | 核定人 | 签发限时角色入口；原文仅本次返回 |
| `POST /api/credentials/:id/revoke` | 核定人 | 撤销入口；不能撤销最后一个有效核定人入口 |
| `GET /api/terminal` | 终端或核定人 | 自身终端的兑换单、扣分及退回交付状态 |
| `POST /api/contributions` | 核定人 | 核定贡献单 |
| `POST /api/orders` | 终端或核定人 | 建立固定目录价格的兑换单 |
| `POST /api/refunds` | 核定人 | 按未交付原扣分记录建立退回单 |
| `POST /api/nfc/scan` | 终端或核定人 | 把账户入口关联到具体积分单据 |
| `POST /api/requests` | 核定人 | 发起借用、转述或有限授权 |
| `GET /api/requests/:id` | 本人成员 | 读取完整待确认事项 |
| `POST /api/requests/:id/view` | 本人成员 | 记录查看，不产生批准 |
| `POST /api/requests/:id/respond` | 本人成员 | 提交设备签名回复 |
| `POST /api/requests/:id/cancel` | 本人成员 | 关闭未回复事项 |
| `POST /api/requests/:id/revise` | 核定人 | 生成新版本；积分单不得改写 |
| `POST /api/members/:id/revoke-device` | 核定人 | 停用旧设备、卡片与成员入口，取消待回复事项及未使用授权 |
| `POST /api/orders/:id/fulfill` | 该单终端 | 扣分后登记交付 |
| `POST /api/grants/:id/revoke` | 本人成员 | 撤销授权 |
| `POST /api/grants/:id/execute` | 对应执行者 | 执行获准的精确单次行动 |

核定人也可承担终端角色，但订单始终绑定创建时的角色主体。核定人的订单不能交给另一个终端身份操作；界面同时持有两种凭证时，创建、扫描和交付统一使用终端凭证。

成员创建正文为 `{"name":"共创伙伴","id":"M-019"}`，可省略 `id` 自动生成。重复相同编号与名称返回已有成员，不重复创建账户；同一编号改成其他名称会拒绝。

签发正文为 `{"role":"member","subject":"M-019","ttlHours":168,"label":"社区访问入口"}`。角色可为 `member`、`admin`、`terminal` 或 `agent`；成员必须已存在，小壤执行者主体固定 `xiaorang`。有效期1–720小时，默认168小时，小壤默认24小时。返回 `{"credential":{...元数据},"token":"...仅本次返回的访问凭证"}`。数据库只存 SHA-256 哈希，审计记录不存原文。

核定人入口轮换应先签发并保存替代入口，验证新入口可用，再撤销原入口。失物换机会撤销该成员的所有访问凭证，旧凭证不能用新密钥重新进入；需核定人核对持有人后重新签发。

`GET /api/terminal` 包含固定资源目录和本终端订单，订单给出是否扣分、退回中、已退回及交付状态，没有成员余额或私有回复历史。独立页面 `/operator.html` 使用这些入口，成员凭证不必交给终端。

## NFC 数据与积分流程

标签使用一个 NDEF UTF-8 文本记录，值为：

```text
sp:1:<32字符的随机base64url账户引用>
```

文本总长 37 个 ASCII 字节。读取结果须完整匹配前缀与长度；服务端再核验是否已登记、仍有效及是否对应单据成员。标签本身不证明持有人身份。

贡献单正文：

```json
{"id":"CT-001","memberId":"M-017","title":"菜园维护","points":30}
```

兑换单正文：

```json
{"id":"EX-001","itemId":"harvest"}
```

NFC 扫描正文：

```json
{"cardPayload":"sp:1:<实际登记的账户引用>","kind":"order","sourceId":"EX-001"}
```

`kind` 可为 `contribution`、`order` 或 `refund`。首次兑换扫描将单据绑定成员，返回 `{"requestId":"..."}`。已经记账的同一单据返回 `{"completed":true,"transactionId":"..."}`；终端不会获得余额、签名公钥或成员私有历史。单纯读取或扫描不记账。

写标签通过 `public/nfc.mjs` 中的 `writeCard()`；读标签通过 `scanCard()`。标签接口只处理 NDEF 账户入口，不支持安全卡 APDU、价值文件、UID 验证或对 MCU 的余额写入。

## 设备签名

设备登记仅接受公开 JWK：`kty=EC`、`crv=P-256`、`x`、`y`。不接收私钥字段。设备编号由公钥摘要派生。

内容摘要为 SHA-256，输入使用 `public/protocol.mjs` 的 `canonical()` 序列化：对象键按 JavaScript 默认字符串顺序排序；数组保序；只接受 null、布尔、字符串和安全整数。当前协议无浮点数。硬件移植须通过相同序列化测试，不能用普通 JSON 输出顺序代替。

签名输入为下面这个对象的 canonical UTF-8 字节：

```json
{
  "protocol":"symsoil-passport/1",
  "communityId":"jiuhua-symsoil",
  "requestId":"<具体请求ID>",
  "requestDigest":"<完整内容SHA-256>",
  "requestVersion":1,
  "nonce":"<服务端一次性挑战>",
  "expiresAt":0,
  "memberId":"M-017",
  "deviceId":"<登记设备ID>",
  "decision":"spend",
  "counter":1
}
```

`expiresAt` 使用请求返回的真实毫秒时间戳。签名算法 ECDSA P-256 / SHA-256；编码为 64 字节 IEEE-P1363 `r || s`，再做无填充 base64url。不是 ASN.1 DER。浏览器私钥不可导出；硬件实现须在设备内签名。

回复正文只有：

```json
{"deviceId":"<登记设备ID>","decision":"spend","counter":1,"signature":"<base64url签名>"}
```

服务端依据所存完整请求重建签名帧，核验签名、角色、成员、版本、有效期、状态和单调计数器。同一成功回执可原样重试，不重复记账。改变回复或把签名搬到其他事项会失败。计数器可以跳号，失败后不必回退。

浏览器设备先持久化完整签名再发送。网络错误或5xx不能证明事务没有成功；保留原回复，重连后原样核对。已经有相同回执时，读取结果或原签名重试不会再次记账。明确的4xx拒绝会释放本地待核对回复；用户需重新读取当前事项，不自动补签。只有签名准备阶段中断且未保存完整签名的占位才会在60秒后释放；已保存的签名不会据本地超时自动删除。

挑战的有效期为两分钟，避免沉默变成默认同意。卡片必须先显示完整正文和明确的选择，摘要前缀不能替代正文阅读。回执保存后不可改写；新的语义需要新的事项。

## 错误

错误格式为 `{"error":{"code":"...","message":"..."}}`。常见类型：

| 状态 | 代码示例 | 处理 |
| --- | --- | --- |
| 400 | `INVALID_CARD`、`INVALID_DECISION`、`INVALID_COUNTER` | 检查格式，不自动重试确认 |
| 401 / 403 | `UNAUTHORIZED`、`FORBIDDEN`、`BAD_SIGNATURE` | 检查身份、设备登记或签名 |
| 404 | `REQUEST_NOT_FOUND`、`SOURCE_NOT_FOUND` | 检查本人归属和终端单据 |
| 409 | `STALE_VERSION`、`REQUEST_EXPIRED`、`REPLAY` | 重新读取当前事项，重新征询 |
| 409 | `INSUFFICIENT_POINTS`、`OUT_OF_STOCK` | 本次事务回滚，告知成员 |
| 409 | `IDEMPOTENCY_CONFLICT`、`GRANT_CONSUMED` | 保留原操作结果，勿更改单号重放 |
| 413 / 415 | `BODY_TOO_LARGE`、`JSON_REQUIRED` | 更正请求格式 |

## 接入外部设备

本地 USB/NFC 读卡端可读取同一 NDEF 文本，然后用单独终端凭证调用 `/api/nfc/scan`。设备签名桥接端需持有本人成员会话，从 `/api/requests/:id` 获取完整内容，把已登记工牌返回的签名原样提交；桥接端不得代替工牌重新签名。

下一阶段 BLE 帧、配对、分片、断线重连与固件签名尚未实现。现有签名帧可以复用，但这份 HTTP 接口不是现成 BLE 固件。硬件要求见 [firmware/README.md](../firmware/README.md)。

固定协议向量位于 `firmware/protocol-vectors/confirmation-v1.json`，仅含合成内容、公钥与签名。Node 和独立 Python 实现已核验 UTF-16 键序、UTF-8 内容、控制字符与孤立代理字符的编码、P1363签名及篡改失败。见 [向量说明](../firmware/protocol-vectors/README.md)。
