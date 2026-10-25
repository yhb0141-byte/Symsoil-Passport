# 已受理回执的服务签名结果

服务器现在可以为确实保存的原回复出具 `symsoil-delivery-result/1` 签名结果，供工牌核对后清除待发记录。签名服务为可选配置，默认关闭；当前浏览器提交方式保持兼容。

## 查询同一笔结果

```http
POST /api/requests/<原事项ID>/delivery-result
Authorization: Bearer <本人成员凭证>
Content-Type: application/json

{"signature":"<原成员签名的base64url>","transferId":42}
```

仅成员可以查询自己的事项，管理员、兑换终端和小壤的凭证不能调用。桥接端必须持有对应成员会话，不能用一个共享终端凭证读取所有人的回执。

服务先找到该成员已持久化的原回执，逐字匹配原签名，再用保留的设备公钥核验历史帧与事项、成员、设备和回复含义。查询不再次调用 `respond`，不增加积分流水、不消费计数器、不执行授权，也不发布新的回复事件。凭证在请求正文接收完后、同一数据库写锁下重新校验，上传期间撤销的旧凭证不能取得签名结果。

成功返回：

```json
{
  "frame": {
    "communityId": "jiuhua-symsoil",
    "outcome": "accepted",
    "protocol": "symsoil-delivery-result/1",
    "replySignature": "<原成员签名>",
    "requestId": "<原事项ID>",
    "resultId": "<已保存回执ID>",
    "transferId": 42
  },
  "signature": "<服务P-256签名，64字节P1363的base64url>",
  "trustEpoch": 1
}
```

签名覆盖 `canonical(frame)` 的完整 UTF-8 字节。`resultId` 是稳定的原回执 ID；查询重试可能生成不同的合法 ECDSA 签名字节，但不改变原业务结果。接口将请求提供的非零 uint32 `transferId` 纳入服务签名。当前工牌对同一待核对回执重连时必须沿用已持久化的传输号和原封装字节，不能因断线重新编号；服务结果的传输号必须与该记录一致。

**`accepted` 表示原回复已被记录，不表示成员同意。** 成员回复 `decline` 或 `no_retelling` 时，也会得到“这份拒绝回复已被记录”的结果，不生成授权、不扣分。读取原成员签名绑定的回复含义，不能把传输结果当作治理立场。

`trustEpoch` 是未纳入结果签名的诊断元数据，不能单独更新工牌信任配置或作为当前有效性的证明。工牌只使用本地已通过恢复根验证的服务公钥核验结果；外层 metadata 不能替换这把钥匙。

没有原回执时返回 `409 RESULT_NOT_RECORDED`，签名不一致时返回 `409 RECEIPT_MISMATCH`，持久记录校验失败时返回 `409 RECEIPT_INVALID`，均不生成最终签名。余额不足、尚未送达和可重试错误不能据此产生永久 `rejected` 凭证。当前 HTTP 接口只出具已受理回复的 `accepted` 证明；协议保留的最终 `rejected` 路径尚未接入业务。

已记录的历史回复在事项过期、改版或旧设备停用后仍是历史事实；核对持有人并发放新成员凭证后可继续查询。查询不会重新激活旧设备或已撤销授权。设备挂失时旧凭证仍立即失效。

## 启动配置

需要三份由运营者独立提供的文件：服务 P-256 私钥 JWK、恢复根签署的有效服务配置包、独立核对的恢复根公钥 JWK。签发流程见 [固件信任配置](firmware-trust.md)。服务器不需要恢复根私钥。

```sh
PASSPORT_SERVICE_KEY_FILE=/secure/service-private.jwk.json \
PASSPORT_SERVICE_TRUST_FILE=/secure/service-public-bundle.json \
PASSPORT_AUTHORITY_PUBLIC_FILE=/secure/pinned-authority-public.jwk.json \
npm start
```

三项都未配置时正常启动，`/api/config` 的 `signedDeliveryResults.enabled` 为 `false`，结果接口返回 `503 DELIVERY_SIGNING_UNAVAILABLE`。部分配置、根签名无效、社区不匹配、配置已停用或私钥不匹配时拒绝启动，不临时生成可信钥匙。

配置文件只读加载，不修改原文件。每份须为不超过64KiB的普通文件，不能是符号链接；POSIX 下私钥文件不能允许组或其他用户读写执行，可用 `chmod 600`。私钥、真实配置、访问凭证和数据库不提交 Git。服务私钥目前在受控服务器文件及进程内使用，不宣称由硬件安全元件保护。

加载后签名器持有不可变快照。换钥需先签发更高版本的服务配置、按本地流程让工牌接受它，再重新启动服务器加载新服务私钥和配置包。旧工牌尚未更新时不能验证新钥匙结果，应保留待核对回执。服务器重启不能替代工牌的版本下限检查，也没有热加载或自动轮换守护进程。

## 本地配置与验证范围

`passport_provision` 提供本地配置状态机：验证根签名与社区，展示完整根指纹，第一阶段按下并松开 OK 表示完成指纹核对，再在最终复核页重新连续按住 OK 两秒，才调用信任层写入。短按、提前松手、其他按键、取消、超时、时间倒退、配置或根变化均不提交；失败后原确认不能复用。恢复模式必须明确提供独立核对的版本下限。

该状态机尚未连接真实屏幕或按键。它不能证明调用它的代码收到了真实物理事件；集成层必须只从可信本地设置入口启动，并在按键事件丢失、队列溢出或松手状态不确定时取消。所有事件和完成写入由同一生命周期/工作任务串行处理，不能在 BSP 定时器回调里执行签名验证和 NVS 写入。

`npm run test:firmware-host` 会临时生成合成 HTTP 交易：真实调用回复接口和结果接口，然后用 C 验证成员签名、完成本地配置复核、逐字节核对结果帧、验证服务签名并清除原回执。临时头文件只有合成标识、公钥和签名；私钥和访问凭证只在测试进程中使用。该互验采用 OpenSSL，未通过真实 BLE 传输，也不是已刷入工牌的 mbedTLS/NVS 实测。
