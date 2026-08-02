# openai-paypal

面向授权 CTF 环境的 PayPal Billing Agreement 协议流程工具。项目保留一个 `PayPalFlow`：标准路线可使用 Chromium 取得动态页面、Cookie 与浏览器风控信号；纯协议路线使用固定 iOS/CriOS 136 身份和 HTTP/1.1。OTP、Signup、Buyer Funding 和 authorize 使用 HTTP GraphQL。

> 仅限已获授权、且 PayPal 域名已经劫持到 CTF 的环境。不要把它用于真实 PayPal、真实卡片或未授权账号。

## 支持范围

输入可以是原始 `BA-...`，也可以是完整 URL：

```text
https://www.paypal.com/agreements/approve?ba_token=BA-...
```

国家由 E.164 手机号自动选择，Web 页面不需要国家选择器：

| 国家 | 前缀 | Locale | Language | GraphQL | Timezone |
| --- | --- | --- | --- | --- | --- |
| 巴西 BR | `+55` | `pt_BR` | `pt-BR` | `pt` | `America/Sao_Paulo` |
| 泰国 TH | `+66` | `en_GB` | `en-TH` | `en` | `Asia/Bangkok` |
| 波黑 BA | `+387` | `en_US` | `en-BA` | `en` | `Europe/Sarajevo` |
| 美国 US | `+1` | `en_US` | `en-US` | `en` | `America/Chicago` |

- 初始手工号码必须是 `+55`、`+66`、`+387` 或 `+1` 的严格 E.164 格式；所有 `+1` 号码均路由到 US。
- OTP 阶段可以换同国号码；跨国换号会被拒绝，需要新建任务。
- SMSBower 仅支持 BR；SMSBower 模式不填手机号时默认 BR。
- CPF/`identityDocument` 只在 BR 生成和提交；TH/BA/US 完全省略字段。
- Web 默认对 BR/TH/BA/US 使用严格地址自动补全；关闭开关后使用本地 MANUAL 地址。
- 四国共用 CTF 卡池 `414709/516292`，不会生成 `403203`。

成功结果包含授权状态、Billing Agreement Token、Payment Action、Buyer ID 和脱敏 Return URL。程序不会访问 Return URL 指向的 Stripe 或商户站点。

## Python 安装

要求 Python 3.10+；推荐 Python 3.12。

Windows PowerShell：

```powershell
py -3.12 -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements-headless.txt
.\.venv\Scripts\python.exe -m playwright install chromium
```

Linux/macOS：

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements-headless.txt
python -m playwright install chromium
```

可复制环境变量模板：

```bash
cp .env.example .env
```

不要提交 `.env`、OTP、Cookie、手机号、抓包或 access token。程序侧 traffic recorder 默认只记录脱敏元数据/body 哈希；Web 明确勾选“记录流量”时会额外把完整响应体写入 Git 忽略的私有 capture body 文件，但请求体、Cookie header 和事件索引中的 token URL 仍保持脱敏。

## 命令行

```bash
python main.py \
  --ba-token "https://www.paypal.com/agreements/approve?ba_token=BA-..." \
  --phone +66000000000 \
  --fingerprint-source headless \
  --datadome-mode headless \
  --mtr-runtime headless \
  --risk-signals-mode headless
```

BR 的 SMSBower 模式：

```bash
python main.py --ba-token BA-... --smsbower --smsbower-api-key YOUR_KEY
```

authorize 最多两次：首次返回 `BUYER_NOT_SET` 时只刷新 review/funding 上下文并重试一次；不会重新 Signup 或换卡。

## Web UI

```bash
python web.py --host 127.0.0.1 --port 8080
```

访问 [http://localhost:8080](http://localhost:8080)。健康检查：

```bash
curl http://127.0.0.1:8080/api/health
```

手动任务会在 OTP 阶段暂停。此时输入 6 位验证码、同国新手机号，或输入 `q` 退出。

“地址自动补全”默认开启：程序在发送 OTP 前执行浏览器同款的候选搜索和 place-id 完整地址解析，并将成功结果标记为 `GOOGLE`。搜索、解析、国家或必填字段校验任一步失败都会立即终止，不会消耗短信接码；关闭后直接使用本地 `MANUAL` 地址。SMSBower 设置默认折叠，需要时再展开启用。

Web 的“执行路线”有三种：

| 路线 | 行为 |
| --- | --- |
| 标准完整流程 | 保留现有 Roxy、Headless、程序随机和自动模式选择；默认路线。 |
| 纯协议到 Signup | 固定使用 iOS 18、CriOS 136、HTTP/1.1 与协议风控，只验证有效 `/checkoutweb/signup` 200，然后在发送 OTP 或注册请求前停止。必须填写 E.164 手机号，不使用 SMSBower。 |
| 纯协议完整流程 | 使用同一固定协议 Profile 继续 OTP、Signup、Funding 和 authorize；不会创建 Roxy 窗口。 |

两种纯协议路线由服务端强制使用 `random / protocol / python_generated / protocol` 和 `curl-chrome-http1`；不会被 `.env` 中的 Roxy 默认值或客户端提交的 runtime 字段覆盖。Web 表单中的 BA 和手机号仍然生效。

Web 不再提供环境变量代理、自定义代理或代理开关。服务端从 Git 忽略的 `var/signup-lab/inputs-ba.toml` 读取第一条代理作为账号模板，只使用其中的 host、port、账号结构和密码；BA、手机号及游标不会从该文件导入。每个 Web 任务按手机号国家重写 `region`，并生成新的 8 位 SID。任务列表和日志展示 host:port、region 与 SID，密码始终隐藏。

纯协议到 Signup 成功时，任务结果包含 HTTP 状态、脱敏 signup URL、approval 结构诊断、`roxy_api_calls=0` 和 `stopped_before_signup_mutation=true`。如果 approval 没有形成有效应用或 signup 被 challenge，任务标为 failed，但保留脱敏分类结果供排查。

纯协议完整流程会在发送 OTP 前再次验证 signup 文档：必须是有效的 `/checkoutweb/signup` HTTP 200 应用页面；`genericError`、challenge、重定向或缺少应用内容都会立即终止。OTP 诊断分别显示 HTTP 状态和 `business_success/state/errors`，只有 Confirm 响应体明确返回 `state=CONFIRMED` 且没有 GraphQL errors 才算验证码业务成功。

## Windows Docker Desktop

构建并启动：

```bash
docker compose build
docker compose up -d
docker compose ps
```

访问 [http://localhost:8080](http://localhost:8080)，查看日志：

```bash
docker compose logs -f openai-paypal
```

Docker 容器不一定继承 Windows 的 hosts 文件。如果宿主机通过 hosts 劫持域名，需要在 `docker-compose.yml` 为实际 CTF IP 配置 `extra_hosts`，或让 Docker 使用同一 CTF DNS。

如果宿主机 8080 已被占用，可指定其他端口：

```bash
PAYPAL_WEB_PORT=18080 docker compose up -d
```

此时访问 `http://localhost:18080`；容器内仍监听 8080。

停止容器：

```bash
docker compose down
```

## 状态机要点

- Signup 成功，或错误响应已经带 access token/EUAT 时，标记 `signup_committed=True`。
- committed 后绝不再次发送 SignUpNewMember。
- 只有无 token 的 addCard/`validate.fi` 卡片错误才换 CTF 卡，最多使用配置的重试次数。
- Funding 的 `NON_PAYABLE` 在存在有效 payer 上下文时允许继续。
- `PAYER_ACCOUNT_RESTRICTED` 映射为 `IDENTITY_ELEVATION_PAYER_RESTRICTED` 并终止。
- HTTP、Schema 或 GraphQL 结构不匹配映射为 `BUYER_FUNDING_CONTEXT_FAILED`。

## 测试

```bash
python -m pip install -r requirements-dev.txt
python -m pytest -q
```

自动化测试不访问 PayPal，全部使用构造响应或脱敏 fixture。它们覆盖四国路由/时区、CPF/state 序列化、共享 CTF 卡池、Signup committed 状态机、Funding 分类、authorize 单次刷新重试及日志脱敏。

## 主要文件

```text
main.py                                  CLI
web.py                                   本地 Web/API
paypal/country.py                        国家、手机号、BA 输入与时区
paypal/flow.py                           单一 PayPalFlow
paypal/graphql.py                        固化 GraphQL 文档
paypal/funding.py                        Funding 结果分类
tests/                                   离线 pytest
Dockerfile / docker-compose.yml          Windows Docker Desktop 运行配置
```
