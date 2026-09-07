# Eclipse Recon

Eclipse Recon 是一个面向授权安全测试和资产运营的资产侦察平台。它将任务编排、资产管理、HTTP 记录、指纹与 PoC 库、代理池、测绘 API 配置和 MCP 工具集中在一个 Web 控制台中。

项目由 Go 后端和 React/Vite 前端组成，使用 PostgreSQL 持久化业务数据，Redis 保存运行时状态与缓存。界面采用深色 ctOS 风格，前端按路由懒加载。

> 仅对你拥有或明确获准测试的资产使用扫描、PoC、代理和 MCP 能力。

## 功能概览

- 任务编排：创建、启动、取消、删除和导出扫描任务，支持策略和实时进度。
- 授权范围护栏：按项目维护精确域名、通配子域、IP 与 CIDR 允许/排除规则；默认或显式范围贯穿手工任务、企业下发、计划任务、连续监控、手工 PoC 和 MCP，并在每条主动网络路径执行前复核。
- 持久化执行队列：任务先入库排队，再由受全局并发限制的 Worker 原子领取；服务重启不会丢失等待中的任务。
- 资产管理：跨任务规范化域名、IP、端口与站点，保留观测、关系证据和语义变化时间线，并聚合漏洞与暴露面风险；同时支持 URL、HTTP 记录和资产分组。
- 狩猎线索：从确认漏洞、接管候选、敏感服务、管理入口、PoC 匹配和攻击面变化中生成全局优先级队列，支持调查状态、个人笔记和资产工作台联动；Web 与 MCP 的线索验证共用来源任务授权范围，并保存可回看的结构化执行审计链。PoC 命中会原子固化为去重的漏洞证据、关联资产风险并更新研判状态，可直接进入任务报告。
- 赏金证据：任务风险支持独立查看、单项复制和完整证据包复制；可导出带完整证明的离线安全 HTML 报告。
- 侦察能力：域名发现、端口探测、服务识别、站点探测、爬虫、截图、指纹匹配、文件泄露检测和 PoC 检测。
- 库管理：编辑和导入指纹 DSL、Nuclei 与受控 Custom HTTP PoC，支持分类、严重级别和匹配模式。
- 代理池：HTTP、HTTPS、SOCKS5，支持认证、批量导入、批量验证、健康检查、轮询和自动轮换。
- 空间测绘：预置 FOFA、Hunter、360 Quake、ZoomEye、Shodan、VirusTotal、GitHub，可逐条保存、启停和验证凭据；加密凭据不会回传浏览器。
- 企业资产发现：通过可插拔 ICP_Query 协议查询网站、APP、小程序和快应用；任务持久化排队，域名可批量同步到全局资产清单/资产分组或下发扫描，并保留企业来源观测与语义变化。
- 自动化：资产监控、NVD CVE 产品关键词监控、计划任务、执行记录和日志；支持定时或立即执行并复用通知通道。
- MCP：可选的 Streamable HTTP MCP 端点，提供任务、资产、库、配置和导出工具。
- 高级检索：支持字段限定、括号、双引号、AND、OR、NOT 和表头单列筛选。
- 模块化前端：视图、组件、接口、状态、工具和样式分层，路由级按需加载。

## 技术栈

- Backend：Go 1.24、Gin、GORM、PostgreSQL、Redis
- Frontend：React 19、Vite、Tailwind CSS 4、Lucide、Motion
- Browser automation：Chromium、chromedp
- Protocol：REST、WebSocket、Streamable HTTP MCP

## 快速开始

### Docker Compose

前置条件：

- Docker Engine 24+
- Docker Compose v2
- 至少 2 GB 可用内存；大规模扫描或截图任务建议更多

克隆并创建环境文件：

~~~bash
git clone https://github.com/Gi1gamesh123/Eclipse-Recon.git
cd Eclipse-Recon
cp .env.example .env
~~~

编辑 .env，至少替换以下值：

~~~dotenv
DB_PASSWORD=一段随机数据库密码
REDIS_PASSWORD=一段随机Redis密码
ADMIN_USERNAME=admin
ADMIN_EMAIL=admin@example.com
ADMIN_PASSWORD=至少12个字符的管理员密码
~~~

构建并启动。推荐使用发布脚本，它会先校验配置；已有数据库运行时会在自动迁移前创建压缩备份，并等待 PostgreSQL、Redis 和后端全部就绪：

~~~bash
./scripts/production-up.sh
~~~

也可以直接运行 `docker compose up -d --build`。平台可直接通过 HTTP 暴露；如 UI 和 API 使用同一地址，`CORS_ALLOWED_ORIGINS` 保持为空。分离部署前端时再填写明确的来源列表，禁止使用 `*`。

服务地址：

- Web 控制台：http://localhost:5003
- 健康检查：http://localhost:5003/health
- 依赖就绪检查：http://localhost:5003/ready
- PostgreSQL：仅绑定本机 127.0.0.1:15432
- Redis：仅绑定本机 127.0.0.1:16379

首次启动时 init-admin 容器会创建管理员。JWT 和加密密钥会自动生成到 Docker 数据卷中。不要删除 .storage/app/data，否则已有加密配置可能无法恢复。

手工创建数据库备份：

~~~bash
./scripts/backup.sh
~~~

备份保存在 `.storage/backups/`。发布脚本不会自动删除历史备份。

停止服务：

~~~bash
docker compose down
~~~

删除所有本地数据会永久清空数据库、密钥和日志：

~~~bash
docker compose down -v
rm -rf .storage
~~~

### 启用 MCP

MCP 只有在启用开关和密钥同时有效时才会挂载。Docker 可在 `.env` 中配置至少 32 个字符的密钥：

~~~dotenv
MCP_API_KEY=请生成一段至少32字符的随机密钥
~~~

重启后端并确认状态：

~~~bash
docker compose up -d backend
curl http://localhost:5003/health
~~~

健康检查返回 mcp_enabled: true 后，MCP 地址为：

~~~text
http://localhost:5003/mcp
~~~

MCP 请求必须携带：

~~~http
Authorization: Bearer <MCP_API_KEY>
~~~

本地直接运行时无需 Docker，后端配置已开启 MCP，启动进程时传入密钥即可：

~~~bash
cd backend
MCP_API_KEY='请替换为至少32字符的随机密钥' go run ./cmd/server
~~~

也可用 `MCP_ENABLED=false` 临时关闭端点。当前 MCP 优先支持全局资产清单、聚类攻击线索、证据工作台、研判状态和授权 PoC 验证工作流。

## 本地开发

需要 PostgreSQL、Redis、Go 1.24+、Node.js 20+ 和 npm。

### 后端

~~~bash
cd backend
cp configs/config.docker.yaml configs/config.yaml
# 按本机环境修改 database、redis、server 等配置
go run ./cmd/init-admin
go run ./cmd/server
~~~

本地配置文件 backend/configs/config.yaml 不会被提交。如果 JWT 或加密密钥为空，服务会在 data/.jwt-secret 和 data/.encryption-key 自动生成权限为 0600 的随机密钥。

重置管理员密码：

~~~bash
cd backend
go run ./cmd/init-admin --reset-password admin
~~~

### 前端

~~~bash
cd backend/web
npm install
npm run dev
~~~

Vite 默认运行在 http://localhost:5173，API 开发代理配置见 [backend/web/vite.config.js](backend/web/vite.config.js)。

生产构建：

~~~bash
npm run build
npm run preview -- --port 4173
~~~

## 检索语法

任务、资产、HTTP、指纹和 PoC 列表支持高级检索。运算优先级为 NOT、AND、OR，空格等同于 AND，字段名以当前页面问号提示中的列表为准。

~~~text
nginx && admin
nginx && !test
title:"管理系统" || product:tomcat
(status=200 || status=302) && !url:logout
~~~

表头单列筛选会和顶部表达式合并后发送到后端。非法表达式会返回错误位置、示例和允许字段；查询使用参数化 SQL。

## 代理池行为

代理节点只有在启用、验证成功且状态为 healthy 时，才会进入扫描请求的轮询集合。

支持格式：

~~~text
http://host:port
https://host:port
socks5://host:port
http://user:password@host:port
~~~

批量导入时每行一个 URL，最多 1000 行。格式错误会逐行返回索引和原因。

- 健康检查默认每 30 秒运行一次。
- 自动轮换默认每 30 秒切换轮询起点。
- 两项功能都能在“设置 → 扫描引擎”关闭或调整。
- 配置修改只影响新启动的任务。
- 测绘 API 凭据验证同样使用已启用的健康代理节点。

## Custom HTTP PoC

Custom PoC 使用 YAML 或 JSON 描述同源 HTTP 请求，不执行 Shell、Python 或任意本机命令。支持 `status`、`word`、`regex` 和 `size` 匹配器：

~~~yaml
requests:
  - method: GET
    path: /admin
    headers:
      X-Target-Host: "{{Host}}"
    timeout_seconds: 10
    matchers_condition: and
    matchers:
      - type: status
        status: [200]
      - type: word
        part: body
        words: [management-console]
      - type: regex
        part: header
        regex: ['Server: .*Example']
~~~

可用占位符为 `{{BaseURL}}`、`{{Scheme}}`、`{{Host}}` 和 `{{Hostname}}`。每个模板最多 10 个请求，请求必须保持在目标同源范围内，跨主机 URL 与跨主机重定向会被拒绝，单个响应最多读取 2 MiB。

## CVE 持续监控

“自动化 → 资产监控”可创建 CVE 类型监控，目标填写产品关键词，多个关键词使用逗号或换行分隔。平台按 NVD `lastModified` 时间窗口拉取最近变化，首次运行建立基线，后续区分新 CVE 与已知 CVE 修订，并通过已选择的 Webhook、钉钉或飞书通道发送一次合并告警。

每个监控最多接受 5 个去重关键词，单轮保存最近 500 条 CVE 摘要；响应大小和单次告警条数均有限制。自动化列表的“执行”按钮与 MCP `manage_platform_record(action=run)` 共用同一调度器并发保护。

## GitHub 泄露监控

“测绘”页面配置并启用 GitHub Personal Access Token 后，可在“自动化 → 资产监控”创建 GitHub 查询。平台每轮最多检索 30 个候选，并发核验其中 12 个文件；只有文件内容中确认存在凭据特征时才生成发现，搜索命中但内容核验失败或未发现凭据不会记为漏洞。

监控快照只保存仓库、路径、可信 `github.com` 证据链接、严重级别和凭据类别计数，不保存原始 Token、私钥或匹配文本。变化判断使用脱敏证据指纹，不再通过搜索结果总数产生误报。

## 凭据存储与回显

API Key、Token、Webhook 地址与签名密钥、自定义测绘/ICP 接口地址和请求头均强制加密存储。设置查询只返回 `configured` 状态，加密值始终为空；编辑框显示“已保存，留空保持不变”，验证已保存凭据时由后端直接解密并请求供应商，浏览器不会重新取得明文。

批量保存设置使用单个数据库事务，任一项加密或写入失败时整批回滚。敏感键是否加密由后端固定规则决定，客户端不能通过提交 `is_encrypted=false` 降级为明文。

## 漏洞证据与安全报告

任务详情的“风险”页通过独立证据窗口展示漏洞描述、Payload、Proof、修复建议和参考资料，避免长证据挤压表格。每个字段可单独复制，也可生成包含目标、级别、类型、来源和全部证明的提交素材。

“导出安全报告”生成 Eclipse Recon 离线 HTML 报告。任务名、目标、站点信息和漏洞证据全部通过上下文感知模板转义；站点链接只接受无凭据的 HTTP/HTTPS URL。报告内置严格 CSP、以附件方式下载并使用 `0600` 文件权限。CSV 导出继续中和公式前缀，避免打开扫描结果时触发电子表格公式注入。

生产 Web 服务统一返回 CSP、`X-Frame-Options: DENY`、`X-Content-Type-Options: nosniff`、无引用来源和禁用摄像头/麦克风/定位的权限策略。表格列宽依赖内联样式，因此 CSP 仅对样式保留必要的 `unsafe-inline`。

## 企业资产闭环

“企业”工作台通过兼容 ICP_Query 的 HTTP 数据源检索网站、APP、小程序和快应用。数据源在“测绘”页面配置；本机地址直连，远程地址复用健康代理池。查询由 PostgreSQL 队列持久化，服务重启会标记中断任务，单次响应受超时、8 MiB 响应体和 10000 条结果限制。

带域名的企业结果可批量执行两种互不混淆的动作：

- 同步资产：只写入跨任务去重的 canonical asset，可选加入已有分组或创建新分组，不产生网络扫描。
- 下发扫描：创建原生待执行扫描任务，由用户在任务页确认后启动。

同步使用事务与 advisory lock 保证并发一致性，同一企业观测和分组成员重复提交保持幂等。`origin_type=enterprise_query`、原始响应、语义状态哈希和变化时间线共同保留来源证据；REST 与 MCP 同步只记录操作者、数量和分组 ID，不在审计日志中写入目标域名或凭据。

## 授权范围护栏

“策略 → 授权范围”用于定义一次赏金项目或授权测试的强制边界。允许规则至少一条，排除规则优先级更高；支持以下格式：

~~~text
example.com
*.example.com
203.0.113.10
203.0.113.0/24
2001:db8::/32
~~~

`*.example.com` 只匹配子域，不自动包含根域；需要同时允许根域时应再添加 `example.com`。URL 目标按主机或 IP 判断边界，但保留原始路径用于任务执行；范围规则是主机/网络级边界，因此不接受带路径、查询串或片段的 URL 规则。

首个范围会自动成为默认范围。默认范围自动应用于未指定 `scope_id` 的手工任务、企业扫描下发、计划任务、网络监控、手工 PoC 和 MCP `create_scan_task`；也可以为单次任务选择其他范围。后端会在创建、入队和 Worker 真正执行前复核目标，范围修改后已存在的待执行任务也不能绕过。Worker 复核后为该任务生成不可变的规则快照，避免每个端口请求查询数据库，也避免并发任务互相覆盖扫描器状态。未配置任何范围时保持兼容模式，已有部署不会被突然阻断。

护栏不仅检查任务入口。域名爆破和插件发现的子域、CIDR/C 段展开地址、端口与服务探测、站点跳转、爬虫页面和 JavaScript、文件泄露探测、截图导航与 HTTP/WebSocket 子请求、WIH、Host 碰撞、接管验证和 PoC 目标都会在网络 I/O 前校验。越界重定向会在第二跳发出前终止。域名规则不会自动授权其解析出的 IP；需要主动扫描解析地址时，应同时加入对应 IP 或 CIDR 规则，避免误扫共享 CDN 或第三方托管地址。

受范围约束的任务只运行同源 Custom HTTP PoC。无法注入网络校验器的 Nuclei/Neutron 模板会跳过，自定义脚本会直接拒绝；兼容模式仍保留原有行为。手工 PoC 执行同样先解析默认或显式 `scope_id`，范围生效时只允许同源 Custom HTTP PoC。

MCP 可先调用 `list_scan_scopes` 获取范围，再用本地只读的 `validate_scan_scope` 预检目标。目标预检不会发起 DNS、HTTP 或端口请求。

## API 与认证

- GET /health：公开健康检查。
- POST /api/v1/auth/login：登录并返回 JWT。
- 其他 /api/v1/*：需要 Authorization: Bearer <JWT>。
- /api/v1/ws/progress：任务实时进度 WebSocket。
- /mcp：只在 MCP 密钥有效时挂载，使用独立 Bearer 密钥。

路由集中在 [backend/internal/api/router.go](backend/internal/api/router.go)。错误响应包含 error 字段；检索语法错误还会提供 example 和 supported_fields。

## 项目结构

~~~text
backend/
  cmd/                  server 与 init-admin 入口
  internal/api/         Gin 路由和 HTTP handlers
  internal/mcpserver/   MCP handler 与工具
  internal/proxypool/   代理健康检查、轮询和请求接入
  internal/scanner/     扫描引擎与结果保存
  internal/searchquery/ 检索表达式解析器
  internal/services/    领域服务
  configs/              配置模板、字典和默认指纹
  web/src/app/          应用壳和懒加载路由
  web/src/components/   共享 UI 与视觉组件
  web/src/hooks/        React hooks
  web/src/lib/          API、常量和检索工具
  web/src/pages/        路由页面
~~~

## 测试与质量检查

后端：

~~~bash
cd backend
go test ./...
go vet ./...
go test -race ./internal/services ./internal/api/handlers ./internal/mcpserver
~~~

前端：

~~~bash
cd backend/web
npm run build
~~~

前端构建会按页面拆分为多个 JavaScript chunk。涉及交互、批量操作或布局的改动还必须在浏览器 MCP 中检查桌面视口、禁用态、确认/取消路径、页面溢出和控制台错误。不要提交 backend/web/dist、node_modules、本地配置、日志、截图或运行数据。

## 日志与排障

- Docker 日志：docker compose logs -f backend
- 本地日志：由 logging.file 配置，默认写入 ./logs/arl.log
- 请求日志包含方法、路径、状态码、耗时和客户端地址。
- Failed to fetch：检查 /health、后端日志、JWT 和前端 API 地址。
- MCP 不可用：检查 MCP_API_KEY 长度并确认 /health 中 mcp_enabled 为 true。
- 数据库连接失败：检查 PostgreSQL 健康状态和 database.host、port、user、dbname。
- 动态模块加载失败：前端重新构建后强制刷新浏览器缓存。

## 贡献约定

提交前至少运行 go test ./... 和 npm run build。涉及 API、MCP、代理池或扫描器行为时，同时补充对应测试或浏览器验证。

不要提交：

- .env
- backend/configs/config.yaml
- backend/data
- backend/logs
- backend/web/dist
- backend/web/node_modules
- 本地截图、构建二进制和参考项目
