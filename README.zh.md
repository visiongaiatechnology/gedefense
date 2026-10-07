<div align="center">

<img width="256" height="256" alt="GeDefense" src="https://github.com/user-attachments/assets/978d2835-c915-473d-9995-d315efaa869c" />



# VGT GeDefense
### Linux 主权安全矩阵 (Linux Security Fabric)

[![License](https://img.shields.io/badge/License-AGPL--3.0--only-blue?style=for-the-badge)](https://www.gnu.org/licenses/agpl-3.0)
[![Version](https://img.shields.io/badge/Version-4.2.0-orange?style=for-the-badge)](#)
[![Status](https://img.shields.io/badge/Status-Release_v4.2.0-yellow?style=for-the-badge)](#)
[![Installer](https://img.shields.io/badge/Installer-4.2.0_Universal_Linux-green?style=for-the-badge)](#-快速上手)
[![Platform](https://img.shields.io/badge/Platform-Linux_x86__64-lightgrey?style=for-the-badge&logo=linux)](#)
[![Data Plane](https://img.shields.io/badge/Data_Plane-Rust_eBPF%2FXDP-red?style=for-the-badge&logo=rust)](#-系统架构)
[![Control Plane](https://img.shields.io/badge/Control_Plane-Go-00ADD8?style=for-the-badge&logo=go)](#-系统架构)
[![Crypto](https://img.shields.io/badge/Evidence-Ed25519%2FAES--256--GCM-gold?style=for-the-badge)](#-密码学与安全)
[![Sovereign](https://img.shields.io/badge/Control_Plane-Local%2FSovereign-brightgreen?style=for-the-badge)](#)
[![Linux](https://img.shields.io/badge/Linux-APT%20%7C%20DNF%20%7C%20pacman%20%7C%20Zypper-cyan?style=for-the-badge&logo=linux)](#-通用-linux-集成)
[![AstraeaOS](https://img.shields.io/badge/AstraeaOS-Native_Ready-7de3ff?style=for-the-badge)](#-astraeaos-原生集成)
[![Architecture](https://img.shields.io/badge/Architecture-Specification-9cf?style=for-the-badge&logo=blueprint)](ARCHITECTURE.md)
[![Security Audit](https://img.shields.io/badge/Security-Audit_Beta_5-success?style=for-the-badge&logo=shield)](SECURITY-AUDIT-BETA5.md)
[![VGT](https://img.shields.io/badge/VGT-VisionGaiaTechnology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

**内核级近源网络防御 · 主机级 XDR · 加密证据链 · 可逆系统加固 · 无云端控制平面**

<br />

🌐 **Languages / Sprachen / Языки / 语言:**  
[English](README.md) · [Deutsch](README.de.md) · [Русский](README.ru.md) · **中文 (简体)**

</div>

---

## 🚨 严重安全警告与公告 — RELEASE v4.2.0

> [!CAUTION]
> **全体系统运维人员与管理员紧急安全通告（强烈建议立即升级）：**
> 
> 在 GeDefense 4.2.0 版本中，作为全面安全审计与验证周期的一部分，**我们排查并彻底修复了此前版本（4.0.x / 4.1.0）中存在的多个严重安全漏洞与完整性缺陷**。强烈建议所有生产环境节点立即升级至 v4.2.0：
> 
> 1. **金丝雀陷阱符号链接遍历提权漏洞（Canary Deployment）：**
>    - *漏洞详情：* 此前的金丝雀诱饵部署在诱饵路径或暂存路径上会跟随符号链接。攻击者若控制上级目录中的符号链接，即可将具有 root 权限的写操作重定向至文件系统的任意位置（如 `cron`、`authorized_keys`、`ld.so.preload`）→ 导致任意文件写入及 root 提权。
>    - *修复措施：* 全面替换为严格基于文件描述符的逐级路径解析（对路径中的每一个组件均使用 `openat(2)` 并附带 `O_NOFOLLOW|O_DIRECTORY`）。跨越符号链接的遍历行为将确定性地返回 `ELOOP` 错误并终止。
> 
> 2. **消除信息泄露的不透明错误响应（Information Disclosure）：**
>    - *漏洞详情：* 5 个 API 处理器曾将原始运行时错误直接暴露给客户端（内部文件系统路径、内核故障、上游威胁源 URL、DNS/TLS 内部状态）。此前的关键词黑名单机制脆弱且不完整。
>    - *修复措施：* 架构解耦 — 内部运行时错误绝不作为 API 响应返回，统一替换为强类型的预定义不透明错误响应。
> 
> 3. **CSPRNG 故障安全关闭（Fail-Closed）及随机数预测防护：**
>    - *漏洞详情：* 当加密级随机数生成器（CSPRNG）熵源不足或失败时，证据链、安全事件、阻断及事务 ID 曾降级为可预测的时间戳。
>    - *修复措施：* 实施严格的 `log.Fatalf` 故障安全终止语义 — 加密标识符绝不降级为可预测数值。
> 
> 4. **防崩溃原子化写入器（`atomicWriteFile`）：**
>    - 安全策略、威胁情报同步状态及 Chronos 检查点全面采用带符号链接拒绝、`O_EXCL` 标识以及对目标文件与父目录双重 `fsync` 的原子写入机制。
> 
> 5. **内容安全策略（CSP）加固与可信类型（Trusted Types）：**
>    - 彻底从 CSP 中剔除 `unsafe-inline` 样式指令。
>    - 浏览器端强制实施 `require-trusted-types-for 'script'` 运行时不变量（彻底阻断 DOM-XSS 汇聚点）。
> 
> 6. **消除引擎死锁与故障开放（Fail-Open）：**
>    - 修复 `CaseEngine.Status` 中的递归互斥锁死锁问题。
>    - 彻底消除 Airlock 检查器及 CaseEngine 中的故障开放状态。
> 
> 7. **提升工具链安全基线（Go ≥ 1.26.6）：**
>    - 修复了旧版 Go 标准库在反向代理入站及威胁情报源解析路径上可被触发的 6 项已知 CVE 漏洞。

---

## ⚠️ 稳定性与可靠性承诺 — RELEASE v4.2.0 · 通用 LINUX 平台

VGT GeDefense 4.2.0 是主权 Linux 安全防御体系的旗舰产品 — 将经过深度加固的内核级防御链与全新的 **Security Fabric Control Plane（安全织网控制平面）**、通用 Linux 原生集成、加固级发布流水线以及真实的内核/网卡适格门禁融为一体。专为主权主机与高对抗网络防御而设计。

**生产环境准入明确属于具体经过审计的目标主机的属性 — 而非仅仅取决于源代码本身。**

初次部署建议：**仅使用 Observe（观察模式）。** 必须在满足文档规定的各项安全门禁后，方可升级至 Canary（金丝雀）与 Enforce（强制执行）模式。

发现漏洞或有改进建议？**欢迎提交 Issue 或直接联系我们团队。**

---

## 🏛️ 安全架构与技术规范

> [!IMPORTANT]
> **面向安全研究员、系统架构师与审计人员：**
> GeDefense 维护着详尽的形式化技术架构规范、信任边界模型与符号数据树：
> 
> ### ➔ [📘 ARCHITECTURE.md — 完整技术架构规范文档](ARCHITECTURE.md)
> 
> *超过 2200 行详细规范，涵盖 7 层架构拓扑、内核 eBPF/XDP 数据平面、Go 控制平面、Rust 响应核心、原生 L7 WAF 引擎、加密证据账本以及可逆系统加固引擎。*

### 7 层主权安全防御架构概览

```text
1. PUBLIC ACCESS GATEWAY       Go · 端口 9843（TLS 1.3、ML-KEM 后量子混合加密、Argon2id、CSRF 同步令牌）
2. COMMAND CENTER DASHBOARD   ESNext / 原生 JS / 原生 CSS · 0 第三方依赖 · CSP 深度加固
3. CONTROL PLANE               Go · 端口 9844（仅限环回回环 · XDR、L7 WAF、FIM、证据账本、事件分析）
4. PRIVILEGED RESPONSE CORE   Rust · /run/vgt-gedefense/core.sock（HMAC VGT3、pidfd_open、sysctl CAS、fanotify）
5. KERNEL DATA PLANE           Rust no_std eBPF/XDP + cgroup-skb + LSM（LPM Trie 25 万条规则，RingBuf EDR）
6. INTEGRATION FABRIC          通用 Linux（APT/DNF/pacman/Zypper）· AstraeaOS 原生 Ring-1 隔离单元
7. RELEASE ENGINEERING         Toolchains.lock · 可复现构建 · 密码学镜像清单
```

### 核心安全不变量
- **无云端控制平面：** 威胁情报、行为基线、操作密钥及取证数据 100% 保留在本地主机，杜绝数据外发。
- **内核级速度数据平面：** 入站网络攻击在网卡驱动层通过 Rust eBPF/XDP 丢弃，在分配套接字缓冲区（`sk_buff`）之前即刻阻断。
- **原生 L7 应用防御（仅使用 Go 标准库）：** 有界 HTTP 规范化、反绕过解码与 RE2 正则扫描，零第三方依赖，零 CGO，无脚本引擎开销。
- **Web 证据隔离屏障：** Web 层检测事件标记为 `AlertOnly: true`（`ResponseScore: 0`）。Web 层的单项告警绝不会自主触发主机级进程终止（`SIGKILL`/`SIGSTOP`）；破坏性阻断必须依赖独立的主机/内核证据。
- **密码学不可篡改证据账本：** 防篡改的单调递增序列，结合前序哈希验证（`AES-256-GCM` + `Ed25519`）。
- **可逆的 Sysctl 内核加固：** 基于原子 Compare-and-Set 与内核回读机制，在部分配置失败时自动执行回滚。

---

## 🚀 GeDefense 4.2.0 新特性：安全织网控制平面、全栈审计修复与 UI/UX 巅峰

VGT GeDefense 4.2.0 标志着主权 Linux 安全矩阵的重大技术跨越：

* **Security Fabric Control Plane（12 大可管理模块）：**
  * 为 12 个模块化子系统提供完整的 Schema 驱动配置（`kinetic`、`network`、`protection`、`xdr`、`l7`、`threat_intel`、`hardening`、`integrity`、`boot_trust`、`policy_trust`、`forensics`、`system`）。
  * 服务端作为唯一可信源；控制台完全基于 Schema 动态渲染，无任何硬编码的配置项名称。
  * **热路径上的不可变快照：** 配置版本编译为原子的不可变快照。单个请求在执行周期内始终绑定唯一快照，彻底杜绝请求期间并发修改导致的竞争或混合状态。
  * **加固级不变量完全不可更改：** 内核 Map 边界、Core IPC 认证、路径校验、私钥保密性、管理自锁定防护及情报防投毒等核心逻辑永久锁定。

* **控制平面工作台操作与配置漂移检测：**
  * `GET /api/v1/settings/search` — 在所有配置键之间进行确定性检索，显示生效的实时数值与命中判定依据。
  * `POST /api/v1/settings/export` — 生成经过密码学签名、剔除敏感机密的跨命名空间配置导出包。
  * `POST /api/v1/settings/import/preview` + `.../apply` — 真正的双阶段导入：密码学签名验证、Diff 生成，并通过绑定到已审计内容的单次有效临时令牌执行应用。
  * `GET /api/v1/settings/drift` — 持续配置漂移监控：若当前配置版本未与底层引擎同步，将标记为 `CONFIG_DRIFT`（绝不虚假显示 `SYSTEM_NOMINAL`）。

* **完全本地化的离线 SVG 世界地图（jsVectorMap 1.7.0）：**
  * 涵盖 43 个本地源码文件的完整几何数据（`world_merc`）。零 CDN，零瓦片服务器，零外部网络请求。
  * **严格的可信类型执行：** 通过使用原生 button 元素绕过 DOM 字符串汇聚点，100% 符合 `require-trusted-types-for 'script'` 规范。
  * 实时跟踪标记、动态脉冲源、事件密度等值面分布图及被阻断威胁的专属色彩分级。
  * 有界的 DOM 渲染资源预算（96 跟踪、48 阻断、24 脉冲、192 区域）及视觉阈值控制。

* **UI/UX Supreme — 现代化控制台重新设计：**
  * 废弃了 Kinetic 防御、威胁情报、应用防御和 XDR 中杂乱的卡片网格，采用统一的指挥层与分组遥测面板。
  * 采用带有发丝分割线的语义化 `<dl>` 数据条带取代厚重的卡片边框。
  * 纯状态驱动的高亮配色：仅在指标非零时激活功能性提示色。
  * 原生 `<button>` 键盘无障碍支持，符合 WCAG AA 对比度规范，全面支持 `prefers-reduced-motion`。

---

## 🚀 GeDefense 4.0.1 特性：简体中文本地化、专用 XDR 内核恢复与扩展

VGT GeDefense 4.0.1 带来了全面的多语言主权支持与自动化自愈维护能力：

* **完整的简体中文（`zh-CN` / `ZH`）本地化：**
  * 指挥中心全量支持简体中文，覆盖所有标签页、弹窗、操作面板、图表、占位符及运行时通知（共 743 个词条，与德语、英语、俄语完全对齐）。
  * 扩展了公共访问网关登录页（`gateway/main.go`）的中文字段，提供 Cookie 持久化语言切换与专属 `ZH` 选择项。
  * 实现了基于 HTTP `Accept-Language` 的浏览器语言自动检测与偏好匹配。
* **专用 XDR 内核恢复面板与安全状态重置：**
  * 新增专用 XDR 内核恢复界面（`#xdr` 恢复面板），允许管理员在安装或故障后直接通过 UI 检查、归档并重新初始化内核传感器栈，无需依赖紧急 SSH 或终端命令。
  * 经过身份鉴权的 `/api/v1/xdr/recovery` 接口，具备严格的 `ARCHIVE_AND_REINITIALIZE_XDR` 确认防护。
  * 损坏或降级的事件账本链将以字节精确度备份至 `/var/lib/vgt/gedefense/xdr-recovery/`，附带 SHA-256 清单。
  * 在安全重置新事件链的同时，严格保留主密钥、传感器 IPC 凭据与管理员账户。
  * 重新初始化内核 eBPF 探针、BPF-LSM 钩子、Ring Buffer 连接与进程监控器。
  * 要求在解除 `DEGRADED` 降级状态前完成磁盘校验与签名证据提交。
* **密码学证据与账本哈希域分离：**
  * 分离了攻击故事默克尔证据树根（`evidence_root`）与事件账本 HMAC 链哈希（`record_hash`），确保关联事件在守护进程重启后仍可验签。
  * 加固了状态传递机制，避免后台轮询掩盖真实的内核异常。

---

## 🚀 原生 L7 应用安全防御与主权加固（v4.0.0 架构）

VGT GeDefense 4.0 在原有 L3/L4/内核防御体系的基础上，**深度集成了原生的 L7 应用安全平面（WAF 与反向代理网关）**。系统在流量进入业务逻辑前直接完成检查与过滤 — 完全基于 Go 标准库构建，零第三方依赖，零 CGO，无脚本引擎开销。

### 🌟 核心能力与 L7 应用安全（WAF）
* **原生 L7 平面（纯 Go 标准库）：** 内置 WAF 直接编译进 `gedefense-control` 守护进程。`go.mod` 零外部扩展包，无 Lua/WASM/Node.js 开销，超低延迟与内存占用。
* **双模式部署架构：**
  * *建议/独立套接字模式（`inspect.sock`）：* `0660` 权限的 Unix 套接字，通过标准 JSON 协议（`POST /v1/inspect`）为 nginx、Apache、Caddy、Envoy 等外部代理提供服务，启用严格模式校验（`DisallowUnknownFields`）。
  * *原生内联反向代理模式（`edge.sock`）：* 部署在 TLS 终止与后端应用之间。具备并发控制、故障安全关闭预算与严格的上游隔离（仅允许干净的绝对 Unix 套接字或回环 IP，无动态 DNS 与请求重定向漏洞）。
* **有界规范化与反绕过引擎：**
  * 多轮递归解码（URL 路径/查询参数、HTML 实体、`\uXXXX` 及 `\xXX` 转义符）。
  * 全角字符转半角映射（Unicode Fullwidth Fold 将 `\uff01`–`\uff5e` 映射为 ASCII），杜绝利用特殊宽字符绕过过滤。
  * 自动识别并解码参数中的未填充及 URL 安全 Base64 负载。
  * 流式 JSON 解析器，具有严格的递归深度限制（`max_json_depth = 32`）与令牌配额。
  * 有界解压缩：通过 `io.LimitReader` 处理 Gzip/Deflate，防御解压炸弹（Zip-bomb DoS）。
  * 对非结构化文本使用 256 字节重叠分块，防止特征码在分块边界被截断绕过。
* **全方位攻击检测特征库（线性 RE2 引擎，零 ReDoS 风险）：**
  * *SQL 注入（SQLi）：* UNION SELECT 语法、布尔恒真式（`' OR 1=1`）、时间延迟（`pg_sleep`、`benchmark`）及堆叠查询语句。
  * *跨站脚本（XSS）：* 脚本标签、内联事件处理器（`onerror=`、`onload=`）、危险伪协议（`javascript:`、`data:text/html`）及 `iframe srcdoc` 攻击载荷。
  * *命令注入 / RCE：* 命令拼接符（`;`、`&&`、`||`、`|`）、命令替换（`$(...)`、反引号）及 PowerShell/CMD 载荷。
  * *路径遍历与本地文件包含（LFI）：* 遍历序列（`../`、`..\`）、Linux 敏感路径（`/etc/passwd`、`/proc/self/environ`）及流包装器（`php://`、`phar://`、`data://`）。
  * *SSTI、XXE 与反序列化：* 模板语法（Jinja、Twig、Smarty、Spring）、外部 XML 实体、PHP 序列化对象、Java 序列化魔数（`rO0AB`）及 JNDI/Log4j 表达式。
  * *HTTP 协议走私与畸形解析：* 重复或非法的 `Content-Length`、CL.TE / TE.CL 冲突、非法传输编码及被禁用的 `TRACE` 方法。
* **反规避 SSRF 检测与灵活 IP 规范化：**
  * 规范化并拦截非常规 IPv4 表示法：十六进制（`0x7f.1`）、八进制（`0177.1`）、十进制 DWORD 整数（`2130706433`）及 2/3 段式简写。
  * 针对主流云厂商元数据端点的严格隔离区（AWS IMDSv2 `169.254.169.254`、GCP `metadata.google.internal`、Azure `168.63.129.16`、阿里云 `100.100.100.200`、Oracle `192.0.0.192`）。
* **内存中 Airlock 复合上传检查（`InspectBytes`）：**
  * 多部件文件上传直接在内存中完成检测 — **绝不在持久化磁盘上落盘暂存**。
  * 限制分块数量与文件大小；严格验证魔数（ELF、PNG、JPEG、GIF、PDF、ZIP）、MIME 匹配、双重扩展名（`.php.jpg`）、截断空字节及 SHA-256 恶意哈希黑名单。
* **三层分片令牌桶速率限制：**
  * 64 个基于 FNV-1a 哈希的独立分片，消除高并发流量下的全局锁竞争。
  * 客户端维度的流量速率限制。
  * 敏感路径的专属防护（针对 `/login`、`/wp-login.php`、`/api/login` 防暴力破解）。
  * 全局敏感路由限速（防御分布式僵尸网络与凭据撞库攻击）。
* **响应数据泄露防护（DLP）：**
  * 监控上游响应体，防止数据库报错泄露（`SQLSTATE`）、服务端源码泄露（`<?php`、`<jsp:`）、堆栈轨迹泄露（Python、Java、Go）及私钥泄露（`BEGIN RSA PRIVATE KEY`）。
  * 基于无损前缀缓冲的检测技术，确保原始字节未经篡改即时传输至客户端。
* **XDR 中的 Web 证据隔离（误报防护屏障）：**
  * L7 事件记录为 `AlertOnly: true`（`ResponseScore: 0`）。
  * **安全保障：** Web 攻击**绝不能自主**对本地服务进程发起破坏性的阻断操作（SIGKILL/SIGSTOP）。破坏性处置必须同时满足独立的主机/内核证据。
  * L7 事件作为节点接入 Trinity XDR 2.0 因果有向无环图（DAG），并带有默克尔根签名证明。
* **Linux DAC 与操作系统加固：**
  * 专用系统组 `gedefense-l7`。
  * 运行时目录 `/run/vgt-gedefense-l7`（权限 `0750`，所属 `gedefense:gedefense-l7`）通过 `systemd-tmpfiles` 创建。
  * 套接字权限配置为 `0660`，启用内核级对端凭证校验（`SO_PEERCRED`）。
  * 针对 systemd 服务单元加固，限制 `ReadWritePaths`。
* **持续模糊测试与质量门禁：**
  * 3 个新的 CI 模糊测试套件（`FuzzL7NormalizerNeverPanics`、`FuzzL7ResponseInspectionPreservesWireBytes`、`FuzzL7InlineUpstreamParserNeverEscapesLocalHost`）。
  * 锁定 Go 1.26.8 工具链，并在 `scripts/security-audit.sh` 中集成了 AST 自动化安全审计。

---

## 🌟 从 V2 Beta 1 到 V3 Beta 1（`3.0.0-beta.1`）的架构突破

VGT GeDefense 3.0.0-beta.1 完成了从静态主机/网络传感器向**完全自主、可逆、纵深防御的 Linux 主权安全矩阵**的蜕变：

* **双模部署教条（单一二进制，动态特性探测）：** 统一的二进制文件同时适配 AstraeaOS（原生 Ring-1 GaiaCells、BPF-LSM、Key-Broker）与标准 Linux 发行版（Ubuntu、Debian、RHEL、Fedora、Arch、Alpine），支持运行时安全飞地自动检测（`platform_caps.go`）。
* **Trinity 动态攻击故事图谱（DAG）与事件关联器：** 完整因果链图谱还原（`CANARY_TRIGGERED` → `PRIVILEGE_ESCALATED` → `EGRESS_ATTEMPTED`），基于确定性默克尔根提供铁证，取代孤立日志条目。
* **自主可逆响应引擎：** 多阶段隔离策略（`CONTAIN_IP`、`FREEZE_EXECUTION`、`CONTAIN_CELL`），内置语义化 TTL 并在未得到管理员确认时自动审计回滚。
* **Nemesis 网络欺骗诱捕网格：** 物理磁盘金丝雀陷阱（`0600` 权限），结合 `StorageCipher` 动态密钥派生与校准的 RASP 辨别机制。
* **Styx 零信任出站与 SSRF 护盾：** 基于 Cgroup/Cell 的出站流量白名单，内置针对各大云厂商元数据接口的防外发过滤机制。
* **Airlock 入站复合检查器：** 严格验证文件魔数，净化 SVG（清除嵌入式脚本、foreignObjects、iframe 及 DTD），有界暂存与符号链接防逃逸。
* **Morpheus Linux RASP 与凭据擦除器：** 保护敏感守护进程免受内存抓取（`/proc/<pid>/mem`、`ptrace`），自动脱敏命令行中的 API 密钥与凭证。
* **Chronos 断点续检 FIM：** 高效的文件完整性扫描器，具备原子检查点、零句柄泄漏与默克尔树完整性根。
* **可逆进程冻结机制：** 校验 `/proc/<pid>/stat` 启动时钟以防 PID 复用竞争；Rust Core 利用 `libc::SIGCONT` 在 TTL 到期后安全唤醒被暂停进程。
* **防规避 SSRF 校验：** 规范化并拦截十六进制、八进制、DWORD 及 IPv4-in-IPv6 格式，全面封堵内部回环地址。
* **零信任内存擦除：** `StorageCipher.Destroy()` 在停机时彻底覆写 RAM 中的主密钥。

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/29413de7-469a-4207-98bf-496ab69ef20a" />



## 🔍 什么是 VGT GeDefense？

GeDefense 绝非简单的防火墙规则管理器。它是**本地化主权 Linux 安全防御矩阵** — 集成了内核级网络防御、主机 XDR、加密证据账本、可逆系统加固以及可选的 AstraeaOS 原生隔离，全程无需任何云端控制平面。

```
传统 Linux 安全技术栈：
  缺乏协同的工具拼凑 (iptables + auditd + fail2ban) → 无共享状态
  盲信配置                                           → 自定义规则自动直接执行
  缺乏证据链                                         → 安全事件无法确证
  不支持自动回滚                                     → 系统加固变更不可逆
  依赖云端 SIEM / 控制平面                           → 敏感数据离开本地主机

VGT GeDefense:
  Rust eBPF/XDP 数据平面                  → 内核就近防御，支持高达 250,000 条规则
  Go 控制平面 (XDR、策略、FIM)            → 独立信任域，仅限环回接口
  Rust 响应核心 (pidfd、SIGKILL)          → 任何 Kill 指令前均须经过仲裁验证
  隔离的信任域架构                        → 公共网关 · 控制面 · 响应核心 · 数据平面
  Ed25519 签名的证据账本                  → 单调递增序列 + 前序哈希验证
  AES-256-GCM 保护的 FIM 基线             → 完整性遭到破坏时即刻 Fail-closed
  可逆系统加固                            → Compare-and-Set、原子持久化、自动回滚
  加密响应隔离保险库 (AES-GCM)            → 附带 SHA-256 唯一身份的样本隔离
  无云端控制平面                          → 敏感状态绝不离开受保护主机
  通用 Linux 原生支持                     → 深度适配 APT · DNF/YUM · pacman · Zypper
  AstraeaOS 原生适配                      → 经校验的镜像源，同一套安全防御链
```

单一的正则表达式、威胁情报命中、行为异常或伪装检测**绝不能单独授权终止进程**。进入 Enforce（强制执行）模式至少需要两个独立的授权类别、客观的仲裁证据以及非降级的系统运行状态。

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/1f5cf6ae-ee59-498d-9c5b-e06e8efc9ef2" />



## 🏛️ 系统架构

```
┌──────────────────────────────────────────────────────────────┐
│                    PUBLIC ACCESS GATEWAY                      │
│   Go · TLS 1.3 · Argon2id · 主机/来源/CSRF · 会话管理        │
│   非特权运行 · 默认端口 9843（可配置范围 1024–65535）        │
├──────────────────────────────────────────────────────────────┤
│                      CONTROL PLANE                            │
│   Go · XDR · 策略引擎 · 遥测 · FIM · 证据账本 · 事件分析     │
│   运行用户: gedefense · 仅限本地环回 (TCP 9844)              │
├──────────────────────────────────────────────────────────────┤
│                      RESPONSE CORE                            │
│   Rust · VGT3 IPC · pidfd 响应 · 隔离库 · Sysctl 修改        │
│   UID 0 · 权能限制 (Capabilities) · HMAC 认证的 IPC 通信     │
│   套接字: /run/vgt-gedefense/core.sock                       │
├──────────────────────────────────────────────────────────────┤
│                       DATA PLANE                              │
│   eBPF/XDP · IPv4/IPv6 · 网卡层最长前缀匹配 (LPM) 白/黑名单  │
│   内核级 XDP · 支持多达 250,000 条阻断条目                   │
└──────────────────────────────────────────────────────────────┘
```

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/0712a990-f3ad-4b4a-8d18-8e0a60395fe1" />



### 信任域分离

| 信任域 | 承担职责 | 运行特权 |
|---|---|---|
| **公共网关 (Gateway)** | TLS 1.3、Argon2id、主机/来源/CSRF 校验、会话鉴权 | 非特权进程 |
| **控制平面 (Control Plane)** | XDR、策略管理、遥测指标、FIM、证据账本、分析控制台 | `gedefense` 普通系统用户 |
| **响应核心 (Response Core)** | XDP Map 管理、pidfd 进程处置、样本隔离、Sysctl 加固 | UID 0（受权能边界严格约束） |
| **数据平面 (Data Plane)** | IPv4/IPv6 数据包解析、网卡物理层 LPM 白名单与黑名单阻断 | 内核态 / XDP |

### 部署形态

**通用 Linux (Universal Linux)** — 在基于 systemd 的 x86_64 Linux 操作系统上通过 APT、DNF/YUM、pacman 或 Zypper 一键安装。Rust Core 和 eBPF 程序将直接针对宿主机的内核与网卡进行编译，并通过严格验证后原子激活。

**AstraeaOS 原生 (AstraeaOS-native)** — 采用完全相同的核心二进制、原生服务配置、AstraeaOS 加固配置集、安全启动证据及可选的 Gaia Cells 隔离单元。GeDefense 是 AstraeaOS 内部的**唯一法定安全管理中枢**。

---

<img width="2560" height="1229" alt="image" src="https://github.com/user-attachments/assets/57feccc5-75ab-46a1-a575-3a5ec3402087" />



## 🛡️ 防御矩阵核心机制

### 网络级近源防御 (Rust eBPF/XDP)

| 特性 | 详细说明 |
|---|---|
| **数据平面** | Rust eBPF/XDP — 原生硬件驱动级 XDP，支持 Generic-XDP 容错回退 |
| **协议覆盖** | 全面支持 IPv4 和 IPv6 |
| **规则匹配算法** | LPM Tries（最长前缀匹配树） |
| **容量规格** | 支持高达 250,000 条规则条目 |
| **管理白名单** | 优先于黑名单生效 — 绝不阻断管理员通信路径 |
| **CIDR 规则** | 具备签名校验与生命周期（TTL）控制 |
| **威胁源自动阻断** | 默认禁用 — 公共威胁情报源必须经过管理员明确授权方可生效 |
| **空规则严格校验** | 权威的 `VERIFY_EMPTY` 校验 — 杜绝隐藏的残留阻断规则 |

### 主机级 XDR

| 特性 | 详细说明 |
|---|---|
| **监控信号** | 进程画像、执行命令、父子继承树、调用源、进程伪装、网络流量、威胁情报 |
| **基线画像** | 自适应学习，严格限制单进程基线的基数上限 |
| **自定义规则** | RE2 线性正则引擎 — 严格限定为仅告警模式（Alert-only） |
| **多信号联动门禁** | 在采取任何阻断升级动作前，必须满足多维证据聚合门禁 |
| **PID 身份绑定** | PID 与 pidfd 双重绑定 — 彻底免疫 PID 回绕复用攻击 |
| **金丝雀阶段处置** | 验证充足证据后执行暂停信号（SIGSTOP） |
| **强制执行阶段处置** | 仅限仲裁器权威核验后方可发送终止信号（SIGKILL） |

**XDR 默认性能与资源预算**

| 参数项 | 设定值 |
|---|---|
| 进程扫描周期 | 750 ms |
| 网络与完整性检查周期 | 3 s / 3 s |
| 告警 / 隔离 / 查杀阈值分值 | 40 / 80 / 120 |
| 工作线程数 / 队列深度 | 4 / 2,048 |
| 单次扫描评估任务上限 | 4,096 |
| 事件日志大小硬上限 | 64 MiB |

### 证据链与完整性

| 特性 | 详细说明 |
|---|---|
| **证据账本 (Ledger)** | 经 `Ed25519` 本地签名与强加密保护 |
| **链式哈希结构** | 单调递增序号，严格绑定前序记录哈希值 |
| **防截断保护** | 独立的头部检查点校验（Head Checkpoint） |
| **FIM 基线库** | 受到 `AES-256-GCM` 认证加密保护 |
| **目录遍历安全** | 递归深度受限，结合流式 SHA-256 计算 |
| **环境安全检查** | 严格校验并发竞争、符号链接及文件权限模数 |
| **完整性受损处置** | 故障闭锁（Fail-closed）— 绝不容忍静默降级 |

### 安全事件与事务控制

| 特性 | 详细说明 |
|---|---|
| **事件关联分析** | 加密封装事件上下文数据 |
| **重复性事件收敛** | 具备账本追溯承诺的重复告警抑制与收敛机制 |
| **加固执行流程** | 变更预览 (Preview) → 管理员授权 (Authorize) → 实际应用 (Apply) |
| **审计追溯流程** | 状态核验 (Verify) → 安全审计 (Audit) → 状态还原 (Reverse) |
| **服务启动自检** | 差异对齐校验 — 发现未知漂移时隔离审查，绝不盲目覆盖 |

---

## 🔒 运行安全与阶段晋升门禁

```
Observe（观察） ──→ Canary（金丝雀） ──→ Enforce（强制执行）
      │                    │                    │
      │              多重客观证据          经签名的 CIDR 规则
      │              校验的 SIGSTOP        与白名单双向同步
      │
 XDP 探针就绪，无阻断规则
 已通过空规则安全验证
```

| 运行状态 | 网络拦截动作 | 进程级处置措施 | 晋升放行条件 |
|---|---|---|---|
| **Observe** | XDP 处于监听状态，无拦截规则 | 仅记录遥测事件 | 确认内核中无残留拦截规则 |
| **Canary** | 保持流量观测 | 经证据核验的暂停（SIGSTOP） | 满足策略、稳定性观察期与健康度门禁 |
| **Enforce** | 执行经签名的 CIDR 阻断 | 经仲裁授权的终止（SIGKILL） | 管理网络白名单已完成原子同步 |
| **Degraded** | 故障安全模式 | 挂起所有主动阻断行为 | 必须由管理员介入排查并显式恢复 |

**紧急阻断终止协议：** 停用主动响应 → 清理所有拦截规则 → 经过鉴权的 `VERIFY_EMPTY` 核验 → 保存经签名的 Observe 策略配置 → 确认恢复纯净空状态。任何中间环节报错均绝不判定为安全。

---

## 🔐 密码学与安全规范

| 保护目标 | 算法标准 | 详细配置规格 |
|---|---|---|
| **管理员凭证** | Argon2id | 64 MiB 内存占用 · 迭代次数 t=3 · 并行度 p=1 · 128 位盐值 · 256 位输出 |
| **Control ↔ Core 通信** | HMAC-SHA-256 | 32 字节共享密钥 · 时间窗口校验 · 随机数 Nonce · 防重放缓存 · `SO_PEERCRED` |
| **运行状态存储** | AES-256-GCM | 随机 Nonce · 专职子密钥隔离 · 关联数据（AAD）绑定校验 |
| **安全策略 / 证据签名** | Ed25519 | 本地私钥签名与公钥验签 |
| **内容身份鉴别** | SHA-256 | 流式哈希计算与二次验证 |
| **公共访问网关** | TLS 1.3 | 本地自签发或系统安装的受信任证书 |

关联数据（AAD）校验上下文：Schema · 节点标识 · 目标用途 · 规范化路径 · 序列号。
系统仅在旧版数据迁移时短暂兼容 PBKDF2 — 首次成功登录后将原子升级至 Argon2id。

### 浏览器与 API 深度加固

| 加固项 | 实现状态 |
|---|---|
| 零外部第三方依赖（无外链 CDN、追踪脚本或网络字体） | ✓ |
| 彻底杜绝动态 HTML 字符串拼接与 eval 执行 | ✓ |
| 实施严苛的 CSP 策略，严禁网页被 iframe 嵌套引用 | ✓ |
| 同步器 CSRF 令牌防护与严格的请求来源（Origin）比对 | ✓ |
| 全面启用 Secure、HttpOnly 及 SameSite=Strict Cookie 属性 | ✓ |
| 服务端执行 Bearer 令牌注入 | ✓ |
| 全局启用 Request-ID、TTL 有效期及防重放攻击检测 | ✓ |
| 外部情报源拉取启用 DNS 防重绑定与 SSRF 拦截 | ✓ |
| 原生 L7 应用安全引擎与有界规范化解析 | ✓ |
| L7 模块未引入任何外部 Go 依赖包 | ✓ |
| Go 语言服务内部严禁拼接执行系统 shell 命令 | ✓ |
| 控制平面后端仅监听本地环回网络（Loopback） | ✓ |

**敏感运行状态与私钥材料绝不离开受保护的主机系统。**

---

## 🔧 可逆系统加固

内置预设：`Generic Linux Server` 与 `AstraeaOS Workstation` — 基于预先审定的键值白名单。

内核参数变更均通过 Compare-and-Set 原子操作执行，完成回读校验后，原子持久化至 `/etc/sysctl.d/90-vgt-gedefense.conf`。

Rust Core **未提供任何通用的系统 Shell、文件系统或 Sysctl 执行后门**。若配置过程中发生局部错误，系统将严格按照相反顺序自动回滚所有修改。

### 加密响应隔离保险库 (Response Vault)

| 特性 | 详细说明 |
|---|---|
| **加密算法** | AES-256-GCM |
| **分块大小** | 1 MiB 分块加密 |
| **源文件体积上限** | 256 MiB |
| **样本身份标识** | SHA-256 哈希值 + 完整元数据签名 |
| **捕获隔离** | 原子写入 — 经还原验证方可提交 |
| **符号链接防护** | `openat2`、`O_NOFOLLOW` 严格阻断逃逸 |
| **保险库系统权限** | `root:gedefense` 0700 — 剥夺 `CAP_DAC_OVERRIDE` |

---

## 🐧 通用 Linux 集成

| 系统层级 | Beta v4 集成规格 |
|---|---|
| 包管理器适配 | 原生支持 APT · DNF/YUM · pacman · Zypper |
| 初始化管理 | 经过语法与运行时验证的加固型 systemd 单元 |
| 特权权限边界 | 受 Polkit 精准限制的准备就绪助手 — 无通用 root shell |
| 桌面快捷方式 | 独立的 Chromium 运行环境配置，实施精准证书 SPKI 锁定 |
| TLS 身份认证 | 绑定公网主机标识，以及 `localhost`、`127.0.0.1`、`::1` 等 SAN 证书属性 |
| 发布阶段流水线 | Go 数据竞争/模糊测试/安全审计 · Rust Core 校验 · eBPF 编译 · 产物指纹 |
| 跨发行版兼容性 | Ubuntu/Debian · Fedora/RHEL · Arch · openSUSE 契约验证 |
| 目标主机实体验证 | bpffs 挂载 · 验证器通过的 eBPF 探针 · 实体网卡 XDP 挂载 · IPC 与 TLS |

发行版测试容器用于保障打包脚本与通用接口规范的正确性。容器环境不代表已通过宿主机内核验证。每个正式版本仍必须在目标主机的实际内核、网卡驱动和网络设备上通过特权安全检查。

---

## 🌐 AstraeaOS 原生集成

| 集成模块 | 实现进度 |
|---|---|
| 原生服务部署与 systemd 管理 | ✅ 已实现 — 遵循与独立版一致的高标准安全链 |
| GeDefense 源码同步镜像 | ✅ 已实现 — 严格校验 SHA-256 发布清单 |
| AstraeaOS 专属加固画像 | ✅ 已实现 — 支持状态回滚与持久化固化 |
| 安全启动链证据采集 | ✅ 已实现 — 严格记录证据，杜绝虚假背书 |
| Gaia Cells VGTGC1 隔离适配层 | ✅ 已实现 — 作为运行时可选组件提供 |
| UUID / 生命周期世代 / Cgroup ID 绑定 | ✅ 已实现 — 实施不可更改的操作上下文绑定 |
| 单元冻结 / 网络隔离快速回滚 | ✅ 已实现 — 证据绑定的原子事务操作 |
| Gaia Cells 守护进程 | — 未包含 — 属于 AstraeaOS 操作系统自身的运行环境 |
| 独立欺骗诱捕服务 (Deception) | — 顺延规划 — 不属于当前 Beta 授权管理范围 |

所有针对隔离单元的操作均严格绑定其 UUID、生命周期世代及内核 cgroup ID。系统将对调用者的 UID、HMAC 签名、时间戳窗口及 Nonce 进行联合验证。

若环境中**未部署** Gaia Cells 运行环境，适配层将安全返回 `runtime_not_installed`。通用主机安全防御层将继续正常工作，**系统绝不降级**。

> **唯一法定中枢：** 在 AstraeaOS 中，GeDefense 是全系统唯一的安全主管实体。Sentinel 仅作为历史迁移与合规审计的数据源提供支持。

---

## ⚙️ 运行时规范与技术契约

### 宿主机运行环境要求（独立部署版）

| 软硬件指标 | 准入要求规格 |
|---|---|
| **操作系统** | Linux |
| **硬件架构** | x86_64 / amd64 |
| **初始化系统** | systemd |
| **内核能力** | 必须支持 BPF/XDP 及 pidfd 特性 |
| **包管理工具** | apt-get、dnf/yum、pacman 或 zypper |
| **安装前提** | 具备 root 执行权限，编译期间需要访问互联网 |
| **网关运行时** | `libargon2.so.1` 依赖库 |

> 本测试阶段不划定一刀切的内核版本死线，亦不承诺特定网卡型号全覆盖。目标主机是否合规完全取决于能否顺利通过源码编译、内核验证器审查、XDP 挂载测试、IPC 连通性以及健康度基准测试。

### 锁定的编译构建工具链

| 工具链组件 | 锁定版本 |
|---|---|
| **Go** | 1.26.8 |
| **Rust Core** | 1.97.1 |
| **Rust eBPF** | nightly-2026-07-16 |
| **Rust 标准源码组件** | rust-src |
| **bpf-linker** | 0.10.3 |
| **Cargo 依赖锁定** | `Cargo.lock --locked` |

### 接口与网络端口分配

| 接口服务名称 | 默认监听配置 | 暴露等级 |
|---|---|---|
| **HTTPS 管理网关** | TCP 9843 | 管理与公网访问 — 可配置范围 1024–65535 |
| **Go 控制平面后端** | TCP 9844 | 仅限本地回环地址（Loopback） |
| **Rust Core IPC 通信** | `/run/vgt-gedefense/core.sock` | HMAC-VGT3 签名 + `SO_PEERCRED` 校验 |
| **L7 检测服务 API** | `/run/vgt-gedefense-l7/inspect.sock` | 本地 Unix 套接字 · 资源限制 · `SO_PEERCRED` |
| **L7 内联反向代理** | `/run/vgt-gedefense-l7/edge.sock` | 可选的本地 Unix 反向代理安全边界 |
| **Gaia Cells 控制接口** | `/run/gaia-cells/control.sock` | 可选组件 — 基于 VGTGC1 协议 |
| **威胁情报数据流** | HTTPS 出站通信 | 可选组件 — 仅允许访问合规的公网 IP |

### 核心文件目录布局

| 目录与文件路径 | 承担职责与用途 |
|---|---|
| `/opt/vgt/gedefense/releases/<版本号>` | 只读且不可变的正式发布程序包 |
| `/opt/vgt/gedefense/current` | 指向当前运行版本的原子软链接 |
| `/etc/vgt/gedefense/` | 核心配置文件、TLS 证书及私钥机密数据 |
| `/var/lib/vgt/gedefense/` | 加密保存的系统动态运行数据 |
| `/var/lib/vgt/gedefense/quarantine/objects` | 加密响应隔离保险库（Response Vault） |
| `/run/vgt-gedefense-l7/` | 专供 L7 检查使用的临时 Unix 域套接字 |
| `/sys/fs/bpf` | 内核 BPF 虚拟文件系统挂载点 |
| `/var/log/vgt-gedefense-install.log` | 系统安装调试日志文件 — 访问权限 0600 |

---

## 🚀 快速上手

```bash
# 下载安装程序
wget https://github.com/visiongaiatechnology/gedefense/releases/download/v4.2.0/GeDefense-4.2.0-OneClick.run

# 校验 SHA-256 完整性指纹
sha256sum --check GeDefense-4.2.0-OneClick.run.sha256

# 执行安装（需要 root 权限）
chmod 700 GeDefense-4.2.0-OneClick.run
sudo ./GeDefense-4.2.0-OneClick.run
```

> 安装包与校验和文件仅在通过全部 GitHub CI 测试及实体 Linux 节点验证后发布。切勿运行未经验签的 RUN 可执行文件。

安装脚本只有在完整通过以下校验链条后方可宣告成功：**代码编译 → 内核验证器测试 → XDP 驱动层挂载 → IPC 通信链路测试 → 控制后端校验 → TLS 证书安全准入**。

安装过程中，脚本可根据检测结果，自动通过 UFW、firewalld 或 iptables 完成 HTTPS 网关服务端口（TCP 9843）的放行配置。

**首次运行请务必保持在 Observe 观察模式。只有在所有验证门禁均正常满足后，方可调整至 Canary 及 Enforce 模式。**

---

## ✅ 发布门禁与质量规范

| 质量核验门禁 | 当前状态 | 准入判定规则 |
|---|---:|---|
| 源码与发布包清单核对 | ✅ 已实现 | 校验和必须实现零漂移 |
| 机密数据与私钥残留扫描 | ✅ 已实现 | 检出违规项必须为零 |
| GitHub Actions 与容器指纹锁定 | ✅ 已实现 | 必须绑定不可变哈希标识 |
| Go 单元测试、集成测试与 Vet 审查 | 🔒 强制 CI 门禁 | 必须全项通过 |
| Go 竞态检测与安全模糊测试冒烟 | 🔒 强制 CI 门禁 | 必须全项通过 |
| JavaScript 与 Shell 语法规范校验 | ✅ 本地与 CI | 必须全项通过 |
| AST 静态安全回归审计 | 🔒 强制 CI 门禁 | 必须全项通过 |
| Rust 核心组件原生单元测试 | 🔒 强制 CI 门禁 | 必须全项通过 |
| Rust Core 与 eBPF 正式环境构建 | 🔒 强制 CI 门禁 | 必须全项通过 |
| Ubuntu、Fedora、Arch、openSUSE 测试矩阵 | 🔒 强制 CI 门禁 | 矩阵任务必须全部绿色通过 |
| 安装包产物与 SHA-256 指纹校验 | 🔒 强制 CI 门禁 | 必须全项通过 |
| 实体主机内核验证器与网卡 XDP 挂载 | ⏳ 目标主机资质 | 针对每个目标部署主机单独审查 |
| systemd、IPC、控制后端、TLS、Polkit 校验 | ⏳ 目标主机资质 | 针对每个目标部署主机单独审查 |

**最终发布门禁：** 针对目标宿主机的具体内核、验证器兼容性、XDP 模式、网卡设备及驱动程序的实体端对端冒烟测试。

---

## 🚧 当前已知局限（4.2.0）

- 暂未集成 Swarm / 集群网格（Mesh）支持
- 暂不支持 QUIC 协议网络卸载
- 不包含云服务商级别的骨干网 DDoS 流量吸收清洗能力
- 不提供入站流量的 TLS 深度解密镜像
- 威胁情报源暂不支持自动强制拦截（Feed Auto-Enforce）
- 若主机遭遇 Root 权限的底层破坏，本系统无法提供绝对免死防护
- 暂未包含完整的 Measured Boot 远程度量证明
- Gaia Cells 隔离生命周期守护进程独立存在（属于 AstraeaOS 专属组件）
- 隔离诱捕服务（Deception Service）顺延规划

---

## 📋 版本更新日志 (Changelog)

### v4.2.0 — Security Fabric Control Plane *(当前版本)*

* **全面安全审计整改与系统加固：**
  * **严重：** 彻底修复金丝雀陷阱中的符号链接遍历漏洞（任意文件写入 / root 提权）。采用基于 `openat(2)` 并带有 `O_NOFOLLOW|O_DIRECTORY` 的逐级安全路径解析，强制阻断符号链接并返回 `ELOOP`。
  * **高危：** 修复 5 个 API 处理器向客户端泄露原始运行时错误信息的缺陷；以强类型的不透明错误响应全面取代脆弱的关键词子串黑名单。
  * **高危：** 强化 CSPRNG 故障安全退出语义（`log.Fatalf`），防止证据链、安全事件、隔离区及阻断记录降级生成可预测的时间戳 ID。
  * **高危：** 修复配置导入预览功能中的远程崩溃隐患，采用故障安全的安全密钥派生逻辑。
  * **高危：** 导入令牌在密码学层面严格绑定已审计内容的哈希指纹，防止令牌重用与碰撞攻击。
  * **中危：** 策略引擎、威胁情报与 Chronos 检查点全面切换至防崩溃原子写入器（`atomicWriteFile`），具备符号链接拦截、`O_EXCL` 标识及对文件与父目录的双重 `fsync` 刷新。
  * **中危：** 彻底从 CSP 中移除 `unsafe-inline` 样式指令；HSTS 强制仅在 TLS 加密通信下生效。
* **Security Fabric Control Plane（安全织网控制平面）：**
  * 涵盖 12 大模块化子系统（`kinetic`、`network`、`protection`、`xdr`、`l7`、`threat_intel`、`hardening`、`integrity`、`boot_trust`、`policy_trust`、`forensics`、`system`）。
  * 服务端 Schema 驱动，热路径上的不可变快照，持久化的 `restart_required` 重启感知语义。
  * 核心安全不变量严禁随意配置修改：内核 Map 规则上限、Core IPC 认证、私钥加密存储、管理网络防自锁、情报源防投毒校验。
* **控制平面工作台与遥测能力：**
  * 确定性配置搜索功能（`GET /api/v1/settings/search`），支持查看实时生效值与命中规则释义。
  * 密码学签名且脱敏的跨域配置导出（`POST /api/v1/settings/export`）。
  * 真正的双阶段安全导入（`/import/preview` + `/import/apply`），内置 Diff 差异比对及单次有效的过期令牌。
  * 实时配置漂移感知（`GET /api/v1/settings/drift`），在同步异常时主动触发 `CONFIG_DRIFT` 预警。
* **完全离线的矢量 SVG 世界地图（jsVectorMap 1.7.0）：**
  * 100% 本地渲染，无任何外部 CDN 或瓦片地图依赖；原生 button 交互设计确保完全符合 `require-trusted-types-for 'script'` 标准。
  * 本地 GeoIP/ASN 解析，等值面威胁密度渲染，实时攻击定位标记与流量动态脉冲。
* **UI/UX Supreme — 现代化控制台重新设计：**
  * 淘汰传统笨重的卡片网格，采用统一的指挥层与分组遥测面板。
  * 采用带有发丝分割线的语义化 `<dl>` 数据条带取代厚重的边框。
  * 纯状态驱动的高亮配色：仅在指标非零时激活功能性提示色。
  * 完整的键盘操作无障碍支持（`<button>`），符合 WCAG AA 对比度规范，支持 `prefers-reduced-motion`。
* **运行时与底层引擎修复：**
  * 修复 `CaseEngine.Status` 中的递归锁死锁问题。
  * 彻底消除 Airlock 检查器与 CaseEngine 中的故障开放（fail-open）状态。
  * 修复针对多层级资源请求的 `GET /assets/{name...}` 路由解析异常。
  * 将 Go 工具链的最低版本安全底线上调至 ≥ 1.26.6（修复 6 个已知的标准库 CVE 漏洞）。

### v4.0.1 — 简体中文本地化、专用 XDR 内核恢复与扩展

- **简体中文（`zh-CN` / `ZH`）本地化：** 全面支持指挥中心简体中文界面（743 个词条，与德语、英语、俄语完全平齐）。在登录页加入中文选项与 Cookie 持久化支持。
- **专用 XDR 内核恢复面板：** 引入 `#xdr` 专用恢复页面与 `/api/v1/xdr/recovery` 接口，具备 `ARCHIVE_AND_REINITIALIZE_XDR` 确认拦截，可在不借助 SSH 的情况下直接备份受损账本并重启 eBPF 内核传感器。
- **账本哈希域解耦：** 攻击故事默克尔证据树根（`evidence_root`）与 HMAC 账本链哈希（`record_hash`）各自独立，避免服务重启后误报异常。
- **全局版本对齐：** 将全套服务组件、网关、Web 端、契约测试、Rust 工作空间及打包脚本统一升级至 `4.0.1`。

### v4.0.0-beta.1 — 原生 L7 应用安全防御与关联加固

**L7 应用安全平面（WAF 与 API 网关）**

- **Go 标准库原生实现：** 内置 L7 检测引擎直接集成于非特权 Go 控制守护进程（`gedefense-control`）内部。100% 纯 Go 实现，无 CGO，零第三方外部依赖，无需 Lua、WASM 或 Node.js 环境。
- **双模部署架构：**
  - *建议/独立套接字模式：* 权限为 `0660` 的 Unix 域套接字（`/run/vgt-gedefense-l7/inspect.sock`），提供标准化 JSON 评估接口（`POST /v1/inspect`）及严格字段校验（`DisallowUnknownFields`），对接外部反向代理（nginx、Caddy、Envoy、Apache）。
  - *原生内联反向代理模式：* 透明内联过滤器（`/run/vgt-gedefense-l7/edge.sock`），串联于 TLS 终止与业务应用之间，提供并发控制与故障安全关闭预算。
- **严格的上游隔离（防 SSRF）：** 转发目标严格限定为干净的绝对 Unix 套接字或回环 IP 字面量（`127.0.0.1`、`[::1]`）。从架构上杜绝了请求重定向与动态 DNS 解析隐患。
- **有界规范化与反规避引擎：**
  - 多轮递归反转义（URL 路径及参数解码、HTML 实体、`\uXXXX` 与 `\xXX` 转义字符）。
  - 全角字符转半角折叠（Unicode Fullwidth Fold 将 `\uff01`–`\uff5e` 转为 ASCII），防范通过特殊宽字符绕过过滤。
  - 自动识别并解码参数中的未填充及 URL 安全 Base64 负载。
  - 流式 JSON 解析器，具有严格的递归深度限制（`max_json_depth = 32`）与令牌配额。
  - 有界解压缩：通过 `io.LimitReader` 处理 Gzip/Deflate，防御解压炸弹（Zip-bomb DoS）。
  - 针对非结构化文本使用 16 KB 分块（重叠 256 字节），在无额外内存分配开销的前提下防止跨块截断绕过。
- **全方位攻击检测特征库（线性 RE2 引擎，零 ReDoS 风险）：**
  - *SQL 注入（SQLi）：* UNION SELECT 语法、布尔恒真式（`' OR 1=1`）、时间延迟（`pg_sleep`、`benchmark`）及堆叠查询语句。
  - *跨站脚本（XSS）：* 脚本标签、内联事件处理器（`onerror=`、`onload=`）、危险伪协议（`javascript:`、`data:text/html`）及 `iframe srcdoc` 攻击载荷。
  - *命令注入 / RCE：* 命令拼接符（`;`、`&&`、`||`、`|`）、命令替换（`$(...)`、反引号）及 PowerShell/CMD 载荷。
  - *路径遍历与本地文件包含（LFI）：* 遍历序列（`../`、`..\`）、Linux 敏感路径（`/etc/passwd`、`/proc/self/environ`）及流包装器（`php://`、`phar://`、`data://`）。
  - *SSTI、XXE 与反序列化：* 模板语法（Jinja、Twig、Smarty、Spring）、外部 XML 实体、PHP 序列化对象、Java 序列化魔数（`rO0AB`）及 JNDI/Log4j 表达式。
  - *HTTP 协议走私与畸形解析：* 重复或非法的 `Content-Length`、CL.TE / TE.CL 冲突、非法传输编码及被禁用的 `TRACE` 方法。
- **反规避 SSRF 检测与灵活 IP 规范化：**
  - 规范化并拦截非常规 IPv4 表示法：十六进制、八进制、十进制整数及简写形式。
  - 全面阻断针对各大云厂商元数据接口的探测（AWS IMDSv2、GCP、Azure、阿里云、Oracle 云）。
- **内存中 Airlock 复合上传检查（`InspectBytes`）：**
  - 上传文件在落盘前直接于内存中完成检查。
  - 严格限制分块数量与文件大小；校验魔数、MIME 匹配、双重扩展名、截断空字节及 SHA-256 恶意哈希。
- **三层分片令牌桶速率限制：**
  - 64 个基于 FNV-1a 哈希的独立分片，消除高并发流量下的锁竞争。
  - 客户端维度的流量速率限制。
  - 敏感端点（`/login`、`/wp-login.php`、`/api/login`）防爆破保护。
  - 全局敏感路由限速（防御分布式僵尸网络攻击）。
- **响应数据泄露防护（DLP）：**
  - 实时监听上游响应，防止数据库报错、源码、堆栈轨迹及私钥泄露。
  - 严格保持网络传输层原始字节未被更改。

**XDR 关联分析与主机完整性**

- **Web 证据隔离（防误报屏障）：** L7 事件标记为 `AlertOnly: true`（`ResponseScore: 0`）。Web 告警绝不能自主触发针对主机进程的破坏性处置动作；必须依托独立内核证据。
- **接入 Trinity XDR 2.0 DAG：** 将 L7 网络事件作为节点写入因果图谱，提供默克尔根签名确证。
- **主机网络关联追踪：** 实时关联外来恶意 HTTP 请求与 Linux 本地套接字连接（`SO_PEERCRED` 及 `NetConnection` 远程追踪）。
- **受控强制拦截放行：** 仅当发布门禁达到健康通过的 `Enforce` 状态时，才启用内联拦截阻断。

**Systemd 服务、Linux 访问控制与加固**

- 专用系统组 `gedefense-l7`，通过 `systemd-tmpfiles` 创建受保护目录 `/run/vgt-gedefense-l7`（权限 `0750`）。
- 套接字权限配置为 `0660`，启用内核级凭据核验（`SO_PEERCRED`）。
- 锁定 Go 1.26.8 工具链，并通过 AST 静态安全审计验证。
- CI 持续集成中包含 3 套高强度模糊测试（Fuzzing）。

### v3.0.0-beta.1 — 通用 Linux 原生集成

**集成与部署**

- 将此前 AstraeaOS 专属的安全契约全面推广至通用 Linux 发行版。
- 添加针对 APT、DNF/YUM、pacman 与 Zypper 的安装依赖自动解析。
- 新增通用 Polkit 权限控制边界与 systemd 服务就绪助手。
- 提供基于 Chromium 独立用户配置环境的桌面快捷方式，使用精准的证书 SPKI 锁定，无需修改系统信任库。
- 将 SDDM、ArchISO 及 Gaia Cells 等特殊行为限定为仅在 AstraeaOS 环境下启用。

**安全与代码健壮性**

- 生成的网关 TLS 证书 SAN 扩展中补充 `localhost`、`127.0.0.1` 及 `::1` 映射。
- 将恶意软件信誉哈希数据库深度整合至构建、发布、加密配置与回滚状态中。
- 引入具备故障闭锁特性的资源校验清单、违规机密标识扫描、符号链接拒绝及体积上限约束。
- 规范化 Linux 脚本换行符（LF）并显式授予执行权限。

**工程化发布流水线**

- 实施严格的 Go 单元/竞态/模糊测试及静态安全门禁。
- 锁定 Rust 用户态测试、Rust Core 正式版本及 no_std eBPF 程序构建。
- 引入基于哈希指纹锁定的 Ubuntu、Fedora、Arch 与 openSUSE 矩阵构建任务。
- 将 GitHub Actions 插件锁定至固定的 40 位 Git Commit 哈希。
- 引入特权主机流水线，实测 bpffs、eBPF、XDP 挂载、IPC/TLS、systemd 与 Polkit。

**稳固的安全基石**

- Go 控制平面、Rust 响应核心与 Rust eBPF/XDP 数据平面构成的三权分立安全基础保持不变。
- Observe → Canary → Enforce 演进逻辑、证据账本、加密隔离库与可逆加固机制始终如一。

### v1.0.0-beta.5 — 完整测试版 (Complete Beta)

里程碑意义的 Complete Beta 标志 — 核心防御链条功能完备并可供测试。3.5.1 安装程序配备全流程验证门禁（编译、内核验证器、XDP 挂载、IPC、后端、TLS）。拥有与 GaiaOS 源码逐字节一致的镜像仓库，全量测试矩阵顺利通过。

---

## 🔗 VGT 主权生态项目

| 项目名称 | 定位分类 | 核心使命 |
|---|---|---|
| 🛡️ **VGT GeDefense** | **Linux 主权安全矩阵** | 内核就近防御、主机 XDR、加密证据账本 — 当前所在项目 |
| 🧠 **[VGT AETHEL](https://github.com/visiongaiatechnology/aethel)** | **主权 AI 操作系统** | 本地运行、由系统操作员全权治理的主权人工智能系统 |
| 🖥️ **[VGT WP-Desk](https://github.com/visiongaiatechnology/vgtdesk)** | **OS 适配层 / UX** | 经过深度安全加固的 WordPress 操作员工作空间 |
| ⚔️ **[VGT Sentinel](https://github.com/visiongaiatechnology/sentinelcom)** | **WAF / IDS** | 适用于 WordPress 的零信任 Web 应用防火墙 |
| ⚡ **[VGT Auto-Punisher](https://github.com/visiongaiatechnology/vgt-auto-punisher)** | **IDS** | L4+L7 混合式入侵检测防御系统 |
| 🔐 **[VGT Omega Vault](https://github.com/visiongaiatechnology/vgt-omega-vault)** | **加密表单系统** | 采用 AES-256-GCM 高强度加密的 WordPress 数据保险库 |
| 🌐 **[GaiaCom](https://github.com/visiongaiatechnology/GaiaCom)** | **安全通信** | 后量子加密、联邦化端到端加密（E2EE）安全通信平台 |
| 📊 **[VGT Dattrack](https://github.com/visiongaiatechnology/dattrack)** | **数据分析** | 主权掌控的本地隐私数据分析系统 |

---

## 💙 支持我们的开源使命

[![Donate](https://img.shields.io/badge/Donate-PayPal-00457C?style=for-the-badge&logo=paypal)](https://paypal.me/dergoldenelotus)

| 赞助途径 | 接收地址 / 链接 |
|---|---|
| **PayPal** | [paypal.me/dergoldenelotus](https://paypal.me/dergoldenelotus) |
| **Bitcoin** | `bc1q3ue5gq822tddmkdrek79adlkm36fatat3lz0dm` |
| **ETH / USDT (ERC-20)** | `0xD37DEfb09e07bD775EaaE9ccDaFE3a5b2348Fe85` |

---

## 📄 开源许可证

**AGPL-3.0-only · © 2026 VisionGaia Technology · 德国科隆**

VGT GeDefense 属于自由开源软件：您可以根据自由软件基金会发布的 GNU Affero 通用公共许可证（仅限第 3 版）条款重新分发和/或修改它。任何衍生作品或基于网络运行的修改版本，均必须以相同的许可证条款公开发布。

企业级部署支持、TIER-0 安全审计认证（VGT SafetySys™）及商业豁免许可咨询：[visiongaiatechnology.de](https://visiongaiatechnology.de)

---

<div align="center">

**VISIONGAIATECHNOLOGY – WE ARCHITECT THE FUTURE OF SECURITY.**

[![VGT](https://img.shields.io/badge/VisionGaia-Technology-cyan?style=for-the-badge)](https://visiongaiatechnology.de)

*VGT GeDefense 4.2.0 — Universal Linux Security Fabric // Rust eBPF/XDP Data Plane // Go Control Plane // Host XDR // Ed25519 Evidence Ledger // AES-256-GCM Encrypted Vault // Reversible Hardening // AstraeaOS-Native Adapter // Separated Trust Domains // No Cloud Control Plane // AGPL-3.0-only // Linux x86_64*

</div>
