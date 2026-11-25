# Nacos v2.2.3-bzz 分支说明

> 基于阿里巴巴 Nacos 官方 **v2.2.3** 定制的私有分支，主要目标：在开启鉴权的前提下，保留
> IP 白名单免鉴权与老客户端兼容能力，并修复官方版本存在的鉴权缺陷，满足 TDP（微步威胁感知平台）
> 安全验收要求。

- 上游仓库：https://github.com/alibaba/nacos.git
- 本分支仓库：https://github.com/jackBaozz/nacos.git
- 基线版本：官方 tag `2.2.3`
- 当前分支：`v2.2.3-bzz-v3`

---

## 目录

1. [与官方 v2.2.3 的差异](#一与官方-v223-的差异)
2. [安全复验结论](#二安全复验结论)
3. [编译与打包](#三编译与打包)
4. [部署 — Linux](#四部署--linux)
5. [部署 — Windows](#五部署--windows)
6. [部署后验证](#六部署后验证)
7. [注意事项与踩坑记录](#七注意事项与踩坑记录)

---

## 一、与官方 v2.2.3 的差异

### 1.1 改动文件总览

| 文件 | 性质 | 说明 |
|---|---|---|
| `auth/src/main/java/com/alibaba/nacos/auth/config/AuthConfigs.java` | 官方文件，新增字段 | 新增 `ipAuthWhite`、`legacyClientAnonymousEnabled` 两个配置项 |
| `core/src/main/java/com/alibaba/nacos/core/auth/AuthFilter.java` | 官方文件，新增逻辑 | HTTP 侧：IP 白名单放行、老客户端匿名放行、白名单取 IP 安全修复 |
| `core/src/main/java/com/alibaba/nacos/core/auth/RemoteRequestAuthFilter.java` | 官方文件，新增逻辑 | gRPC 侧：老客户端匿名放行 |
| `console/src/main/java/com/alibaba/nacos/console/controller/NamespaceController.java` | 官方文件，补注解 | 3 个 GET 接口补 `@Secured(READ)` |
| `console/src/main/resources/application.properties` | 配置（源码默认值） | 鉴权开关、白名单、identity、token key |
| `distribution/conf/application.properties` | 配置（发行包默认值） | **部署时实际生效的配置**，新增白名单与兼容开关占位 |
| `config/.../datasource/ExternalDataSourceProperties.java` | 官方文件，改常量 | MySQL 驱动类名 `com.mysql.cj.jdbc.Driver` → `com.mysql.jdbc.Driver`（兼容 MySQL 5.x 老驱动） |
| `pom.xml`、`style/nacos-eclipse-formatter.xml`、`README_CHANGE.md` | 杂项 | 格式化/换行符差异、IDE 格式化配置、变更记录 |

> 说明：`git diff --stat` 显示 `AuthFilter.java` 502 行、`pom.xml` 2062 行等大数字，
> 绝大部分是 CRLF/LF 换行符差异；用 `git diff -w` 忽略空白后，Java 代码真实改动约 **262 行新增 / 7 行删除**。

### 1.2 新增配置项

| 配置项 | 默认值 | 说明 |
|---|---|---|
| `nacos.core.auth.enable.ipAuthWhite` | 空 | IP 白名单，英文逗号分隔。命中的来源 IP **跳过全部鉴权** |
| `nacos.security.legacy-client.anonymous.enabled` | `false` | 开启后，老客户端核心接口匿名放行（HTTP + gRPC 两侧同时生效） |

### 1.3 功能改动详解

#### （1）IP 白名单（`AuthFilter` + `AuthConfigs`）

官方没有此功能。新增逻辑：

```java
// AuthFilter.doFilter()
String originIp = getRealRemoteIp(req);          // 只取 TCP 真实地址

if (isLegacyClientAllowed(req)) { chain.doFilter(...); return; }

if (StringUtils.isNotBlank(authConfigs.getWhiteIpStr())) {
    for (String ip : authConfigs.getWhiteIpStr().split(",")) {
        if (ip.equals(originIp)) { chain.doFilter(...); return; }   // 白名单命中 → 放行
    }
} else if (authConfigs.isEnableUserAgentAuthWhite()) {
    // ...官方原有逻辑不变...
}
```

**注意**：一旦配置了 `ipAuthWhite`，官方原有的 `userAgentAuthWhite` / `server.identity.key` 两个分支
将不再进入（`if / else if` 互斥），这是原设计意图，升级时请知悉。

#### （2）老客户端匿名兼容（`AuthFilter` + `RemoteRequestAuthFilter`）

开启 `nacos.security.legacy-client.anonymous.enabled=true` 后，以下接口对匿名请求放行：

| 协议 | 放行的接口 / 请求类型 |
|---|---|
| HTTP | `GET /v1/cs/configs`、`POST /v1/cs/configs/listener` |
| HTTP | `POST/DELETE /v1/ns/instance`、`PUT/POST /v1/ns/instance/beat` |
| HTTP | `GET /v1/ns/instance/list`、`GET /v1/ns/service/list` |
| gRPC | `ConfigQueryRequest`、`ConfigBatchListenRequest` |
| gRPC | `InstanceRequest`、`BatchInstanceRequest` |
| gRPC | `ServiceQueryRequest`、`SubscribeServiceRequest` |

> 这是**有意的安全降级**：仅在确实存在无法升级、无法配置账号密码的 1.x 老客户端时才开启。
> 默认 `false`，TDP 验收环境下必须保持 `false`。

#### （3）白名单取 IP 安全修复（`AuthFilter`）

早期版本的白名单比对优先读取 `X-Forwarded-For` / `Proxy-Client-IP` / `WL-Proxy-Client-IP`
请求头。这些头由客户端任意填写，攻击者只需伪造为白名单 IP 即可**绕过全部鉴权**（含读取用户密码哈希）。

已修复为只使用 `request.getRemoteAddr()`（TCP 层真实来源，不可伪造），IPv6 本机地址 `0:0:0:0:0:0:0:1`
归一化为 `127.0.0.1`。

```java
private String getRealRemoteIp(HttpServletRequest request) {
    String ip = request.getRemoteAddr();
    return AN_OBJECT.equals(ip) ? LOCALHOST_STRING : ip;
}
```

> 若 Nacos 部署在 Nginx 等反向代理之后，所有请求的 `remoteAddr` 都是代理 IP，白名单应在代理层实现，
> 而不是信任转发头。

#### （4）命名空间接口补鉴权（`NamespaceController`）

官方 v2.2.3 原文中 `getNamespaces()`、`getNamespace()`、`checkNamespaceIdExist()` 三个 GET 方法
**没有** `@Secured` 注解（已用 `git show 2.2.3:...` 核对），匿名可枚举全部命名空间。
本次补上：

```java
@GetMapping
@Secured(resource = AuthConstants.CONSOLE_RESOURCE_NAME_PREFIX + "namespaces", action = ActionTypes.READ)
public RestResult<List<Namespace>> getNamespaces() { ... }
```

#### （5）保留匿名的接口

`GET /v1/console/server/state` 返回版本号、`auth_enabled`、`standalone_mode` 等信息。
该接口是控制台前端 `console-ui/src/reducers/base.js` 在**登录前**调用的，用于决定是否渲染登录页，
无法加 `@Secured`。Nacos Client SDK 不依赖此接口（源码中零引用）。
TDP 验收方案中已明确接受该接口可匿名，**保持原样**。

---

## 二、安全复验结论

复验环境：本分支单机模式，`nacos.core.auth.enabled=true`，白名单 `127.0.0.1`，
从非白名单地址 `10.5.87.132` 发起请求。

| # | 接口 | 期望 | 结果 |
|---|---|---|---|
| 1 | `GET /v1/console/server/state` | 可匿名 | 200 ✅ |
| 2 | `GET /v1/cs/configs?dataId=...&group=DEFAULT_GROUP` | 403 | 403 ✅ |
| 3 | `GET /v1/auth/users?search=accurate&pageNo=1&pageSize=1`（无 UA） | 403 | 403 ✅ |
| 3 | 同上，带 `User-Agent: Nacos-Server` | 403 | 403 ✅ |
| 4 | `GET /v1/ns/service/list?pageNo=1&pageSize=1&namespaceId=public` | 403 | 403 ✅ |
| 5 | `GET /v1/console/namespaces` | 403 | 403 ✅ |
| — | 伪造 `X-Forwarded-For: 127.0.0.1` / `Proxy-Client-IP` / `WL-Proxy-Client-IP` | 403 | 403 ✅ |
| — | 白名单 `127.0.0.1` 直连，不带 token | 放行 | 200 ✅ |

鉴权开启后对客户端 / 控制台的影响（官方 SDK 2.2.3 实测）：

| 场景 | 结果 |
|---|---|
| 客户端配置了 `username` / `password` | 配置发布/读取 ✅ 服务注册 ✅ |
| 客户端未配置账号密码（匿名） | 全部拒绝 `403 user not found!` |
| 控制台：首页、静态资源、登录前 `server/state` | 200 ✅ |
| 控制台：登录后各业务接口（带 token） | 200 ✅ |

**结论**：开启鉴权后，所有接入的客户端**必须**配置账号密码，否则连接失败。

---

## 三、编译与打包

### 3.1 环境要求

| 项目 | 要求 |
|---|---|
| JDK | 8+（本次验证使用 OpenJDK 21；服务器建议 11 或 17） |
| Maven | 3.6.3+（本次验证 3.6.3） |
| 构建机架构 | x86_64 或 arm64 均可（fat jar 内 `rocksdbjni 7.7.3` 同时包含两种架构） |
| 网络 | 首次构建需访问 Maven 中央仓库 |

### 3.2 构建发行包

```bash
cd /Users/bao/work/idea_workspace/nacos_my

mvn -B install \
    -DskipTests \
    -Drat.skip=true \
    -Dcheckstyle.skip=true \
    -Dpmd.skip=true \
    -Prelease-nacos \
    -pl distribution -am
```

参数说明：

| 参数 | 作用 |
|---|---|
| `-Prelease-nacos` | **必须**。激活后 `console` 模块才会执行 `spring-boot:repackage` 生成 fat jar `nacos-server.jar` |
| `-pl distribution -am` | 只构建 `distribution` 及其上游依赖，省去 test/example 等模块 |
| `-Drat.skip=true` | 跳过 Apache RAT license 头检查（仓库内有 `.vscode/settings.json` 等本地文件会触发失败） |
| `-Dcheckstyle.skip -Dpmd.skip` | 跳过代码风格检查 |
| `-DskipTests` | 跳过单元测试 |

> ⚠️ **不要加 `clean`**。`consistency` 模块使用 `protobuf-maven-plugin` 生成 Java 类，
> `clean` 后首次构建会出现 `ReadRequest` / `WriteRequest` 找不到的编译错误。
> 若必须 clean，请先单独构建一次 `consistency` 模块，再构建整体。

### 3.3 产物

```
distribution/target/
├── nacos-server-2.2.3.zip          ← Windows 用
├── nacos-server-2.2.3.tar.gz       ← Linux 用
└── nacos-server-2.2.3/nacos/       ← 解压后的目录结构
    ├── bin/
    │   ├── startup.sh / shutdown.sh       (Linux/macOS)
    │   └── startup.cmd / shutdown.cmd     (Windows)
    ├── conf/
    │   ├── application.properties         ← 部署时修改此文件
    │   ├── cluster.conf.example
    │   ├── mysql-schema.sql / derby-schema.sql
    │   └── nacos-logback.xml
    ├── target/
    │   └── nacos-server.jar               (约 156 MB)
    ├── plugins/
    ├── LICENSE
    └── NOTICE
```

### 3.4 本地开发运行（IDE / 命令行，不打包）

```bash
# 1. 编译全部模块并生成 classpath
mvn -B install -DskipTests -Drat.skip=true -Dcheckstyle.skip=true -Dpmd.skip=true -q
mvn -pl console dependency:build-classpath -Dmdep.outputFile=target/cp.txt -q

# 2. 启动（单机模式 + 内嵌 Derby）
cd console
java -Dnacos.standalone=true -cp "target/classes:$(cat target/cp.txt)" com.alibaba.nacos.Nacos
```

> 单机模式**必须**用 JVM 参数 `-Dnacos.standalone=true`。
> `EnvUtil.getStandaloneMode()` 读取的是 System property，程序参数 `--nacos.standalone=true` 无效，
> 会导致以集群模式启动后因缺少 `cluster.conf` 退出。

---

## 四、部署 — Linux

### 4.1 前置条件

- JDK 8+ 已安装，`JAVA_HOME` 已配置（`startup.sh` 会读取）
- 开放端口：**8848**（HTTP / 控制台）、**9848**（gRPC，2.x 客户端必需）、**9849**（集群节点间 gRPC）
- 集群模式需要 MySQL 5.7+ / 8.0

### 4.2 安装

```bash
# 建议使用专用用户
sudo useradd -r -s /sbin/nologin nacos

sudo mkdir -p /opt/nacos
tar -zxvf nacos-server-2.2.3.tar.gz -C /opt/nacos --strip-components=1
sudo chown -R nacos:nacos /opt/nacos
```

### 4.3 修改配置（必做）

编辑 `/opt/nacos/conf/application.properties`：

```properties
# ① 开启鉴权（发行包默认 false，必须改）
nacos.core.auth.enabled=true

# ② JWT 密钥：Base64 编码，解码后 ≥ 32 字节。不填则启动报错。
#    生成命令: openssl rand -base64 48
nacos.core.auth.plugin.nacos.token.secret.key=<在服务器上生成，勿复用他人密钥>

# ③ 服务间通信身份，自定义一对随机字符串
nacos.core.auth.server.identity.key=<随机字符串>
nacos.core.auth.server.identity.value=<随机字符串>

# ④ IP 白名单（本分支新增）。只填固定可信 IP，不要填 DHCP 动态地址。
#    命中白名单的来源会跳过全部鉴权（含读取用户密码哈希），请谨慎。
nacos.core.auth.enable.ipAuthWhite=127.0.0.1

# ⑤ 老客户端匿名兼容（本分支新增）。有无法升级的 1.x 客户端才开启，安全验收时保持 false。
nacos.security.legacy-client.anonymous.enabled=false
```

**集群模式**额外需要：

```properties
# 取消注释并填写 MySQL
spring.sql.init.platform=mysql
db.num=1
db.url.0=jdbc:mysql://<mysql-host>:3306/nacos?characterEncoding=utf8&connectTimeout=10000&socketTimeout=30000&autoReconnect=true&useUnicode=true&useSSL=false&serverTimezone=Asia/Shanghai&allowPublicKeyRetrieval=true
db.user.0=nacos
db.password.0=<password>
```

```bash
# 在 MySQL 中执行建表脚本
mysql -u root -p nacos < /opt/nacos/conf/mysql-schema.sql

# 填写节点列表（每行一个 ip:8848，至少 3 节点）
cp /opt/nacos/conf/cluster.conf.example /opt/nacos/conf/cluster.conf
vim /opt/nacos/conf/cluster.conf
```

### 4.4 启动 / 停止

```bash
# 单机模式
bash /opt/nacos/bin/startup.sh -m standalone

# 集群模式
bash /opt/nacos/bin/startup.sh

# 停止
bash /opt/nacos/bin/shutdown.sh

# 查看日志
tail -f /opt/nacos/logs/start.out
tail -f /opt/nacos/logs/nacos.log
```

### 4.5 注册为 systemd 服务（推荐）

官方脚本不托管进程，建议用 systemd 守护：

```ini
# /etc/systemd/system/nacos.service
[Unit]
Description=Nacos Server (v2.2.3-bzz)
After=network.target

[Service]
Type=forking
User=nacos
Group=nacos
Environment="JAVA_HOME=/usr/lib/jvm/java-17-openjdk-amd64"
ExecStart=/opt/nacos/bin/startup.sh -m standalone
ExecStop=/opt/nacos/bin/shutdown.sh
Restart=on-failure
RestartSec=10
LimitNOFILE=65536

[Install]
WantedBy=multi-user.target
```

```bash
sudo systemctl daemon-reload
sudo systemctl enable --now nacos
sudo systemctl status nacos
```

---

## 五、部署 — Windows

### 5.1 前置条件

- 安装 JDK 8+（建议 11 或 17）
- 配置系统环境变量 `JAVA_HOME`（如 `C:\Program Files\Java\jdk-17`），`startup.cmd` 依赖它
- 安装路径**不含空格和中文**，建议 `D:\nacos`
- 防火墙放行 **8848** 和 **9848**

### 5.2 安装

1. 解压 `nacos-server-2.2.3.zip` 到 `D:\nacos`（确保 `D:\nacos\bin\startup.cmd` 存在）
2. 修改 `D:\nacos\conf\application.properties`，内容与 [4.3 节](#43-修改配置必做) 完全一致

### 5.3 启动 / 停止

```cmd
cd /d D:\nacos\bin
startup.cmd -m standalone
shutdown.cmd
```

> 直接运行会弹出一个 CMD 窗口，**关闭窗口即杀掉进程**，仅适合临时调试。

### 5.4 注册为 Windows 服务（推荐）

`startup.cmd` 不支持后台常驻，使用 [WinSW](https://github.com/winsw/winsw) 包装：

1. 下载 `WinSW-x64.exe`，重命名为 `nacos-service.exe`，放到 `D:\nacos\bin\`
2. 同目录创建 `nacos-service.xml`：

```xml
<service>
  <id>nacos</id>
  <name>Nacos Server (v2.2.3-bzz)</name>
  <description>Alibaba Nacos v2.2.3-bzz</description>
  <env name="JAVA_HOME" value="C:\Program Files\Java\jdk-17"/>
  <executable>D:\nacos\bin\startup.cmd</executable>
  <arguments>-m standalone</arguments>
  <workingdirectory>D:\nacos\bin</workingdirectory>
  <startmode>Automatic</startmode>
  <delayedAutoStart>true</delayedAutoStart>
  <log mode="roll-by-size">
    <sizeThreshold>10240</sizeThreshold>
    <keepFiles>8</keepFiles>
  </log>
  <stopexecutable>D:\nacos\bin\shutdown.cmd</stopexecutable>
</service>
```

3. 以管理员身份运行：

```cmd
cd /d D:\nacos\bin
nacos-service.exe install
nacos-service.exe start
```

---

## 六、部署后验证

在**服务器本机**执行（用服务器的真实内网 IP 替换 `<ip>`，不要用 `localhost`，否则会被白名单放行导致假阴性）：

```bash
# 版本与鉴权状态，auth_enabled 应为 "true"
curl -s http://<ip>:8848/nacos/v1/console/server/state

# 以下 4 项应全部返回 403
curl -s -o /dev/null -w '%{http_code}\n' 'http://<ip>:8848/nacos/v1/cs/configs?dataId=probe&group=DEFAULT_GROUP'
curl -s -o /dev/null -w '%{http_code}\n' 'http://<ip>:8848/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=1'
curl -s -o /dev/null -w '%{http_code}\n' -H 'User-Agent: Nacos-Server' 'http://<ip>:8848/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=1'
curl -s -o /dev/null -w '%{http_code}\n' 'http://<ip>:8848/nacos/v1/console/namespaces'

# X-Forwarded-For 伪造绕过，应返回 403
curl -s -o /dev/null -w '%{http_code}\n' -H 'X-Forwarded-For: 127.0.0.1' 'http://<ip>:8848/nacos/v1/auth/users?search=accurate&pageNo=1&pageSize=1'

# 登录应成功并返回 accessToken
curl -s -X POST 'http://<ip>:8848/nacos/v1/auth/login' -d 'username=nacos&password=nacos'
```

浏览器访问 `http://<ip>:8848/nacos`，默认账号密码 `nacos` / `nacos`，**登录后请立即修改密码**。

---

## 七、注意事项与踩坑记录

### 7.1 部署必读

| 事项 | 说明 |
|---|---|
| **生效的配置文件是 `conf/application.properties`** | 启动脚本通过 `--spring.config.additional-location=file:.../conf/` 加载。源码 `console/src/main/resources/application.properties` 只影响 IDE 运行，**部署时不生效** |
| **开启鉴权后客户端必须配账号密码** | 匿名客户端会收到 `403 user not found!`。上线前为所有 Spring Cloud Alibaba / Dubbo / 原生 SDK 接入方配置 `username` / `password` |
| **token secret.key 必须重新生成** | 用 `openssl rand -base64 48` 在服务器上生成。不要复用文档、聊天记录或他人仓库中出现过的密钥 |
| **白名单是跳过全部鉴权** | 包括 `/v1/auth/users`（返回密码哈希）。只填固定可信 IP，禁止填 DHCP 动态地址 |
| **反代场景白名单失效** | Nginx 后面所有请求 `remoteAddr` 都是代理 IP，白名单应在代理层实现 |
| **集群必须用 MySQL** | 单机可用内嵌 Derby；集群必须外置 MySQL 并执行 `mysql-schema.sql` |
| **TDP 复验用真实 IP** | 用 `localhost` 会被白名单放行，扫出假阴性 |

### 7.2 构建踩坑

| 问题 | 原因 | 解决 |
|---|---|---|
| `Too many files with unapproved license` | Apache RAT 检查，`.vscode/settings.json` 等本地文件无 license 头 | 加 `-Drat.skip=true` |
| `ReadRequest` / `WriteRequest` 找不到 | `clean` 后 `consistency` 模块 protobuf 生成时序问题 | 构建不加 `clean`；或先单独构建 `consistency` |
| 生成不了 `nacos-server.jar` | 未激活 profile | 必须加 `-Prelease-nacos` |
| 旧 `nacos-server.jar` 在 Apple Silicon 上 `UnsatisfiedLinkError: librocksdbjni ... incompatible architecture` | 2023 年的旧构建产物内含 `rocksdbjni 5.18.4`，无 arm64 | 重新构建，新产物为 `rocksdbjni 7.7.3`，同时含 x86_64 / arm64 |

### 7.3 运行踩坑

| 问题 | 原因 | 解决 |
|---|---|---|
| 启动后立即退出，日志无明确错误 | 以集群模式启动但缺 `cluster.conf` | 加 `-Dnacos.standalone=true`（JVM 参数，不是程序参数） |
| `Another instance of Derby may have already booted the database` | 上一个进程未完全退出，持有 `data/derby-data` 锁 | 等待或 `kill` 旧进程后重启 |
| `Column 'ENCRYPTED_DATA_KEY' ... not a column` | `data/derby-data` 是旧版本 schema，Derby 不会自动迁移 | 备份并删除 `data/derby-data` 让其重建；或改用 MySQL |
| `the length of secret key must great than or equal 32 bytes` | 开启鉴权但 `token.secret.key` 为空或不合规 | 填入 Base64 编码、解码后 ≥ 32 字节的密钥 |
| `/v1/auth/users` 返回 500 | 缺少必填参数 | 必须带 `search=blur` 或 `search=accurate`，不是 bug |
| SDK `getConfig` 返回 `null` 但 `publishConfig` 为 `true` | 客户端 `namespace` 设为 `"public"`，实际变成了一个不存在的租户 | 默认命名空间的 ID 是**空字符串**，不要设置 `namespace=public` |

### 7.4 从旧版本升级

1. 备份 `conf/`、`data/`（或 MySQL 数据库）
2. 替换 `target/nacos-server.jar`、`bin/`、`plugins/`，**保留** `conf/` 和 `data/`
3. 对照新的 `conf/application.properties` 补齐新增配置项（鉴权 5 项）
4. 若使用内嵌 Derby 且跨大版本，Derby 不会自动迁移 schema，建议趁升级切换到 MySQL
5. 升级后按 [第六节](#六部署后验证) 逐项复验
