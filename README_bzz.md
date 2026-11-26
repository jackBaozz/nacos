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
| `console/pom.xml` | 官方文件，`release-nacos` profile 增强 | 排除 shade 版 `nacos-client`，改用 `pure` 版，消除 fat jar 重复类（见 3.2.1） |
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

#### （6）fat jar 打包修复（`console/pom.xml`）

官方 2.2.3 在 `-Prelease-nacos` 下构建出的 `nacos-server.jar` 内，`StringUtils` 等常用工具类
存在**两份副本**（独立的 `nacos-common.jar` + shade 进 `nacos-client.jar` 的裁剪版）。
`PropertiesLauncher`（`startup.cmd` / `java -jar`）可能先加载裁剪版，触发
`NoSuchMethodError: StringUtils.isBlank(Ljava/lang/String;)Z`。

修复方式见 [3.2.1](#321-fat-jar-结构说明本分支修复)：对 4 个直接依赖排除 shade 版 `nacos-client`，
改依赖 `pure` classifier。仅影响 server fat jar，不影响 SDK 发布包。

> 此问题在官方发行包中不会出现，因为官方是在**不激活** `release-nacos` 的情况下单独构建 console 的。
> 本分支需要在同一 profile 下同时产出 SDK 和 server，所以必须显式处理。

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
| **JDK** | **必须用 JDK 8 构建**（仓库已通过 `mise.toml` 约束：`java = "8"`）。**不能用 JDK 9+ 构建**，否则产物在 JDK 8 服务器上运行会报 `NoSuchMethodError: ByteBuffer.flip()Ljava/nio/ByteBuffer;`（见 7.2） |
| Maven | 3.6.3（`mise.toml` 约束 `maven = "3.6.3"`） |
| mvnd | 0.8.2（`mise.toml` 约束 `mvnd = "0.8.2"`，Maven 守护进程版，内嵌 Maven 3.8.6，构建更快） |
| 构建机架构 | x86_64 或 arm64 均可（fat jar 内 `rocksdbjni 7.7.3` 同时包含两种架构） |
| 网络 | 首次构建需访问 Maven 中央仓库 |

**构建前先确认环境**（务必在项目目录下执行，否则 mise 不会加载 `mise.toml`）：

```bash
cd /Users/bao/work/idea_workspace/nacos_my
mise exec -- java -version     # 期望: 1.8.x
mise exec -- mvn -version      # 期望: Apache Maven 3.6.3, Java version: 1.8.x
mise exec -- mvnd --version    # 期望: mvnd 0.8.2, Apache Maven 3.8.6, Java version: 1.8.x
```

> 如果 `Java version` 不是 1.8，说明终端的 `JAVA_HOME` 被其他工具覆盖了。
> 显式指定：`export JAVA_HOME="$(mise where java)" && export PATH="$JAVA_HOME/bin:$PATH"`

### 3.2 构建发行包

**严格使用官方 `BUILDING` 文档的全量 reactor 命令**，不要加 `-pl` / `-am`（原因见 7.2）。
`maven.simplify.skip=true` 已固化在根 `pom.xml` 的 `<properties>` 中，命令行无需再传。

**方式 A：mvnd（推荐，约 45 秒）**

```bash
cd /Users/bao/work/idea_workspace/nacos_my
export JAVA_HOME="$(mise where java)" && export PATH="$(mise where mvnd)/bin:$JAVA_HOME/bin:$PATH"

mvnd -Prelease-nacos -Dmaven.test.skip=true -Drat.skip=true clean install -U
mvnd --stop    # 构建完成后停掉 mvnd 后台 daemon，避免 Java 进程常驻
```

> mvnd 为加速下次构建会在后台保留一个 Java daemon 进程，构建结束后不会自动退出。
> 日常使用建议每次构建后执行 `mvnd --stop`；或设置环境变量 `MVND_DAEMON_IDLE_TIMEOUT=5000`（毫秒）让其空闲后自动退出。

**方式 B：mvn（约 60 秒）**

```bash
cd /Users/bao/work/idea_workspace/nacos_my
export JAVA_HOME="$(mise where java)" && export PATH="$(mise where maven)/bin:$JAVA_HOME/bin:$PATH"

mvn -Prelease-nacos -Dmaven.test.skip=true -Drat.skip=true clean install -U
```

> `-Drat.skip=true` 是官方命令之外**唯一**需要加的参数：仓库内 `.vscode/settings.json`、
> `build-release.sh` 等本地文件没有 license 头，会触发 Apache RAT 检查失败。
> 若连续构建遇到 mvnd daemon 文件锁残留，先执行 `mvnd --stop` 再重试。

参数说明：

| 参数 | 作用 |
|---|---|
| `clean` | **必须**。Maven 增量编译会保留陈旧的 `.class` 文件并直接打进 jar，导致运行期 `NoSuchMethodError`（见 7.2） |
| `-Dmaven.test.skip=true` | 跳过测试的**编译和运行**。注意不能用 `-DskipTests`——它只跳过运行、仍会编译测试代码，而 `consistency` 的测试类依赖 protobuf 生成顺序，clean 后编译会失败 |
| `-Prelease-nacos` | **必须**。激活后 `console` 模块才会执行 `spring-boot:repackage` 生成 fat jar `nacos-server.jar` |
| `-U` | 强制刷新 SNAPSHOT / 检查远程更新（官方命令自带） |
| `-Drat.skip=true` | 跳过 Apache RAT license 头检查 |
| `maven.simplify.skip=true`（pom 固化） | 跳过 `easyj-maven-plugin` 的 `simplify-pom`。该插件用于发布到 Maven 中央仓库时解析 `${revision}`，内部部署不需要；且它会在 package 阶段替换项目 POM，触发 `protobuf-maven-plugin` 的 `compile-custom` 在 jar 打包**之后**才执行，导致 `nacos-istio` / `nacos-consistency` jar 随机丢失 grpc 生成类（见 7.2）。已写入根 pom `<properties>`，无需命令行传递 |

**不要使用的参数**：

| 参数 | 原因 |
|---|---|
| `-pl distribution -am` | 改变 Maven 对上游模块 POM 的解析路径，加剧 protobuf 插件时序错乱。官方命令是全量 reactor |
| `-DskipTests` | 仍会编译测试代码，`consistency` 的 `ProtoMessageUtilTest` 在 clean 后编译失败 |

### 3.2.0 构建产物自检（部署前必做）

构建成功不代表产物可用，**每次构建后执行以下检查**：

```bash
J=console/target/nacos-server.jar

# ① class 文件版本必须是 52（Java 8）。若是 61/65 说明用了 JDK 17/21 构建
cd /tmp && rm -rf chk && mkdir chk && cd chk && unzip -o -q "$OLDPWD/$J" 'BOOT-INF/lib/nacos-sys-2.2.3.jar' \
  && unzip -o -q BOOT-INF/lib/nacos-sys-2.2.3.jar 'com/alibaba/nacos/sys/utils/DiskUtils.class' \
  && javap -v com/alibaba/nacos/sys/utils/DiskUtils.class | grep "major version"
#   期望: major version: 52

# ② ByteBuffer.flip 必须返回 Buffer（JDK 8 签名）。若返回 ByteBuffer 说明 JDK 9+ 编译
javap -c -p com/alibaba/nacos/sys/utils/DiskUtils.class | grep -oE "ByteBuffer\.flip:\(\)Ljava/nio/[A-Za-z]+;"
#   期望: ByteBuffer.flip:()Ljava/nio/Buffer;

# ③ fat jar 内只有 pure 版 nacos-client，无 shade 版重复类
unzip -l "$OLDPWD/$J" | grep -E "BOOT-INF/lib/nacos-(common|client|consistency|istio)-"
#   期望恰好四行: nacos-common-2.2.3.jar / nacos-client-2.2.3-pure.jar / nacos-consistency-2.2.3.jar / nacos-istio-2.2.3.jar
#   nacos-consistency 应约 100KB、nacos-istio 应约 1.4MB；若 consistency 只有 ~9KB 或 istio 只有 ~1.41MB 以下是空壳

# ④ protobuf 生成的 grpc 类必须存在（随机丢失会导致服务器启动 NoClassDefFoundError）
cd "$OLDPWD" && rm -rf /tmp/chk2 && mkdir -p /tmp/chk2 && cd /tmp/chk2 \
  && unzip -o -q "$OLDPWD/$J" 'BOOT-INF/lib/nacos-istio-2.2.3.jar' 'BOOT-INF/lib/nacos-consistency-2.2.3.jar'
unzip -l BOOT-INF/lib/nacos-istio-2.2.3.jar | grep -c "istio/mcp/v1alpha1/.*\.class"
#   期望: 83（坏包只有 68~69）
unzip -l BOOT-INF/lib/nacos-istio-2.2.3.jar | grep -c "ResourceSourceGrpc\$ResourceSourceImplBase"
#   期望: 1（为 0 则服务器启动必崩）
unzip -l BOOT-INF/lib/nacos-consistency-2.2.3.jar | grep -c "entity/ReadRequest.class"
#   期望: 1

# ⑤ 对外版本号（本分支故意隐藏真实版本）
unzip -p BOOT-INF/lib/nacos-common-2.2.3.jar nacos-version.txt
#   期望: version=9.9.9
```

> 也可直接执行仓库根目录的 `bash build-release.sh mvnd`，它会构建并自动完成以上全部检查，任一项失败以非 0 退出。

参考：mvnd 全量构建约 45 秒、mvn 约 60 秒（Apple Silicon，2026 年机器）。

### 3.2.1 fat jar 结构说明（本分支修复）

官方 2.2.3 在 `-Prelease-nacos` 下，`client` 模块的 `maven-shade-plugin` 会把 `nacos-common` /
`nacos-api` 合并进 `nacos-client` jar（对外发布的 SDK 需要）。但 `console` 的 fat jar 又同时打入了
独立的 `nacos-common-2.2.3.jar`，造成 **同一个类在 fat jar 中有两份副本**，且 shade 版经过
`minimizeJar` 裁剪，方法不全。`PropertiesLauncher`（`startup.cmd` 和 `java -jar` 都走它）的
类加载顺序可能先命中裁剪版，导致 `NoSuchMethodError`。

本分支在 `console/pom.xml` 的 `release-nacos` profile 中：
1. 对 `nacos-config` / `nacos-naming` / `nacos-istio` / `nacos-prometheus` 排除传递进来的 shade 版 `nacos-client`
2. 显式依赖 `nacos-client` 的 `pure` classifier（未 shade 的普通 jar，同一 profile 下产出）

修复后 fat jar 内只有 `nacos-common-2.2.3.jar` + `nacos-client-2.2.3-pure.jar`，无重复类。
此修改仅影响 server fat jar，**不影响**对外发布的 `nacos-client-2.2.3.jar` SDK。

验证命令：
```bash
unzip -l console/target/nacos-server.jar | grep -E "BOOT-INF/lib/nacos-(common|client)-"
# 期望输出恰好两行：
#   BOOT-INF/lib/nacos-common-2.2.3.jar
#   BOOT-INF/lib/nacos-client-2.2.3-pure.jar
```

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
# 0. 切到 mise 约束的 JDK 8
export JAVA_HOME="$(mise where java)" && export PATH="$JAVA_HOME/bin:$PATH"

# 1. 全量编译（官方命令，maven.simplify.skip 已固化在 pom）
mvn -Prelease-nacos -Dmaven.test.skip=true -Drat.skip=true clean install -U -q
mvn -pl console dependency:build-classpath -Dmdep.outputFile=target/cp.txt -q

# 2. 启动（单机模式 + 内嵌 Derby）
cd console
java -Dnacos.standalone=true \
     -Dnacos.core.auth.plugin.nacos.token.secret.key=$(openssl rand -base64 48) \
     -cp "target/classes:$(cat target/cp.txt)" com.alibaba.nacos.Nacos
```

> 源码默认配置 `nacos.core.auth.enabled=true` 且 `token.secret.key` 留空，本地启动必须用
> `-D` JVM 参数临时注入密钥，**不要把真实密钥写回源码**。
> 用 `-cp` 方式启动时类加载顺序与 `java -jar`（`PropertiesLauncher`）不同，**不能**用它验证
> fat jar 是否可用；验证发行包请用 `bash bin/startup.sh -m standalone`。
> **本地开发也请用 JDK 8**，与生产保持一致，避免 IDE 用 JDK 17/21 编译后本地正常、部署报错的假象。

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
| **四层转发（`stream`）下白名单必须留空** | 本项目生产架构为 `Nginx stream`（TCP 层）转发，后端看到的来源永远是 Nginx IP。若把 Nginx IP 加进 `ipAuthWhite`，等于**全世界免鉴权**。必须把 `ipAuthWhite` 留空或只留 `127.0.0.1`，鉴权靠账号密码（见 7.3） |
| **集群必须用 MySQL** | 单机可用内嵌 Derby；集群必须外置 MySQL 并执行 `mysql-schema.sql` |
| **TDP 复验用真实 IP** | 用 `localhost` 会被白名单放行，扫出假阴性 |
| **构建必须用 JDK 8** | 仓库 `mise.toml` 已约束，但终端 `JAVA_HOME` 可能被其他工具覆盖。用 JDK 9+ 构建出的 jar 在 JDK 8 服务器上会崩（见 7.2） |

### 7.2 构建踩坑

| 问题 | 原因 | 解决 |
|---|---|---|
| `Too many files with unapproved license` | Apache RAT 检查，`.vscode/settings.json` 等本地文件无 license 头 | 加 `-Drat.skip=true` |
| `clean` 后 `ProtoMessageUtilTest.java` 报 `找不到 WriteRequestOrBuilder 的类文件` | `-DskipTests` 只跳过测试**运行**，仍会编译测试代码；`consistency` 的测试类依赖 protobuf 生成结果，clean 后编译顺序不满足 | 改用 `-Dmaven.test.skip=true`（跳过编译 + 运行） |
| **`core` 模块编译报 `程序包 com.alibaba.nacos.consistency.entity 不存在` / `找不到符号 ReadRequest`**，但 `consistency` 模块显示 SUCCESS | `easyj-maven-plugin` 的 `simplify-pom` 在 package 阶段把 `.flattened-pom.xml` 设为项目 POM，触发 `protobuf-maven-plugin` **在 jar 打包之后二次执行**。jar 打包时 `target/classes` 还没有 grpc 生成类，产出空壳 jar。**此问题随机触发**（取决于插件执行时序的竞争结果），JDK 8 下更容易复现 | `maven.simplify.skip=true` 已固化在根 pom `<properties>`。该插件仅用于发布 Maven 中央仓库，内部部署不需要 |
| **服务器启动报 `NoClassDefFoundError: istio/mcp/v1alpha1/ResourceSourceGrpc$ResourceSourceImplBase`**（`NacosMcpService` 加载失败） | 同上，这次轮到 `istio` 模块：`compile-custom` 产出的 `*Grpc` 类在 jar 之后才生成，`nacos-istio` jar 只有 68 个类（完整应为 83） | 同上。部署前按 3.2.0 ④ 检查 `ResourceSourceGrpc$ResourceSourceImplBase` 是否存在 |
| **`-pl distribution -am` 构建出的 jar 更容易丢类** | `-am` 模式改变 Maven 对上游 POM 的解析路径，加剧上述时序错乱 | **严格用官方全量 reactor 命令**，不加 `-pl` / `-am` |
| **控制台 `/v1/console/server/announcement` 返回 500，`NoSuchMethodError: java.nio.ByteBuffer.flip()Ljava/nio/ByteBuffer;`** | **用 JDK 9+ 构建了 jar，服务器用 JDK 8 运行**。JDK 9 起 `ByteBuffer.flip()` 协变返回 `ByteBuffer`，JDK 8 返回 `Buffer`。根 pom 只配了 `source/target=1.8` **没有** `release`，JDK 21 的 javac 会链接自身 API 生成 JDK 9+ 签名的字节码。`DiskUtils.readFile()` 是第一个踩雷的调用点 | **用 JDK 8 构建**（`mise.toml` 约束），构建后按 3.2.0 自检 `major version: 52` 和 `flip()Ljava/nio/Buffer;` |
| `mise.toml` 不生效，`java -version` 仍是 21 | mise 只对**项目目录下的交互式 shell** 生效；终端 cwd 漂移到其他目录、或 `JAVA_HOME` 被别的工具硬设时失效。Maven 用的是 `JAVA_HOME`，不是 `mise current` | 构建前显式 `export JAVA_HOME="$(mise where java)"`；用 `mvn -version` 的 `Java version` 行而非 `java -version` 判断 |
| 生成不了 `nacos-server.jar` | 未激活 profile | 必须加 `-Prelease-nacos` |
| 重跑 shade 报 `duplicate entry: META-INF/services/...ServerProvider` | `client/target` 残留上次 shade 产物 | 构建前 `rm -rf client/target`，或直接用 `clean` |
| **启动报 `NoSuchMethodError: StringUtils.isBlank(Ljava/lang/String;)Z`**（`EnvUtil.getNacosHome`） | **两个独立原因，都会导致同一报错**：① **Maven 增量编译残留**——`sys/target/classes` 中的 `EnvUtil.class` 是更早某次编译的产物，当时链接到了老版本 `nacos-common`（1.3 ~ 2.0.1 的 `isBlank` 签名是 `(String)`，2.2.3 改为 `(CharSequence)`），源码未变则 Maven 不重编译，陈旧 class 直接进 jar；② **fat jar 重复类**——shade 版 `nacos-client` 内含被 `minimizeJar` 裁剪的 `StringUtils` 副本，`PropertiesLauncher` 可能先加载它 | ① **构建必须加 `clean`**；② 本分支已在 `console/pom.xml` 修复（见 3.2.1）。两者缺一不可——只做 ② 陈旧 class 仍会报错，只做 ① 重复类仍可能触发 |
| 用 `-cp target/classes:...` 能启动，但 `java -jar nacos-server.jar` 报错 | 两者类加载顺序不同：`-cp` 方式可能被 shade 版副本"兜底"掩盖问题 | 验证发行包必须用 `java -jar` 或 `bin/startup.sh`，不要用 `-cp` |
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
| **鉴权已开启，但所有匿名请求仍返回 200（含 `/v1/auth/users` 泄露密码哈希）** | **Nginx 四层转发 + `ipAuthWhite` 含 Nginx IP**。`stream` 块不解析 HTTP，后端 `remoteAddr` 永远是 Nginx 的 IP，白名单命中即全部放行。IP 白名单功能在四层转发架构下**从设计上不成立** | `ipAuthWhite` 留空或只留 `127.0.0.1`，所有客户端配账号密码。如需按来源放行，改在 Nginx 层用 `allow/deny` |
| **启动即崩 `EXCEPTION_ILLEGAL_INSTRUCTION`，problematic frame `librocksdbjni*.dll`** | 运行机器的 CPU/OS 不支持 `rocksdbjni 7.7.3` 用到的 SIMD 指令。实测：Xeon E7-4800 v2 + **Windows Server 2008 R2** 崩溃（2008 R2 内核不保存 AVX 寄存器状态）；Xeon Gold 5318H + Server 2019 正常 | Nacos 只部署在较新的机器上；老机器只做 Nginx 转发。若必须在老机器运行，需降级 `rocksdbjni` 到 5.18.4（但该版本无 arm64，不能在 Apple Silicon 上测试） |

### 7.4 从旧版本升级

1. 备份 `conf/`、`data/`（或 MySQL 数据库）
2. 替换 `target/nacos-server.jar`、`bin/`、`plugins/`，**保留** `conf/` 和 `data/`
3. 对照新的 `conf/application.properties` 补齐新增配置项（鉴权 5 项）
4. 若使用内嵌 Derby 且跨大版本，Derby 不会自动迁移 schema，建议趁升级切换到 MySQL
5. 升级后按 [第六节](#六部署后验证) 逐项复验
