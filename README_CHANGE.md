# 本分支修改记录 (对比 v2.2.3 原始分支)

本文件用于记录当前分支 `v2.2.3-bzz` 相比于 Nacos 官方原始 `v2.2.3` 版本的分支所做的所有定制化修改，以便日后回溯与维护。

---

## 一、 核心改动概述

1. **新增 IP 白名单免鉴权功能 (IP Auth Whitelist)**
   * 在鉴权开启时，支持配置指定的 IP 地址列表。当请求来自这些 IP 时，自动绕过 Nacos 的权限校验，直接放行。
2. **降级 MySQL 驱动版本 (MySQL Driver Downgrade)**
   * 将 `mysql-connector-java` 版本从 `8.0.28` 降级为 `5.1.49`。
   * 数据源驱动类由 `com.mysql.cj.jdbc.Driver` 更改为旧版的 `com.mysql.jdbc.Driver`。
3. **默认配置定制化 (Default Configuration Customization)**
   * 修改了内置 `application.properties` 中的默认端口、数据库连接以及鉴权相关密钥，方便本地及特定环境的开箱即用。
4. **代码规范与格式化工具**
   * 新增了适用于 VS Code 开发环境的 Eclipse Formatter 格式化配置文件。
5. **老客户端核心接口匿名放行 (Legacy Client Anonymous Bypass)**
   * 为了平滑升级并兼容未配置密码的老业务，新增了局部放行开关。开启该模式后，仅针对老客户端服务注册、发现、配置拉取等基础生命周期接口实施免密码放行，控制台、配置发布删除等核心操作仍受原生鉴权严密保护。

---

## 二、 详细文件变动及修改内容

### 1. `pom.xml`
* **变动文件**：[pom.xml](file:///Users/bao/work/idea_workspace/nacos/pom.xml)
* **具体修改**：
  * 将 `<mysql-connector-java.version>` 属性的值从 `8.0.28` 修改为 `5.1.49`。

### 2. 数据库驱动类调整
* **变动文件**：[ExternalDataSourceProperties.java](file:///Users/bao/work/idea_workspace/nacos/config/src/main/java/com/alibaba/nacos/config/server/service/datasource/ExternalDataSourceProperties.java)
* **具体修改**：
  * 修改静态常量 `JDBC_DRIVER_NAME`：
    ```diff
    - private static final String JDBC_DRIVER_NAME = "com.mysql.cj.jdbc.Driver";
    + private static final String JDBC_DRIVER_NAME = "com.mysql.jdbc.Driver";
    ```

### 3. 配置类增加自定义安全属性 (IP 白名单与老客户端兼容)
* **变动文件**：[AuthConfigs.java](file:///Users/bao/work/idea_workspace/nacos/auth/src/main/java/com/alibaba/nacos/auth/config/AuthConfigs.java)
* **具体修改**：
  * 引入新属性 `nacos.core.auth.enable.ipAuthWhite`（对应 Java 变量 `whiteIpStr`），用于接收 IP 白名单配置。
  * 引入新属性 `nacos.security.legacy-client.anonymous.enabled`（对应 Java 变量 `legacyClientAnonymousEnabled`），用于控制老客户端兼容模式。
  * 为这两个新属性提供 Getter 及 Setter 支持。
  * 在配置动态监听事件 `onEvent(ServerConfigChangeEvent event)` 中，增加对这两项属性的动态热更新支持。

### 4. 鉴权过滤器过滤逻辑改造 (适配 HTTP 1.x 与 gRPC 2.x 客户端)
* **变动文件**：
  * [AuthFilter.java](file:///Users/bao/work/idea_workspace/nacos/core/src/main/java/com/alibaba/nacos/core/auth/AuthFilter.java)
  * [RemoteRequestAuthFilter.java](file:///Users/bao/work/idea_workspace/nacos/core/src/main/java/com/alibaba/nacos/core/auth/RemoteRequestAuthFilter.java)
* **具体修改**：
  * `AuthFilter.java` (针对 HTTP)：新增辅助方法 `getRemoteHost(HttpServletRequest request)` 提取真实 IP；新增 `isLegacyClientAllowed` 拦截放行核心 HTTP 接口。改造 `doFilter` 依次增加老客户端 API 兼容与 IP 白名单放行判断。
  * `RemoteRequestAuthFilter.java` (针对 gRPC)：为 Nacos 2.x 客户端引入同等放行逻辑。新增 `isLegacyClientAllowed` 方法拦截 `InstanceRequest`, `ServiceQueryRequest`, `SubscribeServiceRequest` (服务注册与发现) 及 `ConfigQueryRequest`, `ConfigBatchListenRequest` (配置拉取与监听) 等核心 gRPC 请求，实现 SOFARPC 等新型客户端在兼容模式下的无密码访问。

### 5. 默认配置文件调整
* **变动文件**：[application.properties](file:///Users/bao/work/idea_workspace/nacos/console/src/main/resources/application.properties)
* **具体修改**：
  * **端口保持默认**：运行端口 `server.port` 保持 `8848`。
  * **数据库默认关闭**：默认已将 `spring.sql.init.platform=mysql` 及相关配置注释掉。如果您在替换 Jar 包后启动报错 `No DataSource set`，请使用原始完整配置文件或保持此默认配置，确保单机模式正常使用 Derby 数据库。
  * **鉴权默认关闭**：`nacos.core.auth.enabled` 默认为 `false`。
  * **新增开关默认值**：
    * `nacos.core.auth.enable.ipAuthWhite=10.5.84.204,127.0.0.1`。
    * `nacos.security.legacy-client.anonymous.enabled=true`。
  * **集群及身份鉴权密钥配置**：
    * 写入了默认的内部通信身份 Key/Value（如 `snoopdog`）。
    * 配置了用于 JWT Token 签名的密钥。

### 6. 格式化工具配置文件 (新增)
* **变动文件**：[nacos-eclipse-formatter.xml](file:///Users/bao/work/idea_workspace/nacos/style/nacos-eclipse-formatter.xml) (新文件)
* **具体说明**：
  * 将原有 IDEA 格式化规范转换为 Eclipse XML 格式，以便于在 VS Code 中结合 `Language Support for Java(TM) by Red Hat` 插件对代码进行规范化排版，防止不同 IDE 协作时产生多余的空格/换行 Git 变动。

---

## 三、 权限控制模式设计与使用说明

通过对鉴权开关的定制，目前本分支的 Nacos 支持以下三种权限控制的组合模式。您可以根据集群安全性要求与老业务兼容性的不同权衡，自由选择最适合的模式：

### 模式 1：平滑升级模式（新增定制功能，推荐过渡期使用，半开权限）
* **配置组合**：`nacos.core.auth.enabled=true` 且 `nacos.security.legacy-client.anonymous.enabled=true`
* **效果**：Nacos 鉴权整体**已开启**，但对核心客户端接口网开一面。
* **业务表现**：
  * **老业务微服务**：无需修改代码配置账号密码，依然可以匿名拉取配置、注册服务、发现服务，业务零感知。
  * **控制台 & 管理员**：登录 Web 控制台必须输入账号密码；调用 API 发布/删除配置、增删用户等高危操作会被严格拦截并提示无权限。
* **适用场景**：准备给处于“裸奔”状态的 Nacos 增加安全防护（防止黑客或外部人员访问控制台篡改数据），但又无法推动所有存量微服务项目去排期加上鉴权密码。这是一个既保护了高危接口，又保障了老客户端正常运转的完美折中方案。

### 模式 2：原生强安全模式（官方标准）
* **配置组合**：`nacos.core.auth.enabled=true` 且 `nacos.security.legacy-client.anonymous.enabled=false`
* **效果**：Nacos 鉴权**全量开启**，没有任何后门或兼容放行。
* **业务表现**：无论是控制台登录，还是**任何一个**微服务客户端想要拉取配置或注册服务，都必须配置正确的鉴权信息（在 `application.properties` 配置 `username` 和 `password`），否则请求全量拦截并报 403 Forbidden。
* **适用场景**：要求极高安全性的公有云环境或零信任网络，所有接入的微服务客户端都必须严格通过身份校验。

### 模式 3：完全裸奔模式（默认开箱状态）
* **配置组合**：`nacos.core.auth.enabled=false` 且 `nacos.security.legacy-client.anonymous.enabled=false`（或 `true`，此时 legacy 开关无实际意义）
* **效果**：Nacos 鉴权彻底**关闭**。
* **业务表现**：一切畅通无阻。任何人都可以免密打开 Web 控制台，随意发送请求删掉生产环境的配置，注册垃圾服务等。
* **适用场景**：仅限于本地开发调试，或者完全与外网隔离、内部绝对互信的安全局域网环境。

---

## 四、 生产环境安全配置警告 (Security Best Practices)

> [!WARNING]
> **切勿在生产环境使用默认 JWT 密钥！**

在开启 Nacos 鉴权（`nacos.core.auth.enabled=true`）时，**必须**在服务器外部的 `conf/application.properties` 中手动配置自定义的 JWT 密钥 `nacos.core.auth.plugin.nacos.token.secret.key`。

* **安全隐患**：如果该配置项为空，Nacos 会回退使用开源代码中硬编码的默认公开密钥（例如 `SecretKey01234...`）。这意味着即使开启了鉴权，外部攻击者也可以利用这个公开密钥，随意伪造包含超管权限的 `accessToken` 并在您的服务器上畅通无阻！
* **正确做法**：在上生产环境前，请务必生成一个**长度大于等于 32 字节且使用 Base64 编码的随机字符串**，并显式配置，例如：
  ```properties
  nacos.core.auth.plugin.nacos.token.secret.key=VGhpc0lzQU15U2VjcmV0S2V5VGhhdE5vYm9keUtub3dzMTIzNDU2Nzg5MA==
  ```

只要确保配置了您专属的、不泄露的 `secret.key`，任何由外部伪造或篡改的 Token（无论是修改了用户名还是篡改了过期时间）都会在 Nacos 重新计算签名比对时，因为签名不匹配抛出 `SignatureException` 并被 100% 拦截。
