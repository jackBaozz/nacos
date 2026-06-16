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

### 3. 配置类增加 IP 白名单属性
* **变动文件**：[AuthConfigs.java](file:///Users/bao/work/idea_workspace/nacos/auth/src/main/java/com/alibaba/nacos/auth/config/AuthConfigs.java)
* **具体修改**：
  * 引入新属性 `nacos.core.auth.enable.ipAuthWhite`（对应 Java 变量 `whiteIpStr`），用于接收 IP 白名单配置。
  * 提供 `whiteIpStr` 的 Getter 和 Setter。
  * 在配置动态监听事件 `onEvent(ServerConfigChangeEvent event)` 中，增加对该属性的动态更新支持。

### 4. 鉴权过滤器过滤逻辑改造
* **变动文件**：[AuthFilter.java](file:///Users/bao/work/idea_workspace/nacos/core/src/main/java/com/alibaba/nacos/core/auth/AuthFilter.java)
* **具体修改**：
  * 新增辅助方法 `getRemoteHost(HttpServletRequest request)`，通过读取 `x-forwarded-for`、`Proxy-Client-IP`、`WL-Proxy-Client-IP` 等 HTTP 请求头，获取客户端的真实 IP 地址。
  * 改造 `doFilter` 拦截过滤入口：在执行正常的鉴权逻辑之前，优先判断配置的 `whiteIpStr`（IP 白名单）是否包含当前客户端真实 IP。如果匹配成功，则直接执行 `chain.doFilter` 放行，免除身份校验。

### 5. 默认配置文件调整
* **变动文件**：[application.properties](file:///Users/bao/work/idea_workspace/nacos/console/src/main/resources/application.properties)
* **具体修改**：
  * **端口修改**：将默认运行端口 `server.port` 从 `8848` 修改为 `28848`。
  * **数据库启用**：启用了 MySQL 数据源配置，配置 `db.num=1`，并默认写入了特定的测试库链接及密码。
  * **鉴权开启**：将 `nacos.core.auth.enabled` 默认值设为 `true`。
  * **IP 白名单默认值**：添加了新配置项 `nacos.core.auth.enable.ipAuthWhite=10.5.84.204,127.0.0.1`。
  * **集群及身份鉴权密钥配置**：
    * 写入了默认的内部通信 `nacos.core.auth.server.identity.key=sneb` 和 `nacos.core.auth.server.identity.value=54uyJYEbExdD33Nm`。
    * 配置了用于 JWT Token 签名的密钥 `nacos.core.auth.plugin.nacos.token.secret.key`。

### 6. 格式化工具配置文件 (新增)
* **变动文件**：[nacos-eclipse-formatter.xml](file:///Users/bao/work/idea_workspace/nacos/style/nacos-eclipse-formatter.xml) (新文件)
* **具体说明**：
  * 将原有 IDEA 格式化规范转换为 Eclipse XML 格式，以便于在 VS Code 中结合 `Language Support for Java(TM) by Red Hat` 插件对代码进行规范化排版，防止不同 IDE 协作时产生多余的空格/换行 Git 变动。
