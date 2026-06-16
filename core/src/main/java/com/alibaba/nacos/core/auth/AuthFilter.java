/*
 * Copyright 1999-2018 Alibaba Group Holding Ltd.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package com.alibaba.nacos.core.auth;

import com.alibaba.nacos.auth.HttpProtocolAuthService;
import com.alibaba.nacos.auth.annotation.Secured;
import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.utils.ExceptionUtil;
import com.alibaba.nacos.common.utils.StringUtils;
import com.alibaba.nacos.core.code.ControllerMethodsCache;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.core.utils.WebUtils;
import com.alibaba.nacos.plugin.auth.api.IdentityContext;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import com.alibaba.nacos.sys.env.Constants;

import javax.servlet.Filter;
import javax.servlet.FilterChain;
import javax.servlet.ServletException;
import javax.servlet.ServletRequest;
import javax.servlet.ServletResponse;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.lang.reflect.Method;

/**
 * Unified filter to handle authentication and authorization.
 *
 * @author nkorange
 * @since 1.2.0
 */
public class AuthFilter implements Filter {
    
    public static final String PROXY_CLIENT_IP = "Proxy-Client-IP";
    
    public static final String X_FORWARDED_FOR = "x-forwarded-for";
    
    public static final String WL_PROXY_CLIENT_IP = "WL-Proxy-Client-IP";
    
    public static final String REGEX = ",";
    
    public static final String AN_OBJECT = "0:0:0:0:0:0:0:1";
    
    public static final String LOCALHOST_STRING = "127.0.0.1";
    
    public static final String UNKNOWN = "unknown";
    
    /**
     * HTTP 方法常量.
     */
    private static final String METHOD_GET = "GET";
    
    private static final String METHOD_POST = "POST";
    
    private static final String METHOD_PUT = "PUT";
    
    private static final String METHOD_DELETE = "DELETE";

    /**
     * 当开启了 nacos.security.legacy-client.anonymous.enabled=true 时，
     * Nacos 会对以下核心接口进行匿名放行
     * 1. 配置发布/删除/修改/查询
     * 2. 服务发现查询实例列表.
     */
    private static final String URI_CS_CONFIGS = "/v1/cs/configs";
    
    private static final String URI_CS_CONFIGS_LISTENER = "/v1/cs/configs/listener";
    
    private static final String URI_NS_INSTANCE = "/v1/ns/instance";
    
    private static final String URI_NS_INSTANCE_BEAT = "/v1/ns/instance/beat";
    
    private static final String URI_NS_INSTANCE_LIST = "/v1/ns/instance/list";
    
    private static final String URI_NS_SERVICE_LIST = "/v1/ns/service/list";
    
    private static final String URI_NACOS_PREFIX = "/nacos/";
    
    private static final String URI_NACOS_PREFIX_REPLACE = "/nacos";
    
    private final AuthConfigs authConfigs;
    
    private final ControllerMethodsCache methodsCache;
    
    private final HttpProtocolAuthService protocolAuthService;
    
    public AuthFilter(AuthConfigs authConfigs, ControllerMethodsCache methodsCache) {
        this.authConfigs = authConfigs;
        this.methodsCache = methodsCache;
        this.protocolAuthService = new HttpProtocolAuthService(authConfigs);
        this.protocolAuthService.initialize();
    }
    
    @Override
    public void doFilter(ServletRequest request, ServletResponse response, FilterChain chain)
            throws IOException, ServletException {
        
        if (!authConfigs.isAuthEnabled()) {
            chain.doFilter(request, response);
            return;
        }
        
        HttpServletRequest req = (HttpServletRequest) request;
        HttpServletResponse resp = (HttpServletResponse) response;
        String originIp = getRemoteHost(req);
        
        // 【兼容逻辑】检查是否是需要匿名放行的老客户端请求
        if (isLegacyClientAllowed(req)) {
            chain.doFilter(request, response);
            return;
        }
        
        if (StringUtils.isNotBlank(authConfigs.getWhiteIpStr())) {
            // 这里是新加的过滤规则,某些特定的IP地址可以直接访问Nacos不需要权限校验
            String whiteIpStr = authConfigs.getWhiteIpStr();
            
            for (String ip : whiteIpStr.split(REGEX)) {
                if (ip.equals(originIp)) {
                    chain.doFilter(request, response);
                    return;
                }
            }
        } else if (authConfigs.isEnableUserAgentAuthWhite()) {
            String userAgent = WebUtils.getUserAgent(req);
            if (StringUtils.startsWith(userAgent, Constants.NACOS_SERVER_HEADER)) {
                chain.doFilter(request, response);
                return;
            }
        } else if (StringUtils.isNotBlank(authConfigs.getServerIdentityKey()) && StringUtils.isNotBlank(
                authConfigs.getServerIdentityValue())) {
            String serverIdentity = req.getHeader(authConfigs.getServerIdentityKey());
            if (StringUtils.isNotBlank(serverIdentity)) {
                if (authConfigs.getServerIdentityValue().equals(serverIdentity)) {
                    chain.doFilter(request, response);
                    return;
                }
                Loggers.AUTH.warn("Invalid server identity value for {} from {}", authConfigs.getServerIdentityKey(),
                        req.getRemoteHost());
            }
        } else {
            resp.sendError(HttpServletResponse.SC_FORBIDDEN,
                    "Invalid server identity key or value, Please make sure set `nacos.core.auth.server.identity.key`"
                            + " and `nacos.core.auth.server.identity.value`, or open `nacos.core.auth.enable.userAgentAuthWhite`");
            return;
        }
        
        try {
            
            Method method = methodsCache.getMethod(req);
            
            if (method == null) {
                chain.doFilter(request, response);
                return;
            }
            
            if (method.isAnnotationPresent(Secured.class) && authConfigs.isAuthEnabled()) {
                
                if (Loggers.AUTH.isDebugEnabled()) {
                    Loggers.AUTH.debug("auth start, request: {} {}", req.getMethod(), req.getRequestURI());
                }
                
                Secured secured = method.getAnnotation(Secured.class);
                if (!protocolAuthService.enableAuth(secured)) {
                    chain.doFilter(request, response);
                    return;
                }
                Resource resource = protocolAuthService.parseResource(req, secured);
                IdentityContext identityContext = protocolAuthService.parseIdentity(req);
                boolean result = protocolAuthService.validateIdentity(identityContext, resource);
                if (!result) {
                    // TODO Get reason of failure
                    throw new AccessException("Validate Identity failed.");
                }
                injectIdentityId(req, identityContext);
                String action = secured.action().toString();
                result = protocolAuthService.validateAuthority(identityContext, new Permission(resource, action));
                if (!result) {
                    // TODO Get reason of failure
                    throw new AccessException("Validate Authority failed.");
                }
            }
            chain.doFilter(request, response);
        } catch (AccessException e) {
            if (Loggers.AUTH.isDebugEnabled()) {
                Loggers.AUTH.debug("access denied, request: {} {}, reason: {}", req.getMethod(), req.getRequestURI(),
                        e.getErrMsg());
            }
            resp.sendError(HttpServletResponse.SC_FORBIDDEN, e.getErrMsg());
        } catch (IllegalArgumentException e) {
            resp.sendError(HttpServletResponse.SC_BAD_REQUEST, ExceptionUtil.getAllExceptionMsg(e));
        } catch (Exception e) {
            Loggers.AUTH.warn("[AUTH-FILTER] Server failed: ", e);
            resp.sendError(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, "Server failed, " + e.getMessage());
        }
    }
    
    /**
     * Set identity id to request session, make sure some actual logic can get identity information.
     *
     * <p>May be replaced with whole identityContext.
     *
     * @param request         http request
     * @param identityContext identity context
     */
    private void injectIdentityId(HttpServletRequest request, IdentityContext identityContext) {
        String identityId = identityContext.getParameter(
                com.alibaba.nacos.plugin.auth.constant.Constants.Identity.IDENTITY_ID, StringUtils.EMPTY);
        request.getSession()
                .setAttribute(com.alibaba.nacos.plugin.auth.constant.Constants.Identity.IDENTITY_ID, identityId);
        request.getSession().setAttribute(com.alibaba.nacos.plugin.auth.constant.Constants.Identity.IDENTITY_CONTEXT,
                identityContext);
    }
    
    /**
     * 从request里面获取真实IP.
     *
     * @param request http request
     * @return string
     */
    private String getRemoteHost(HttpServletRequest request) {
        String ip = request.getHeader(X_FORWARDED_FOR);
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getHeader(WL_PROXY_CLIENT_IP);
        }
        if (ip == null || ip.length() == 0 || UNKNOWN.equalsIgnoreCase(ip)) {
            ip = request.getRemoteAddr();
        }
        return AN_OBJECT.equals(ip) ? LOCALHOST_STRING : ip;
    }
    
    /**
     * 检查是否是需要匿名放行的老客户端请求(核心修改逻辑).
     */
    private boolean isLegacyClientAllowed(HttpServletRequest request) {
        if (!authConfigs.isLegacyClientAnonymousEnabled()) {
            return false;
        }

        String path = normalizePath(request);
        String method = request.getMethod();

        // 配置拉取：允许
        if (METHOD_GET.equalsIgnoreCase(method) && URI_CS_CONFIGS.equals(path)) {
            return true;
        }

        // 配置监听：Nacos 客户端监听配置变更通常会用这个接口
        if (METHOD_POST.equalsIgnoreCase(method) && URI_CS_CONFIGS_LISTENER.equals(path)) {
            return true;
        }

        // 服务注册
        if (METHOD_POST.equalsIgnoreCase(method) && URI_NS_INSTANCE.equals(path)) {
            return true;
        }

        // 服务注销
        if (METHOD_DELETE.equalsIgnoreCase(method) && URI_NS_INSTANCE.equals(path)) {
            return true;
        }

        // 服务心跳
        if (URI_NS_INSTANCE_BEAT.equals(path)) {
            if (METHOD_PUT.equalsIgnoreCase(method) || METHOD_POST.equalsIgnoreCase(method)) {
                return true;
            }
        }

        // 服务发现：查询实例列表
        if (METHOD_GET.equalsIgnoreCase(method) && URI_NS_INSTANCE_LIST.equals(path)) {
            return true;
        }

        // 查询服务列表，部分老客户端/工具可能会用
        if (METHOD_GET.equalsIgnoreCase(method) && URI_NS_SERVICE_LIST.equals(path)) {
            return true;
        }

        return false;
    }

    /**
     * 规范化请求路径，用于鉴权匹配。
     *
     * <p>主要步骤包括：
     * 1. 获取请求的 URI。
     * 2. 去除上下文路径（Context Path）。
     * 3. 去除前缀 "/nacos"（如果存在，例如 "/nacos/..." 会变为 "/..."）。
     * 4. 将连续的多个斜杠（"//" 等）替换为单个斜杠。
     * 5. 将结果转换为小写以进行大小写无关的匹配。
     *
     * @param request 客户端的 HTTP 请求
     * @return 规范化后的路径字符串
     */
    private String normalizePath(HttpServletRequest request) {
        // 获取请求的完整 URI
        String uri = request.getRequestURI();

        // 如果配置了 ContextPath，且 URI 以该 ContextPath 开头，则将其剥离
        String contextPath = request.getContextPath();
        if (contextPath != null && !contextPath.isEmpty() && uri.startsWith(contextPath)) {
            uri = uri.substring(contextPath.length());
        }

        // 如果路径是以 "/nacos/" 开头，剥离前面的 "/nacos" 前缀
        if (uri.startsWith(URI_NACOS_PREFIX)) {
            uri = uri.substring(URI_NACOS_PREFIX_REPLACE.length());
        }

        // 将多个连续的斜杠替换为单个斜杠（例如：///a//b -> /a/b）
        uri = uri.replaceAll("/{2,}", "/");
        // 统一转换为小写，保证路径匹配时大小写不敏感
        return uri.toLowerCase(java.util.Locale.ROOT);
    }
    
}
