/*
 * Copyright 1999-2020 Alibaba Group Holding Ltd.
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

import com.alibaba.nacos.api.exception.NacosException;
import com.alibaba.nacos.api.remote.request.Request;
import com.alibaba.nacos.api.remote.request.RequestMeta;
import com.alibaba.nacos.api.remote.response.Response;
import com.alibaba.nacos.auth.GrpcProtocolAuthService;
import com.alibaba.nacos.auth.annotation.Secured;
import com.alibaba.nacos.auth.config.AuthConfigs;
import com.alibaba.nacos.common.utils.ExceptionUtil;
import com.alibaba.nacos.core.remote.AbstractRequestFilter;
import com.alibaba.nacos.core.utils.Loggers;
import com.alibaba.nacos.plugin.auth.api.IdentityContext;
import com.alibaba.nacos.plugin.auth.api.Permission;
import com.alibaba.nacos.plugin.auth.api.Resource;
import com.alibaba.nacos.plugin.auth.constant.Constants;
import com.alibaba.nacos.plugin.auth.exception.AccessException;
import org.springframework.stereotype.Component;

import java.lang.reflect.Method;

/**
 * request auth filter for remote.
 *
 * @author liuzunfei
 * @version $Id: RemoteRequestAuthFilter.java, v 0.1 2020年09月14日 12:38 PM liuzunfei Exp $
 */
@Component
public class RemoteRequestAuthFilter extends AbstractRequestFilter {

    /**
     * Request type ConfigQueryRequest.
     */
    private static final String REQ_CONFIG_QUERY = "ConfigQueryRequest";

    /**
     * Request type ConfigBatchListenRequest.
     */
    private static final String REQ_CONFIG_LISTEN = "ConfigBatchListenRequest";

    /**
     * Request type InstanceRequest.
     */
    private static final String REQ_INSTANCE = "InstanceRequest";

    /**
     * Request type BatchInstanceRequest.
     */
    private static final String REQ_BATCH_INSTANCE = "BatchInstanceRequest";

    /**
     * Request type ServiceQueryRequest.
     */
    private static final String REQ_SERVICE_QUERY = "ServiceQueryRequest";

    /**
     * Request type SubscribeServiceRequest.
     */
    private static final String REQ_SUBSCRIBE_SERVICE = "SubscribeServiceRequest";
    
    private final AuthConfigs authConfigs;
    
    private final GrpcProtocolAuthService protocolAuthService;
    
    public RemoteRequestAuthFilter(AuthConfigs authConfigs) {
        this.authConfigs = authConfigs;
        this.protocolAuthService = new GrpcProtocolAuthService(authConfigs);
        this.protocolAuthService.initialize();
    }

    /**
     * 判断是否为兼容老客户端允许匿名访问的 gRPC 请求.
     *
     * @param request 请求对象
     * @return 是否放行
     */
    private boolean isLegacyClientAllowed(Request request) {
        String requestType = request.getClass().getSimpleName();
        if (REQ_CONFIG_QUERY.equals(requestType) || REQ_CONFIG_LISTEN.equals(requestType)) {
            return true;
        }
        if (REQ_INSTANCE.equals(requestType) || REQ_BATCH_INSTANCE.equals(requestType)) {
            return true;
        }
        return REQ_SERVICE_QUERY.equals(requestType) || REQ_SUBSCRIBE_SERVICE.equals(requestType);
    }
    
    @Override
    public Response filter(Request request, RequestMeta meta, Class handlerClazz) throws NacosException {
        
        try {
            
            Method method = getHandleMethod(handlerClazz);
            if (method.isAnnotationPresent(Secured.class) && authConfigs.isAuthEnabled()) {
                
                if (Loggers.AUTH.isDebugEnabled()) {
                    Loggers.AUTH.debug("auth start, request: {}", request.getClass().getSimpleName());
                }
                
                Secured secured = method.getAnnotation(Secured.class);
                if (!protocolAuthService.enableAuth(secured)) {
                    return null;
                }
                
                // 兼容模式：如果开启了老客户端匿名访问，则对核心 gRPC 请求放行
                if (authConfigs.isLegacyClientAnonymousEnabled() && isLegacyClientAllowed(request)) {
                    if (Loggers.AUTH.isDebugEnabled()) {
                        Loggers.AUTH.debug("legacy client anonymous access allowed for gRPC request: {}", request.getClass().getSimpleName());
                    }
                    return null;
                }

                String clientIp = meta.getClientIp();
                request.putHeader(Constants.Identity.X_REAL_IP, clientIp);
                Resource resource = protocolAuthService.parseResource(request, secured);
                IdentityContext identityContext = protocolAuthService.parseIdentity(request);
                boolean result = protocolAuthService.validateIdentity(identityContext, resource);
                if (!result) {
                    // TODO Get reason of failure
                    throw new AccessException("Validate Identity failed.");
                }
                String action = secured.action().toString();
                result = protocolAuthService.validateAuthority(identityContext, new Permission(resource, action));
                if (!result) {
                    // TODO Get reason of failure
                    throw new AccessException("Validate Authority failed.");
                }
            }
        } catch (AccessException e) {
            if (Loggers.AUTH.isDebugEnabled()) {
                Loggers.AUTH.debug("access denied, request: {}, reason: {}", request.getClass().getSimpleName(),
                        e.getErrMsg());
            }
            Response defaultResponseInstance = getDefaultResponseInstance(handlerClazz);
            defaultResponseInstance.setErrorInfo(NacosException.NO_RIGHT, e.getErrMsg());
            return defaultResponseInstance;
        } catch (Exception e) {
            Response defaultResponseInstance = getDefaultResponseInstance(handlerClazz);
            
            defaultResponseInstance.setErrorInfo(NacosException.SERVER_ERROR, ExceptionUtil.getAllExceptionMsg(e));
            return defaultResponseInstance;
        }
        
        return null;
    }
}
