/*
 * Copyright (c) 2015, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.identity.application.authentication.framework;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;
import org.wso2.carbon.identity.application.authentication.framework.exception.CookieValidationFailedException;
import org.wso2.carbon.identity.application.authentication.framework.util.FrameworkUtils;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Common authentication handler.
 */
public class CommonAuthenticationHandler {

    private static final Log log = LogFactory.getLog(CommonAuthenticationHandler.class);

    public CommonAuthenticationHandler() {
        if (log.isDebugEnabled()) {
            log.debug("Initializing CommonAuthenticationHandler.");
        }
        ConfigurationFacade.getInstance();
        log.info("CommonAuthenticationHandler initialized successfully.");
    }

    public void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Delegating GET request to POST handler for authentication processing.");
        }
        doPost(request, response);
    }

    public void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {

        if (log.isDebugEnabled()) {
            log.debug("Starting authentication request processing.");
        }

        if (FrameworkUtils.getMaxInactiveInterval() == 0) {
            if (log.isDebugEnabled()) {
                log.debug("Setting max inactive interval from session.");
            }
            FrameworkUtils.setMaxInactiveInterval(request.getSession().getMaxInactiveInterval());
        }

        try {
            if (log.isDebugEnabled()) {
                String sessionDataKey = request.getParameter("sessionDataKey");
                log.debug("Processing authentication request with sessionDataKey: " +
                         (sessionDataKey != null ? sessionDataKey : "[not provided]"));
            }
            FrameworkUtils.getRequestCoordinator().handle(request, response);
        } catch (CookieValidationFailedException e) {

            log.warn("Session nonce cookie validation has failed for the sessionDataKey: "
                        + request.getParameter("sessionDataKey") + ". Hence, restarting the login flow.");
            try {
                FrameworkUtils.getRequestCoordinator().handle(request, response);
                if (log.isDebugEnabled()) {
                    log.debug("Successfully restarted authentication flow after cookie validation failure.");
                }
            } catch (Exception retryException) {
                log.error("Failed to restart authentication flow after cookie validation failure.", retryException);
                throw retryException;
            }
        } catch (ServletException | IOException e) {
            log.error("Error occurred during authentication request processing.", e);
            throw e;
        }
    }
}
