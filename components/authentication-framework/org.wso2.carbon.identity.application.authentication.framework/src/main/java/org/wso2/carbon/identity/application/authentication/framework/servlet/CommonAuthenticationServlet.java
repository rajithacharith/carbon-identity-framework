/*
 * Copyright (c) 2013, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
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

package org.wso2.carbon.identity.application.authentication.framework.servlet;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.CommonAuthenticationHandler;
import org.wso2.carbon.identity.application.authentication.framework.config.ConfigurationFacade;

import java.io.IOException;

import javax.servlet.ServletException;
import javax.servlet.http.HttpServlet;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Servlet to handle common authentication requests.
 */
public class CommonAuthenticationServlet extends HttpServlet {

    private static final Log log = LogFactory.getLog(CommonAuthenticationServlet.class);
    private final CommonAuthenticationHandler commonAuthenticationHandler = new CommonAuthenticationHandler();
    private static final long serialVersionUID = -7182121722709941646L;

    @Override
    public void init() {
        if (log.isDebugEnabled()) {
            log.debug("Initializing CommonAuthenticationServlet.");
        }
        // TODO move ConfigurationFacade initialization
        ConfigurationFacade.getInstance();
        log.info("CommonAuthenticationServlet initialized successfully.");
    }

    @Override
    protected void doGet(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Processing GET request for authentication.");
        }
        try {
            commonAuthenticationHandler.doGet(request, response);
        } catch (ServletException | IOException e) {
            log.error("Error occurred while processing GET request for authentication.", e);
            throw e;
        }
    }

    @Override
    protected void doPost(HttpServletRequest request, HttpServletResponse response)
            throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Processing POST request for authentication.");
        }
        try {
            commonAuthenticationHandler.doGet(request, response);
        } catch (ServletException | IOException e) {
            log.error("Error occurred while processing POST request for authentication.", e);
            throw e;
        }
    }

    @Override
    protected void doHead(HttpServletRequest request, HttpServletResponse response) {
        if (log.isDebugEnabled()) {
            log.debug("Processing HEAD request for authentication.");
        }
        response.setStatus(HttpServletResponse.SC_OK);
    }

    @Override
    protected void doOptions(HttpServletRequest req, HttpServletResponse resp)
            throws ServletException, IOException {
        if (log.isDebugEnabled()) {
            log.debug("Processing OPTIONS request for authentication.");
        }
        resp.setHeader("Allow", "GET, POST, HEAD, OPTIONS");
    }
}
