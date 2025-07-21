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

package org.wso2.carbon.identity.application.authentication.framework;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.exception.ApplicationAuthenticationException;
import org.wso2.carbon.identity.application.authentication.framework.internal.core.ApplicationAuthenticatorManager;

import java.util.ArrayList;
import java.util.List;

/**
 * Application authentication service. This server only return the system defined authenticators.
 * The application authentication service currently returns only system-defined authenticators. This service is publicly
 * exposed and is presently utilized exclusively for API-based authenticator implementations, which are currently
 * support only for system-defined authenticators.
 * To support API-based authentication for custom authentication extensions, the existing methods will need to be
 * deprecated, and introduce new methods to support custom authenticators.
 * Issue: https://github.com/wso2/product-is/issues/22462
 */
public class ApplicationAuthenticationService {

    private static final Log log = LogFactory.getLog(ApplicationAuthenticationService.class);

    public ApplicationAuthenticator getAuthenticator(String name) throws ApplicationAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving authenticator with name: " + (name != null ? name : "[null]"));
        }

        if (name == null) {
            String errMsg = "Authenticator name cannot be null";
            log.error(errMsg);
            throw new ApplicationAuthenticationException(errMsg);
        }

        ApplicationAuthenticator appAuthenticator = null;

        for (ApplicationAuthenticator authenticator :
                ApplicationAuthenticatorManager.getInstance().getSystemDefinedAuthenticators()) {

            if (authenticator.getName().equals(name)) {
                appAuthenticator = authenticator;
                if (log.isDebugEnabled()) {
                    log.debug("Found authenticator: " + name);
                }
                break;
            }
        }

        if (appAuthenticator == null && log.isDebugEnabled()) {
            log.debug("Authenticator not found: " + name);
        }

        return appAuthenticator;
    }

    public List<ApplicationAuthenticator> getAllAuthenticators() throws ApplicationAuthenticationException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving all system defined authenticators.");
        }
        List<ApplicationAuthenticator> authenticators = 
                ApplicationAuthenticatorManager.getInstance().getSystemDefinedAuthenticators();
        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + (authenticators != null ? authenticators.size() : 0) + 
                     " system defined authenticators.");
        }
        return authenticators;
    }

    public List<ApplicationAuthenticator> getLocalAuthenticators() throws ApplicationAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving local authenticators.");
        }

        List<ApplicationAuthenticator> localAuthenticators = new ArrayList<ApplicationAuthenticator>();

        for (ApplicationAuthenticator authenticator :
                ApplicationAuthenticatorManager.getInstance().getSystemDefinedAuthenticators()) {

            if (authenticator instanceof LocalApplicationAuthenticator) {
                localAuthenticators.add(authenticator);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + localAuthenticators.size() + " local authenticators.");
        }

        return localAuthenticators;
    }

    public List<ApplicationAuthenticator> getFederatedAuthenticators() throws ApplicationAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving federated authenticators.");
        }

        List<ApplicationAuthenticator> federatedAuthenticators = new ArrayList<ApplicationAuthenticator>();

        for (ApplicationAuthenticator authenticator :
                ApplicationAuthenticatorManager.getInstance().getSystemDefinedAuthenticators()) {

            if (authenticator instanceof FederatedApplicationAuthenticator) {
                federatedAuthenticators.add(authenticator);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + federatedAuthenticators.size() + " federated authenticators.");
        }

        return federatedAuthenticators;
    }

    public List<ApplicationAuthenticator> getRequestPathAuthenticators() throws ApplicationAuthenticationException {

        if (log.isDebugEnabled()) {
            log.debug("Retrieving request path authenticators.");
        }

        List<ApplicationAuthenticator> reqPathAuthenticators = new ArrayList<ApplicationAuthenticator>();

        for (ApplicationAuthenticator authenticator :
                ApplicationAuthenticatorManager.getInstance().getSystemDefinedAuthenticators()) {

            if (authenticator instanceof RequestPathApplicationAuthenticator) {
                reqPathAuthenticators.add(authenticator);
            }
        }

        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + reqPathAuthenticators.size() + " request path authenticators.");
        }

        return reqPathAuthenticators;
    }
}
