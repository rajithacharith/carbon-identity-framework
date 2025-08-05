/*
 * Copyright (c) 2013-2023, WSO2 LLC. (http://www.wso2.com).
 *
 * WSO2 LLC. licenses this file to you under the Apache License,
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

package org.wso2.carbon.identity.application.authentication.framework.config.model;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.application.authentication.framework.config.model.graph.AuthenticationGraph;
import org.wso2.carbon.identity.application.authentication.framework.model.AuthenticatedUser;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

/**
 * Configuration holder for an application.
 */
public class SequenceConfig implements Serializable, Cloneable {

    private static final Log log = LogFactory.getLog(SequenceConfig.class);
    private static final long serialVersionUID = 6822366703354668075L;

    private String name;
    private boolean isForceAuthn;
    private boolean isCheckAuthn;
    private String applicationId;
    private Map<Integer, StepConfig> stepMap = new HashMap<>();
    private AuthenticationGraph authenticationGraph;
    private List<AuthenticatorConfig> reqPathAuthenticators = new ArrayList<>();
    private ApplicationConfig applicationConfig = null;
    private OptimizedApplicationConfig optimizedApplicationConfig = null;
    private boolean completed;

    private AuthenticatedUser authenticatedUser;
    private String authenticatedIdPs;

    private AuthenticatorConfig authenticatedReqPathAuthenticator;
    private List<String> requestedAcr;

    public SequenceConfig() {
        if (log.isDebugEnabled()) {
            log.debug("Creating new SequenceConfig instance.");
        }
    }

    public String getName() {
        return name;
    }

    public void setName(String name) {
        if (log.isDebugEnabled()) {
            log.debug("Setting sequence name to: " + (name != null ? name : "[null]"));
        }
        this.name = name;
    }

    public Map<Integer, StepConfig> getStepMap() {
        return stepMap;
    }

    public void setStepMap(Map<Integer, StepConfig> stepMap) {
        if (log.isDebugEnabled()) {
            log.debug("Setting step map with " + (stepMap != null ? stepMap.size() : 0) + " steps.");
        }
        this.stepMap = stepMap;
    }

    public boolean isForceAuthn() {
        return isForceAuthn;
    }

    public void setForceAuthn(boolean isForceAuthn) {
        if (log.isDebugEnabled()) {
            log.debug("Setting force authentication flag to: " + isForceAuthn);
        }
        this.isForceAuthn = isForceAuthn;
    }

    public boolean isCheckAuthn() {
        return isCheckAuthn;
    }

    public void setCheckAuthn(boolean isCheckAuthn) {
        this.isCheckAuthn = isCheckAuthn;
    }

    public List<AuthenticatorConfig> getReqPathAuthenticators() {
        return reqPathAuthenticators;
    }

    public void setReqPathAuthenticators(
            List<AuthenticatorConfig> reqPathAuthenticators) {
        this.reqPathAuthenticators = reqPathAuthenticators;
    }

    public ApplicationConfig getApplicationConfig() {
        return applicationConfig;
    }

    public void setApplicationConfig(ApplicationConfig applicationConfig) {
        if (log.isDebugEnabled()) {
            log.debug("Setting application configuration: " + 
                     (applicationConfig != null ? "[provided]" : "[null]"));
        }
        this.applicationConfig = applicationConfig;
    }

    public String getApplicationId() {
        return applicationId;
    }

    public void setApplicationId(String applicationId) {
        this.applicationId = applicationId;
    }

    public boolean isCompleted() {
        return completed;
    }

    public void setCompleted(boolean completed) {
        if (log.isDebugEnabled()) {
            log.debug("Setting sequence completion status to: " + completed);
        }
        this.completed = completed;
    }

    public AuthenticatedUser getAuthenticatedUser() {
        return authenticatedUser;
    }

    public void setAuthenticatedUser(AuthenticatedUser authenticatedUser) {
        if (log.isDebugEnabled()) {
            log.debug("Setting authenticated user: " + 
                     (authenticatedUser != null ? authenticatedUser.getUserName() : "[null]"));
        }
        this.authenticatedUser = authenticatedUser;
    }

    public String getAuthenticatedIdPs() {
        return authenticatedIdPs;
    }

    public void setAuthenticatedIdPs(String authenticatedIdPs) {
        this.authenticatedIdPs = authenticatedIdPs;
    }

    public AuthenticatorConfig getAuthenticatedReqPathAuthenticator() {
        return authenticatedReqPathAuthenticator;
    }

    public void setAuthenticatedReqPathAuthenticator(
            AuthenticatorConfig authenticatedReqPathAuthenticator) {
        this.authenticatedReqPathAuthenticator = authenticatedReqPathAuthenticator;
    }

    public AuthenticationGraph getAuthenticationGraph() {
        return authenticationGraph;
    }

    public void setAuthenticationGraph(AuthenticationGraph authenticationGraph) {
        if (log.isDebugEnabled()) {
            log.debug("Setting authentication graph: " + 
                     (authenticationGraph != null ? "[provided]" : "[null]"));
        }
        this.authenticationGraph = authenticationGraph;
    }

    public List<String> getRequestedAcr() {
        if (requestedAcr == null) {
            return Collections.emptyList();
        }
        return Collections.unmodifiableList(requestedAcr);
    }

    public void addRequestedAcr(String acr) {
        if (log.isDebugEnabled()) {
            log.debug("Adding requested ACR: " + (acr != null ? acr : "[null]"));
        }
        if (requestedAcr == null) {
            requestedAcr = new ArrayList<>();
        }
        requestedAcr.add(acr);
    }

    /**
     * This method will clone current class objects.
     * This method is to solve the issue - multiple requests for same user/SP
     *
     * @return Object object
     */
    public Object clone() throws CloneNotSupportedException {
        if (log.isDebugEnabled()) {
            log.debug("Cloning SequenceConfig for: " + (name != null ? name : "[unnamed]"));
        }
        SequenceConfig sequenceConfig = (SequenceConfig) super.clone();
        sequenceConfig.setApplicationConfig((ApplicationConfig) applicationConfig.clone());
        sequenceConfig.setStepMap(new HashMap<>(this.stepMap));
        sequenceConfig.setReqPathAuthenticators(new ArrayList<>(this.reqPathAuthenticators));
        sequenceConfig.setName(this.getName());
        sequenceConfig.setForceAuthn(this.isForceAuthn());
        sequenceConfig.setCheckAuthn(this.isCheckAuthn());
        sequenceConfig.setApplicationId(this.getApplicationId());
        sequenceConfig.setCompleted(this.isCompleted());
        sequenceConfig.setAuthenticatedUser(this.getAuthenticatedUser());
        sequenceConfig.setAuthenticatedIdPs(this.getAuthenticatedIdPs());
        sequenceConfig.setAuthenticatedReqPathAuthenticator(this.getAuthenticatedReqPathAuthenticator());
        sequenceConfig.requestedAcr = new ArrayList<>(this.getRequestedAcr());
        sequenceConfig.setAuthenticationGraph(this.getAuthenticationGraph());
        sequenceConfig.setOptimizedApplicationConfig(this.getOptimizedApplicationConfig());
        if (log.isDebugEnabled()) {
            log.debug("Successfully cloned SequenceConfig.");
        }
        return sequenceConfig;
    }

    public void setRequestedAcr(List<String> requestedAcr) {

        this.requestedAcr = requestedAcr;
    }

    public OptimizedApplicationConfig getOptimizedApplicationConfig() {

        return this.optimizedApplicationConfig;
    }

    public void setOptimizedApplicationConfig(OptimizedApplicationConfig optimizedApplicationConfig) {

        this.optimizedApplicationConfig = optimizedApplicationConfig;
    }
}
