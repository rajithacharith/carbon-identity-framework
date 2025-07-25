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
 *
 */

package org.wso2.carbon.claim.mgt;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.user.api.ClaimMapping;

public class ClaimDialect {

    private static final Log log = LogFactory.getLog(ClaimDialect.class);
    private ClaimMapping[] claimMapping;
    private String dialectUri;
    private String userStore;

    public String getUserStore() {
        return userStore;
    }

    public void setUserStore(String userStore) {
        this.userStore = userStore;
    }

    public ClaimMapping[] getClaimMapping() {
        if (claimMapping != null) {
            if (log.isDebugEnabled()) {
                log.debug("Returning claim mapping array with " + claimMapping.length + " mappings");
            }
            return claimMapping.clone();
        } else {
            if (log.isDebugEnabled()) {
                log.debug("Claim mapping array is null, returning empty array");
            }
            return new ClaimMapping[0];
        }
    }

    public void setClaimMapping(ClaimMapping[] claimMapping) {
        if (claimMapping != null) {
            if (log.isDebugEnabled()) {
                log.debug("Setting claim mapping array with " + claimMapping.length + " mappings");
            }
            this.claimMapping = claimMapping.clone();
        } else if (log.isDebugEnabled()) {
            log.debug("Setting claim mapping array to null");
        }
    }

    public String getDialectUri() {
        return dialectUri;
    }

    public void setDialectUri(String dialectUri) {
        this.dialectUri = dialectUri;
    }
}
