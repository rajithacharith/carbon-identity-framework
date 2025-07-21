/*
 * Copyright (c) 2016, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.wso2.carbon.identity.claim.metadata.mgt.ui.client;

import org.apache.axis2.AxisFault;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.ClaimMetadataManagementServiceClaimMetadataException;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.ClaimMetadataManagementServiceStub;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.dto.ClaimDialectDTO;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.dto.ExternalClaimDTO;
import org.wso2.carbon.identity.claim.metadata.mgt.stub.dto.LocalClaimDTO;

import java.rmi.RemoteException;

/**
 * This class invokes the operations of ClaimMetadataManagementService.
 */
public class ClaimMetadataAdminClient {

    private static final Log log = LogFactory.getLog(ClaimMetadataAdminClient.class);
    private ClaimMetadataManagementServiceStub stub;

    /**
     * Instantiates ClaimMetadataAdminClient
     *
     * @param cookie           For session management
     * @param backendServerURL URL of the back end server where ClaimManagementServiceStub is running.
     * @param configCtx        ConfigurationContext
     * @throws org.apache.axis2.AxisFault if error occurs when instantiating the stub
     */
    public ClaimMetadataAdminClient(String cookie, String backendServerURL, ConfigurationContext configCtx) throws
            AxisFault {

        if (log.isDebugEnabled()) {
            log.debug("Initializing ClaimMetadataAdminClient with backend server URL: " + backendServerURL);
        }
        String serviceURL = backendServerURL + "ClaimMetadataManagementService";
        stub = new ClaimMetadataManagementServiceStub(configCtx, serviceURL);
        ServiceClient client = stub._getServiceClient();
        Options option = client.getOptions();
        option.setManageSession(true);
        option.setProperty(org.apache.axis2.transport.http.HTTPConstants.COOKIE_STRING, cookie);
        if (log.isDebugEnabled()) {
            log.debug("ClaimMetadataAdminClient initialized successfully");
        }
    }


    public ClaimDialectDTO[] getClaimDialects() throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claim dialects");
        }
        try {
            ClaimDialectDTO[] claimDialects = stub.getClaimDialects();
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + (claimDialects != null ? claimDialects.length : 0) + " claim dialects");
            }
            return claimDialects;
        } catch (RemoteException e) {
            log.error("Failed to retrieve claim dialects due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to retrieve claim dialects: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addClaimDialect(ClaimDialectDTO externalClaimDialect) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Adding claim dialect: " + (externalClaimDialect != null ? 
                    externalClaimDialect.getClaimDialectURI() : "null"));
        }
        try {
            stub.addClaimDialect(externalClaimDialect);
            if (log.isDebugEnabled()) {
                log.debug("Successfully added claim dialect: " + (externalClaimDialect != null ? 
                        externalClaimDialect.getClaimDialectURI() : "null"));
            }
        } catch (RemoteException e) {
            log.error("Failed to add claim dialect due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to add claim dialect: " + e.getMessage(), e);
            throw e;
        }
    }

    public void removeClaimDialect(String externalClaimDialect) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Removing claim dialect: " + externalClaimDialect);
        }
        try {
            ClaimDialectDTO claimDialect = new ClaimDialectDTO();
            claimDialect.setClaimDialectURI(externalClaimDialect);
            stub.removeClaimDialect(claimDialect);
            if (log.isDebugEnabled()) {
                log.debug("Successfully removed claim dialect: " + externalClaimDialect);
            }
        } catch (RemoteException e) {
            log.error("Failed to remove claim dialect due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to remove claim dialect: " + e.getMessage(), e);
            throw e;
        }
    }


    public LocalClaimDTO[] getLocalClaims() throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving local claims");
        }
        try {
            LocalClaimDTO[] localClaims = stub.getLocalClaims();
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + (localClaims != null ? localClaims.length : 0) + " local claims");
            }
            return localClaims;
        } catch (RemoteException e) {
            log.error("Failed to retrieve local claims due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to retrieve local claims: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addLocalClaim(LocalClaimDTO localCLaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Adding local claim: " + (localCLaim != null ? localCLaim.getLocalClaimURI() : "null"));
        }
        try {
            stub.addLocalClaim(localCLaim);
            if (log.isDebugEnabled()) {
                log.debug("Successfully added local claim: " + (localCLaim != null ? 
                        localCLaim.getLocalClaimURI() : "null"));
            }
        } catch (RemoteException e) {
            log.error("Failed to add local claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to add local claim: " + e.getMessage(), e);
            }
            throw e;
        }
    }

    public void updateLocalClaim(LocalClaimDTO localClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Updating local claim: " + (localClaim != null ? localClaim.getLocalClaimURI() : "null"));
        }
        try {
            stub.updateLocalClaim(localClaim);
            if (log.isDebugEnabled()) {
                log.debug("Successfully updated local claim: " + (localClaim != null ? 
                        localClaim.getLocalClaimURI() : "null"));
            }
        } catch (RemoteException e) {
            log.error("Failed to update local claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to update local claim: " + e.getMessage(), e);
            throw e;
        }
    }

    public void removeLocalClaim(String localCLaimURI) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Removing local claim: " + localCLaimURI);
        }
        try {
            stub.removeLocalClaim(localCLaimURI);
            if (log.isDebugEnabled()) {
                log.debug("Successfully removed local claim: " + localCLaimURI);
            }
        } catch (RemoteException e) {
            log.error("Failed to remove local claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to remove local claim: " + e.getMessage(), e);
            throw e;
        }
    }


    public ExternalClaimDTO[] getExternalClaims(String externalClaimDialectURI) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving external claims for dialect: " + externalClaimDialectURI);
        }
        try {
            ExternalClaimDTO[] externalClaims = stub.getExternalClaims(externalClaimDialectURI);
            if (log.isDebugEnabled()) {
                log.debug("Retrieved " + (externalClaims != null ? externalClaims.length : 0) + 
                        " external claims for dialect: " + externalClaimDialectURI);
            }
            return externalClaims;
        } catch (RemoteException e) {
            log.error("Failed to retrieve external claims due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to retrieve external claims: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addExternalClaim(ExternalClaimDTO externalClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Adding external claim: " + (externalClaim != null ? externalClaim.getExternalClaimURI() : 
                    "null"));
        }
        try {
            stub.addExternalClaim(externalClaim);
            if (log.isDebugEnabled()) {
                log.debug("Successfully added external claim: " + (externalClaim != null ? 
                        externalClaim.getExternalClaimURI() : "null"));
            }
        } catch (RemoteException e) {
            log.error("Failed to add external claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            if (log.isDebugEnabled()) {
                log.debug("Failed to add external claim: " + e.getMessage(), e);
            }
            throw e;
        }
    }

    public void updateExternalClaim(ExternalClaimDTO externalClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Updating external claim: " + (externalClaim != null ? 
                    externalClaim.getExternalClaimURI() : "null"));
        }
        try {
            stub.updateExternalClaim(externalClaim);
            if (log.isDebugEnabled()) {
                log.debug("Successfully updated external claim: " + (externalClaim != null ? 
                        externalClaim.getExternalClaimURI() : "null"));
            }
        } catch (RemoteException e) {
            log.error("Failed to update external claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to update external claim: " + e.getMessage(), e);
            throw e;
        }
    }

    public void removeExternalClaim(String externalClaimDialectURI, String externalClaimURI) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Removing external claim: " + externalClaimURI + " from dialect: " + 
                    externalClaimDialectURI);
        }
        try {
            stub.removeExternalClaim(externalClaimDialectURI, externalClaimURI);
            if (log.isDebugEnabled()) {
                log.debug("Successfully removed external claim: " + externalClaimURI + " from dialect: " + 
                        externalClaimDialectURI);
            }
        } catch (RemoteException e) {
            log.error("Failed to remove external claim due to remote exception: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Failed to remove external claim: " + e.getMessage(), e);
            throw e;
        }
    }
}
