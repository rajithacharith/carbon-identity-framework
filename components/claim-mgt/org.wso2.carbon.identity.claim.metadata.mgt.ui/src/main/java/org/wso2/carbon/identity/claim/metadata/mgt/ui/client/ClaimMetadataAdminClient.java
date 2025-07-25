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
            log.debug("ClaimMetadataAdminClient initialized successfully for service URL: " + serviceURL);
        }
    }


    public ClaimDialectDTO[] getClaimDialects() throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving claim dialects");
        }
        try {
            ClaimDialectDTO[] dialects = stub.getClaimDialects();
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved " + (dialects != null ? dialects.length : 0) + " claim dialects");
            }
            return dialects;
        } catch (RemoteException e) {
            log.error("Remote exception occurred while retrieving claim dialects: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while retrieving claim dialects: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addClaimDialect(ClaimDialectDTO externalClaimDialect) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            String dialectURI = (externalClaimDialect != null) ? externalClaimDialect.getClaimDialectURI() : "null";
            log.debug("Adding claim dialect: " + dialectURI);
        }
        try {
            stub.addClaimDialect(externalClaimDialect);
            log.info("Claim dialect added successfully");
        } catch (RemoteException e) {
            log.error("Remote exception occurred while adding claim dialect: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while adding claim dialect: " + e.getMessage(), e);
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
            log.info("Claim dialect removed successfully: " + externalClaimDialect);
        } catch (RemoteException e) {
            log.error("Remote exception occurred while removing claim dialect: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while removing claim dialect: " + e.getMessage(), e);
            throw e;
        }
    }


    public LocalClaimDTO[] getLocalClaims() throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving local claims");
        }
        try {
            LocalClaimDTO[] claims = stub.getLocalClaims();
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved " + (claims != null ? claims.length : 0) + " local claims");
            }
            return claims;
        } catch (RemoteException e) {
            log.error("Remote exception occurred while retrieving local claims: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while retrieving local claims: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addLocalClaim(LocalClaimDTO localCLaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            String claimURI = (localCLaim != null) ? localCLaim.getLocalClaimURI() : "null";
            log.debug("Adding local claim: " + claimURI);
        }
        try {
            stub.addLocalClaim(localCLaim);
            log.info("Local claim added successfully");
        } catch (RemoteException e) {
            log.error("Remote exception occurred while adding local claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while adding local claim: " + e.getMessage(), e);
            throw e;
        }
    }

    public void updateLocalClaim(LocalClaimDTO localClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            String claimURI = (localClaim != null) ? localClaim.getLocalClaimURI() : "null";
            log.debug("Updating local claim: " + claimURI);
        }
        try {
            stub.updateLocalClaim(localClaim);
            log.info("Local claim updated successfully");
        } catch (RemoteException e) {
            log.error("Remote exception occurred while updating local claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while updating local claim: " + e.getMessage(), e);
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
            log.info("Local claim removed successfully: " + localCLaimURI);
        } catch (RemoteException e) {
            log.error("Remote exception occurred while removing local claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while removing local claim: " + e.getMessage(), e);
            throw e;
        }
    }


    public ExternalClaimDTO[] getExternalClaims(String externalClaimDialectURI) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Retrieving external claims for dialect: " + externalClaimDialectURI);
        }
        try {
            ExternalClaimDTO[] claims = stub.getExternalClaims(externalClaimDialectURI);
            if (log.isDebugEnabled()) {
                log.debug("Successfully retrieved " + (claims != null ? claims.length : 0) + 
                         " external claims for dialect: " + externalClaimDialectURI);
            }
            return claims;
        } catch (RemoteException e) {
            log.error("Remote exception occurred while retrieving external claims: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while retrieving external claims: " + e.getMessage(), e);
            throw e;
        }
    }

    public void addExternalClaim(ExternalClaimDTO externalClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            String claimURI = (externalClaim != null) ? externalClaim.getExternalClaimURI() : "null";
            log.debug("Adding external claim: " + claimURI);
        }
        try {
            stub.addExternalClaim(externalClaim);
            log.info("External claim added successfully");
        } catch (RemoteException e) {
            log.error("Remote exception occurred while adding external claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while adding external claim: " + e.getMessage(), e);
            throw e;
        }
    }

    public void updateExternalClaim(ExternalClaimDTO externalClaim) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            String claimURI = (externalClaim != null) ? externalClaim.getExternalClaimURI() : "null";
            log.debug("Updating external claim: " + claimURI);
        }
        try {
            stub.updateExternalClaim(externalClaim);
            log.info("External claim updated successfully");
        } catch (RemoteException e) {
            log.error("Remote exception occurred while updating external claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while updating external claim: " + e.getMessage(), e);
            throw e;
        }
    }

    public void removeExternalClaim(String externalClaimDialectURI, String externalClaimURI) throws RemoteException,
            ClaimMetadataManagementServiceClaimMetadataException {
        if (log.isDebugEnabled()) {
            log.debug("Removing external claim: " + externalClaimURI + " from dialect: " + externalClaimDialectURI);
        }
        try {
            stub.removeExternalClaim(externalClaimDialectURI, externalClaimURI);
            log.info("External claim removed successfully: " + externalClaimURI);
        } catch (RemoteException e) {
            log.error("Remote exception occurred while removing external claim: " + e.getMessage(), e);
            throw e;
        } catch (ClaimMetadataManagementServiceClaimMetadataException e) {
            log.error("Claim metadata exception occurred while removing external claim: " + e.getMessage(), e);
            throw e;
        }
    }
}
