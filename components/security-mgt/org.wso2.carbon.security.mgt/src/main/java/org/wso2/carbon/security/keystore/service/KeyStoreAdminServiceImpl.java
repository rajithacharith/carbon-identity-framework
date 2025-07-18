/*
 * Copyright (c) 2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
 *
 * WSO2 Inc. licenses this file to you under the Apache License,
 * Version 2.0 (the "License"); you may not use this file except
 * in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.wso2.carbon.security.keystore.service;

import org.apache.axiom.om.util.Base64;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.base.MultitenantConstants;
import org.wso2.carbon.context.CarbonContext;
import org.wso2.carbon.core.AbstractAdmin;
import org.wso2.carbon.core.util.KeyStoreManager;
import org.wso2.carbon.security.SecurityConfigException;
import org.wso2.carbon.security.keystore.KeyStoreAdmin;

public class KeyStoreAdminServiceImpl extends AbstractAdmin implements KeyStoreAdminInterface {

    private static final Log log = LogFactory.getLog(KeyStoreAdminServiceImpl.class);

    @Override
    public KeyStoreData[] getKeyStores() throws SecurityConfigException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Retrieving keystores for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        boolean isSuperTenant = tenantId == MultitenantConstants.SUPER_TENANT_ID;
        KeyStoreData[] keyStores = admin.getKeyStores(isSuperTenant);
        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + (keyStores != null ? keyStores.length : 0) + " keystores for tenant ID: " + 
                    tenantId);
        }
        return keyStores;
    }

    @Override
    public void addKeyStore(String fileData, String filename, String password, String provider,
                            String type, String pvtkeyPass) throws SecurityConfigException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Adding keystore '" + filename + "' for tenant ID: " + tenantId);
        }
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        try {
            keyStoreManager.addKeyStore(Base64.decode(fileData), filename, password, provider, type, pvtkeyPass);
            if (log.isInfoEnabled()) {
                log.info("Keystore '" + filename + "' added successfully for tenant ID: " + tenantId);
            }
        } catch (SecurityException e) {
            throw new SecurityConfigException(e.getMessage());
        }
    }

    @Override
    public void addTrustStore(String fileData, String filename, String password, String provider,
                              String type) throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Adding truststore '" + filename + "' for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        admin.addTrustStore(fileData, filename, password, provider, type);
        if (log.isInfoEnabled()) {
            log.info("Truststore '" + filename + "' added successfully for tenant ID: " + tenantId);
        }
    }

    @Override
    public void deleteStore(String keyStoreName) throws SecurityConfigException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Deleting keystore '" + keyStoreName + "' for tenant ID: " + tenantId);
        }
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance(tenantId);
        try {
            keyStoreManager.deleteStore(keyStoreName);
            if (log.isInfoEnabled()) {
                log.info("Keystore '" + keyStoreName + "' deleted successfully for tenant ID: " + tenantId);
            }
        } catch (SecurityException e) {
            throw new SecurityConfigException(e.getMessage());
        }
    }

    @Override
    public void importCertToStore(String fileName, String fileData, String keyStoreName)
            throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Importing certificate '" + fileName + "' to keystore '" + keyStoreName + 
                    "' for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        admin.importCertToStore(fileName, fileData, keyStoreName);
        if (log.isInfoEnabled()) {
            log.info("Certificate '" + fileName + "' imported successfully to keystore '" + keyStoreName + 
                    "' for tenant ID: " + tenantId);
        }
    }

    @Override
    public String[] getStoreEntries(String keyStoreName) throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Retrieving store entries for keystore '" + keyStoreName + "' for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        String[] entries = admin.getStoreEntries(keyStoreName);
        if (log.isDebugEnabled()) {
            log.debug("Retrieved " + (entries != null ? entries.length : 0) + " entries from keystore '" + 
                    keyStoreName + "' for tenant ID: " + tenantId);
        }
        return entries;
    }

    @Override
    public KeyStoreData getKeystoreInfo(String keyStoreName) throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Retrieving keystore info for '" + keyStoreName + "' for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        return admin.getKeystoreInfo(keyStoreName);
    }

    @Override
    public void removeCertFromStore(String alias, String keyStoreName) throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Removing certificate with alias '" + alias + "' from keystore '" + keyStoreName + 
                    "' for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        admin.removeCertFromStore(alias, keyStoreName);
        if (log.isInfoEnabled()) {
            log.info("Certificate with alias '" + alias + "' removed successfully from keystore '" + keyStoreName + 
                    "' for tenant ID: " + tenantId);
        }
    }

    public PaginatedKeyStoreData getPaginatedKeystoreInfo(String keyStoreName, int pageNumber) throws SecurityConfigException {
        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Retrieving paginated keystore info for '" + keyStoreName + "', page: " + pageNumber + 
                    " for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        return admin.getPaginatedKeystoreInfo(keyStoreName, pageNumber);
    }

    /**
     * Calls method to get the keystore info using keystore name and its certificates filtered by the given filter.
     *
     * @param keyStoreName Keystore name.
     * @param pageNumber   Page number.
     * @param filter       Filter for certificate alias.
     * @return Paginated keystore data with certificates.
     * @throws SecurityConfigException
     */
    public PaginatedKeyStoreData getFilteredPaginatedKeyStoreInfo(String keyStoreName, int pageNumber,
                                                                  String filter) throws SecurityConfigException {

        int tenantId = CarbonContext.getThreadLocalCarbonContext().getTenantId();
        if (log.isDebugEnabled()) {
            log.debug("Retrieving filtered paginated keystore info for '" + keyStoreName + "', page: " + pageNumber + 
                    ", filter: " + filter + " for tenant ID: " + tenantId);
        }
        KeyStoreAdmin admin = new KeyStoreAdmin(tenantId);
        return admin.getFilteredPaginatedKeyStoreInfo(keyStoreName, pageNumber, filter);
    }
}
