/*
 * Copyright (c) 2025, WSO2 LLC. (http://www.wso2.com).
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

package org.wso2.carbon.identity.webhook.management.internal.dao.impl;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.wso2.carbon.identity.webhook.management.api.core.cache.WebhookCache;
import org.wso2.carbon.identity.webhook.management.api.core.cache.WebhookCacheEntry;
import org.wso2.carbon.identity.webhook.management.api.core.cache.WebhookCacheKey;
import org.wso2.carbon.identity.webhook.management.api.exception.WebhookMgtException;
import org.wso2.carbon.identity.webhook.management.api.model.Webhook;
import org.wso2.carbon.identity.webhook.management.internal.dao.WebhookManagementDAO;

import java.util.Collections;
import java.util.List;

/**
 * Cache backed implementation of WebhookManagementDAO.
 * This class adds caching layer to webhook management operations.
 */
public class CacheBackedWebhookManagementDAO implements WebhookManagementDAO {

    private static final Log LOG = LogFactory.getLog(CacheBackedWebhookManagementDAO.class);
    private final WebhookManagementDAO webhookManagementDAO;
    private final WebhookCache webhookCache;

    /**
     * Constructor.
     *
     * @param webhookManagementDAO WebhookManagementDAO implementation to be wrapped.
     */
    public CacheBackedWebhookManagementDAO(WebhookManagementDAO webhookManagementDAO) {

        this.webhookManagementDAO = webhookManagementDAO;
        this.webhookCache = WebhookCache.getInstance();
    }

    @Override
    public void createWebhook(Webhook webhook, int tenantId) throws WebhookMgtException {

        webhookManagementDAO.createWebhook(webhook, tenantId);
    }

    @Override
    public Webhook getWebhook(String webhookId, int tenantId) throws WebhookMgtException {

        WebhookCacheEntry webhookCacheEntry = webhookCache.getValueFromCache(new WebhookCacheKey(webhookId), tenantId);
        if (webhookCacheEntry != null && webhookCacheEntry.getWebhook() != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Webhook cache hit for webhook ID: " + webhookId + ". Returning from cache.");
            }
            return webhookCacheEntry.getWebhook();
        }

        Webhook webhook = webhookManagementDAO.getWebhook(webhookId, tenantId);
        if (webhook != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Webhook cache miss for webhook ID: " + webhookId + ". Adding to cache.");
            }
            webhookCache.addToCache(new WebhookCacheKey(webhookId), new WebhookCacheEntry(webhook), tenantId);
        }
        return webhook;
    }

    @Override
    public List<String> getWebhookEvents(String webhookId, int tenantId) throws WebhookMgtException {

        WebhookCacheEntry webhookCacheEntry = webhookCache.getValueFromCache(new WebhookCacheKey(webhookId), tenantId);
        if (webhookCacheEntry != null && webhookCacheEntry.getWebhook() != null &&
                webhookCacheEntry.getWebhook().getEventsSubscribed() != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Webhook cache hit for webhook ID: " + webhookId + ". Returning from cache.");
            }
            return webhookCacheEntry.getWebhook().getEventsSubscribed();
        }

        Webhook webhook = webhookManagementDAO.getWebhook(webhookId, tenantId);
        if (webhook != null) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Webhook cache miss for webhook events for webhook ID: " + webhookId + ". Adding to cache.");
            }
            webhookCache.addToCache(new WebhookCacheKey(webhookId), new WebhookCacheEntry(webhook), tenantId);

            if (webhook.getEventsSubscribed() != null) {
                return webhook.getEventsSubscribed();
            }
        }
        return Collections.emptyList();
    }

    @Override
    public void updateWebhook(Webhook webhook, int tenantId) throws WebhookMgtException {

        webhookCache.clearCacheEntry(new WebhookCacheKey(webhook.getUuid()), tenantId);
        LOG.debug("Webhook cache entry is cleared for webhook ID: " + webhook.getUuid() + " for webhook update.");
        webhookManagementDAO.updateWebhook(webhook, tenantId);
    }

    @Override
    public void deleteWebhook(String webhookId, int tenantId) throws WebhookMgtException {

        webhookCache.clearCacheEntry(new WebhookCacheKey(webhookId), tenantId);
        LOG.debug("Webhook cache entry is cleared for webhook ID: " + webhookId + " for webhook deletion.");
        webhookManagementDAO.deleteWebhook(webhookId, tenantId);
    }

    @Override
    public List<Webhook> getWebhooks(int tenantId) throws WebhookMgtException {
        // Get all operations bypass cache
        return webhookManagementDAO.getWebhooks(tenantId);
    }

    @Override
    public boolean isWebhookEndpointExists(String endpoint, int tenantId) throws WebhookMgtException {
        // Endpoint existence check bypasses cache
        return webhookManagementDAO.isWebhookEndpointExists(endpoint, tenantId);
    }

    @Override
    public void activateWebhook(String webhookId, int tenantId) throws WebhookMgtException {

        webhookCache.clearCacheEntry(new WebhookCacheKey(webhookId), tenantId);
        LOG.debug("Webhook cache entry is cleared for webhook ID: " + webhookId + " for webhook activate.");
        webhookManagementDAO.activateWebhook(webhookId, tenantId);
    }

    @Override
    public void deactivateWebhook(String webhookId, int tenantId) throws WebhookMgtException {

        webhookCache.clearCacheEntry(new WebhookCacheKey(webhookId), tenantId);
        LOG.debug("Webhook cache entry is cleared for webhook ID: " + webhookId + " for webhook deactivate.");
        webhookManagementDAO.deactivateWebhook(webhookId, tenantId);
    }
}
