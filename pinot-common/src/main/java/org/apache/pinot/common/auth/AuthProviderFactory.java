/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.pinot.common.auth;

import org.apache.pinot.common.auth.vault.VaultConfig;
import org.apache.pinot.common.auth.vault.VaultTokenAuthProvider;
import org.apache.pinot.common.auth.vault.VaultStartupManager;
import org.apache.pinot.spi.auth.AuthProvider;
import org.apache.pinot.spi.env.PinotConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Factory class for creating authentication providers based on configuration
 * Supports both static token and HashiCorp Vault authentication
 */
public class AuthProviderFactory {
  private static final Logger _logger = LoggerFactory.getLogger(AuthProviderFactory.class);
  
  // Configuration keys
  private static final String AUTH_TYPE_KEY = "auth.type";
  private static final String AUTH_TOKEN_KEY = "auth.token";
  
  // Vault configuration keys  
  private static final String VAULT_URL_KEY = "auth.vault.url";
  private static final String VAULT_TOKEN_KEY = "auth.vault.token";
  private static final String VAULT_AUTH_METHOD_KEY = "auth.vault.authMethod";
  private static final String VAULT_NAMESPACE_KEY = "auth.vault.namespace";
  private static final String VAULT_PATH_KEY = "auth.vault.path";
  private static final String VAULT_SECRET_PATH_KEY = "auth.vault.secretPath";
  private static final String VAULT_ROLE_ID_KEY = "auth.vault.roleId";
  private static final String VAULT_SECRET_ID_KEY = "auth.vault.secretId";
  private static final String VAULT_TOKEN_REFRESH_INTERVAL_KEY = "auth.vault.tokenRefreshInterval";
  private static final String VAULT_MAX_RETRIES_KEY = "auth.vault.maxRetries";
  private static final String VAULT_RETRY_INTERVAL_MS_KEY = "auth.vault.retryIntervalMs";
  private static final String VAULT_OPEN_TIMEOUT_SECONDS_KEY = "auth.vault.openTimeoutSeconds";
  private static final String VAULT_READ_TIMEOUT_SECONDS_KEY = "auth.vault.readTimeoutSeconds";
  
  // Auth types
  public static final String AUTH_TYPE_STATIC = "static";
  public static final String AUTH_TYPE_VAULT = "vault";

  /**
   * Create an authentication provider based on configuration
   */
  public static AuthProvider createAuthProvider(PinotConfiguration config) {
    String authType = config.getProperty(AUTH_TYPE_KEY, AUTH_TYPE_STATIC).toLowerCase();
    
    _logger.info("Initializing authentication provider: {}", authType);
    
    switch (authType) {
      case AUTH_TYPE_VAULT:
        return createVaultAuthProvider(config);
      case AUTH_TYPE_STATIC:
      default:
        return createStaticAuthProvider(config);
    }
  }

  /**
   * Create HashiCorp Vault authentication provider
   */
  private static AuthProvider createVaultAuthProvider(PinotConfiguration config) {
    try {
      VaultConfig vaultConfig = buildVaultConfig(config);
      
      // Initialize Vault startup manager (singleton)
      VaultStartupManager.getInstance().initialize(vaultConfig);
      
      // Create and initialize Vault auth provider
      VaultTokenAuthProvider provider = new VaultTokenAuthProvider(vaultConfig);
      provider.init();
      
      _logger.info("Successfully initialized Vault authentication provider");
      return provider;
      
    } catch (Exception e) {
      _logger.error("Failed to initialize Vault authentication provider", e);
      throw new RuntimeException("Vault authentication initialization failed", e);
    }
  }

  /**
   * Create static token authentication provider
   */
  private static AuthProvider createStaticAuthProvider(PinotConfiguration config) {
    String token = config.getProperty(AUTH_TOKEN_KEY);
    if (token == null || token.trim().isEmpty()) {
      _logger.warn("No static authentication token provided");
      token = "";
    }
    
    StaticTokenAuthProvider provider = new StaticTokenAuthProvider(token);
    provider.init();
    
    _logger.info("Successfully initialized static token authentication provider");
    return provider;
  }

  /**
   * Build VaultConfig from PinotConfiguration
   */
  private static VaultConfig buildVaultConfig(PinotConfiguration config) {
    VaultConfig vaultConfig = new VaultConfig();
    
    // Required settings
    vaultConfig.setUrl(config.getProperty(VAULT_URL_KEY));
    
    // Optional settings with defaults
    if (config.containsKey(VAULT_TOKEN_KEY)) {
      vaultConfig.setToken(config.getProperty(VAULT_TOKEN_KEY));
    }
    
    vaultConfig.setAuthMethod(config.getProperty(VAULT_AUTH_METHOD_KEY, "token"));
    
    if (config.containsKey(VAULT_NAMESPACE_KEY)) {
      vaultConfig.setNamespace(config.getProperty(VAULT_NAMESPACE_KEY));
    }
    
    if (config.containsKey(VAULT_PATH_KEY)) {
      vaultConfig.setPath(config.getProperty(VAULT_PATH_KEY));
    }
    
    if (config.containsKey(VAULT_SECRET_PATH_KEY)) {
      vaultConfig.setSecretPath(config.getProperty(VAULT_SECRET_PATH_KEY));
    }
    
    if (config.containsKey(VAULT_ROLE_ID_KEY)) {
      vaultConfig.setRoleId(config.getProperty(VAULT_ROLE_ID_KEY));
    }
    
    if (config.containsKey(VAULT_SECRET_ID_KEY)) {
      vaultConfig.setSecretId(config.getProperty(VAULT_SECRET_ID_KEY));
    }
    
    // Numeric settings with defaults
    vaultConfig.setTokenRefreshInterval(
        config.getProperty(VAULT_TOKEN_REFRESH_INTERVAL_KEY, 3600000L));
    vaultConfig.setMaxRetries(
        config.getProperty(VAULT_MAX_RETRIES_KEY, 3));
    vaultConfig.setRetryIntervalMs(
        config.getProperty(VAULT_RETRY_INTERVAL_MS_KEY, 1000L));
    vaultConfig.setOpenTimeoutSeconds(
        config.getProperty(VAULT_OPEN_TIMEOUT_SECONDS_KEY, 5));
    vaultConfig.setReadTimeoutSeconds(
        config.getProperty(VAULT_READ_TIMEOUT_SECONDS_KEY, 20));
    
    return vaultConfig;
  }

  /**
   * Check if Vault authentication is configured
   */
  public static boolean isVaultConfigured(PinotConfiguration config) {
    String authType = config.getProperty(AUTH_TYPE_KEY, AUTH_TYPE_STATIC).toLowerCase();
    return AUTH_TYPE_VAULT.equals(authType) && config.containsKey(VAULT_URL_KEY);
  }

  /**
   * Get authentication type from configuration
   */
  public static String getAuthType(PinotConfiguration config) {
    return config.getProperty(AUTH_TYPE_KEY, AUTH_TYPE_STATIC).toLowerCase();
  }
}
