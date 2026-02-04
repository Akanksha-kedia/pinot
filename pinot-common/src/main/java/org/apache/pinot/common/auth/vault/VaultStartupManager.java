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
package org.apache.pinot.common.auth.vault;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* START GENAI@CLINE */
/**
 * Singleton lifecycle management for Vault integration
 */
public class VaultStartupManager {
  private static final Logger _logger = LoggerFactory.getLogger(VaultStartupManager.class);
  private static volatile VaultStartupManager _instance;
  private static final Object _lock = new Object();
  
  private volatile boolean _initialized = false;
  private volatile VaultConfig _globalConfig;

  private VaultStartupManager() {
    // Singleton
  }

  public static VaultStartupManager getInstance() {
    if (_instance == null) {
      synchronized (_lock) {
        if (_instance == null) {
          _instance = new VaultStartupManager();
        }
      }
    }
    return _instance;
  }

  public synchronized void initialize(VaultConfig config) {
    if (_initialized) {
      _logger.warn("VaultStartupManager already initialized");
      return;
    }
    
    try {
      _logger.info("Initializing Vault startup manager");
      validateConfig(config);
      _globalConfig = config;
      _initialized = true;
      _logger.info("Vault startup manager initialized successfully");
    } catch (Exception e) {
      _logger.error("Failed to initialize Vault startup manager", e);
      throw new RuntimeException("Vault startup initialization failed", e);
    }
  }

  public VaultConfig getGlobalConfig() {
    if (!_initialized) {
      throw new IllegalStateException("VaultStartupManager not initialized");
    }
    return _globalConfig;
  }

  public boolean isInitialized() {
    return _initialized;
  }

  private void validateConfig(VaultConfig config) {
    if (config == null) {
      throw new IllegalArgumentException("VaultConfig cannot be null");
    }
    
    if (!VaultUtil.isValidVaultUrl(config.getUrl())) {
      throw new IllegalArgumentException("Invalid Vault URL: " + config.getUrl());
    }
    
    if (!VaultUtil.isValidAuthMethod(config.getAuthMethod())) {
      throw new IllegalArgumentException("Invalid auth method: " + config.getAuthMethod());
    }
    
    if ("token".equals(config.getAuthMethod()) && !VaultUtil.isValidVaultToken(config.getToken())) {
      throw new IllegalArgumentException("Invalid Vault token for token auth method");
    }
    
    if ("approle".equals(config.getAuthMethod())) {
      if (config.getRoleId() == null || config.getRoleId().trim().isEmpty()) {
        throw new IllegalArgumentException("Role ID required for AppRole auth method");
      }
      if (config.getSecretId() == null || config.getSecretId().trim().isEmpty()) {
        throw new IllegalArgumentException("Secret ID required for AppRole auth method");
      }
    }
    
    _logger.debug("Vault configuration validation successful: {}", VaultUtil.createSecureConfigString(config));
  }

  public synchronized void shutdown() {
    if (!_initialized) {
      return;
    }
    
    _logger.info("Shutting down Vault startup manager");
    _globalConfig = null;
    _initialized = false;
    _logger.info("Vault startup manager shutdown complete");
  }
}
/* END GENAI@CLINE */
