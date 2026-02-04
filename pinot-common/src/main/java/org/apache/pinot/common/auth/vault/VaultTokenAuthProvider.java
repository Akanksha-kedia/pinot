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

import org.apache.pinot.spi.auth.AuthProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* START GENAI@CLINE */
/**
 * Vault-based authentication provider with automatic token refresh
 */
public class VaultTokenAuthProvider implements AuthProvider {
  private static final Logger _logger = LoggerFactory.getLogger(VaultTokenAuthProvider.class);
  
  private final VaultConfig _config;
  private final VaultAuth _vaultAuth;
  private final VaultTokenCache _tokenCache;
  private volatile boolean _initialized = false;

  public VaultTokenAuthProvider(VaultConfig config) {
    _config = config;
    _vaultAuth = new VaultAuth(config);
    _tokenCache = new VaultTokenCache();
  }

  @Override
  public void init() {
    if (_initialized) {
      return;
    }
    
    try {
      _logger.info("Initializing Vault authentication provider");
      _vaultAuth.authenticate();
      _initialized = true;
      _logger.info("Vault authentication provider initialized successfully");
    } catch (Exception e) {
      _logger.error("Failed to initialize Vault authentication provider", e);
      throw new RuntimeException("Vault authentication initialization failed", e);
    }
  }

  @Override
  public String getToken() {
    if (!_initialized) {
      init();
    }
    
    String token = _tokenCache.getToken();
    if (token == null || isTokenExpired(token)) {
      synchronized (this) {
        token = _tokenCache.getToken();
        if (token == null || isTokenExpired(token)) {
          token = refreshToken();
        }
      }
    }
    return token;
  }

  private String refreshToken() {
    try {
      _logger.debug("Refreshing Vault token");
      String newToken = _vaultAuth.getToken();
      _tokenCache.setToken(newToken);
      _logger.debug("Vault token refreshed successfully");
      return newToken;
    } catch (Exception e) {
      _logger.error("Failed to refresh Vault token", e);
      throw new RuntimeException("Token refresh failed", e);
    }
  }

  private boolean isTokenExpired(String token) {
    // Token expiration logic would be implemented here
    // For now, refresh based on configured interval
    return _tokenCache.isExpired(_config.getTokenRefreshInterval());
  }

  @Override
  public void close() {
    _logger.info("Closing Vault authentication provider");
    _tokenCache.clear();
    _initialized = false;
  }
}
/* END GENAI@CLINE */
