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

import java.io.IOException;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/* START GENAI@CLINE */
/**
 * Low-level Vault authentication operations with retry logic
 */
public class VaultAuth {
  private static final Logger _logger = LoggerFactory.getLogger(VaultAuth.class);
  
  private final VaultConfig _config;
  private final HttpClient _httpClient;
  private volatile String _currentToken;

  public VaultAuth(VaultConfig config) {
    _config = config;
    _httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(config.getOpenTimeoutSeconds()))
        .build();
  }

  public void authenticate() throws Exception {
    int attempts = 0;
    Exception lastException = null;
    
    while (attempts < _config.getMaxRetries()) {
      try {
        attempts++;
        _logger.debug("Vault authentication attempt {} of {}", attempts, _config.getMaxRetries());
        
        if ("token".equals(_config.getAuthMethod())) {
          _currentToken = _config.getToken();
          validateToken();
        } else if ("approle".equals(_config.getAuthMethod())) {
          authenticateWithAppRole();
        } else {
          throw new IllegalArgumentException("Unsupported auth method: " + _config.getAuthMethod());
        }
        
        _logger.info("Vault authentication successful");
        return;
        
      } catch (Exception e) {
        lastException = e;
        _logger.warn("Vault authentication attempt {} failed: {}", attempts, VaultUtil.maskSensitiveData(e.getMessage()));
        
        if (attempts < _config.getMaxRetries()) {
          try {
            Thread.sleep(_config.getRetryIntervalMs() * attempts); // Exponential backoff
          } catch (InterruptedException ie) {
            Thread.currentThread().interrupt();
            throw new RuntimeException("Authentication interrupted", ie);
          }
        }
      }
    }
    
    throw new RuntimeException("Vault authentication failed after " + _config.getMaxRetries() + " attempts", lastException);
  }

  private void validateToken() throws Exception {
    if (_currentToken == null || _currentToken.isEmpty()) {
      throw new IllegalStateException("Vault token is null or empty");
    }
    
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(_config.getUrl() + "/v1/auth/token/lookup-self"))
        .header("X-Vault-Token", _currentToken)
        .header("Content-Type", "application/json")
        .timeout(Duration.ofSeconds(_config.getReadTimeoutSeconds()))
        .GET()
        .build();

    HttpResponse<String> response = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    
    if (response.statusCode() != 200) {
      throw new RuntimeException("Token validation failed with status: " + response.statusCode());
    }
    
    _logger.debug("Token validation successful");
  }

  private void authenticateWithAppRole() throws Exception {
    String requestBody = String.format("{\"role_id\":\"%s\",\"secret_id\":\"%s\"}", 
        _config.getRoleId(), _config.getSecretId());
    
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(_config.getUrl() + "/v1/auth/approle/login"))
        .header("Content-Type", "application/json")
        .timeout(Duration.ofSeconds(_config.getReadTimeoutSeconds()))
        .POST(HttpRequest.BodyPublishers.ofString(requestBody))
        .build();

    HttpResponse<String> response = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    
    if (response.statusCode() != 200) {
      throw new RuntimeException("AppRole authentication failed with status: " + response.statusCode());
    }

    VaultResponse vaultResponse = VaultResponse.parseResponse(response.body());
    _currentToken = vaultResponse.getClientToken();
    
    if (_currentToken == null || _currentToken.isEmpty()) {
      throw new RuntimeException("Failed to obtain token from AppRole authentication");
    }
    
    _logger.debug("AppRole authentication successful");
  }

  public String getToken() {
    return _currentToken;
  }

  public void close() {
    _currentToken = null;
  }
}
/* END GENAI@CLINE */
