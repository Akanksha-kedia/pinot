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

import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Health checker for Vault connectivity and authentication status
 */
public class VaultHealthChecker {
  private static final Logger _logger = LoggerFactory.getLogger(VaultHealthChecker.class);
  
  private final VaultConfig _config;
  private final HttpClient _httpClient;

  public VaultHealthChecker(VaultConfig config) {
    _config = config;
    _httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(config.getOpenTimeoutSeconds()))
        .build();
  }

  public boolean isVaultHealthy() {
    try {
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(_config.getUrl() + "/v1/sys/health"))
          .header("Content-Type", "application/json")
          .timeout(Duration.ofSeconds(_config.getReadTimeoutSeconds()))
          .GET()
          .build();

      HttpResponse<String> response = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      return response.statusCode() == 200;
    } catch (Exception e) {
      _logger.warn("Vault health check failed: {}", VaultUtil.maskSensitiveData(e.getMessage()));
      return false;
    }
  }

  public boolean isTokenValid(String token) {
    if (token == null || token.isEmpty()) {
      return false;
    }

    try {
      HttpRequest request = HttpRequest.newBuilder()
          .uri(URI.create(_config.getUrl() + "/v1/auth/token/lookup-self"))
          .header("X-Vault-Token", token)
          .header("Content-Type", "application/json")
          .timeout(Duration.ofSeconds(_config.getReadTimeoutSeconds()))
          .GET()
          .build();

      HttpResponse<String> response = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
      return response.statusCode() == 200;
    } catch (Exception e) {
      _logger.debug("Token validation failed: {}", VaultUtil.maskSensitiveData(e.getMessage()));
      return false;
    }
  }

  public HealthStatus getOverallHealth() {
    boolean vaultHealthy = isVaultHealthy();
    boolean tokenValid = false;
    
    try {
      VaultAuth vaultAuth = new VaultAuth(_config);
      vaultAuth.authenticate();
      tokenValid = isTokenValid(vaultAuth.getToken());
    } catch (Exception e) {
      _logger.debug("Authentication health check failed", e);
    }

    return new HealthStatus(vaultHealthy, tokenValid);
  }

  public static class HealthStatus {
    private final boolean vaultHealthy;
    private final boolean tokenValid;

    public HealthStatus(boolean vaultHealthy, boolean tokenValid) {
      this.vaultHealthy = vaultHealthy;
      this.tokenValid = tokenValid;
    }

    public boolean isVaultHealthy() { return vaultHealthy; }
    public boolean isTokenValid() { return tokenValid; }
    public boolean isOverallHealthy() { return vaultHealthy && tokenValid; }
    
    @Override
    public String toString() {
      return String.format("HealthStatus{vault=%s, token=%s}", vaultHealthy, tokenValid);
    }
  }
}
