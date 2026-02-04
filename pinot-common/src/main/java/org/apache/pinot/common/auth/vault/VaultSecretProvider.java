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

import com.fasterxml.jackson.databind.JsonNode;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.net.URI;
import java.time.Duration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Provides secret retrieval functionality from Vault
 */
public class VaultSecretProvider {
  private static final Logger _logger = LoggerFactory.getLogger(VaultSecretProvider.class);
  
  private final VaultConfig _config;
  private final VaultAuth _vaultAuth;
  private final HttpClient _httpClient;

  public VaultSecretProvider(VaultConfig config, VaultAuth vaultAuth) {
    _config = config;
    _vaultAuth = vaultAuth;
    _httpClient = HttpClient.newBuilder()
        .connectTimeout(Duration.ofSeconds(config.getOpenTimeoutSeconds()))
        .build();
  }

  public String getSecret(String path, String key) throws Exception {
    String token = _vaultAuth.getToken();
    if (token == null) {
      throw new IllegalStateException("No valid Vault token available");
    }

    String secretPath = buildSecretPath(path);
    HttpRequest request = HttpRequest.newBuilder()
        .uri(URI.create(_config.getUrl() + "/v1/" + secretPath))
        .header("X-Vault-Token", token)
        .header("Content-Type", "application/json")
        .timeout(Duration.ofSeconds(_config.getReadTimeoutSeconds()))
        .GET()
        .build();

    HttpResponse<String> response = _httpClient.send(request, HttpResponse.BodyHandlers.ofString());
    
    if (response.statusCode() != 200) {
      throw new RuntimeException("Failed to retrieve secret from path: " + path + 
          ", status: " + response.statusCode());
    }

    VaultResponse vaultResponse = VaultResponse.parseResponse(response.body());
    JsonNode data = vaultResponse.getData();
    
    if (data == null) {
      throw new RuntimeException("No data found in Vault response for path: " + path);
    }

    JsonNode secretValue = data.get(key);
    if (secretValue == null) {
      throw new RuntimeException("Key '" + key + "' not found in secret at path: " + path);
    }

    return secretValue.asText();
  }

  private String buildSecretPath(String path) {
    if (path.startsWith("/")) {
      path = path.substring(1);
    }
    
    if (_config.getSecretPath() != null && !_config.getSecretPath().isEmpty()) {
      return _config.getSecretPath() + "/" + path;
    }
    
    return path;
  }

  public boolean pathExists(String path) {
    try {
      getSecret(path, "dummy");
      return true;
    } catch (Exception e) {
      _logger.debug("Path does not exist or is inaccessible: {}", path);
      return false;
    }
  }
}
