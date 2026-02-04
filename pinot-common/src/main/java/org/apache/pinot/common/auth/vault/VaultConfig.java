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

/* START GENAI@CLINE */
/**
 * Configuration class for Vault authentication
 */
public class VaultConfig {
  private String url;
  private String token;
  private String authMethod = "token";
  private String namespace;
  private String path;
  private String secretPath;
  private String roleId;
  private String secretId;
  private long tokenRefreshInterval = 3600000L; // 1 hour
  private int maxRetries = 3;
  private long retryIntervalMs = 1000L;
  private int openTimeoutSeconds = 5;
  private int readTimeoutSeconds = 20;

  public String getUrl() { return url; }
  public void setUrl(String url) { this.url = url; }

  public String getToken() { return token; }
  public void setToken(String token) { this.token = token; }

  public String getAuthMethod() { return authMethod; }
  public void setAuthMethod(String authMethod) { this.authMethod = authMethod; }

  public String getNamespace() { return namespace; }
  public void setNamespace(String namespace) { this.namespace = namespace; }

  public String getPath() { return path; }
  public void setPath(String path) { this.path = path; }

  public String getSecretPath() { return secretPath; }
  public void setSecretPath(String secretPath) { this.secretPath = secretPath; }

  public String getRoleId() { return roleId; }
  public void setRoleId(String roleId) { this.roleId = roleId; }

  public String getSecretId() { return secretId; }
  public void setSecretId(String secretId) { this.secretId = secretId; }

  public long getTokenRefreshInterval() { return tokenRefreshInterval; }
  public void setTokenRefreshInterval(long tokenRefreshInterval) { 
    this.tokenRefreshInterval = tokenRefreshInterval; 
  }

  public int getMaxRetries() { return maxRetries; }
  public void setMaxRetries(int maxRetries) { this.maxRetries = maxRetries; }

  public long getRetryIntervalMs() { return retryIntervalMs; }
  public void setRetryIntervalMs(long retryIntervalMs) { this.retryIntervalMs = retryIntervalMs; }

  public int getOpenTimeoutSeconds() { return openTimeoutSeconds; }
  public void setOpenTimeoutSeconds(int openTimeoutSeconds) { 
    this.openTimeoutSeconds = openTimeoutSeconds; 
  }

  public int getReadTimeoutSeconds() { return readTimeoutSeconds; }
  public void setReadTimeoutSeconds(int readTimeoutSeconds) { 
    this.readTimeoutSeconds = readTimeoutSeconds; 
  }
}
/* END GENAI@CLINE */
