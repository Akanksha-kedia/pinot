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

import java.util.regex.Pattern;

/* START GENAI@CLINE */
/**
 * Security utilities and validation methods for Vault operations
 */
public final class VaultUtil {
  private static final Pattern TOKEN_PATTERN = Pattern.compile("(hvs\\.[a-zA-Z0-9_-]+)");
  private static final Pattern SECRET_PATTERN = Pattern.compile("(secret[_\\-]?id[\"']?\\s*[=:]\\s*[\"']?)([^\"',\\s]+)");
  private static final Pattern PASSWORD_PATTERN = Pattern.compile("(password[\"']?\\s*[=:]\\s*[\"']?)([^\"',\\s]+)");
  
  private VaultUtil() {
    // Utility class
  }

  /**
   * Masks sensitive data in log messages for security
   */
  public static String maskSensitiveData(String message) {
    if (message == null || message.isEmpty()) {
      return message;
    }
    
    String masked = message;
    
    // Mask Vault tokens (hvs.xxxx format)
    masked = TOKEN_PATTERN.matcher(masked).replaceAll("hvs.***");
    
    // Mask secret_id values
    masked = SECRET_PATTERN.matcher(masked).replaceAll("$1***");
    
    // Mask password values
    masked = PASSWORD_PATTERN.matcher(masked).replaceAll("$1***");
    
    return masked;
  }

  /**
   * Validates Vault URL format
   */
  public static boolean isValidVaultUrl(String url) {
    if (url == null || url.trim().isEmpty()) {
      return false;
    }
    
    String normalizedUrl = url.trim().toLowerCase();
    return normalizedUrl.startsWith("http://") || normalizedUrl.startsWith("https://");
  }

  /**
   * Validates Vault token format (basic validation)
   */
  public static boolean isValidVaultToken(String token) {
    if (token == null || token.trim().isEmpty()) {
      return false;
    }
    
    String trimmed = token.trim();
    // Basic token format validation - Vault tokens typically start with 'hvs.' or are root tokens
    return trimmed.length() >= 8 && (trimmed.startsWith("hvs.") || trimmed.startsWith("root") || trimmed.length() >= 20);
  }

  /**
   * Validates authentication method
   */
  public static boolean isValidAuthMethod(String authMethod) {
    if (authMethod == null || authMethod.trim().isEmpty()) {
      return false;
    }
    
    String method = authMethod.trim().toLowerCase();
    return "token".equals(method) || "approle".equals(method);
  }

  /**
   * Sanitizes configuration values for logging
   */
  public static String sanitizeForLog(String key, String value) {
    if (value == null) {
      return null;
    }
    
    String lowerKey = key.toLowerCase();
    if (lowerKey.contains("token") || lowerKey.contains("secret") || lowerKey.contains("password")) {
      return "***";
    }
    
    return value;
  }

  /**
   * Creates a secure string representation of config for logging
   */
  public static String createSecureConfigString(VaultConfig config) {
    StringBuilder sb = new StringBuilder();
    sb.append("VaultConfig{");
    sb.append("url='").append(config.getUrl()).append("'");
    sb.append(", authMethod='").append(config.getAuthMethod()).append("'");
    sb.append(", namespace='").append(config.getNamespace()).append("'");
    sb.append(", path='").append(config.getPath()).append("'");
    sb.append(", secretPath='").append(config.getSecretPath()).append("'");
    sb.append(", token='***'");
    sb.append(", roleId='").append(sanitizeForLog("roleId", config.getRoleId())).append("'");
    sb.append(", secretId='***'");
    sb.append(", tokenRefreshInterval=").append(config.getTokenRefreshInterval());
    sb.append(", maxRetries=").append(config.getMaxRetries());
    sb.append(", retryIntervalMs=").append(config.getRetryIntervalMs());
    sb.append(", openTimeoutSeconds=").append(config.getOpenTimeoutSeconds());
    sb.append(", readTimeoutSeconds=").append(config.getReadTimeoutSeconds());
    sb.append("}");
    return sb.toString();
  }
}
/* END GENAI@CLINE */
