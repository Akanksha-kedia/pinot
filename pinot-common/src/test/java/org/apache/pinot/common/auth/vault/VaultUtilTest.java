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

import org.testng.Assert;
import org.testng.annotations.Test;

/**
 * Test cases for VaultUtil security utilities
 */
public class VaultUtilTest {

  @Test
  public void testMaskSensitiveData() {
    String message = "Token: hvs.12345abcde, secret_id=mysecret, password=mypassword";
    String masked = VaultUtil.maskSensitiveData(message);
    Assert.assertTrue(masked.contains("hvs.***"));
    Assert.assertTrue(masked.contains("secret_id=***"));
    Assert.assertTrue(masked.contains("password=***"));
    Assert.assertFalse(masked.contains("12345abcde"));
    Assert.assertFalse(masked.contains("mysecret"));
    Assert.assertFalse(masked.contains("mypassword"));
  }

  @Test
  public void testValidVaultUrl() {
    Assert.assertTrue(VaultUtil.isValidVaultUrl("https://vault.example.com"));
    Assert.assertTrue(VaultUtil.isValidVaultUrl("http://localhost:8200"));
    Assert.assertTrue(VaultUtil.isValidVaultUrl("https://vault.company.com:8200"));
    Assert.assertFalse(VaultUtil.isValidVaultUrl("invalid-url"));
    Assert.assertFalse(VaultUtil.isValidVaultUrl(""));
    Assert.assertFalse(VaultUtil.isValidVaultUrl(null));
  }

  @Test
  public void testValidVaultToken() {
    Assert.assertTrue(VaultUtil.isValidVaultToken("hvs.12345abcde"));
    Assert.assertTrue(VaultUtil.isValidVaultToken("root"));
    Assert.assertTrue(VaultUtil.isValidVaultToken("very-long-token-string-with-more-than-20-chars"));
    Assert.assertFalse(VaultUtil.isValidVaultToken("short"));
    Assert.assertFalse(VaultUtil.isValidVaultToken(""));
    Assert.assertFalse(VaultUtil.isValidVaultToken(null));
  }

  @Test
  public void testValidAuthMethod() {
    Assert.assertTrue(VaultUtil.isValidAuthMethod("token"));
    Assert.assertTrue(VaultUtil.isValidAuthMethod("approle"));
    Assert.assertTrue(VaultUtil.isValidAuthMethod("TOKEN"));
    Assert.assertTrue(VaultUtil.isValidAuthMethod("APPROLE"));
    Assert.assertFalse(VaultUtil.isValidAuthMethod("invalid"));
    Assert.assertFalse(VaultUtil.isValidAuthMethod(""));
    Assert.assertFalse(VaultUtil.isValidAuthMethod(null));
  }

  @Test
  public void testSanitizeForLog() {
    Assert.assertEquals(VaultUtil.sanitizeForLog("token", "secret-value"), "***");
    Assert.assertEquals(VaultUtil.sanitizeForLog("secret", "secret-value"), "***");
    Assert.assertEquals(VaultUtil.sanitizeForLog("password", "secret-value"), "***");
    Assert.assertEquals(VaultUtil.sanitizeForLog("url", "https://example.com"), "https://example.com");
    Assert.assertEquals(VaultUtil.sanitizeForLog("timeout", "30"), "30");
    Assert.assertNull(VaultUtil.sanitizeForLog("key", null));
  }

  @Test
  public void testCreateSecureConfigString() {
    VaultConfig config = new VaultConfig();
    config.setUrl("https://vault.example.com");
    config.setToken("secret-token");
    config.setAuthMethod("token");
    config.setRoleId("test-role");
    config.setSecretId("secret-id");

    String configString = VaultUtil.createSecureConfigString(config);
    Assert.assertTrue(configString.contains("https://vault.example.com"));
    Assert.assertTrue(configString.contains("token='***'"));
    Assert.assertTrue(configString.contains("secretId='***'"));
    Assert.assertFalse(configString.contains("secret-token"));
    Assert.assertFalse(configString.contains("secret-id"));
  }
}
