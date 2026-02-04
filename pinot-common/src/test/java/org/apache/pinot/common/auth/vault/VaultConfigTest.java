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
 * Test cases for VaultConfig functionality
 */
public class VaultConfigTest {

  @Test
  public void testDefaultValues() {
    VaultConfig config = new VaultConfig();
    Assert.assertEquals(config.getAuthMethod(), "token");
    Assert.assertEquals(config.getTokenRefreshInterval(), 3600000L);
    Assert.assertEquals(config.getMaxRetries(), 3);
    Assert.assertEquals(config.getRetryIntervalMs(), 1000L);
    Assert.assertEquals(config.getOpenTimeoutSeconds(), 5);
    Assert.assertEquals(config.getReadTimeoutSeconds(), 20);
  }

  @Test
  public void testConfigurationSetters() {
    VaultConfig config = new VaultConfig();
    config.setUrl("https://vault.example.com");
    config.setToken("test-token");
    config.setAuthMethod("approle");
    config.setNamespace("test-namespace");
    config.setPath("secret/data");
    config.setSecretPath("kv");
    config.setRoleId("test-role-id");
    config.setSecretId("test-secret-id");
    config.setTokenRefreshInterval(7200000L);
    config.setMaxRetries(5);
    config.setRetryIntervalMs(2000L);
    config.setOpenTimeoutSeconds(10);
    config.setReadTimeoutSeconds(30);

    Assert.assertEquals(config.getUrl(), "https://vault.example.com");
    Assert.assertEquals(config.getToken(), "test-token");
    Assert.assertEquals(config.getAuthMethod(), "approle");
    Assert.assertEquals(config.getNamespace(), "test-namespace");
    Assert.assertEquals(config.getPath(), "secret/data");
    Assert.assertEquals(config.getSecretPath(), "kv");
    Assert.assertEquals(config.getRoleId(), "test-role-id");
    Assert.assertEquals(config.getSecretId(), "test-secret-id");
    Assert.assertEquals(config.getTokenRefreshInterval(), 7200000L);
    Assert.assertEquals(config.getMaxRetries(), 5);
    Assert.assertEquals(config.getRetryIntervalMs(), 2000L);
    Assert.assertEquals(config.getOpenTimeoutSeconds(), 10);
    Assert.assertEquals(config.getReadTimeoutSeconds(), 30);
  }

  @Test
  public void testNullValues() {
    VaultConfig config = new VaultConfig();
    Assert.assertNull(config.getUrl());
    Assert.assertNull(config.getToken());
    Assert.assertNull(config.getNamespace());
    Assert.assertNull(config.getPath());
    Assert.assertNull(config.getSecretPath());
    Assert.assertNull(config.getRoleId());
    Assert.assertNull(config.getSecretId());
  }
}
