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

import java.util.concurrent.locks.ReentrantReadWriteLock;

/* START GENAI@CLINE */
/**
 * Thread-safe token caching system for Vault authentication
 */
public class VaultTokenCache {
  private final ReentrantReadWriteLock _lock = new ReentrantReadWriteLock();
  private volatile String _cachedToken;
  private volatile long _lastRefreshTime = 0;

  /**
   * Gets the cached token
   */
  public String getToken() {
    _lock.readLock().lock();
    try {
      return _cachedToken;
    } finally {
      _lock.readLock().unlock();
    }
  }

  /**
   * Sets the token in cache
   */
  public void setToken(String token) {
    _lock.writeLock().lock();
    try {
      _cachedToken = token;
      _lastRefreshTime = System.currentTimeMillis();
    } finally {
      _lock.writeLock().unlock();
    }
  }

  /**
   * Checks if token has expired based on refresh interval
   */
  public boolean isExpired(long refreshIntervalMs) {
    _lock.readLock().lock();
    try {
      if (_cachedToken == null || _lastRefreshTime == 0) {
        return true;
      }
      return (System.currentTimeMillis() - _lastRefreshTime) >= refreshIntervalMs;
    } finally {
      _lock.readLock().unlock();
    }
  }

  /**
   * Clears the cached token
   */
  public void clear() {
    _lock.writeLock().lock();
    try {
      _cachedToken = null;
      _lastRefreshTime = 0;
    } finally {
      _lock.writeLock().unlock();
    }
  }

  /**
   * Gets the last refresh timestamp
   */
  public long getLastRefreshTime() {
    _lock.readLock().lock();
    try {
      return _lastRefreshTime;
    } finally {
      _lock.readLock().unlock();
    }
  }
}
/* END GENAI@CLINE */
