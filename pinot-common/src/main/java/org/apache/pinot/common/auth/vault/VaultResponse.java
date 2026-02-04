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
import com.fasterxml.jackson.databind.ObjectMapper;
import java.io.IOException;

/* START GENAI@CLINE */
/**
 * Response parsing and error handling for Vault operations
 */
public class VaultResponse {
  private static final ObjectMapper OBJECT_MAPPER = new ObjectMapper();
  
  private final JsonNode _responseData;
  private final String _clientToken;
  private final Long _leaseDuration;
  private final boolean _renewable;

  private VaultResponse(JsonNode responseData, String clientToken, Long leaseDuration, boolean renewable) {
    _responseData = responseData;
    _clientToken = clientToken;
    _leaseDuration = leaseDuration;
    _renewable = renewable;
  }

  public static VaultResponse parseResponse(String jsonResponse) throws IOException {
    JsonNode rootNode = OBJECT_MAPPER.readTree(jsonResponse);
    
    JsonNode authNode = rootNode.get("auth");
    String clientToken = null;
    Long leaseDuration = null;
    boolean renewable = false;
    
    if (authNode != null && !authNode.isNull()) {
      JsonNode tokenNode = authNode.get("client_token");
      if (tokenNode != null && !tokenNode.isNull()) {
        clientToken = tokenNode.asText();
      }
      
      JsonNode leaseNode = authNode.get("lease_duration");
      if (leaseNode != null && !leaseNode.isNull()) {
        leaseDuration = leaseNode.asLong();
      }
      
      JsonNode renewableNode = authNode.get("renewable");
      if (renewableNode != null && !renewableNode.isNull()) {
        renewable = renewableNode.asBoolean();
      }
    }
    
    return new VaultResponse(rootNode, clientToken, leaseDuration, renewable);
  }

  public String getClientToken() {
    return _clientToken;
  }

  public Long getLeaseDuration() {
    return _leaseDuration;
  }

  public boolean isRenewable() {
    return _renewable;
  }

  public JsonNode getData() {
    return _responseData.get("data");
  }

  public JsonNode getResponseData() {
    return _responseData;
  }

  public boolean hasErrors() {
    JsonNode errorsNode = _responseData.get("errors");
    return errorsNode != null && errorsNode.isArray() && errorsNode.size() > 0;
  }

  public String getErrorMessage() {
    if (!hasErrors()) {
      return null;
    }
    
    JsonNode errorsNode = _responseData.get("errors");
    StringBuilder errorMessage = new StringBuilder();
    
    for (JsonNode error : errorsNode) {
      if (errorMessage.length() > 0) {
        errorMessage.append("; ");
      }
      errorMessage.append(error.asText());
    }
    
    return errorMessage.toString();
  }
}
/* END GENAI@CLINE */
