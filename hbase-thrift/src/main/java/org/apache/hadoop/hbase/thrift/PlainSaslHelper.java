/**
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.hadoop.hbase.thrift;

import java.io.IOException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.NameCallback;
import javax.security.auth.callback.PasswordCallback;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.security.sasl.AuthenticationException;
import javax.security.sasl.AuthorizeCallback;
import javax.security.sasl.Sasl;
import javax.security.sasl.SaslException;
import org.apache.thrift.transport.TSaslClientTransport;
import org.apache.thrift.transport.TSaslServerTransport;
import org.apache.thrift.transport.TTransport;
import org.apache.thrift.transport.TTransportFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;


public final class PlainSaslHelper {
  private static final Log LOG = LogFactory.getLog(ThriftServer.class);
  private static final String SDP_PLAIN = "PLAIN";

  // Register Plain SASL server provider
  static {
    Security.addProvider(new SdpPlainSaslServer.SdpSaslServerProvider());
  }

  public static TTransportFactory getPlainTransportFactory(String authTypeStr)
     {
    TSaslServerTransport.Factory saslFactory = new TSaslServerTransport.Factory();
      Map<String, String> properties = new HashMap<String, String>();
      properties.put(Sasl.QOP, "auth");
      properties.put(Sasl.SERVER_AUTH, "true");
      saslFactory.addServerDefinition(SDP_PLAIN, authTypeStr, null, properties,
        null);
    return saslFactory;
  }

  public static TTransport getPlainTransport(String username, String password,
    TTransport underlyingTransport) throws SaslException {
    Map<String, String> properties = new HashMap<String, String>();
    properties.put(Sasl.QOP, "auth");
    properties.put(Sasl.SERVER_AUTH, "true");
    return new TSaslClientTransport(SDP_PLAIN, null, null, null, properties,
      new PlainCallbackHandler(username, password), underlyingTransport);
  }

  private PlainSaslHelper() {
    throw new UnsupportedOperationException("Can't initialize class");
  }

  public static final class PlainServerCallbackHandler implements CallbackHandler {

//    private final AuthMethods authMethod;

    PlainServerCallbackHandler(String authMethodStr) throws AuthenticationException {
//      authMethod = AuthMethods.getValidAuthMethod(authMethodStr);
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      String username = null;
      AuthorizeCallback ac = null;

      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          NameCallback nc = (NameCallback) callback;
          username = nc.getName();
        } else if (callback instanceof PasswordCallback) {
          PasswordCallback pc = (PasswordCallback) callback;
        } else if (callback instanceof AuthorizeCallback) {
          ac = (AuthorizeCallback) callback;
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
      
      if (ac != null) {
        ac.setAuthorized(true);
        ac.setAuthorizedID(username);
      }
    }
  }

  public static class PlainCallbackHandler implements CallbackHandler {

    private final String username;
    private final String password;

    public PlainCallbackHandler(String username, String password) {
      this.username = username;
      this.password = password;
    }

    @Override
    public void handle(Callback[] callbacks) throws IOException, UnsupportedCallbackException {
      for (Callback callback : callbacks) {
        if (callback instanceof NameCallback) {
          NameCallback nameCallback = (NameCallback) callback;
          nameCallback.setName(username);
        } else if (callback instanceof PasswordCallback) {
          PasswordCallback passCallback = (PasswordCallback) callback;
          passCallback.setPassword(password.toCharArray());
        } else {
          throw new UnsupportedCallbackException(callback);
        }
      }
    }
  }
}
