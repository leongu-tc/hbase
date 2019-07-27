/**
 *
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
package org.apache.hadoop.hbase.client;

import java.io.IOException;
import java.lang.reflect.Constructor;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;
import java.util.concurrent.ExecutorService;

import org.apache.commons.lang.StringUtils;
import org.apache.hadoop.hbase.classification.InterfaceAudience;
import org.apache.hadoop.hbase.classification.InterfaceStability;
import org.apache.hadoop.conf.Configuration;
import org.apache.hadoop.hbase.HBaseConfiguration;
import org.apache.hadoop.hbase.security.User;
import org.apache.hadoop.hbase.security.UserProvider;
import org.apache.hadoop.security.UserGroupInformation;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * A non-instantiable class that manages creation of {@link Connection}s.
 * Managing the lifecycle of the {@link Connection}s to the cluster is the responsibility of
 * the caller.
 * From a {@link Connection}, {@link Table} implementations are retrieved
 * with {@link Connection#getTable(TableName)}. Example:
 * <pre>
 * Connection connection = ConnectionFactory.createConnection(config);
 * Table table = connection.getTable(TableName.valueOf("table1"));
 * try {
 *   // Use the table as needed, for a single operation and a single thread
 * } finally {
 *   table.close();
 *   connection.close();
 * }
 * </pre>
 *
 * Similarly, {@link Connection} also returns {@link Admin} and {@link RegionLocator}
 * implementations.
 *
 * This class replaces {@link HConnectionManager}, which is now deprecated.
 * @see Connection
 * @since 0.99.0
 */
@InterfaceAudience.Public
@InterfaceStability.Evolving
public class ConnectionFactory {
  private static final Logger LOG = LoggerFactory.getLogger(ConnectionFactory.class);
  public static Map<String, String> sdpAuthKeys = new HashMap<String, String>();
  
  static{
    sdpAuthKeys.put("hbase_security_authentication_sdp_publickey", ConnectionConfiguration.HBASE_AUTHENTICATION_SDP_PUBLICKEY);
    sdpAuthKeys.put("hbase_security_authentication_sdp_privatekey", ConnectionConfiguration.HBASE_AUTHENTICATION_SDP_PRIVATEKEY);
  }

  /** No public c.tors */
  protected ConnectionFactory() {
  }

  /**
   * Create a new Connection instance using default HBaseConfiguration. Connection
   * encapsulates all housekeeping for a connection to the cluster. All tables and interfaces
   * created from returned connection share zookeeper connection, meta cache, and connections
   * to region servers and masters.
   * <br>
   * The caller is responsible for calling {@link Connection#close()} on the returned
   * connection instance.
   *
   * Typical usage:
   * <pre>
   * Connection connection = ConnectionFactory.createConnection();
   * Table table = connection.getTable(TableName.valueOf("mytable"));
   * try {
   *   table.get(...);
   *   ...
   * } finally {
   *   table.close();
   *   connection.close();
   * }
   * </pre>
   *
   * @return Connection object for <code>conf</code>
   */
  public static Connection createConnection() throws IOException {
    return createConnection(HBaseConfiguration.create(), null, null);
  }

  /**
   * Create a new Connection instance using the passed <code>conf</code> instance. Connection
   * encapsulates all housekeeping for a connection to the cluster. All tables and interfaces
   * created from returned connection share zookeeper connection, meta cache, and connections
   * to region servers and masters.
   * <br>
   * The caller is responsible for calling {@link Connection#close()} on the returned
   * connection instance.
   *
   * Typical usage:
   * <pre>
   * Connection connection = ConnectionFactory.createConnection(conf);
   * Table table = connection.getTable(TableName.valueOf("mytable"));
   * try {
   *   table.get(...);
   *   ...
   * } finally {
   *   table.close();
   *   connection.close();
   * }
   * </pre>
   *
   * @param conf configuration
   * @return Connection object for <code>conf</code>
   */
  public static Connection createConnection(Configuration conf) throws IOException {
    return createConnection(conf, null, null);
  }

  /**
   * Create a new Connection instance using the passed <code>conf</code> instance. Connection
   * encapsulates all housekeeping for a connection to the cluster. All tables and interfaces
   * created from returned connection share zookeeper connection, meta cache, and connections
   * to region servers and masters.
   * <br>
   * The caller is responsible for calling {@link Connection#close()} on the returned
   * connection instance.
   *
   * Typical usage:
   * <pre>
   * Connection connection = ConnectionFactory.createConnection(conf);
   * Table table = connection.getTable(TableName.valueOf("mytable"));
   * try {
   *   table.get(...);
   *   ...
   * } finally {
   *   table.close();
   *   connection.close();
   * }
   * </pre>
   *
   * @param conf configuration
   * @param pool the thread pool to use for batch operations
   * @return Connection object for <code>conf</code>
   */
  public static Connection createConnection(Configuration conf, ExecutorService pool)
      throws IOException {
    return createConnection(conf, pool, null);
  }

  /**
   * Create a new Connection instance using the passed <code>conf</code> instance. Connection
   * encapsulates all housekeeping for a connection to the cluster. All tables and interfaces
   * created from returned connection share zookeeper connection, meta cache, and connections
   * to region servers and masters.
   * <br>
   * The caller is responsible for calling {@link Connection#close()} on the returned
   * connection instance.
   *
   * Typical usage:
   * <pre>
   * Connection connection = ConnectionFactory.createConnection(conf);
   * Table table = connection.getTable(TableName.valueOf("table1"));
   * try {
   *   table.get(...);
   *   ...
   * } finally {
   *   table.close();
   *   connection.close();
   * }
   * </pre>
   *
   * @param conf configuration
   * @param user the user the connection is for
   * @return Connection object for <code>conf</code>
   */
  public static Connection createConnection(Configuration conf, User user)
  throws IOException {
    return createConnection(conf, null, user);
  }

  /**
   * Create a new Connection instance using the passed <code>conf</code> instance. Connection
   * encapsulates all housekeeping for a connection to the cluster. All tables and interfaces
   * created from returned connection share zookeeper connection, meta cache, and connections
   * to region servers and masters.
   * <br>
   * The caller is responsible for calling {@link Connection#close()} on the returned
   * connection instance.
   *
   * Typical usage:
   * <pre>
   * Connection connection = ConnectionFactory.createConnection(conf);
   * Table table = connection.getTable(TableName.valueOf("table1"));
   * try {
   *   table.get(...);
   *   ...
   * } finally {
   *   table.close();
   *   connection.close();
   * }
   * </pre>
   *
   * @param conf configuration
   * @param user the user the connection is for
   * @param pool the thread pool to use for batch operations
   * @return Connection object for <code>conf</code>
   */
  public static Connection createConnection(Configuration conf, ExecutorService pool, User user)
  throws IOException {
//    if (user == null) {
//      UserProvider provider = UserProvider.instantiate(conf);
//      user = provider.getCurrent();
//    }
    
    if (user == null) {
      UserProvider provider = UserProvider.instantiate(conf);
      try {
        user = provider.getCurrent();
      } catch (Exception e) {
        LOG.warn("Failed to get current user from configuration.", e);
        user = null;
      }
      
      if (user == null) {
        user = getCurrentUser();
      }
    }

    return createConnection(conf, false, pool, user);
  }
  
  private static User getCurrentUser(){
    String currentUserName = System.getProperty("user.name");
    if(StringUtils.isBlank(currentUserName)){
      LOG.warn("The current user name is blank, and set it to hbase user.");
      currentUserName = "hbase";
    }
    
    return new User.SecureHadoopUser(UserGroupInformation.createRemoteUser(currentUserName));
  }
  
  public static void loadSdpAuthParams(Configuration conf){
    LOG.debug("start load auth param from env or sys properties...");
    Map<String, String> envs = System.getenv();
    Properties sysProps = System.getProperties();
    for( String key : sdpAuthKeys.keySet() ){
      if( envs.get(key) != null ){
        conf.set(sdpAuthKeys.get(key),envs.get(key));
        LOG.debug("loaded hbase authentication parameter from evn. key:{} value:{}",key,envs.get(key));
      }else if( sysProps.get(key) != null ){
        conf.set(sdpAuthKeys.get(key),(String)sysProps.get(key));
        LOG.debug("loaded hbase authentication parameter from conf. key:{} value:{}",key,(String)sysProps.get(key));
      }    
    }
  }

  static Connection createConnection(final Configuration conf, final boolean managed,
      final ExecutorService pool, final User user)
  throws IOException {
    loadSdpAuthParams(conf);
    
    String className = conf.get(HConnection.HBASE_CLIENT_CONNECTION_IMPL,
      ConnectionManager.HConnectionImplementation.class.getName());
    Class<?> clazz = null;
    try {
      clazz = Class.forName(className);
    } catch (ClassNotFoundException e) {
      throw new IOException(e);
    }
    try {
      // Default HCM#HCI is not accessible; make it so before invoking.
      Constructor<?> constructor =
        clazz.getDeclaredConstructor(Configuration.class,
          boolean.class, ExecutorService.class, User.class);
      constructor.setAccessible(true);
      return (Connection) constructor.newInstance(conf, managed, pool, user);
    } catch (Exception e) {
      throw new IOException(e);
    }
  }
}
