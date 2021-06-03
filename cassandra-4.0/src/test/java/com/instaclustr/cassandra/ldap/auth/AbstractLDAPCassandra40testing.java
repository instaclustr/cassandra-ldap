/*
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
package com.instaclustr.cassandra.ldap.auth;

import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_MINUTES;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;
import static org.testng.Assert.fail;

import java.io.Closeable;
import java.net.InetAddress;
import java.net.InetSocketAddress;
import java.net.Socket;
import java.net.SocketException;

import com.datastax.oss.driver.api.core.CqlSession;
import com.datastax.oss.driver.api.core.CqlSessionBuilder;
import com.datastax.oss.driver.api.core.cql.ResultSet;
import com.github.nosan.embedded.cassandra.Cassandra;
import com.github.nosan.embedded.cassandra.CassandraBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractLDAPCassandra40testing {

    private static final Logger logger = LoggerFactory.getLogger(AbstractLDAPCassandra40testing.class);

    protected void testLDAPinternal() throws Exception {
        try (final CassandraClusterContext context = getClusterContext(true)) {

            context.start();

            context.execute(context.firstNode,
                            "cassandra",
                            "cassandra",
                            "ALTER KEYSPACE system_auth WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 1, 'datacenter2':1};", "datacenter1", false);

            Thread.sleep(10000);

            logger.info("[first node]: login via cassandra");
            context.execute(context.firstNode, "cassandra", "cassandra", "select * from system_auth.roles", "datacenter1", true);
            logger.info("[first node]: login stefan");
            context.execute(context.firstNode, "stefan", "stefan", "select * from system.local", "datacenter1", true);

            logger.info("[second node]: login cassandra");
            context.execute(context.secondNode, "cassandra", "cassandra", "select * from system_auth.roles", "datacenter2", true);
            logger.info("[second node]: login stefan");
            context.execute(context.secondNode, "stefan", "stefan", "select * from system.local", "datacenter2", true);
        } catch (final Exception ex) {
            fail("Exception occurred!", ex);
        }
    }

    protected abstract CassandraBuilder configure(boolean ldap, String node);

    private CassandraClusterContext getClusterContext(boolean ldapEnabled) {
        CassandraClusterContext cassandraClusterContext = new CassandraClusterContext();
        cassandraClusterContext.firstNode = configure(ldapEnabled, "first").build();
        cassandraClusterContext.secondNode = configure(ldapEnabled, "second").build();
        return cassandraClusterContext;
    }

    private static class CassandraClusterContext implements Closeable {

        public Cassandra firstNode;
        public Cassandra secondNode;

        public void start() {
            firstNode.start();
            waitForOpenPort("127.0.0.1", 9042);
            secondNode.start();
            waitForOpenPort("127.0.0.2", 9042);
        }

        @Override
        public void close() {
            if (firstNode != null) {
                firstNode.stop();
                waitForClosedPort("127.0.0.1", 9042);
                firstNode = null;
            }

            if (secondNode != null) {
                secondNode.stop();
                waitForClosedPort("127.0.0.2", 9042);
                secondNode = null;
            }
        }

        public synchronized void execute(Cassandra node,
                                         String username,
                                         String password,
                                         String query,
                                         String dc,
                                         boolean check) {
            execute(node.getSettings().getAddress(), username, password, query, dc, check);
        }

        public synchronized void execute(InetAddress point,
                                         String username,
                                         String password,
                                         String query,
                                         String dc,
                                         boolean check) {
            try (final CqlSession session = new CqlSessionBuilder()
                .addContactPoint(new InetSocketAddress(point, 9042))
                .withLocalDatacenter(dc)
                .withAuthCredentials(username, password)
                .build()) {
                final ResultSet execute = session.execute(query);

                if (check) {
                    assertNotNull(execute);
                    assertFalse(execute.all().isEmpty());
                    assertTrue(execute.isFullyFetched());
                }
            } catch (final Exception ex) {
                fail("Failed to execute a request!", ex);
            }
        }

        public void waitForClosedPort(String hostname, int port) {
            await().timeout(FIVE_MINUTES).until(() ->
                                                {
                                                    try {
                                                        (new Socket(hostname, port)).close();
                                                        return false;
                                                    } catch (SocketException e) {
                                                        return true;
                                                    }
                                                });
        }

        public void waitForOpenPort(String hostname, int port) {
            await().timeout(FIVE_MINUTES).until(() ->
                                                {
                                                    try {
                                                        (new Socket(hostname, port)).close();
                                                        return true;
                                                    } catch (SocketException e) {
                                                        return false;
                                                    }
                                                });
        }
    }
}
