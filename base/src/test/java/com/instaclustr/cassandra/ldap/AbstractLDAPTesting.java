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
package com.instaclustr.cassandra.ldap;

import static org.awaitility.Awaitility.await;
import static org.testng.Assert.assertFalse;
import static org.testng.Assert.assertNotNull;
import static org.testng.Assert.assertTrue;

import java.io.IOException;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.List;
import java.util.Random;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.TimeUnit;

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.policies.DCAwareRoundRobinPolicy;
import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.github.nosan.embedded.cassandra.api.Cassandra;
import com.github.nosan.embedded.cassandra.api.Version;
import com.github.nosan.embedded.cassandra.artifact.Artifact;
import com.github.nosan.embedded.cassandra.commons.io.ClassPathResource;
import com.github.nosan.embedded.cassandra.commons.util.FileUtils;
import org.awaitility.Durations;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.testng.Assert;

public abstract class AbstractLDAPTesting
{

    private static final Logger logger = LoggerFactory.getLogger(AbstractLDAPTesting.class);

    public void testLDAPinternal() throws Exception
    {
        CassandraClusterContext context = null;

        List<Path> pluginJars = createPluginJars();

        try
        {
            copyJars(pluginJars, getCassandraArtifact().getDistribution().getDirectory());

            context = getClusterContext(true);

            configure(context.firstFactory);
            configure(context.secondFactory);

            context.start();

            context.execute(context.firstNode,
                            "cassandra",
                            "cassandra",
                            "ALTER KEYSPACE system_auth WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 1, 'datacenter2':1};", "datacenter1", false);

            context.execute(context.firstNode,
                            "cassandra",
                            "cassandra",
                            "CREATE ROLE stefan WITH PASSWORD = 'stefan' and LOGIN = true AND SUPERUSER = true",
                            "datacenter1",
                            false);

            Thread.sleep(10000);

            logger.info("first node ...");

            context.execute(context.firstNode, "cassandra", "cassandra", "select * from system_auth.roles", "datacenter1", true);
            context.execute(context.firstNode, "stefan", "stefan", "select * from system_auth.roles", "datacenter1", true);

            logger.info("second node ...");

            context.execute(context.secondNode, "cassandra", "cassandra", "select * from system_auth.roles", "datacenter2", true);
            context.execute(context.secondNode, "stefan", "stefan", "select * from system_auth.roles", "datacenter2", true);

            // ldap!

            logger.info("first node ...");

            context.execute(context.firstNode, "admin", "admin", "select * from system_auth.roles", "datacenter1", true);

            Thread.sleep(10000);

            // even we stop, we can still do stuff

            ExecutorService executorService = Executors.newFixedThreadPool(3);

            final CassandraClusterContext clusterContext = context;

            executorService.submit(new Runnable() {

                final Random r = new Random();

                @Override
                public void run() {
                    for (int i = 0; i < 20; i++)
                    {
                        clusterContext.execute(clusterContext.firstNode, "stefan", "stefan", "select * from system_auth.roles", "datacenter1", true);
                        try
                        {
                            Thread.sleep(r.nextInt(3000));
                        } catch (final Exception ex)
                        {

                        }
                    }

                    System.out.println("DONE");
                }
            });

            executorService.submit(new Runnable()
            {
                @Override
                public void run() {

                    final Random r = new Random();

                    for (int i = 0; i < 20; i++)
                    {
                        clusterContext.execute(clusterContext.firstNode, "admin", "admin", "select * from system_auth.roles", "datacenter1", true);
                        try
                        {
                            Thread.sleep(r.nextInt(3000));
                        } catch (final Exception ex)
                        {

                        }

                    }

                    System.out.println("DONE");
                }
            });

            executorService.shutdown();
            executorService.awaitTermination(1, TimeUnit.HOURS);

            logger.info("stopping second node");

            context.secondNode.stop();

            logger.info("first node ...");

            context.execute(context.firstNode, "stefan", "stefan", "select * from system_auth.roles", "datacenter1", true);
            context.execute(context.firstNode, "admin", "admin", "select * from system_auth.roles", "datacenter1", true);
        } catch (final Exception ex)
        {
            Assert.fail("Exception occurred!", ex);
        } finally
        {
            if (context != null)
            {
                context.stop();
            }

            if (pluginJars != null)
            {
                for (Path p : pluginJars)
                {
                    Files.deleteIfExists(getCassandraArtifact().getDistribution().getDirectory().resolve("lib").resolve(p.getFileName()));
                }
            }
        }
    }

    public abstract List<Path> createPluginJars() throws IOException;

    public Artifact getCassandraArtifact()
    {
        return Artifact.ofVersion(Version.of(getCassandraVersion()));
    }

    public String getCassandraVersion()
    {
        return System.getProperty("cassandra.version", "3.11.9");
    }

    public EmbeddedCassandraFactory defaultNodeFactory()
    {
        EmbeddedCassandraFactory factory = new EmbeddedCassandraFactory();
        factory.getJvmOptions().add("-Xmx1g");
        factory.getJvmOptions().add("-Xms1g");

        return factory;
    }

    public CassandraClusterContext getClusterContext(boolean ldapEnabled) throws Exception
    {
        return getClusterContext(null, null, ldapEnabled);
    }

    public CassandraClusterContext getClusterContext() throws Exception
    {
        return getClusterContext(null, null, false);
    }

    public CassandraClusterContext getClusterContext(Path firstDir, Path secondDir, boolean ldap) throws Exception
    {
        EmbeddedCassandraFactory firstFactory = defaultNodeFactory();

        Path firstWorkDir = firstDir == null ? Files.createTempDirectory(null) : firstDir;

        firstFactory.setArtifact(getCassandraArtifact());
        firstFactory.setRackConfig(new ClassPathResource("cassandra1-rackdc.properties"));
        firstFactory.setWorkingDirectory(firstWorkDir);

        if (!ldap)
        {
            firstFactory.setConfig(new ClassPathResource("first.yaml"));
        } else
        {
            firstFactory.setConfig(new ClassPathResource("first-ldap.yaml"));
        }

        firstFactory.setJmxLocalPort(7199);

        EmbeddedCassandraFactory secondFactory = defaultNodeFactory();

        Path secondWorkDir = secondDir == null ? Files.createTempDirectory(null) : secondDir;

        secondFactory.setArtifact(getCassandraArtifact());
        secondFactory.setRackConfig(new ClassPathResource("cassandra2-rackdc.properties"));
        secondFactory.setWorkingDirectory(secondWorkDir);

        if (!ldap)
        {
            secondFactory.setConfig(new ClassPathResource("second.yaml"));
        } else
        {
            secondFactory.setConfig(new ClassPathResource("second-ldap.yaml"));
        }

        secondFactory.setJmxLocalPort(7200);

        CassandraClusterContext cassandraClusterContext = new CassandraClusterContext();

        cassandraClusterContext.firstFactory = firstFactory;
        cassandraClusterContext.secondFactory = secondFactory;

        cassandraClusterContext.firstWorkDir = firstWorkDir;
        cassandraClusterContext.secondWorkDir = secondWorkDir;

        return cassandraClusterContext;
    }

    public abstract void configure(final EmbeddedCassandraFactory factory);

    public static class CassandraClusterContext
    {

        public static final Path firstNodePath = Paths.get("target/cassandra-1").toAbsolutePath();
        public static final Path secondNodePath = Paths.get("target/cassandra-2").toAbsolutePath();

        public Cassandra firstNode;
        public Cassandra secondNode;

        public EmbeddedCassandraFactory firstFactory;
        public EmbeddedCassandraFactory secondFactory;

        public Path firstWorkDir;
        public Path secondWorkDir;

        public void start()
        {
            firstNode = firstFactory.create();
            firstNode.start();
            waitForOpenPort("127.0.0.1", 9042);
            secondNode = secondFactory.create();
            secondNode.start();
            waitForOpenPort("127.0.0.2", 9042);
        }

        public void stop()
        {
            if (firstNode != null)
            {
                firstNode.stop();
                firstNode = null;
            }

            if (secondNode != null)
            {
                secondNode.stop();
                secondNode = null;
            }
        }

        public void execute(Cassandra node,
                            String username,
                            String password,
                            String query,
                            String dc,
                            boolean check)
        {
            execute(node.getAddress(), username, password, query, dc, check);
        }

        public void execute(InetAddress point,
                            String username,
                            String password,
                            String query,
                            String dc,
                            boolean check)
        {
            try (final Session session = Cluster.builder()
                .addContactPoints(point)
                .withLoadBalancingPolicy(DCAwareRoundRobinPolicy.builder().withLocalDc(dc).build())
                .withCredentials(username, password).build().connect())
            {
                ResultSet execute = session.execute(query);

                if (check)
                {
                    assertNotNull(execute);
                    assertFalse(execute.all().isEmpty());
                    assertTrue(execute.isFullyFetched());
                }
            } catch (final Exception ex)
            {
                Assert.fail("Failed to execute a request!", ex);
            }
        }

        public void waitForClosedPort(String hostname, int port)
        {
            await().timeout(Durations.FIVE_MINUTES).until(() ->
                                                          {
                                                              try
                                                              {
                                                                  (new Socket(hostname, port)).close();
                                                                  return false;
                                                              } catch (SocketException e)
                                                              {
                                                                  return true;
                                                              }
                                                          });
        }

        public void waitForOpenPort(String hostname, int port)
        {
            await().timeout(Durations.FIVE_MINUTES).until(() ->
                                                          {
                                                              try
                                                              {
                                                                  (new Socket(hostname, port)).close();
                                                                  return true;
                                                              } catch (SocketException e)
                                                              {
                                                                  return false;
                                                              }
                                                          });
        }
    }


    public void copyJars(List<Path> paths, Path cassandraHome) throws Exception
    {
        for (Path path : paths)
        {
            FileUtils.copy(path, cassandraHome.resolve("lib").resolve(path.getFileName()), (a, b) -> true);
        }
    }
}
