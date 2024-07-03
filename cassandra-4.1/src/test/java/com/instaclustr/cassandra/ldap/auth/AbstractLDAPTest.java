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

import com.datastax.driver.core.Cluster;
import com.datastax.driver.core.PlainTextAuthProvider;
import com.datastax.driver.core.ResultSet;
import com.datastax.driver.core.Session;
import com.datastax.driver.core.policies.DCAwareRoundRobinPolicy;
import com.github.dockerjava.api.command.CreateContainerCmd;
import com.github.nosan.embedded.cassandra.Cassandra;
import com.github.nosan.embedded.cassandra.CassandraBuilder;
import com.github.nosan.embedded.cassandra.WorkingDirectoryCustomizer;
import com.github.nosan.embedded.cassandra.WorkingDirectoryDestroyer;
import com.github.nosan.embedded.cassandra.commons.ClassPathResource;
import com.github.nosan.embedded.cassandra.commons.FileSystemResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.github.nosan.embedded.cassandra.commons.FileUtils;
import org.testcontainers.containers.BindMode;
import org.testcontainers.containers.Container;
import org.testcontainers.containers.GenericContainer;
import org.testcontainers.containers.wait.strategy.HostPortWaitStrategy;
import org.testcontainers.utility.DockerImageName;
import org.testcontainers.utility.MountableFile;

import java.io.*;
import java.net.InetAddress;
import java.net.Socket;
import java.net.SocketException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;
import java.util.Properties;
import java.util.function.Consumer;

import static com.github.nosan.embedded.cassandra.WorkingDirectoryCustomizer.addResource;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.awaitility.Awaitility.await;
import static org.awaitility.Durations.FIVE_MINUTES;
import static org.jboss.shrinkwrap.resolver.api.maven.Maven.resolver;
import static org.testng.Assert.*;

public abstract class AbstractLDAPTest {

    private static final Logger logger = LoggerFactory.getLogger(AbstractLDAPTest.class);
    private static final String cassandraAdminUser = "cassandra";
    private static final String cassandraAdminPassword = "cassandra";
    private static final String cassandraDataCenter1 = "datacenter1";
    private static final String testUserName = "bill";
    private static final String testUserPassword = "test";
    private static final String testUserDn = "cn=bill,dc=example,dc=org";
    private static final String defaultRoleName = "default_role";
    private static final String basicQuery = "SELECT * FROM system.local;";

    protected void testLDAPinternal(boolean withTLS) throws Exception {
        final int port = withTLS ? 636 : 389;
        try (final GenericContainer ldapContainer = prepareLdapContainer(port, withTLS);
             final CassandraClusterContext context = getClusterContext(true, ldapContainer.getMappedPort(port), withTLS)) {

            context.start();

            context.execute(context.firstNode,
                    cassandraAdminUser,
                    cassandraAdminPassword,
                    "ALTER KEYSPACE system_auth WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 1, 'datacenter2':1};", cassandraDataCenter1, false);

            logger.info("[first node]: login via cassandra");
            context.execute(context.firstNode, cassandraAdminUser, cassandraAdminPassword, "select * from system_auth.roles", cassandraDataCenter1, true);
            logger.info("[first node]: login bill");
            context.execute(context.firstNode, testUserName, testUserPassword, basicQuery, cassandraDataCenter1, true);

            logger.info("[second node]: login bill");
            context.execute(context.secondNode, testUserName, testUserPassword, basicQuery, "datacenter2", true);

            testDefaultRoleMembership(ldapContainer, context);
        } catch (final Exception ex) {
            fail("Exception occurred!", ex);
        }
    }

    protected void testDefaultRoleMembership(GenericContainer ldapContainer, CassandraClusterContext context) throws Exception
    {
        // Create the default role
        context.simpleExecute(
            context.firstNode,
            cassandraAdminUser,
            cassandraAdminPassword,
            String.format("CREATE ROLE '%s';", defaultRoleName),
            cassandraDataCenter1
        );

        // Delete the user if it already exists
        context.simpleExecute(
            context.firstNode,
            cassandraAdminUser,
            cassandraAdminPassword,
            String.format("DROP ROLE IF EXISTS '%s';", testUserDn),
            cassandraDataCenter1
        );

        // Simulate a Logon as the user
        context.simpleExecute(
            context.firstNode,
            testUserName,
            testUserPassword,
            basicQuery,
            cassandraDataCenter1
        );

        // Check that the default role has been added to the user
        assertTrue(
            context.simpleExecute(
                context.firstNode,
                cassandraAdminUser,
                cassandraAdminPassword,
                String.format("LIST ROLES OF '%s';", testUserDn),
                cassandraDataCenter1
            ).all().stream().anyMatch(row -> row.getString("role").equals(defaultRoleName))
        );
    }

    public abstract String getCassandraVersion();

    public abstract String getImplementationGAV();

    private CassandraClusterContext getClusterContext(boolean ldapEnabled, int ldapPort, boolean secure) {
        CassandraClusterContext cassandraClusterContext = new CassandraClusterContext();
        cassandraClusterContext.firstNode = configure(ldapEnabled, "first", ldapPort, secure).build();
        cassandraClusterContext.secondNode = configure(ldapEnabled, "second", ldapPort, secure).build();
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
            try (final Session session = Cluster.builder()
                    .addContactPoint(point.getHostAddress())
                    .withLoadBalancingPolicy(new DCAwareRoundRobinPolicy.Builder().withLocalDc(dc).build())
                    .withAuthProvider(new PlainTextAuthProvider(username, password))
                    .build().connect()) {
                ResultSet execute = session.execute(query);

                if (check) {
                    assertNotNull(execute);
                    assertFalse(execute.all().isEmpty());
                    assertTrue(execute.isFullyFetched());
                }
            } catch (final Exception ex) {
                fail("Failed to execute a request!", ex);
            }
        }

        public synchronized ResultSet simpleExecute(Cassandra node,
                                                    String username,
                                                    String password,
                                                    String query,
                                                    String dc)
        {
            try (final Session session = Cluster.builder()
                    .addContactPoint(node.getSettings().getAddress().getHostAddress())
                    .withLoadBalancingPolicy(new DCAwareRoundRobinPolicy.Builder().withLocalDc(dc).build())
                    .withAuthProvider(new PlainTextAuthProvider(username, password))
                    .build().connect()) {
                return session.execute(query);
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

    protected CassandraBuilder configure(final boolean ldap, final String node, final int ldapPort, boolean secure) {
        final List<Path> pluginJars = stream(resolver()
                .loadPomFromFile("pom.xml")
                .resolve(getImplementationGAV())
                .withTransitivity()
                .asFile()).map(file -> file.toPath().toAbsolutePath()).collect(toList());

        final File ldapPropertiesFile = getLdapPropertiesFile(ldapPort, secure);

        return new CassandraBuilder()
                .version(getCassandraVersion())
                .addJvmOptions("-Xmx1g", "-Xms1g")
                .addSystemProperties(new HashMap<String, String>() {{
                    put("cassandra.jmx.local.port", node.equals("first") ? "7199" : "7200");
                    put("cassandra.ring_delay_ms", "1000");
                    put("cassandra.ldap.properties.file", ldapPropertiesFile.toPath().toAbsolutePath().toString());
                }})
                .workingDirectory(() -> Files.createTempDirectory(null))
                .addWorkingDirectoryCustomizers(new ArrayList<WorkingDirectoryCustomizer>() {{
                    if (ldap) {
                        add(addResource(new ClassPathResource(node + "-ldap.yaml"), "conf/cassandra.yaml"));
                    } else {
                        add(addResource(new ClassPathResource(node + ".yaml"), "conf/cassandra.yaml"));
                    }
                    add(addResource(new ClassPathResource(node + "-rackdc.properties"), "conf/cassandra-rackdc.properties"));
                    for (Path pluginJar : pluginJars) {
                        add(addResource(new FileSystemResource(pluginJar), "lib/" + pluginJar.getFileName().toString()));
                    }
                }}.toArray(new WorkingDirectoryCustomizer[0]))
                .workingDirectoryDestroyer(WorkingDirectoryDestroyer.doNothing());
    }

    protected GenericContainer prepareLdapContainer(int port, boolean withTLS) throws Exception {
        GenericContainer ldapContainer = new GenericContainer(DockerImageName.parse("osixia/openldap:1.5.0"))
                .withCopyFileToContainer(MountableFile.forHostPath("../conf/new-user.ldif"), "/new-user.ldif")
                .withEnv("LDAP_ADMIN_PASSWORD", "admin")
                .withExposedPorts(port)
                .withCreateContainerCmdModifier((Consumer<CreateContainerCmd>) cmd -> cmd.withHostName("ldap.my-company.com"))
                .waitingFor(new HostPortWaitStrategy());

        if (withTLS) {
            Path tempDirectory = Files.createTempDirectory("cassandra-ldap-plugin");

            Files.copy(Paths.get("../conf/tls-server/dhparam.pem"), tempDirectory.resolve("dhparam.pem"));
            Files.copy(Paths.get("../conf/tls-server/my-ca.crt"), tempDirectory.resolve("my-ca.crt"));
            Files.copy(Paths.get("../conf/tls-server/my-ldap.crt"), tempDirectory.resolve("my-ldap.crt"));
            Files.copy(Paths.get("../conf/tls-server/my-ldap.key"), tempDirectory.resolve("my-ldap.key"));

            ldapContainer.withFileSystemBind(tempDirectory.toAbsolutePath().toString(), "/container/service/slapd/assets/certs", BindMode.READ_WRITE);

            ldapContainer.withEnv("LDAP_LOG_LEVEL", "-1");
            ldapContainer.withEnv("LDAP_TLS_DH_PARAM_FILENAME", "dhparam.pem");
            ldapContainer.withEnv("LDAP_TLS_CRT_FILENAME", "my-ldap.crt");
            ldapContainer.withEnv("LDAP_TLS_KEY_FILENAME", "my-ldap.key");
            ldapContainer.withEnv("LDAP_TLS_CA_CRT_FILENAME", "my-ca.crt");
            ldapContainer.withEnv("LDAP_TLS_VERIFY_CLIENT", "try");
        }

        ldapContainer.start();

        Container.ExecResult result = addLdapUser(ldapContainer);

        while (result.getExitCode() != 0) {
            logger.error(result.getStderr());
            if (result.getStderr().contains("Already exists")) {
                break;
            }
            Thread.sleep(5000);
            result = addLdapUser(ldapContainer);
        }

        logger.info(result.getStdout());

        return ldapContainer;
    }

    private Container.ExecResult addLdapUser(GenericContainer ldapContainer) throws Exception {
        return ldapContainer.execInContainer(
                "ldapadd",
                "-x",
                "-D",
                "cn=admin,dc=example,dc=org",
                "-w",
                "admin",
                "-f",
                "/new-user.ldif",
                "-H",
                "ldap://127.0.0.1:389");
    }

    protected File getLdapPropertiesFile(int ldapPort, boolean secure) {
        try {
            File ldapPropertiesFile = Paths.get("../conf/ldap.properties").toFile();
            Properties ldapProperties = new Properties();

            try (InputStream is = new BufferedInputStream(new FileInputStream(ldapPropertiesFile))) {
                ldapProperties.load(is);
            } catch (Exception ex) {
                throw new IllegalStateException("Unable to read content of ldap.properties!");
            }

            String protocol = "ldap";
            if (secure)
                protocol = "ldaps";

            ldapProperties.setProperty("ldap_uri", protocol + "://ldap.my-company.com:" + ldapPort + "/dc=example,dc=org");

            if (secure)
                ldapProperties.setProperty("ldap_truststore", Paths.get("../conf/tls-client/myTrustStore.jks").toFile().getAbsolutePath());

            File tempFile = Files.createTempFile("ldap-test", ".properties").toFile();
            ldapProperties.store(new FileWriter(tempFile, true), "comments");
            return tempFile;
        } catch (Exception ex) {
            throw new IllegalStateException("Unable to create ldap properties file for test.", ex);
        }
    }
}
