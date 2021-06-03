package com.instaclustr.cassandra.ldap.auth;

import static com.github.nosan.embedded.cassandra.WorkingDirectoryCustomizer.addResource;
import static java.util.Arrays.stream;
import static java.util.stream.Collectors.toList;
import static org.jboss.shrinkwrap.resolver.api.maven.Maven.resolver;

import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.List;

import com.github.nosan.embedded.cassandra.CassandraBuilder;
import com.github.nosan.embedded.cassandra.WorkingDirectoryCustomizer;
import com.github.nosan.embedded.cassandra.WorkingDirectoryDestroyer;
import com.github.nosan.embedded.cassandra.commons.ClassPathResource;
import com.github.nosan.embedded.cassandra.commons.FileSystemResource;
import org.testng.annotations.Test;

public class Cassandra40LDAPIntegrationTest extends AbstractLDAPCassandra40testing {

    public String getCassandraVersion() {
        return System.getProperty("cassandra4.version", "4.0-rc1");
    }

    @Override
    public CassandraBuilder configure(final boolean ldap,
                                      final String node) {
        List<Path> pluginJars = stream(resolver()
                                           .loadPomFromFile("pom.xml")
                                           .resolve("com.instaclustr:cassandra-ldap-4.0-rc1:1.0.0")
                                           .withTransitivity()
                                           .asFile()).map(file -> file.toPath().toAbsolutePath()).collect(toList());

        return new CassandraBuilder()
            .version(getCassandraVersion())
            .addJvmOptions("-Xmx1g", "-Xms1g")
            .addSystemProperties(new HashMap<String, String>() {{
                put("cassandra.jmx.local.port", node.equals("first") ? "7199" : "7200");
                put("cassandra.ring_delay_ms", "1000");
                put("cassandra.ldap.properties.file", Paths.get("src/test/resources/ldap.properties").toAbsolutePath().toString());
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

    @Test
    public void testLDAPinternal() throws Exception {
        super.testLDAPinternal();
    }
}