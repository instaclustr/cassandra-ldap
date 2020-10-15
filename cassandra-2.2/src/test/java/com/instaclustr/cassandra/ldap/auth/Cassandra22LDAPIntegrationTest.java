package com.instaclustr.cassandra.ldap.auth;

import static java.util.stream.Collectors.toList;

import java.io.File;
import java.io.IOException;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.List;

import com.github.nosan.embedded.cassandra.EmbeddedCassandraFactory;
import com.instaclustr.cassandra.ldap.AbstractLDAPTesting;
import org.jboss.shrinkwrap.resolver.api.maven.Maven;
import org.testng.annotations.Test;

public class Cassandra22LDAPIntegrationTest extends AbstractLDAPTesting
{

    public String getCassandraVersion()
    {
        return System.getProperty("cassandra.version", "2.2.18");
    }

    @Override
    public void configure(final EmbeddedCassandraFactory factory)
    {
        assert factory.getWorkingDirectory() != null;
        factory.getConfigProperties().put("data_file_directories", new String[]{factory.getWorkingDirectory().resolve("data").toString()});
        factory.getSystemProperties().put("cassandra.ldap.properties.file", Paths.get("src/test/resources/ldap.properties").toAbsolutePath().toString());
    }

    @Test
    public void testLDAPinternal() throws Exception
    {
        super.testLDAPinternal();
    }

    @Override
    public List<Path> createPluginJars() throws IOException
    {
        File[] singleFile = Maven.resolver()
            .loadPomFromFile("pom.xml")
            .resolve("com.instaclustr:cassandra-ldap-2.2:1.0.0")
            .withTransitivity()
            .asFile();

        return Arrays.stream(singleFile).map(file -> file.toPath().toAbsolutePath()).collect(toList());
    }
}