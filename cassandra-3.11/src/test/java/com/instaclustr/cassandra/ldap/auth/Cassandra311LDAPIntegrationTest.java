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

public class Cassandra311LDAPIntegrationTest extends AbstractLDAPTesting
{

    public String getCassandraVersion()
    {
        return System.getProperty("cassandra.version", "3.11.10");
    }

    @Override
    public void configure(final EmbeddedCassandraFactory factory)
    {
        factory.getSystemProperties().put("cassandra.ldap.properties.file", Paths.get("src/test/resources/ldap.properties").toAbsolutePath().toString());
    }

    @Test
    public void testLDAPinternal() throws Exception
    {
        super.testLDAPinternal();
    }

    public List<Path> createPluginJars() throws IOException
    {
        File[] singleFile = Maven.resolver()
            .loadPomFromFile("pom.xml")
            .resolve("com.instaclustr:cassandra-ldap-3.11:1.2.0-SNAPSHOT")
            .withTransitivity()
            .asFile();

        return Arrays.stream(singleFile).map(file -> file.toPath().toAbsolutePath()).collect(toList());
    }
}