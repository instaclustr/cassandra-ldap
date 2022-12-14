package com.instaclustr.cassandra.ldap.auth;

import org.testng.annotations.Test;

public class Cassandra311LDAPIntegrationTest extends AbstractLDAPTest {
    @Override
    public String getCassandraVersion() {
        return System.getProperty("version.cassandra311", "3.11.14");
    }

    @Override
    public String getImplementationGAV() {
        return "com.instaclustr:cassandra-ldap-" + getCassandraVersion() + ":1.0.0";
    }

    @Test
    public void ldapTest() throws Exception {
        super.testLDAPinternal();
    }
}