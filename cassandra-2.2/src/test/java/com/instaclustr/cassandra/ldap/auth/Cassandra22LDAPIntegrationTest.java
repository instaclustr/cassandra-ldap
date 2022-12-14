package com.instaclustr.cassandra.ldap.auth;

import org.testng.annotations.Test;

public class Cassandra22LDAPIntegrationTest extends AbstractLDAPTest {
    @Override
    public String getCassandraVersion() {
        return System.getProperty("version.cassandra22", "2.2.19");
    }

    @Override
    public String getImplementationGAV() {
        return "com.instaclustr:cassandra-ldap-" + getCassandraVersion() + ":1.0.2";
    }

    @Test
    public void ldapTest() throws Exception {
        super.testLDAPinternal();
    }
}