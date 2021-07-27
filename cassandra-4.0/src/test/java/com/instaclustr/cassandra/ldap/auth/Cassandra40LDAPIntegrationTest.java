package com.instaclustr.cassandra.ldap.auth;

import org.testng.annotations.Test;

public class Cassandra40LDAPIntegrationTest extends AbstractLDAPTest {
    @Override
    public String getCassandraVersion() {
        return System.getProperty("cassandra4.version", "4.0.0");
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