package com.instaclustr.cassandra.ldap.auth;

import org.testng.annotations.Test;

public class Cassandra41LDAPIntegrationTest extends AbstractLDAPTest {
    @Override
    public String getCassandraVersion() {
        return System.getProperty("version.cassandra41", "4.1.0");
    }

    @Override
    public String getImplementationGAV() {
        return "com.instaclustr:cassandra-ldap-" + getCassandraVersion() + ":1.1.0";
    }

    @Test
    public void ldapTest() throws Exception {
        super.testLDAPinternal();
    }
}
