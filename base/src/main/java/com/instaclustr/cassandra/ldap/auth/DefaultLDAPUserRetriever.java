package com.instaclustr.cassandra.ldap.auth;

import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import com.instaclustr.cassandra.ldap.utils.ServiceUtils;

public class DefaultLDAPUserRetriever implements UserRetriever {

    private final Hasher hasher;
    private final Properties properties;
    private final boolean dontLoadService;

    public DefaultLDAPUserRetriever(final Hasher hasher, final Properties properties) {
        this.hasher = hasher;
        this.properties = properties;
        this.dontLoadService = !Boolean.parseBoolean(properties.getProperty("load_ldap_service", "false"));
    }

    @Override
    public User retrieve(final User user) {
        if (dontLoadService)
        {
            return new DefaultLDAPServer().setup(hasher, properties).retrieve(user);
        }
        else
        {
            return ServiceUtils.getService(LDAPUserRetriever.class, DefaultLDAPServer.class).setup(hasher, properties).retrieve(user);
        }
    }
}
