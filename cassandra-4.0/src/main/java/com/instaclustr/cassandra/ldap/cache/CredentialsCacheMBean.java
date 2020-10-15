package com.instaclustr.cassandra.ldap.cache;

import org.apache.cassandra.auth.AuthCacheMBean;

public interface CredentialsCacheMBean extends AuthCacheMBean
{

    void invalidateCredentials(String username);
}
