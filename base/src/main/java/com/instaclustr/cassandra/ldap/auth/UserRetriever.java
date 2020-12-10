package com.instaclustr.cassandra.ldap.auth;

import com.instaclustr.cassandra.ldap.User;

public interface UserRetriever
{
    User retrieve(User user);
}
