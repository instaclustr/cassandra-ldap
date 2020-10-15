package com.instaclustr.cassandra.ldap.auth;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public interface PasswordRetriever
{

    void init(ClientState clientState) throws ConfigurationException;

    String retrieveHashedPassword(User user);
}
