package com.instaclustr.cassandra.ldap.auth;

import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public interface CassandraUserRetriever extends UserRetriever
{
    void init(ClientState clientState) throws ConfigurationException;

}
