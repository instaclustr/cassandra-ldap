package com.instaclustr.cassandra.ldap.auth;

import java.util.Properties;

import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;

public abstract class SystemAuthRoles
{

    public static final String SELECT_ROLE_STATEMENT = "SELECT role FROM %s.%s where role = ?";

    public static final String CREATE_ROLE_STATEMENT_WITH_LOGIN = "CREATE ROLE IF NOT EXISTS \"%s\" WITH LOGIN = true AND SUPERUSER = %s";

    private ClientState clientState;

    private Properties properties;

    public void setClientState(ClientState clientState)
    {
        this.clientState = clientState;
    }

    public void setProperties(Properties properties)
    {
        this.properties = properties;
    }

    public ClientState getClientState()
    {
        return clientState;
    }

    public Properties getProperties()
    {
        return properties;
    }

    public abstract boolean roleMissing(String dn);

    public abstract void createRole(String roleName, boolean superUser);

    public boolean hasAdminRole(String role) throws RequestExecutionException
    {
        // Try looking up the 'cassandra' default role first, to avoid the range query if possible.
        String defaultSUQuery = "SELECT * FROM system_auth.roles WHERE role = '" + role + "'";
        String allUsersQuery = "SELECT * FROM system_auth.roles LIMIT 1";
        return !QueryProcessor.process(defaultSUQuery, ConsistencyLevel.ONE).isEmpty()
            || !QueryProcessor.process(defaultSUQuery, ConsistencyLevel.QUORUM).isEmpty()
            || !QueryProcessor.process(allUsersQuery, ConsistencyLevel.QUORUM).isEmpty();
    }


    public boolean hasAdminRole() throws RequestExecutionException
    {
        return hasAdminRole("cassandra");
    }
}
