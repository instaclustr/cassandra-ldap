package com.instaclustr.cassandra.ldap.auth;

import static java.util.Collections.singletonList;
import static org.apache.cassandra.auth.AuthKeyspace.NAME;
import static org.apache.cassandra.auth.AuthKeyspace.ROLES;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage.Rows;
import org.apache.cassandra.utils.ByteBufferUtil;

public class LegacyCassandraRolePasswordRetriever extends AbstractCassandraRolePasswordRetriever
{

    @Override
    public void init(ClientState clientState)
    {
        this.clientState = clientState;

        final String statement = String.format("SELECT salted_hash FROM %s.%s WHERE role = ?", NAME, ROLES);
        authenticateStatement = (SelectStatement) QueryProcessor.getStatement(statement, clientState).statement;
        legacyTableExists = legacyCredentialsTableExists();

        if (legacyTableExists)
        {
            prepareLegacyAuthenticateStatementInternal(clientState);
        }
    }

    @Override
    protected Rows getRows(final User user)
    {
        return authenticationStatement(clientState, legacyTableExists).execute(new QueryState(clientState),
                                                                               QueryOptions.forInternalCalls(consistencyForRole(user.getUsername()),
                                                                                                             singletonList(ByteBufferUtil.bytes(user.getUsername()))));
    }

    @Override
    protected void prepareLegacyAuthenticateStatementInternal(final ClientState clientState)
    {
        final String query = String.format("SELECT salted_hash from %s.%s WHERE username = ?", AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE);
        legacyAuthenticateStatement = (SelectStatement) QueryProcessor.getStatement(query, clientState).statement;
    }

    @Override
    protected boolean legacyCredentialsTableExists()
    {
        return Schema.instance.getCFMetaData(AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE) != null;
    }
}
