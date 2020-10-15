package com.instaclustr.cassandra.ldap.auth;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.apache.cassandra.db.ConsistencyLevel.LOCAL_ONE;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class LegacySystemAuthRoles extends SystemAuthRoles
{

    public boolean roleMissing(String dn)
    {
        assert getClientState() != null;

        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(format(SELECT_ROLE_STATEMENT,
                                                                                             "system_auth",
                                                                                             AuthKeyspace.ROLES),
                                                                                      getClientState()).statement;

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(getClientState()),
                                                        QueryOptions.forInternalCalls(ONE,
                                                                                      singletonList(ByteBufferUtil.bytes(dn))));

        return rows.result.isEmpty();
    }

    private static final Logger logger = LoggerFactory.getLogger(LegacySystemAuthRoles.class);

    public void createRole(String roleName, boolean superUser)
    {
        final CreateRoleStatement createStmt =
            (CreateRoleStatement) QueryProcessor.getStatement(format(CREATE_ROLE_STATEMENT_WITH_LOGIN, roleName, superUser), getClientState()).statement;

        if (getClientState() == null)
        {
            logger.error("CLIENT STATE IS NULL");
        }
        else
        {
            if (getClientState().getUser() == null)
            {
                logger.error("USER IS NULL");
            }
        }

        createStmt.execute(new QueryState(getClientState()),
                           QueryOptions.forInternalCalls(LOCAL_ONE, singletonList(ByteBufferUtil.bytes(roleName))));
    }
}
