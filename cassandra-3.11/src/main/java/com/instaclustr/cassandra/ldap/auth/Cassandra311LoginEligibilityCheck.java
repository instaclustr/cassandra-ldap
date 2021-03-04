package com.instaclustr.cassandra.ldap.auth;

import static java.util.Collections.singletonList;

import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage.Rows;
import org.apache.cassandra.utils.ByteBufferUtil;

public class Cassandra311LoginEligibilityCheck extends BaseCassandraLoginEligibilityCheck
{
    @Override
    protected Rows getRows(final String loginName)
    {
        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(selectStatement, clientState).statement;
        return selStmt.execute(new QueryState(clientState),
                               QueryOptions.forInternalCalls(singletonList(ByteBufferUtil.bytes(loginName))),
                               System.nanoTime());
    }
}
