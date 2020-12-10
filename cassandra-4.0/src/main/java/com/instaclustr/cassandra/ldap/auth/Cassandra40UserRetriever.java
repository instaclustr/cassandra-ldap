/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.instaclustr.cassandra.ldap.auth;

import static java.util.Collections.singletonList;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.schema.Schema;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage.Rows;
import org.apache.cassandra.utils.ByteBufferUtil;

public class Cassandra40UserRetriever extends AbstractCassandraUserRetriever
{

    @Override
    public void init(ClientState clientState)
    {
        this.clientState = clientState;
        authenticateStatement = (SelectStatement) QueryProcessor.getStatement("SELECT salted_hash FROM system_auth.roles WHERE role = ?", clientState);

        legacyTableExists = legacyCredentialsTableExists();

        if (legacyTableExists)
        {
            prepareLegacyAuthenticateStatementInternal(clientState);
        }
    }

    @Override
    public Rows getRows(User user)
    {
        return authenticationStatement(clientState, legacyTableExists).execute(QueryState.forInternalCalls(),
                                                                               QueryOptions.forInternalCalls(consistencyForRole(user.getUsername()),
                                                                                                             singletonList(ByteBufferUtil.bytes(user.getUsername()))),
                                                                               System.nanoTime());
    }

    @Override
    protected void prepareLegacyAuthenticateStatementInternal(final ClientState clientState)
    {
        String query = String.format("SELECT salted_hash from %s.%s WHERE username = ?",
                                     AUTH_KEYSPACE,
                                     LEGACY_CREDENTIALS_TABLE);
        legacyAuthenticateStatement = (SelectStatement) QueryProcessor.getStatement(query, clientState);
    }

    /**
     * If the legacy users table exists try to verify credentials there. This is to handle the case
     * where the cluster is being upgraded and so is running with mixed versions of the auth tables
     */
    protected SelectStatement authenticationStatement(final ClientState clientState,
                                                      final boolean legacyTableExists)
    {
        if (!legacyTableExists)
        {
            return (SelectStatement) QueryProcessor.getStatement("SELECT salted_hash FROM system_auth.roles WHERE role = ?", clientState);
        } else
        {
            // the statement got prepared, we to try preparing it again.
            // If the credentials was initialised only after statement got prepared, re-prepare (CASSANDRA-12813).
            if (legacyAuthenticateStatement == null)
            {
                prepareLegacyAuthenticateStatementInternal(clientState);
            }
            return legacyAuthenticateStatement;
        }
    }

    @Override
    protected boolean legacyCredentialsTableExists()
    {
        return Schema.instance.getTableMetadata(AUTH_KEYSPACE, LEGACY_CREDENTIALS_TABLE) != null;
    }
}
