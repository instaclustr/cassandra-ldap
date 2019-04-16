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

import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.config.Schema;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.exception.NoSuchCredentialsException;
import com.instaclustr.cassandra.ldap.exception.NoSuchRoleException;

public class CassandraRolePasswordRetriever implements HashedPasswordRetriever
{
    private static final Logger logger = LoggerFactory.getLogger(CassandraRolePasswordRetriever.class);

    private SelectStatement authenticateStatement;

    public static final String LEGACY_CREDENTIALS_TABLE = "credentials";
    private SelectStatement legacyAuthenticateStatement;

    // name of the hash column.
    private static final String SALTED_HASH = "salted_hash";

    private final ClientState clientState;

    public CassandraRolePasswordRetriever(ClientState clientState)
    {
        this.clientState = clientState;

        String query = String.format("SELECT %s FROM %s.%s WHERE role = ?",
                                     SALTED_HASH,
                                     SchemaConstants.AUTH_KEYSPACE_NAME,
                                     AuthKeyspace.ROLES);
        authenticateStatement = prepare(query);

        if (Schema.instance.getCFMetaData(SchemaConstants.AUTH_KEYSPACE_NAME, LEGACY_CREDENTIALS_TABLE) != null)
            prepareLegacyAuthenticateStatement();
    }

    public String retrieveHashedPassword(User user)
    {
        try
        {
            SelectStatement authenticationStatement = authenticationStatement();

            ResultMessage.Rows rows =
                authenticationStatement.execute(QueryState.forInternalCalls(),
                                                QueryOptions.forInternalCalls(consistencyForRole(user.getUsername()),
                                                                              Lists.newArrayList(ByteBufferUtil.bytes(user.getUsername()))),
                                                System.nanoTime());

            // If either a non-existent role name was supplied, or no credentials
            // were found for that role we don't want to cache the result so we throw
            // a specific, but unchecked, exception to keep LoadingCache happy.
            if (rows.result.isEmpty())
                throw new NoSuchRoleException();

            UntypedResultSet result = UntypedResultSet.create(rows.result);
            if (!result.one().has(SALTED_HASH))
                throw new NoSuchCredentialsException();

            return result.one().getString(SALTED_HASH);
        }
        catch (NoSuchRoleException ex)
        {
            logger.trace(String.format("User %s does not exist in the Cassandra database.", user.getUsername()));

            throw ex;
        }
        catch (NoSuchCredentialsException ex)
        {
            logger.trace(String.format("User %s does not have password in the Cassandra database.", user.getUsername()));

            throw ex;
        }
        catch (RequestExecutionException ex)
        {
            logger.trace("Error performing internal authentication", ex);

            throw ex;
        }
    }

    /**
     * If the legacy users table exists try to verify credentials there. This is to handle the case
     * where the cluster is being upgraded and so is running with mixed versions of the authn tables
     */
    private SelectStatement authenticationStatement()
    {
        if (Schema.instance.getCFMetaData(SchemaConstants.AUTH_KEYSPACE_NAME, LEGACY_CREDENTIALS_TABLE) == null)
            return authenticateStatement;
        else
        {
            // the statement got prepared, we to try preparing it again.
            // If the credentials was initialised only after statement got prepared, re-prepare (CASSANDRA-12813).
            if (legacyAuthenticateStatement == null)
                prepareLegacyAuthenticateStatement();
            return legacyAuthenticateStatement;
        }
    }

    private SelectStatement prepare(String query)
    {
        return (SelectStatement) QueryProcessor.getStatement(query, clientState).statement;
    }

    private void prepareLegacyAuthenticateStatement()
    {
        String query = String.format("SELECT %s from %s.%s WHERE username = ?",
                                     SALTED_HASH,
                                     SchemaConstants.AUTH_KEYSPACE_NAME,
                                     LEGACY_CREDENTIALS_TABLE);
        legacyAuthenticateStatement = prepare(query);
    }

    private ConsistencyLevel consistencyForRole(String role)
    {
        if (role.equals("cassandra"))
            return ConsistencyLevel.QUORUM;
        else
            return ConsistencyLevel.LOCAL_ONE;
    }
}
