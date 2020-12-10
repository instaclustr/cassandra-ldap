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

import static java.lang.String.format;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.exception.NoSuchCredentialsException;
import com.instaclustr.cassandra.ldap.exception.NoSuchRoleException;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class AbstractCassandraUserRetriever implements CassandraUserRetriever
{

    private static final Logger logger = LoggerFactory.getLogger(AbstractCassandraUserRetriever.class);

    protected static final String LEGACY_CREDENTIALS_TABLE = "credentials";
    protected static final String AUTH_KEYSPACE = "system_auth";

    protected SelectStatement authenticateStatement;
    protected SelectStatement legacyAuthenticateStatement;
    protected ClientState clientState;

    protected boolean legacyTableExists;

    @Override
    public User retrieve(User user)
    {
        try
        {
            ResultMessage.Rows rows = getRows(user);

            // If either a non-existent role name was supplied, or no credentials
            // were found for that role we don't want to cache the result so we throw
            // a specific, but unchecked, exception to keep LoadingCache happy.
            if (rows.result.isEmpty())
            {
                throw new NoSuchRoleException();
            }

            UntypedResultSet result = UntypedResultSet.create(rows.result);
            if (!result.one().has("salted_hash"))
            {
                throw new NoSuchCredentialsException();
            }

            return new User(user.getUsername(), result.one().getString("salted_hash"));
        } catch (NoSuchRoleException ex)
        {
            logger.trace(format("User %s does not exist in the Cassandra database.", user.getUsername()));

            throw ex;
        } catch (NoSuchCredentialsException ex)
        {
            logger.trace(format("User %s does not have password in the Cassandra database.", user.getUsername()));

            throw ex;
        } catch (RequestExecutionException ex)
        {
            logger.trace("Error performing internal authentication", ex);

            throw ex;
        }
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
            return (SelectStatement) QueryProcessor.getStatement("SELECT salted_hash FROM system_auth.roles WHERE role = ?", clientState).statement;
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

    protected abstract void prepareLegacyAuthenticateStatementInternal(final ClientState clientState);

    protected abstract boolean legacyCredentialsTableExists();

    protected abstract ResultMessage.Rows getRows(final User user);

    protected ConsistencyLevel consistencyForRole(String role)
    {
        if (role.equals("cassandra"))
        {
            return ConsistencyLevel.ONE;
        } else
        {
            return ConsistencyLevel.LOCAL_QUORUM;
        }
    }
}
