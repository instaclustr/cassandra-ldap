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
package com.instaclustr.cassandra.ldap.cassandra;

import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.DEFAULT_SUPERUSER_NAME;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPTS;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.LDAP_DN;
import static java.lang.String.format;
import static java.util.concurrent.TimeUnit.SECONDS;
import static org.apache.cassandra.db.ConsistencyLevel.ONE;

import java.util.Properties;

import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.Uninterruptibles;

public class SystemAuthRolesHelper
{
    private final String SELECT_ROLE_STATEMENT = "SELECT role FROM %s.%s where role = ?";

    private final String CREATE_ROLE_STATEMENT_WITH_LOGIN = "CREATE ROLE \"%s\" WITH LOGIN = true";

    private final ClientState clientState;

    private final Properties properties;

    public SystemAuthRolesHelper(ClientState clientState, Properties properties)
    {
        this.clientState = clientState;
        this.properties = properties;
    }

    public void createServiceDNIfNotExist()
    {
        createRoleIfNotExists(properties.getProperty(LDAP_DN));
    }

    public void createRoleIfNotExists(String serviceDN)
    {
        if (!roleExists(serviceDN))
        {
            QueryProcessor.process(format("INSERT INTO %s.%s (role, is_superuser, can_login) VALUES ('%s', true, true)",
                                          SchemaConstants.AUTH_KEYSPACE_NAME,
                                          AuthKeyspace.ROLES,
                                          serviceDN),
                                   ONE);
        }
    }

    /**
     * Check if a particular role exists in system.auth
     *
     * @param dn user's distinguished name.
     * @return True if DN exists in C* roles otherwise false
     */
    public boolean roleExists(String dn)
    {
        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(format(SELECT_ROLE_STATEMENT,
                                                                                             SchemaConstants.AUTH_KEYSPACE_NAME,
                                                                                             AuthKeyspace.ROLES),
                                                                                      clientState).statement;

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(clientState),
                                                        QueryOptions.forInternalCalls(ONE,
                                                                                      Lists.newArrayList(ByteBufferUtil.bytes(dn))),
                                                        System.nanoTime());

        return !rows.result.isEmpty();
    }

    public void createRole(String roleName)
    {
        final CreateRoleStatement createStmt =
            (CreateRoleStatement) QueryProcessor.getStatement(format(CREATE_ROLE_STATEMENT_WITH_LOGIN, roleName), clientState).statement;

        createStmt.execute(new QueryState(clientState),
                           QueryOptions.forInternalCalls(ONE, Lists.newArrayList(ByteBufferUtil.bytes(roleName))),
                           System.nanoTime());
    }

    public void waitUntilCassandraRoleIsInitialised()
    {
        if (DatabaseDescriptor.getAuthorizer().requireAuthorization())
        {
            boolean defaultCassandraRoleExists = false;

            int attempts = 0;

            Throwable caughtException = null;

            while (!defaultCassandraRoleExists && attempts < INITIAL_CASSANDRA_LOGIN_ATTEMPTS)
            {
                Uninterruptibles.sleepUninterruptibly(INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD, SECONDS);

                attempts++;

                String cassandraUserSelect = String.format("SELECT * FROM %s.%s WHERE role = '%s'",
                                                           SchemaConstants.AUTH_KEYSPACE_NAME,
                                                           AuthKeyspace.ROLES,
                                                           DEFAULT_SUPERUSER_NAME);
                try
                {
                    defaultCassandraRoleExists = !QueryProcessor.process(cassandraUserSelect, ONE).isEmpty();
                }
                catch (Exception ex)
                {
                    caughtException = ex;
                }
            }

            if (!defaultCassandraRoleExists)
            {
                if (caughtException != null)
                {
                    throw new ConfigurationException("Unable to perform initial login: " + caughtException.getMessage(), caughtException);
                }
                else
                {
                    throw new ConfigurationException(String.format("There was not %s user created in %s seconds.",
                                                                   DEFAULT_SUPERUSER_NAME,
                                                                   INITIAL_CASSANDRA_LOGIN_ATTEMPTS * INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD));
                }
            }
        }
    }
}
