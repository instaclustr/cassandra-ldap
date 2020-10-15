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
package org.apache.cassandra.auth;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_LDAP_ADMIN_USER;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP;
import static com.instaclustr.cassandra.ldap.utils.ServiceUtils.getService;
import static java.lang.String.format;

import java.util.concurrent.TimeUnit;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.common.util.concurrent.Uninterruptibles;
import com.instaclustr.cassandra.ldap.AbstractLDAPAuthenticator;
import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.auth.CassandraPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.DefaultLDAPServer;
import com.instaclustr.cassandra.ldap.auth.LDAPPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.LegacyCassandraRolePasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.LegacySystemAuthRoles;
import com.instaclustr.cassandra.ldap.cache.CredentialsLoadingFunction;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class LegacyCassandraLDAPAuthenticator extends AbstractLDAPAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(LegacyCassandraLDAPAuthenticator.class);

    private CredentialsLoadingFunction credentialsLoadingFunction;

    public void setup()
    {
        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException(format("%s only works with %s",
                                                    LegacyCassandraLDAPAuthenticator.class.getCanonicalName(),
                                                    CassandraAuthorizer.class.getCanonicalName()));
        }

        clientState = ClientState.forInternalCalls();

        systemAuthRoles = new LegacySystemAuthRoles();
        systemAuthRoles.setClientState(clientState);

        final CassandraPasswordRetriever cassandraPasswordRetriever = new LegacyCassandraRolePasswordRetriever();
        cassandraPasswordRetriever.init(clientState);

        final LDAPPasswordRetriever ldapPasswordRetriever = getService(LDAPPasswordRetriever.class, DefaultLDAPServer.class);
        try
        {
            ldapPasswordRetriever.init(clientState, hasher, properties);
        } catch (ConfigurationException e)
        {
            logger.warn(format("Not possible to connect to LDAP server as user %s.", properties.getProperty(LDAP_DN)), e);
        }

        final String adminRole = System.getProperty(CASSANDRA_LDAP_ADMIN_USER, "cassandra");

        while (true)
        {
            try
            {
                if (!systemAuthRoles.hasAdminRole(adminRole))
                {
                    throw new IllegalStateException("Waiting for " + adminRole + " role!");
                }

                break;
            } catch (final Exception ex)
            {
                logger.debug("Waiting for cassandra role, sleeping for 5 seconds and trying again ...");
                Uninterruptibles.sleepUninterruptibly(5, TimeUnit.SECONDS);
            }
        }

        clientState.login(new AuthenticatedUser(adminRole));

        credentialsLoadingFunction = new CredentialsLoadingFunction(cassandraPasswordRetriever::retrieveHashedPassword,
                                                                    ldapPasswordRetriever::retrieveHashedPassword,
                                                                    properties.getProperty(NAMING_ATTRIBUTE_PROP));

        logger.info("{} was initialised", LegacyCassandraLDAPAuthenticator.class.getName());
    }


    @Override
    public AuthenticatedUser authenticate(final String username, final String loginPassword)
    {
        try
        {
            final User user = new User(username, loginPassword);

            final String userPassword = credentialsLoadingFunction.apply(user);

            if (userPassword != null)
            {
                if (!hasher.checkPasswords(loginPassword, userPassword))
                {

                    if (user.getLdapDN() == null)
                    {
                        throw new AuthenticationException("invalid username/password");
                    }
                }

                final String loginName = user.getLdapDN() == null ? user.getUsername() : user.getLdapDN();

                if (user.getLdapDN() != null)
                {
                    systemAuthRoles.createRole(user.getLdapDN(), false);
                } else if (user.getUsername().startsWith(properties.getProperty(NAMING_ATTRIBUTE_PROP)))
                {
                    systemAuthRoles.createRole(user.getUsername(), false);
                }

                return new AuthenticatedUser(loginName);
            }
        } catch (final UncheckedExecutionException ex)
        {
            if (ex.getCause() instanceof LDAPAuthFailedException)
            {
                final LDAPAuthFailedException ldex = (LDAPAuthFailedException) ex.getCause();

                logger.warn("Failed login for {}, reason was {}", username, ex.getMessage());

                throw new AuthenticationException(format(
                    "Failed to authenticate with directory server, user may not exist: %s",
                    ldex.getMessage()));
            } else
            {
                throw ex;
            }
        } catch (final AuthenticationException ex)
        {
            throw ex;
        } catch (final Exception ex)
        {
            logger.error("ERROR", ex);

            throw new AuthenticationException(format("Could not authenticate: %s", ex.getMessage()));
        }

        return null; // should never
    }
}
