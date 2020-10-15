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

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_AUTH_CACHE_ENABLED_PROP;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_LDAP_ADMIN_USER;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP;
import static com.instaclustr.cassandra.ldap.utils.ServiceUtils.getService;
import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import java.net.InetAddress;
import java.util.concurrent.TimeUnit;
import java.util.function.Function;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.common.util.concurrent.Uninterruptibles;
import com.instaclustr.cassandra.ldap.AbstractLDAPAuthenticator;
import com.instaclustr.cassandra.ldap.PlainTextSaslAuthenticator;
import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.auth.CassandraPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.DefaultLDAPServer;
import com.instaclustr.cassandra.ldap.auth.LDAPPasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.cache.CacheDelegate;
import com.instaclustr.cassandra.ldap.cache.CredentialsLoadingFunction;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Uses JNDI to authenticate to an LDAP server. On successful authentication a Cassandra role is created for the provided
 * user. This user is configured without a password. If LDAP server connection is lost or there is other communication error
 * while talking to LDAP server, operator has still a possibility to log in via "cassandra" user as usually and until LDAP server
 * is not back again, users meant to be authenticated against LDAP server will not be able to log in.
 *
 * Users that are disabled in LDAP can only be cleaned up manually, however this is not typically necessary as long as you
 * keep using LDAPAuthenticator, they will just needlessly fill up system_auth. As long as they are disabled in your LDAP
 * server, they cannot be authenticated with Cassandra (after expiring from the cache).
 *
 * A cache exists to stop us from spamming the LDAP server with requests. It only stores the DN of the user and should only be
 * populated if a user has successfully authenticated using LDAP previously. Expiry from the cache is configured through
 * the usual auth cache configuration option.
 */
public class LDAPAuthenticator extends AbstractLDAPAuthenticator
{

    private static final Logger logger = LoggerFactory.getLogger(AbstractLDAPAuthenticator.class);

    protected CacheDelegate cacheDelegate;

    public void setup()
    {
        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException(format("%s only works with %s",
                                                    LDAPAuthenticator.class.getCanonicalName(),
                                                    CassandraAuthorizer.class.getCanonicalName()));
        }

        clientState = ClientState.forInternalCalls();

        systemAuthRoles = getService(SystemAuthRoles.class, null);
        systemAuthRoles.setClientState(clientState);

        final CassandraPasswordRetriever cassandraPasswordRetriever = getService(CassandraPasswordRetriever.class, null);
        cassandraPasswordRetriever.init(clientState);

        final LDAPPasswordRetriever ldapPasswordRetriever = getService(LDAPPasswordRetriever.class, DefaultLDAPServer.class);
        try
        {
            ldapPasswordRetriever.init(clientState, hasher, properties);
        } catch (ConfigurationException e)
        {
            logger.warn(format("Not possible to connect to LDAP server as user %s.", properties.getProperty(LDAP_DN)), e);
        }

        cacheDelegate = getService(CacheDelegate.class, null);

        final String adminRole = System.getProperty(CASSANDRA_LDAP_ADMIN_USER, "cassandra");

        while (true)
        {
            try
            {
                if (!systemAuthRoles.hasAdminRole())
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

        final Function<User, String> credentialsLoadingFunction = new CredentialsLoadingFunction(cassandraPasswordRetriever::retrieveHashedPassword,
                                                                                                 ldapPasswordRetriever::retrieveHashedPassword,
                                                                                                 properties.getProperty(NAMING_ATTRIBUTE_PROP));

        cacheDelegate.init(credentialsLoadingFunction, parseBoolean(properties.getProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP)));

        logger.info("{} was initialised", LDAPAuthenticator.class.getName());
    }

    @Override
    public SaslNegotiator newSaslNegotiator(final InetAddress clientAddress)
    {
        return new PlainTextSaslAuthenticator(this);
    }

    /**
     * Authenticate a user/password combination to the configured LDAP server. On the first successful authentication a corresponding
     * Cassandra role will be created.
     *
     * @param username username portion of the CN or UID. E.g "James Hook" in cn=James Hook,ou=people,o=sevenSeas
     * @param password corresponding password
     * @return {@link AuthenticatedUser} for the DN as stored in C*.
     * @throws AuthenticationException when authentication with LDAP server fails.
     */
    public AuthenticatedUser authenticate(String username, String password) throws AuthenticationException
    {
        try
        {
            final User user = new User(username, password);

            final String cachedPassword = cacheDelegate.get(user);

            // authenticate will be called if we're not in cache, subsequently loading the cache for the given user.
            if (cachedPassword != null)
            {
                if (!hasher.checkPasswords(password, cachedPassword))
                {

                    if (user.getLdapDN() == null)
                    {
                        throw new AuthenticationException("invalid username/password");
                    }

                    // Password has changed, re-auth and store new password in cache (or fail). A bit dodgy because
                    // we don't have access to cache.put(). This has a side-effect that a bad auth will invalidate the
                    // cache for the user and the next auth for the user will have to re-populate the cache. tl;dr:
                    // don't spam incorrect passwords (or let others spam them for your user).

                    cacheDelegate.invalidate(user);
                    cacheDelegate.get(user);
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
            ex.printStackTrace();

            throw new AuthenticationException(format("Could not authenticate: %s", ex.getMessage()));
        }

        return null; // should never be reached
    }
}
