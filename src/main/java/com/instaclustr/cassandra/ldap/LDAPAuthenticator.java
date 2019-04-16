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
package com.instaclustr.cassandra.ldap;

import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.CASSANDRA_AUTH_CACHE_ENABLED_PROP;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.PASSWORD_KEY;
import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import java.net.InetAddress;
import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;

import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.config.Config;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.util.concurrent.UncheckedExecutionException;
import com.instaclustr.cassandra.ldap.auth.CassandraRolePasswordRetriever;
import com.instaclustr.cassandra.ldap.auth.LDAPServer;
import com.instaclustr.cassandra.ldap.cache.CredentialsCache;
import com.instaclustr.cassandra.ldap.cache.CredentialsCacheLoadingFunction;
import com.instaclustr.cassandra.ldap.cassandra.SystemAuthRolesHelper;
import com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import com.instaclustr.cassandra.ldap.hash.HasherImpl;

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
 * the usual auth cache configuration option {@link Config#credentials_validity_in_ms }
 */
public class LDAPAuthenticator implements IAuthenticator
{
    private static final Logger logger = LoggerFactory.getLogger(LDAPAuthenticator.class);

    private Properties properties;

    private SystemAuthRolesHelper systemAuthRolesHelper;

    private HasherImpl hashUtils;

    private CredentialsCache cache;

    public boolean requireAuthentication()
    {
        return true;
    }

    public Set<? extends IResource> protectedResources()
    {
        return Collections.emptySet();
    }

    public void validateConfiguration() throws ConfigurationException
    {
        properties = new LdapAuthenticatorConfiguration().parseProperties();
    }

    public void setup()
    {

        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException(String.format("%s only works with %s",
                                                           LDAPAuthenticator.class.getCanonicalName(),
                                                           CassandraAuthorizer.class.getCanonicalName()));
        }

        ClientState state = ClientState.forInternalCalls();

        hashUtils = new HasherImpl();

        systemAuthRolesHelper = new SystemAuthRolesHelper(state, properties);
        systemAuthRolesHelper.waitUntilCassandraRoleIsInitialised();

        state.login(new AuthenticatedUser("cassandra"));

        LDAPServer ldapServer = new LDAPServer(state, hashUtils, properties);

        try
        {
            ldapServer.setup();
            systemAuthRolesHelper.createServiceDNIfNotExist();
        }
        catch (ConfigurationException e)
        {
            logger.warn(String.format("Not possible to connect to LDAP server as user %s.", properties.getProperty(LDAP_DN)));
        }

        CassandraRolePasswordRetriever cassandraRolePasswordRetriever = new CassandraRolePasswordRetriever(state);

        cache = new CredentialsCache(new CredentialsCacheLoadingFunction(cassandraRolePasswordRetriever::retrieveHashedPassword,
                                                                         ldapServer::retrieveHashedPassword),
                                     parseBoolean(properties.getProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP)));
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

            final String cachedPassword = cache.get(user);

            // authenticate will be called if we're not in cache, subsequently loading the cache for the given user.
            if (cachedPassword != null)
            {
                if (!hashUtils.checkPasswords(password, cachedPassword))
                {
                    // Password has changed, re-auth and store new password in cache (or fail). A bit dodgy because
                    // we don't have access to cache.put(). This has a side-effect that a bad auth will invalidate the
                    // cache for the user and the next auth for the user will have to re-populate the cache. tl;dr:
                    // don't spam incorrect passwords (or let others spam them for your user).
                    cache.invalidate(user);
                    cache.get(user);
                }

                if (user.getLdapDN() != null && user.getLdapDN().equals(properties.getProperty(LDAP_DN)))
                {
                    systemAuthRolesHelper.createServiceDNIfNotExist();
                }
                else if (user.getLdapDN() != null && !systemAuthRolesHelper.roleExists(user.getLdapDN()))
                {
                    logger.info("DN {} doesn't exist in {}.{}, creating new user",
                                user.getLdapDN(),
                                SchemaConstants.AUTH_KEYSPACE_NAME,
                                AuthKeyspace.ROLES);
                    systemAuthRolesHelper.createRole(user.getLdapDN());
                }

                String loginName = user.getLdapDN() == null ? user.getUsername() : user.getLdapDN();

                return new AuthenticatedUser(loginName);
            }
        }
        catch (UncheckedExecutionException ex)
        {
            if (ex.getCause() instanceof LDAPAuthFailedException)
            {
                LDAPAuthFailedException ldex = (LDAPAuthFailedException) ex.getCause();

                logger.warn("Failed login for {}, reason was {}", username, ex.getMessage());

                throw new AuthenticationException(format(
                    "Failed to authenticate with directory server, user may not exist: %s",
                    ldex.getMessage()));
            }
            else
            {
                throw ex;
            }
        }
        catch (ExecutionException | LDAPAuthFailedException ex)
        {
            throw new SecurityException(format("Could not authenticate to the LDAP directory: %s", ex.getMessage()), ex);
        }

        return null; // should never be reached
    }

    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new PlainTextSaslAuthenticator(this);
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        final String username = credentials.get(LDAP_DN);

        if (username == null)
        {
            throw new AuthenticationException(format("Required key '%s' is missing", LDAP_DN));
        }

        final String password = credentials.get(PASSWORD_KEY);

        if (password == null)
        {
            throw new AuthenticationException(format("Required key '%s' is missing for provided username %s",
                                                     PASSWORD_KEY,
                                                     username));
        }

        return authenticate(username, password);
    }
}
