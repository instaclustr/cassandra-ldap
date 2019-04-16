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

import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.ANONYMOUS_ACCESS_PROP;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.DEFAULT_SERVICE_ROLE;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.LDAP_URI_PROP;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP;
import static com.instaclustr.cassandra.ldap.configuration.LdapAuthenticatorConfiguration.PASSWORD_KEY;
import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import java.util.Hashtable;
import java.util.Properties;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.ExceptionCode;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import com.instaclustr.cassandra.ldap.hash.HasherImpl;

public class LDAPServer implements HashedPasswordRetriever
{
    private static final Logger logger = LoggerFactory.getLogger(LDAPServer.class);

    private final Properties properties;

    private final ClientState clientState;

    private final HasherImpl hashUtils;

    // Use the service context for the initial connection so we can search for users DNs.
    private DirContext serviceContext;

    public LDAPServer(ClientState clientState,
                      HasherImpl hashUtils,
                      Properties properties)
    {
        this.properties = properties;
        this.clientState = clientState;
        this.hashUtils = hashUtils;
    }

    public void setup()
    {

        if (serviceContext != null)
        {
            try
            {
                serviceContext.close();
            }
            catch (Exception ex)
            {
                logger.warn("Error while closing LDAP service context.", ex);
            }
        }

        try
        {
            if (parseBoolean(properties.getProperty(ANONYMOUS_ACCESS_PROP)))
            {
                // Anonymous
                serviceContext = new InitialDirContext(properties);
                clientState.login(new AuthenticatedUser(DEFAULT_SERVICE_ROLE));
            }
            else
            {
                final String serviceDN = properties.getProperty(LDAP_DN);
                final String servicePass = properties.getProperty(PASSWORD_KEY);

                properties.put(Context.SECURITY_PRINCIPAL, serviceDN);
                properties.put(Context.SECURITY_CREDENTIALS, servicePass);

                serviceContext = new InitialDirContext(properties);
            }
        }
        catch (NamingException ex)
        {
            throw new ConfigurationException(format("Failed to connect to LDAP server: %s, explanation: %s",
                                                    ex.getMessage(),
                                                    ex.getExplanation() == null ? "uknown" : ex.getExplanation()),
                                             ex);
        }
    }

    /**
     * Authenticate to LDAP server as provided DN.
     *
     * @param user {@link User} to authenticate
     * @return password of user
     * @throws LDAPAuthFailedException if authentication fails or other error occurs.
     */
    public String retrieveHashedPassword(User user) throws LDAPAuthFailedException
    {
        DirContext ctx = null;

        try
        {
            String ldapDn = getLdapDN(user.getUsername());

            if (ldapDn == null)
            {
                throw new AuthenticationException(String.format("Could not authenticate to directory server using naming attribute %s and username %s."
                                                                    + "User likely does not exist or connection to LDAP server is invalid.",
                                                                getLdapNamingAttribute(),
                                                                user.getUsername()));
            }

            user.setLdapDN(ldapDn);

            final Hashtable env = getUserEnv(user.getLdapDN(), user.getPassword());

            ctx = new InitialDirContext(env);
        }
        catch (NamingException ex)
        {
            throw new LDAPAuthFailedException(ExceptionCode.BAD_CREDENTIALS, ex.getMessage(), ex);
        }
        finally
        {
            if (ctx != null)
            {
                try
                {
                    ctx.close();
                }
                catch (NamingException ex)
                {
                    logger.debug("Exception occured while trying to close DirContext.", ex);
                }
            }
        }

        return hashUtils.hashPassword(user.getPassword());
    }

    /**
     * Fetch a LDAP DN for a specific user
     *
     * @param username Username (CN)
     * @return DN for user
     */
    public String getLdapDN(String username) throws NamingException
    {
        if (serviceContext == null)
        {
            throw new ConfigurationException("LDAP server connection was not initialised.");
        }

        try
        {
            return searchLdapDN(username);
        }
        catch (NamingException ex)
        {
            logger.info(ex.getExplanation());

            setup();

            return searchLdapDN(username);
        }
    }

    private String searchLdapDN(String username) throws NamingException
    {
        final String filter = format("(%s=%s)",
                                     getLdapNamingAttribute(),
                                     username);

        String dn = null;

        final SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration answer = null;

        try
        {

            answer = serviceContext.search("", filter, searchControls);

            if (answer.hasMore())
            {
                SearchResult result = (SearchResult) answer.next();
                dn = result.getNameInNamespace();
            }

            return dn;
        }
        catch (NamingException ex)
        {
            if (answer != null)
            {
                try
                {
                    answer.close();
                }
                catch (NamingException closingException)
                {
                    logger.debug("Failing to close connection to LDAP server.");
                }
            }

            throw ex;
        }
    }

    /**
     * Generate a table of properties for connecting to LDAP server using JNDI
     *
     * @return Table containing {@link Context#INITIAL_CONTEXT_FACTORY}, {@link Context#PROVIDER_URL} and {@link Context#SECURITY_AUTHENTICATION} set.
     */
    protected Hashtable<String, String> getUserEnv(String username, String password)
    {
        Hashtable<String, String> env = new Hashtable<>(11);

        env.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(Context.INITIAL_CONTEXT_FACTORY));
        env.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        return env;
    }

    private Object getLdapNamingAttribute()
    {
        return properties.getOrDefault(NAMING_ATTRIBUTE_PROP, "cn");
    }
}
