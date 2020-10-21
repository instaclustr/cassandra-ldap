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

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;
import java.util.Hashtable;
import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.exception.LDAPAuthFailedException;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.ExceptionCode;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class DefaultLDAPServer extends LDAPPasswordRetriever
{

    private static final Logger logger = LoggerFactory.getLogger(DefaultLDAPServer.class);

    // Use the service context for the initial connection so we can search for users DNs.
    private DirContext serviceContext;

    private Properties properties;

    private int rounds;

    @Override
    public void close()
    {
        if (serviceContext != null)
        {
            try
            {
                serviceContext.close();
            } catch (final Exception ex)
            {
                logger.error("Unable to close service context.", ex);
            } finally
            {
                serviceContext = null;
            }
        }

        properties = null;
    }

    @Override
    public void setup() throws ConfigurationException
    {

        if (serviceContext != null)
        {
            try
            {
                serviceContext.close();
            } catch (Exception ex)
            {
                logger.warn("Error while closing LDAP service context.", ex);
            }
        }

        if (properties == null)
        {
            properties = new LdapAuthenticatorConfiguration().parseProperties();
            rounds = LdapAuthenticatorConfiguration.getGensaltLog2Rounds(properties);
        }

        try
        {
            final String serviceDN = properties.getProperty(LdapAuthenticatorConfiguration.LDAP_DN);
            final String servicePass = properties.getProperty(LdapAuthenticatorConfiguration.PASSWORD_KEY);

            properties.put(Context.SECURITY_PRINCIPAL, serviceDN);
            properties.put(Context.SECURITY_CREDENTIALS, servicePass);

            serviceContext = new InitialDirContext(properties);

        } catch (NamingException ex)
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
    @Override
    public String retrieveHashedPassword(User user) throws LDAPAuthFailedException
    {
        DirContext ctx = null;

        try
        {
            String ldapDn = getLdapDN(user.getUsername());

            if (ldapDn == null)
            {
                throw new AuthenticationException(String.format("Could not authenticate to directory server using naming attribute %s and username %s. "
                                                                    + "User likely does not exist or connection to LDAP server is invalid.",
                                                                properties.getProperty(LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP),
                                                                user.getUsername()));
            }

            user.setLdapDN(ldapDn);

            final Hashtable<String, String> env = getUserEnv(user.getLdapDN(), user.getPassword());

            ctx = new InitialDirContext(env);
        } catch (NamingException ex)
        {
            throw new LDAPAuthFailedException(ExceptionCode.BAD_CREDENTIALS, ex.getMessage(), ex);
        } finally
        {
            if (ctx != null)
            {
                try
                {
                    ctx.close();
                } catch (NamingException ex)
                {
                    logger.debug("Exception occured while trying to close DirContext.", ex);
                }
            }
        }

        return hasher.hashPassword(user.getPassword(), rounds);
    }

    private String searchLdapDN(String username) throws NamingException
    {
        final String filter = format("(%s=%s)",
                                     properties.getProperty(LdapAuthenticatorConfiguration.NAMING_ATTRIBUTE_PROP),
                                     username);

        String dn = null;

        final SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        NamingEnumeration<SearchResult> answer = null;

        try
        {

            answer = serviceContext.search("", filter, searchControls);

            if (answer.hasMore())
            {
                SearchResult result = answer.next();
                dn = result.getNameInNamespace();
            }

            return dn;
        } catch (NamingException ex)
        {
            if (answer != null)
            {
                try
                {
                    answer.close();
                } catch (NamingException closingException)
                {
                    logger.debug("Failing to close connection to LDAP server.");
                }
            }

            throw ex;
        }
    }


    /**
     * Fetch a LDAP DN for a specific user
     *
     * @param username Username (CN)
     * @return DN for user
     */
    private String getLdapDN(String username) throws NamingException
    {
        if (serviceContext == null)
        {
            setup();
        }

        try
        {
            return searchLdapDN(username);
        } catch (NamingException ex)
        {
            logger.info(ex.getExplanation());

            setup();

            return searchLdapDN(username);
        }
    }

    /**
     * Generate a table of properties for connecting to LDAP server using JNDI
     *
     * @return Table containing {@link Context#INITIAL_CONTEXT_FACTORY}, {@link Context#PROVIDER_URL} and {@link Context#SECURITY_AUTHENTICATION} set.
     */
    private Hashtable<String, String> getUserEnv(String username, String password)
    {
        Hashtable<String, String> env = new Hashtable<>(11);

        env.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(Context.INITIAL_CONTEXT_FACTORY));
        env.put(Context.PROVIDER_URL, properties.getProperty(LdapAuthenticatorConfiguration.LDAP_URI_PROP));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        env.put(Context.SECURITY_PRINCIPAL, username);
        env.put(Context.SECURITY_CREDENTIALS, password);

        return env;
    }
}
