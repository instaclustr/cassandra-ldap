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

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.net.InetAddress;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Hashtable;
import java.util.Map;
import java.util.Properties;
import java.util.Set;
import java.util.concurrent.ExecutionException;
import java.util.concurrent.TimeUnit;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.DirContext;
import javax.naming.directory.InitialDirContext;
import javax.naming.directory.SearchControls;
import javax.naming.directory.SearchResult;

import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.auth.AuthCacheMBean;
import org.apache.cassandra.auth.AuthKeyspace;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.CassandraAuthorizer;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.config.Config;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.config.SchemaConstants;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.ExceptionCode;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.apache.commons.lang3.builder.HashCodeBuilder;
import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.google.common.collect.Lists;
import com.google.common.util.concurrent.UncheckedExecutionException;
import com.google.common.util.concurrent.Uninterruptibles;

/**
 * Uses JNDI to authenticate to an LDAP server. On successful authentication a Cassandra role is created for the provided
 * user. This user is configured without a password, so if you disable Authenticator or switch Authenticator any user
 * will be usable by anyone (this is no different to switching a single node to AllowAllAuthenticator).
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

    // Ldap URI including DN
    public final static String LDAP_URI_PROP = "ldap_uri";
    public final static String CONTEXT_FACTORY_PROP = "context_factory";
    // Initial connection to LDAP can be anonymous if it's enabled. Won't allow you to connect to C* anonymously.
    public final static String ANONYMOUS_ACCESS_PROP = "anonymous_access";

    public final static String DEFAULT_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public final static String DEFAULT_SERVICE_ROLE = "_LDAPAUTH_";
    public final static String ROLE = "role";
    // If no anonymous access a default DN and password is required.
    public final static String LDAP_DN = "service_dn";
    public final static String PASSWORD_KEY = "service_password";

    public final static String LDAP_PROPERTIES_FILE = "ldap.properties.file";
    public final static String LDAP_PROPERTIES_FILENAME = "ldap.properties";
    // Just to support those not using "cn"
    public final static String NAMING_ATTRIBUTE_PROP = "ldap_naming_attribute";
    public final static String CACHE_HASHED_PASSWORD_PROP = "cache_hashed_password";
    public final static String DEFAULT_SUPERUSER_NAME = "cassandra";

    private static ClientState state;

    private static final String GENSALT_LOG2_ROUNDS_PROPERTY = Config.PROPERTY_PREFIX + "auth_bcrypt_gensalt_log2_rounds";
    private static final int GENSALT_LOG2_ROUNDS = getGensaltLogRounds();

    // Hash the password we store in the cache. Will incur a performance penalty, but necessary if you don't want
    // passwords stored in the clear on the Cassandra nodes in the cache.
    private static boolean hashPassword;

    private String serviceDN;
    private String servicePass;

    private final Set<String> existingUsers = new HashSet<>();
    private Properties properties;
    // Use the service context for the initial connection so we can search for users DNs.
    private DirContext serviceContext;
    // Keeps track of usernames to DN's to reduce trips to the LDAP server
    private Map<String, String> usernameToDN = new HashMap<>();

    private static final byte NUL = 0;

    /**
     * Cache to reduce trips to LDAP server. See {@link CredentialsCache}.
     */
    private CredentialsCache cache;

    private static int getGensaltLogRounds()
    {
        int rounds = Integer.getInteger(GENSALT_LOG2_ROUNDS_PROPERTY, 10);

        if (rounds < 4 || rounds > 31)
        {
            throw new ConfigurationException(String.format(
                "Bad value for system property -D%s. Please use a value between 4 and 31 inclusively",
                GENSALT_LOG2_ROUNDS_PROPERTY));
        }

        return rounds;
    }

    private static String hashpw(String password)
    {
        return BCrypt.hashpw(password, BCrypt.gensalt(GENSALT_LOG2_ROUNDS));
    }

    /**
     * Checks if passwords are same.
     *
     * @param firstPassword  plaintext password
     * @param secondPassword possibly hashed password
     * @return true if passwords equal, false otherwise
     */
    protected static boolean checkpw(String firstPassword, String secondPassword)
    {
        if (hashPassword)
        {
            try
            {
                return BCrypt.checkpw(firstPassword, secondPassword);
            }
            catch (Exception ex)
            {
                // Improperly formatted hashes may cause BCrypt.checkpw to throw, so trap any other exception as a failure
                logger.warn("Error: invalid password hash encountered, rejecting user.", ex);

                return false;
            }
        }
        else
        {
            return firstPassword.equals(secondPassword);
        }
    }

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

        properties = new Properties();

        properties.put(Context.SECURITY_AUTHENTICATION, "simple");
        properties.put("com.sun.jndi.ldap.read.timeout", "1000");
        properties.put("com.sun.jndi.ldap.connect.timeout", "2000");
        properties.put("com.sun.jndi.ldap.connect.pool", "true");

        final String cassandraConfEnvProperty = System.getenv().get("CASSANDRA_CONF");

        File defaultLdapPropertyFile = null;

        if (cassandraConfEnvProperty != null)
        {
            defaultLdapPropertyFile = new File(cassandraConfEnvProperty, "ldap.properties");
        }

        final File ldapPropertyFile = new File(System.getProperty(LDAP_PROPERTIES_FILE, LDAP_PROPERTIES_FILENAME));

        File finalLdapPropertyFile = null;

        if (ldapPropertyFile.exists() && ldapPropertyFile.canRead())
        {
            finalLdapPropertyFile = ldapPropertyFile;
        }
        else if (defaultLdapPropertyFile != null && defaultLdapPropertyFile.exists() && defaultLdapPropertyFile.canRead())
        {
            finalLdapPropertyFile = defaultLdapPropertyFile;
        }

        if (finalLdapPropertyFile == null)
        {
            throw new ConfigurationException(String.format(
                "Unable to locate readable LDAP configuration file from system property %s nor from $CASSANDRA_CONF/ldap.properties.",
                LDAP_PROPERTIES_FILE));
        }
        else
        {
            logger.info("LDAP configuration file: {}", finalLdapPropertyFile.getAbsoluteFile());
        }

        try (FileInputStream input = new FileInputStream(finalLdapPropertyFile))
        {
            properties.load(input);
        }
        catch (IOException ex)
        {
            throw new ConfigurationException(String.format("Could not open ldap configuration file %s", finalLdapPropertyFile), ex);
        }

        if (!properties.containsKey(LDAP_URI_PROP))
        {
            throw new ConfigurationException(String.format("%s MUST be set in the configuration file %s",
                                                           LDAP_URI_PROP,
                                                           finalLdapPropertyFile.getAbsolutePath()));
        }

        serviceDN = properties.getProperty(LDAP_DN);
        servicePass = properties.getProperty(PASSWORD_KEY);

        if (!Boolean.parseBoolean(properties.getProperty(ANONYMOUS_ACCESS_PROP, "false"))) {

            if (serviceDN == null || servicePass == null)
            {
                throw new ConfigurationException(String.format("You must specify both %s and %s if %s is false.",
                                                               LDAP_DN,
                                                               PASSWORD_KEY,
                                                               ANONYMOUS_ACCESS_PROP));
            }
        }

        properties.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(CONTEXT_FACTORY_PROP, DEFAULT_CONTEXT_FACTORY));
        properties.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));
    }

    public void setup()
    {

        if (!(CassandraAuthorizer.class.isAssignableFrom(DatabaseDescriptor.getAuthorizer().getClass())))
        {
            throw new ConfigurationException("LDAPAuthenticator only works with CassandraAuthorizer");
        }

        state = ClientState.forInternalCalls();

        if (DatabaseDescriptor.getAuthorizer().requireAuthorization())
        {
            try
            {
                state.login(new AuthenticatedUser(DEFAULT_SUPERUSER_NAME));
            }
            catch (AuthenticationException ex)
            {
                // If we got here it was likely the first node in the clusters first startup, and we need to
                // sleep to ensure superuser and auth has been set up before we try login.
                Uninterruptibles.sleepUninterruptibly(20,
                                                      TimeUnit.SECONDS);

                try
                {
                    state.login(new AuthenticatedUser(DEFAULT_SUPERUSER_NAME));
                }
                catch (AuthenticationException aex)
                {
                    throw new ConfigurationException("Unable to perform initial login: " + ex.getMessage(), ex);
                }
            }
        }

        try
        {
            if (Boolean.parseBoolean(properties.getProperty(ANONYMOUS_ACCESS_PROP, "false")))
            {
                // Anonymous
                serviceContext = new InitialDirContext(properties);
                state.login(new AuthenticatedUser(DEFAULT_SERVICE_ROLE));
            }
            else
            {
                properties.put(Context.SECURITY_PRINCIPAL, serviceDN);
                properties.put(Context.SECURITY_CREDENTIALS, servicePass);

                serviceContext = new InitialDirContext(properties);

                if (!userExists(serviceDN))
                {
                    QueryProcessor
                        .process(String.format("INSERT INTO %s.%s (role, is_superuser, can_login) VALUES ('%s', true, true)",
                                               SchemaConstants.AUTH_KEYSPACE_NAME,
                                               AuthKeyspace.ROLES,
                                               serviceDN),
                                 ConsistencyLevel.QUORUM);
                }

                state.login(new AuthenticatedUser(serviceDN));
            }
        }
        catch (NamingException ex)
        {
            throw new ConfigurationException("Failed to connect to LDAP server.", ex);
        }

        if (Boolean.parseBoolean(properties.getProperty(CACHE_HASHED_PASSWORD_PROP, "false")))
        {
            hashPassword = true;
        }

        cache = new CredentialsCache();
    }

    /**
     * Generate a table of properties for connecting to LDAP server using JNDI
     *
     * @return Table containing {@link Context#INITIAL_CONTEXT_FACTORY}, {@link Context#PROVIDER_URL} and {@link Context#SECURITY_AUTHENTICATION} set.
     */
    private Hashtable<String, String> getUserEnv()
    {
        Hashtable<String, String> env = new Hashtable<>(11);

        env.put(Context.INITIAL_CONTEXT_FACTORY, "com.sun.jndi.ldap.LdapCtxFactory");
        env.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));
        env.put(Context.SECURITY_AUTHENTICATION, "simple");

        return env;
    }

    /**
     * Fetch a DN for a specific user
     *
     * @param user Username (CN)
     * @return DN for user
     */
    private String getUid(String user) throws NamingException
    {
        if (usernameToDN.containsKey(user))
        {
            return usernameToDN.get(user);
        }

        if (serviceContext == null)
        {
            throw new ConfigurationException("LDAP server connection was not initialised.");
        }

        logger.debug("Connected to LDAP server {}", properties.get(LDAP_URI_PROP));

        final String filter = String.format("(%s=%s)",
                                            properties.getOrDefault(NAMING_ATTRIBUTE_PROP, "cn"),
                                            user);

        final SearchControls searchControls = new SearchControls();
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        final NamingEnumeration answer = serviceContext.search("", filter, searchControls);

        String dn = null;

        if (answer.hasMore())
        {
            SearchResult result = (SearchResult) answer.next();
            dn = result.getNameInNamespace();
        }

        answer.close();

        usernameToDN.put(user, dn);

        return dn;
    }

    /**
     * Authenticate to LDAP server as provided DN.
     *
     * @param user {@link User} to authenticate
     * @return password of user
     * @throws LDAPAuthFailedException if authentication fails or other error occurs.
     */
    private String authDN(User user) throws LDAPAuthFailedException
    {
        final Hashtable env = getUserEnv();

        env.put(Context.SECURITY_PRINCIPAL, user.username);
        env.put(Context.SECURITY_CREDENTIALS, user.password);

        DirContext ctx = null;

        try
        {
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

        if (hashPassword)
        {
            return hashpw(user.password);
        }
        else
        {
            return user.password;
        }
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
            String dn = getUid(username);

            if (dn == null)
            {
                throw new AuthenticationException("Could not authenticate to directory server using provided credentials");
            }

            logger.trace("DN for user {}: {}", username, dn);

            final User user = new User(dn, password);

            final String cachedPassword = cache.get(user);

            // authDN will be called if we're not in cache, subsequently loading the cache for the given user.
            if (cachedPassword != null)
            {
                if (!checkpw(password, cachedPassword))
                {
                    // Password has changed, re-auth and store new password in cache (or fail). A bit dodgy because
                    // we don't have access to cache.put(). This has a side-effect that a bad auth will invalidate the
                    // cache for the user and the next auth for the user will have to re-populate the cache. tl;dr:
                    // don't spam incorrect passwords (or let others spam them for your user).
                    cache.invalidate(user);
                    cache.get(user);
                }

                if (!userExists(dn))
                {
                    logger.debug("DN {} doesn't exist in {}.{}, creating new user",
                                 dn,
                                 SchemaConstants.AUTH_KEYSPACE_NAME,
                                 AuthKeyspace.ROLES);
                    createRole(dn);
                }

                return new AuthenticatedUser(dn);
            }
        }
        catch (UncheckedExecutionException ex)
        {
            if (ex.getCause() instanceof LDAPAuthFailedException)
            {
                LDAPAuthFailedException ldex = (LDAPAuthFailedException) ex.getCause();

                logger.warn("Failed login from {}, reason was {}", username, ex.getMessage());

                throw new AuthenticationException(String.format(
                    "Failed to authenticate with directory server, user may not exist: %s",
                    ldex.getMessage()));
            }
            else
            {
                throw ex;
            }
        }
        catch (NamingException | ExecutionException ex)
        {
            throw new SecurityException(String.format("Could not authenticate to the LDAP directory: %s", ex.getMessage()), ex);
        }

        return null; // should never be reached
    }

    private static void createRole(String dn)
    {
        final String CREATE_ROLE_STMT = "CREATE ROLE \"%s\" WITH LOGIN = true";

        CreateRoleStatement createStmt =
            (CreateRoleStatement) QueryProcessor.getStatement(String.format(CREATE_ROLE_STMT, dn), state).statement;

        final ResultMessage result = createStmt.execute(new QueryState(state),
                                                        QueryOptions.forInternalCalls(ConsistencyLevel.LOCAL_ONE,
                                                                                      Lists.newArrayList(ByteBufferUtil
                                                                                                             .bytes(dn))),
                                                        System.nanoTime());

        if (!result.getWarnings().isEmpty())
        {
            for (final String warning : result.getWarnings())
            {
                logger.warn("Warning emitted from create role method: {}", warning);
            }
        }
    }

    /**
     * Check if a particular role exists in system.auth
     *
     * @param dn user's distinguished name.
     * @return True if DN exists in C* roles otherwise false
     */
    private boolean userExists(String dn)
    {
        // To avoid doing a select every auth we store previously checked users in mem
        if (existingUsers.contains(dn))
        {
            return true;
        }

        final String FIND_USER_STMT = "SELECT %s FROM %s.%s where role = ?";

        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(String.format(FIND_USER_STMT,
                                                                                                    ROLE,
                                                                                                    SchemaConstants.AUTH_KEYSPACE_NAME,
                                                                                                    AuthKeyspace.ROLES),
                                                                                      state).statement;

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(state),
                                                        QueryOptions.forInternalCalls(ConsistencyLevel.LOCAL_ONE,
                                                                                      Lists.newArrayList(ByteBufferUtil
                                                                                                             .bytes(dn))),
                                                        System.nanoTime());

        if (rows.result.isEmpty())
        {
            return false;
        }
        else
        {
            existingUsers.add(dn);
            return true;
        }
    }

    public SaslNegotiator newSaslNegotiator(InetAddress clientAddress)
    {
        return new PlainTextSaslAuthenticator();
    }

    public AuthenticatedUser legacyAuthenticate(Map<String, String> credentials) throws AuthenticationException
    {
        final String username = credentials.get(LDAP_DN);

        if (username == null)
        {
            throw new AuthenticationException(String.format("Required key '%s' is missing", LDAP_DN));
        }

        final String password = credentials.get(PASSWORD_KEY);

        if (password == null)
        {
            throw new AuthenticationException(String.format("Required key '%s' is missing for provided username %s",
                                                            PASSWORD_KEY,
                                                            username));
        }

        return authenticate(username, password);
    }

    public class PlainTextSaslAuthenticator implements SaslNegotiator
    {
        private boolean complete = false;
        private String username;
        private String password;

        public byte[] evaluateResponse(byte[] clientResponse) throws AuthenticationException
        {
            decodeCredentials(clientResponse);
            complete = true;
            return null;
        }

        public boolean isComplete()
        {
            return complete;
        }

        public AuthenticatedUser getAuthenticatedUser() throws AuthenticationException
        {
            if (!complete)
            {
                throw new AuthenticationException("SASL negotiation not complete");
            }

            return authenticate(username, password);
        }

        /**
         * SASL PLAIN mechanism specifies that credentials are encoded in a
         * sequence of UTF-8 bytes, delimited by 0 (US-ASCII NUL).
         * The form is : {code}authzId<NUL>authnId<NUL>password<NUL>{code}
         * authzId is optional, and in fact we don't care about it here as we'll
         * set the authzId to match the authnId (that is, there is no concept of
         * a user being authorized to act on behalf of another with this IAuthenticator).
         *
         * @param bytes encoded credentials string sent by the client
         * @throws org.apache.cassandra.exceptions.AuthenticationException if either the
         *                                                                 authnId or password is null
         */
        private void decodeCredentials(byte[] bytes) throws AuthenticationException
        {
            logger.trace("Decoding credentials from client token");

            byte[] user = null;
            byte[] pass = null;

            int end = bytes.length;

            for (int i = bytes.length - 1; i >= 0; i--)
            {
                if (bytes[i] == NUL)
                {
                    if (pass == null)
                        pass = Arrays.copyOfRange(bytes, i + 1, end);
                    else if (user == null)
                        user = Arrays.copyOfRange(bytes, i + 1, end);
                    end = i;
                }
            }

            if (pass == null)
                throw new AuthenticationException("Password must not be null");

            if (user == null)
                throw new AuthenticationException("Authentication ID must not be null");

            username = new String(user, StandardCharsets.UTF_8);
            password = new String(pass, StandardCharsets.UTF_8);
        }
    }

    public class CredentialsCache extends AuthCache<User, String> implements CredentialsCacheMBean
    {

        private CredentialsCache()
        {
            super("CredentialsCache",
                  DatabaseDescriptor::setCredentialsValidity,
                  DatabaseDescriptor::getCredentialsValidity,
                  DatabaseDescriptor::setCredentialsUpdateInterval,
                  DatabaseDescriptor::getCredentialsUpdateInterval,
                  DatabaseDescriptor::setCredentialsCacheMaxEntries,
                  DatabaseDescriptor::getCredentialsCacheMaxEntries,
                  LDAPAuthenticator.this::authDN,
                  () -> true);
        }

        public void invalidateCredentials(String username)
        {
            invalidate(new User(username, ""));
        }
    }

    public interface CredentialsCacheMBean extends AuthCacheMBean
    {
        void invalidateCredentials(String username);
    }

    public static class User
    {
        public final String username;

        public final String password;

        User(String name, String pass)
        {
            username = name;
            password = pass;
        }

        @Override
        public boolean equals(Object obj)
        {
            if (obj == null)
                return false;

            final User other = (User) obj;

            return this.username.equals(other.username);
        }

        @Override
        public int hashCode()
        {
            return new HashCodeBuilder(19, 29)
                .append(username)
                .toHashCode();
        }
    }

    public static class LDAPAuthFailedException extends RequestExecutionException
    {

        public LDAPAuthFailedException(ExceptionCode code, String msg, Throwable t)
        {
            super(code, msg, t);
        }
    }
}
