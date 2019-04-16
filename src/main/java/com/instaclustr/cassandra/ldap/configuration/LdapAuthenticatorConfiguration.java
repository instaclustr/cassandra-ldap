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
package com.instaclustr.cassandra.ldap.configuration;

import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

import javax.naming.Context;

import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * Properties loaded from ldap.properties file.
 */
public final class LdapAuthenticatorConfiguration
{
    private static final Logger logger = LoggerFactory.getLogger(LdapAuthenticatorConfiguration.class);

    public static final String LDAP_PROPERTIES_FILE_PROP = "cassandra.ldap.properties.file";
    public static final String LDAP_PROPERTIES_FILENAME = "ldap.properties";

    // Ldap URI including DN
    public static final String LDAP_URI_PROP = "ldap_uri";
    public static final String CONTEXT_FACTORY_PROP = "context_factory";
    // Initial connection to LDAP can be anonymous if it's enabled. Won't allow you to connect to C* anonymously.
    public static final String ANONYMOUS_ACCESS_PROP = "anonymous_access";

    // If no anonymous access a default DN and password is required.
    public static final String LDAP_DN = "service_dn";
    public static final String PASSWORD_KEY = "service_password";

    // Just to support those not using "cn"
    public static final String NAMING_ATTRIBUTE_PROP = "ldap_naming_attribute";

    public static final String CASSANDRA_AUTH_CACHE_ENABLED_PROP = "auth_cache_enabled";

    // system properties not meant to be in configuration file but specified as -D property

    public static final String INITIAL_CASSANDRA_LOGIN_ATTEMPTS_PROP = "cassandra.ldap_cassandra_initial_login_attempts";
    public static final String INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_PROP = "cassandra.ldap_cassandra_initial_login_attemp_period";

    public static final int INITIAL_CASSANDRA_LOGIN_ATTEMPTS = getLdapCassandraInitialLoginAttempts();
    public static final int INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD = getLdapCassandraInitialLoggingAttemptPeriod();

    public static final int INITIAL_CASSANDRA_LOGIN_ATTEMPTS_DEFAULT = 10;
    public static final int INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_IN_SECONDS_DEFAULT = 5;

    public static final String GENSALT_LOG2_ROUNDS_PROP = "cassandra.auth_bcrypt_gensalt_log2_rounds";
    public static final int GENSALT_LOG2_ROUNDS_DEFAULT = 10;

    public static int GENSALT_ROUNDS = getGensaltLog2Rounds();

    public final static String DEFAULT_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";
    public final static String DEFAULT_SERVICE_ROLE = "_LDAPAUTH_";
    public final static String DEFAULT_SUPERUSER_NAME = "cassandra";

    public Properties parseProperties() throws ConfigurationException
    {
        Properties properties = new Properties();

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

        final File ldapPropertyFile = new File(System.getProperty(LDAP_PROPERTIES_FILE_PROP, LDAP_PROPERTIES_FILENAME));

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
            throw new ConfigurationException(format(
                "Unable to locate readable LDAP configuration file from system property %s nor from $CASSANDRA_CONF/ldap.properties.",
                LDAP_PROPERTIES_FILE_PROP));
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
            throw new ConfigurationException(format("Could not open ldap configuration file %s", finalLdapPropertyFile), ex);
        }

        if (!properties.containsKey(LDAP_URI_PROP))
        {
            throw new ConfigurationException(format("%s MUST be set in the configuration file %s",
                                                    LDAP_URI_PROP,
                                                    finalLdapPropertyFile.getAbsolutePath()));
        }

        String serviceDN = properties.getProperty(LDAP_DN);
        String servicePass = properties.getProperty(PASSWORD_KEY);

        if (!parseBoolean(properties.getProperty(ANONYMOUS_ACCESS_PROP, "false")))
        {

            if (serviceDN == null || servicePass == null)
            {
                throw new ConfigurationException(format("You must specify both %s and %s if %s is false.",
                                                        LDAP_DN,
                                                        PASSWORD_KEY,
                                                        ANONYMOUS_ACCESS_PROP));
            }
        }

        properties.put(Context.INITIAL_CONTEXT_FACTORY, properties.getProperty(CONTEXT_FACTORY_PROP, DEFAULT_CONTEXT_FACTORY));
        properties.put(Context.PROVIDER_URL, properties.getProperty(LDAP_URI_PROP));

        properties.setProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP, Boolean.toString(parseBoolean(properties.getProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP, "true"))));

        return properties;
    }

    private static int getGensaltLog2Rounds()
    {
        int rounds = Integer.getInteger(GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT);

        if (rounds < 4 || rounds > 31)
        {
            throw new ConfigurationException(format("Bad value for system property -D%s. Please use a value between 4 and 31 inclusively",
                                                    GENSALT_LOG2_ROUNDS_PROP));
        }

        return rounds;
    }

    private static int getLdapCassandraInitialLoginAttempts()
    {
        int readValue = Integer.getInteger(INITIAL_CASSANDRA_LOGIN_ATTEMPTS_PROP, INITIAL_CASSANDRA_LOGIN_ATTEMPTS_DEFAULT);

        if (readValue < 2)
        {
            throw new ConfigurationException(format("Bad value for system property -D%s. Please use value bigger then 1.",
                                                    INITIAL_CASSANDRA_LOGIN_ATTEMPTS_PROP));
        }

        return readValue;
    }

    private static int getLdapCassandraInitialLoggingAttemptPeriod()
    {
        int readValue = Integer.getInteger(INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_PROP, INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_IN_SECONDS_DEFAULT);

        if (readValue < INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_IN_SECONDS_DEFAULT)
        {
            throw new ConfigurationException(format("Bad value for system property -D%s in seconds. Please use value bigger then 5.",
                                                    INITIAL_CASSANDRA_LOGIN_ATTEMPT_PERIOD_PROP));
        }

        return readValue;
    }
}
