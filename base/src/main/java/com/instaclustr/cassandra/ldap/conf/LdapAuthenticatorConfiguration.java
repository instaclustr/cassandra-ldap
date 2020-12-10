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
package com.instaclustr.cassandra.ldap.conf;

import static java.lang.Boolean.parseBoolean;
import static java.lang.String.format;

import javax.naming.Context;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.util.Properties;

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

    // If no anonymous access a default DN and password is required.
    public static final String LDAP_DN = "service_dn";
    public static final String PASSWORD_KEY = "service_password";

    public static final String FILTER_TEMPLATE = "filter_template";

    public static final String CASSANDRA_AUTH_CACHE_ENABLED_PROP = "auth_cache_enabled";

    public static final String GENSALT_LOG2_ROUNDS_PROP = "auth_bcrypt_gensalt_log2_rounds";
    public static final int GENSALT_LOG2_ROUNDS_DEFAULT = 10;

    public static final String DEFAULT_CONTEXT_FACTORY = "com.sun.jndi.ldap.LdapCtxFactory";

    public static final String CASSANDRA_LDAP_ADMIN_USER = "cassandra.ldap.admin.user";

    public static final String CONSISTENCY_FOR_ROLE = "consistency_for_role";
    public static final String DEFAULT_CONSISTENCY_FOR_ROLE = "LOCAL_ONE";

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
        } else if (defaultLdapPropertyFile != null && defaultLdapPropertyFile.exists() && defaultLdapPropertyFile.canRead())
        {
            finalLdapPropertyFile = defaultLdapPropertyFile;
        }

        if (finalLdapPropertyFile == null)
        {
            throw new ConfigurationException(format(
                "Unable to locate readable LDAP configuration file from system property %s nor from $CASSANDRA_CONF/ldap.properties.",
                LDAP_PROPERTIES_FILE_PROP));
        } else
        {
            logger.info("LDAP configuration file: {}", finalLdapPropertyFile.getAbsoluteFile());
        }

        try (FileInputStream input = new FileInputStream(finalLdapPropertyFile))
        {
            properties.load(input);
        } catch (IOException ex)
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

        if (serviceDN == null || servicePass == null)
        {
            throw new ConfigurationException(format("You must specify both %s and %s.", LDAP_DN, PASSWORD_KEY));
        }

        properties.setProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP, Boolean.toString(parseBoolean(properties.getProperty(CASSANDRA_AUTH_CACHE_ENABLED_PROP, "true"))));

        properties.setProperty(CONSISTENCY_FOR_ROLE, properties.getProperty(CONSISTENCY_FOR_ROLE, DEFAULT_CONSISTENCY_FOR_ROLE));

        String filterTemplate = properties.getProperty(FILTER_TEMPLATE, "(cn=%s)");

        if (!filterTemplate.contains("%s"))
        {
            throw new ConfigurationException(String.format("Filter template property %s, has to contain placeholder '\\%s'", filterTemplate));
        }

        properties.setProperty(FILTER_TEMPLATE, filterTemplate);



        properties.put(LdapAuthenticatorConfiguration.CONTEXT_FACTORY_PROP, properties.getProperty(CONTEXT_FACTORY_PROP, DEFAULT_CONTEXT_FACTORY));
        properties.put(LdapAuthenticatorConfiguration.LDAP_URI_PROP, properties.getProperty(LDAP_URI_PROP));

        return properties;
    }

    public static int getGensaltLog2Rounds(Properties properties)
    {

        try
        {
            int rounds = Integer.parseInt(properties.getProperty(GENSALT_LOG2_ROUNDS_PROP, String.valueOf(GENSALT_LOG2_ROUNDS_DEFAULT)));

            if (rounds < 4 || rounds > 31)
            {
                logger.warn(format("Unable to parse %s property, setting it to %s", GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT));

                return GENSALT_LOG2_ROUNDS_DEFAULT;
            }

            return rounds;
        } catch (final NumberFormatException e)
        {
            logger.warn(format("Unable to parse %s property, setting it to %s", GENSALT_LOG2_ROUNDS_PROP, GENSALT_LOG2_ROUNDS_DEFAULT));
            return GENSALT_LOG2_ROUNDS_DEFAULT;
        }
    }
}
