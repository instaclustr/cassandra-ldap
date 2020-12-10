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
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CONSISTENCY_FOR_ROLE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.DEFAULT_CONSISTENCY_FOR_ROLE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static java.lang.String.format;

import java.util.Properties;
import java.util.Set;
import java.util.StringJoiner;
import java.util.concurrent.Callable;
import java.util.concurrent.TimeUnit;

import com.google.common.base.Objects;
import com.google.common.collect.ImmutableSet;
import com.google.common.util.concurrent.Uninterruptibles;
import com.instaclustr.cassandra.ldap.AbstractLDAPAuthenticator;
import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.utils.ServiceUtils;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.UnauthorizedException;
import org.apache.cassandra.service.ClientState;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * CassandraRoleManager by default supports setting passwords only in connection with PasswordAuthenticator.
 */
public class LDAPCassandraRoleManager extends CassandraRoleManager
{

    private static final Logger logger = LoggerFactory.getLogger(LDAPCassandraRoleManager.class);

    private Properties properties;

    private ClientState clientState;

    private ConsistencyLevel roleConsistencyLevel = ConsistencyLevel.LOCAL_ONE;

    private SystemAuthRoles systemAuthRoles;

    @Override
    public void validateConfiguration() throws ConfigurationException
    {
        properties = new LdapAuthenticatorConfiguration().parseProperties();
        roleConsistencyLevel = ConsistencyLevel.valueOf(properties.getProperty(CONSISTENCY_FOR_ROLE, DEFAULT_CONSISTENCY_FOR_ROLE));
    }

    @Override
    public void setup()
    {
        super.setup();

        systemAuthRoles = ServiceUtils.getService(SystemAuthRoles.class, null);

        final String dbaRole = System.getProperty(CASSANDRA_LDAP_ADMIN_USER, "cassandra");
        logger.info("DB admin role is {}", dbaRole);

        final String ldapAdminRole = properties.getProperty(LDAP_DN);
        logger.info("LDAP admin role is {}", ldapAdminRole);

        try
        {
            final Callable<Void> roleManagerSetupCallable = () ->
            {

                if (!systemAuthRoles.hasAdminRole(dbaRole))
                {
                    throw new IllegalStateException("Waiting for " + dbaRole + " role!");
                }

                if (!canLogin(RoleResource.fromName("roles/" + dbaRole)))
                {
                    logger.info("Role '" + dbaRole + "' can not log in, prematurely existing setup, not going to create LDAP admin role {}", ldapAdminRole);
                    return null;
                }

                clientState = ClientState.forInternalCalls();

                clientState.login(new AuthenticatedUser(dbaRole));

                systemAuthRoles.setClientState(clientState);

                if (ldapAdminRole == null || ldapAdminRole.isEmpty())
                {
                    logger.info("Not trying to create LDAP admin role as it is not set in configuration via {} option.", LDAP_DN);
                    return null;
                }

                try
                {
                    if (systemAuthRoles.roleMissing(ldapAdminRole))
                    {
                        systemAuthRoles.createRole(ldapAdminRole, true);
                        logger.info("Created LDAP admin role '{}'", ldapAdminRole);
                    } else
                    {
                        logger.info("Not creating LDAP admin role '{}' as it is already present.", ldapAdminRole);
                    }
                } catch (final Exception ex)
                {
                    logger.trace("Unable to create LDAP admin role.", ex);
                    logger.error("Unable to create LDAP admin role {}", ldapAdminRole);
                    throw ex;
                }

                return null;
            };

            while (true)
            {
                try
                {
                    roleManagerSetupCallable.call();
                    break;
                } catch (final Exception ex)
                {
                    logger.trace("Role manager setup was not successful, sleeping for 5 seconds and trying again ...", ex);
                    Uninterruptibles.sleepUninterruptibly(5, TimeUnit.SECONDS);
                }
            }
        } catch (Exception ex)
        {
            logger.trace("Unable to setup " + LDAPCassandraRoleManager.class.getName(), ex);
            throw new AuthenticationException("Unable to setup " + LDAPCassandraRoleManager.class.getName() + ": " + ex.getMessage());
        }
    }

    @Override
    public Set<Option> supportedOptions()
    {
        return AbstractLDAPAuthenticator.class.isAssignableFrom(DatabaseDescriptor.getAuthenticator().getClass())
            ? ImmutableSet.of(Option.LOGIN, Option.SUPERUSER, Option.PASSWORD)
            : ImmutableSet.of(Option.LOGIN, Option.SUPERUSER);
    }

    @Override
    public boolean canLogin(RoleResource role)
    {
        try
        {
            Role retrievedRole = systemAuthRoles.getRole(role.getRoleName(), roleConsistencyLevel);

            logger.debug(format("Attempting to log in: role: %s, role name: %s, permissions: %s, canLogin: %s, memberOf: %s, isSuper: %s",
                               role.getName(),
                               role.getRoleName(),
                               role.applicablePermissions(),
                               retrievedRole.canLogin,
                               retrievedRole.memberOf,
                               retrievedRole.isSuper));

            return retrievedRole.canLogin;
        }
        catch (RequestExecutionException e)
        {
            logger.debug("Failed to authorize {} for login permission", role.getRoleName());
            throw new UnauthorizedException("Unable to perform authorization of login permission: " + e.getMessage());
        }
    }

    public static final class Role {

        private String name;
        private final boolean isSuper;
        private final boolean canLogin;
        private Set<String> memberOf;

        public Role(String name, boolean isSuper, boolean canLogin, Set<String> memberOf) {
            this.name = name;
            this.isSuper = isSuper;
            this.canLogin = canLogin;
            this.memberOf = memberOf;
        }

        public boolean equals(Object o) {
            if (this == o) {
                return true;
            }

            if (!(o instanceof Role)) {
                return false;
            }

            Role r = (Role) o;
            return Objects.equal(name, r.name);
        }

        public int hashCode() {
            return Objects.hashCode(name);
        }

        @Override
        public String toString() {
            return new StringJoiner(", ", Role.class.getSimpleName() + "[", "]")
                .add("name='" + name + "'")
                .add("isSuper=" + isSuper)
                .add("canLogin=" + canLogin)
                .add("memberOf=" + memberOf)
                .toString();
        }
    }
}
