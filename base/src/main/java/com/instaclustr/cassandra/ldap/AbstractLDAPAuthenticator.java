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

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.LDAP_DN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.PASSWORD_KEY;
import static java.lang.String.format;

import java.util.Collections;
import java.util.Map;
import java.util.Properties;
import java.util.Set;

import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import com.instaclustr.cassandra.ldap.hash.Hasher;
import com.instaclustr.cassandra.ldap.hash.HasherImpl;
import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.auth.IResource;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public abstract class AbstractLDAPAuthenticator implements IAuthenticator
{

    protected Properties properties;

    protected SystemAuthRoles systemAuthRoles;

    protected static final Hasher hasher = new HasherImpl();

    protected ClientState clientState;

    public abstract AuthenticatedUser authenticate(String username, String password);

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

    @Override
    public AuthenticatedUser legacyAuthenticate(final Map<String, String> credentials) throws AuthenticationException
    {
        return authenticate(credentials.get("username"), credentials.get("password"));
    }
}
