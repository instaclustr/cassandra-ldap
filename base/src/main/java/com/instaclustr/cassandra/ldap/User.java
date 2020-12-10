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

import java.util.StringJoiner;

import org.apache.commons.lang3.builder.HashCodeBuilder;

public class User
{

    private String username;

    private String password;

    private String ldapDN = null;

    public User(String username)
    {
        this(username, null);
    }

    public User(String username, String password)
    {
        if (username == null)
        {
            throw new RuntimeException("Username provided to User instance can not be a null object.");
        }

        this.username = username;
        this.password = password;
    }

    public void setUsername(final String username) {
        this.username = username;
    }

    public void setPassword(final String password) {
        this.password = password;
    }

    public String getLdapDN()
    {
        return ldapDN;
    }

    public void setLdapDN(String ldapDN)
    {
        this.ldapDN = ldapDN;
    }

    public String getUsername()
    {
        return ldapDN == null ? username : ldapDN;
    }

    public String getPassword()
    {
        return password;
    }

    public boolean equals(Object obj)
    {
        if (obj == null)
        {
            return false;
        }

        if (!(obj instanceof User))
        {
            return false;
        }

        if (this == obj)
        {
            return true;
        }

        final User other = (User) obj;

        if (this.ldapDN != null && other.ldapDN != null)
        {
            return this.ldapDN.equals(other.ldapDN);
        }
        else if (this.username != null && other.username != null)
        {
            return this.username.equals(other.username);
        }

        return false;
    }

    public int hashCode()
    {
        if (ldapDN != null)
        {
            return new HashCodeBuilder(19, 29).append(ldapDN).toHashCode();
        }

        assert username != null;

        return new HashCodeBuilder(19, 29).append(username).toHashCode();
    }

    @Override
    public String toString() {
        return new StringJoiner(", ", User.class.getSimpleName() + "[", "]")
            .add("username='" + username + "'")
            .add("password=redacted")
            .add("ldapDN='" + ldapDN + "'")
            .toString();
    }
}
