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

import org.apache.commons.lang3.builder.HashCodeBuilder;

public class User
{
    private final String username;

    private final String password;

    private String ldapDN = null;

    public User(String username)
    {
        this(username, null);
    }

    public User(String username, String password)
    {
        if (username == null)
            throw new RuntimeException("Username provided to User instance can not be a null object.");

        this.username = username;
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
            return false;

        if (!(obj instanceof User))
            return false;

        if (this == obj)
            return true;

        final User other = (User) obj;

        return this.getUsername().equals(other.getUsername());
    }

    public int hashCode()
    {
        return new HashCodeBuilder(19, 29).append(getUsername()).toHashCode();
    }
}
