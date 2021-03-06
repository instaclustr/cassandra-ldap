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
package com.instaclustr.cassandra.ldap.cache;

import java.util.function.Function;

import com.instaclustr.cassandra.ldap.User;

public class CredentialsLoadingFunction implements Function<User, User>
{
    private Function<User, User> passwordAuthLoadingFunction;
    private Function<User, User> ldapAuthLoadingFunction;

    public CredentialsLoadingFunction(final Function<User, User> passwordAuthLoadingFunction,
                                      final Function<User, User> ldapAuthLoadingFunction)
    {
        this.passwordAuthLoadingFunction = passwordAuthLoadingFunction;
        this.ldapAuthLoadingFunction = ldapAuthLoadingFunction;
    }

    @Override
    public User apply(User user)
    {
        try
        {
            return passwordAuthLoadingFunction.apply(user);
        }
        catch (final Exception ex)
        {
            // we are in this catch block because
            // 1) there was not such role found in Cassandra DB hence we have to go against LDAP
            // 2) there was such role but that role does not have password in the database
            //    so we have nothing to check against so we need to do authentication against LDAP.
            //    This happens e.g. with admin user which is created but it does not have its password hashed there since it is in LDAP
            //    This also means what we will be able to login with "cassandra:cassandra" combination without the necessity to ever reach LDAP server.
            //
            // If there is such username and password in the database, we will never reach this catch and
            // from the user's perspective it acts as if there was not any LDAP server at all, we are effectively doing PasswordAuthenticator

            return ldapAuthLoadingFunction.apply(user);
        }
    }
}
