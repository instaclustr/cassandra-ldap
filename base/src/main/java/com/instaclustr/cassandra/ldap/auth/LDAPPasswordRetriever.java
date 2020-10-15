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

import java.util.Properties;

import com.instaclustr.cassandra.ldap.hash.Hasher;
import org.apache.cassandra.exceptions.ConfigurationException;
import org.apache.cassandra.service.ClientState;

public abstract class LDAPPasswordRetriever implements PasswordRetriever
{

    protected ClientState clientState;
    protected Hasher hasher;
    protected Properties properties;

    public void close()
    {

    }

    public abstract void setup() throws ConfigurationException;

    public void init(ClientState clientState)
    {
        this.clientState = clientState;
    }

    public void init(ClientState clientState, Hasher hasher, Properties properties)
    {
        this.init(clientState);
        this.clientState = clientState;
        this.hasher = hasher;
        this.properties = properties;

        setup();
    }
}
