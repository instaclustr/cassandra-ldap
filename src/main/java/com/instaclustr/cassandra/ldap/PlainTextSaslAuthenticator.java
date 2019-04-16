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

import static java.nio.charset.StandardCharsets.UTF_8;

import java.util.Arrays;

import org.apache.cassandra.auth.AuthenticatedUser;
import org.apache.cassandra.auth.IAuthenticator;
import org.apache.cassandra.exceptions.AuthenticationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class PlainTextSaslAuthenticator implements IAuthenticator.SaslNegotiator
{
    private static final Logger logger = LoggerFactory.getLogger(PlainTextSaslAuthenticator.class);

    private LDAPAuthenticator ldapAuthenticator;

    private boolean complete = false;

    private String username;
    private String password;

    public PlainTextSaslAuthenticator(LDAPAuthenticator ldapAuthenticator)
    {
        this.ldapAuthenticator = ldapAuthenticator;
    }

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

        return ldapAuthenticator.authenticate(username, password);
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
     * @throws AuthenticationException if either the
     *                                 authnId or password is null
     */
    private void decodeCredentials(byte[] bytes) throws AuthenticationException
    {
        logger.trace("Decoding credentials from client token");

        byte[] user = null;
        byte[] pass = null;

        int end = bytes.length;

        for (int i = bytes.length - 1; i >= 0; i--)
        {
            if (bytes[i] == 0)
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

        username = new String(user, UTF_8);
        password = new String(pass, UTF_8);
    }
}
