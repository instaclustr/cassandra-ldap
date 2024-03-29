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
package com.instaclustr.cassandra.ldap.hash;

import org.mindrot.jbcrypt.BCrypt;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class HasherImpl implements Hasher
{

    private static final Logger logger = LoggerFactory.getLogger(HasherImpl.class);

    @Override
    public String hashPassword(String password, int rounds)
    {
        return BCrypt.hashpw(password, BCrypt.gensalt(rounds));
    }

    @Override
    public boolean checkPasswords(String plaintext, String hashed)
    {
        try
        {
            return BCrypt.checkpw(plaintext, hashed);
        } catch (Exception ex)
        {
            // Improperly formatted hashes may cause BCrypt.checkpw to throw, so trap any other exception as a failure
            logger.warn("Error: invalid password hash encountered, rejecting user.", ex);

            return false;
        }
    }
}
