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

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class CredentialsCache extends AuthCache<User, String> implements CredentialsCacheMBean
{
    private static final Logger logger = LoggerFactory.getLogger(CredentialsCache.class);

    public CredentialsCache(CredentialsCacheLoadingFunction loadingFunction, boolean enableCache)
    {
        super("CredentialsCache",
              DatabaseDescriptor::setCredentialsValidity,
              DatabaseDescriptor::getCredentialsValidity,
              DatabaseDescriptor::setCredentialsUpdateInterval,
              DatabaseDescriptor::getCredentialsUpdateInterval,
              DatabaseDescriptor::setCredentialsCacheMaxEntries,
              DatabaseDescriptor::getCredentialsCacheMaxEntries,
              loadingFunction,
              () ->
              {
                  logger.info(String.format("Using %s: %s", CredentialsCache.class.getCanonicalName(), enableCache));

                  return enableCache;
              });
    }

    public void invalidateCredentials(String username)
    {
        invalidate(new User(username));
    }
}
