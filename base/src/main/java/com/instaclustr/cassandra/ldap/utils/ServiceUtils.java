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
package com.instaclustr.cassandra.ldap.utils;

import static java.lang.String.format;
import static java.util.stream.Collectors.joining;

import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.ServiceLoader;

import org.apache.cassandra.exceptions.ConfigurationException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class ServiceUtils
{

    private static final Logger logger = LoggerFactory.getLogger(ServiceUtils.class);

    public static <T> T getService(final Class<T> clazz, final Class<? extends T> defaultImplClazz)
    {
        final ServiceLoader<T> loader = ServiceLoader.load(clazz);
        final Iterator<T> iterator = loader.iterator();
        final List<T> services = new ArrayList<>();

        if (iterator.hasNext())
        {
            services.add(iterator.next());
        }

        if (services.isEmpty())
        {
            if (defaultImplClazz == null)
            {
                throw new IllegalStateException(format("There is no implementation of %s", clazz));
            }

            try
            {
                logger.info(format("Using default implementation of %s: %s", clazz.getName(), defaultImplClazz.getName()));
                return defaultImplClazz.newInstance();
            } catch (InstantiationException | IllegalAccessException e)
            {
                logger.error(format("Unable to instantiate default implementation of %s: %s", clazz.getName(), defaultImplClazz.getName()));
                throw new IllegalStateException(e);
            }
        }

        if (services.size() != 1)
        {
            throw new ConfigurationException(format("More than one or no implementation of %s was found: %s",
                                                    clazz.getName(),
                                                    services.stream().map(impl -> impl.getClass().getName()).collect(joining(","))));
        }

        logger.debug(format("Using implementation of %s: %s", clazz.getName(), services.get(0).getClass().getName()));

        return services.get(0);
    }
}
