package com.instaclustr.cassandra.ldap.cache;

import java.util.function.Function;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cassandra3CacheDelegate implements CacheDelegate
{

    private AuthCache<User, String> cache;

    @Override
    public void invalidate(final User user)
    {
        assert cache != null;
        this.cache.invalidate(user);
    }

    @Override
    public String get(final User user)
    {
        assert cache != null;
        return this.cache.get(user);
    }

    @Override
    public void init(final Function<User, String> loadingFunction, final boolean enableCache)
    {
        if (this.cache != null)
        {
            return;
        }

        this.cache = new CredentialsCache(loadingFunction, enableCache);
    }

    @Override
    public void init(final Function<User, String> passwordAuthLoadingFunction,
                     final Function<User, String> ldapAuthLoadingFunction,
                     final String namingAttributeValue,
                     final boolean enableCache)
    {
        if (this.cache != null)
        {
            return;
        }

        final Function<User, String> loadingFunction = new CredentialsLoadingFunction(passwordAuthLoadingFunction,
                                                                                      ldapAuthLoadingFunction,
                                                                                      namingAttributeValue);

        init(loadingFunction, enableCache);
    }

    private static class CredentialsCache extends AuthCache<User, String> implements CredentialsCacheMBean
    {

        private static final Logger logger = LoggerFactory.getLogger(CredentialsCache.class);

        public CredentialsCache(Function<User, String> loadingFunction, boolean enableCache)
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
                      logger.info(String.format("Using %s, enabled: %s", CredentialsCache.class.getCanonicalName(), enableCache));

                      return enableCache;
                  });
        }

        public void invalidateCredentials(String username)
        {
            invalidate(new User(username));
        }
    }
}
