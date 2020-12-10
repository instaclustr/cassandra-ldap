package com.instaclustr.cassandra.ldap.cache;

import java.util.function.Function;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.auth.AuthCache;
import org.apache.cassandra.config.DatabaseDescriptor;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cassandra3CacheDelegate implements CacheDelegate
{
    private static final Logger logger = LoggerFactory.getLogger(Cassandra3CacheDelegate.class);

    private AuthCache<User, User> cassandraCache;
    private AuthCache<User, User> ldapCache;

    @Override
    public void invalidate(final User user)
    {
        assert cassandraCache != null;
        this.cassandraCache.invalidate(user);
        this.ldapCache.invalidate(user);
    }

    @Override
    public User get(final User user)
    {
        assert cassandraCache != null;
        assert ldapCache != null;

        try
        {
            try
            {
                User cassandraUser = this.cassandraCache.get(user);

                if (cassandraUser != null)
                {
                    logger.debug("Fetching user from Cassandra: " + user.toString());
                    return cassandraUser;
                }
            } catch (final Exception ex)
            {
                logger.trace("{} not found in Cassandra", user);
            }

            User ldapUser = this.ldapCache.get(user);

            logger.debug("{} fetched user from LDAP", ldapUser);

            return ldapUser;
        } catch (final Exception ex)
        {
            throw new RuntimeException(ex);
        }
    }

    @Override
    public void init(final Function<User, User> cassandraLoadingFunction,
                     final Function<User, User> ldapLoadingFunction,
                     final boolean enableCache)
    {
        if (this.cassandraCache != null && this.ldapCache != null)
        {
            return;
        }

        this.cassandraCache = new CredentialsCache(cassandraLoadingFunction, "CredentialsCache", enableCache);
        this.ldapCache = new CredentialsCache(ldapLoadingFunction, "LdapCredentialsCache", enableCache);
    }

    private static class CredentialsCache extends AuthCache<User, User> implements CredentialsCacheMBean
    {

        private static final Logger logger = LoggerFactory.getLogger(CredentialsCache.class);

        public CredentialsCache(Function<User, User> loadingFunction, String cacheName, boolean enableCache)
        {
            super(cacheName,
                  DatabaseDescriptor::setCredentialsValidity,
                  DatabaseDescriptor::getCredentialsValidity,
                  DatabaseDescriptor::setCredentialsUpdateInterval,
                  DatabaseDescriptor::getCredentialsUpdateInterval,
                  DatabaseDescriptor::setCredentialsCacheMaxEntries,
                  DatabaseDescriptor::getCredentialsCacheMaxEntries,
                  loadingFunction,
                  () ->
                  {
                      logger.info(String.format("Using cache %s, enabled: %s", cacheName, enableCache));

                      return enableCache;
                  });
        }

        public void invalidateCredentials(String username)
        {
            invalidate(new User(username));
        }
    }
}
