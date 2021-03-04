package com.instaclustr.cassandra.ldap.auth;

import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_ELIGIBILITY_CHECK_ACCESS_COLUMN;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_ELIGIBILITY_CHECK_KEYSPACE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_ELIGIBILITY_CHECK_TABLE;
import static com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration.CASSANDRA_ELIGIBILITY_CHECK_USER_COLUMN;

import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import com.instaclustr.cassandra.ldap.conf.LdapAuthenticatorConfiguration;
import org.apache.cassandra.serializers.BooleanSerializer;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public abstract class BaseCassandraLoginEligibilityCheck implements LoginEligibilityCheck
{
    private static final Logger logger = LoggerFactory.getLogger(BaseCassandraLoginEligibilityCheck.class);

    private static final String BASE_SELECT_USER_STATEMENT_TEMPLATE = "select %s from %s.%s where %s = ?";

    protected ClientState clientState;
    protected Properties configProperties;
    protected String selectStatement;

    @Override
    public void init(final ClientState clientState, final Properties configProperties)
    {
        this.clientState = clientState;
        this.configProperties = configProperties;

        this.selectStatement = String.format(BASE_SELECT_USER_STATEMENT_TEMPLATE,
                                             configProperties.getProperty(CASSANDRA_ELIGIBILITY_CHECK_ACCESS_COLUMN),
                                             configProperties.getProperty(CASSANDRA_ELIGIBILITY_CHECK_KEYSPACE),
                                             configProperties.getProperty(CASSANDRA_ELIGIBILITY_CHECK_TABLE),
                                             configProperties.getProperty(CASSANDRA_ELIGIBILITY_CHECK_USER_COLUMN));

    }

    protected abstract ResultMessage.Rows getRows(final String loginName);

    @Override
    public boolean isEligibleToLogin(final User user, final String loginName)
    {

        // all non-ldap users are free to log in just fine
        if (user.getLdapDN() == null)
        {
            return true;
        }

        assert clientState != null;

        final ResultMessage.Rows rows = getRows(loginName);

        final boolean noResults = rows.result.isEmpty();

        if (noResults)
        {
            logger.debug(String.format("User with login name '%s' is not eligible to be logged in!", loginName));
            return false;
        }

        if (rows.result.size() != 1)
        {
            throw new IllegalStateException("There was more than one record returned from eligibility check select query!");
        }

        if (rows.result.rows.get(0).size() != 1)
        {
            throw new IllegalStateException("There was more than one column returned from eligibility check select query!");
        }

        if (BooleanSerializer.instance.deserialize(rows.result.rows.get(0).get(0)))
        {
            logger.debug(String.format("User with login name '%s' is eligible to be logged in!", loginName));
            return true;
        }

        logger.debug(String.format("User with login name '%s' is not eligible to be logged in!", loginName));
        return false;
    }
}
