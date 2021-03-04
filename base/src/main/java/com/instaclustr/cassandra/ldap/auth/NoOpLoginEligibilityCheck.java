package com.instaclustr.cassandra.ldap.auth;

import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.service.ClientState;

public final class NoOpLoginEligibilityCheck implements LoginEligibilityCheck
{

    @Override
    public void init(final ClientState clientState, final Properties properties)
    {

    }

    @Override
    public boolean isEligibleToLogin(final User user, final String loginName)
    {
        return true;
    }
}
