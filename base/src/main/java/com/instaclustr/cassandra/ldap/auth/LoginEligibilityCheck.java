package com.instaclustr.cassandra.ldap.auth;

import java.util.Properties;

import com.instaclustr.cassandra.ldap.User;
import org.apache.cassandra.service.ClientState;

public interface LoginEligibilityCheck
{

    void init(final ClientState clientState, final Properties configProperties);

    boolean isEligibleToLogin(final User user, final String loginName);

}
