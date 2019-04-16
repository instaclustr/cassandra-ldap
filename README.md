LDAP Authenticator for Apache Cassandra
=======================================

This is a pluggable authentication implementation for Apache Cassandra, providing a way to authenticate and create users based on a configured LDAP server.
This implementation purely provides authentication only. Role management must be performed through the usual Cassandra role management, CassandraAuthorizer. See **How it works** for more details.

Building
========

The JAR is released to Maven Central. You can download it there without actually building this repository: https://search.maven.org/artifact/com.instaclustr/cassandra-ldap

There are separate branches for each supported version of Apache Cassandra. Each branch should work with any corresponding minor version of the same branch in Cassandra.
Building the jar requires Apache maven. Clone and checkout the desired branch if you want to develop against that.

Compile and package

    mvn package

Configuration
=============

Please be sure that `system_auth` keyspace uses `NetworkTopologyStrategy` with number of replicas equal to number of nodes in DC. If it is not 
the case, you can alter your keyspace like:

    ALTER KEYSPACE system_auth WITH replication = {'class': 'NetworkTopologyStrategy', 'dc1': '3'}  AND durable_writes = true;
    
After this, rebuild system_auth keyspace:

    nodetool rebuild -ks system_auth

From the git repo, fill in and copy the `ldap.properties` file to some location ($CASSANDRA_CONF is a good one) on each of the nodes. This file is used for telling the authenticator details about the LDAP server and connection.

Copy the created jar file to each node in your cluster, and append it to the CLASSPATH variable in the cassandra-env.sh/cassandra-env.ps1). It is enough to put that jar into 
Cassandra's `lib` directory from where it will be picked up automatically.

    CLASSPATH="$CLASSPATH:/path/to/cassandra-ldap-3.11.4.jar"

Also add the following option to the JVM options, pointing to the location of your ldap.properties file (on each node). This is not necessary if you place `ldap.properties` into 
`$CASSANDRA_CONF` directory as from there it will be picked up automatically (assuming `$CASSANDRA_CONF` is set in your system).

    JVM_OPTS="$JVM_OPTS -Dcassandra.ldap.properties.file=$CASSANDRA_CONF/ldap.properties"
    
You can achieve same behaviour with doing

    $ ./cassandra -f -Dcassandra.ldap.properties.file=/where/is/my/ldap.properties

In your `cassandra.yaml` configure the authenticator **and authorizer** like so:

    authenticator: com.instaclustr.cassandra.ldap.LDAPAuthenticator
    authorizer: CassandraAuthorizer

Configure credential caching parameters in `cassandra.yaml`.
[Re]start Cassandra.

**WARNING** - Doing this on a live cluster should be handled with care. If done in a rolling fashion from PasswordAuthenticator (or some other implementation) connections to an LDAP configured node using non-ldap credentials will fail if usernames and passwords don't match, that is, nodes running LDAPAuthenticator will not be able to access Cassandra users that are *not* in LDAP. Safest method would be to either support both mechanisms in your application (handle failure with C* users) or switch to AllowAllAuthenticator (in a rolling fashion) prior to switching to LDAPAuthenticator.

Example
============

For fast testing there is Debian OpenLDAP Docker container

    docker run -e LDAP_ADMIN_PASSWORD=admin --rm -d -p 389:389 --name ldap1 osixia/openldap

The `ldap.configuration` file in `conf` directory does not need to be changed and with the above `docker run`, it will work out of the box. You just 
have to put it in `$CASSANDRA_CONF`.

How it works
============

LDAPAuthenticator currently supports plain text authorisation requests only in the form of a username and password. This request is made to the LDAP server over plain text, so you should be using client encryption on the Cassandra side and secure ldap (ldaps) on the LDAP side.

Credentials are sent from your client to the Cassandra server and then tested against the LDAP server for authentication using a specified service account. This service account should be configured in the `ldap.properties` file using the `service_dn` and `service_password` properties. This can be excluded if you allow anonymous access to ldap (not recommended unless you know what you're doing!).

On successful authentication to LDAP a corresponding Cassandra user will be created (including for the service user who will be SUPERUSER). These users are never removed, as it is deemed cleanup is not necessary as long as auth is still handled by LDAP. Manual cleanup of users will work fine, and if they re-auth a replacement user will be created. Passwords are not stored in Cassandra, however on 3.11 and later they will live in the credentials cache when used.

There is also default `cassandra` user with `cassandra` password created but not used in case you go against LDAP. If you ever change your mind and switch 
back to some other authenticator, e.g. `PasswordAuthenticator` in connection with `CassandraRoleManager`, you can authenticate with `cassandra:cassandra` as normally.

If LDAP server connection is lost or there is other communication error while talking to LDAP server, operator has still a possibility to log in via 
`cassandra` user as usually and until LDAP server is not back again, users meant to be authenticated against LDAP server will not be able to log in.

## Further Information
- See blog by Kurt Greaves ["Apache Cassandra LDAP Authentication"](https://www.instaclustr.com/apache-cassandra-ldap-authentication/)
- Please see https://www.instaclustr.com/support/documentation/announcements/instaclustr-open-source-project-status/ for Instaclustr support status of this project
