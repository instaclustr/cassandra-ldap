package org.apache.cassandra.auth;

import static java.lang.String.format;
import static java.util.Collections.singletonList;
import static org.apache.cassandra.db.ConsistencyLevel.LOCAL_ONE;

import java.util.Collections;
import java.util.function.Function;

import com.instaclustr.cassandra.ldap.auth.SystemAuthRoles;
import org.apache.cassandra.auth.LDAPCassandraRoleManager.Role;
import org.apache.cassandra.cql3.CQLStatement;
import org.apache.cassandra.cql3.QueryOptions;
import org.apache.cassandra.cql3.QueryProcessor;
import org.apache.cassandra.cql3.UntypedResultSet;
import org.apache.cassandra.cql3.UntypedResultSet.Row;
import org.apache.cassandra.cql3.statements.CreateRoleStatement;
import org.apache.cassandra.cql3.statements.SelectStatement;
import org.apache.cassandra.db.ConsistencyLevel;
import org.apache.cassandra.db.marshal.UTF8Type;
import org.apache.cassandra.exceptions.RequestExecutionException;
import org.apache.cassandra.exceptions.RequestValidationException;
import org.apache.cassandra.service.ClientState;
import org.apache.cassandra.service.QueryState;
import org.apache.cassandra.transport.messages.ResultMessage;
import org.apache.cassandra.utils.ByteBufferUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class Cassandra30SystemAuthRoles implements SystemAuthRoles {

    private static final Logger logger = LoggerFactory.getLogger(Cassandra30SystemAuthRoles.class);

    public static final String SELECT_ROLE_STATEMENT = "SELECT role FROM %s.%s where role = ?";

    public static final String CREATE_ROLE_STATEMENT_WITH_LOGIN = "CREATE ROLE IF NOT EXISTS \"%s\" WITH LOGIN = true AND SUPERUSER = %s";

    private ClientState clientState;

    public void setClientState(ClientState clientState) {
        this.clientState = clientState;
    }

    public ClientState getClientState() {
        return clientState;
    }

    public boolean roleMissing(String dn)
    {
        assert getClientState() != null;

        final SelectStatement selStmt = (SelectStatement) QueryProcessor.getStatement(format(SELECT_ROLE_STATEMENT,
                                                                                             "system_auth",
                                                                                             AuthKeyspace.ROLES),
                                                                                      getClientState()).statement;

        final ResultMessage.Rows rows = selStmt.execute(new QueryState(getClientState()),
                                                        QueryOptions.forInternalCalls(singletonList(ByteBufferUtil.bytes(dn))));

        return rows.result.isEmpty();
    }

    public void createRole(String roleName, boolean superUser)
    {
        final CreateRoleStatement createStmt = (CreateRoleStatement) QueryProcessor.getStatement(format(CREATE_ROLE_STATEMENT_WITH_LOGIN, roleName, superUser),
                                                                                                 getClientState()).statement;

        createStmt.execute(new QueryState(getClientState()),
                           QueryOptions.forInternalCalls(LOCAL_ONE, singletonList(ByteBufferUtil.bytes(roleName))));
    }

    public boolean hasAdminRole(String role) throws RequestExecutionException
    {
        // Try looking up the 'cassandra' default role first, to avoid the range query if possible.
        String defaultSUQuery = "SELECT * FROM system_auth.roles WHERE role = '" + role + "'";
        String allUsersQuery = "SELECT * FROM system_auth.roles LIMIT 1";
        return !QueryProcessor.process(defaultSUQuery, ConsistencyLevel.ONE).isEmpty()
            || !QueryProcessor.process(defaultSUQuery, ConsistencyLevel.QUORUM).isEmpty()
            || !QueryProcessor.process(allUsersQuery, ConsistencyLevel.QUORUM).isEmpty();
    }


    public boolean hasAdminRole() throws RequestExecutionException
    {
        return hasAdminRole("cassandra");
    }

    @Override
    public Role getRole(final String name, final ConsistencyLevel roleConsistencyLevel) {
        SelectStatement loadRoleStatement = (SelectStatement) prepare("SELECT * from %s.%s WHERE role = ?", "system_auth", "roles");

        ResultMessage.Rows rows = loadRoleStatement.execute(QueryState.forInternalCalls(),
                                                            QueryOptions.forInternalCalls(getConsistencyForRole("cassandra", name, roleConsistencyLevel),
                                                                                          Collections.singletonList(ByteBufferUtil.bytes(name))));
        if (rows.result.isEmpty()) {
            return NULL_ROLE;
        }

        return ROW_TO_ROLE.apply(UntypedResultSet.create(rows.result).one());
    }

    public CQLStatement prepare(String template, String keyspace, String table) {
        try {
            return QueryProcessor.parseStatement(String.format(template, keyspace, table)).prepare(ClientState.forInternalCalls()).statement;
        } catch (RequestValidationException e) {
            throw new AssertionError(e); // not supposed to happen
        }
    }

    protected ConsistencyLevel getConsistencyForRole(String defaultSuperUserName, String role, ConsistencyLevel roleConsistencyLevel) {
        ConsistencyLevel cl = role.equals(defaultSuperUserName) ? ConsistencyLevel.QUORUM : roleConsistencyLevel;

        logger.debug(String.format("Resolved consistency level for role %s: %s", role, cl));

        return cl;
    }

    // NullObject returned when a supplied role name not found in AuthKeyspace.ROLES
    protected static final Role NULL_ROLE = new Role(null, false, false, Collections.<String>emptySet());

    protected static final Function<Row, Role> ROW_TO_ROLE = new Function<UntypedResultSet.Row, Role>() {
        public Role apply(UntypedResultSet.Row row) {
            try {
                return new Role(row.getString("role"),
                                row.getBoolean("is_superuser"),
                                row.getBoolean("can_login"),
                                row.has("member_of") ? row.getSet("member_of", UTF8Type.instance)
                                    : Collections.<String>emptySet());
            }
            // Failing to deserialize a boolean in is_superuser or can_login will throw an NPE
            catch (NullPointerException e) {
                logger.warn("An invalid value has been detected in the {} table for role {}. If you are " +
                                "unable to login, you may need to disable authentication and confirm " +
                                "that values in that table are accurate", AuthKeyspace.ROLES, row.getString("role"));
                throw new RuntimeException(String.format("Invalid metadata has been detected for role %s", row.getString("role")), e);
            }

        }
    };
}
