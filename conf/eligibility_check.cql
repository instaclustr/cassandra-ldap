-- change datacenter replication and strategy as you please to suite your needs

CREATE KEYSPACE IF NOT EXISTS login_eligibility WITH replication = {'class': 'NetworkTopologyStrategy', 'datacenter1': 1};
CREATE TABLE IF NOT EXISTS login_eligibility.login_eligibility (user text, has_access boolean, PRIMARY KEY (user));