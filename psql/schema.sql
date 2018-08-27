DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    passhash TEXT
);
CREATE INDEX on users (id);

-- User insertion example
-- INSERT INTO users (username, passhash) VALUES ('default_user', 'somevalidhash');
