DROP TABLE IF EXISTS users CASCADE;
CREATE TABLE users (
    id BIGSERIAL PRIMARY KEY,
    username TEXT UNIQUE NOT NULL,
    passhash TEXT,
    CHECK (username <> '')
);
CREATE INDEX ON users (id);

-- User insertion example
-- INSERT INTO users (username, passhash) VALUES ('default_user', 'somevalidhash');

DROP TABLE IF EXISTS groups CASCADE;
CREATE TABLE groups (
    id BIGSERIAL PRIMARY KEY,
    groupname TEXT UNIQUE NOT NULL,
    CHECK (groupname <> '')
);
CREATE INDEX ON groups (id);

DROP TABLE IF EXISTS relations CASCADE;
CREATE TABLE relations (
    id BIGSERIAL PRIMARY KEY,
    groupID BIGSERIAL NOT NULL REFERENCES groups (id) ON UPDATE CASCADE,
    userID BIGSERIAL NOT NULL REFERENCES users (id) ON UPDATE CASCADE,
    UNIQUE (groupID, userID)
);
CREATE INDEX ON relations (id);
CREATE INDEX ON relations (groupID);
CREATE INDEX ON relations (userID);

DROP TABLE IF EXISTS files CASCADE;
CREATE TABLE files (
    id BIGSERIAL PRIMARY KEY,
    filepath TEXT UNIQUE NOT NULL,
    md5 TEXT NOT NULL,
    ownerID BIGSERIAL NOT NULL REFERENCES groups (id) ON UPDATE CASCADE,
    CHECK (filepath <> '' and md5 <> '')
);
CREATE INDEX ON files (id);
CREATE INDEX ON files (ownerID);

DROP TABLE IF EXISTS readers CASCADE;
CREATE TABLE readers (
    id BIGSERIAL PRIMARY KEY,
    groupID BIGSERIAL NOT NULL REFERENCES groups (id) ON UPDATE CASCADE,
    fileID BIGSERIAL NOT NULL REFERENCES files (id) ON UPDATE CASCADE,
    UNIQUE (groupID, fileID)
);
CREATE INDEX ON readers (id);
CREATE INDEX ON readers (fileID);
CREATE INDEX ON readers (groupID);
