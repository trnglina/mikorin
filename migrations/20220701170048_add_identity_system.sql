--
-- Extensions
--
CREATE EXTENSION pg_trgm;

--
-- Permissions
--
CREATE TYPE Permission AS ENUM (
    'groups.create',
    'groups.delete',
    'groups.name.edit',
    'groups.permissions.edit',
    'users.groups.edit'
);

--
-- Groups
--
CREATE TABLE Groups (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    name TEXT NOT NULL,
    permissions Permission ARRAY NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (name)
);

INSERT INTO Groups (name, permissions)
VALUES ('Admin', ENUM_RANGE(null::Permission));

--
-- Users
--
CREATE TABLE Users (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    username TEXT,
    digest TEXT,
    name TEXT,
    PRIMARY KEY (id)
);

CREATE UNIQUE INDEX ON Users (LOWER(username));

CREATE TABLE UserGroups (
    user_id BIGINT NOT NULL,
    group_id BIGINT NOT NULL,
    PRIMARY KEY (user_id, group_id),
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE CASCADE,
    FOREIGN KEY (group_id) REFERENCES Groups (id) ON DELETE CASCADE
);

--
-- Sessions
--
CREATE TABLE Sessions (
    id TEXT,
    user_id BIGINT NOT NULL,
    expires TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE CASCADE
);