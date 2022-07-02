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
    'groups.edit',
    'users.group_id.edit'
);

--
-- Groups
--
CREATE TABLE Groups_ (
    id bigint GENERATED ALWAYS AS IDENTITY,
    name text NOT NULL,
    permissions Permission[] NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (name)
);

INSERT INTO Groups_ (name, permissions)
    VALUES ('User', ARRAY[]::Permission[]);

INSERT INTO Groups_ (name, permissions)
    VALUES ('Admin', ENUM_RANGE(NULL::Permission));

--
-- Users
--
CREATE TABLE Users (
    id bigint GENERATED ALWAYS AS IDENTITY,
    username text,
    digest text,
    name text,
    group_id bigint NOT NULL DEFAULT 1::bigint,
    PRIMARY KEY (id),
    FOREIGN KEY (group_id) REFERENCES Groups_ (id) ON DELETE SET DEFAULT
);

CREATE UNIQUE INDEX ON Users (LOWER(username));

--
-- Sessions
--
CREATE TABLE Sessions (
    id text,
    user_id bigint NOT NULL,
    expires timestamptz NOT NULL,
    PRIMARY KEY (id),
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE CASCADE
);

