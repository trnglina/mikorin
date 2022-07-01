--
-- Permissions
--
CREATE TABLE Permissions (name TEXT NOT NULL, PRIMARY KEY (name));

INSERT INTO Permissions (name)
VALUES ('groups.create'),
    ('groups.delete'),
    ('groups.name.edit'),
    ('groups.permissions.edit'),
    ('users.groups.edit');

--
-- Groups
--
CREATE TABLE Groups (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    name TEXT NOT NULL,
    PRIMARY KEY (id),
    UNIQUE (name)
);

CREATE TABLE GroupPermissions (
    group_id BIGINT NOT NULL,
    permission_name TEXT NOT NULL,
    PRIMARY KEY (group_id, permission_name),
    FOREIGN KEY (group_id) REFERENCES Groups (id) ON DELETE CASCADE,
    FOREIGN KEY (permission_name) REFERENCES Permissions (name)
);

-- Set up admin group.
INSERT INTO Groups (name)
VALUES ('Admin');

INSERT INTO GroupPermissions (group_id, permission_name)
SELECT g.id,
    p.name
FROM Permissions p
    CROSS JOIN (
        SELECT id
        FROM Groups
        WHERE name = 'Admin'
        LIMIT 1
    ) AS g;

--
-- Users
--
CREATE TABLE Users (
    id BIGINT GENERATED ALWAYS AS IDENTITY,
    username TEXT,
    password TEXT,
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
-- Users
--
CREATE TABLE Tokens (
    token TEXT,
    user_id BIGINT NOT NULL,
    expires TIMESTAMPTZ NOT NULL,
    PRIMARY KEY (token),
    FOREIGN KEY (user_id) REFERENCES Users (id) ON DELETE CASCADE
);