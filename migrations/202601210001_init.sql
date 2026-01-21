create
    extension if not exists citext;

create table users
(
    id         uuid primary key,
    username   citext      not null,
    created_at timestamptz not null default now()
);

create unique index users_username_idx on users (username);

create table sessions
(
    token_hash bytea primary key,
    user_id    uuid        not null references users (id) on delete cascade,
    created_at timestamptz not null default now(),
    expires_at timestamptz,
    revoked_at timestamptz
);

create table servers
(
    id            uuid primary key,
    owner_user_id uuid        not null references users (id) on delete cascade,
    name          text        not null,
    created_at    timestamptz not null default now()
);

create table channels
(
    id         uuid primary key,
    server_id  uuid        not null references servers (id) on delete cascade,
    name       text        not null,
    created_at timestamptz not null default now()
);

create unique index channels_server_name_idx on channels (server_id, name);

create table channel_members
(
    channel_id uuid        not null references channels (id) on delete cascade,
    user_id    uuid        not null references users (id) on delete cascade,
    joined_at  timestamptz not null default now(),
    primary key (channel_id, user_id)
);

create index channel_members_user_id_idx on channel_members (user_id);
