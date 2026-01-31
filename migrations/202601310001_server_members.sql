create table server_members
(
    server_id uuid        not null references servers (id) on delete cascade,
    user_id   uuid        not null references users (id) on delete cascade,
    role      text        not null default 'member',
    joined_at timestamptz not null default now(),
    primary key (server_id, user_id)
);

create index server_members_user_id_idx on server_members (user_id);
