-- Server invitations
create table server_invites
(
    id         uuid primary key,
    code       text        not null unique,
    server_id  uuid        not null references servers (id) on delete cascade,
    creator_id uuid        not null references users (id) on delete cascade,
    max_uses   int,         -- null = unlimited
    use_count  int         not null default 0,
    expires_at timestamptz, -- null = never expires
    created_at timestamptz not null default now()
);

create index server_invites_server_id_idx on server_invites (server_id);
