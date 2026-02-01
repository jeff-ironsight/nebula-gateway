create table messages
(
    id             text primary key,
    channel_id     uuid        not null references channels (id) on delete cascade,
    author_user_id uuid        not null references users (id) on delete cascade,
    content        text        not null,
    created_at     timestamptz not null default now()
);

create index idx_messages_channel_created on messages (channel_id, created_at desc);
