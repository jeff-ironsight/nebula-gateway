-- Make owner_user_id nullable for system-owned servers
alter table servers
    alter column owner_user_id drop not null;

-- Well-known UUIDs for the default server and channel
insert into servers (id, owner_user_id, name)
values ('00000000-0000-0000-0000-000000000001', null, 'Nebula');

insert into channels (id, server_id, name)
values ('00000000-0000-0000-0000-000000000001',
        '00000000-0000-0000-0000-000000000001',
        'general');
