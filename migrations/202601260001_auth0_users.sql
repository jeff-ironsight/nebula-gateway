alter table users
    add column auth_sub text;

create unique index users_auth_sub_idx
    on users (auth_sub)
    where auth_sub is not null;
