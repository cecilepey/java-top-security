create table user (
    id int not null auto_increment,
    firstname VARCHAR(100) not null,
    lastname VARCHAR(100) not null,
    login VARCHAR(50) not null,
    password VARCHAR(200) not null,
    is_admin bool not null default false,
    primary key (id)
);

create table token (
  id int not null auto_increment,
  token_value VARCHAR(100) not null,
  primary key (id)
);


insert into user(firstname, lastname, login, password, is_admin) values ('Bilel', 'KHARBECHE', 'bilel', 'admin', true);
insert into user(firstname, lastname, login, password) values ('Olivier', 'LASBLEIS', 'olivier', 'admin');
insert into user(firstname, lastname, login, password) values ('Jean-baptiste', 'MERAND', 'jb', 'admin');
insert into user(firstname, lastname, login, password) values ('Cécile', 'PEYRAS', 'cecile', 'admin');
insert into user(firstname, lastname, login, password) values ('Guillaume', 'PIERRE', 'guillaume', 'admin');
insert into user(firstname, lastname, login, password) values ('Kévin', 'SEGUINEAU', 'kevin', 'admin');
insert into user(firstname, lastname, login, password) values ('Eloi', 'TURPIN', 'eloi', 'admin');

insert into token(token_value) values ('ceci est un secret inaccessible!!!');
