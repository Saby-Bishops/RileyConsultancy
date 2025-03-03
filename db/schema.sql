CREATE TABLE assets
(
    id serial,
    name varchar(255) NOT NULL,
    category varchar(50),
    description text,
    risk_level integer,

    PRIMARY KEY (id),
    CHECK (risk_level BETWEEN 1 AND 10)
);

CREATE TABLE threats
(
    id serial,
    asset_id integer NOT NULL,
    name varchar(255),
    risk_level integer,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id)
    CHECK (risk_level BETWEEN 1 AND 10)
);

CREATE TABLE vulnerabilities
(
    id serial,
    asset_id integer,
    name varchar(255),
    description text,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES asset (id),
);

CREATE TABLE risk_ratings
(
    id serial,
    asset_id integer,
    threat_id integer,
    vulnerability_id integer,


    PRIMARY KEY id,
    FOREIGN KEY asset_id REFERENCES assets (id),
    FOREIGN KEY threat_id REFERENCES threats (id),
    FOREIGN KEY vulnerability_id REFERENCES vulnerability (id)
);
