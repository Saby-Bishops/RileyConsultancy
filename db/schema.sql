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
    threat_name varchar(255),
    vulnerability_description text,
    likelihood integer,
    impact integer,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id),
    UNIQUE (threat_name)
);

CREATE TABLE vulnerabilities
(
    id serial,
    asset_id integer,
    name varchar(255),
    description text,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id)
);

CREATE TABLE risk_ratings
(
    id serial,
    asset_id integer,
    threat_id integer,
    vulnerability_id integer,

    PRIMARY KEY (id),
    FOREIGN KEY (asset_id) REFERENCES assets (id),
    FOREIGN KEY (threat_id) REFERENCES threats (id),
    FOREIGN KEY (vulnerability_id) REFERENCES vulnerabilities (id)
);
