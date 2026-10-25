-- Fresh volumes only (docker-entrypoint-initdb.d). For an existing volume run the same
-- statements by hand; see local/README.md.
--
-- The gateway's own database and a role that owns only it. Windmill's schema is untouched.
\set ON_ERROR_STOP on
\set gateway_password `cat /run/secrets/entra_gateway_db_password`

CREATE ROLE entra_gateway LOGIN PASSWORD :'gateway_password'
    NOSUPERUSER NOCREATEDB NOCREATEROLE NOREPLICATION NOBYPASSRLS;
CREATE DATABASE entra_gateway OWNER entra_gateway;
REVOKE ALL ON DATABASE entra_gateway FROM PUBLIC;
