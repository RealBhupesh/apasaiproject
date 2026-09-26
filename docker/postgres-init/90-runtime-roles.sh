#!/bin/sh
set -eu
: "${APAS_API_PASSWORD:?APAS_API_PASSWORD is required}"
: "${APAS_AUTH_PASSWORD:?APAS_AUTH_PASSWORD is required}"
: "${APAS_INGESTION_PASSWORD:?APAS_INGESTION_PASSWORD is required}"
: "${APAS_AUDIT_PASSWORD:?APAS_AUDIT_PASSWORD is required}"
psql -v ON_ERROR_STOP=1 --username "$POSTGRES_USER" --dbname "$POSTGRES_DB" \
  --set=api_password="$APAS_API_PASSWORD" --set=auth_password="$APAS_AUTH_PASSWORD" \
  --set=ingestion_password="$APAS_INGESTION_PASSWORD" --set=audit_password="$APAS_AUDIT_PASSWORD" <<'SQL'
SELECT 'CREATE ROLE apas_api_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='apas_api_runtime') \gexec
SELECT 'CREATE ROLE apas_auth_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='apas_auth_runtime') \gexec
SELECT 'CREATE ROLE apas_ingestion_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='apas_ingestion_runtime') \gexec
SELECT 'CREATE ROLE apas_audit_runtime LOGIN NOSUPERUSER NOCREATEDB NOCREATEROLE INHERIT NOBYPASSRLS' WHERE NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname='apas_audit_runtime') \gexec
ALTER ROLE apas_api_runtime PASSWORD :'api_password';
ALTER ROLE apas_auth_runtime PASSWORD :'auth_password';
ALTER ROLE apas_ingestion_runtime PASSWORD :'ingestion_password';
ALTER ROLE apas_audit_runtime PASSWORD :'audit_password';
GRANT apas_api_reader,apas_api_writer TO apas_api_runtime;
GRANT apas_auth_reader TO apas_auth_runtime;
GRANT apas_ingestion_worker TO apas_ingestion_runtime;
GRANT apas_audit_writer TO apas_audit_runtime;
SQL
