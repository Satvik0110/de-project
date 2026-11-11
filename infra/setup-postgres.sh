#!/usr/bin/env bash
# One-time PostgreSQL setup: create the warehouse role + database, then apply the schema.
# Needs sudo once (to act as the postgres superuser). Safe to re-run.
set -euo pipefail
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
DB=secops USER_=secops PASS=secops

sudo -u postgres psql -v ON_ERROR_STOP=1 -q <<SQL
DO \$\$ BEGIN
  IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname = '$USER_') THEN
    CREATE ROLE $USER_ LOGIN PASSWORD '$PASS';
  END IF;
END \$\$;
SELECT 'CREATE DATABASE $DB OWNER $USER_'
WHERE NOT EXISTS (SELECT FROM pg_database WHERE datname = '$DB')\gexec
SQL

PGPASSWORD=$PASS psql -h localhost -U $USER_ -d $DB -v ON_ERROR_STOP=1 -q -f "$ROOT/warehouse/schema.sql"
echo "warehouse ready: postgresql://$USER_:$PASS@localhost:5432/$DB"
