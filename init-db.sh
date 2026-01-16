#!/bin/bash
set -e

# This script runs as the postgres superuser during container initialization.
# It creates the app_user role with LIMITED privileges (no SUPERUSER, no BYPASSRLS)
# so that Row Level Security (RLS) policies are enforced.

psql -v ON_ERROR_STOP=1 --username "postgres" --dbname "$POSTGRES_DB" <<-EOSQL
    -- Create app_user role if it doesn't exist (without SUPERUSER or BYPASSRLS)
    DO \$\$
    BEGIN
        IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = '${DATABASE_USER}') THEN
            CREATE ROLE ${DATABASE_USER} WITH
                LOGIN 
                PASSWORD '${DATABASE_PASSWORD:-changeme}'
                NOSUPERUSER 
                NOCREATEDB 
                NOCREATEROLE 
                NOREPLICATION
                NOBYPASSRLS;
        END IF;
    END
    \$\$;

    -- Grant connection to the database
    GRANT CONNECT ON DATABASE "${POSTGRES_DB}" TO $DATABASE_USER;

    -- Grant schema usage and CREATE (needed for migrations)
    GRANT USAGE, CREATE ON SCHEMA public TO $DATABASE_USER;

    -- Grant ALL on tables (including ALTER for migrations, but NOT superuser privileges)
    GRANT ALL ON ALL TABLES IN SCHEMA public TO $DATABASE_USER;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT ALL ON TABLES TO $DATABASE_USER;

    -- Grant sequence privileges (needed for serial/identity columns)
    GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO $DATABASE_USER;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT USAGE, SELECT ON SEQUENCES TO $DATABASE_USER;

    -- Grant execute on functions (if any are needed)
    GRANT EXECUTE ON ALL FUNCTIONS IN SCHEMA public TO $DATABASE_USER;
    ALTER DEFAULT PRIVILEGES IN SCHEMA public GRANT EXECUTE ON FUNCTIONS TO $DATABASE_USER;
EOSQL

echo "✓ default app role created with RLS-enforced privileges (NOBYPASSRLS)"