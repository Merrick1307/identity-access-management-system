#!/usr/bin/env python3
"""
Database migration runner using yoyo-migrations.

Usage:
    python -m app.database.run_migrations apply      # Apply pending migrations
    python -m app.database.run_migrations rollback   # Rollback last migration
    python -m app.database.run_migrations list       # List all migrations
    python -m app.database.run_migrations status     # Show migration status
    
Environment variables:
    DATABASE_URL: PostgreSQL connection string
    
Example:
    DATABASE_URL=postgresql://user:pass@localhost:5432/hexiam python -m app.database.run_migrations apply
"""
import argparse
import os
import sys
from pathlib import Path

from yoyo import read_migrations, get_backend


def get_database_url() -> str:
    """Get database URL from environment or config."""
    # Try environment variable first
    db_url = os.getenv("DATABASE_URL")
    if db_url:
        return db_url
    
    # Fall back to individual components
    host = os.getenv("PG_HOST", "localhost")
    port = os.getenv("PG_PORT", "5432")
    user = os.getenv("PG_USER", "postgres")
    password = os.getenv("PG_PASSWORD", "postgres")
    database = os.getenv("PG_DATABASE", "hexiam")
    
    return f"postgresql://{user}:{password}@{host}:{port}/{database}"


def get_migrations_path() -> Path:
    """Get the path to migrations directory."""
    return Path(__file__).parent / "migrations"


def apply_migrations(backend, migrations):
    """Apply all pending migrations."""
    pending = backend.to_apply(migrations)
    if not pending:
        print("✓ No pending migrations")
        return
    
    print(f"Applying {len(pending)} migration(s)...")
    for migration in pending:
        print(f"  → {migration.id}")
    
    backend.apply_migrations(pending)
    print("✓ Migrations applied successfully")


def rollback_migrations(backend, migrations, count: int = 1):
    """Rollback the last N migrations."""
    applied = list(backend.to_rollback(migrations))
    if not applied:
        print("✓ No migrations to rollback")
        return
    
    to_rollback = applied[:count]
    print(f"Rolling back {len(to_rollback)} migration(s)...")
    for migration in to_rollback:
        print(f"  ← {migration.id}")
    
    backend.rollback_migrations(to_rollback)
    print("✓ Rollback completed successfully")


def list_migrations(backend, migrations):
    """List all migrations and their status."""
    applied = set(m.id for m in backend.to_rollback(migrations))
    pending = set(m.id for m in backend.to_apply(migrations))
    
    print("\nMigrations:")
    print("-" * 60)
    
    all_migrations = sorted(migrations, key=lambda m: m.id)
    for migration in all_migrations:
        if migration.id in applied:
            status = "✓ applied"
        elif migration.id in pending:
            status = "○ pending"
        else:
            status = "? unknown"
        print(f"  {status:12} {migration.id}")
    
    print("-" * 60)
    print(f"Total: {len(all_migrations)} | Applied: {len(applied)} | Pending: {len(pending)}")


def show_status(backend, migrations):
    """Show current migration status."""
    applied = list(backend.to_rollback(migrations))
    pending = list(backend.to_apply(migrations))
    
    print("\nDatabase Migration Status")
    print("=" * 40)
    print(f"Applied migrations: {len(applied)}")
    print(f"Pending migrations: {len(pending)}")
    
    if pending:
        print("\nPending:")
        for m in pending[:5]:
            print(f"  ○ {m.id}")
        if len(pending) > 5:
            print(f"  ... and {len(pending) - 5} more")
    
    if applied:
        print("\nLast applied:")
        for m in applied[:3]:
            print(f"  ✓ {m.id}")


def main():
    parser = argparse.ArgumentParser(
        description="HEX IAM Database Migration Tool",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__
    )
    parser.add_argument(
        "command",
        choices=["apply", "rollback", "list", "status"],
        help="Migration command to execute"
    )
    parser.add_argument(
        "-n", "--count",
        type=int,
        default=1,
        help="Number of migrations to rollback (default: 1)"
    )
    parser.add_argument(
        "--database-url",
        help="Database connection URL (overrides DATABASE_URL env var)"
    )
    
    args = parser.parse_args()
    
    # Get database URL
    db_url = args.database_url or get_database_url()
    migrations_path = get_migrations_path()
    
    print(f"Database: {db_url.split('@')[-1] if '@' in db_url else db_url}")
    print(f"Migrations: {migrations_path}")
    
    # Initialize yoyo
    try:
        backend = get_backend(db_url)
        migrations = read_migrations(str(migrations_path))
    except Exception as e:
        print(f"Error connecting to database: {e}", file=sys.stderr)
        sys.exit(1)
    
    # Execute command
    try:
        if args.command == "apply":
            apply_migrations(backend, migrations)
        elif args.command == "rollback":
            rollback_migrations(backend, migrations, args.count)
        elif args.command == "list":
            list_migrations(backend, migrations)
        elif args.command == "status":
            show_status(backend, migrations)
    except Exception as e:
        print(f"Error: {e}", file=sys.stderr)
        sys.exit(1)
    finally:
        backend.connection.close()


if __name__ == "__main__":
    main()
