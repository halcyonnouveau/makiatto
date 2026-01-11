# Corrosion Schema

Corrosion uses an **automatic diff-based system** rather than traditional migrations. When `schema.sql` changes, Corrosion compares the old and new schemas and applies the necessary changes upon restart.

See: https://superfly.github.io/corrosion/schema.html

## Supported SQL Commands

Only two SQL commands are permitted:

- `CREATE TABLE`
- `CREATE INDEX`

**`ALTER TABLE` is not supported.**

## Making Changes

To add a new column or table, just edit `schema.sql`. Corrosion will detect the diff and apply changes automatically on restart.

## Constraints

1. **Destructive operations are prohibited** - removing tables or columns is ignored
2. **No unique indexes allowed** (except the default primary key index)
3. **Primary keys must be non-nullable**
4. **Non-nullable columns require default values**
