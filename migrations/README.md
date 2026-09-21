# SQLite migrations

The server applies these SQL files automatically, in filename order, using Node's built-in SQLite driver. Applied filenames are recorded in `_cleo_migrations`. Existing databases are backed up before pending migrations run.

To change the schema, add the next numbered `.sql` file and test both fresh initialization and upgrading an existing database. Keep each migration compatible with the runner's transaction; do not put transaction boundaries in a migration.

Never rename or modify an applied migration. The original filenames are retained so existing installations do not reapply their schema. These files require no ORM or migration-generator dependency.
