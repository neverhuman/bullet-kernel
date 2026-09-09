-- Event time is durable protocol truth. Existing pre-V1 rows remain NULL and
-- therefore fail closed when read; demo databases are intentionally disposable.
ALTER TABLE events ADD COLUMN at TEXT;
