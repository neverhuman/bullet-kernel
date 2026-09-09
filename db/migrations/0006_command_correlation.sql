CREATE UNIQUE INDEX commands_id_unique ON commands(id);

ALTER TABLE outbox
  ADD COLUMN command_id TEXT REFERENCES commands(id);

CREATE INDEX outbox_command_sequence ON outbox(command_id, seq);
