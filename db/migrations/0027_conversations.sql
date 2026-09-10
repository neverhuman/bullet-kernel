-- Complete message history belongs to the server, independent of any client.
-- These records request head turns; they confer no provider or coding authority.
CREATE TABLE conversations (
    conversation_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(conversation_id) = 'text' AND length(CAST(conversation_id AS BLOB)) = 68 AND length(conversation_id) = 68 AND substr(conversation_id, 1, 4) = 'cnv_' AND substr(conversation_id, 5) NOT GLOB '*[^0-9a-f]*'),
    operator_id TEXT NOT NULL REFERENCES local_operator(operator_id),
    created_command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
    created_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq) CHECK (typeof(created_sequence) = 'integer' AND created_sequence BETWEEN 1 AND 9007199254740991),
    created_at TEXT NOT NULL CHECK (typeof(created_at) = 'text' AND length(created_at) BETWEEN 20 AND 32)
);
CREATE INDEX conversation_owner ON conversations(operator_id, created_sequence);

CREATE TABLE conversation_messages (
    message_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(message_id) = 'text' AND length(CAST(message_id AS BLOB)) = 68 AND length(message_id) = 68 AND substr(message_id, 1, 4) = 'msg_' AND substr(message_id, 5) NOT GLOB '*[^0-9a-f]*'),
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    sequence INTEGER NOT NULL CHECK (typeof(sequence) = 'integer' AND sequence BETWEEN 1 AND 9007199254740991),
    parent_message_id TEXT REFERENCES conversation_messages(message_id),
    role TEXT NOT NULL CHECK (role IN ('user', 'assistant')),
    content TEXT NOT NULL CHECK (typeof(content) = 'text' AND length(CAST(content AS BLOB)) BETWEEN 1 AND 32768),
    content_digest TEXT NOT NULL CHECK (typeof(content_digest) = 'text' AND length(CAST(content_digest AS BLOB)) = 64 AND length(content_digest) = 64 AND content_digest NOT GLOB '*[^0-9a-f]*'),
    command_id TEXT UNIQUE REFERENCES commands(id),
    head_turn_id TEXT UNIQUE REFERENCES conversation_head_requests(turn_id),
    accepted_sequence INTEGER NOT NULL UNIQUE REFERENCES events(seq) CHECK (typeof(accepted_sequence) = 'integer' AND accepted_sequence BETWEEN 1 AND 9007199254740991),
    accepted_at TEXT NOT NULL CHECK (typeof(accepted_at) = 'text' AND length(accepted_at) BETWEEN 20 AND 32),
    UNIQUE (conversation_id, sequence),
    CHECK ((role = 'user' AND command_id IS NOT NULL AND head_turn_id IS NULL)
        OR (role = 'assistant' AND command_id IS NULL AND head_turn_id IS NOT NULL)),
    CHECK ((sequence = 1 AND parent_message_id IS NULL) OR (sequence > 1 AND parent_message_id IS NOT NULL))
);

CREATE TABLE conversation_head_requests (
    turn_id TEXT PRIMARY KEY NOT NULL CHECK (typeof(turn_id) = 'text' AND length(CAST(turn_id AS BLOB)) = 68 AND length(turn_id) = 68 AND substr(turn_id, 1, 4) = 'hdt_' AND substr(turn_id, 5) NOT GLOB '*[^0-9a-f]*'),
    conversation_id TEXT NOT NULL REFERENCES conversations(conversation_id),
    input_message_id TEXT NOT NULL UNIQUE REFERENCES conversation_messages(message_id),
    input_sequence INTEGER NOT NULL CHECK (typeof(input_sequence) = 'integer' AND input_sequence BETWEEN 1 AND 9007199254740991),
    command_id TEXT NOT NULL UNIQUE REFERENCES commands(id),
    outbox_sequence INTEGER NOT NULL UNIQUE REFERENCES outbox(seq),
    requested_at TEXT NOT NULL CHECK (typeof(requested_at) = 'text' AND length(requested_at) BETWEEN 20 AND 32)
);
CREATE INDEX conversation_head_order ON conversation_head_requests(conversation_id, input_sequence);

CREATE TRIGGER conversation_message_append BEFORE INSERT ON conversation_messages
WHEN NEW.sequence <> COALESCE((SELECT MAX(sequence) + 1 FROM conversation_messages WHERE conversation_id = NEW.conversation_id), 1)
  OR NEW.parent_message_id IS NOT (SELECT message_id FROM conversation_messages WHERE conversation_id = NEW.conversation_id ORDER BY sequence DESC LIMIT 1)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_CURSOR_CONFLICT'); END;
CREATE TRIGGER conversation_assistant_cause BEFORE INSERT ON conversation_messages
WHEN NEW.role = 'assistant' AND NOT EXISTS (
    SELECT 1 FROM conversation_head_requests WHERE turn_id = NEW.head_turn_id
      AND conversation_id = NEW.conversation_id AND input_sequence < NEW.sequence
)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_HEAD_CAUSE_INVALID'); END;
CREATE TRIGGER conversation_head_input BEFORE INSERT ON conversation_head_requests
WHEN NOT EXISTS (
    SELECT 1 FROM conversation_messages WHERE message_id = NEW.input_message_id
      AND conversation_id = NEW.conversation_id AND sequence = NEW.input_sequence
      AND role = 'user' AND command_id = NEW.command_id
)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_HEAD_INPUT_INVALID'); END;

CREATE TRIGGER conversation_no_update BEFORE UPDATE ON conversations
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_IMMUTABLE'); END;
CREATE TRIGGER conversation_no_delete BEFORE DELETE ON conversations
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_IMMUTABLE'); END;
CREATE TRIGGER conversation_no_replace BEFORE INSERT ON conversations
WHEN EXISTS (SELECT 1 FROM conversations WHERE conversation_id = NEW.conversation_id OR created_command_id = NEW.created_command_id OR created_sequence = NEW.created_sequence)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_IMMUTABLE'); END;
CREATE TRIGGER conversation_message_no_update BEFORE UPDATE ON conversation_messages
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_MESSAGE_IMMUTABLE'); END;
CREATE TRIGGER conversation_message_no_delete BEFORE DELETE ON conversation_messages
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_MESSAGE_IMMUTABLE'); END;
CREATE TRIGGER conversation_message_no_replace BEFORE INSERT ON conversation_messages
WHEN EXISTS (SELECT 1 FROM conversation_messages WHERE message_id = NEW.message_id OR (conversation_id = NEW.conversation_id AND sequence = NEW.sequence) OR command_id = NEW.command_id OR head_turn_id = NEW.head_turn_id OR accepted_sequence = NEW.accepted_sequence)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_MESSAGE_IMMUTABLE'); END;
CREATE TRIGGER conversation_head_no_update BEFORE UPDATE ON conversation_head_requests
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_HEAD_REQUEST_IMMUTABLE'); END;
CREATE TRIGGER conversation_head_no_delete BEFORE DELETE ON conversation_head_requests
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_HEAD_REQUEST_IMMUTABLE'); END;
CREATE TRIGGER conversation_head_no_replace BEFORE INSERT ON conversation_head_requests
WHEN EXISTS (SELECT 1 FROM conversation_head_requests WHERE turn_id = NEW.turn_id OR input_message_id = NEW.input_message_id OR command_id = NEW.command_id OR outbox_sequence = NEW.outbox_sequence)
BEGIN SELECT RAISE(ABORT, 'CONVERSATION_HEAD_REQUEST_IMMUTABLE'); END;
