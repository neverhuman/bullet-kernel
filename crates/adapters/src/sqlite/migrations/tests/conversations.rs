use super::{database, sidecar, sqlite_fixture, SqliteLedger, MIGRATIONS};
use bullet_application::{conversations, CommandRequest};
use bullet_domain::{CommandId, Digest};
use rusqlite::{params, Connection};

const AT: &str = "2026-09-10T00:00:00.000Z";

fn command_event(conn: &Connection, key: &str) -> (CommandId, i64) {
    let request = CommandRequest::from_json(key, "document", "{}").unwrap();
    crate::sqlite::commands::record_command(conn, &request).unwrap();
    crate::sqlite::events::insert_event(
        conn,
        "schema_fixture",
        request.id().as_str(),
        None,
        None,
        None,
    )
    .unwrap();
    (request.id(), conn.last_insert_rowid())
}

struct Message {
    id: String,
    thread: String,
    sequence: i64,
    parent: Option<String>,
    role: &'static str,
    content: String,
    command: Option<String>,
    turn: Option<String>,
    event: i64,
}

impl Message {
    fn insert(&self, conn: &Connection) -> rusqlite::Result<usize> {
        conn.execute(
            "INSERT INTO conversation_messages (message_id, conversation_id, sequence,
             parent_message_id, role, content, content_digest, command_id, head_turn_id,
             accepted_sequence, accepted_at) VALUES (?1,?2,?3,?4,?5,?6,?7,?8,?9,?10,?11)",
            params![
                self.id,
                self.thread,
                self.sequence,
                self.parent,
                self.role,
                self.content,
                Digest::of(self.content.as_bytes()).to_hex(),
                self.command,
                self.turn,
                self.event,
                AT
            ],
        )
    }
}

fn initial(conn: &Connection) -> Message {
    let operator = format!("opr_{}", Digest::of(b"schema-fixture-operator").to_hex());
    conn.execute("INSERT INTO local_operator VALUES (1,?1,1)", [&operator])
        .unwrap();
    let (command, event) = command_event(conn, "first-message");
    let thread = conversations::conversation_id(&operator, &command).unwrap();
    conn.execute(
        "INSERT INTO conversations VALUES (?1,?2,?3,?4,?5)",
        params![thread, operator, command.as_str(), event, AT],
    )
    .unwrap();
    Message {
        id: conversations::message_id(&command),
        thread,
        sequence: 1,
        parent: None,
        role: "user",
        content: "Please improve the API.\nPreserve its behavior.".into(),
        command: Some(command.to_string()),
        turn: None,
        event,
    }
}

fn head_request(conn: &Connection, message: &Message, turn: &str) -> rusqlite::Result<usize> {
    conn.execute(
        "INSERT INTO conversation_head_requests VALUES (?1,?2,?3,?4,?5,?6,?7)",
        params![
            turn,
            message.thread,
            message.id,
            message.sequence,
            message.command,
            1,
            AT
        ],
    )
}

#[test]
fn conversation_history_requires_exact_parent_and_preserves_complete_turns() {
    let (_directory, path) = database();
    let ledger = SqliteLedger::open(&path).unwrap();
    let conn = &ledger.conn;
    let mut first = initial(conn);
    let original_id = first.id.clone();
    first.id = format!("msg_{}\0{}", "a".repeat(31), "b".repeat(32));
    assert_eq!(first.id.len(), 68);
    assert!(first.insert(conn).is_err());
    first.id = original_id;
    first.insert(conn).unwrap();
    let (command, event) = command_event(conn, "second-message");
    let mut second = Message {
        id: conversations::message_id(&command),
        thread: first.thread.clone(),
        sequence: 3,
        parent: Some(first.id.clone()),
        role: "user",
        content: "What changed?".into(),
        command: Some(command.to_string()),
        turn: None,
        event,
    };
    assert!(second
        .insert(conn)
        .unwrap_err()
        .to_string()
        .contains("CONVERSATION_CURSOR_CONFLICT"));
    second.sequence = 2;
    second.parent = Some(format!("msg_{}", Digest::of(b"wrong-parent").to_hex()));
    assert!(second.insert(conn).is_err());
    second.parent = Some(first.id.clone());
    second.content = "🦀".repeat(8193);
    assert!(second.insert(conn).is_err());
    second.content = "What changed?".into();
    second.insert(conn).unwrap();
    assert!(first.insert(conn).is_err());
    for statement in [
        "UPDATE conversation_messages SET content='rewritten'",
        "DELETE FROM conversation_messages",
        "INSERT OR REPLACE INTO conversation_messages SELECT * FROM conversation_messages",
        "UPDATE conversations SET created_at='2026-09-11T00:00:00.000Z'",
        "DELETE FROM conversations",
        "INSERT OR REPLACE INTO conversations SELECT * FROM conversations",
    ] {
        assert!(conn.execute_batch(statement).is_err(), "{statement}");
    }
    drop(ledger);
    let reopened = SqliteLedger::open(&path).unwrap();
    let rows: Vec<(String, i64, String)> = reopened
        .conn
        .prepare(
            "SELECT message_id, sequence, content FROM conversation_messages ORDER BY sequence",
        )
        .unwrap()
        .query_map([], |row| Ok((row.get(0)?, row.get(1)?, row.get(2)?)))
        .unwrap()
        .collect::<Result<_, _>>()
        .unwrap();
    assert_eq!(
        rows,
        vec![(first.id, 1, first.content), (second.id, 2, second.content)]
    );
}

#[test]
fn assistant_rows_require_a_durable_same_thread_head_cause() {
    let (_directory, path) = database();
    let ledger = SqliteLedger::open(path).unwrap();
    let conn = &ledger.conn;
    let first = initial(conn);
    first.insert(conn).unwrap();
    let (command, event) = command_event(conn, "assistant-fixture-event");
    let turn = format!("hdt_{}", Digest::of(b"head-turn-fixture").to_hex());
    let mut assistant = Message {
        id: conversations::message_id(&command),
        thread: first.thread.clone(),
        sequence: 2,
        parent: Some(first.id.clone()),
        role: "assistant",
        content: "Fixture response.".into(),
        command: None,
        turn: Some(turn.clone()),
        event,
    };
    assert!(assistant
        .insert(conn)
        .unwrap_err()
        .to_string()
        .contains("CONVERSATION_HEAD_CAUSE_INVALID"));
    conn.execute("INSERT INTO outbox (seq,command_id,kind,payload,phase) VALUES (1,?1,'conversation_head_turn','{}','pending')", [&first.command]).unwrap();
    assert!(head_request(conn, &assistant, &turn).is_err());
    head_request(conn, &first, &turn).unwrap();
    assistant.command = Some(command.to_string());
    assert!(assistant.insert(conn).is_err());
    assistant.command = None;
    assistant.insert(conn).unwrap();
    assert!(head_request(conn, &first, &turn).is_err());
    for statement in [
        "UPDATE conversation_head_requests SET input_sequence=2",
        "DELETE FROM conversation_head_requests",
        "INSERT OR REPLACE INTO conversation_head_requests SELECT * FROM conversation_head_requests",
    ] {
        assert!(conn.execute_batch(statement).is_err(), "{statement}");
    }
    let count: i64 = conn
        .query_row("SELECT COUNT(*) FROM conversation_messages", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(count, 2);
    let causes: i64 = conn
        .query_row("SELECT COUNT(*) FROM conversation_head_requests", [], |r| {
            r.get(0)
        })
        .unwrap();
    assert_eq!(causes, 1);
}

#[test]
fn conversation_schema_preserves_every_supported_predecessor_without_rewrite() {
    for version in 22..=26 {
        let (_directory, path) = database();
        let mut conn = sqlite_fixture(&path);
        super::super::initialize_prefix(&mut conn, &MIGRATIONS[..version]).unwrap();
        drop(conn);
        let before = std::fs::read(&path).unwrap();
        for _ in 0..2 {
            let error = match SqliteLedger::open(&path) {
                Ok(_) => panic!("predecessor{version} served"),
                Err(error) => error,
            };
            assert!(error.to_string().contains("UPGRADE_REQUIRED"), "{error}");
            assert_eq!(std::fs::read(&path).unwrap(), before);
            for suffix in ["-wal", "-shm", "-journal"] {
                assert!(!sidecar(&path, suffix).exists());
            }
        }
    }
}
