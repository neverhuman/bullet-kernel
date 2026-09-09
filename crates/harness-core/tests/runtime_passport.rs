//! Provider-neutral runtime-passport canonicalization and hostile shape tests.
//! All fixtures are data only; no provider binary or filesystem is touched.

use bullet_harness_core::{
    ProviderProtocol, ProviderRuntimePassportV1, RuntimeExecutionV1, RuntimeFileRoleV1,
    RuntimeFileV1, RuntimeLoaderV1, RuntimePassportError, MAX_RUNTIME_FILES,
    MAX_RUNTIME_FILE_BYTES, MAX_RUNTIME_TOTAL_BYTES, RUNTIME_PASSPORT_ID_PREFIX,
};
use serde_json::{json, Value};
use std::collections::BTreeSet;

type Fixture = (
    &'static str,
    ProviderProtocol,
    &'static str,
    &'static str,
    bool,
);

const FIXTURES: [Fixture; 4] = [
    (
        "claude",
        ProviderProtocol::ClaudeStreamJson,
        "2.1.251",
        "bin/claude",
        false,
    ),
    (
        "codex",
        ProviderProtocol::CodexAppServerJsonl,
        "0.150.1",
        "bin/codex",
        false,
    ),
    (
        "cursor",
        ProviderProtocol::CursorAcp,
        "2026.08.11",
        "bin/cursor-agent",
        true,
    ),
    (
        "agy",
        ProviderProtocol::AntigravityHeadlessStructured,
        "1.1.19",
        "bin/agy",
        false,
    ),
];

const EXPECTED_IDS: [&str; 4] = [
    "rtp_5fe1a9168febf914a141bee524eeec828dd86c995af1e9cc4170a2b78f17f9a1",
    "rtp_8c46a1eb5d02e7a8ad8aa348c7f16e91a7b7d48e81293f0dce2fca326512c446",
    "rtp_4afe05dcda2d06afc5bed02ccebb898134f2c03ed2c7d3934644a2027de406a8",
    "rtp_0466b2257a4ff9b8eb51aaf54fd4845a724f357b105c7da9b0a73f6d3a1eda15",
];

fn digest(digit: char) -> String {
    digit.to_string().repeat(64)
}

fn file(path: &str, role: RuntimeFileRoleV1, mode: u32, size: u64, digit: char) -> RuntimeFileV1 {
    RuntimeFileV1 {
        path: path.into(),
        role,
        mode,
        size,
        blake3: digest(digit),
    }
}

fn passport(fixture: Fixture) -> ProviderRuntimePassportV1 {
    let (provider, protocol, version, entrypoint, interpreted) = fixture;
    let (files, execution) = if interpreted {
        (
            vec![
                file(entrypoint, RuntimeFileRoleV1::Entrypoint, 0o555, 31, '1'),
                file("bin/node", RuntimeFileRoleV1::Interpreter, 0o555, 47, '2'),
                file("lib/index.js", RuntimeFileRoleV1::Module, 0o444, 59, '3'),
            ],
            RuntimeExecutionV1::Interpreted {
                interpreter_path: "bin/node".into(),
                interpreter_blake3: digest('2'),
                loader: RuntimeLoaderV1::Static,
            },
        )
    } else {
        (
            vec![
                file(entrypoint, RuntimeFileRoleV1::Entrypoint, 0o555, 31, '1'),
                file("lib/ld.so", RuntimeFileRoleV1::Loader, 0o555, 47, '2'),
                file(
                    "lib/libprovider.so",
                    RuntimeFileRoleV1::NativeLibrary,
                    0o444,
                    59,
                    '3',
                ),
            ],
            RuntimeExecutionV1::Native {
                loader: RuntimeLoaderV1::Dynamic {
                    path: "lib/ld.so".into(),
                    blake3: digest('2'),
                },
            },
        )
    };
    let aggregate_size_bytes = files.iter().map(|member| member.size).sum();
    ProviderRuntimePassportV1 {
        schema_version: 1,
        provider: provider.into(),
        protocol,
        version: version.into(),
        deployment_root: format!("/usr/lib/bullet/providers/{provider}/{version}"),
        entrypoint: entrypoint.into(),
        aggregate_file_count: files.len() as u32,
        aggregate_size_bytes,
        execution,
        files,
    }
}

fn static_passport(sizes: &[u64]) -> ProviderRuntimePassportV1 {
    let mut files = Vec::with_capacity(sizes.len());
    for (index, size) in sizes.iter().copied().enumerate() {
        let (path, role, mode) = if index == 0 {
            (
                "bin/claude".to_string(),
                RuntimeFileRoleV1::Entrypoint,
                0o555,
            )
        } else {
            (
                format!("resources/{index:03}"),
                RuntimeFileRoleV1::Resource,
                0o444,
            )
        };
        files.push(file(&path, role, mode, size, 'a'));
    }
    ProviderRuntimePassportV1 {
        schema_version: 1,
        provider: "claude".into(),
        protocol: ProviderProtocol::ClaudeStreamJson,
        version: "bounds-1".into(),
        deployment_root: "/usr/lib/bullet/providers/claude/bounds-1".into(),
        entrypoint: "bin/claude".into(),
        execution: RuntimeExecutionV1::Native {
            loader: RuntimeLoaderV1::Static,
        },
        aggregate_file_count: files.len() as u32,
        aggregate_size_bytes: sizes.iter().sum(),
        files,
    }
}

fn value(passport: &ProviderRuntimePassportV1) -> Value {
    serde_json::to_value(passport).unwrap()
}

fn decode_value(value: &Value) -> Result<ProviderRuntimePassportV1, RuntimePassportError> {
    ProviderRuntimePassportV1::decode(&serde_jcs::to_vec(value).unwrap())
}

#[test]
fn all_provider_protocol_pairs_round_trip_with_stable_full_width_ids() {
    let mut ids = BTreeSet::new();
    for (index, fixture) in FIXTURES.into_iter().enumerate() {
        let passport = passport(fixture);
        let bytes = passport.canonical_bytes().unwrap();
        assert_eq!(ProviderRuntimePassportV1::decode(&bytes).unwrap(), passport);
        let id = passport.passport_id().unwrap();
        assert_eq!(id, EXPECTED_IDS[index]);
        assert!(ids.insert(id.clone()));
        let digest = id.strip_prefix(RUNTIME_PASSPORT_ID_PREFIX).unwrap();
        assert_eq!(digest.len(), 64);
        assert!(digest
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte)));
        assert_eq!(
            ProviderProtocol::required_for_wire_provider(fixture.0).unwrap(),
            fixture.1
        );
    }
    assert_eq!(ids.len(), FIXTURES.len());

    assert_eq!(
        ProviderProtocol::wire_provider_from_cli("antigravity").unwrap(),
        "agy"
    );
    assert_eq!(
        ProviderProtocol::wire_provider_from_cli("agy").unwrap(),
        "agy"
    );
    assert!(ProviderProtocol::required_for_wire_provider("antigravity").is_err());

    let mut executable_library = passport(FIXTURES[0]);
    executable_library.files[2].mode = 0o555;
    executable_library.validate().unwrap();
}

#[test]
fn canonical_decoder_refuses_noncanonical_duplicate_and_recursive_unknown_fields() {
    let passport = passport(FIXTURES[0]);
    let bytes = passport.canonical_bytes().unwrap();
    let text = String::from_utf8(bytes).unwrap();
    for raw in [
        format!(" {text}"),
        format!("{text}\n"),
        text.replacen(
            "\"schema_version\":1",
            "\"schema_version\":1,\"schema_version\":1",
            1,
        ),
        text.replacen("\"mode\":365", "\"mode\":365,\"mode\":365", 1),
        text.replacen(
            "\"kind\":\"dynamic\"",
            "\"kind\":\"dynamic\",\"kind\":\"dynamic\"",
            1,
        ),
    ] {
        assert_eq!(
            ProviderRuntimePassportV1::decode(raw.as_bytes())
                .unwrap_err()
                .reason_code(),
            "RUNTIME_PASSPORT_MALFORMED"
        );
    }

    let base = value(&passport);
    let mutations: [fn(&mut Value); 4] = [
        |value| value["unknown"] = json!(true),
        |value| value["files"][0]["unknown"] = json!(true),
        |value| value["execution"]["unknown"] = json!(true),
        |value| value["execution"]["loader"]["unknown"] = json!(true),
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_eq!(
            decode_value(&changed).unwrap_err().reason_code(),
            "RUNTIME_PASSPORT_MALFORMED"
        );
    }
}

#[test]
fn provider_alias_and_protocol_substitution_never_enter_the_wire() {
    let base = value(&passport(FIXTURES[0]));
    let mutations: [fn(&mut Value); 5] = [
        |value| value["provider"] = json!("antigravity"),
        |value| value["provider"] = json!("codex"),
        |value| value["protocol"] = json!("codex_app_server_jsonl"),
        |value| value["protocol"] = json!("codex_exec_json"),
        |value| value["deployment_root"] = json!("/usr/lib/bullet/providers/codex/2.1.251"),
    ];
    for (index, mutate) in mutations.into_iter().enumerate() {
        let mut changed = base.clone();
        mutate(&mut changed);
        let error = decode_value(&changed).unwrap_err();
        assert!(
            matches!(
                error,
                RuntimePassportError::Malformed { .. }
                    | RuntimePassportError::ProtocolMismatch { .. }
            ),
            "substitution {index} was not refused"
        );
    }
}

#[test]
fn unsafe_integers_aggregate_drift_and_mutable_files_refuse() {
    let base = value(&passport(FIXTURES[0]));
    let mutations: [fn(&mut Value); 10] = [
        |value| value["files"][0]["size"] = json!(9_007_199_254_740_992_u64),
        |value| value["aggregate_size_bytes"] = json!(9_007_199_254_740_992_u64),
        |value| value["files"][0]["size"] = json!(MAX_RUNTIME_FILE_BYTES + 1),
        |value| value["aggregate_file_count"] = json!(2),
        |value| value["aggregate_size_bytes"] = json!(1),
        |value| value["files"][0]["mode"] = json!(0o755),
        |value| value["files"][0]["mode"] = json!(0o444),
        |value| value["files"][0]["mode"] = json!(0o1000),
        |value| value["files"][0]["size"] = json!(0),
        |value| value["files"][0]["blake3"] = json!("A".repeat(64)),
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_eq!(
            decode_value(&changed).unwrap_err().reason_code(),
            "RUNTIME_PASSPORT_MALFORMED"
        );
    }

    let exact_total = static_passport(&[MAX_RUNTIME_FILE_BYTES; 8]);
    assert_eq!(exact_total.aggregate_size_bytes, MAX_RUNTIME_TOTAL_BYTES);
    exact_total.validate().unwrap();

    let mut above_total = static_passport(&[MAX_RUNTIME_FILE_BYTES; 8]);
    above_total.files.push(file(
        "resources/999",
        RuntimeFileRoleV1::Resource,
        0o444,
        1,
        'b',
    ));
    above_total.aggregate_file_count += 1;
    above_total.aggregate_size_bytes += 1;
    assert_eq!(
        above_total.validate().unwrap_err().reason_code(),
        "RUNTIME_PASSPORT_MALFORMED"
    );
}

#[test]
fn manifest_order_paths_roles_and_linkage_are_exact() {
    let base = value(&passport(FIXTURES[2]));
    let mutations: [fn(&mut Value); 7] = [
        |value| value["files"].as_array_mut().unwrap().reverse(),
        |value| value["files"][1]["path"] = value["files"][0]["path"].clone(),
        |value| value["files"][0]["path"] = json!("../cursor-agent"),
        |value| value["files"][0]["role"] = json!("executable"),
        |value| value["execution"]["interpreter_path"] = json!("bin/missing-node"),
        |value| value["execution"]["interpreter_blake3"] = json!(digest('f')),
        |value| value["entrypoint"] = json!("bin/agent"),
    ];
    for mutate in mutations {
        let mut changed = base.clone();
        mutate(&mut changed);
        assert_eq!(
            decode_value(&changed).unwrap_err().reason_code(),
            "RUNTIME_PASSPORT_MALFORMED"
        );
    }

    let maximum = static_passport(&vec![1; MAX_RUNTIME_FILES]);
    maximum.canonical_bytes().unwrap();

    let mut oversized_document = maximum.clone();
    for (index, member) in oversized_document.files.iter_mut().enumerate().skip(1) {
        member.path = format!("z{index:03}{}", "x".repeat(508));
    }
    assert_eq!(
        oversized_document
            .canonical_bytes()
            .unwrap_err()
            .reason_code(),
        "RUNTIME_PASSPORT_MALFORMED"
    );

    let empty = static_passport(&[]);
    assert_eq!(
        empty.validate().unwrap_err().reason_code(),
        "RUNTIME_PASSPORT_MALFORMED"
    );
    let above_maximum = static_passport(&vec![1; MAX_RUNTIME_FILES + 1]);
    assert_eq!(
        above_maximum.validate().unwrap_err().reason_code(),
        "RUNTIME_PASSPORT_MALFORMED"
    );

    let mut exact_path = passport(FIXTURES[0]);
    exact_path.files[2].path = "z".repeat(512);
    exact_path.canonical_bytes().unwrap();
    for invalid in [
        "z".repeat(513),
        "../resource".into(),
        "z\\resource".into(),
        "z\nresource".into(),
        "z/é".into(),
    ] {
        let mut changed = passport(FIXTURES[0]);
        changed.files[2].path = invalid;
        assert_eq!(
            changed.validate().unwrap_err().reason_code(),
            "RUNTIME_PASSPORT_MALFORMED"
        );
    }
}
