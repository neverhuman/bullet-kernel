//! Create-once component observations. This is not a signing/admission consumer.
use anyhow::{ensure, Result};
use serde_json::{json, Value};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{Read, Write};
use std::os::unix::fs::{DirBuilderExt, OpenOptionsExt};
use std::path::{Path, PathBuf};
use std::time::Instant;
use tuiwright::ScreenSnapshot;

pub fn hash(path: &Path) -> Result<String> {
    let mut file = File::open(path)?;
    let mut hash = Sha256::new();
    let mut bytes = [0; 65536];
    loop {
        let size = file.read(&mut bytes)?;
        if size == 0 {
            break;
        }
        hash.update(&bytes[..size]);
    }
    Ok(format!("{:x}", hash.finalize()))
}

pub struct Evidence {
    directory: PathBuf,
    events: File,
    started: Instant,
    sequence: u64,
    selected: Vec<String>,
    completed: Vec<Value>,
    subjects: Value,
    artifacts: Vec<Value>,
}

impl Evidence {
    pub fn create(
        directory: &Path,
        binary: &Path,
        digest: &str,
        selected: &[&str],
    ) -> Result<Self> {
        std::fs::DirBuilder::new().mode(0o700).create(directory)?;
        let events = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(directory.join("events.jsonl"))?;
        let mut sources = Vec::new();
        let root = Path::new(env!("CARGO_MANIFEST_DIR"));
        for name in [
            "Cargo.toml",
            "Cargo.lock",
            "src/main.rs",
            "src/launcher.rs",
            "src/session.rs",
            "src/cases.rs",
            "src/fixture.rs",
            "src/evidence.rs",
            "src/custody.rs",
            "README.md",
            "LICENSE-JANKURAI",
            "LICENSE-JETBRAINS-MONO",
        ] {
            let path = root.join(name);
            sources.push(json!({"path":name,"sha256":hash(&path)?}));
        }
        let subjects = json!({"evidence_class":"COMPONENT_PROOF", "installed_authenticated":false,
            "release_eligible":false,"source_build_binding":"EXTERNAL_REVIEW_REQUIRED",
            "bullet":{"path":binary,"sha256":digest},
            "harness":{"path":std::env::current_exe()?,"sha256":hash(&std::env::current_exe()?)?},
            "runtime_observed_source":sources,
            "tuiwright":{"git":"https://github.com/neverhuman/jankurai",
                "revision":"5e85a4de2ce59a8d1fc7865520665af58e9e6727",
                "crate_tree":"c7dce342986889287d4bd0da48ce54973ebe8148",
                "font_sha256":"e6fd0d7e91550b3ed2b735d4312474362c4716edc4fc0577a0f61ed782d5aed1",
                "font_license_sha256":"a76abf002c49097d146e86740a3105a5d00450b1592e820a1109a8c5680cd697"},
            "host":std::fs::read_to_string("/proc/sys/kernel/hostname")?.trim(),
            "kernel":std::fs::read_to_string("/proc/sys/kernel/osrelease")?.trim(),
            "architecture":std::env::consts::ARCH,"terminal":{"initial_cols":120,"initial_rows":30},
            "timing":"monotonic observations; launcher permission to observed screen; no percentile certification",
            "recording":"action/screen observations; not raw terminal transcript or public demonstration"});
        let mut report = Self {
            directory: directory.into(),
            events,
            started: Instant::now(),
            sequence: 0,
            selected: selected.iter().map(|s| (*s).to_owned()).collect(),
            completed: Vec::new(),
            subjects,
            artifacts: Vec::new(),
        };
        report.artifact("subjects.json", &report.subjects.clone())?;
        Ok(report)
    }

    fn artifact(&mut self, name: &str, value: &Value) -> Result<()> {
        let bytes = serde_json::to_vec_pretty(value)?;
        ensure!(bytes.len() <= 2_000_000, "ARTIFACT_SIZE_LIMIT");
        let path = self.directory.join(name);
        let mut file = OpenOptions::new()
            .create_new(true)
            .write(true)
            .mode(0o600)
            .open(&path)?;
        file.write_all(&bytes)?;
        file.sync_all()?;
        self.artifacts
            .push(json!({"path":name,"bytes":bytes.len(),"sha256":hash(&path)?}));
        Ok(())
    }

    pub fn event(&mut self, case: &str, kind: &str, data: Value) -> Result<()> {
        self.sequence += 1;
        ensure!(self.sequence <= 2000, "EVENT_LIMIT");
        let value = json!({"sequence":self.sequence,"elapsed_us":self.started.elapsed().as_micros(),
            "case":case,"kind":kind,"data":data});
        let bytes = serde_json::to_vec(&value)?;
        ensure!(bytes.len() <= 64_000, "EVENT_SIZE_LIMIT");
        self.events.write_all(&bytes)?;
        self.events.write_all(b"\n")?;
        self.events.sync_data()?;
        Ok(())
    }

    pub fn screen(
        &mut self,
        case: &str,
        client: usize,
        step: &str,
        screen: ScreenSnapshot,
    ) -> Result<()> {
        let text = screen.plain_text();
        let name = format!("screen-{:04}-{client}.json", self.sequence + 1);
        self.artifact(
            &name,
            &json!({"case":case,"client":client,"step":step,"text":text,"screen":screen}),
        )?;
        self.event(
            case,
            "screen",
            json!({"client":client,"step":step,"artifact":name}),
        )?;
        ensure!(
            !text.contains("ses_") && !text.contains("csrf_"),
            "CREDENTIAL_DISPLAYED"
        );
        Ok(())
    }

    pub fn complete(&mut self, case: &str, result: &Result<()>) -> Result<()> {
        for observation in crate::session::take_cleanup_events() {
            self.event(case, "process_custody", observation)?;
        }
        ensure!(self.selected.iter().any(|id| id == case), "UNSELECTED_CASE");
        ensure!(
            !self.completed.iter().any(|row| row["id"] == case),
            "DUPLICATE_CASE"
        );
        let row = json!({"id":case,"outcome":if result.is_ok(){"PASS"}else{"FAIL"},
            "error":result.as_ref().err().map(|error|format!("{error:#}"))});
        self.event(case, "completed", row.clone())?;
        self.completed.push(row);
        Ok(())
    }

    pub fn finish(mut self, failures: &[String]) -> Result<()> {
        self.events.sync_all()?;
        self.artifacts.push(
            json!({"path":"events.jsonl","sha256":hash(&self.directory.join("events.jsonl"))?}),
        );
        let complete = self.selected.len() == self.completed.len();
        let manifest = json!({"schema":1,"evidence_class":"COMPONENT_PROOF",
            "outcome":if complete && failures.is_empty(){"PASS"}else{"FAIL"},
            "selected":self.selected,"completed":self.completed,"failures":failures,
            "subjects":self.subjects,"artifacts":self.artifacts,
            "installed_authenticated":false,"release_eligible":false});
        self.artifact("manifest.json", &manifest)?;
        File::open(&self.directory)?.sync_all()?;
        Ok(())
    }
}
