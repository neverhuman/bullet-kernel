//! Portal bundle verifier proofs.
//!
//! The admitted fixture manifest below was produced by `bullet-portal`'s own
//! `ops/build/bundle.ts` (`expectedManifestBytes`) over the exact fixture files
//! this test writes, so accepting it proves this Rust verifier reproduces the
//! TypeScript canonical JSON, per-file BLAKE3 digests, and framed BLAKE3 root
//! byte for byte. Every other case proves a refusal.

// The build script consumes the rest of this shared module.
#[allow(dead_code)]
#[path = "../build/bundle.rs"]
mod bundle;

use bundle::{records::admit_path, verify, MANIFEST_NAME};
use std::fs;
use std::path::{Path, PathBuf};

const MANIFEST: &str = r#"{"files":[{"blake3":"blake3:e2d2211d424c10fa0a0cb25c967fe096043e7bd198cd253ef9bfeb34916c8e76","mime":"text/css; charset=utf-8","path":"assets/app.css","size":18},{"blake3":"blake3:4bcc0a2b1a41f83544c5ff2f11bdff857dd811e3951001a2c6a8cd7bbad8e842","mime":"text/javascript; charset=utf-8","path":"assets/app.js","size":23},{"blake3":"blake3:4f27b6199683d4533d5d5d2116edadd06ab7827ae0862f9e6e63b1a540b29c73","mime":"text/html; charset=utf-8","path":"index.html","size":74}],"package_lock":{"blake3":"blake3:d203a69b6750bf1421e466433c1f73d6959199c8b444b955702984cad94f0f02","path":"package-lock.json","size":39},"root":"blake3:252b870b5d3063622bcca1d2b52d35b9b14233e6e390cb35a0bc2b8a334822c3","schema_version":"bullet.portal.bundle.v1","source":{"commit_oid":"sha1:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","repository":"bullet-portal","tree_oid":"sha1:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"},"tools":[{"blake3":"blake3:42347edd494ffbbeb9c1a87e0c308f1fd5e262f072dc97fd142e14f2ad48f11f","name":"git","size":10,"version":"git version 2.43.0"},{"architecture":"x64","blake3":"blake3:2181f342e352d583ced3d18231db126b374446d044c7c3ae1fb33b5536877b49","name":"node","platform":"linux","size":11,"version":"v26.1.0"},{"blake3":"blake3:a19f1053b1608f6461e028d201e9d12dc875c600b4945392c08068b32e535395","file_count":3,"name":"npm","size":10,"version":"11.13.0"}],"total_size":115}
"#;
const INDEX_HTML: &str =
    "<!doctype html>\n<html lang=\"en\"><body><div id=\"root\"></div></body></html>\n";
const APP_JS: &str = "console.log(\"bullet\");\n";
const APP_CSS: &str = ":root{color:#fff}\n";
const EXPECTED_ROOT: &str =
    "blake3:252b870b5d3063622bcca1d2b52d35b9b14233e6e390cb35a0bc2b8a334822c3";

struct Fixture {
    _directory: tempfile::TempDir,
    dist: PathBuf,
}

fn fixture() -> Fixture {
    let directory = tempfile::tempdir().expect("tempdir");
    let dist = directory.path().join("dist");
    fs::create_dir_all(dist.join("assets")).expect("create dist");
    fs::write(dist.join("index.html"), INDEX_HTML).expect("index");
    fs::write(dist.join("assets/app.js"), APP_JS).expect("script");
    fs::write(dist.join("assets/app.css"), APP_CSS).expect("style");
    fs::write(dist.join(MANIFEST_NAME), MANIFEST).expect("manifest");
    Fixture {
        _directory: directory,
        dist,
    }
}

fn refusal_code(dist: &Path) -> &'static str {
    verify(dist).err().expect("refusal").code
}

#[test]
fn the_typescript_generated_manifest_is_reproduced_exactly() {
    let fixture = fixture();
    let bundle = verify(&fixture.dist).expect("admitted bundle");
    assert_eq!(bundle.root, EXPECTED_ROOT);
    assert_eq!(
        bundle.commit_oid,
        format!("sha1:{}", "a".repeat(40)),
        "the source commit subject is carried through"
    );
    assert_eq!(bundle.tree_oid, format!("sha1:{}", "b".repeat(40)));
    let paths: Vec<&str> = bundle.files.iter().map(|file| file.path.as_str()).collect();
    assert_eq!(paths, ["assets/app.css", "assets/app.js", "index.html"]);
    let index = &bundle.files[2];
    assert_eq!(index.mime, "text/html; charset=utf-8");
    assert_eq!(index.body, INDEX_HTML.as_bytes());
    assert_eq!(
        index.digest_hex,
        "4f27b6199683d4533d5d5d2116edadd06ab7827ae0862f9e6e63b1a540b29c73"
    );
    assert_eq!(
        blake3::hash(&bundle.files[1].body).to_hex().to_string(),
        bundle.files[1].digest_hex
    );
}

#[test]
fn one_changed_byte_is_refused() {
    let fixture = fixture();
    fs::write(
        fixture.dist.join("assets/app.js"),
        "console.log(\"bulleT\");\n",
    )
    .expect("tamper");
    assert_eq!(refusal_code(&fixture.dist), "FILE_DIGEST_MISMATCH");
}

#[test]
fn a_size_change_is_refused_before_any_digest_collision_question() {
    let fixture = fixture();
    fs::write(fixture.dist.join("index.html"), "<!doctype html>\n").expect("truncate");
    assert_eq!(refusal_code(&fixture.dist), "FILE_SIZE_MISMATCH");
}

#[test]
fn an_unlisted_file_is_refused_even_when_every_listed_file_matches() {
    let fixture = fixture();
    fs::write(fixture.dist.join("assets/extra.js"), "console.log(1);\n").expect("extra");
    assert_eq!(refusal_code(&fixture.dist), "UNEXPECTED_BUNDLE_ENTRY");
    fs::remove_file(fixture.dist.join("assets/extra.js")).expect("remove");
    fs::create_dir(fixture.dist.join("vendor")).expect("directory");
    assert_eq!(refusal_code(&fixture.dist), "UNEXPECTED_BUNDLE_ENTRY");
}

#[test]
fn a_missing_listed_file_is_refused() {
    let fixture = fixture();
    fs::remove_file(fixture.dist.join("assets/app.css")).expect("remove");
    assert_eq!(refusal_code(&fixture.dist), "BUNDLE_FILE_MISSING");
}

#[cfg(unix)]
#[test]
fn a_symlinked_entry_is_refused_and_never_followed() {
    let fixture = fixture();
    let secret = fixture.dist.parent().expect("parent").join("secret.js");
    fs::write(&secret, APP_JS).expect("secret");
    fs::remove_file(fixture.dist.join("assets/app.js")).expect("remove");
    std::os::unix::fs::symlink(&secret, fixture.dist.join("assets/app.js")).expect("symlink");
    assert_eq!(refusal_code(&fixture.dist), "SYMLINK_REJECTED");
}

#[test]
fn a_pretty_printed_or_reordered_manifest_is_refused() {
    let fixture = fixture();
    let value: serde_json::Value = serde_json::from_str(MANIFEST).expect("parse");
    let pretty = format!(
        "{}\n",
        serde_json::to_string_pretty(&value).expect("pretty")
    );
    fs::write(fixture.dist.join(MANIFEST_NAME), pretty).expect("write");
    assert_eq!(refusal_code(&fixture.dist), "MANIFEST_NOT_CANONICAL");
}

#[test]
fn a_manifest_root_that_does_not_bind_its_body_is_refused() {
    let fixture = fixture();
    let forged = MANIFEST.replace(EXPECTED_ROOT, &format!("blake3:{}", "c".repeat(64)));
    fs::write(fixture.dist.join(MANIFEST_NAME), forged).expect("write");
    assert_eq!(refusal_code(&fixture.dist), "ROOT_MISMATCH");
}

#[test]
fn a_dirty_or_untagged_source_subject_is_refused() {
    let fixture = fixture();
    let forged = MANIFEST.replace(&format!("sha1:{}", "a".repeat(40)), "HEAD");
    fs::write(fixture.dist.join(MANIFEST_NAME), forged).expect("write");
    assert_eq!(refusal_code(&fixture.dist), "SOURCE_SUBJECT_INVALID");
}

#[test]
fn a_declared_size_that_contradicts_the_total_is_refused() {
    let fixture = fixture();
    let forged = MANIFEST.replace(r#""total_size":115"#, r#""total_size":116"#);
    fs::write(fixture.dist.join(MANIFEST_NAME), forged).expect("write");
    assert_eq!(refusal_code(&fixture.dist), "TOTAL_SIZE_MISMATCH");
}

#[test]
fn a_missing_manifest_or_relative_path_is_refused_before_any_read() {
    let fixture = fixture();
    fs::remove_file(fixture.dist.join(MANIFEST_NAME)).expect("remove");
    assert_eq!(refusal_code(&fixture.dist), "MANIFEST_MISSING");
    assert_eq!(refusal_code(Path::new("dist")), "PORTAL_DIST_NOT_ABSOLUTE");
    assert_eq!(
        refusal_code(&fixture.dist.join("assets/app.js")),
        "BUNDLE_ROOT_INVALID"
    );
}

#[test]
fn only_the_flat_entrypoint_and_one_assets_level_are_admitted() {
    assert_eq!(
        admit_path("index.html").expect("entrypoint"),
        "text/html; charset=utf-8"
    );
    assert_eq!(
        admit_path("assets/index-DjHynClQ.css").expect("asset"),
        "text/css; charset=utf-8"
    );
    assert_eq!(admit_path("assets/f.woff2").expect("font"), "font/woff2");
    for rejected in [
        "",
        "/etc/passwd",
        "../secret.js",
        "assets/../../secret.js",
        "assets/nested/app.js",
        "assets/.hidden.js",
        ".git/config",
        "assets/app.js ",
        "assets\\app.js",
        "assets/app.exe",
        "index.htm",
        "assets/caf\u{e9}.js",
        "assets/app\u{0}.js",
    ] {
        assert!(admit_path(rejected).is_err(), "{rejected:?} was admitted");
    }
}
