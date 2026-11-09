#![cfg(unix)]

use serde_json::Value;
use std::{
    fs::{self, DirBuilder},
    io::Write,
    os::unix::fs::{DirBuilderExt, PermissionsExt, symlink},
    path::PathBuf,
    process::{Command, Output, Stdio},
    sync::atomic::{AtomicU64, Ordering},
    time::{SystemTime, UNIX_EPOCH},
};

static NEXT_DIRECTORY: AtomicU64 = AtomicU64::new(0);

struct Fixture {
    home: PathBuf,
    pat_file: PathBuf,
}

impl Fixture {
    fn new() -> Self {
        let timestamp = SystemTime::now()
            .duration_since(UNIX_EPOCH)
            .unwrap()
            .as_nanos();
        let sequence = NEXT_DIRECTORY.fetch_add(1, Ordering::Relaxed);
        let home = std::env::temp_dir().join(format!(
            "kms-mcp-launcher-{}-{timestamp}-{sequence}",
            std::process::id()
        ));
        DirBuilder::new().mode(0o700).create(&home).unwrap();
        let pat_file = home.join("credential with spaces.pat");
        Self { home, pat_file }
    }

    fn write_pat(&self, contents: &str) {
        fs::write(&self.pat_file, contents).unwrap();
        fs::set_permissions(&self.pat_file, fs::Permissions::from_mode(0o600)).unwrap();
    }

    fn run(&self, defaults: bool, trace: bool) -> Output {
        let mut command = Command::new("/bin/sh");
        if trace {
            command.arg("-x");
        }
        command
            .arg(concat!(
                env!("CARGO_MANIFEST_DIR"),
                "/scripts/kms-mcp-from-file.sh"
            ))
            .args(["--allow", "keystore-get"])
            .env_clear()
            .env("HOME", &self.home)
            .env("PATH", "/usr/bin:/bin")
            .env("ORBITPORT_URL", "http://127.0.0.1:1")
            // The file must replace, not accidentally inherit, a stale PAT.
            .env("ORBITPORT_PAT", "invalid\ninherited-pat")
            .stdin(Stdio::piped())
            .stdout(Stdio::piped())
            .stderr(Stdio::piped());
        if !defaults {
            command
                .env("ORBITPORT_PAT_FILE", &self.pat_file)
                .env("KMS_MCP_BIN", env!("CARGO_BIN_EXE_kms-mcp"));
        }
        let mut child = command.spawn().unwrap();
        let written = child.stdin.take().unwrap().write_all(
            b"{\"jsonrpc\":\"2.0\",\"id\":1,\"method\":\"initialize\",\"params\":{\"protocolVersion\":\"2025-11-25\"}}\n\
              {\"jsonrpc\":\"2.0\",\"method\":\"notifications/initialized\"}\n\
              {\"jsonrpc\":\"2.0\",\"id\":2,\"method\":\"tools/list\"}\n",
        );
        if let Err(error) = written {
            // Startup failures can close stdin before the fixture writes.
            assert_eq!(error.kind(), std::io::ErrorKind::BrokenPipe);
        }
        child.wait_with_output().unwrap()
    }
}

impl Drop for Fixture {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.home);
    }
}

fn assert_protocol(output: &Output) {
    assert!(
        output.status.success(),
        "{}",
        String::from_utf8_lossy(&output.stderr)
    );
    let replies: Vec<Value> = String::from_utf8_lossy(&output.stdout)
        .lines()
        .map(|line| serde_json::from_str(line).unwrap())
        .collect();
    assert_eq!(replies.len(), 2);
    assert_eq!(
        replies[0]["result"]["serverInfo"]["name"],
        "spacecomputer-kms"
    );
    let tools = replies[1]["result"]["tools"].as_array().unwrap();
    assert_eq!(tools.len(), 10);
    assert!(tools.iter().any(|tool| tool["name"] == "kms_keystore_get"));
    assert!(
        !tools
            .iter()
            .any(|tool| tool["name"] == "kms_keystore_delete")
    );
}

#[test]
fn launcher_reads_pat_with_or_without_final_newline_and_forwards_opt_ins() {
    for token in ["fixture-pat", "fixture-pat\n"] {
        let fixture = Fixture::new();
        fixture.write_pat(token);
        let output = fixture.run(false, false);
        assert_protocol(&output);
        assert!(output.stderr.is_empty());
        assert!(!String::from_utf8_lossy(&output.stdout).contains("fixture-pat"));
    }
}

#[test]
fn launcher_rejects_missing_or_empty_files_without_protocol_noise() {
    let fixture = Fixture::new();
    let output = fixture.run(false, false);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("missing or unreadable"));

    fixture.write_pat("");
    let output = fixture.run(false, false);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    assert!(String::from_utf8_lossy(&output.stderr).contains("PAT file is empty"));
}

#[test]
fn launcher_uses_default_user_paths() {
    let fixture = Fixture::new();
    let config = fixture.home.join(".config/spacecomputer-kms");
    let bin = fixture.home.join(".local/bin");
    fs::create_dir_all(&config).unwrap();
    fs::create_dir_all(&bin).unwrap();
    fs::write(config.join("prod.pat"), "fixture-pat").unwrap();
    symlink(env!("CARGO_BIN_EXE_kms-mcp"), bin.join("kms-mcp")).unwrap();
    let output = fixture.run(true, false);
    assert_protocol(&output);
    assert!(output.stderr.is_empty());
}

#[test]
fn launcher_treats_file_as_data_and_disables_shell_tracing() {
    let fixture = Fixture::new();
    let marker = fixture.home.join("must-not-exist");
    let token = format!("$(touch {})", marker.display());
    fixture.write_pat(&token);
    let output = fixture.run(false, true);
    assert_protocol(&output);
    assert!(!marker.exists());
    assert!(!String::from_utf8_lossy(&output.stdout).contains(&token));
    assert!(!String::from_utf8_lossy(&output.stderr).contains(&token));
}

#[test]
fn launcher_does_not_expose_malformed_multiline_credentials() {
    let fixture = Fixture::new();
    fixture.write_pat("private-pat-marker\nsecond-line");
    let output = fixture.run(false, false);
    assert!(!output.status.success());
    assert!(output.stdout.is_empty());
    let stderr = String::from_utf8_lossy(&output.stderr);
    assert!(stderr.contains("not a valid bearer credential"));
    assert!(!stderr.contains("private-pat-marker"));
    assert!(!stderr.contains("second-line"));
}
