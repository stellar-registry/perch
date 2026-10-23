//! Emit (or drift-check) the committed PolicyDoc JSON Schema.
//!
//! Usage:
//!   perch-schema-gen            print the schema to stdout
//!   perch-schema-gen --write    (re)write the committed artifact
//!   perch-schema-gen --check    exit non-zero if the committed artifact drifted
//!
//! The committed artifact is [`perch_schema::CANONICAL_RELPATH`], resolved from
//! the workspace root. `just schema` runs `--write`; CI's drift test calls the
//! library directly (see `tests/drift.rs`), so this binary is for humans.

use std::path::PathBuf;
use std::process::ExitCode;

fn canonical_path() -> PathBuf {
    // CARGO_MANIFEST_DIR is crates/perch-schema; the workspace root is two up.
    PathBuf::from(env!("CARGO_MANIFEST_DIR"))
        .join("..")
        .join("..")
        .join(perch_schema::CANONICAL_RELPATH)
}

fn main() -> ExitCode {
    let generated = perch_schema::policy_schema_json();
    let mode = std::env::args().nth(1);
    match mode.as_deref() {
        None => {
            print!("{generated}");
            ExitCode::SUCCESS
        }
        Some("--write") => {
            let path = canonical_path();
            if let Err(e) = std::fs::write(&path, &generated) {
                eprintln!("perch-schema-gen: writing {}: {e}", path.display());
                return ExitCode::FAILURE;
            }
            eprintln!("perch-schema-gen: wrote {}", path.display());
            ExitCode::SUCCESS
        }
        Some("--check") => {
            let path = canonical_path();
            match std::fs::read_to_string(&path) {
                Ok(committed) if committed == generated => {
                    eprintln!("perch-schema-gen: {} is up to date", path.display());
                    ExitCode::SUCCESS
                }
                Ok(_) => {
                    eprintln!(
                        "perch-schema-gen: {} is stale — run `just schema`",
                        path.display()
                    );
                    ExitCode::FAILURE
                }
                Err(e) => {
                    eprintln!("perch-schema-gen: reading {}: {e}", path.display());
                    ExitCode::FAILURE
                }
            }
        }
        Some(other) => {
            eprintln!("perch-schema-gen: unknown argument `{other}` (use --write or --check)");
            ExitCode::FAILURE
        }
    }
}
