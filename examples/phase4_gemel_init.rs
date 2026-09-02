//! Phase-4 demo helper: initialize a Gemel repository with a head state.
//!
//! The golden demonstration (acceptance items 15-17) publishes durable
//! boundaries into a REAL Gemel repository. This helper creates one at a
//! given directory — with a real head state (a tracked file), so verified
//! findings can bind their evidence to an evaluated state — the same way a
//! developer's `gemel init` + first change would leave it:
//!
//! ```text
//! cargo run --example phase4_gemel_init -- <project-dir>
//! ```
//!
//! Coordinator-gated (requires the `gemel` crate); without the coordinator
//! feature the example is an empty binary so the target-runtime feature
//! matrix stays clean.

#[cfg(feature = "coordinator")]
mod demo {
    use gemel::store::refs::{RefOp, RefTransaction};
    use gemel::store::Repo;

    pub fn run() {
        let dir = std::env::args().nth(1).unwrap_or_else(|| {
            eprintln!("usage: phase4_gemel_init <project-dir>");
            std::process::exit(2)
        });
        match run_at(&dir) {
            Ok(state) => println!("gemel repo ready at {dir} (head state {state})"),
            Err(e) => {
                eprintln!("phase4_gemel_init: {e}");
                std::process::exit(1)
            }
        }
    }

    fn run_at(dir: &str) -> Result<gemel::gid::Gid, String> {
        let root = std::path::PathBuf::from(dir);
        std::fs::create_dir_all(&root).map_err(|e| e.to_string())?;
        let repo = if root.join(".gemel/meta.json").is_file() {
            // A repository already exists: reuse it (idempotent demo setup).
            Repo::open(&root).map_err(|e| e.to_string())?
        } else {
            Repo::init(
                &root,
                &gemel::store::InitOptions {
                    author_name: Some("frf-fuzz golden demo".to_string()),
                    author_email: None,
                },
            )
            .map_err(|e| e.to_string())?
        };
        // A head state requires the state ref; build one from a single
        // tracked file (the demo project's source marker), mirroring a first
        // change.
        if let Some(head) = repo
            .read_ref(gemel::store::REF_STATE_HEAD)
            .map_err(|e| e.to_string())?
        {
            return Ok(head);
        }
        let blob = gemel::Object::blob(b"frf-fuzz golden demo state\n".to_vec());
        let blob_gid = repo.insert_object(&blob).map_err(|e| e.to_string())?;
        let mut files = std::collections::BTreeMap::new();
        files.insert("demo.txt".to_string(), (0o100644u64, blob_gid));
        let state =
            gemel::content::build_state_from_files(&repo, &files).map_err(|e| e.to_string())?;
        repo.write_refs(&RefTransaction {
            ops: vec![RefOp::set(gemel::store::REF_STATE_HEAD, state)],
        })
        .map_err(|e| e.to_string())?;
        Ok(state)
    }
}

#[cfg(feature = "coordinator")]
fn main() {
    demo::run();
}

#[cfg(not(feature = "coordinator"))]
fn main() {}
