use std::fs;
use std::path::{Path, PathBuf};
use std::time::{Duration, SystemTime, UNIX_EPOCH};

use rayon::prelude::*;
use serde::{Deserialize, Serialize};
use walkdir::{DirEntry, WalkDir};

use crate::model::{CleanupAction, CleanupGroup, CleanupItem, Risk};
use crate::scanner::dir_size;

const ARTIFACTS: &[&str] = &["node_modules", "target", ".build", "build", "dist", ".venv"];

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PurgeCandidate {
    pub path: PathBuf,
    pub kind: String,
    pub size: u64,
    pub modified_unix: Option<u64>,
    pub age_days: u64,
}

impl PurgeCandidate {
    pub fn cleanup_item(&self) -> CleanupItem {
        CleanupItem {
            id: format!("purge:{}", self.path.display()),
            group: CleanupGroup::Dev,
            label: format!("{} ({})", self.path.display(), self.kind),
            estimated_bytes: self.size,
            risk: Risk::Explicit,
            action: CleanupAction::RemovePath {
                path: self.path.clone(),
                contents_only: false,
            },
        }
    }
}

/// A discovered artifact directory, before its (potentially expensive) size is computed.
struct DiscoveredArtifact {
    path: PathBuf,
    kind: String,
    modified_unix: Option<u64>,
    age_days: u64,
}

pub fn scan_artifacts(roots: &[PathBuf], older_than_days: u64) -> Vec<PurgeCandidate> {
    let now = SystemTime::now();
    let minimum_age = Duration::from_secs(older_than_days.saturating_mul(86_400));

    // Discovery is a cheap, metadata-only walk; it is kept sequential per root, but the roots
    // themselves may be walked in parallel.
    let discovered: Vec<DiscoveredArtifact> = roots
        .par_iter()
        .filter(|root| root.exists())
        .flat_map(|root| discover_artifacts(root, now, minimum_age))
        .collect();

    // Sizing an artifact directory (e.g. `node_modules`) is the expensive, I/O-bound step, so
    // it is done in parallel across all discovered candidates, independent of which root or
    // walk produced them.
    let mut candidates: Vec<PurgeCandidate> = discovered
        .par_iter()
        .map(|artifact| PurgeCandidate {
            path: artifact.path.clone(),
            kind: artifact.kind.clone(),
            size: dir_size(&artifact.path),
            modified_unix: artifact.modified_unix,
            age_days: artifact.age_days,
        })
        .collect();

    candidates.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));
    candidates
}

fn discover_artifacts(
    root: &Path,
    now: SystemTime,
    minimum_age: Duration,
) -> Vec<DiscoveredArtifact> {
    let walker = WalkDir::new(root)
        .max_depth(7)
        .follow_links(false)
        .into_iter()
        .filter_entry(visit_project_entry);

    let mut found = Vec::new();
    for entry in walker.filter_map(Result::ok) {
        if !entry.file_type().is_dir() || !is_artifact(entry.path()) {
            continue;
        }
        let Ok(metadata) = fs::symlink_metadata(entry.path()) else {
            continue;
        };
        if metadata.file_type().is_symlink() {
            continue;
        }
        let modified = metadata.modified().unwrap_or(UNIX_EPOCH);
        let age = now.duration_since(modified).unwrap_or_default();
        if age < minimum_age {
            continue;
        }
        found.push(DiscoveredArtifact {
            path: entry.path().to_path_buf(),
            kind: entry.file_name().to_string_lossy().into_owned(),
            modified_unix: modified
                .duration_since(UNIX_EPOCH)
                .ok()
                .map(|duration| duration.as_secs()),
            age_days: age.as_secs() / 86_400,
        });
    }
    found
}

fn visit_project_entry(entry: &DirEntry) -> bool {
    entry.depth() == 0 || entry.file_name() != ".git"
}

fn is_artifact(path: &Path) -> bool {
    path.file_name()
        .and_then(|name| name.to_str())
        .map(|name| ARTIFACTS.contains(&name))
        .unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn finds_build_artifacts_but_never_git_contents() {
        let root = tempdir().unwrap();
        let target = root.path().join("project/target");
        let hidden_target = root.path().join("project/.git/target");
        fs::create_dir_all(&target).unwrap();
        fs::create_dir_all(&hidden_target).unwrap();
        fs::write(target.join("binary"), vec![0; 50]).unwrap();
        fs::write(hidden_target.join("object"), vec![0; 100]).unwrap();

        let results = scan_artifacts(&[root.path().to_path_buf()], 0);
        assert_eq!(results.len(), 1);
        assert_eq!(results[0].path, target);
    }
}
