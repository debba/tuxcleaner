use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::sync::atomic::{AtomicBool, AtomicU64, Ordering};
use std::sync::mpsc::{self, Receiver, Sender};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, UNIX_EPOCH};

use anyhow::{Context, Result, bail};
use rayon::prelude::*;
use serde::{Deserialize, Serialize};

use crate::model::{CleanupAction, CleanupGroup, CleanupItem, Risk};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskEntry {
    pub name: String,
    pub path: PathBuf,
    pub size: u64,
    pub is_dir: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LargeFile {
    pub path: PathBuf,
    pub size: u64,
    pub modified_unix: Option<u64>,
    pub app_data: bool,
}

impl LargeFile {
    pub fn cleanup_item(&self) -> CleanupItem {
        CleanupItem {
            id: format!("large-file:{}", self.path.display()),
            group: CleanupGroup::User,
            label: format!("Large personal file {}", self.path.display()),
            estimated_bytes: self.size,
            risk: Risk::Explicit,
            action: CleanupAction::RemovePersonalFile {
                path: self.path.clone(),
            },
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AnalysisReport {
    pub root: PathBuf,
    pub entries: Vec<DiskEntry>,
    pub large_files: Vec<LargeFile>,
    pub total_size: u64,
    pub total_files: u64,
    pub skipped_entries: u64,
}

/// Live progress emitted while a directory tree is scanned in the background.
///
/// A stream of updates always ends with exactly one of `Done` or `Error`.
#[derive(Debug, Clone)]
pub enum ScanUpdate {
    Progress {
        top: PathBuf,
        size: u64,
        files: u64,
        is_dir: bool,
    },
    Large(LargeFile),
    Skipped(u64),
    Done {
        total_size: u64,
        total_files: u64,
        skipped: u64,
    },
    Error(String),
}

pub fn analyze(root: &Path, minimum_size: u64, max_depth: usize) -> Result<AnalysisReport> {
    analyze_cancellable(root, minimum_size, max_depth, &AtomicBool::new(false))
}

pub(crate) fn analyze_cancellable(
    root: &Path,
    minimum_size: u64,
    max_depth: usize,
    cancelled: &AtomicBool,
) -> Result<AnalysisReport> {
    if !root.exists() {
        bail!("analysis path does not exist: {}", root.display());
    }
    let root =
        fs::canonicalize(root).with_context(|| format!("failed to resolve {}", root.display()))?;
    if cancelled.load(Ordering::Relaxed) {
        bail!("analysis cancelled");
    }

    let mut skipped_entries = 0_u64;
    let children: Vec<fs::DirEntry> = match fs::read_dir(&root) {
        Ok(read_dir) => read_dir.filter_map(Result::ok).collect(),
        Err(_) => {
            skipped_entries += 1;
            Vec::new()
        }
    };

    let plans: Vec<ChildPlan> = children
        .into_iter()
        .filter_map(|entry| plan_child(entry, &mut skipped_entries))
        .collect();

    let large_files: Mutex<Vec<LargeFile>> = Mutex::new(Vec::new());
    let nested_skipped = AtomicU64::new(0);

    let bucket_totals: Vec<(u64, u64)> = plans
        .par_iter()
        .map(|plan| {
            process_child(
                plan,
                &root,
                minimum_size,
                max_depth,
                cancelled,
                &large_files,
            )
        })
        .map(|totals| {
            nested_skipped.fetch_add(totals.2, Ordering::Relaxed);
            (totals.0, totals.1)
        })
        .collect();

    if cancelled.load(Ordering::Relaxed) {
        bail!("analysis cancelled");
    }

    let mut entries = Vec::with_capacity(plans.len());
    let mut total_size = 0_u64;
    let mut total_files = 0_u64;
    for (plan, (bytes, files)) in plans.into_iter().zip(bucket_totals) {
        total_size = total_size.saturating_add(bytes);
        total_files += files;
        entries.push(DiskEntry {
            name: plan
                .path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .into_owned(),
            path: plan.path,
            size: bytes,
            is_dir: plan.is_dir,
        });
    }
    entries.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.name.cmp(&b.name)));

    let mut large_files = large_files.into_inner().unwrap();
    large_files.sort_by(|a, b| b.size.cmp(&a.size).then_with(|| a.path.cmp(&b.path)));

    skipped_entries += nested_skipped.load(Ordering::Relaxed);

    Ok(AnalysisReport {
        root,
        entries,
        large_files,
        total_size,
        total_files,
        skipped_entries,
    })
}

struct ChildPlan {
    path: PathBuf,
    is_dir: bool,
    kind: ChildKind,
}

enum ChildKind {
    File(fs::Metadata),
    Dir,
    Skip,
}

fn plan_child(entry: fs::DirEntry, skipped_entries: &mut u64) -> Option<ChildPlan> {
    let name = entry.file_name();
    if should_skip_name(&name) {
        return None;
    }
    let path = entry.path();
    let is_dir = fs::metadata(&path)
        .map(|value| value.is_dir())
        .unwrap_or(false);
    let kind = match entry.file_type() {
        Ok(file_type) if file_type.is_symlink() => ChildKind::Skip,
        Ok(file_type) if file_type.is_dir() => ChildKind::Dir,
        Ok(file_type) if file_type.is_file() => match entry.metadata() {
            Ok(metadata) => ChildKind::File(metadata),
            Err(_) => {
                *skipped_entries += 1;
                ChildKind::Skip
            }
        },
        Ok(_) => ChildKind::Skip,
        Err(_) => {
            *skipped_entries += 1;
            ChildKind::Skip
        }
    };
    Some(ChildPlan { path, is_dir, kind })
}

/// Returns `(bytes, files, skipped)` for one direct child of the analysis root.
fn process_child(
    plan: &ChildPlan,
    root: &Path,
    minimum_size: u64,
    max_depth: usize,
    cancelled: &AtomicBool,
    large_files: &Mutex<Vec<LargeFile>>,
) -> (u64, u64, u64) {
    match &plan.kind {
        ChildKind::Skip => (0, 0, 0),
        ChildKind::File(metadata) => {
            check_large_file(root, minimum_size, large_files, &plan.path, metadata);
            (metadata.len(), 1, 0)
        }
        ChildKind::Dir => {
            let on_file = |path: &Path, metadata: &fs::Metadata| {
                check_large_file(root, minimum_size, large_files, path, metadata);
            };
            parallel_walk(
                &plan.path,
                1,
                max_depth,
                cancelled,
                &should_skip_name,
                &on_file,
            )
        }
    }
}

/// Symlink-safe, cancellable, parallel recursive walk of `dir`.
///
/// Never follows symlinks: any entry whose `file_type()` (an `lstat`, not a `stat`) reports
/// `is_symlink()` is skipped entirely, both for sizing and for recursion. Returns
/// `(bytes, files, skipped)` accumulated across the subtree.
fn parallel_walk<F, S>(
    dir: &Path,
    depth: usize,
    max_depth: usize,
    cancelled: &AtomicBool,
    skip: &F,
    on_file: &S,
) -> (u64, u64, u64)
where
    F: Fn(&OsStr) -> bool + Sync,
    S: Fn(&Path, &fs::Metadata) + Sync,
{
    if depth > max_depth || cancelled.load(Ordering::Relaxed) {
        return (0, 0, 0);
    }
    let entries: Vec<fs::DirEntry> = match fs::read_dir(dir) {
        Ok(read_dir) => read_dir.filter_map(Result::ok).collect(),
        Err(_) => return (0, 0, 1),
    };
    entries
        .into_par_iter()
        .map(|entry| {
            if cancelled.load(Ordering::Relaxed) {
                return (0, 0, 0);
            }
            let name = entry.file_name();
            if skip(&name) {
                return (0, 0, 0);
            }
            match entry.file_type() {
                Ok(file_type) if file_type.is_symlink() => (0, 0, 0),
                Ok(file_type) if file_type.is_dir() => parallel_walk(
                    &entry.path(),
                    depth + 1,
                    max_depth,
                    cancelled,
                    skip,
                    on_file,
                ),
                Ok(file_type) if file_type.is_file() => match entry.metadata() {
                    Ok(metadata) => {
                        let size = metadata.len();
                        on_file(&entry.path(), &metadata);
                        (size, 1, 0)
                    }
                    Err(_) => (0, 0, 1),
                },
                Ok(_) => (0, 0, 0),
                Err(_) => (0, 0, 1),
            }
        })
        .reduce(|| (0, 0, 0), |a, b| (a.0 + b.0, a.1 + b.1, a.2 + b.2))
}

/// Symlink-safe parallel total size of `path`, for callers (Clean, Purge) that only need a
/// byte count. Never follows symlinks; cooperative cancellation via `cancelled`.
pub fn parallel_dir_size(path: &Path, cancelled: &AtomicBool) -> u64 {
    let Ok(metadata) = fs::symlink_metadata(path) else {
        return 0;
    };
    if metadata.file_type().is_symlink() || metadata.is_file() {
        return metadata.len();
    }
    parallel_walk(path, 1, usize::MAX, cancelled, &|_| false, &|_, _| {}).0
}

/// Spawns a background streaming scan of `root`, reporting live per-top-level-child progress.
///
/// The returned receiver yields `ScanUpdate::Progress`/`Large`/`Skipped` messages roughly every
/// 100ms while the scan runs, and always ends with exactly one `Done` or `Error`. Setting the
/// returned `AtomicBool` requests cooperative cancellation.
pub fn spawn_streaming_scan(
    root: PathBuf,
    minimum_size: u64,
    max_depth: usize,
) -> (Receiver<ScanUpdate>, Arc<AtomicBool>) {
    let cancelled = Arc::new(AtomicBool::new(false));
    let worker_cancelled = Arc::clone(&cancelled);
    let (sender, receiver) = mpsc::channel();
    thread::spawn(move || {
        run_streaming_scan(&root, minimum_size, max_depth, &worker_cancelled, &sender);
    });
    (receiver, cancelled)
}

struct StreamBucket {
    path: PathBuf,
    is_dir: bool,
    bytes: AtomicU64,
    files: AtomicU64,
}

fn run_streaming_scan(
    root: &Path,
    minimum_size: u64,
    max_depth: usize,
    cancelled: &AtomicBool,
    sender: &Sender<ScanUpdate>,
) {
    let root = match fs::canonicalize(root) {
        Ok(root) => root,
        Err(error) => {
            let _ = sender.send(ScanUpdate::Error(format!(
                "failed to resolve {}: {error}",
                root.display()
            )));
            return;
        }
    };
    let children: Vec<fs::DirEntry> = match fs::read_dir(&root) {
        Ok(read_dir) => read_dir.filter_map(Result::ok).collect(),
        Err(error) => {
            let _ = sender.send(ScanUpdate::Error(format!(
                "failed to read {}: {error}",
                root.display()
            )));
            return;
        }
    };

    let skipped = AtomicU64::new(0);
    let mut buckets = Vec::new();
    let mut kinds = Vec::new();
    for entry in children {
        let mut local_skipped = 0_u64;
        let Some(plan) = plan_child(entry, &mut local_skipped) else {
            skipped.fetch_add(local_skipped, Ordering::Relaxed);
            continue;
        };
        skipped.fetch_add(local_skipped, Ordering::Relaxed);
        buckets.push(StreamBucket {
            path: plan.path,
            is_dir: plan.is_dir,
            bytes: AtomicU64::new(0),
            files: AtomicU64::new(0),
        });
        kinds.push(plan.kind);
    }

    let large_files: Mutex<Vec<LargeFile>> = Mutex::new(Vec::new());
    let flusher_done = AtomicBool::new(false);

    thread::scope(|scope| {
        scope.spawn(|| {
            flush_loop(&buckets, &large_files, &skipped, &flusher_done, sender);
        });

        buckets
            .par_iter()
            .zip(kinds.par_iter())
            .for_each(|(bucket, kind)| match kind {
                ChildKind::Skip => {}
                ChildKind::File(metadata) => {
                    bucket.bytes.store(metadata.len(), Ordering::Relaxed);
                    bucket.files.store(1, Ordering::Relaxed);
                    check_large_file(&root, minimum_size, &large_files, &bucket.path, metadata);
                }
                ChildKind::Dir => {
                    let on_file = |path: &Path, metadata: &fs::Metadata| {
                        bucket.bytes.fetch_add(metadata.len(), Ordering::Relaxed);
                        bucket.files.fetch_add(1, Ordering::Relaxed);
                        check_large_file(&root, minimum_size, &large_files, path, metadata);
                    };
                    let (_, _, sub_skipped) = parallel_walk(
                        &bucket.path,
                        1,
                        max_depth,
                        cancelled,
                        &should_skip_name,
                        &on_file,
                    );
                    skipped.fetch_add(sub_skipped, Ordering::Relaxed);
                }
            });

        flusher_done.store(true, Ordering::Relaxed);
    });

    for bucket in &buckets {
        let _ = sender.send(ScanUpdate::Progress {
            top: bucket.path.clone(),
            size: bucket.bytes.load(Ordering::Relaxed),
            files: bucket.files.load(Ordering::Relaxed),
            is_dir: bucket.is_dir,
        });
    }
    for file in large_files.into_inner().unwrap() {
        let _ = sender.send(ScanUpdate::Large(file));
    }

    let total_size = buckets
        .iter()
        .map(|b| b.bytes.load(Ordering::Relaxed))
        .sum();
    let total_files = buckets
        .iter()
        .map(|b| b.files.load(Ordering::Relaxed))
        .sum();
    let _ = sender.send(ScanUpdate::Done {
        total_size,
        total_files,
        skipped: skipped.load(Ordering::Relaxed),
    });
}

fn flush_loop(
    buckets: &[StreamBucket],
    large_files: &Mutex<Vec<LargeFile>>,
    skipped: &AtomicU64,
    done: &AtomicBool,
    sender: &Sender<ScanUpdate>,
) {
    let mut last_sizes = vec![0_u64; buckets.len()];
    let mut last_skipped = 0_u64;
    loop {
        thread::sleep(Duration::from_millis(100));
        for (bucket, previous) in buckets.iter().zip(last_sizes.iter_mut()) {
            let size = bucket.bytes.load(Ordering::Relaxed);
            if size != *previous {
                *previous = size;
                let _ = sender.send(ScanUpdate::Progress {
                    top: bucket.path.clone(),
                    size,
                    files: bucket.files.load(Ordering::Relaxed),
                    is_dir: bucket.is_dir,
                });
            }
        }
        {
            let mut guard = large_files.lock().unwrap();
            for file in guard.drain(..) {
                let _ = sender.send(ScanUpdate::Large(file));
            }
        }
        let current_skipped = skipped.load(Ordering::Relaxed);
        if current_skipped != last_skipped {
            last_skipped = current_skipped;
            let _ = sender.send(ScanUpdate::Skipped(current_skipped));
        }
        if done.load(Ordering::Relaxed) {
            break;
        }
    }
}

fn check_large_file(
    root: &Path,
    minimum_size: u64,
    large_files: &Mutex<Vec<LargeFile>>,
    path: &Path,
    metadata: &fs::Metadata,
) {
    let size = metadata.len();
    if size < minimum_size {
        return;
    }
    let Ok(relative) = path.strip_prefix(root) else {
        return;
    };
    if is_excluded_large_file(relative) {
        return;
    }
    let modified_unix = metadata
        .modified()
        .ok()
        .and_then(|time| time.duration_since(UNIX_EPOCH).ok())
        .map(|duration| duration.as_secs());
    large_files.lock().unwrap().push(LargeFile {
        path: path.to_path_buf(),
        size,
        modified_unix,
        app_data: relative.components().any(is_hidden_component),
    });
}

fn should_skip_name(name: &OsStr) -> bool {
    matches!(name.to_string_lossy().as_ref(), ".git" | "node_modules")
}

fn is_hidden_component(component: Component<'_>) -> bool {
    match component {
        Component::Normal(value) => value.to_string_lossy().starts_with('.'),
        _ => false,
    }
}

fn is_excluded_large_file(relative: &Path) -> bool {
    [
        Path::new(".cache"),
        Path::new(".local/share/Trash"),
        Path::new(".cargo"),
        Path::new(".npm"),
        Path::new("go/pkg"),
        Path::new(".local/share/flatpak"),
        Path::new(".local/share/docker"),
    ]
    .iter()
    .any(|excluded| relative.starts_with(excluded))
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn analyzes_top_level_usage_and_marks_hidden_app_data() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("Documents")).unwrap();
        fs::create_dir_all(root.path().join(".models")).unwrap();
        fs::write(root.path().join("Documents/video.mkv"), vec![0; 100]).unwrap();
        fs::write(root.path().join(".models/model.bin"), vec![0; 200]).unwrap();

        let report = analyze(root.path(), 50, 10).unwrap();
        assert_eq!(report.total_size, 300);
        assert_eq!(report.large_files.len(), 2);
        assert!(report.large_files[0].app_data);
    }

    #[test]
    fn excludes_git_and_node_modules_trees() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("project/.git")).unwrap();
        fs::create_dir_all(root.path().join("project/node_modules")).unwrap();
        fs::write(root.path().join("project/.git/object"), vec![0; 100]).unwrap();
        fs::write(
            root.path().join("project/node_modules/module"),
            vec![0; 100],
        )
        .unwrap();
        fs::write(root.path().join("project/source.rs"), vec![0; 10]).unwrap();
        let report = analyze(root.path(), 1, 10).unwrap();
        assert_eq!(report.total_size, 10);
    }

    #[test]
    fn excludes_known_cache_trees_from_large_file_candidates() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join(".cache/browser")).unwrap();
        fs::create_dir_all(root.path().join("go/pkg/mod")).unwrap();
        fs::create_dir_all(root.path().join("Downloads")).unwrap();
        fs::write(root.path().join(".cache/browser/cache.bin"), vec![0; 100]).unwrap();
        fs::write(root.path().join("go/pkg/mod/archive.bin"), vec![0; 100]).unwrap();
        fs::write(root.path().join("Downloads/archive.bin"), vec![0; 100]).unwrap();

        let report = analyze(root.path(), 50, 10).unwrap();
        assert_eq!(report.total_size, 300);
        assert_eq!(report.large_files.len(), 1);
        assert_eq!(
            report.large_files[0].path,
            root.path().join("Downloads/archive.bin")
        );
    }

    #[test]
    fn cancellable_analysis_stops_before_traversal() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("file.bin"), vec![0; 10]).unwrap();
        let cancelled = AtomicBool::new(true);

        let error = analyze_cancellable(root.path(), 1, 10, &cancelled).unwrap_err();

        assert_eq!(error.to_string(), "analysis cancelled");
    }

    #[test]
    fn never_follows_symlinked_directories() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("large.bin"), vec![0; 4096]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();

        let report = analyze(root.path(), 1, 10).unwrap();
        assert_eq!(report.total_size, 0);
        assert!(report.large_files.is_empty());
    }

    #[test]
    fn never_follows_symlink_loops() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("real")).unwrap();
        fs::write(root.path().join("real/small.bin"), vec![0; 10]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(root.path(), root.path().join("real/loop")).unwrap();

        let report = analyze(root.path(), 1, 10).unwrap();
        assert_eq!(report.total_size, 10);
    }

    #[test]
    fn parallel_dir_size_matches_manual_total_and_ignores_symlinks() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("a/b")).unwrap();
        fs::write(root.path().join("a/one.bin"), vec![0; 30]).unwrap();
        fs::write(root.path().join("a/b/two.bin"), vec![0; 70]).unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("large.bin"), vec![0; 999]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), root.path().join("a/link")).unwrap();

        let size = parallel_dir_size(root.path(), &AtomicBool::new(false));
        assert_eq!(size, 100);
    }

    #[test]
    fn parallel_dir_size_stops_when_cancelled() {
        let root = tempdir().unwrap();
        fs::write(root.path().join("file.bin"), vec![0; 100]).unwrap();
        let cancelled = AtomicBool::new(true);

        let size = parallel_dir_size(root.path(), &cancelled);
        assert_eq!(size, 0);
    }

    #[test]
    fn streaming_scan_reports_same_totals_as_blocking_analyze() {
        let root = tempdir().unwrap();
        fs::create_dir_all(root.path().join("Documents")).unwrap();
        fs::create_dir_all(root.path().join("project/node_modules")).unwrap();
        fs::write(root.path().join("Documents/video.mkv"), vec![0; 500]).unwrap();
        fs::write(
            root.path().join("project/node_modules/module"),
            vec![0; 1000],
        )
        .unwrap();
        fs::write(root.path().join("project/source.rs"), vec![0; 20]).unwrap();

        let expected = analyze(root.path(), 100, 10).unwrap();

        let (receiver, _cancel) = spawn_streaming_scan(root.path().to_path_buf(), 100, 10);
        let (total_size, total_files) = loop {
            match receiver.recv().unwrap() {
                ScanUpdate::Done {
                    total_size,
                    total_files,
                    ..
                } => break (total_size, total_files),
                ScanUpdate::Error(error) => panic!("streaming scan failed: {error}"),
                _ => {}
            }
        };

        assert_eq!(total_size, expected.total_size);
        assert_eq!(total_files, expected.total_files);
    }
}
