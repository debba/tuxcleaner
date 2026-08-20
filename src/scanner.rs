use std::collections::HashMap;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::sync::atomic::AtomicBool;

use anyhow::Result;
use rayon::prelude::*;

use crate::analyze::parallel_dir_size;
use crate::distro::{Distribution, DistroFamily};
use crate::model::{CleanupAction, CleanupGroup, CleanupItem, Risk, ScanReport};

const USER_CACHE_PATHS: &[(&str, &str)] = &[
    (".cache/yay", "yay build cache"),
    (".cache/paru", "paru build cache"),
    (".cache/thumbnails", "Desktop thumbnails"),
    (".cache/mozilla", "Firefox cache"),
    (".cache/chromium", "Chromium cache"),
    (".cache/google-chrome", "Google Chrome cache"),
    (".cache/BraveSoftware", "Brave cache"),
    (".cache/vivaldi", "Vivaldi cache"),
    (".cache/opera", "Opera cache"),
];

const DEV_CACHE_PATHS: &[(&str, &str)] = &[
    (".cache/pip", "pip cache"),
    (".npm/_cacache", "npm content cache"),
    (".cache/pnpm", "pnpm cache"),
    (".cache/yarn", "Yarn cache"),
    (".cargo/registry/cache", "Cargo package cache"),
    (".cargo/registry/src", "Cargo unpacked registry sources"),
    (".cargo/git", "Cargo Git checkout cache"),
    ("go/pkg/mod", "Go module cache"),
    (".gradle/caches", "Gradle cache"),
    (".cache/composer", "Composer cache"),
];

pub struct Scanner {
    home: PathBuf,
    distro: Distribution,
}

impl Scanner {
    pub fn new(home: PathBuf, distro: Distribution) -> Self {
        Self { home, distro }
    }

    pub fn system_default() -> Result<Self> {
        let home = dirs::home_dir()
            .ok_or_else(|| anyhow::anyhow!("could not determine home directory"))?;
        Ok(Self::new(home, Distribution::detect()?))
    }

    pub fn scan(&self) -> ScanReport {
        let mut items = Vec::new();
        let mut warnings = Vec::new();

        self.scan_packages(&mut items, &mut warnings);
        self.scan_system(&mut items);
        self.scan_known_paths(USER_CACHE_PATHS, CleanupGroup::User, &mut items);
        self.scan_trash(&mut items);
        self.scan_known_paths(DEV_CACHE_PATHS, CleanupGroup::Dev, &mut items);
        self.scan_containers(&mut items);

        if self.distro.family == DistroFamily::Unsupported {
            warnings.push(format!(
                "{} is not yet supported for package cleanup; user and developer caches are still available",
                self.distro.name
            ));
        }

        items.sort_by(|a, b| {
            a.group
                .title()
                .cmp(b.group.title())
                .then_with(|| b.estimated_bytes.cmp(&a.estimated_bytes))
        });
        ScanReport::from_items(self.distro.name.clone(), items, warnings)
    }

    fn scan_packages(&self, items: &mut Vec<CleanupItem>, warnings: &mut Vec<String>) {
        let estimated = self
            .distro
            .package_cache_paths()
            .iter()
            .map(Path::new)
            .map(dir_size)
            .sum();

        if let Some(item) = self.distro.package_cleanup_item(estimated) {
            let program = match &item.action {
                CleanupAction::Command { program, .. } => program,
                CleanupAction::CommandSequence { commands } => &commands[0].program,
                _ => unreachable!(),
            };
            if command_exists(program) {
                items.push(item);
            } else if estimated > 0 {
                warnings.push(format!(
                    "{program} is not installed; the package cache was measured but cannot be cleaned safely"
                ));
            }
        }
    }

    fn scan_system(&self, items: &mut Vec<CleanupItem>) {
        if command_exists("journalctl") {
            let journal_bytes = dir_size(Path::new("/var/log/journal"));
            let reclaimable = journal_bytes.saturating_sub(200 * 1024 * 1024);
            if reclaimable > 0 {
                items.push(CleanupItem {
                    id: "system.journal".into(),
                    group: CleanupGroup::System,
                    label: "systemd journal above 200 MiB".into(),
                    estimated_bytes: reclaimable,
                    risk: Risk::Elevated,
                    action: CleanupAction::Command {
                        program: "journalctl".into(),
                        args: vec!["--vacuum-size=200M".into()],
                        requires_root: true,
                    },
                });
            }
        }
    }

    fn scan_known_paths(
        &self,
        definitions: &[(&str, &str)],
        group: CleanupGroup,
        items: &mut Vec<CleanupItem>,
    ) {
        // Size every known path in parallel; `par_iter().map(..).collect()` preserves the
        // original `definitions` order, so the resulting items keep the exact same order as
        // the previous sequential loop.
        let sized: Vec<(PathBuf, &str, u64)> = definitions
            .par_iter()
            .map(|(relative, label)| {
                let path = self.home.join(relative);
                let estimated_bytes = dir_size(&path);
                (path, *label, estimated_bytes)
            })
            .collect();

        for ((relative, _), (path, label, estimated_bytes)) in definitions.iter().zip(sized) {
            if estimated_bytes == 0 {
                continue;
            }
            items.push(CleanupItem {
                id: format!("{}.{}", group_slug(group), relative.replace('/', ".")),
                group,
                label: label.into(),
                estimated_bytes,
                risk: Risk::Low,
                action: CleanupAction::RemovePath {
                    path,
                    contents_only: false,
                },
            });
        }
    }

    fn scan_trash(&self, items: &mut Vec<CleanupItem>) {
        let path = self.home.join(".local/share/Trash");
        let estimated_bytes = dir_size(&path);
        if estimated_bytes > 0 {
            items.push(CleanupItem {
                id: "user.trash".into(),
                group: CleanupGroup::User,
                label: "Trash contents".into(),
                estimated_bytes,
                risk: Risk::Explicit,
                action: CleanupAction::RemovePath {
                    path,
                    contents_only: true,
                },
            });
        }
    }

    fn scan_containers(&self, items: &mut Vec<CleanupItem>) {
        if command_exists("docker") {
            items.push(CleanupItem {
                id: "containers.docker".into(),
                group: CleanupGroup::Containers,
                label:
                    "Stopped containers, dangling images, networks, and build cache (never volumes)"
                        .into(),
                estimated_bytes: 0,
                risk: Risk::Elevated,
                action: CleanupAction::Command {
                    program: "docker".into(),
                    args: vec!["system".into(), "prune".into(), "-f".into()],
                    requires_root: false,
                },
            });
        }
        if command_exists("flatpak") {
            items.push(CleanupItem {
                id: "containers.flatpak".into(),
                group: CleanupGroup::Containers,
                label: "Unused Flatpak runtimes".into(),
                estimated_bytes: 0,
                risk: Risk::Elevated,
                action: CleanupAction::Command {
                    program: "flatpak".into(),
                    args: vec!["uninstall".into(), "--unused".into(), "-y".into()],
                    requires_root: false,
                },
            });
        }
    }
}

fn group_slug(group: CleanupGroup) -> &'static str {
    match group {
        CleanupGroup::System => "system",
        CleanupGroup::User => "user",
        CleanupGroup::Dev => "dev",
        CleanupGroup::Containers => "containers",
    }
}

pub fn command_exists(program: &str) -> bool {
    let Some(path) = env::var_os("PATH") else {
        return false;
    };
    env::split_paths(&path).any(|directory| {
        let candidate = directory.join(program);
        fs::metadata(candidate)
            .map(|metadata| metadata.is_file())
            .unwrap_or(false)
    })
}

pub fn dir_size(path: &Path) -> u64 {
    parallel_dir_size(path, &AtomicBool::new(false))
}

pub fn summarize_by_group(items: &[CleanupItem]) -> HashMap<CleanupGroup, u64> {
    let mut sizes = HashMap::new();
    for item in items {
        *sizes.entry(item.group).or_default() += item.estimated_bytes;
    }
    sizes
}

#[cfg(test)]
mod tests {
    use std::fs;

    use tempfile::tempdir;

    use super::*;

    #[test]
    fn dir_size_does_not_follow_symlinks() {
        let root = tempdir().unwrap();
        let outside = tempdir().unwrap();
        fs::write(outside.path().join("large"), vec![0; 4096]).unwrap();
        #[cfg(unix)]
        std::os::unix::fs::symlink(outside.path(), root.path().join("link")).unwrap();
        assert_eq!(dir_size(root.path()), 0);
    }

    #[test]
    fn scan_only_includes_existing_known_cache_paths() {
        let root = tempdir().unwrap();
        let cache = root.path().join(".cache/pip");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("wheel"), vec![0; 123]).unwrap();
        let scanner = Scanner::new(
            root.path().to_path_buf(),
            Distribution::parse_os_release("ID=custom\nNAME=Custom\n"),
        );
        let report = scanner.scan();
        assert!(report.items.iter().any(|item| item.id == "dev..cache.pip"));
        assert!(!report.items.iter().any(|item| item.id.contains("mozilla")));
    }
}
