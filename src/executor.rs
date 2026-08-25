use std::ffi::OsStr;
use std::fs;
use std::path::{Component, Path, PathBuf};
use std::process::{Command, Output};

use crate::distro::PACMAN_TRANSACTION_LOCK;
use crate::model::{ActionResult, CleanupAction, CleanupItem};
use crate::uninstall::{
    Application, ApplicationSource, UninstallPreview, is_protected_package, is_valid_identifier,
};

#[derive(Debug, thiserror::Error)]
pub enum ExecutionError {
    #[error("unsafe cleanup target rejected: {0}")]
    UnsafePath(PathBuf),
    #[error("symbolic-link cleanup target rejected: {0}")]
    Symlink(PathBuf),
    #[error("cleanup command is not allowed: {program} {args}")]
    UnsafeCommand { program: String, args: String },
    #[error(
        "a package transaction is in progress ({0}); rerun once it finishes so package archives \
         stay available to it"
    )]
    PackageTransactionInProgress(PathBuf),
    #[error("I/O error while processing {path}: {source}")]
    Io {
        path: PathBuf,
        #[source]
        source: std::io::Error,
    },
}

pub trait CommandRunner {
    fn run(&self, program: &str, args: &[String], requires_root: bool) -> std::io::Result<Output>;
}

pub struct ProcessCommandRunner;

impl CommandRunner for ProcessCommandRunner {
    fn run(&self, program: &str, args: &[String], requires_root: bool) -> std::io::Result<Output> {
        if requires_root && !is_effective_root() {
            Command::new("sudo")
                .arg("--")
                .arg(program)
                .args(args)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .output()
        } else {
            Command::new(program)
                .args(args)
                .env("LC_ALL", "C")
                .env("LANG", "C")
                .output()
        }
    }
}

pub struct Executor<R = ProcessCommandRunner> {
    home: PathBuf,
    runner: R,
    transaction_locks: Vec<PathBuf>,
}

impl Executor<ProcessCommandRunner> {
    pub fn new(home: PathBuf) -> Self {
        Self::with_runner(home, ProcessCommandRunner)
    }
}

impl<R: CommandRunner> Executor<R> {
    pub fn with_runner(home: PathBuf, runner: R) -> Self {
        Self {
            home,
            runner,
            transaction_locks: vec![PathBuf::from(PACMAN_TRANSACTION_LOCK)],
        }
    }

    /// Overrides the lock files that mark a package transaction as running.
    pub fn with_transaction_locks(mut self, locks: Vec<PathBuf>) -> Self {
        self.transaction_locks = locks;
        self
    }

    /// Refuses cleanups that would pull package archives or cache state out
    /// from under a running transaction.
    ///
    /// A transaction reads the archives it installs straight from the package
    /// caches, so emptying them mid-upgrade turns a routine cleanup into a
    /// failed upgrade, and a package database left half written.
    fn ensure_no_package_transaction(&self, action: &CleanupAction) -> Result<(), ExecutionError> {
        if !self.touches_package_manager_state(action) {
            return Ok(());
        }
        match self
            .transaction_locks
            .iter()
            .find(|lock| lock.exists())
            .cloned()
        {
            Some(lock) => Err(ExecutionError::PackageTransactionInProgress(lock)),
            None => Ok(()),
        }
    }

    fn touches_package_manager_state(&self, action: &CleanupAction) -> bool {
        match action {
            CleanupAction::Command { program, .. } => is_package_manager_program(program),
            CleanupAction::CommandSequence { commands } => commands
                .iter()
                .any(|command| is_package_manager_program(&command.program)),
            CleanupAction::RemovePath { path, .. } => path
                .strip_prefix(&self.home)
                .is_ok_and(|relative| PACKAGE_BUILD_CACHES.contains(&&*relative.to_string_lossy())),
            CleanupAction::RemovePersonalFile { .. } => false,
        }
    }

    pub fn execute(&self, item: &CleanupItem, dry_run: bool) -> ActionResult {
        let outcome = match self.ensure_no_package_transaction(&item.action) {
            Err(error) => Err(error.to_string()),
            Ok(()) => self.execute_action(&item.action, dry_run),
        };

        ActionResult {
            item_id: item.id.clone(),
            label: item.label.clone(),
            success: outcome.is_ok(),
            dry_run,
            estimated_bytes: item.estimated_bytes,
            message: outcome
                .map(|()| "completed".into())
                .unwrap_or_else(|message| message),
        }
    }

    fn execute_action(&self, action: &CleanupAction, dry_run: bool) -> Result<(), String> {
        match action {
            CleanupAction::RemovePath {
                path,
                contents_only,
            } => self
                .validate_path(path)
                .and_then(|()| self.ensure_not_symlink(path))
                .and_then(|()| {
                    if dry_run || !path.exists() {
                        Ok(())
                    } else if *contents_only {
                        remove_contents(path)
                    } else {
                        remove_entry(path)
                    }
                })
                .map_err(|error| error.to_string()),
            CleanupAction::RemovePersonalFile { path } => self
                .validate_personal_file(path)
                .and_then(|()| {
                    if dry_run || !path.exists() {
                        Ok(())
                    } else {
                        remove_entry(path)
                    }
                })
                .map_err(|error| error.to_string()),
            CleanupAction::Command {
                program,
                args,
                requires_root,
            } => self.execute_command(program, args, *requires_root, dry_run),
            CleanupAction::CommandSequence { commands } => {
                commands.iter().try_for_each(|command| {
                    self.execute_command(
                        &command.program,
                        &command.args,
                        command.requires_root,
                        dry_run,
                    )
                })
            }
        }
    }

    pub fn preview_uninstall(&self, application: &Application) -> Result<UninstallPreview, String> {
        validate_application(application)?;
        let package = application.package.clone();
        let (program, args, expected_success) = match application.source {
            ApplicationSource::Pacman => (
                "pacman",
                vec![
                    "-Rs".into(),
                    "--print".into(),
                    "--print-format".into(),
                    "%n\t%v\t%s".into(),
                    "--".into(),
                    package.clone(),
                ],
                true,
            ),
            ApplicationSource::Apt => (
                "apt-get",
                vec!["--simulate".into(), "remove".into(), package.clone()],
                true,
            ),
            ApplicationSource::Dnf => (
                "dnf",
                vec!["--assumeno".into(), "remove".into(), package.clone()],
                false,
            ),
            ApplicationSource::FlatpakUser | ApplicationSource::FlatpakSystem => {
                return Ok(UninstallPreview {
                    application_id: application.id.clone(),
                    command: uninstall_command_display(application),
                    removals: vec![format!("{} ({})", application.package, application.version)],
                    raw: "Flatpak application data is preserved by default.".into(),
                    preserves_user_data: true,
                });
            }
        };
        let output = self
            .runner
            .run(program, &args, false)
            .map_err(|error| format!("failed to preview {}: {error}", application.id))?;
        let raw = combined_output(&output);
        if expected_success && !output.status.success() {
            return Err(format!(
                "preview command exited with {}: {}",
                output.status,
                raw.trim()
            ));
        }
        if !expected_success && !output.status.success() && !raw.contains(&package) {
            return Err(format!(
                "DNF could not produce a removal plan for {}: {}",
                application.id,
                raw.trim()
            ));
        }
        let removals = parse_uninstall_removals(application.source, &raw);
        if removals.is_empty() {
            return Err(format!(
                "the package manager returned an empty removal plan for {}",
                application.id
            ));
        }
        Ok(UninstallPreview {
            application_id: application.id.clone(),
            command: uninstall_command_display(application),
            removals,
            raw,
            preserves_user_data: true,
        })
    }

    pub fn execute_uninstall(&self, application: &Application, dry_run: bool) -> ActionResult {
        let outcome = validate_application(application).and_then(|()| {
            let (program, args, requires_root) = uninstall_command(application);
            self.execute_command(program, &args, requires_root, dry_run)
        });
        ActionResult {
            item_id: application.id.clone(),
            label: format!("Uninstall {} ({})", application.name, application.id),
            success: outcome.is_ok(),
            dry_run,
            estimated_bytes: application.installed_bytes,
            message: outcome
                .map(|()| "completed; user data preserved".into())
                .unwrap_or_else(|message| message),
        }
    }

    pub fn validate_path(&self, path: &Path) -> Result<(), ExecutionError> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path == self.home
            || !path.starts_with(&self.home)
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        let relative = path
            .strip_prefix(&self.home)
            .map_err(|_| ExecutionError::UnsafePath(path.to_path_buf()))?;
        if relative.components().any(
            |component| matches!(component, Component::Normal(name) if name == OsStr::new(".git")),
        ) {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        let protected = [".config", ".ssh", ".gnupg"];
        if relative
            .components()
            .next()
            .is_some_and(|component| matches!(component, Component::Normal(name) if protected.contains(&name.to_string_lossy().as_ref())))
        {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }

        let normalized = relative.to_string_lossy();
        let known = [
            ".cache/yay",
            ".cache/paru",
            ".cache/thumbnails",
            ".cache/mozilla",
            ".cache/chromium",
            ".cache/google-chrome",
            ".cache/BraveSoftware",
            ".cache/vivaldi",
            ".cache/opera",
            ".local/share/Trash",
            ".cache/pip",
            ".npm/_cacache",
            ".cache/pnpm",
            ".cache/yarn",
            ".cargo/registry/cache",
            ".cargo/registry/src",
            ".cargo/git",
            "go/pkg/mod",
            ".gradle/caches",
            ".cache/composer",
        ];
        let artifact = path
            .file_name()
            .and_then(OsStr::to_str)
            .is_some_and(|name| {
                matches!(
                    name,
                    "node_modules" | "target" | ".build" | "build" | "dist" | ".venv"
                )
            });
        if !known.contains(&normalized.as_ref()) && !artifact {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        self.ensure_no_symlink_ancestors(path)?;
        Ok(())
    }

    pub fn validate_personal_file(&self, path: &Path) -> Result<(), ExecutionError> {
        if !path.is_absolute()
            || path == Path::new("/")
            || path == self.home
            || !path.starts_with(&self.home)
            || path
                .components()
                .any(|component| component == Component::ParentDir)
        {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        let relative = path
            .strip_prefix(&self.home)
            .map_err(|_| ExecutionError::UnsafePath(path.to_path_buf()))?;
        if relative.components().any(|component| {
            matches!(component, Component::Normal(name) if name.to_string_lossy().starts_with('.'))
        }) || relative.starts_with("go/pkg")
        {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        self.ensure_no_symlink_ancestors(path)?;
        let metadata = fs::symlink_metadata(path).map_err(|source| ExecutionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        if metadata.file_type().is_symlink() || !metadata.is_file() {
            return Err(ExecutionError::UnsafePath(path.to_path_buf()));
        }
        Ok(())
    }

    fn execute_command(
        &self,
        program: &str,
        args: &[String],
        requires_root: bool,
        dry_run: bool,
    ) -> Result<(), String> {
        if !is_allowed_command(program, args, requires_root) {
            return Err(ExecutionError::UnsafeCommand {
                program: program.into(),
                args: args.join(" "),
            }
            .to_string());
        }
        if dry_run {
            return Ok(());
        }
        let output = self
            .runner
            .run(program, args, requires_root)
            .map_err(|error| error.to_string())?;
        if output.status.success() {
            return Ok(());
        }
        let stderr = String::from_utf8_lossy(&output.stderr);
        let detail = stderr.trim();
        Err(if detail.is_empty() {
            format!("command exited with {}", output.status)
        } else {
            detail.to_owned()
        })
    }

    fn ensure_no_symlink_ancestors(&self, path: &Path) -> Result<(), ExecutionError> {
        let relative = path
            .strip_prefix(&self.home)
            .map_err(|_| ExecutionError::UnsafePath(path.to_path_buf()))?;
        let mut current = self.home.clone();
        for component in relative.components() {
            current.push(component.as_os_str());
            match fs::symlink_metadata(&current) {
                Ok(metadata) if metadata.file_type().is_symlink() => {
                    return Err(ExecutionError::Symlink(current));
                }
                Ok(_) => {}
                Err(error) if error.kind() == std::io::ErrorKind::NotFound => break,
                Err(source) => {
                    return Err(ExecutionError::Io {
                        path: current,
                        source,
                    });
                }
            }
        }
        Ok(())
    }

    fn ensure_not_symlink(&self, path: &Path) -> Result<(), ExecutionError> {
        match fs::symlink_metadata(path) {
            Ok(metadata) if metadata.file_type().is_symlink() => {
                Err(ExecutionError::Symlink(path.to_path_buf()))
            }
            Ok(_) => Ok(()),
            Err(error) if error.kind() == std::io::ErrorKind::NotFound => Ok(()),
            Err(source) => Err(ExecutionError::Io {
                path: path.to_path_buf(),
                source,
            }),
        }
    }
}

fn remove_contents(path: &Path) -> Result<(), ExecutionError> {
    let entries = fs::read_dir(path).map_err(|source| ExecutionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    for entry in entries {
        let entry = entry.map_err(|source| ExecutionError::Io {
            path: path.to_path_buf(),
            source,
        })?;
        remove_entry(&entry.path())?;
    }
    Ok(())
}

fn remove_entry(path: &Path) -> Result<(), ExecutionError> {
    let metadata = fs::symlink_metadata(path).map_err(|source| ExecutionError::Io {
        path: path.to_path_buf(),
        source,
    })?;
    let result = if metadata.is_dir() && !metadata.file_type().is_symlink() {
        fs::remove_dir_all(path)
    } else {
        fs::remove_file(path)
    };
    result.map_err(|source| ExecutionError::Io {
        path: path.to_path_buf(),
        source,
    })
}

/// Home-relative caches where AUR helpers keep the built package archives a
/// pacman transaction installs from.
const PACKAGE_BUILD_CACHES: &[&str] = &[".cache/yay", ".cache/paru"];

fn is_package_manager_program(program: &str) -> bool {
    matches!(program, "pacman" | "paccache" | "apt-get" | "dnf")
}

fn is_allowed_command(program: &str, args: &[String], requires_root: bool) -> bool {
    let values: Vec<&str> = args.iter().map(String::as_str).collect();
    if matches!(
        (program, values.as_slice(), requires_root),
        ("paccache", ["-rk1"], true)
            | ("paccache", ["-ruk0"], true)
            | ("apt-get", ["clean"], true)
            | ("dnf", ["clean", "all"], true)
            | ("journalctl", ["--vacuum-size=200M"], true)
            | ("docker", ["system", "prune", "-f"], false)
            | ("flatpak", ["uninstall", "--unused", "-y"], false)
    ) {
        return true;
    }
    match (program, values.as_slice(), requires_root) {
        ("pacman", ["-Rns", "--noconfirm", "--", package], true)
        | ("apt-get", ["--yes", "remove", package], true)
        | ("dnf", ["--assumeyes", "remove", package], true) => {
            is_valid_identifier(package) && !is_protected_package(package)
        }
        ("flatpak", ["uninstall", "--user", "-y", application], false)
        | ("flatpak", ["uninstall", "--system", "-y", application], false) => {
            is_valid_identifier(application)
        }
        _ => false,
    }
}

fn validate_application(application: &Application) -> Result<(), String> {
    if !is_valid_identifier(&application.package)
        || application.id != Application::new_id(application.source, &application.package)
        || (!application.source.is_flatpak() && is_protected_package(&application.package))
    {
        return Err(format!(
            "unsafe or protected application identifier rejected: {}",
            application.id
        ));
    }
    Ok(())
}

fn uninstall_command(application: &Application) -> (&'static str, Vec<String>, bool) {
    let package = application.package.clone();
    match application.source {
        ApplicationSource::Pacman => (
            "pacman",
            vec!["-Rns".into(), "--noconfirm".into(), "--".into(), package],
            true,
        ),
        ApplicationSource::Apt => (
            "apt-get",
            vec!["--yes".into(), "remove".into(), package],
            true,
        ),
        ApplicationSource::Dnf => (
            "dnf",
            vec!["--assumeyes".into(), "remove".into(), package],
            true,
        ),
        ApplicationSource::FlatpakUser => (
            "flatpak",
            vec!["uninstall".into(), "--user".into(), "-y".into(), package],
            false,
        ),
        ApplicationSource::FlatpakSystem => (
            "flatpak",
            vec!["uninstall".into(), "--system".into(), "-y".into(), package],
            false,
        ),
    }
}

fn uninstall_command_display(application: &Application) -> String {
    let (program, args, requires_root) = uninstall_command(application);
    let prefix = if requires_root { "sudo -- " } else { "" };
    format!("{prefix}{program} {}", args.join(" "))
}

fn combined_output(output: &Output) -> String {
    let mut text = String::from_utf8_lossy(&output.stdout).into_owned();
    let stderr = String::from_utf8_lossy(&output.stderr);
    if !stderr.trim().is_empty() {
        if !text.ends_with('\n') && !text.is_empty() {
            text.push('\n');
        }
        text.push_str(&stderr);
    }
    text
}

fn parse_uninstall_removals(source: ApplicationSource, raw: &str) -> Vec<String> {
    match source {
        ApplicationSource::Pacman => raw
            .lines()
            .filter(|line| !line.trim().is_empty())
            .map(|line| {
                let fields: Vec<_> = line.split('\t').collect();
                if fields.len() >= 3 {
                    let size = fields[2]
                        .parse::<u64>()
                        .map(crate::size::format_bytes)
                        .unwrap_or_else(|_| fields[2].into());
                    format!("{} {} ({size})", fields[0], fields[1])
                } else {
                    line.trim().to_owned()
                }
            })
            .collect(),
        ApplicationSource::Apt => raw
            .lines()
            .filter_map(|line| line.strip_prefix("Remv "))
            .filter_map(|line| line.split_whitespace().next())
            .map(str::to_owned)
            .collect(),
        ApplicationSource::Dnf => raw
            .lines()
            .map(str::trim)
            .filter(|line| {
                !line.is_empty()
                    && !line.starts_with("Dependencies resolved")
                    && !line.starts_with("Transaction Summary")
                    && !line.starts_with("Operation aborted")
            })
            .take(80)
            .map(str::to_owned)
            .collect(),
        ApplicationSource::FlatpakUser | ApplicationSource::FlatpakSystem => Vec::new(),
    }
}

fn is_effective_root() -> bool {
    fs::read_to_string("/proc/self/status")
        .ok()
        .and_then(|content| {
            content
                .lines()
                .find(|line| line.starts_with("Uid:"))
                .and_then(|line| line.split_whitespace().nth(2))
                .and_then(|value| value.parse::<u32>().ok())
        })
        == Some(0)
}

#[cfg(test)]
mod tests {
    use std::os::unix::process::ExitStatusExt;
    use std::sync::{Arc, Mutex};

    use super::*;
    use crate::model::{CleanupGroup, CommandSpec, Risk};
    use tempfile::tempdir;

    struct SuccessfulRunner;

    impl CommandRunner for SuccessfulRunner {
        fn run(&self, _: &str, _: &[String], _: bool) -> std::io::Result<Output> {
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: Vec::new(),
                stderr: Vec::new(),
            })
        }
    }

    fn item(path: PathBuf) -> CleanupItem {
        CleanupItem {
            id: "test".into(),
            group: CleanupGroup::Dev,
            label: "test".into(),
            estimated_bytes: 1,
            risk: Risk::Explicit,
            action: CleanupAction::RemovePath {
                path,
                contents_only: false,
            },
        }
    }

    #[test]
    fn rejects_home_root_and_git_paths() {
        let home = PathBuf::from("/home/tester");
        let executor = Executor::with_runner(home.clone(), SuccessfulRunner);
        assert!(executor.validate_path(&home).is_err());
        assert!(executor.validate_path(Path::new("/")).is_err());
        assert!(
            executor
                .validate_path(Path::new("/home/tester/project/.git/target"))
                .is_err()
        );
    }

    #[test]
    fn refuses_unknown_paths_even_inside_home() {
        let home = PathBuf::from("/home/tester");
        let executor = Executor::with_runner(home, SuccessfulRunner);
        assert!(
            executor
                .validate_path(Path::new("/home/tester/Documents"))
                .is_err()
        );
    }

    fn paccache_item() -> CleanupItem {
        CleanupItem {
            id: "packages.arch.paccache".into(),
            group: CleanupGroup::System,
            label: "old package versions".into(),
            estimated_bytes: 1,
            risk: Risk::Elevated,
            action: CleanupAction::CommandSequence {
                commands: vec![CommandSpec {
                    program: "paccache".into(),
                    args: vec!["-rk1".into()],
                    requires_root: true,
                }],
            },
        }
    }

    fn build_cache_item(path: PathBuf) -> CleanupItem {
        CleanupItem {
            id: "user.cache.yay".into(),
            group: CleanupGroup::User,
            label: "yay build cache".into(),
            estimated_bytes: 1,
            risk: Risk::Low,
            action: CleanupAction::RemovePath {
                path,
                contents_only: true,
            },
        }
    }

    #[test]
    fn refuses_package_cache_cleanup_while_a_transaction_runs() {
        let root = tempdir().unwrap();
        let lock = root.path().join("db.lck");
        fs::write(&lock, b"").unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner)
            .with_transaction_locks(vec![lock]);

        let result = executor.execute(&paccache_item(), false);

        assert!(!result.success);
        assert!(
            result
                .message
                .contains("package transaction is in progress"),
            "{}",
            result.message
        );
    }

    #[test]
    fn refuses_build_cache_removal_while_a_transaction_runs() {
        let root = tempdir().unwrap();
        let lock = root.path().join("db.lck");
        fs::write(&lock, b"").unwrap();
        let cache = root.path().join(".cache/yay");
        fs::create_dir_all(&cache).unwrap();
        fs::write(cache.join("package.pkg.tar.zst"), b"data").unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner)
            .with_transaction_locks(vec![lock]);

        let result = executor.execute(&build_cache_item(cache.clone()), false);

        assert!(!result.success);
        assert!(
            cache.join("package.pkg.tar.zst").exists(),
            "the archive a running transaction may still install from was removed"
        );
    }

    #[test]
    fn allows_package_cache_cleanup_once_the_lock_is_gone() {
        let root = tempdir().unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner)
            .with_transaction_locks(vec![root.path().join("db.lck")]);

        let result = executor.execute(&paccache_item(), false);

        assert!(result.success, "{}", result.message);
    }

    #[test]
    fn unrelated_cleanups_run_during_a_transaction() {
        let root = tempdir().unwrap();
        let lock = root.path().join("db.lck");
        fs::write(&lock, b"").unwrap();
        let target = root.path().join("project/target");
        fs::create_dir_all(&target).unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner)
            .with_transaction_locks(vec![lock]);

        let result = executor.execute(&item(target.clone()), false);

        assert!(result.success, "{}", result.message);
        assert!(!target.exists());
    }

    #[test]
    fn removes_exact_build_artifact_after_validation() {
        let root = tempdir().unwrap();
        let target = root.path().join("project/target");
        fs::create_dir_all(&target).unwrap();
        fs::write(target.join("binary"), b"data").unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner);
        let result = executor.execute(&item(target.clone()), false);
        assert!(result.success, "{}", result.message);
        assert!(!target.exists());
    }

    #[test]
    fn dry_run_preserves_target() {
        let root = tempdir().unwrap();
        let target = root.path().join("project/target");
        fs::create_dir_all(&target).unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner);
        assert!(executor.execute(&item(target.clone()), true).success);
        assert!(target.exists());
    }

    #[test]
    fn removes_an_exact_personal_file() {
        let root = tempdir().unwrap();
        let file = root.path().join("Downloads/archive.iso");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"data").unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner);
        let item = CleanupItem {
            id: "large-file:test".into(),
            group: CleanupGroup::User,
            label: "archive.iso".into(),
            estimated_bytes: 4,
            risk: Risk::Explicit,
            action: CleanupAction::RemovePersonalFile { path: file.clone() },
        };

        let result = executor.execute(&item, false);
        assert!(result.success, "{}", result.message);
        assert!(!file.exists());
    }

    #[test]
    fn rejects_hidden_application_data_as_a_personal_file() {
        let root = tempdir().unwrap();
        let file = root.path().join(".models/model.bin");
        fs::create_dir_all(file.parent().unwrap()).unwrap();
        fs::write(&file, b"data").unwrap();
        let executor = Executor::with_runner(root.path().to_path_buf(), SuccessfulRunner);

        assert!(executor.validate_personal_file(&file).is_err());
        assert!(file.exists());
    }

    fn application(package: &str) -> Application {
        Application {
            id: Application::new_id(ApplicationSource::Pacman, package),
            name: package.into(),
            package: package.into(),
            version: "1.0".into(),
            source: ApplicationSource::Pacman,
            installed_bytes: 100,
            user_data_bytes: 0,
            desktop_file: None,
            user_data_paths: Vec::new(),
        }
    }

    type RecordedCalls = Arc<Mutex<Vec<(String, Vec<String>, bool)>>>;

    struct RecordingRunner {
        calls: RecordedCalls,
    }

    impl CommandRunner for RecordingRunner {
        fn run(
            &self,
            program: &str,
            args: &[String],
            requires_root: bool,
        ) -> std::io::Result<Output> {
            self.calls
                .lock()
                .unwrap()
                .push((program.into(), args.to_vec(), requires_root));
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout: b"firefox\t1.0\t100\n".to_vec(),
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn uninstall_uses_an_exact_source_specific_command() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor = Executor::with_runner(
            PathBuf::from("/home/tester"),
            RecordingRunner {
                calls: calls.clone(),
            },
        );
        let result = executor.execute_uninstall(&application("firefox"), false);
        assert!(result.success, "{}", result.message);
        assert_eq!(
            calls.lock().unwrap().as_slice(),
            [(
                "pacman".into(),
                vec![
                    "-Rns".into(),
                    "--noconfirm".into(),
                    "--".into(),
                    "firefox".into()
                ],
                true,
            )]
        );
    }

    #[test]
    fn uninstall_preview_reports_package_manager_impact() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor =
            Executor::with_runner(PathBuf::from("/home/tester"), RecordingRunner { calls });
        let preview = executor.preview_uninstall(&application("firefox")).unwrap();
        assert_eq!(preview.removals, ["firefox 1.0 (100 B)"]);
        assert!(preview.preserves_user_data);
    }

    #[test]
    fn protected_packages_never_reach_the_command_runner() {
        let calls = Arc::new(Mutex::new(Vec::new()));
        let executor = Executor::with_runner(
            PathBuf::from("/home/tester"),
            RecordingRunner {
                calls: calls.clone(),
            },
        );
        let result = executor.execute_uninstall(&application("systemd"), false);
        assert!(!result.success);
        assert!(calls.lock().unwrap().is_empty());
    }
}
