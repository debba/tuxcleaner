use std::collections::{HashMap, HashSet};
use std::fs;
use std::path::{Path, PathBuf};
use std::process::Output;

use anyhow::Result;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use walkdir::WalkDir;

use crate::distro::{Distribution, DistroFamily};
use crate::executor::{CommandRunner, ProcessCommandRunner};
use crate::scanner::dir_size;
use crate::size::parse_size;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize, ValueEnum)]
#[serde(rename_all = "kebab-case")]
pub enum ApplicationSource {
    Pacman,
    Apt,
    Dnf,
    FlatpakUser,
    FlatpakSystem,
}

impl ApplicationSource {
    pub fn title(self) -> &'static str {
        match self {
            Self::Pacman => "pacman",
            Self::Apt => "APT",
            Self::Dnf => "DNF",
            Self::FlatpakUser => "Flatpak (user)",
            Self::FlatpakSystem => "Flatpak (system)",
        }
    }

    pub fn slug(self) -> &'static str {
        match self {
            Self::Pacman => "pacman",
            Self::Apt => "apt",
            Self::Dnf => "dnf",
            Self::FlatpakUser => "flatpak-user",
            Self::FlatpakSystem => "flatpak-system",
        }
    }

    pub fn is_flatpak(self) -> bool {
        matches!(self, Self::FlatpakUser | Self::FlatpakSystem)
    }
}

impl std::fmt::Display for ApplicationSource {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.title())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Application {
    pub id: String,
    pub name: String,
    pub package: String,
    pub version: String,
    pub source: ApplicationSource,
    pub installed_bytes: u64,
    pub user_data_bytes: u64,
    pub desktop_file: Option<PathBuf>,
    pub user_data_paths: Vec<PathBuf>,
}

impl Application {
    pub fn new_id(source: ApplicationSource, package: &str) -> String {
        format!("{}:{package}", source.slug())
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ApplicationReport {
    pub distribution: String,
    pub applications: Vec<Application>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct UninstallPreview {
    pub application_id: String,
    pub command: String,
    pub removals: Vec<String>,
    pub raw: String,
    pub preserves_user_data: bool,
}

#[derive(Debug, Clone)]
struct DesktopApplication {
    name: String,
    path: PathBuf,
}

pub struct ApplicationCatalog<R = ProcessCommandRunner> {
    distro: Distribution,
    home: PathBuf,
    desktop_dirs: Vec<PathBuf>,
    runner: R,
}

impl ApplicationCatalog<ProcessCommandRunner> {
    pub fn system_default(home: PathBuf, distro: Distribution) -> Self {
        let desktop_dirs = std::env::var_os("TUXCLEANER_DESKTOP_DIRS")
            .map(|value| std::env::split_paths(&value).collect())
            .unwrap_or_else(|| {
                vec![
                    PathBuf::from("/usr/share/applications"),
                    PathBuf::from("/usr/local/share/applications"),
                    home.join(".local/share/applications"),
                ]
            });
        Self {
            distro,
            home,
            desktop_dirs,
            runner: ProcessCommandRunner,
        }
    }
}

impl<R: CommandRunner> ApplicationCatalog<R> {
    pub fn with_runner(
        home: PathBuf,
        distro: Distribution,
        desktop_dirs: Vec<PathBuf>,
        runner: R,
    ) -> Self {
        Self {
            distro,
            home,
            desktop_dirs,
            runner,
        }
    }

    pub fn discover(&self) -> ApplicationReport {
        let mut applications = Vec::new();
        let mut warnings = Vec::new();
        let desktop_entries = discover_desktop_entries(&self.desktop_dirs);

        match self.distro.family {
            DistroFamily::Arch => self.discover_native(
                ApplicationSource::Pacman,
                &desktop_entries,
                &mut applications,
                &mut warnings,
            ),
            DistroFamily::Debian => self.discover_native(
                ApplicationSource::Apt,
                &desktop_entries,
                &mut applications,
                &mut warnings,
            ),
            DistroFamily::Fedora => self.discover_native(
                ApplicationSource::Dnf,
                &desktop_entries,
                &mut applications,
                &mut warnings,
            ),
            DistroFamily::Unsupported => warnings.push(format!(
                "{} does not have a native package uninstall provider; Flatpak applications are still available",
                self.distro.name
            )),
        }

        self.discover_flatpaks(&mut applications, &mut warnings);
        applications.sort_by(|left, right| {
            left.name
                .to_ascii_lowercase()
                .cmp(&right.name.to_ascii_lowercase())
                .then_with(|| left.id.cmp(&right.id))
        });
        applications.dedup_by(|left, right| left.id == right.id);

        ApplicationReport {
            distribution: self.distro.name.clone(),
            applications,
            warnings,
        }
    }

    fn discover_native(
        &self,
        source: ApplicationSource,
        desktop_entries: &[DesktopApplication],
        applications: &mut Vec<Application>,
        warnings: &mut Vec<String>,
    ) {
        let explicit = match self.explicit_packages(source) {
            Ok(packages) => packages,
            Err(error) => {
                warnings.push(format!(
                    "failed to list explicitly installed packages: {error}"
                ));
                return;
            }
        };
        let owners = self.owners_of(source, desktop_entries);
        let mut seen = HashSet::new();
        let mut candidates = Vec::new();
        for desktop in desktop_entries {
            let Some(package) = owners.get(&desktop.path).cloned() else {
                continue;
            };
            if !explicit.contains(&package)
                || is_protected_package(&package)
                || !seen.insert(package.clone())
            {
                continue;
            }
            candidates.push((desktop, package));
        }
        let packages: Vec<_> = candidates
            .iter()
            .map(|(_, package)| package.clone())
            .collect();
        let details = self.package_details_many(source, &packages);
        for (desktop, package) in candidates {
            let (version, installed_bytes) = details
                .get(&package)
                .cloned()
                .unwrap_or_else(|| (String::from("unknown"), 0));
            applications.push(Application {
                id: Application::new_id(source, &package),
                name: desktop.name.clone(),
                package,
                version,
                source,
                installed_bytes,
                user_data_bytes: 0,
                desktop_file: Some(desktop.path.clone()),
                user_data_paths: Vec::new(),
            });
        }
    }

    fn owners_of(
        &self,
        source: ApplicationSource,
        desktop_entries: &[DesktopApplication],
    ) -> HashMap<PathBuf, String> {
        let mut owners = HashMap::new();
        if desktop_entries.is_empty() {
            return owners;
        }
        if matches!(source, ApplicationSource::Pacman | ApplicationSource::Apt) {
            let (program, first_arg) = match source {
                ApplicationSource::Pacman => ("pacman", "-Qo"),
                ApplicationSource::Apt => ("dpkg-query", "-S"),
                _ => unreachable!(),
            };
            let mut args = vec![first_arg.into()];
            args.extend(
                desktop_entries
                    .iter()
                    .map(|entry| entry.path.to_string_lossy().into_owned()),
            );
            if let Ok(output) = self.runner.run(program, &args, false) {
                let stdout = String::from_utf8_lossy(&output.stdout);
                match source {
                    ApplicationSource::Pacman => {
                        for line in stdout.lines() {
                            let Some((path, ownership)) = line.split_once(" is owned by ") else {
                                continue;
                            };
                            let package = ownership
                                .split_whitespace()
                                .next()
                                .map(normalize_native_package)
                                .unwrap_or_default();
                            if is_valid_identifier(&package) {
                                owners.insert(PathBuf::from(path), package);
                            }
                        }
                    }
                    ApplicationSource::Apt => {
                        for line in stdout.lines() {
                            let Some((package, path)) = line.rsplit_once(": ") else {
                                continue;
                            };
                            let package = normalize_native_package(package);
                            if is_valid_identifier(&package) {
                                owners.insert(PathBuf::from(path), package);
                            }
                        }
                    }
                    _ => unreachable!(),
                }
            }
        }
        for entry in desktop_entries {
            if owners.contains_key(&entry.path) {
                continue;
            }
            if let Ok(Some(package)) = self.owner_of(source, &entry.path) {
                owners.insert(entry.path.clone(), package);
            }
        }
        owners
    }

    fn explicit_packages(&self, source: ApplicationSource) -> Result<HashSet<String>> {
        let (program, args): (&str, Vec<String>) = match source {
            ApplicationSource::Pacman => ("pacman", vec!["-Qqe".into()]),
            ApplicationSource::Apt => ("apt-mark", vec!["showmanual".into()]),
            ApplicationSource::Dnf => (
                "dnf",
                vec![
                    "repoquery".into(),
                    "--installed".into(),
                    "--userinstalled".into(),
                    "--qf".into(),
                    "%{name}".into(),
                ],
            ),
            _ => return Ok(HashSet::new()),
        };
        let output = self.query(program, &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        Ok(stdout
            .lines()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(normalize_native_package)
            .filter(|value| is_valid_identifier(value))
            .collect())
    }

    fn owner_of(&self, source: ApplicationSource, path: &Path) -> Result<Option<String>> {
        let path = path.to_string_lossy().into_owned();
        let (program, args): (&str, Vec<String>) = match source {
            ApplicationSource::Pacman => ("pacman", vec!["-Qqo".into(), path]),
            ApplicationSource::Apt => ("dpkg-query", vec!["-S".into(), path]),
            ApplicationSource::Dnf => (
                "rpm",
                vec!["-qf".into(), "--qf".into(), "%{NAME}\n".into(), path],
            ),
            _ => return Ok(None),
        };
        let output = match self.query(program, &args) {
            Ok(output) => output,
            Err(_) => return Ok(None),
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        let value = match source {
            ApplicationSource::Apt => stdout
                .lines()
                .next()
                .and_then(|line| line.split_once(':').map(|(package, _)| package)),
            _ => stdout.lines().next(),
        }
        .map(str::trim)
        .map(normalize_native_package)
        .filter(|value| is_valid_identifier(value));
        Ok(value)
    }

    fn package_details(&self, source: ApplicationSource, package: &str) -> Result<(String, u64)> {
        let (program, args): (&str, Vec<String>) = match source {
            ApplicationSource::Pacman => {
                ("pacman", vec!["-Qi".into(), "--".into(), package.into()])
            }
            ApplicationSource::Apt => (
                "dpkg-query",
                vec![
                    "-W".into(),
                    "-f=${Version}\t${Installed-Size}\n".into(),
                    package.into(),
                ],
            ),
            ApplicationSource::Dnf => (
                "rpm",
                vec![
                    "-q".into(),
                    "--qf".into(),
                    "%{VERSION}-%{RELEASE}\t%{SIZE}\n".into(),
                    package.into(),
                ],
            ),
            _ => return Ok((String::from("unknown"), 0)),
        };
        let output = self.query(program, &args)?;
        let stdout = String::from_utf8_lossy(&output.stdout);
        match source {
            ApplicationSource::Pacman => parse_pacman_details(&stdout),
            ApplicationSource::Apt => Ok(parse_tab_details(&stdout, 1024)),
            ApplicationSource::Dnf => Ok(parse_tab_details(&stdout, 1)),
            _ => unreachable!(),
        }
    }

    fn package_details_many(
        &self,
        source: ApplicationSource,
        packages: &[String],
    ) -> HashMap<String, (String, u64)> {
        if packages.is_empty() {
            return HashMap::new();
        }
        let (program, mut args): (&str, Vec<String>) = match source {
            ApplicationSource::Pacman => ("pacman", vec!["-Qi".into(), "--".into()]),
            ApplicationSource::Apt => (
                "dpkg-query",
                vec![
                    "-W".into(),
                    "-f=${Package}\t${Version}\t${Installed-Size}\n".into(),
                ],
            ),
            ApplicationSource::Dnf => (
                "rpm",
                vec![
                    "-q".into(),
                    "--qf".into(),
                    "%{NAME}\t%{VERSION}-%{RELEASE}\t%{SIZE}\n".into(),
                ],
            ),
            _ => return HashMap::new(),
        };
        args.extend(packages.iter().cloned());
        let mut details = self
            .query(program, &args)
            .map(|output| {
                let stdout = String::from_utf8_lossy(&output.stdout);
                match source {
                    ApplicationSource::Pacman => parse_pacman_detail_map(&stdout),
                    ApplicationSource::Apt => parse_tab_detail_map(&stdout, 1024),
                    ApplicationSource::Dnf => parse_tab_detail_map(&stdout, 1),
                    _ => unreachable!(),
                }
            })
            .unwrap_or_default();
        for package in packages {
            if details.contains_key(package) {
                continue;
            }
            if let Ok(value) = self.package_details(source, package) {
                details.insert(package.clone(), value);
            }
        }
        details
    }

    fn discover_flatpaks(&self, applications: &mut Vec<Application>, warnings: &mut Vec<String>) {
        let args = vec![
            "list".into(),
            "--app".into(),
            "--columns=application,name,version,size,installation".into(),
        ];
        let output = match self.query("flatpak", &args) {
            Ok(output) => output,
            Err(error) => {
                warnings.push(format!("failed to list Flatpak applications: {error}"));
                return;
            }
        };
        let stdout = String::from_utf8_lossy(&output.stdout);
        for line in stdout.lines().filter(|line| !line.trim().is_empty()) {
            let columns: Vec<_> = line.split('\t').collect();
            if columns.len() < 5 || !is_valid_identifier(columns[0]) {
                continue;
            }
            applications.push(flatpak_application(&self.home, columns));
        }
    }

    fn query(&self, program: &str, args: &[String]) -> Result<Output> {
        let output = self.runner.run(program, args, false)?;
        if output.status.success() {
            Ok(output)
        } else {
            let detail = String::from_utf8_lossy(&output.stderr);
            anyhow::bail!(
                "{program} {} exited with {}: {}",
                args.join(" "),
                output.status,
                detail.trim()
            )
        }
    }
}

fn discover_desktop_entries(directories: &[PathBuf]) -> Vec<DesktopApplication> {
    let mut entries = Vec::new();
    for directory in directories.iter().filter(|path| path.is_dir()) {
        for entry in WalkDir::new(directory)
            .max_depth(2)
            .follow_links(false)
            .into_iter()
            .filter_map(Result::ok)
            .filter(|entry| entry.file_type().is_file())
            .filter(|entry| {
                entry
                    .path()
                    .extension()
                    .is_some_and(|value| value == "desktop")
            })
        {
            if let Some(name) = parse_desktop_name(entry.path()) {
                entries.push(DesktopApplication {
                    name,
                    path: entry.path().to_path_buf(),
                });
            }
        }
    }
    entries
}

fn parse_desktop_name(path: &Path) -> Option<String> {
    let content = fs::read_to_string(path).ok()?;
    let mut in_entry = false;
    let mut name = None;
    let mut application = true;
    let mut visible = true;
    for line in content.lines().map(str::trim) {
        if line.starts_with('[') {
            in_entry = line == "[Desktop Entry]";
            continue;
        }
        if !in_entry || line.starts_with('#') {
            continue;
        }
        let Some((key, value)) = line.split_once('=') else {
            continue;
        };
        match key {
            "Name" if !value.trim().is_empty() => name = Some(value.trim().to_owned()),
            "Type" => application = value.trim() == "Application",
            "Hidden" | "NoDisplay" if value.trim().eq_ignore_ascii_case("true") => visible = false,
            _ => {}
        }
    }
    (application && visible).then_some(name).flatten()
}

fn parse_pacman_details(stdout: &str) -> Result<(String, u64)> {
    let fields: HashMap<_, _> = stdout
        .lines()
        .filter_map(|line| line.split_once(':'))
        .map(|(key, value)| (key.trim(), value.trim()))
        .collect();
    let version = fields
        .get("Version")
        .copied()
        .unwrap_or("unknown")
        .to_owned();
    let installed_bytes = fields
        .get("Installed Size")
        .map(|value| parse_reported_size(value))
        .unwrap_or(0);
    Ok((version, installed_bytes))
}

fn parse_pacman_detail_map(stdout: &str) -> HashMap<String, (String, u64)> {
    stdout
        .split("\n\n")
        .filter_map(|block| {
            let fields: HashMap<_, _> = block
                .lines()
                .filter_map(|line| line.split_once(':'))
                .map(|(key, value)| (key.trim(), value.trim()))
                .collect();
            let package = fields.get("Name")?.to_string();
            let version = fields
                .get("Version")
                .copied()
                .unwrap_or("unknown")
                .to_owned();
            let size = fields
                .get("Installed Size")
                .map(|value| parse_reported_size(value))
                .unwrap_or(0);
            Some((package, (version, size)))
        })
        .collect()
}

fn parse_tab_details(stdout: &str, size_multiplier: u64) -> (String, u64) {
    let mut fields = stdout.trim().split('\t');
    let version = fields.next().unwrap_or("unknown").trim().to_owned();
    let installed_bytes = fields
        .next()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(0)
        .saturating_mul(size_multiplier);
    (version, installed_bytes)
}

fn parse_tab_detail_map(stdout: &str, size_multiplier: u64) -> HashMap<String, (String, u64)> {
    stdout
        .lines()
        .filter_map(|line| {
            let mut fields = line.split('\t');
            let package = normalize_native_package(fields.next()?);
            let version = fields.next()?.trim().to_owned();
            let size = fields
                .next()
                .and_then(|value| value.trim().parse::<u64>().ok())
                .unwrap_or(0)
                .saturating_mul(size_multiplier);
            Some((package, (version, size)))
        })
        .collect()
}

/// Parses a human-readable size such as `441.3 MB` into bytes.
///
/// Everything that is not a digit, a decimal point, or a unit letter is
/// dropped before parsing. Discarding only whitespace is not enough: package
/// managers separate the number from its unit with a non-breaking space, and
/// commands are deliberately run under `LC_ALL=C` (see `ProcessCommandRunner`)
/// so their output is stable to parse. Under that locale GLib cannot encode
/// U+00A0 and transliterates it to a literal `?`, which is not whitespace, so
/// `flatpak list` reports `14.8?MB` and every size used to parse as zero.
fn parse_reported_size(value: &str) -> u64 {
    let normalized: String = value
        .replace(',', ".")
        .chars()
        .filter(|character| character.is_ascii_alphanumeric() || *character == '.')
        .collect();
    let upper = normalized.to_ascii_uppercase();
    for (suffix, multiplier) in [
        ("KB", 1_000_u64),
        ("MB", 1_000_000),
        ("GB", 1_000_000_000),
        ("TB", 1_000_000_000_000),
    ] {
        if upper.ends_with(suffix) {
            let number = &normalized[..normalized.len().saturating_sub(suffix.len())];
            return number
                .parse::<f64>()
                .ok()
                .filter(|value| value.is_finite() && *value >= 0.0)
                .map(|value| (value * multiplier as f64).round() as u64)
                .unwrap_or(0);
        }
    }
    parse_size(&normalized).unwrap_or(0)
}

fn nonempty(value: &str, fallback: &str) -> String {
    let value = value.trim();
    if value.is_empty() {
        fallback.to_owned()
    } else {
        value.to_owned()
    }
}

fn normalize_native_package(value: &str) -> String {
    value.split(':').next().unwrap_or(value).trim().to_owned()
}

fn flatpak_application(home: &Path, columns: Vec<&str>) -> Application {
    let source = if columns[4].trim().eq_ignore_ascii_case("user") {
        ApplicationSource::FlatpakUser
    } else {
        ApplicationSource::FlatpakSystem
    };
    let package = columns[0].trim().to_owned();
    let data_path = home.join(".var/app").join(&package);
    let user_data_paths = data_path
        .exists()
        .then_some(data_path.clone())
        .into_iter()
        .collect();
    Application {
        id: Application::new_id(source, &package),
        name: nonempty(columns[1], &package),
        package,
        version: nonempty(columns[2], "unknown"),
        source,
        installed_bytes: parse_reported_size(columns[3]),
        user_data_bytes: dir_size(&data_path),
        desktop_file: None,
        user_data_paths,
    }
}

pub fn is_valid_identifier(value: &str) -> bool {
    !value.is_empty()
        && value.len() <= 255
        && !value.starts_with('-')
        && value
            .bytes()
            .all(|byte| byte.is_ascii_alphanumeric() || b"._+:@-".contains(&byte))
}

pub fn is_protected_package(package: &str) -> bool {
    let normalized = normalize_native_package(package).to_ascii_lowercase();
    const EXACT: &[&str] = &[
        "apt",
        "base",
        "bash",
        "coreutils",
        "dnf",
        "dnf5",
        "filesystem",
        "glibc",
        "grub",
        "gdm",
        "gnome-shell",
        "kwin",
        "libc6",
        "lightdm",
        "lxsession",
        "networkmanager",
        "pacman",
        "plasma-desktop",
        "plasma-workspace",
        "polkit",
        "rpm",
        "sudo",
        "systemd",
        "xorg-server",
    ];
    EXACT.contains(&normalized.as_str())
        || normalized.starts_with("linux-image")
        || normalized.starts_with("linux-headers")
        || normalized.ends_with("-firmware")
        || normalized.ends_with("-ucode")
}

#[cfg(test)]
mod tests {
    use std::collections::BTreeMap;
    use std::os::unix::process::ExitStatusExt;
    use std::sync::Mutex;

    use tempfile::tempdir;

    use super::*;

    struct FixtureRunner {
        outputs: Mutex<BTreeMap<String, String>>,
    }

    impl FixtureRunner {
        fn new(entries: &[(&str, &str)]) -> Self {
            Self {
                outputs: Mutex::new(
                    entries
                        .iter()
                        .map(|(key, value)| ((*key).to_owned(), (*value).to_owned()))
                        .collect(),
                ),
            }
        }
    }

    impl CommandRunner for FixtureRunner {
        fn run(&self, program: &str, args: &[String], _: bool) -> std::io::Result<Output> {
            let key = format!("{program} {}", args.join(" "));
            let stdout = self
                .outputs
                .lock()
                .unwrap()
                .get(&key)
                .cloned()
                .unwrap_or_default()
                .into_bytes();
            Ok(Output {
                status: std::process::ExitStatus::from_raw(0),
                stdout,
                stderr: Vec::new(),
            })
        }
    }

    #[test]
    fn desktop_parser_skips_hidden_entries() {
        let root = tempdir().unwrap();
        let visible = root.path().join("visible.desktop");
        let hidden = root.path().join("hidden.desktop");
        fs::write(
            &visible,
            "[Desktop Entry]\nType=Application\nName=Visible App\n",
        )
        .unwrap();
        fs::write(
            &hidden,
            "[Desktop Entry]\nType=Application\nName=Hidden App\nNoDisplay=true\n",
        )
        .unwrap();
        assert_eq!(parse_desktop_name(&visible).as_deref(), Some("Visible App"));
        assert!(parse_desktop_name(&hidden).is_none());
    }

    #[test]
    fn arch_catalog_only_includes_explicit_desktop_packages() {
        let root = tempdir().unwrap();
        let desktop = root.path().join("applications/firefox.desktop");
        fs::create_dir_all(desktop.parent().unwrap()).unwrap();
        fs::write(
            &desktop,
            "[Desktop Entry]\nType=Application\nName=Firefox\n",
        )
        .unwrap();
        let runner = FixtureRunner::new(&[
            ("pacman -Qqe", "firefox\nbash\n"),
            (&format!("pacman -Qqo {}", desktop.display()), "firefox\n"),
            (
                "pacman -Qi -- firefox",
                "Name : firefox\nVersion : 140.0-1\nInstalled Size : 245 MiB\n",
            ),
        ]);
        let catalog = ApplicationCatalog::with_runner(
            root.path().to_path_buf(),
            Distribution::parse_os_release("ID=arch\nNAME=Arch Linux\n"),
            vec![desktop.parent().unwrap().to_path_buf()],
            runner,
        );
        let report = catalog.discover();
        assert_eq!(report.applications.len(), 1);
        assert_eq!(report.applications[0].id, "pacman:firefox");
        assert_eq!(report.applications[0].installed_bytes, 245 * 1024 * 1024);
    }

    #[test]
    fn debian_catalog_uses_manual_packages_and_installed_size() {
        let root = tempdir().unwrap();
        let desktop = root.path().join("applications/firefox.desktop");
        fs::create_dir_all(desktop.parent().unwrap()).unwrap();
        fs::write(
            &desktop,
            "[Desktop Entry]\nType=Application\nName=Firefox\n",
        )
        .unwrap();
        let runner = FixtureRunner::new(&[
            ("apt-mark showmanual", "firefox\nlibc6\n"),
            (
                &format!("dpkg-query -S {}", desktop.display()),
                &format!("firefox: {}\n", desktop.display()),
            ),
            (
                "dpkg-query -W -f=${Version}\t${Installed-Size}\n firefox",
                "128.0-1\t250000\n",
            ),
        ]);
        let catalog = ApplicationCatalog::with_runner(
            root.path().to_path_buf(),
            Distribution::parse_os_release("ID=ubuntu\nID_LIKE=debian\nNAME=Ubuntu\n"),
            vec![desktop.parent().unwrap().to_path_buf()],
            runner,
        );
        let report = catalog.discover();
        assert_eq!(report.applications.len(), 1);
        assert_eq!(report.applications[0].id, "apt:firefox");
        assert_eq!(report.applications[0].installed_bytes, 250_000 * 1024);
    }

    #[test]
    fn fedora_catalog_uses_userinstalled_packages() {
        let root = tempdir().unwrap();
        let desktop = root.path().join("applications/firefox.desktop");
        fs::create_dir_all(desktop.parent().unwrap()).unwrap();
        fs::write(
            &desktop,
            "[Desktop Entry]\nType=Application\nName=Firefox\n",
        )
        .unwrap();
        let runner = FixtureRunner::new(&[
            (
                "dnf repoquery --installed --userinstalled --qf %{name}",
                "firefox\nsystemd\n",
            ),
            (
                &format!("rpm -qf --qf %{{NAME}}\n {}", desktop.display()),
                "firefox\n",
            ),
            (
                "rpm -q --qf %{VERSION}-%{RELEASE}\t%{SIZE}\n firefox",
                "128.0-1.fc42\t300000000\n",
            ),
        ]);
        let catalog = ApplicationCatalog::with_runner(
            root.path().to_path_buf(),
            Distribution::parse_os_release("ID=fedora\nNAME=Fedora Linux\n"),
            vec![desktop.parent().unwrap().to_path_buf()],
            runner,
        );
        let report = catalog.discover();
        assert_eq!(report.applications.len(), 1);
        assert_eq!(report.applications[0].id, "dnf:firefox");
        assert_eq!(report.applications[0].installed_bytes, 300_000_000);
    }

    #[test]
    fn parses_flatpak_scope_and_preserves_user_data() {
        let root = tempdir().unwrap();
        let data = root.path().join(".var/app/com.spotify.Client");
        fs::create_dir_all(&data).unwrap();
        fs::write(data.join("database"), vec![0; 128]).unwrap();
        let app = flatpak_application(
            root.path(),
            vec!["com.spotify.Client", "Spotify", "1.2.3", "600 MiB", "user"],
        );
        assert_eq!(app.source, ApplicationSource::FlatpakUser);
        assert_eq!(app.user_data_bytes, 128);
        assert_eq!(app.installed_bytes, 600 * 1024 * 1024);
    }

    #[test]
    fn identifiers_and_protected_packages_are_conservative() {
        assert!(is_valid_identifier("org.mozilla.firefox"));
        assert!(!is_valid_identifier("--help"));
        assert!(!is_valid_identifier("name with spaces"));
        assert!(is_protected_package("systemd"));
        assert!(is_protected_package("linux-image-amd64"));
        assert!(!is_protected_package("firefox"));
        assert_eq!(parse_reported_size("441.3\u{a0}MB"), 441_300_000);
    }

    #[test]
    fn reported_sizes_survive_the_c_locale_transliterating_the_unit_separator() {
        // Commands run under LC_ALL=C, where GLib cannot encode the U+00A0
        // separator and emits a literal `?` instead. Every one of these spellings
        // describes the same size and must parse identically.
        assert_eq!(parse_reported_size("14.8?MB"), 14_800_000);
        assert_eq!(parse_reported_size("14.8\u{a0}MB"), 14_800_000);
        assert_eq!(parse_reported_size("14.8 MB"), 14_800_000);
        assert_eq!(parse_reported_size("14.8MB"), 14_800_000);
        // Narrow no-break and thin spaces appear in other locales.
        assert_eq!(parse_reported_size("14.8\u{202f}MB"), 14_800_000);
        assert_eq!(parse_reported_size("14.8\u{2009}MB"), 14_800_000);
        // Comma decimal separators still work alongside the substitution.
        assert_eq!(parse_reported_size("441,3?MB"), 441_300_000);
        assert_eq!(parse_reported_size("1.5?GB"), 1_500_000_000);
        // Unparseable input must stay at zero rather than guessing.
        assert_eq!(parse_reported_size("?"), 0);
        assert_eq!(parse_reported_size(""), 0);
    }
}
