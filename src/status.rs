use std::fs;
use std::path::Path;
use std::process::Command;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::distro::Distribution;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MemoryStatus {
    pub total_bytes: u64,
    pub available_bytes: u64,
    pub used_bytes: u64,
    pub used_percent: f64,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DiskStatus {
    pub filesystem: String,
    pub mount: String,
    pub total_bytes: u64,
    pub used_bytes: u64,
    pub available_bytes: u64,
    pub used_percent: f64,
}

/// Integrity of the local package database, which a package manager rewrites
/// during every transaction and can therefore be left half written by an
/// interrupted upgrade or an unclean shutdown.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PackageDatabaseStatus {
    pub path: String,
    pub entry_count: usize,
    /// Entries whose metadata is unreadable, named as they appear on disk
    /// (`<package>-<version>-<release>`).
    pub damaged_entries: Vec<String>,
    /// A package transaction was running while this snapshot was taken.
    pub transaction_in_progress: bool,
}

impl PackageDatabaseStatus {
    pub fn is_healthy(&self) -> bool {
        self.damaged_entries.is_empty()
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SystemStatus {
    pub hostname: String,
    pub logical_cpus: usize,
    pub load_average: [f64; 3],
    pub uptime_seconds: u64,
    pub memory: MemoryStatus,
    pub disks: Vec<DiskStatus>,
    /// Absent when the distribution has no package database this tool knows
    /// how to inspect, or when the database could not be read.
    pub package_database: Option<PackageDatabaseStatus>,
}

pub fn collect() -> Result<SystemStatus> {
    Ok(SystemStatus {
        hostname: read_hostname(),
        logical_cpus: std::thread::available_parallelism()
            .map(usize::from)
            .unwrap_or(1),
        load_average: read_load_average()?,
        uptime_seconds: read_uptime()?,
        memory: read_memory()?,
        disks: read_disks()?,
        package_database: read_package_database(),
    })
}

fn read_package_database() -> Option<PackageDatabaseStatus> {
    let distro = Distribution::detect().ok()?;
    let database = distro.package_database_path()?;
    let lock = distro.package_transaction_lock_path().map(Path::new);
    inspect_package_database(Path::new(database), lock).ok()
}

/// Reports entries whose `desc` file is missing or empty.
///
/// `desc` is the only metadata file every valid entry must have content in.
/// `files` and `mtree` are legitimately empty for meta packages such as `base`
/// or `base-devel`, which own no files, so treating those as damage would
/// report healthy systems as broken.
pub fn inspect_package_database(
    database: &Path,
    lock: Option<&Path>,
) -> Result<PackageDatabaseStatus> {
    let entries =
        fs::read_dir(database).with_context(|| format!("failed to read {}", database.display()))?;
    let mut entry_count = 0;
    let mut damaged_entries = Vec::new();
    for entry in entries {
        let entry = entry.with_context(|| format!("failed to read {}", database.display()))?;
        if !entry.file_type().is_ok_and(|kind| kind.is_dir()) {
            continue;
        }
        entry_count += 1;
        let description = entry.path().join("desc");
        let readable = fs::metadata(&description).is_ok_and(|metadata| metadata.len() > 0);
        if !readable {
            damaged_entries.push(entry.file_name().to_string_lossy().into_owned());
        }
    }
    damaged_entries.sort();
    Ok(PackageDatabaseStatus {
        path: database.display().to_string(),
        entry_count,
        damaged_entries,
        transaction_in_progress: lock.is_some_and(Path::exists),
    })
}

fn read_hostname() -> String {
    fs::read_to_string("/etc/hostname")
        .map(|value| value.trim().to_owned())
        .unwrap_or_else(|_| "unknown".into())
}

fn read_load_average() -> Result<[f64; 3]> {
    let content = fs::read_to_string("/proc/loadavg").context("failed to read /proc/loadavg")?;
    let values: Vec<f64> = content
        .split_whitespace()
        .take(3)
        .map(str::parse)
        .collect::<Result<_, _>>()?;
    Ok([
        values.first().copied().unwrap_or(0.0),
        values.get(1).copied().unwrap_or(0.0),
        values.get(2).copied().unwrap_or(0.0),
    ])
}

fn read_uptime() -> Result<u64> {
    let content = fs::read_to_string("/proc/uptime").context("failed to read /proc/uptime")?;
    let seconds: f64 = content.split_whitespace().next().unwrap_or("0").parse()?;
    Ok(seconds.max(0.0) as u64)
}

fn read_memory() -> Result<MemoryStatus> {
    let content = fs::read_to_string("/proc/meminfo").context("failed to read /proc/meminfo")?;
    let value = |key: &str| -> u64 {
        content
            .lines()
            .find(|line| line.starts_with(key))
            .and_then(|line| line.split_whitespace().nth(1))
            .and_then(|value| value.parse::<u64>().ok())
            .unwrap_or(0)
            .saturating_mul(1024)
    };
    let total_bytes = value("MemTotal:");
    let available_bytes = value("MemAvailable:");
    let used_bytes = total_bytes.saturating_sub(available_bytes);
    let used_percent = percentage(used_bytes, total_bytes);
    Ok(MemoryStatus {
        total_bytes,
        available_bytes,
        used_bytes,
        used_percent,
    })
}

fn read_disks() -> Result<Vec<DiskStatus>> {
    let output = Command::new("df")
        .args(["-B1", "-P"])
        .output()
        .context("failed to run df")?;
    if !output.status.success() {
        anyhow::bail!("df exited with {}", output.status);
    }
    let text = String::from_utf8_lossy(&output.stdout);
    let disks = text
        .lines()
        .skip(1)
        .filter_map(|line| {
            let fields: Vec<_> = line.split_whitespace().collect();
            if fields.len() < 6 || !fields[0].starts_with('/') {
                return None;
            }
            let total_bytes = fields[1].parse().ok()?;
            let used_bytes = fields[2].parse().ok()?;
            let available_bytes = fields[3].parse().ok()?;
            Some(DiskStatus {
                filesystem: fields[0].into(),
                mount: fields[5..].join(" "),
                total_bytes,
                used_bytes,
                available_bytes,
                used_percent: percentage(used_bytes, total_bytes),
            })
        })
        .collect();
    Ok(disks)
}

fn percentage(part: u64, total: u64) -> f64 {
    if total == 0 {
        0.0
    } else {
        part as f64 * 100.0 / total as f64
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn percentage_handles_zero_total() {
        assert_eq!(percentage(10, 0), 0.0);
        assert_eq!(percentage(1, 4), 25.0);
    }

    fn write_entry(database: &Path, name: &str, description: &str, files: &str) {
        let entry = database.join(name);
        fs::create_dir_all(&entry).expect("entry directory");
        fs::write(entry.join("desc"), description).expect("desc");
        fs::write(entry.join("files"), files).expect("files");
    }

    #[test]
    fn reports_entries_with_empty_metadata_as_damaged() {
        let temp = tempfile::tempdir().expect("temporary database");
        let database = temp.path();
        write_entry(
            database,
            "bash-5.3.15-1",
            "%NAME%\nbash\n",
            "%FILES%\nusr/bin/bash\n",
        );
        write_entry(database, "zen-browser-bin-1.21.14b-1", "", "");

        let status = inspect_package_database(database, None).expect("inspection");

        assert_eq!(status.entry_count, 2);
        assert_eq!(status.damaged_entries, vec!["zen-browser-bin-1.21.14b-1"]);
        assert!(!status.is_healthy());
        assert!(!status.transaction_in_progress);
    }

    #[test]
    fn meta_packages_without_files_stay_healthy() {
        let temp = tempfile::tempdir().expect("temporary database");
        let database = temp.path();
        // base owns no files, so an empty `files` entry is normal for it.
        write_entry(database, "base-3-2", "%NAME%\nbase\n", "");
        write_entry(database, "base-devel-1-2", "%NAME%\nbase-devel\n", "");

        let status = inspect_package_database(database, None).expect("inspection");

        assert_eq!(status.entry_count, 2);
        assert!(status.damaged_entries.is_empty());
        assert!(status.is_healthy());
    }

    #[test]
    fn detects_a_running_transaction_from_the_lock_file() {
        let temp = tempfile::tempdir().expect("temporary database");
        let lock = temp.path().join("db.lck");

        let idle = inspect_package_database(temp.path(), Some(&lock)).expect("inspection");
        assert!(!idle.transaction_in_progress);

        fs::write(&lock, "").expect("lock");
        let busy = inspect_package_database(temp.path(), Some(&lock)).expect("inspection");
        assert!(busy.transaction_in_progress);
    }

    #[test]
    fn missing_database_is_an_error_rather_than_a_clean_bill_of_health() {
        let temp = tempfile::tempdir().expect("temporary database");
        assert!(inspect_package_database(&temp.path().join("absent"), None).is_err());
    }
}
