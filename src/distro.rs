use std::fs;
use std::path::Path;

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};

use crate::model::{CleanupAction, CleanupGroup, CleanupItem, CommandSpec, Risk};

/// Directory holding one metadata entry per installed package.
///
/// Only pacman is covered for now. The dpkg and rpm databases are single files
/// rather than per-package directories, so they need a different integrity
/// check and are reported as unsupported instead of guessed at.
pub const PACMAN_LOCAL_DATABASE: &str = "/var/lib/pacman/local";

/// Lock file pacman creates for the duration of a transaction and removes
/// afterwards, so its presence is a reliable "transaction in progress" signal.
///
/// The apt and dnf equivalents are permanent files locked with `flock`, so
/// existence alone proves nothing about them and they are not checked here.
pub const PACMAN_TRANSACTION_LOCK: &str = "/var/lib/pacman/db.lck";

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum DistroFamily {
    Arch,
    Debian,
    Fedora,
    Unsupported,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Distribution {
    pub id: String,
    pub name: String,
    pub family: DistroFamily,
}

impl Distribution {
    pub fn detect() -> Result<Self> {
        let override_path = std::env::var_os("TUXCLEANER_OS_RELEASE");
        let path = override_path
            .as_deref()
            .map(Path::new)
            .unwrap_or_else(|| Path::new("/etc/os-release"));
        Self::from_path(path)
    }

    pub fn from_path(path: &Path) -> Result<Self> {
        let input = fs::read_to_string(path)
            .with_context(|| format!("failed to read {}", path.display()))?;
        Ok(Self::parse_os_release(&input))
    }

    pub fn parse_os_release(input: &str) -> Self {
        let mut id = String::from("unknown");
        let mut name = String::from("Unknown Linux");
        let mut id_like = String::new();

        for raw_line in input.lines() {
            let line = raw_line.trim();
            if line.is_empty() || line.starts_with('#') {
                continue;
            }
            let Some((key, raw_value)) = line.split_once('=') else {
                continue;
            };
            let value = raw_value.trim().trim_matches('"').trim_matches('\'');
            match key {
                "ID" => id = value.to_ascii_lowercase(),
                "NAME" => name = value.to_owned(),
                "ID_LIKE" => id_like = value.to_ascii_lowercase(),
                _ => {}
            }
        }

        let identifiers = format!("{id} {id_like}");
        let family = if identifiers
            .split_whitespace()
            .any(|value| matches!(value, "arch" | "manjaro" | "endeavouros"))
        {
            DistroFamily::Arch
        } else if identifiers
            .split_whitespace()
            .any(|value| matches!(value, "debian" | "ubuntu" | "linuxmint" | "pop"))
        {
            DistroFamily::Debian
        } else if identifiers
            .split_whitespace()
            .any(|value| matches!(value, "fedora" | "rhel" | "centos" | "rocky" | "almalinux"))
        {
            DistroFamily::Fedora
        } else {
            DistroFamily::Unsupported
        };

        Self { id, name, family }
    }

    /// Path of the package database whose integrity `status` can verify, when
    /// the distribution ships one this tool knows how to inspect.
    pub fn package_database_path(&self) -> Option<&'static str> {
        match self.family {
            DistroFamily::Arch => Some(PACMAN_LOCAL_DATABASE),
            DistroFamily::Debian | DistroFamily::Fedora | DistroFamily::Unsupported => None,
        }
    }

    /// Path whose existence means a package transaction is running right now.
    pub fn package_transaction_lock_path(&self) -> Option<&'static str> {
        match self.family {
            DistroFamily::Arch => Some(PACMAN_TRANSACTION_LOCK),
            DistroFamily::Debian | DistroFamily::Fedora | DistroFamily::Unsupported => None,
        }
    }

    pub fn package_cache_paths(&self) -> &'static [&'static str] {
        match self.family {
            DistroFamily::Arch => &["/var/cache/pacman/pkg"],
            DistroFamily::Debian => &["/var/cache/apt/archives"],
            DistroFamily::Fedora => &["/var/cache/dnf", "/var/cache/libdnf5"],
            DistroFamily::Unsupported => &[],
        }
    }

    pub fn package_cleanup_item(&self, estimated_bytes: u64) -> Option<CleanupItem> {
        let (id, label, action) = match self.family {
            DistroFamily::Arch => (
                "packages.arch.paccache",
                "Old pacman package versions (keeps one installed version)",
                CleanupAction::CommandSequence {
                    commands: vec![
                        CommandSpec {
                            program: "paccache".into(),
                            args: vec!["-rk1".into()],
                            requires_root: true,
                        },
                        CommandSpec {
                            program: "paccache".into(),
                            args: vec!["-ruk0".into()],
                            requires_root: true,
                        },
                    ],
                },
            ),
            DistroFamily::Debian => (
                "packages.debian.apt",
                "Downloaded APT package files",
                CleanupAction::Command {
                    program: "apt-get".into(),
                    args: vec!["clean".into()],
                    requires_root: true,
                },
            ),
            DistroFamily::Fedora => (
                "packages.fedora.dnf",
                "DNF repository and package caches",
                CleanupAction::Command {
                    program: "dnf".into(),
                    args: vec!["clean".into(), "all".into()],
                    requires_root: true,
                },
            ),
            DistroFamily::Unsupported => return None,
        };

        Some(CleanupItem {
            id: id.into(),
            group: CleanupGroup::System,
            label: label.into(),
            estimated_bytes,
            risk: Risk::Elevated,
            action,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn detects_arch_derivatives_from_id_like() {
        let distro =
            Distribution::parse_os_release("NAME=EndeavourOS\nID=endeavouros\nID_LIKE=\"arch\"\n");
        assert_eq!(distro.family, DistroFamily::Arch);
    }

    #[test]
    fn detects_ubuntu_as_debian_family() {
        let distro =
            Distribution::parse_os_release("NAME=\"Ubuntu\"\nID=ubuntu\nID_LIKE=\"debian\"\n");
        assert_eq!(distro.family, DistroFamily::Debian);
    }

    #[test]
    fn detects_fedora_family() {
        let distro = Distribution::parse_os_release("NAME=Fedora Linux\nID=fedora\n");
        assert_eq!(distro.family, DistroFamily::Fedora);
    }

    #[test]
    fn unknown_distribution_remains_safe() {
        let distro = Distribution::parse_os_release("NAME=Custom Linux\nID=custom\n");
        assert_eq!(distro.family, DistroFamily::Unsupported);
        assert!(distro.package_cleanup_item(100).is_none());
    }
}
