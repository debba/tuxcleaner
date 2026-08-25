use super::*;

pub(super) fn run_status(args: StatusArgs) -> Result<()> {
    let report = status::collect()?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("TuxCleaner status for {}", report.hostname);
        println!(
            "CPU: {} logical cores | load {:.2} / {:.2} / {:.2}",
            report.logical_cpus,
            report.load_average[0],
            report.load_average[1],
            report.load_average[2]
        );
        println!(
            "Memory: {} / {} used ({:.1}%)",
            format_bytes(report.memory.used_bytes),
            format_bytes(report.memory.total_bytes),
            report.memory.used_percent
        );
        println!("Uptime: {}", format_duration(report.uptime_seconds));
        println!();
        println!("Disks:");
        for disk in report.disks {
            println!(
                "  {:<20} {:>8} / {:>8} ({:>5.1}%)  {}",
                disk.mount,
                format_bytes(disk.used_bytes),
                format_bytes(disk.total_bytes),
                disk.used_percent,
                disk.filesystem
            );
        }
        if let Some(database) = &report.package_database {
            println!();
            println!(
                "Package database: {} entries at {}",
                database.entry_count, database.path
            );
            if database.transaction_in_progress {
                println!("  A package transaction is running right now.");
            }
            if database.is_healthy() {
                println!("  All entries have readable metadata.");
            } else {
                println!(
                    "  {} entries have unreadable metadata, usually left behind by an",
                    database.damaged_entries.len()
                );
                println!("  interrupted transaction or an unclean shutdown:");
                for entry in &database.damaged_entries {
                    println!("    {entry}");
                }
                println!("  Reinstall these packages to rebuild their metadata.");
            }
        }
    }
    Ok(())
}

pub(super) fn run_history(args: HistoryArgs) -> Result<()> {
    let store = HistoryStore::system_default()?;
    let records = store.read_recent(args.limit)?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&records)?);
    } else if records.is_empty() {
        println!("No cleanup history at {}.", store.path().display());
    } else {
        for record in records {
            let succeeded = record
                .results
                .iter()
                .filter(|result| result.success)
                .count();
            let reclaimed: u64 = record
                .results
                .iter()
                .filter(|result| result.success && !result.dry_run)
                .map(|result| result.estimated_bytes)
                .sum();
            println!(
                "{}  {:<6}  {}/{} succeeded  estimated {}",
                record.timestamp.format("%Y-%m-%d %H:%M:%S UTC"),
                record.command,
                succeeded,
                record.results.len(),
                format_bytes(reclaimed)
            );
        }
    }
    Ok(())
}

pub(super) fn run_update(args: UpdateArgs) -> Result<()> {
    if !args.check && !args.dry_run && !args.yes && !io::stdin().is_terminal() {
        bail!("update needs an interactive terminal; use --dry-run, --check, or --yes")
    }
    let info = update::check(args.target_version.as_deref())?;
    if args.check || args.dry_run || (!info.update_available && args.target_version.is_none()) {
        if args.json {
            println!("{}", serde_json::to_string_pretty(&info)?);
        } else if info.update_available || args.target_version.is_some() {
            println!(
                "TuxCleaner {} is installed; release {} is available for {}{}.",
                info.current_version,
                info.available_version,
                info.target,
                if args.dry_run { " (dry-run)" } else { "" }
            );
        } else {
            println!("TuxCleaner {} is already up to date.", info.current_version);
        }
        return Ok(());
    }
    if !args.yes
        && !Confirm::with_theme(&ColorfulTheme::default())
            .with_prompt(format!(
                "Replace TuxCleaner {} with {}?",
                info.current_version, info.available_version
            ))
            .default(false)
            .interact()?
    {
        println!("Cancelled.");
        return Ok(());
    }
    let result = update::install(args.target_version.as_deref())?;
    if args.json {
        println!("{}", serde_json::to_string_pretty(&result)?);
    } else if result.updated {
        println!(
            "Updated TuxCleaner from {} to {} for {}.",
            result.previous_version, result.installed_version, result.target
        );
    } else {
        println!(
            "TuxCleaner {} is already up to date.",
            result.installed_version
        );
    }
    Ok(())
}
